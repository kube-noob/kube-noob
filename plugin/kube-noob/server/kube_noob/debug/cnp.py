"""ClusterNetworkPolicy v1alpha2, evaluated offline (P4).

``policy.networking.k8s.io/v1alpha2`` replaces AdminNetworkPolicy and BaselineAdminNetworkPolicy with one
cluster-scoped kind carrying both tiers in ``spec.tier``. Calico 3.32 **removed** ANP and BANP enforcement in
favour of it -- "You must migrate to ClusterNetworkPolicy before upgrading to v3.32" -- so on such a cluster the
policy that actually decides is this kind, and the two :mod:`kube_noob.debug.anp` evaluates are the ones that no
longer apply. Until this module existed, ``policy reach`` answered ``undetermined`` whenever one was in the
input: honest, and useless on the clusters where it is the only policy that matters.

Precedence, from the API's own documentation of ``spec.tier``:

1. **Admin tier** -- every Admin-tier policy by ``priority`` ascending, rules in order, first match wins.
   ``Accept`` and ``Deny`` are final. ``Pass`` ends this tier and hands the decision to the NetworkPolicy tier.
2. **NetworkPolicy** -- the namespaced evaluation in :mod:`kube_noob.debug.netpol`. A NetworkPolicy that selects
   the pod for that direction decides finally, and the Baseline tier is not consulted.
3. **Baseline tier** -- every Baseline-tier policy by ``priority`` ascending. ``Accept`` and ``Deny`` are final.
4. No match in any tier: allowed, which is Kubernetes' own default.

Why this is a module and not a flag on :mod:`kube_noob.debug.anp`. Four things changed, and each one would make
the v1alpha1 evaluator read a valid v1alpha2 policy *wrong* rather than refuse it:

* ``Allow`` is renamed **``Accept``**. The old action list rejects every valid Admin rule.
* ``ports`` is replaced by **``protocols``**: a list of ``{tcp|udp|sctp: {destinationPort: {number|range}}}``
  plus ``destinationNamedPort``. The old matcher reads an absent ``ports`` key as "every port", so handing it a
  v1alpha2 rule scoped to one port would widen the rule to every port -- a verdict that is wrong in the
  dangerous direction.
* The Baseline tier is no longer a singleton named ``default``, and it carries ``priority`` like the Admin tier.
  ``Pass`` is in the action enum for both tiers.
* Every list is capped at **25** items rather than 100.

And one rule the v1alpha1 evaluator has no equivalent of, which the API states outright: a peer with no
recognised field means the CRD is a version this reader does not understand, and the implementation **fails
closed** -- "for Accept rules, treat the rule as matching no traffic; for Deny and Pass rules, treat the rule as
a Deny all rule". That is the opposite of skipping it, and it is the whole reason a reader of this API cannot be
permissive about shapes it does not know.

Verified against kubernetes-sigs/network-policy-api at 2383f01,
``apis/v1alpha2/clusternetworkpolicy_types.go``: the action enum, the tier enum, ``priority`` 0-1000 in both
tiers, the protocol and port unions, the peer fields, the MaxItems of 25, and the fail-closed paragraph.

As with the v1alpha1 tiers, :mod:`kube_noob.debug.cni` decides whether these policies are enforced at all: when
the caller names a CNI that does not implement them, they are withheld rather than fed through this module.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from kube_noob.debug.anp import Decision, outside_peer, peer_matches, rules_of, subject_matches
from kube_noob.debug.netpol import Endpoint, Inventory, selector_problem, shown_field, shown_name, shown_ref

KIND = "ClusterNetworkPolicy"
API_VERSION = "policy.networking.k8s.io/v1alpha2"
ACTIONS = ("Accept", "Deny", "Pass")
TIERS = ("Admin", "Baseline")
PRIORITY_MAX = 1000
#: Every list in the v1alpha2 spec. A document above it is one the API server refuses, so evaluating the first
#: 25 of its rules would answer a question about a policy that cannot exist.
MAX_ITEMS = 25
_PROTOCOL_KEYS = {"TCP": "tcp", "UDP": "udp", "SCTP": "sctp"}
#: The peer fields this reader understands. Anything else means a newer CRD, and the API says to fail closed.
_INGRESS_PEER_FIELDS = {"namespaces", "pods"}
_EGRESS_PEER_FIELDS = {"namespaces", "pods", "nodes", "networks", "domainNames"}


@dataclass(frozen=True)
class Tier:
    """One tier's policies, already ordered by (priority, document order)."""

    name: str
    policies: tuple[dict[str, Any], ...]


def _str(v: Any) -> str:
    return v if isinstance(v, str) else ""


def _dict(v: Any) -> dict[str, Any]:
    return v if isinstance(v, dict) else {}


def _port_number(spec: Any, number: int | None) -> bool:
    """One ``destinationPort``: ``{number: N}`` or ``{range: {start, end}}``. An absent ``destinationPort`` is
    every port on that protocol, which is the API's own default and the only case where silence widens a rule."""
    if spec is None:
        return True
    if not isinstance(spec, dict) or number is None:
        return False
    if isinstance(spec.get("number"), int) and not isinstance(spec.get("number"), bool):
        return bool(spec["number"] == number)
    rng = spec.get("range")
    if isinstance(rng, dict):
        start, end = rng.get("start"), rng.get("end")
        if isinstance(start, int) and isinstance(end, int) and not isinstance(start, bool):
            return bool(start <= number <= end)
    return False


def protocols_match(protocols: Any, port: int | str, protocol: str, dest: Endpoint) -> bool | None:
    """Whether this rule's ``protocols`` select ``protocol``/``port`` on ``dest``.

    No ``protocols`` key at all means every port, which is the API's default. Present and non-empty, it is a
    list of alternatives: the rule matches when ANY entry does. An entry naming a protocol other than the
    traffic's does not match -- and that is the case the v1alpha1 matcher would have got wrong, because it reads
    the whole field as "every port" whenever it does not recognise the shape.
    """
    if protocols is None:
        return True  # the field is optional, and absent means every port. The ONLY widening silence here.
    # `minItems: 1` and `minProperties: 1` are on the CRD, so each of these is a document the API server
    # refuses. Reading them as "every port" widened an Accept rule past anything it says; reading them as "no
    # port" quietly dropped a Deny. Unreadable is the third answer, and the caller decides by action.
    if not isinstance(protocols, list) or not protocols:
        return None
    key = _PROTOCOL_KEYS.get(protocol.upper())
    declared = None if isinstance(port, int) else dest.ports.get(port)
    number = port if isinstance(port, int) else (declared[0] if declared else None)
    for entry in protocols:
        if not isinstance(entry, dict):
            continue
        named = entry.get("destinationNamedPort")
        if isinstance(named, str) and named:
            # A named port is the container's own name for it, so it matches the name the caller asked about,
            # or the number that name resolves to ON ITS OWN PROTOCOL. Resolving by number alone matched TCP
            # 53 against a named port declared UDP 53 -- a rule accepting traffic it does not name.
            if isinstance(port, str) and port == named:
                return True
            declared_named = dest.ports.get(named)
            if (
                number is not None
                and declared_named is not None
                and declared_named[0] == number
                and str(declared_named[1]).upper() == protocol.upper()
            ):
                return True
            continue
        if not set(entry) & (set(_PROTOCOL_KEYS.values()) | {"destinationNamedPort"}):
            return None  # an entry naming nothing this reader knows: a newer CRD, not an empty scope
        if key is None or key not in entry:
            continue  # a protocol entry for other traffic than this: it simply does not match
        body = entry.get(key)
        if not isinstance(body, dict) or not body:
            return None  # `tcp: {}` and `tcp: null` are refused by the CRD (minProperties 1)
        if _port_number(body.get("destinationPort"), number):
            return True
    return False


def _first_selector_problem(*selectors: Any) -> str | None:
    """The first of these label selectors the API server would refuse, or None when every one is well formed."""
    for sel in selectors:
        why = selector_problem(sel)
        if why is not None:
            return why
    return None


def _peer_verdict(peer: Any, other: Endpoint, inv: Inventory, *, egress: bool) -> bool | str:
    """``True`` matched, ``False`` did not, or WHY it could not be told -- and the two reasons differ.

    ``"unknown-field"`` is the API's fail-closed case: a peer with no field this reader knows is a CRD newer
    than this code, and the spec says what to do about it. ``"uncheckable"`` is an ordinary CIDR or node peer
    that might select the other side, where the manifests simply do not carry an address to compare. Both stop
    a later rule from deciding, but only the first is a newer CRD -- printing that sentence for the second
    told the reader a field was unrecognised when it was recognised perfectly well.
    """
    if not isinstance(peer, dict) or not peer:
        return "unknown-field"
    known = _EGRESS_PEER_FIELDS if egress else _INGRESS_PEER_FIELDS
    present = set(peer) & known
    if not present:
        return "unknown-field"
    if present & {"namespaces", "pods"}:
        pods = _dict(peer.get("pods"))
        if _first_selector_problem(peer.get("namespaces"), pods.get("namespaceSelector"), pods.get("podSelector")):
            return "unreadable-selector"
        try:
            return peer_matches(peer, other, inv)
        except (AttributeError, TypeError):
            # A selector the API server would refuse (`matchLabels: "x"`, `matchExpressions: [null]`). It used
            # to abort the whole command; an unreadable selector is an unreadable rule, not a crash.
            return "unreadable-selector"
    got = outside_peer(peer, other)
    return "uncheckable" if got is None else got


#: Why a peer could not be decided, in the words the reader gets. Separate strings because the first is a
#: statement about THIS BUILD of kube-noob and the other two are statements about the input.
_WHY = {
    "unknown-field": "a peer naming no field this version of kube-noob recognises, which is a newer CRD",
    "uncheckable": "a nodes, networks or domainNames peer that might select the other side and cannot be "
    "checked from the manifests",
    "unreadable-selector": "a peer selector the API server itself refuses",
}


def _failed_closed(
    name: str,
    label: str,
    action: str,
    direction: str,
    other: Endpoint,
    protocol: str,
    port: int | str,
    why: str,
) -> Decision:
    """The spec's rule, said out loud: for Deny and Pass, an unreadable rule is a deny-all."""
    return Decision(
        "deny",
        name,
        label,
        reason=(
            f"{name} {direction.lower()} {label} is a {action} rule with {why}, so the API says to fail "
            f"closed and treat it as deny-all. {other.describe()} on {protocol} {port} is denied by that "
            "rule, not by anything below it."
        ),
    )


def _policy_decision(
    pol: dict[str, Any],
    subject_ep: Endpoint,
    other: Endpoint,
    direction: str,
    port: int | str,
    protocol: str,
    dest: Endpoint,
    inv: Inventory,
    notes: list[str],
) -> Decision | None:
    """This one policy's answer: its first rule whose peers and protocols both match."""
    meta = _dict(pol.get("metadata"))
    # Printed in every sentence below and in `unreadable_cluster_scoped`, which the summary and the
    # `unknown because:` line both read: a raw `metadata.name` forged a line of output (G373, class 7).
    name = shown_ref(KIND, meta.get("name"))
    spec = _dict(pol.get("spec"))
    tier = _str(spec.get("tier"))
    subject = spec.get("subject")
    # `subject` is required and MinProperties=1. A shape this reader does not know is a newer CRD, exactly as
    # a peer is, and skipping the whole policy for it dropped its Deny rules in silence -- the one direction
    # the peer rule above exists to prevent. It is refused by name instead, and `collect` has already recorded
    # the policy so the verdict can be undetermined rather than allowed.
    if not isinstance(subject, dict) or not (set(subject) & {"namespaces", "pods"}):
        inv.unreadable_cluster_scoped.append(name)
        # `map(str, ...)` before `sorted`: a mapping with keys of two types (`{1: x, "a": y}`) made `sorted`
        # raise TypeError, which ended the whole command instead of reporting one unreadable policy.
        shape = (
            ", ".join(shown_field(k) for k in sorted(map(str, subject)))
            if isinstance(subject, dict)
            else type(subject).__name__
        )
        notes.append(
            f"{name}: its subject names no field kube-noob reads ({shape}); that is a newer CRD than this "
            "version understands, so the policy is not evaluated and the answer below cannot be trusted "
            "over it"
        )
        return None
    # Checked rather than caught: `operator: Exist` raises nothing, it just matches no pod -- so the policy
    # read as selecting nobody and its Deny rules disappeared. An invalid selector is not a selector that
    # matches nothing; it is a document the API server refuses, and the answer over it is not clean.
    pods = _dict(subject.get("pods"))
    bad = _first_selector_problem(subject.get("namespaces"), pods.get("namespaceSelector"), pods.get("podSelector"))
    if bad is not None:
        inv.unreadable_cluster_scoped.append(name)
        notes.append(f"{name}: its subject selector is one the API server refuses ({bad}), so it is not evaluated")
        return None
    try:
        selects = subject_matches(subject, subject_ep, inv)
    except (AttributeError, TypeError):
        inv.unreadable_cluster_scoped.append(name)
        notes.append(f"{name}: its subject selector is one the API server refuses, so it is not evaluated")
        return None
    if not selects:
        return None
    egress = direction == "Egress"
    for i, raw in enumerate(rules_of(spec, direction), 1):
        rule = raw if isinstance(raw, dict) else {}
        action = _str(rule.get("action"))
        label = shown_name(rule.get("name")) if _str(rule.get("name")) else f"rule {i}"
        if action not in ACTIONS:
            notes.append(
                f"{name} {direction.lower()} {label}: action "
                f"{shown_field(action) if action else '(empty)'} is not one of "
                f"{', '.join(ACTIONS)}; the rule is skipped rather than read as the nearest valid action "
                "(v1alpha2 renamed Allow to Accept, so an Allow here is a v1alpha1 rule in a v1alpha2 document)"
            )
            continue
        raw_peers = rule.get("to" if egress else "from")
        peers = raw_peers if isinstance(raw_peers, list) else []
        # `from`/`to` are required with MinItems=1. An empty or non-list one is a document the API server
        # refuses, and reading it as "this rule matches nothing" dropped Deny rules without a word.
        bad_peers = (
            f"{len(peers)} peers, above the API's limit of {MAX_ITEMS}"
            if len(peers) > MAX_ITEMS
            else ("no peers, where the API requires at least one" if not peers else "")
        )
        ports = protocols_match(rule.get("protocols"), port, protocol, dest)
        if bad_peers or ports is None:
            why = bad_peers or "a protocols entry kube-noob cannot read"
            notes.append(
                f"{name} {direction.lower()} {label} has {why}; it is not evaluated"
                + ("" if action == "Accept" else f", and an unreadable {action} rule is read as deny-all")
            )
            if action == "Accept":
                continue  # fail closed: an Accept rule nobody can read accepts nothing
            return _failed_closed(name, label, action, direction, other, protocol, port, why)
        if ports is False:
            continue
        matched = False
        unreadable = ""
        for peer in peers:
            got = _peer_verdict(peer, other, inv, egress=egress)
            if got is True:
                matched = True
                break
            if isinstance(got, str):
                unreadable = unreadable or got
        if not matched and unreadable:
            # The API's rule, not a choice made here: an unreadable peer on an Accept rule matches nothing, and
            # on Deny or Pass it is a deny-all. Reporting it as undetermined would be softer than the spec and
            # softer than the cluster, which is the wrong direction for a reachability answer.
            if action == "Accept":
                continue
            return _failed_closed(name, label, action, direction, other, protocol, port, _WHY[unreadable])
        if not matched:
            continue
        if action == "Pass":
            return Decision(
                "passed",
                name,
                label,
                f"{name} {direction.lower()} {label} passes {other.describe()} on {protocol} {port} down to "
                f"the {'NetworkPolicies in the namespace' if tier == 'Admin' else 'default'}.",
            )
        return Decision(
            "allow" if action == "Accept" else "deny",
            name,
            label,
            f"{'Accepted' if action == 'Accept' else 'Denied'} by {name} {direction.lower()} {label} "
            f"({tier} tier, priority {spec.get('priority')}).",
        )
    return None


def _evaluate(
    tier: Tier,
    subject_ep: Endpoint,
    other: Endpoint,
    direction: str,
    port: int | str,
    protocol: str,
    dest: Endpoint,
    inv: Inventory,
) -> Decision:
    """The first priority at which any policy decides. Policies tied at one priority that disagree are
    ``undetermined``, because the API does not define which the server applies."""
    groups: list[list[dict[str, Any]]] = []
    for pol in tier.policies:
        priority = _dict(pol.get("spec")).get("priority")
        last = _dict(groups[-1][0].get("spec")) if groups else None
        if groups and last is not None and last.get("priority") == priority:
            groups[-1].append(pol)
        else:
            groups.append([pol])
    for group in groups:
        decided = [
            d
            for pol in group
            if (d := _policy_decision(pol, subject_ep, other, direction, port, protocol, dest, inv, inv.notes))
            is not None
        ]
        if not decided:
            continue
        if len({d.outcome for d in decided}) == 1:
            return decided[0]
        names = tuple(dict.fromkeys(d.policy for d in decided))
        priority = _dict(group[0].get("spec")).get("priority")
        return Decision(
            "undetermined",
            policies=names,
            reason=(
                f"{' and '.join(names)} are both at priority {priority} in the {tier.name} tier and disagree "
                f"about {other.describe()} on {protocol} {port} "
                f"({', '.join(sorted({d.outcome for d in decided}))}). Two policies at one priority in one tier "
                "are undefined behaviour in the API, so which one the API server applies is not something "
                "kube-noob can work out from the manifests."
            ),
        )
    return Decision("nomatch")


def collect(inv: Inventory, objects: list[dict[str, Any]]) -> tuple[Tier, Tier]:
    """(Admin tier, Baseline tier), each ordered by (priority, document order).

    A document the API server would itself refuse -- an unknown tier, a priority outside 0-1000, more than 25
    rules -- is noted in ``inv.notes`` and left out, because such a manifest is a mistake to report rather than
    a policy to evaluate. Leaving it out is only safe BECAUSE it is reported: silence here would be the same
    defect as dropping the kind entirely.
    """
    buckets: dict[str, list[tuple[int, int, dict[str, Any]]]] = {t: [] for t in TIERS}
    for i, obj in enumerate(objects):
        if not isinstance(obj, dict) or _str(obj.get("kind")) != KIND:
            continue
        meta = _dict(obj.get("metadata"))
        ref = shown_ref(KIND, meta.get("name"))
        spec = _dict(obj.get("spec"))
        version = _str(obj.get("apiVersion"))
        # The whole version, not its suffix. `endswith("/v1alpha2")` was correct only because `rules.refusal`
        # checks the group first; a second version of this group (`policy.networking.k8s.io/v1alpha3`) would
        # then have been refused by neither, and read with v1alpha2 semantics it does not have. Comparing the
        # string this module declares needs no second reader to be right (G373).
        if version and version != API_VERSION:
            inv.unreadable_cluster_scoped.append(ref)
            inv.notes.append(
                f"{ref}: apiVersion {shown_field(version)} is not {API_VERSION}; kube-noob reads the v1alpha2 "
                "shape only, so this document is not evaluated"
            )
            continue
        tier = _str(spec.get("tier"))
        if tier not in TIERS:
            inv.unreadable_cluster_scoped.append(ref)
            inv.notes.append(
                f"{ref}: tier {shown_field(spec.get('tier')) if tier else '(missing)'} is not one of "
                f"{', '.join(TIERS)}, which the API server refuses, so this policy is not evaluated"
            )
            continue
        priority = spec.get("priority")
        if not isinstance(priority, int) or isinstance(priority, bool) or not 0 <= priority <= PRIORITY_MAX:
            inv.unreadable_cluster_scoped.append(ref)
            inv.notes.append(
                f"{ref}: priority {shown_field(priority)} is outside 0-{PRIORITY_MAX}, which the API server "
                "refuses, so this policy is not evaluated"
            )
            continue
        for direction in ("ingress", "egress"):
            got = spec.get(direction)
            if isinstance(got, list) and len(got) > MAX_ITEMS:
                inv.unreadable_cluster_scoped.append(ref)
                inv.notes.append(
                    f"{ref}: {len(got)} {direction} rules, above the API's limit of {MAX_ITEMS}; the "
                    "API server refuses the document, so this policy is not evaluated"
                )
                break
        else:
            buckets[tier].append((priority, i, obj))
            continue
    out: list[Tier] = []
    for tier in TIERS:
        rows = sorted(buckets[tier], key=lambda t: (t[0], t[1]))
        by_priority: dict[int, list[str]] = {}
        for priority, _, obj in rows:
            by_priority.setdefault(priority, []).append(shown_name(_dict(obj.get("metadata")).get("name")))
        for priority, names in by_priority.items():
            if len(names) > 1:
                inv.notes.append(
                    f"{', '.join(names)} are all at priority {priority} in the {tier} tier: the API does not "
                    "define which ClusterNetworkPolicy wins at one priority in one tier, so give them "
                    "distinct priorities"
                )
        out.append(Tier(tier, tuple(obj for _, _, obj in rows)))
    return out[0], out[1]


def tier_before(
    inv: Inventory,
    admin: Tier,
    subject: Endpoint,
    other: Endpoint,
    direction: str,
    port: int | str,
    protocol: str,
    dest: Endpoint,
) -> Decision:
    """The Admin tier, which runs before any NetworkPolicy."""
    if not admin.policies or subject.external:
        return Decision("nomatch")
    return _evaluate(admin, subject, other, direction, port, protocol, dest, inv)


def tier_after(
    inv: Inventory,
    baseline: Tier,
    subject: Endpoint,
    other: Endpoint,
    direction: str,
    port: int | str,
    protocol: str,
    dest: Endpoint,
) -> Decision:
    """The Baseline tier, which runs only where no NetworkPolicy selects the pod."""
    if not baseline.policies or subject.external:
        return Decision("nomatch")
    return _evaluate(baseline, subject, other, direction, port, protocol, dest, inv)
