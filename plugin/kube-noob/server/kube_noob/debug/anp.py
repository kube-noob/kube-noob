"""AdminNetworkPolicy and BaselineAdminNetworkPolicy, evaluated offline.

These two cluster-scoped resources (``policy.networking.k8s.io``) sit on either side of NetworkPolicy, so leaving
them out does not narrow an answer, it changes it: an AdminNetworkPolicy ``Deny`` blocks traffic every NetworkPolicy
in the namespace allows, an ``Allow`` permits traffic every NetworkPolicy denies, and a BaselineAdminNetworkPolicy
decides the traffic no NetworkPolicy selects at all.

Precedence, as OVN-Kubernetes implements it:

1. **AdminNetworkPolicy** - every policy by ``priority`` ascending (lower number first), rules within a policy in
   order, first match wins. ``Allow`` and ``Deny`` are final. ``Pass`` ends this tier and hands the decision down.
   No match anywhere in the tier also hands it down: the tier has no implicit deny of its own.
2. **NetworkPolicy** - the namespaced evaluation in ``kube_noob.debug.netpol``. If any NetworkPolicy selects the pod
   for that direction, its answer is final and the baseline is not consulted.
3. **BaselineAdminNetworkPolicy** - the singleton named ``default``. ``Allow`` and ``Deny`` only, no priority, first
   matching rule wins. No match means allowed.

Sources: https://ovn-kubernetes.io/features/network-security-controls/admin-network-policy/ and
https://network-policy-api.sigs.k8s.io/api-overview/.

Upstream replaces both with a single ``ClusterNetworkPolicy`` in v1alpha2, which **this module does not
evaluate**: :mod:`kube_noob.debug.cnp` does (P4). The two tiers survive there as a ``tier`` field, but the
semantics are not the same, which is why it is a module of its own rather than a flag on this one. Nothing here
may be reused on a v1alpha2 document without reading each of these:

* ``Allow`` is renamed ``Accept``, so :data:`ANP_ACTIONS` rejects every valid v1alpha2 Admin rule.
* ``Pass`` is legal in the Baseline tier, which :data:`BANP_ACTIONS` does not allow.
* The ``ports`` field is replaced by ``protocols``, with ``tcp``/``udp``/``sctp`` each carrying a
  ``destinationPort``. :func:`_port_matches` treats an absent ``ports`` key as "every port", which is right for
  v1alpha1 -- so simply adding the kind to :func:`collect` would read a rule scoped to one port as a blanket
  rule, and widen every verdict. That is worse than not reading the kind at all.
* The Baseline tier is no longer a singleton named ``default``, which :func:`collect` requires.
* Egress peers gain ``nodes``, ``networks`` and ``domainNames``. A CIDR is matched when the other side is an
  address, or when it is ``0.0.0.0/0`` or ``::/0``. A peer that might match and cannot be checked stops the
  tier as ``undetermined``; it is not skipped so a later rule can allow the traffic.
* The per-list cap fell from 100 items to 25.

Each of those is now implemented in :mod:`kube_noob.debug.cnp`, and ``policy reach`` evaluates both APIs:
the v1alpha2 Admin tier first, then this one, then the NetworkPolicies, then this baseline, then the v1alpha2
Baseline tier. This mattered on current clusters rather than future ones: Calico 3.32 removed
AdminNetworkPolicy and BaselineAdminNetworkPolicy enforcement outright in favour of ``ClusterNetworkPolicy``,
so on such a cluster the policy that actually decides was the kind nothing could read.

The other half of that is :mod:`kube_noob.debug.cni`: everything here is the semantics of a tier the CNI may not
apply at all, so when the caller names the CNI, the policies this module would have evaluated are withheld from
it rather than fed through it.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any

from kube_noob.debug.netpol import Endpoint, Inventory, selector_matches, shown_field, shown_name, shown_ref

ANP_KIND = "AdminNetworkPolicy"
BANP_KIND = "BaselineAdminNetworkPolicy"
ANP_ACTIONS = ("Allow", "Deny", "Pass")
BANP_ACTIONS = ("Allow", "Deny")
PRIORITY_MAX = 1000  # the API's range; OVN-Kubernetes implements 0-99 and warns above that
OVN_PRIORITY_MAX = 99


@dataclass
class Decision:
    """A tier's answer: ``allow`` and ``deny`` are final, ``passed`` hands the decision to the next tier,
    ``undetermined`` means the tier's own rules disagree and the API server's choice between them is undefined."""

    outcome: str  # "allow" | "deny" | "passed" | "nomatch" | "undetermined"
    policy: str = ""
    rule: str = ""
    reason: str = ""
    policies: tuple[str, ...] = ()  # the tied policies, when `outcome` is "undetermined"


def _str(v: Any) -> str:
    return v if isinstance(v, str) else ""


def peer_matches(peer: Any, other: Endpoint, inv: Inventory) -> bool:
    """One ``namespaces`` or ``pods`` entry. ``nodes``, ``networks`` and ``domainNames`` are handled by
    :func:`outside_peer`, which can say "unknown" rather than pretend the peer did not match."""
    if not isinstance(peer, dict):
        return False
    if "namespaces" in peer:
        if other.namespace is None:
            return False
        return selector_matches(peer.get("namespaces") or {}, inv.ns_labels(other.namespace))
    if "pods" in peer:
        pods = peer.get("pods") or {}
        if not isinstance(pods, dict) or other.namespace is None:
            return False
        return selector_matches(
            pods.get("namespaceSelector") or {}, inv.ns_labels(other.namespace)
        ) and selector_matches(pods.get("podSelector") or {}, other.labels)
    return False


def _port_matches(ports: Any, port: int | str, protocol: str, dest: Endpoint) -> bool:
    """``portNumber`` {protocol, port}, ``portRange`` {protocol, start, end} or ``namedPort``. No ``ports`` at all
    means every port, as in NetworkPolicy."""
    if not ports:
        return True
    if not isinstance(ports, list):
        return False
    declared = None if isinstance(port, int) else dest.ports.get(port)
    number = port if isinstance(port, int) else (declared[0] if declared else None)
    for entry in ports:
        if not isinstance(entry, dict):
            continue
        if "namedPort" in entry:
            if isinstance(port, str) and _str(entry.get("namedPort")) == port:
                return True
            continue
        if "portNumber" in entry:
            spec = entry.get("portNumber") or {}
            if not isinstance(spec, dict):
                continue
            if _str(spec.get("protocol")).upper() not in ("", protocol):
                continue
            if number is not None and spec.get("port") == number:
                return True
            continue
        if "portRange" in entry:
            spec = entry.get("portRange") or {}
            if not isinstance(spec, dict):
                continue
            if _str(spec.get("protocol")).upper() not in ("", protocol):
                continue
            start, end = spec.get("start"), spec.get("end")
            if number is None or not isinstance(start, int) or not isinstance(end, int):
                continue
            if start <= number <= end:
                return True
    return False


def subject_matches(subject: Any, subject_ep: Endpoint, inv: Inventory) -> bool:
    """``spec.subject`` is exactly one of ``namespaces`` (a namespace selector) or ``pods`` (both selectors)."""
    if not isinstance(subject, dict) or subject_ep.namespace is None:
        return False
    if "namespaces" in subject:
        return selector_matches(subject.get("namespaces") or {}, inv.ns_labels(subject_ep.namespace))
    if "pods" in subject:
        pods = subject.get("pods") or {}
        if not isinstance(pods, dict):
            return False
        return selector_matches(
            pods.get("namespaceSelector") or {}, inv.ns_labels(subject_ep.namespace)
        ) and selector_matches(pods.get("podSelector") or {}, subject_ep.labels)
    return False


def rules_of(spec: Any, direction: str) -> list[Any]:
    if not isinstance(spec, dict):
        return []
    rules = spec.get("ingress" if direction == "Ingress" else "egress")
    return rules if isinstance(rules, list) else []


def _subnet_of(
    inner: ipaddress.IPv4Network | ipaddress.IPv6Network,
    outer: ipaddress.IPv4Network | ipaddress.IPv6Network,
) -> bool:
    """True when ``inner`` is inside ``outer``. A v4 address is not inside a v6 prefix, and the reverse."""
    if isinstance(inner, ipaddress.IPv4Network) and isinstance(outer, ipaddress.IPv4Network):
        return inner.subnet_of(outer)
    if isinstance(inner, ipaddress.IPv6Network) and isinstance(outer, ipaddress.IPv6Network):
        return inner.subnet_of(outer)
    return False


def _overlaps(
    left: ipaddress.IPv4Network | ipaddress.IPv6Network,
    right: ipaddress.IPv4Network | ipaddress.IPv6Network,
) -> bool:
    if isinstance(left, ipaddress.IPv4Network) and isinstance(right, ipaddress.IPv4Network):
        return left.overlaps(right)
    if isinstance(left, ipaddress.IPv6Network) and isinstance(right, ipaddress.IPv6Network):
        return left.overlaps(right)
    return False


def outside_peer(peer: dict[str, Any], other: Endpoint) -> bool | None:
    """A ``nodes``, ``networks`` or ``domainNames`` peer.

    ``True`` matches, ``False`` does not, ``None`` might and cannot be checked from what was passed in. ``None``
    must stop the tier: skipping the rule and letting a later ``Allow`` decide is a guess.
    """
    if "networks" in peer:
        cidrs = _cidrs(peer.get("networks"))
        if cidrs is None:
            return None
        if other.external and other.net is not None:
            dest = other.net
            if any(_subnet_of(dest, c) for c in cidrs):
                return True
            if any(_overlaps(dest, c) for c in cidrs):
                return None
            return False
        if any(c.prefixlen == 0 for c in cidrs):
            return True
        return None
    if "nodes" in peer:
        # A node peer selects node addresses. A normal pod is not one. A host-network pod or a raw IP might be.
        if other.external or other.host_network:
            return None
        return False
    if "domainNames" in peer:
        # The caller named a workload or an IP, not a DNS name, so this peer does not select it.
        return False
    return False


def _cidrs(value: Any) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network] | None:
    if not isinstance(value, list):
        return None
    out: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for item in value:
        raw = item if isinstance(item, str) else (item.get("cidr") if isinstance(item, dict) else None)
        if not isinstance(raw, str):
            return None
        try:
            out.append(ipaddress.ip_network(raw, strict=False))
        except ValueError:
            return None
    return out


def _policy_decision(
    pol: dict[str, Any],
    actions: tuple[str, ...],
    subject_ep: Endpoint,
    other: Endpoint,
    direction: str,
    port: int | str,
    protocol: str,
    dest: Endpoint,
    inv: Inventory,
    notes: list[str],
) -> Decision | None:
    """This one policy's answer for this traffic: its first rule whose peer and ports both match, or ``None`` when
    the policy does not select the subject or no rule matches."""
    meta = pol.get("metadata") or {}
    # Every sentence below names this policy and this rule, and both names came out of the document: printed raw,
    # a `metadata.name` holding a newline forged a line of kube-noob's own output (G373, class 7).
    name = shown_ref(pol.get("kind"), meta.get("name") if isinstance(meta, dict) else None)
    spec = pol.get("spec") or {}
    if not subject_matches(spec.get("subject") if isinstance(spec, dict) else None, subject_ep, inv):
        return None
    for i, raw in enumerate(rules_of(spec, direction), 1):
        rule = raw if isinstance(raw, dict) else {}
        action = _str(rule.get("action"))
        label = shown_name(rule.get("name")) if _str(rule.get("name")) else f"rule {i}"
        if action not in actions:
            notes.append(
                f"{name} {direction.lower()} {label}: action "
                f"{shown_field(action) if action else '(empty)'} is not one of "
                f"{', '.join(actions)}; the rule is skipped rather than read as the nearest valid action"
            )
            continue
        peers = rule.get("from" if direction == "Ingress" else "to")
        peers = peers if isinstance(peers, list) else []
        if not _port_matches(rule.get("ports"), port, protocol, dest):
            continue
        matched = False
        unknown = False
        for peer in peers:
            if not isinstance(peer, dict):
                continue
            if "namespaces" in peer or "pods" in peer:
                if peer_matches(peer, other, inv):
                    matched = True
                    break
                continue
            if "nodes" in peer or "networks" in peer or "domainNames" in peer:
                got = outside_peer(peer, other)
                if got is True:
                    matched = True
                    break
                if got is None:
                    unknown = True
        if not matched:
            if unknown:
                return Decision(
                    "undetermined",
                    name,
                    label,
                    reason=(
                        f"{name} {direction.lower()} {label} has a nodes, networks or domainNames peer that "
                        f"might select {other.describe()} on {protocol} {port}, and kube-noob cannot check it. "
                        "A later rule is not allowed to allow the traffic instead."
                    ),
                )
            continue
        if action == "Pass":
            return Decision(
                "passed",
                name,
                label,
                f"{name} {direction.lower()} {label} passes {other.describe()} on {protocol} {port} down to the "
                "NetworkPolicies in the namespace.",
            )
        return Decision(
            "allow" if action == "Allow" else "deny",
            name,
            label,
            f"{'Allowed' if action == 'Allow' else 'Denied'} by {name} {direction.lower()} {label} "
            f"(priority {spec.get('priority')})."
            if pol.get("kind") == ANP_KIND
            else f"{'Allowed' if action == 'Allow' else 'Denied'} by {name} {direction.lower()} {label}.",
        )
    return None


def _evaluate(
    groups: list[list[dict[str, Any]]],
    actions: tuple[str, ...],
    subject_ep: Endpoint,
    other: Endpoint,
    direction: str,
    port: int | str,
    protocol: str,
    dest: Endpoint,
    inv: Inventory,
    notes: list[str],
) -> Decision:
    """The first group, in precedence order, in which any policy decides.

    ``groups`` is the tier's policies bucketed by the thing that orders them -- ``priority`` for
    AdminNetworkPolicy, and one policy per group where nothing orders them. Within a group nothing says which
    policy the API server picks, so a group whose matching policies disagree is reported ``undetermined`` rather
    than settled by the order the documents happened to arrive in.
    """
    for group in groups:
        decided: list[Decision] = []
        for pol in group:
            got = _policy_decision(pol, actions, subject_ep, other, direction, port, protocol, dest, inv, notes)
            if got is not None:
                decided.append(got)
        if not decided:
            continue
        if len({d.outcome for d in decided}) == 1:
            return decided[0]
        names = tuple(dict.fromkeys(d.policy for d in decided))
        spec = group[0].get("spec")
        priority = spec.get("priority") if isinstance(spec, dict) else None
        return Decision(
            "undetermined",
            policies=names,
            reason=(
                f"{' and '.join(names)} are both at priority {priority} and disagree about "
                f"{other.describe()} on {protocol} {port} "
                f"({', '.join(sorted({d.outcome for d in decided}))}). Two policies at one priority in one tier are "
                "undefined behaviour in the API, so which one the API server applies is not something kube-noob can "
                "work out from the manifests."
            ),
        )
    return Decision("nomatch")


def collect(inv: Inventory, objects: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(AdminNetworkPolicies in precedence order, BaselineAdminNetworkPolicies). Notes about a policy the API server
    would itself refuse are appended to ``inv.notes``, because such a manifest is a mistake to report rather than a
    policy to evaluate."""
    anps: list[tuple[int, int, dict[str, Any]]] = []
    banps: list[dict[str, Any]] = []
    for i, obj in enumerate(objects):
        if not isinstance(obj, dict):
            continue
        kind = _str(obj.get("kind"))
        meta = obj.get("metadata") or {}
        name = _str(meta.get("name") if isinstance(meta, dict) else "")
        ref = shown_ref(kind, name)
        if kind == ANP_KIND:
            spec = obj.get("spec") or {}
            priority = spec.get("priority") if isinstance(spec, dict) else None
            if not isinstance(priority, int) or isinstance(priority, bool) or not 0 <= priority <= PRIORITY_MAX:
                inv.notes.append(
                    f"{ref}: priority {shown_field(priority)} is outside 0-{PRIORITY_MAX}, which the API server "
                    "refuses, so this policy is not evaluated"
                )
                continue
            if priority > OVN_PRIORITY_MAX:
                inv.notes.append(
                    f"{ref}: priority {priority} is above {OVN_PRIORITY_MAX}, which OVN-Kubernetes does not "
                    "implement (it raises ANPWithUnsupportedPriority and the policy has no effect on the cluster); "
                    "it is not evaluated, so it does not decide this traffic"
                )
                continue
            anps.append((priority, i, obj))
        elif kind == BANP_KIND:
            if name != "default":
                inv.notes.append(
                    f"{ref}: a BaselineAdminNetworkPolicy is a singleton that must be named 'default'; the "
                    "API server refuses any other name, so this one is not evaluated"
                )
                continue
            banps.append(obj)
    anps.sort(key=lambda t: (t[0], t[1]))
    # Two policies at one priority in one tier is undefined behaviour in the API, so a config that relies on it is
    # fragile even in the runs where the tied policies happen to agree. Say it once, naming them.
    by_priority: dict[int, list[str]] = {}
    for priority, _, obj in anps:
        by_priority.setdefault(priority, []).append(shown_name((obj.get("metadata") or {}).get("name")))
    for priority, names in by_priority.items():
        if len(names) > 1:
            inv.notes.append(
                f"{', '.join(names)} are all at priority {priority}: the API does not define which "
                "AdminNetworkPolicy wins at one priority in one tier, so give them distinct priorities"
            )
    return [obj for _, _, obj in anps], banps


def tier_before(
    inv: Inventory,
    anps: list[dict[str, Any]],
    subject: Endpoint,
    other: Endpoint,
    direction: str,
    port: int | str,
    protocol: str,
    dest: Endpoint,
) -> Decision:
    """The AdminNetworkPolicy tier, which runs before any NetworkPolicy."""
    if not anps or subject.external:
        return Decision("nomatch")
    groups: list[list[dict[str, Any]]] = []
    for pol in anps:  # `collect` already sorted these by (priority, document order)
        spec = pol.get("spec")
        priority = spec.get("priority") if isinstance(spec, dict) else None
        last = (groups[-1][0].get("spec") or {}) if groups else None
        if groups and isinstance(last, dict) and last.get("priority") == priority:
            groups[-1].append(pol)
        else:
            groups.append([pol])
    return _evaluate(groups, ANP_ACTIONS, subject, other, direction, port, protocol, dest, inv, inv.notes)


def tier_after(
    inv: Inventory,
    banps: list[dict[str, Any]],
    subject: Endpoint,
    other: Endpoint,
    direction: str,
    port: int | str,
    protocol: str,
    dest: Endpoint,
) -> Decision:
    """The BaselineAdminNetworkPolicy tier, which runs only where no NetworkPolicy selects the pod."""
    if not banps or subject.external:
        return Decision("nomatch")
    groups = [[b] for b in banps]  # the baseline tier is the singleton `default`, so nothing can tie
    return _evaluate(groups, BANP_ACTIONS, subject, other, direction, port, protocol, dest, inv, inv.notes)
