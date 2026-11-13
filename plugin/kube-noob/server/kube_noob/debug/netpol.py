"""Would this connection be allowed? Kubernetes NetworkPolicy semantics, evaluated offline.

Given NetworkPolicies, the workloads they apply to (Pods, Deployments, StatefulSets, DaemonSets, ReplicaSets, Jobs,
CronJobs, DeploymentConfigs) and optionally Namespaces, decide whether a connection from a source to a destination on a
port is allowed. Both directions must allow it: egress from the source pod and ingress to the destination pod. Each
verdict names the policy and the rule that decided it, explains why every other rule did not match (wrong peer or
wrong port), and, when the answer is no, proposes the smallest NetworkPolicy that would allow it.

The same evaluation runs on objects read from a live cluster (read-only) through ``inventory_from_cluster``.

Three tiers decide, in order: AdminNetworkPolicy, then the NetworkPolicies in the namespace, then
BaselineAdminNetworkPolicy where no NetworkPolicy selects the pod (``kube_noob.debug.anp`` has the semantics). Where
the deciding tier has no determinate answer -- two AdminNetworkPolicies at one priority whose rules disagree, which
the API leaves undefined -- the verdict is ``undetermined`` and no fix is proposed, rather than a guess.

Those two tiers only decide on a cluster whose CNI enforces them. Pass the CNI (``cni="calico:3.32"``) and
``kube_noob.debug.cni`` says whether it does: a CNI documented as ignoring the tier makes every policy in it
``inertPolicies`` -- read, named, and not allowed to decide -- and a CNI nobody documents either way makes the
verdict ``undetermined``. Without the argument the OVN-Kubernetes semantics above are assumed, as before.

Not evaluated, and said so in every result: ClusterNetworkPolicy, OpenShift EgressFirewall and EgressNetworkPolicy,
CNI-specific policies (Cilium, Calico), host-network pods, and firewalls outside the cluster.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any

import yaml

from kube_noob.debug.steps import classify_step, split_comment
from kube_noob.yamlio import load_documents

IPNet = ipaddress.IPv4Network | ipaddress.IPv6Network

WORKLOAD_KINDS = (
    "Deployment",
    "StatefulSet",
    "DaemonSet",
    "DeploymentConfig",
    "ReplicaSet",
    "ReplicationController",
    "Job",
    "CronJob",
    "Pod",
)
_KIND_RANK = {k.lower(): i for i, k in enumerate(WORKLOAD_KINDS)}
ANP_KIND = "AdminNetworkPolicy"
BANP_KIND = "BaselineAdminNetworkPolicy"
#: Said in every offline answer whose input holds an admin-tier policy and no --cni (G279, third review).
ADMIN_TIER_DEFAULT_NOTE = (
    "admin-tier policies evaluated with OVN-Kubernetes semantics; pass --cni <name> for your CNI "
    "(Calico 3.32 and later ignore AdminNetworkPolicy; Cilium states no support for it)"
)
# Cluster-scoped kinds that sit ABOVE NetworkPolicy and that this evaluator does not read yet. A NetworkPolicy
# cannot override one, so when any of these is in the input, a namespace-scoped fix may be applied and change
# nothing -- the caveat below says so. `ClusterNetworkPolicy` (policy.networking.k8s.io/v1alpha2) is the API under
# active development at kubernetes-sigs/network-policy-api; the v1alpha1 pair this evaluator does read are listed
# upstream as "no longer actively developed".
_CNP_KIND = "ClusterNetworkPolicy"
# Kinds that are decided BEFORE any NetworkPolicy and that this evaluator does not read. Empty since P4 made
# ClusterNetworkPolicy evaluated, and deliberately not refilled with the two CNI kinds below: a Cilium
# clusterwide policy and a Calico GlobalNetworkPolicy are cluster-scoped and unread, but neither is "decided
# before any NetworkPolicy" the way an Admin tier is, and the summary says those words. They make the verdict
# undetermined through UNEVALUATED_POLICY_KINDS, which is what that protection actually keys off; this tuple
# only picks the stronger sentence, and it is empty because no unread kind earns it today.
CLUSTER_SCOPED_ABOVE_NETWORKPOLICY: tuple[str, ...] = ()
# Cluster-scoped kinds this evaluator records and does not read. A namespace deny does not answer the question
# while one of them is in the input: it can reverse that deny. An EgressFirewall, a namespace CiliumNetworkPolicy
# and a MultiNetworkPolicy are not in this set. The first does not decide pod-to-pod traffic, and the other two
# do not decide the primary interface, so calling the whole answer unknown because they were present would be a
# different lie. They stay on the "not evaluated" list.
UNEVALUATED_POLICY_KINDS = frozenset(
    {
        *CLUSTER_SCOPED_ABOVE_NETWORKPOLICY,
        "CiliumClusterwideNetworkPolicy",
        "GlobalNetworkPolicy",
    }
)
# The read-only command that lists the object. ClusterNetworkPolicy stays the singular the CLI already prints.
# The other two are the plurals on the published CRDs.
_RESOLVING_GET = {
    "ClusterNetworkPolicy": "clusternetworkpolicy",
    "CiliumClusterwideNetworkPolicy": "ciliumclusterwidenetworkpolicies",
    "GlobalNetworkPolicy": "globalnetworkpolicies",
}
OTHER_POLICY_KINDS = {
    ANP_KIND,
    BANP_KIND,
    _CNP_KIND,  # evaluated since P4, and still recorded here so a refused document is listed rather than lost
    *CLUSTER_SCOPED_ABOVE_NETWORKPOLICY,
    "EgressFirewall",
    "EgressNetworkPolicy",
    "CiliumNetworkPolicy",
    "CiliumClusterwideNetworkPolicy",
    "GlobalNetworkPolicy",
    "MultiNetworkPolicy",
}
NOT_EVALUATED = (
    "OpenShift EgressFirewall / EgressNetworkPolicy (egress to destinations outside the cluster)",
    "CNI-specific policies (Cilium, Calico) and firewalls or security groups outside the cluster",
    "pods with hostNetwork: true (NetworkPolicy does not apply to them on most network plugins)",
)
_LABEL_VALUE = re.compile(r"^[A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?\Z")
_DNS = re.compile(r"^[a-z0-9]([-a-z0-9.]*[a-z0-9])?\Z")
_PORT_NAME = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?\Z")
_LABEL_KEY = re.compile(r"^([a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?/)?[A-Za-z0-9]([-A-Za-z0-9_.]{0,61}[A-Za-z0-9])?\Z")


def _shell_safe_selector(labels: dict[str, str]) -> str | None:
    """``k=v,k2=v2`` for a command line, or None when a key or value is not valid label syntax (it came from a
    manifest or the cluster, so it could carry shell syntax)."""
    if not labels or not all(_LABEL_KEY.match(k) and (v == "" or _LABEL_VALUE.match(v)) for k, v in labels.items()):
        return None
    return ",".join(f"{k}={v}" for k, v in sorted(labels.items()))


def _labelstr(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


def _labels(d: Any) -> dict[str, str]:
    return {str(k): _labelstr(v) for k, v in d.items()} if isinstance(d, dict) else {}


@dataclass
class Endpoint:
    """One side of a connection: a workload's pods, a label set, or an address outside the cluster."""

    namespace: str | None
    ref: str
    labels: dict[str, str] = field(default_factory=dict)
    selector: dict[str, str] = field(default_factory=dict)  # labels that select it in a generated policy
    ports: dict[str, tuple[int, str]] = field(default_factory=dict)  # named container ports
    net: IPNet | None = None
    host_network: bool = False

    @property
    def external(self) -> bool:
        return self.net is not None

    def describe(self) -> str:
        if self.net is not None:
            return str(self.net) if self.net.num_addresses > 1 else str(self.net.network_address)
        return f"{self.namespace}/{self.ref}"


def selector_matches(sel: Any, labels: dict[str, str]) -> bool:
    """A Kubernetes label selector: matchLabels plus matchExpressions; ``{}`` selects everything."""
    if not isinstance(sel, dict):
        return False
    for k, v in (sel.get("matchLabels") or {}).items():
        if labels.get(str(k)) != _labelstr(v):
            return False
    for e in sel.get("matchExpressions") or []:
        key = str(e.get("key"))
        op = e.get("operator")
        values = [_labelstr(v) for v in e.get("values") or []]
        if op == "In" and labels.get(key) not in values:
            return False
        if op == "NotIn" and key in labels and labels[key] in values:
            return False
        if op == "Exists" and key not in labels:
            return False
        if op == "DoesNotExist" and key in labels:
            return False
        if op not in {"In", "NotIn", "Exists", "DoesNotExist"}:
            return False
    return True


_SELECTOR_OPS = ("In", "NotIn", "Exists", "DoesNotExist")


def selector_problem(sel: Any) -> str | None:
    """Why the API server would refuse this label selector, or None when it is well formed.

    An invalid selector is not a selector that matches nothing. ``operator: Exist`` (for ``Exists``) makes
    ``selector_matches`` return False for every pod, so a default-deny NetworkPolicy reads as "selects no pods",
    the policy reads as absent and the verdict flips from denied to allowed -- on a policy the API server would
    have rejected outright. Dropping an unreadable policy always widens the answer, so these are reported as
    undetermined instead of evaluated (see docs/limits.md, "a policy document that cannot be parsed is not the
    same as a policy that does not exist").
    """
    if sel is None:
        return None
    if not isinstance(sel, dict):
        return f"selector is {type(sel).__name__}, not a mapping"
    labels = sel.get("matchLabels")
    if labels is not None and not isinstance(labels, dict):
        return f"matchLabels is {type(labels).__name__}, not a mapping"
    exprs = sel.get("matchExpressions")
    if exprs is not None and not isinstance(exprs, list):
        return f"matchExpressions is {type(exprs).__name__}, not a list"
    for e in exprs or []:
        if not isinstance(e, dict):
            return f"matchExpressions entry is {type(e).__name__}, not a mapping"
        op = e.get("operator")
        if op not in _SELECTOR_OPS:
            return f"matchExpressions operator {op!r} is not one of {', '.join(_SELECTOR_OPS)}"
        if op in ("In", "NotIn") and not (isinstance(e.get("values"), list) and e.get("values")):
            return f"matchExpressions operator {op} needs a non-empty values list"
    return None


def policy_problem(pol: dict[str, Any]) -> str | None:
    """The first reason the API server would refuse this NetworkPolicy's selectors, or None."""
    spec = pol.get("spec")
    if not isinstance(spec, dict):
        return f"spec is {type(spec).__name__}, not a mapping"
    why = selector_problem(spec.get("podSelector"))
    if why:
        return f"spec.podSelector: {why}"
    types = spec.get("policyTypes")
    # A scalar is not a list of directions: iterating "Ingress" yields letters, so the policy read as selecting no
    # direction and the answer as allowed (G279). The API server accepts only these two values.
    if types is not None and (not isinstance(types, list) or any(t not in ("Ingress", "Egress") for t in types)):
        return f"spec.policyTypes is {types!r:.60}, not a list of Ingress and Egress"
    for direction in ("ingress", "egress"):
        rules = spec.get(direction)
        if rules is None:
            continue
        if not isinstance(rules, list):
            return f"spec.{direction} is {type(rules).__name__}, not a list"
        for i, rule in enumerate(rules):
            if not isinstance(rule, dict):
                return f"spec.{direction}[{i}] is {type(rule).__name__}, not a mapping"
            peers = rule.get("from") if direction == "ingress" else rule.get("to")
            side = "from" if direction == "ingress" else "to"
            if peers is not None and not isinstance(peers, list):
                return f"spec.{direction}[{i}].{side} is {type(peers).__name__}, not a list"
            ports = rule.get("ports")
            if ports is not None and not isinstance(ports, list):
                return f"spec.{direction}[{i}].ports is {type(ports).__name__}, not a list"
            for j, peer in enumerate(peers or []):
                if not isinstance(peer, dict):
                    continue
                for sel_field in ("podSelector", "namespaceSelector"):
                    why = selector_problem(peer.get(sel_field))
                    if why:
                        return f"spec.{direction}[{i}].{side}[{j}].{sel_field}: {why}"
    return None


def describe_selector(sel: Any) -> str:
    if not isinstance(sel, dict):
        return "nothing"
    parts = [f"{k}={_labelstr(v)}" for k, v in sorted((sel.get("matchLabels") or {}).items())]
    for e in sel.get("matchExpressions") or []:
        vals = ",".join(_labelstr(v) for v in e.get("values") or [])
        parts.append(f"{e.get('key')} {e.get('operator')}" + (f" ({vals})" if vals else ""))
    return ", ".join(parts) or "all"


def _template(kind: str, data: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    spec = data.get("spec") or {}
    if kind == "Pod":
        return data.get("metadata") or {}, spec
    if kind == "CronJob":
        tpl = ((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}
    else:
        tpl = spec.get("template") or {}
    return tpl.get("metadata") or {}, tpl.get("spec") or {}


def _endpoint_from(kind: str, data: dict[str, Any], default_ns: str) -> Endpoint:
    meta = data.get("metadata") or {}
    ns = str(meta.get("namespace") or default_ns)
    tmeta, tspec = _template(kind, data)
    labels = _labels(tmeta.get("labels"))
    sel = (data.get("spec") or {}).get("selector")
    if kind in {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"} and isinstance(sel, dict):
        selector = _labels(sel.get("matchLabels")) or labels
    elif kind in {"DeploymentConfig", "ReplicationController"} and isinstance(sel, dict):
        selector = _labels(sel) or labels
    else:
        selector = labels
    ports: dict[str, tuple[int, str]] = {}
    for c in tspec.get("containers") or []:
        for p in (c or {}).get("ports") or []:
            if isinstance(p, dict) and p.get("name") and isinstance(p.get("containerPort"), int):
                ports[str(p["name"])] = (p["containerPort"], str(p.get("protocol") or "TCP").upper())
    return Endpoint(
        namespace=ns,
        ref=f"{kind.lower()}/{meta.get('name', '<unnamed>')}",
        labels=labels,
        selector=selector,
        ports=ports,
        host_network=bool(tspec.get("hostNetwork")),
    )


class Inventory:
    """NetworkPolicies, workloads and namespace labels: what the evaluation reads."""

    def __init__(
        self,
        objects: list[dict[str, Any]],
        default_namespace: str = "default",
        cni: str | None = None,
        *,
        cni_unread: bool = False,
        cni_unknown: str = "could not be read",
    ) -> None:
        self.default_namespace = default_namespace
        # Set when the live read of the CNI failed (G279). Not the same as no CNI being named: with no name the
        # OVN-Kubernetes semantics are the documented default, and with a failed read this may be the Calico
        # 3.32 cluster that ignores the admin tier. See _cni_not_read.
        self.cni_unread = cni_unread
        self.cni_unknown = cni_unknown  # "could not be read", or "was not identified" (G279)
        self.policies: list[dict[str, Any]] = []
        self.workloads: dict[tuple[str, str, str], Endpoint] = {}
        self.namespace_labels: dict[str, dict[str, str]] = {}
        self.other_policies: list[str] = []
        self.notes: list[str] = []
        self.tier_unreadable: list[str] = []
        self.invalid_policies: list[str] = []
        # Cluster-scoped policies kube-noob READ and then could not evaluate: a newer apiVersion, a subject
        # shape it does not know, a document the API server would refuse. Before P4 any ClusterNetworkPolicy
        # made the verdict undetermined because none was evaluated; once most of them are, the few that still
        # cannot be must keep doing it, or making the kind readable turned a refusal into a clean answer.
        self.unreadable_cluster_scoped: list[str] = []
        self.admin: list[dict[str, Any]] = []
        self.baseline: list[dict[str, Any]] = []
        # An admin policy the cluster's CNI does not enforce, and one whose enforcement is unknown. Both are read
        # and then NOT evaluated: see _apply_cni.
        self.inert: list[dict[str, str]] = []
        self.enforcement_unknown: list[str] = []
        self.enforcement_unknown_why = "whether this CNI enforces that tier is not documented either way"
        # Which policy APIs have no stated enforcement: "v1alpha1" (AdminNetworkPolicy, BaselineAdminNetworkPolicy)
        # and "v1alpha2" (ClusterNetworkPolicy). A CNI enforces one, the other, both or neither, so every
        # combination is a reading check_reachability evaluates (G279).
        self.unknown_apis: set[str] = set()
        # Namespaces whose labels a live read could not get (G279); see _reads_namespace_labels.
        self.namespace_unread: list[str] = []
        # Namespaces whose NetworkPolicy list a live read could not get: a direction there is not evaluated (G279).
        self.np_unread: list[str] = []
        for obj in objects:
            if not isinstance(obj, dict):
                continue
            kind = str(obj.get("kind", ""))
            meta = obj.get("metadata") or {}
            name = str(meta.get("name", ""))
            if kind == "NetworkPolicy":
                pol = dict(obj)
                pol_ns = str(meta.get("namespace") or default_namespace)
                pol["metadata"] = {**meta, "namespace": pol_ns}
                why = policy_problem(pol)
                if why:
                    # Not evaluated and not treated as absent: an unreadable policy only ever widens the answer.
                    self.invalid_policies.append(f"NetworkPolicy/{pol_ns}/{name} ({why})")
                else:
                    self.policies.append(pol)
            elif kind == "Namespace":
                self.namespace_labels[name] = _labels(meta.get("labels"))
            elif kind in WORKLOAD_KINDS:
                ep = _endpoint_from(kind, obj, default_namespace)
                self.workloads[(str(ep.namespace), kind.lower(), name)] = ep
            elif kind in OTHER_POLICY_KINDS:
                ns = meta.get("namespace")
                self.other_policies.append(f"{kind}/{ns + '/' if ns else ''}{name}")
        from kube_noob.debug.anp import collect
        from kube_noob.debug.cnp import KIND as CNP_KIND
        from kube_noob.debug.cnp import collect as collect_cnp

        self.admin, self.baseline = collect(self, objects)
        # The v1alpha2 ClusterNetworkPolicy tiers, which Calico 3.32 enforces in place of the two above.
        # Imported here rather than at module scope: `cnp` imports this module for Endpoint and Inventory.
        self.cnp_admin, self.cnp_baseline = collect_cnp(self, objects)
        evaluated_kinds = {ANP_KIND, BANP_KIND}
        if self.admin or self.baseline:
            # Evaluated now, so they must not also be listed as policies that were only found.
            self.other_policies = [p for p in self.other_policies if p.split("/", 1)[0] not in evaluated_kinds]
        if self.cnp_admin.policies or self.cnp_baseline.policies:
            self.other_policies = [p for p in self.other_policies if p.split("/", 1)[0] != CNP_KIND]
        if (self.admin or self.baseline) and (self.cnp_admin.policies or self.cnp_baseline.policies):
            # A cluster mid-migration. Which API the CNI honours decides the answer, and no manifest says: the
            # verdict below is still reported, with the policy that produced it named, so the reader can see
            # whether it came from the API their CNI actually enforces.
            self.notes.append(
                "both AdminNetworkPolicy/BaselineAdminNetworkPolicy (v1alpha1) and ClusterNetworkPolicy "
                "(v1alpha2) are in the input. A CNI enforces one API or the other, not both, so which one "
                "decides on your cluster depends on the CNI and its version; the verdict below names the "
                "policy it came from"
            )
        self._apply_cni(cni)

    def _apply_cni(self, cni: str | None) -> None:
        """Drop the admin tier when the named CNI does not enforce it, or when nobody says whether it does.

        Evaluating ``AdminNetworkPolicy`` assumes the CNI applies it. Calico stopped doing so in 3.32 "without
        reporting an error", so the assumption is wrong on a current Calico cluster and the verdict it produces is
        a deny that is not happening. Dropping the tier is the right answer only where that is documented: where
        it is not, the policies are dropped too and the verdict becomes undetermined, because evaluating guesses
        enforcement and ignoring guesses the reverse. ``kube_noob.debug.cni`` holds the table and its sources.
        """
        if not cni:
            if self.cni_unread:
                self._cni_not_read()
            elif self.admin or self.baseline:
                # Offline, with no --cni, the admin tier is evaluated as OVN-Kubernetes enforces it (the owner's
                # default, G207). That stays; what changes is that the answer says so (G279, third review).
                self.notes.append(ADMIN_TIER_DEFAULT_NOTE)
            return
        from kube_noob.debug.cni import REPLACEMENT, admin_tier_reason, admin_tier_support, parse_cni

        # Parsed before the empty-tier check, so a library caller's typo is refused rather than ignored whenever
        # the bundle happens to carry no admin policy.
        name, version = parse_cni(cni)
        self._apply_cni_to_cnp(name, version)
        if not (self.admin or self.baseline):
            return
        support = admin_tier_support(name, version)
        if support == "enforced":
            return
        reason = admin_tier_reason(name, version, support)
        refs = [
            f"{kind}/{(pol.get('metadata') or {}).get('name', '')!s}"
            for kind, tier in ((ANP_KIND, self.admin), (BANP_KIND, self.baseline))
            for pol in tier
        ]
        if support == "not-enforced":
            # Dropped only here, where the CNI is documented as ignoring them. No note beside this: `inertPolicies`
            # and the summary both carry it, and the CLI prints them, so a note would repeat the same sentence.
            self.admin, self.baseline = [], []
            self.inert = [{"policy": ref, "reason": reason, "replacement": REPLACEMENT} for ref in refs]
            return
        # NOT dropped here. An unknown must not read as a pass, and it must not discard an answer that is the
        # same under both readings either: check_reachability evaluates the tier and withholds it, and only calls
        # the question unanswerable when the two disagree.
        self.enforcement_unknown = refs
        self.unknown_apis.add("v1alpha1")
        self.notes.append(f"{', '.join(refs)}: {reason}.")

    def _cni_not_read(self) -> None:
        """The live read of the CNI failed, so no tier above NetworkPolicy is known to be enforced or ignored.

        Withheld exactly like a tier whose enforcement upstream does not document: evaluated, then the answer is
        undetermined only where the enforced and the ignored readings disagree. Before G279 a failed read kept the
        OVN-Kubernetes assumption, which on a Calico 3.32 cluster is a deny that is not happening (roadmap P7).
        """
        refs = [
            f"{kind}/{(pol.get('metadata') or {}).get('name', '')!s}"
            for kind, tier in ((ANP_KIND, self.admin), (BANP_KIND, self.baseline))
            for pol in tier
        ] + [
            f"{_CNP_KIND}/{(pol.get('metadata') or {}).get('name', '')!s}"
            for tier in (self.cnp_admin, self.cnp_baseline)
            for pol in tier.policies
        ]
        if not refs:
            return
        if self.admin or self.baseline:
            self.unknown_apis.add("v1alpha1")
        if self.cnp_admin.policies or self.cnp_baseline.policies:
            self.unknown_apis.add("v1alpha2")
        self.enforcement_unknown += refs
        self.enforcement_unknown_why = (
            f"the cluster's CNI {self.cni_unknown}, so whether it enforces that tier is not known"
        )
        self.notes.append(
            f"{', '.join(refs)}: the cluster's CNI {self.cni_unknown}, so whether it enforces this tier is not known."
        )

    def _apply_cni_to_cnp(self, name: str, version: str | None) -> None:
        """The same question for the v1alpha2 tiers, and NOT the inverse of the one above.

        "Calico 3.31 does not enforce ClusterNetworkPolicy" and "Calico 3.32 does not enforce
        AdminNetworkPolicy" are two separate facts, and a CNI that enforces neither would be read as enforcing
        the other if one answer were derived from the other. So the table is its own, and says nothing where
        upstream says nothing.
        """
        from kube_noob.debug.cni import cnp_reason, cnp_support

        if not (self.cnp_admin.policies or self.cnp_baseline.policies):
            return
        support = cnp_support(name, version)
        if support == "enforced":
            return
        refs = [
            f"{_CNP_KIND}/{(pol.get('metadata') or {}).get('name', '')!s}"
            for tier in (self.cnp_admin, self.cnp_baseline)
            for pol in tier.policies
        ]
        reason = cnp_reason(name, version, support)
        if support == "not-enforced":
            import kube_noob.debug.cnp as _cnp_mod

            self.cnp_admin = _cnp_mod.Tier("Admin", ())
            self.cnp_baseline = _cnp_mod.Tier("Baseline", ())
            self.inert += [{"policy": ref, "reason": reason, "replacement": "NetworkPolicy"} for ref in refs]
            return
        # Kept and evaluated, then withheld where it changes the answer: the same treatment the v1alpha1 tiers
        # get when nobody states whether the CNI applies them.
        self.enforcement_unknown += refs
        self.unknown_apis.add("v1alpha2")
        self.notes.append(f"{', '.join(refs)}: {reason}.")

    def with_tiers(self, v1alpha1: bool, v1alpha2: bool) -> Inventory:
        """A shallow view of this inventory with the v1alpha1 pair, the v1alpha2 pair, or both emptied: one
        enforcement reading. ``True`` keeps that API's policies as they are."""
        import copy

        import kube_noob.debug.cnp as _cnp_mod

        view = copy.copy(self)
        if not v1alpha1:
            view.admin, view.baseline = [], []
        if not v1alpha2:
            view.cnp_admin = _cnp_mod.Tier("Admin", ())
            view.cnp_baseline = _cnp_mod.Tier("Baseline", ())
        return view

    def without_admin_tier(self) -> Inventory:
        """A shallow view of this inventory with EVERY admin tier empty, for the second reading above.

        All four of them. Clearing only the v1alpha1 pair left the v1alpha2 tiers in both readings, so the two
        always agreed, the withholding never fired, and a ClusterNetworkPolicy whose enforcement nobody states
        decided the answer while the page said both readings agreed -- an unknown read as a fact.
        """
        import copy

        import kube_noob.debug.cnp as _cnp_mod

        bare = copy.copy(self)
        bare.admin, bare.baseline = [], []
        bare.cnp_admin = _cnp_mod.Tier("Admin", ())
        bare.cnp_baseline = _cnp_mod.Tier("Baseline", ())
        return bare

    @classmethod
    def from_yaml(cls, text: str, default_namespace: str = "default", cni: str | None = None) -> Inventory:
        return cls([d.data for d in load_documents(text)], default_namespace, cni)

    def ns_labels(self, ns: str) -> dict[str, str]:
        return {**self.namespace_labels.get(ns, {}), "kubernetes.io/metadata.name": ns}

    def known(self) -> list[str]:
        return [f"{ns}/{kind}/{name}" for ns, kind, name in sorted(self.workloads)][:25]

    def resolve(self, spec: str) -> Endpoint:
        """``ns/name``, ``ns/kind/name``, ``ns:key=value,key2=value2``, or an IP address / CIDR outside the cluster."""
        spec = spec.strip()
        if spec.startswith("ip:"):
            spec = spec[3:]
        try:
            net = ipaddress.ip_network(spec, strict=False)
        except ValueError:
            net = None
        if net is not None:
            return Endpoint(namespace=None, ref=str(net), net=net)
        if ":" in spec and "=" in spec:
            ns, _, sel = spec.partition(":")
            labels: dict[str, str] = {}
            for part in sel.split(","):
                k, eq, v = part.partition("=")
                if not eq or not _LABEL_KEY.match(k.strip()) or not _LABEL_VALUE.match(v.strip() or "x"):
                    raise ValueError(f"bad label in {spec!r}: use ns:key=value,key2=value2")
                labels[k.strip()] = v.strip()
            if not _DNS.match(ns):
                raise ValueError(f"bad namespace in {spec!r}")
            return Endpoint(namespace=ns, ref=f"pods {sel}", labels=labels, selector=dict(labels))
        parts = spec.split("/")
        if len(parts) == 3:
            ns, kind, name = parts
            ep = self.workloads.get((ns, kind.lower(), name))
            if ep is None:
                raise ValueError(
                    f"{spec} is not in the manifests; known workloads: {', '.join(self.known()) or 'none'}"
                )
            return ep
        if len(parts) == 2:
            ns, name = parts
            hits = sorted(
                ((k, ep) for (n, k, nm), ep in self.workloads.items() if n == ns and nm == name),
                key=lambda kv: _KIND_RANK.get(kv[0], 99),
            )
            if hits:
                return hits[0][1]
            raise ValueError(f"{spec} is not in the manifests; known workloads: {', '.join(self.known()) or 'none'}")
        named = [ep for (_, _, nm), ep in self.workloads.items() if nm == spec]
        if len(named) == 1:
            return named[0]
        raise ValueError(
            f"use namespace/name for {spec!r} (or ns:key=value for a label set); known workloads: "
            f"{', '.join(self.known()) or 'none'}"
        )


def policy_types(spec: dict[str, Any]) -> set[str]:
    types = spec.get("policyTypes")
    if types:
        return {str(t) for t in types}
    out = {"Ingress"}
    if spec.get("egress"):
        out.add("Egress")
    return out


def _peer_matches(peer: dict[str, Any], policy_ns: str, other: Endpoint, inv: Inventory) -> tuple[bool, str]:
    if "ipBlock" in peer:
        block = peer.get("ipBlock") or {}
        try:
            cidr = ipaddress.ip_network(str(block.get("cidr")), strict=False)
            excepts = [ipaddress.ip_network(str(x), strict=False) for x in block.get("except") or []]
        except ValueError:
            return False, f"ipBlock {block.get('cidr')} (not a valid CIDR)"
        label = f"ipBlock {cidr}" + (f" except {', '.join(str(x) for x in excepts)}" if excepts else "")
        if other.net is None:
            return False, f"{label} (matches addresses outside the cluster, not pods)"
        inside = other.net.version == cidr.version and other.net.subnet_of(cidr)  # type: ignore[arg-type]
        excluded = any(other.net.version == x.version and other.net.overlaps(x) for x in excepts)
        return inside and not excluded, label
    ns_sel, pod_sel = peer.get("namespaceSelector"), peer.get("podSelector")
    if ns_sel is None and pod_sel is None:
        return False, "an empty peer (matches nothing)"
    if ns_sel is not None:
        where = f"namespaces {describe_selector(ns_sel)}"
    else:
        where = f"namespace {policy_ns}"
    who = f"pods {describe_selector(pod_sel)}" if pod_sel is not None else "all pods"
    label = f"{who} in {where}"
    if other.net is not None:
        return False, label
    if ns_sel is not None:
        if not selector_matches(ns_sel, inv.ns_labels(str(other.namespace))):
            return False, label
    elif other.namespace != policy_ns:
        return False, label
    if pod_sel is not None and not selector_matches(pod_sel, other.labels):
        return False, label
    return True, label


def _port_matches(rule_ports: Any, port: int | str, protocol: str, dest: Endpoint) -> tuple[bool, str]:
    if not rule_ports:
        return True, "all ports"
    number = port if isinstance(port, int) else (dest.ports.get(port) or (None, ""))[0]
    labels = []
    ok = False
    for entry in rule_ports:
        rp = entry or {}
        proto = str(rp.get("protocol") or "TCP").upper()
        p = rp.get("port")
        end = rp.get("endPort")
        labels.append(f"{proto} {p if p is not None else 'any'}" + (f"-{end}" if end else ""))
        if proto != protocol or ok:
            continue
        if p is None:
            ok = True
        elif isinstance(p, int) or (isinstance(p, str) and p.isdigit()):
            lo = int(p)
            hi = int(end) if end else lo
            ok = number is not None and lo <= number <= hi
        else:  # a named port resolves against the destination pod's container ports
            named = dest.ports.get(str(p))
            ok = (isinstance(port, str) and p == port) or (
                named is not None and number is not None and named[0] == number and named[1] == protocol
            )
    return ok, ", ".join(labels)


def _direction(
    inv: Inventory, subject: Endpoint, other: Endpoint, direction: str, port: int | str, protocol: str, dest: Endpoint
) -> dict[str, Any]:
    """Does this traffic leave ``subject`` (Egress) or reach it (Ingress)?

    Three tiers decide, in order: AdminNetworkPolicy, then the NetworkPolicies in the namespace, then
    BaselineAdminNetworkPolicy where no NetworkPolicy selects the pod. ``kube_noob.debug.anp`` has the semantics.
    """
    from kube_noob.debug.anp import tier_after, tier_before
    from kube_noob.debug.cnp import KIND as CNP_KIND
    from kube_noob.debug.cnp import tier_after as cnp_after
    from kube_noob.debug.cnp import tier_before as cnp_before

    # The current API first. v1alpha2 ClusterNetworkPolicy replaces the v1alpha1 pair, and where a cluster runs
    # both, the Admin tier of the newer API is the one upstream puts at the top. A cluster with both is noted by
    # the Inventory, because which one the CNI honours is not something a manifest says.
    cnp_admin = cnp_before(inv, inv.cnp_admin, subject, other, direction, port, protocol, dest)
    if cnp_admin.outcome == "undetermined":
        return {
            "evaluated": False,
            "undetermined": True,
            "tier": CNP_KIND,
            "cnpTier": "Admin",
            "allowed": False,  # an unknown must never read as a pass
            "tiedPolicies": list(cnp_admin.policies),
            "reason": cnp_admin.reason,
        }
    if cnp_admin.outcome in ("allow", "deny"):
        return {
            "evaluated": True,
            "tier": CNP_KIND,
            "cnpTier": "Admin",
            "isolated": cnp_admin.outcome == "deny",
            "allowed": cnp_admin.outcome == "allow",
            "policy": cnp_admin.policy,
            "rule": cnp_admin.rule,
            "reason": cnp_admin.reason,
        }
    admin = tier_before(inv, inv.admin, subject, other, direction, port, protocol, dest)
    if admin.outcome == "undetermined":
        return {
            "evaluated": False,
            "undetermined": True,
            "tier": ANP_KIND,
            "allowed": False,  # an unknown must never read as a pass
            "tiedPolicies": list(admin.policies),
            "reason": admin.reason,
        }
    if admin.outcome in ("allow", "deny"):
        return {
            "evaluated": True,
            "tier": ANP_KIND,
            "isolated": admin.outcome == "deny",
            "allowed": admin.outcome == "allow",
            "policy": admin.policy,
            "rule": admin.rule,
            "reason": admin.reason,
        }
    np = _networkpolicy_tier(inv, subject, other, direction, port, protocol, dest)
    passed_by = next((d for d in (cnp_admin, admin) if d.outcome == "passed"), None)
    if passed_by is not None:
        np["passedBy"] = passed_by.policy
        np["reason"] = f"{passed_by.reason} {np['reason']}"
    if np.get("isolated") or not np.get("evaluated"):
        return np
    base = tier_after(inv, inv.baseline, subject, other, direction, port, protocol, dest)
    if base.outcome == "nomatch":
        # The v1alpha2 Baseline tier, which unlike the v1alpha1 singleton can hold several policies ordered by
        # priority -- so unlike the branch below, a tie here is reachable.
        cnp_base = cnp_after(inv, inv.cnp_baseline, subject, other, direction, port, protocol, dest)
        if cnp_base.outcome == "undetermined":
            return {
                "evaluated": False,
                "undetermined": True,
                "tier": CNP_KIND,
                "cnpTier": "Baseline",
                "allowed": False,
                "tiedPolicies": list(cnp_base.policies),
                "reason": cnp_base.reason,
            }
        if cnp_base.outcome in ("allow", "deny"):
            return {
                "evaluated": True,
                "tier": CNP_KIND,
                "cnpTier": "Baseline",
                "isolated": cnp_base.outcome == "deny",
                "allowed": cnp_base.outcome == "allow",
                "policy": cnp_base.policy,
                "rule": cnp_base.rule,
                "reason": cnp_base.reason,
            }
    if base.outcome == "undetermined":  # unreachable while the baseline is a singleton; kept so it cannot regress
        return {
            "evaluated": False,
            "undetermined": True,
            "tier": BANP_KIND,
            "allowed": False,
            "tiedPolicies": list(base.policies),
            "reason": base.reason,
        }
    if base.outcome in ("allow", "deny"):
        return {
            "evaluated": True,
            "tier": BANP_KIND,
            "isolated": base.outcome == "deny",
            "allowed": base.outcome == "allow",
            "policy": base.policy,
            "rule": base.rule,
            "reason": f"{np['reason']} {base.reason}",
        }
    return np


def _networkpolicy_tier(
    inv: Inventory, subject: Endpoint, other: Endpoint, direction: str, port: int | str, protocol: str, dest: Endpoint
) -> dict[str, Any]:
    """Does ``subject``'s namespace let this traffic out (Egress) or in (Ingress)?"""
    word = direction.lower()
    if subject.external:
        return {
            "evaluated": False,
            "tier": "NetworkPolicy",
            "allowed": True,
            "reason": f"{subject.describe()} is outside the cluster; no NetworkPolicy governs its {word}.",
        }
    if subject.namespace in inv.np_unread:
        # The list that would decide this direction was never read. "No NetworkPolicy selects it, so all traffic
        # is allowed" was the reason this direction gave, under an undetermined verdict (G279).
        return {
            "evaluated": False,
            "tier": "NetworkPolicy",
            "allowed": None,
            "undetermined": True,
            "reason": f"The NetworkPolicies in {subject.namespace} could not be read, so whether they let this "
            f"{word} through is not known.",
        }
    if subject.host_network:
        return {
            "evaluated": False,
            "tier": "NetworkPolicy",
            "allowed": False,
            "undetermined": True,
            "reason": f"{subject.describe()} uses hostNetwork; NetworkPolicy does not apply to its {word} on most "
            "network plugins, so this direction is unknown rather than allowed.",
        }
    selecting = [
        p
        for p in inv.policies
        if p["metadata"]["namespace"] == subject.namespace
        and selector_matches((p.get("spec") or {}).get("podSelector") or {}, subject.labels)
        and direction in policy_types(p.get("spec") or {})
    ]
    if not selecting:
        return {
            "evaluated": True,
            "tier": "NetworkPolicy",
            "isolated": False,
            "allowed": True,
            "policies": [],
            "reason": f"No NetworkPolicy in {subject.namespace} selects {subject.describe()} for {direction}, so all "
            f"{word} traffic is allowed.",
        }
    decisions: list[dict[str, Any]] = []
    for pol in selecting:
        spec = pol.get("spec") or {}
        rules = spec.get("ingress" if direction == "Ingress" else "egress") or []
        name = f"{pol['metadata']['namespace']}/{pol['metadata'].get('name')}"
        verdicts = []
        allowing = None
        for i, raw in enumerate(rules, 1):
            rule = raw or {}
            peers = rule.get("from" if direction == "Ingress" else "to") or []
            if peers:
                results = [_peer_matches(p or {}, pol["metadata"]["namespace"], other, inv) for p in peers]
                peer_ok = any(ok for ok, _ in results)
                peer_label = "; ".join(lbl for _, lbl in results)
            else:
                peer_ok, peer_label = True, "anywhere"
            port_ok, port_label = _port_matches(rule.get("ports"), port, protocol, dest)
            verdicts.append(
                {
                    "rule": i,
                    "allows": peer_ok and port_ok,
                    "peer": peer_label,
                    "peerMatches": peer_ok,
                    "ports": port_label,
                    "portMatches": port_ok,
                }
            )
            if peer_ok and port_ok and allowing is None:
                allowing = i
        decisions.append(
            {
                "policy": name,
                "allows": allowing is not None,
                "rule": allowing,
                "rules": verdicts,
                **({} if rules else {"note": f"no {word} rules: denies all {word} for the pods it selects"}),
            }
        )
    allowed = any(d["allows"] for d in decisions)
    if allowed:
        first = next(d for d in decisions if d["allows"])
        reason = f"Allowed by {first['policy']}, {word} rule {first['rule']}."
    else:
        names = ", ".join(str(d["policy"]) for d in decisions)
        reason = (
            f"{len(decisions)} NetworkPolic{'y' if len(decisions) == 1 else 'ies'} ({names}) "
            f"select{'s' if len(decisions) == 1 else ''} "
            f"{subject.describe()} for {direction}, and no rule allows {other.describe()} on {protocol} {port}."
        )
    return {
        "evaluated": True,
        "tier": "NetworkPolicy",
        "isolated": True,
        "allowed": allowed,
        "policies": decisions,
        "reason": reason,
    }


def _dns_name(*parts: str) -> str:
    raw = "-".join(re.sub(r"[^a-z0-9-]+", "-", p.lower()).strip("-") for p in parts if p)
    return raw[:63].rstrip("-") or "allow-traffic"


def _short(ep: Endpoint) -> str:
    return ep.ref.split("/")[-1] if ep.net is None else "external"


def _allow_policy(direction: str, subject: Endpoint, other: Endpoint, port: int | str, protocol: str) -> str:
    peer: dict[str, Any]
    if other.net is not None:
        peer = {"ipBlock": {"cidr": str(other.net)}}
    else:
        peer = {"podSelector": {"matchLabels": dict(other.selector)}}
        if other.namespace != subject.namespace:
            peer = {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": other.namespace}}, **peer}
    src, dst = (other, subject) if direction == "Ingress" else (subject, other)
    name = _dns_name("allow", _short(src), "to", _short(dst), str(port))
    policy = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": name, "namespace": subject.namespace},
        "spec": {
            "podSelector": {"matchLabels": dict(subject.selector)},
            "policyTypes": [direction],
            direction.lower(): [
                {"from" if direction == "Ingress" else "to": [peer], "ports": [{"protocol": protocol, "port": port}]}
            ],
        },
    }
    return yaml.safe_dump(policy, sort_keys=False)


def _step(check: str) -> dict[str, str]:
    cmd, why = split_comment(check)
    return {"command": cmd, **({"why": why} if why else {})}


def _same_answer(a: dict[str, Any], b: dict[str, Any]) -> bool:
    """Do two readings of one direction reach the same verdict?

    Only the three states are compared -- allowed, denied, undetermined -- not which policy decided or why. A
    reading that reaches the same state by another route does not leave the question open; it changes the
    explanation, and the explanation reported is the one that holds under both (the withheld reading).
    """
    return (
        bool(a["allowed"]) == bool(b["allowed"])
        and bool(a.get("undetermined")) == bool(b.get("undetermined"))
        and bool(a.get("evaluated", True)) == bool(b.get("evaluated", True))
    )


def _selector_reads_labels(sel: Any) -> bool:
    """A label selector that needs a namespace's labels: any key but ``kubernetes.io/metadata.name``, which is the
    namespace's own name and known without a read. ``{}`` matches every namespace and reads nothing."""
    if not isinstance(sel, dict):
        return False
    keys = set((sel.get("matchLabels") or {}) if isinstance(sel.get("matchLabels"), dict) else {})
    for expr in sel.get("matchExpressions") or []:
        keys.add(expr.get("key") if isinstance(expr, dict) else None)
    return bool(keys - {"kubernetes.io/metadata.name"})


def _reads_namespace_labels(inv: Inventory) -> bool:
    """Whether any evaluated policy selects namespaces by label: a NetworkPolicy ``namespaceSelector``, or the
    ``namespaces`` selector of an admin-tier subject or peer (v1alpha1 and v1alpha2)."""

    def walk(node: Any) -> bool:
        if isinstance(node, dict):
            for key, value in node.items():
                if key in {"namespaceSelector", "namespaces"} and _selector_reads_labels(value):
                    return True
                if walk(value):
                    return True
        elif isinstance(node, list):
            return any(walk(v) for v in node)
        return False

    tiers = [*inv.policies, *inv.admin, *inv.baseline, *inv.cnp_admin.policies, *inv.cnp_baseline.policies]
    return any(walk(pol.get("spec")) for pol in tiers if isinstance(pol, dict))


def check_reachability(
    inv: Inventory, source: str, destination: str, port: int | str, protocol: str = "TCP", cli: str = "kubectl"
) -> dict[str, Any]:
    protocol = protocol.upper()
    if protocol not in {"TCP", "UDP", "SCTP"}:
        raise ValueError("protocol must be TCP, UDP or SCTP")
    if isinstance(port, str) and port.isdigit():
        port = int(port)
    if isinstance(port, int) and not 1 <= port <= 65535:
        raise ValueError("port must be 1-65535 or a named container port")
    if isinstance(port, str) and not _PORT_NAME.match(port):
        raise ValueError(f"bad port name {port!r}")
    src, dst = inv.resolve(source), inv.resolve(destination)
    if src.external and dst.external:
        raise ValueError("at least one side must be a workload in the cluster")
    egress = _direction(inv, src, dst, "Egress", port, protocol, dst)
    ingress = _direction(inv, dst, src, "Ingress", port, protocol, dst)
    # A CNI nobody documents either way leaves the admin tier in doubt, not the question. Evaluate it and withhold
    # it, and only call the answer unknown where the two readings disagree: an unknown must not read as a pass, and
    # it must not throw away an answer that holds under both readings either. On a Cilium cluster the first version
    # of this made every question unanswerable as long as one AdminNetworkPolicy existed anywhere.
    enforcement_unknown = list(inv.enforcement_unknown)
    if enforcement_unknown:
        # Every enforcement reading a CNI could have, not only "all enforced" and "none": Calico 3.32 enforces
        # ClusterNetworkPolicy and ignores AdminNetworkPolicy, OVN-Kubernetes the reverse, and comparing only the
        # two extremes let a mixed cluster read as "both readings agree" while the real one denied (G279).
        import itertools

        apis = sorted(inv.unknown_apis) or ["v1alpha1", "v1alpha2"]
        readings = []
        for combo in itertools.product((True, False), repeat=len(apis)):
            on = dict(zip(apis, combo, strict=True))
            view = inv.with_tiers(on.get("v1alpha1", True), on.get("v1alpha2", True))
            readings.append(
                (
                    _direction(view, src, dst, "Egress", port, protocol, dst),
                    _direction(view, dst, src, "Ingress", port, protocol, dst),
                )
            )
        agree = (
            all(_same_answer(r[0], readings[0][0]) and _same_answer(r[1], readings[0][1]) for r in readings[1:])
            and _same_answer(readings[0][0], egress)
            and _same_answer(readings[0][1], ingress)
        )
        # The reading with every unknown tier ignored is the one reported either way: the tier may not apply, so
        # its reason must not be the one the operator reads.
        egress, ingress = readings[-1]
        if agree:
            enforcement_unknown = []
            inv.notes.append(
                "Both readings of that tier -- enforced and ignored -- give the same answer here, so the verdict "
                "stands either way."
                if len(apis) == 1
                else "Every reading of those tiers -- "
                + " and ".join(apis)
                + " each enforced or ignored, in every combination a CNI could have -- gives the same answer here, "
                "so the verdict stands either way."
            )
    allowed = bool(egress["allowed"] and ingress["allowed"])
    # A direction whose deciding tier has no determinate answer is neither allowed nor denied. Calling it either
    # would be a guess, and a proposed NetworkPolicy under it would be applied and change nothing if the admin
    # tier's tie lands on Deny.
    undetermined = [d for d, r in (("Egress", egress), ("Ingress", ingress)) if r.get("undetermined")]
    # A forbidden or failed read of a tier that can overrule NetworkPolicy is not "the tier is absent".
    # The namespace-scoped chart cannot read these, so treating that 403 as a NetworkPolicy-only allow
    # is the answer an operator gets by default.
    unreadable = list(inv.tier_unreadable) + list(inv.invalid_policies)
    # A namespace whose labels were not read decides nothing only where no selector reads its labels; where one
    # does, the subject or the peer it would have matched is unknown, and an answer from it is a guess (G279).
    if inv.namespace_unread and _reads_namespace_labels(inv):
        unreadable += [f"labels of namespace {ns}" for ns in inv.namespace_unread]
    # A cluster-scoped kind that sits above NetworkPolicy and that this evaluator cannot read yet decides BEFORE
    # any NetworkPolicy and has the last word. Naming it under `notEvaluated` was not enough: the verdict still
    # read "allowed" and the CLI still exited 0, so a gate merged on an answer a ClusterNetworkPolicy `Deny` may
    # reverse. Calico 3.32 removed AdminNetworkPolicy enforcement entirely in favour of ClusterNetworkPolicy, so
    # on a current Calico cluster this is where the real policy lives, not an edge case.
    unevaluated_above = [
        ref for ref in inv.other_policies if ref.split("/", 1)[0] in CLUSTER_SCOPED_ABOVE_NETWORKPOLICY
    ]
    # A cluster-scoped policy that was READ and could not be evaluated belongs here too, and the filter that
    # first did this excluded anything already in `other_policies` -- which is every one of them, so it added
    # nothing and a refused document stayed a clean allow.
    unevaluated_above = list(dict.fromkeys(unevaluated_above + inv.unreadable_cluster_scoped))
    # Cilium clusterwide and Calico GlobalNetworkPolicy are cluster-scoped and unread. An EgressFirewall, a
    # namespace CiliumNetworkPolicy and a MultiNetworkPolicy are not: they stay listed and do not flip the verdict.
    unevaluated_present = [ref for ref in inv.other_policies if ref.split("/", 1)[0] in UNEVALUATED_POLICY_KINDS]
    unevaluated_present = list(dict.fromkeys(unevaluated_present + inv.unreadable_cluster_scoped))
    # A hostNetwork direction is unknown. It does not erase a deny a tier we did evaluate already returned.
    # A cluster-scoped policy we did not read can, so that case stays unknown.
    evaluated_deny = [
        d
        for d, r in (("Egress", egress), ("Ingress", ingress))
        if r.get("evaluated", True) and not r.get("undetermined") and not r["allowed"]
    ]
    # `allowed` is false for an undetermined direction too (an unknown must not read as a pass). A summary that
    # says the policies "would deny" from that flag is describing a decision that was never made.
    # evaluated_deny is every evaluated direction that is not allowed, so a non-empty evaluated set with no deny
    # is an allow. No all() over that set: an empty one must not read as allowed.
    evaluated_answers = [r for r in (egress, ingress) if r.get("evaluated", True) and not r.get("undetermined")]
    if evaluated_deny:
        decided = "deny"
    elif evaluated_answers and not undetermined:
        # Both directions must have an answer before the pair has one. With one direction allowed and the other
        # never decided, "the NetworkPolicies would allow this traffic" is a claim about a decision nobody made.
        decided = "allow"
    else:
        decided = None
    # A policy whose tier this CNI may or may not apply was read and then withheld. It is not "unreadable"
    # -- the document is right here -- and it is not "absent", so it gets its own reason rather than borrowing one.
    overrides = bool(unevaluated_present or unreadable or enforcement_unknown)
    unknown = bool(undetermined or overrides)
    if unknown and (not evaluated_deny or overrides):
        verdict = "undetermined"
    elif not allowed or evaluated_deny:
        verdict = "denied"
    else:
        verdict = "allowed"
    out: dict[str, Any] = {
        "verdict": verdict,
        "source": src.describe(),
        "destination": dst.describe(),
        "port": port,
        "protocol": protocol,
        "egress": egress,
        "ingress": ingress,
    }
    if isinstance(port, str) and port not in dst.ports:
        out["warning"] = f"named port {port!r} is not declared by {dst.describe()}'s containers in these manifests"
    blocked = [d for d, r in (("Egress", egress), ("Ingress", ingress)) if not r["allowed"] and d not in undetermined]
    if unreadable:
        blocked = []
    if verdict == "undetermined" and undetermined and not overrides:
        out["undetermined"] = undetermined
        out["summary"] = (
            f"Undetermined: kube-noob could not determine whether {src.describe()} reaches {dst.describe()} on "
            f"{protocol} {port}. " + " ".join((ingress if d == "Ingress" else egress)["reason"] for d in undetermined)
        )
    elif verdict == "undetermined" and unevaluated_present:
        out["undeterminedBy"] = unevaluated_present
        names = ", ".join(unevaluated_present[:10])
        if unevaluated_present == unevaluated_above:
            if len(unevaluated_present) == 1:
                detail = (
                    f"{names} is cluster-scoped and decided before any NetworkPolicy, and kube-noob does not "
                    "evaluate it yet. It can reverse this either way"
                )
            else:
                detail = (
                    f"{names} are cluster-scoped and decided before any NetworkPolicy, and kube-noob does not "
                    "evaluate them yet. They can reverse this either way"
                )
        else:
            pronoun = "it" if len(unevaluated_present) == 1 else "them"
            detail = (
                f"{names} {'is' if len(unevaluated_present) == 1 else 'are'} in the input and kube-noob does not "
                f"evaluate {pronoun}. That can change this answer"
            )
        if decided:
            body = (
                f"the NetworkPolicies in these manifests would {decided} "
                f"{src.describe()} -> {dst.describe()} on {protocol} {port}, but {detail}, so the answer is unknown "
                "rather than allowed or denied."
            )
        else:
            # Where a direction is undetermined in its own right, its reason belongs here too: this branch used to
            # drop it, so a hostNetwork destination behind an unread policy was reported with neither fact.
            why = " ".join((ingress if d == "Ingress" else egress)["reason"] for d in undetermined)
            body = (
                f"kube-noob could not determine whether {src.describe()} reaches {dst.describe()} on "
                f"{protocol} {port}, and {detail}, so the answer is unknown rather than allowed or denied."
                + (f" {why}" if why else "")
            )
            if undetermined:
                out["undetermined"] = undetermined
        out["summary"] = f"Undetermined: {body}"
    elif enforcement_unknown:
        out["undeterminedBy"] = enforcement_unknown
        if undetermined:
            out["undetermined"] = undetermined
        if decided:
            tail = (
                f"the NetworkPolicies in these manifests would {decided} this traffic, but that is the answer only "
                "if the admin tier does not decide it first"
            )
        elif undetermined:
            reasons = " ".join((ingress if d == "Ingress" else egress)["reason"] for d in undetermined)
            tail = f"the {' and '.join(d.lower() for d in undetermined)} direction was not determined either. {reasons}"
        else:
            tail = "what the NetworkPolicies would do was not determined either"
        plural = len(enforcement_unknown) != 1
        out["summary"] = (
            f"Undetermined: {', '.join(enforcement_unknown)} "
            f"{'were' if plural else 'was'} read and not evaluated, because {inv.enforcement_unknown_why}, "
            f"so {tail}"
        ).rstrip(".") + "."
        if plural:
            out["summary"] = out["summary"].replace("was read and not evaluated", "were read and not evaluated")
    elif unreadable:
        out["undeterminedBy"] = unreadable
        if decided:
            word = "denying" if decided == "deny" else "allowing"
            tail = f"so the NetworkPolicies ({word} this traffic) are not the answer."
        else:
            tail = "so what the NetworkPolicies would do was not determined, and is not the answer."
        out["summary"] = (
            f"Undetermined: {', '.join(unreadable)} could not be read. A forbidden or failed read is not the "
            f"same as the tier being absent, {tail}"
        )
    elif allowed:
        out["summary"] = (
            f"Allowed: {src.describe()} -> {dst.describe()} on {protocol} {port}. "
            f"{egress['reason']} {ingress['reason']}"
        )
    else:
        out["summary"] = (
            f"Denied: {src.describe()} -> {dst.describe()} on {protocol} {port} is blocked by "
            + " and ".join(f"the {d.lower()} policies of {(src if d == 'Egress' else dst).describe()}" for d in blocked)
            + "."
        )
    if inv.inert:
        out["inertPolicies"] = [dict(entry) for entry in inv.inert]
        names = ", ".join(entry["policy"] for entry in inv.inert)
        out["summary"] = (
            f"{out['summary']} {names} {'is' if len(inv.inert) == 1 else 'are'} in the input and NOT enforced by "
            f"this CNI, so {'it' if len(inv.inert) == 1 else 'they'} did not decide this answer."
        )
    changes = []
    for direction in blocked:
        decision = ingress if direction == "Ingress" else egress
        subject, peer = (dst, src) if direction == "Ingress" else (src, dst)
        word = direction.lower()
        # The v1alpha2 Admin tier is the same situation under a newer API, so it takes the same branch: once
        # the kind became evaluated (P4) rather than merely named, the old caveat went away with it, and
        # without this the answer proposed a NetworkPolicy against a cluster-scoped Deny -- the very fix the
        # caveat had existed to warn about, now with nothing warning about it.
        # Admin tiers only. A v1alpha2 BASELINE deny is overridable by a NetworkPolicy -- the spec says so in
        # as many words -- so sending it here told a reader no NetworkPolicy could help, when one is exactly
        # what helps. Both CNP tiers report the same `tier`, which is why the decision carries `cnpTier`.
        if decision.get("tier") == ANP_KIND or (
            decision.get("tier") == _CNP_KIND and decision.get("cnpTier") == "Admin"
        ):
            # A NetworkPolicy cannot undo this: the admin tier runs first and has already decided. Proposing one
            # would be applied, change nothing, and cost the next verdict its credibility.
            allow_word = "an Allow" if decision.get("tier") == ANP_KIND else "an Accept"
            changes.append(
                {
                    "change": f"{decision['policy']} {word} rule {decision['rule']!r} denies this, and it is "
                    f"cluster-scoped: no NetworkPolicy in {subject.namespace} can override it. A cluster "
                    f"administrator has to narrow that rule's peers or ports, or add {allow_word} or Pass rule "
                    f"at a higher precedence (a LOWER priority number), for {peer.describe()} on "
                    f"{protocol} {port}.",
                    "requiresApproval": True,
                    "ownedBy": "cluster administrator",
                    "policy": decision["policy"],
                    "rule": decision["rule"],
                }
            )
            continue
        baseline = decision.get("tier") == BANP_KIND or decision.get("cnpTier") == "Baseline"
        changes.append(
            {
                "change": f"Allow {word} {'to' if direction == 'Ingress' else 'from'} {subject.describe()} "
                f"{'from' if direction == 'Ingress' else 'to'} {peer.describe()} on {protocol} {port}"
                + (
                    f" -- {decision['policy']} denies it as the baseline, and any NetworkPolicy that selects "
                    f"{subject.describe()} for {direction} takes the decision away from the baseline"
                    if baseline
                    else ""
                ),
                "manifest": _allow_policy(direction, subject, peer, port, protocol),
                "requiresApproval": True,
            }
        )
    if "Egress" in blocked:
        changes.append(
            {
                "change": "If the source reaches the destination by name, its egress must also allow DNS: UDP and "
                "TCP 5353 to namespace openshift-dns on OpenShift, 53 to kube-system elsewhere.",
                "requiresApproval": True,
            }
        )
    if enforcement_unknown and not unevaluated_present:
        # The withheld tier is the case where a proposed NetworkPolicy is MOST likely to change nothing, and the
        # first version of this was the only branch that left the caveat off.
        caveat = (
            "kube-noob withheld " + ", ".join(enforcement_unknown[:10]) + f", because {inv.enforcement_unknown_why}. "
            "If it does and one of them denies this traffic, the NetworkPolicy above is applied and changes nothing."
        )
        for change in changes:
            if change.get("manifest"):
                change["caveat"] = caveat
    if unevaluated_present:
        # The admin tier, and any policy in the input this evaluator did not read, can make a NetworkPolicy fix
        # a no-op. Say that on the fix. Do not call an EgressFirewall cluster-scoped: it is not.
        if unevaluated_above and unevaluated_present == unevaluated_above:
            caveat = (
                "kube-noob did not evaluate " + ", ".join(unevaluated_above[:10]) + ", which is cluster-scoped and "
                "decided before any NetworkPolicy. If one of them denies this traffic, the NetworkPolicy above is "
                f"applied and changes nothing. Check it first: {cli} get clusternetworkpolicy -o yaml."
            )
        else:
            caveat = (
                "kube-noob did not evaluate " + ", ".join(unevaluated_present[:10]) + ". If one of them decides this "
                "traffic, the NetworkPolicy above is applied and changes nothing."
            )
        for change in changes:
            if change.get("manifest"):
                change["caveat"] = caveat
    if changes:
        out["proposedChanges"] = changes
    # Names and labels come from manifests or the cluster: only Kubernetes syntax goes into a command line.
    checks = []
    safe_ns = [ns for ns in dict.fromkeys(e.namespace for e in (src, dst) if e.namespace) if _DNS.match(ns)]
    for ns in safe_ns:
        checks.append(f"{cli} get networkpolicy -n {ns} -o yaml")
        checks.append(f"{cli} get namespace {ns} --show-labels")
    for e in (src, dst):
        sel = _shell_safe_selector(e.selector)
        if e.namespace in safe_ns and sel:
            checks.append(f"{cli} get pods -n {e.namespace} -l {sel} -o wide --show-labels")
    # The admin tiers are upstream CRDs, not an OpenShift feature, so they are worth reading on either CLI - and
    # first, when one of them is what decided the verdict.
    anp_check = f"{cli} get adminnetworkpolicy,baselineadminnetworkpolicy,clusternetworkpolicy"
    if {egress.get("tier"), ingress.get("tier")} & {ANP_KIND, BANP_KIND, _CNP_KIND}:
        checks.insert(0, anp_check)
    else:
        checks.append(anp_check)
    if inv.inert:
        # The tier is inert, so reading it answers nothing and its CRDs may not even be served. The kind that
        # decides instead is the one to read, and it was missing from this list entirely.
        replacement = {entry["replacement"] for entry in inv.inert}
        for kind_name in sorted(replacement):
            checks.insert(0, f"{cli} get {_RESOLVING_GET.get(kind_name, kind_name.lower())} -o yaml")
    # When a cluster-scoped kind this evaluator cannot read is what made the answer unknown, reading it is the
    # one step that resolves the verdict -- so it goes first. Printing checks that cannot settle the question,
    # and omitting the one that can, is the same failure as naming the policy in a field nobody reads.
    unresolved = []
    for ref in unevaluated_present:
        kind_name = ref.split("/", 1)[0]
        if kind_name in _RESOLVING_GET and kind_name not in unresolved:
            unresolved.append(kind_name)
    for kind_name in reversed(unresolved):
        checks.insert(0, f"{cli} get {_RESOLVING_GET[kind_name]} -o yaml")
    if cli == "oc" and src.namespace in safe_ns:
        checks.append(f"oc get egressfirewall -n {src.namespace} -o yaml")
    out["readOnlyNextSteps"] = [_step(c) for c in checks if classify_step(c) == "read"]
    kind, _, name = src.ref.partition("/")
    if src.namespace in safe_ns and kind.isalpha() and _DNS.match(name) and (dst.external or dst.namespace in safe_ns):
        target = dst.describe() if dst.external else f"<{_short(dst)}-service>.{dst.namespace}.svc"
        probe = f"{cli} exec -n {src.namespace} {src.ref} -- curl -sS -o /dev/null --max-time 5 {target}:{port}"
        out["diagnosticCommands"] = [{"command": probe, "requiresApproval": True}]
    not_evaluated = list(NOT_EVALUATED)
    if inv.other_policies:
        not_evaluated.insert(0, "found in the input but not evaluated: " + ", ".join(inv.other_policies[:10]))
    out["notEvaluated"] = not_evaluated
    if inv.notes:
        out["notes"] = list(inv.notes)
    return out


def _cni_from_cluster(backend: Any) -> tuple[str | None, str, bool]:
    """Read the CNI and its version from the cluster, or say why not. Never guesses.

    Returns a `NAME[:VERSION]` string for :func:`kube_noob.debug.cni.parse_cni`, a note for the caller to show, and
    whether the CNI could not be established at all. What each answer means:

    * the API answering that `clusterinformations.crd.projectcalico.org` is not served -- Calico is not
      installed; no note, because nothing changed. Recognised only in the words a backend writes for it
      (:func:`kube_noob.debug.cluster.classify_read_failure`): an auth plugin "not found" on PATH is not it;
    * a 403, any other failed read, a response without an `items` list or with items that are not objects -- the
      CNI is not known (G279): the admin tiers are withheld where they decide the answer instead of being
      evaluated with the OVN-Kubernetes semantics, because a failed read may be hiding the Calico 3.32 cluster
      that ignores them;
    * the CRD served but empty, an object with no `calicoVersion`, or one that does not parse as a version --
      Calico is installed and its version is not known, which is `calico` with no version: G209's `unknown`;
    * a `variant` other than open-source Calico, whose versions run on their own schedule, so the open-source
      table does not apply to them -- the CNI's enforcement is not known.
    """
    from kube_noob.debug.cluster import classify_read_failure, list_items, read
    from kube_noob.errors import ClusterAccessError

    try:
        items = list_items(read(backend, "clusterinformations", namespace=None), "clusterinformations")
    except ClusterAccessError as exc:
        if classify_read_failure("clusterinformations", exc) == "not-served":
            return None, "", False  # no Calico on this cluster
        return (
            None,
            f"the cluster's CNI could not be read ({exc}); whether it enforces AdminNetworkPolicy, "
            "BaselineAdminNetworkPolicy and ClusterNetworkPolicy is not known, so an answer one of them decides is "
            "undetermined. Pass --cni if you know it",
            True,
        )
    from kube_noob.debug.cni import parse_cni

    unknown_version = (
        "Calico is installed (clusterinformations.crd.projectcalico.org is served) but {why}, so whether it "
        "enforces AdminNetworkPolicy or ClusterNetworkPolicy is not known and an answer one of them decides is "
        "undetermined. Pass --cni if you know it"
    )
    for item in items:
        raw = item.get("spec")
        spec: dict[str, Any] = raw if isinstance(raw, dict) else {}
        version = str(spec.get("calicoVersion") or "").strip()
        variant = str(spec.get("variant") or "").strip()
        if variant and variant.lower() not in {"calico", "calico-oss", "oss"}:
            return (
                None,
                f"this cluster runs Calico variant {variant!r} at {version!r}, whose versions are numbered on "
                "their own schedule, so kube-noob does not read it against the open-source support table and does "
                "not know whether it enforces AdminNetworkPolicy. Pass --cni if you know it",
                True,
            )
        if not version:
            continue
        try:
            parse_cni(f"calico:{version}")
        except ValueError:
            return "calico", unknown_version.format(why=f"reports version {version!r}, which is not a version"), False
        return f"calico:{version}", f"CNI read from the cluster: Calico {version}", False
    return "calico", unknown_version.format(why="it reports no calicoVersion"), False


#: The kinds `ns/name` may name, in the order they are looked for. A kind that is not there is the next kind's
#: turn; a kind that could not be READ ends the search, because the object asked about is then not established.
_WORKLOAD_PLURALS = {
    "deployment": "deployments",
    "statefulset": "statefulsets",
    "daemonset": "daemonsets",
    "pod": "pods",
    "replicaset": "replicasets",
    "job": "jobs",
    "cronjob": "cronjobs",
}
_PLURAL_KIND = {
    "deployments": "Deployment",
    "statefulsets": "StatefulSet",
    "daemonsets": "DaemonSet",
    "pods": "Pod",
    "replicasets": "ReplicaSet",
    "jobs": "Job",
    "cronjobs": "CronJob",
}


def _read_workload(backend: Any, ns: str, name: str, kinds: list[str], explicit: bool) -> dict[str, Any]:
    from kube_noob.debug.cluster import classify_read_failure, read_object
    from kube_noob.errors import ClusterAccessError

    for kind in kinds:
        resource = _WORKLOAD_PLURALS.get(kind, kind)
        expected = _PLURAL_KIND.get(resource, "")
        try:
            return (
                read_object(backend, resource, expected, name, namespace=ns)
                if expected
                else backend.get(resource, name=name, namespace=ns)
            )
        except ClusterAccessError as exc:
            if classify_read_failure(resource, exc, name=name) in {"not-found", "not-served"}:
                continue
            # Not "not there": with this kind unread, a lower-ranked kind of the same name would be answered about
            # in place of the object asked about (G279). Unless the caller named the kind, nothing is established.
            raise ClusterAccessError(
                f"could not read {ns}/{name}: {resource}: {exc}"
                + ("" if explicit else f"; name the kind (for example {ns}/pod/{name}) to read only that kind")
            ) from exc
    return {}


def _namespace_labels_read(backend: Any, ns: str) -> tuple[dict[str, Any] | None, str]:
    from kube_noob.debug.cluster import read_object
    from kube_noob.errors import ClusterAccessError

    try:
        return read_object(backend, "namespaces", "Namespace", ns), ""
    except ClusterAccessError as exc:
        return None, str(exc)


def _serves(backend: Any, resource: str, namespace: str) -> bool:
    """Whether a list of ``resource`` in ``namespace`` was read: the API is served. A failed read says nothing."""
    from kube_noob.debug.cluster import list_items, read
    from kube_noob.errors import ClusterAccessError

    try:
        list_items(read(backend, resource, namespace=namespace), resource, namespace)
    except ClusterAccessError:
        return False
    return True


def inventory_from_cluster(backend: Any, source: str, destination: str, cni: str | None = None) -> Inventory:
    """Read (never write) the NetworkPolicies, namespaces and workloads the two endpoints need.

    Every read that did not happen is part of the answer: a NetworkPolicy list that failed, namespace labels a
    selector needs, a tier, the CNI. None of them is taken for "nothing there" (G279).
    """
    from kube_noob.debug.cluster import classify_read_failure, list_items, read
    from kube_noob.errors import ClusterAccessError

    objects: list[dict[str, Any]] = []
    namespaces: list[str] = []
    notes: list[str] = []
    unreadable: list[str] = []
    namespace_unread: list[str] = []
    np_unread: list[str] = []
    for spec in (source, destination):
        s = spec.strip()
        if ":" in s and "=" in s:
            ns = s.split(":", 1)[0]
        elif "/" in s:
            ns = s.split("/", 1)[0]
        else:
            continue  # an IP address
        if not _DNS.match(ns):
            raise ValueError(f"bad namespace in {spec!r}")
        if ns not in namespaces:
            namespaces.append(ns)
        parts = s.split("/")
        if len(parts) in (2, 3) and "=" not in s:
            explicit = len(parts) == 3
            kinds = [parts[1].lower()] if explicit else ["deployments", "statefulsets", "daemonsets", "pods"]
            obj = _read_workload(backend, ns, parts[-1], kinds, explicit)
            if obj:
                objects.append(obj)
    for ns in namespaces:
        # A NetworkPolicy read that failed -- forbidden, a timeout, no list -- names the namespace and withholds the
        # verdict, as an unreadable tier does: a namespace-scoped token reads one namespace and not the other, and
        # naming the one it could not read is more use than an error (G279).
        try:
            policies = list_items(read(backend, "networkpolicies", namespace=ns), "networkpolicies", ns)
        except ClusterAccessError as exc:
            notes.append(f"NetworkPolicies in namespace {ns} could not be read ({exc})")
            unreadable.append(f"NetworkPolicy in namespace {ns}")
            np_unread.append(ns)
            policies = []
        objects += [{**item, "kind": "NetworkPolicy"} for item in policies]
        nso, why = _namespace_labels_read(backend, ns)
        if nso is None:
            namespace_unread.append(ns)
            notes.append(
                f"could not read namespace {ns}'s labels ({why}); only kubernetes.io/metadata.name is known, so an "
                "answer a selector on any other namespace label decides is undetermined"
            )
        else:
            objects.append({**nso, "kind": "Namespace"})
    # The admin tiers are cluster-scoped: read once, not per namespace. Only the API saying it does not serve the
    # kind is "not installed"; ClusterNetworkPolicy, Cilium's clusterwide policy and Calico's GlobalNetworkPolicy are
    # read even though some are not parsed, because collecting one is what puts it in `other_policies`.
    # A tier this CNI does not enforce is still read, and a failed read of it must not withhold the verdict: the
    # namespace-scoped RBAC that produces that 403 is the common `--live` case, and "this AdminNetworkPolicy is in
    # your cluster and decides nothing" needs the policy in hand.
    admin_tier_inert = False
    cni_unread = False
    caller_cni = bool(cni)
    ccnp_served = False
    if not cni:
        # `--cni` is the caller's claim; on a live cluster the fact is readable. Calico publishes its version in
        # `clusterinformations.crd.projectcalico.org` ("set automatically by calico/node").
        cni, why, cni_unread = _cni_from_cluster(backend)
        if why:
            notes.append(why)
    if cni:
        from kube_noob.debug.cni import admin_tier_support, parse_cni

        cni_name, cni_version = parse_cni(cni)
        admin_tier_inert = admin_tier_support(cni_name, cni_version) == "not-enforced"
    for tier_plural, tier_kind in (
        ("clusternetworkpolicies", "ClusterNetworkPolicy"),
        ("ciliumclusterwidenetworkpolicies", "CiliumClusterwideNetworkPolicy"),
        ("globalnetworkpolicies", "GlobalNetworkPolicy"),
        ("adminnetworkpolicies", ANP_KIND),
        ("baselineadminnetworkpolicies", BANP_KIND),
    ):
        try:
            items = list_items(read(backend, tier_plural, namespace=None), tier_plural)
        except ClusterAccessError as exc:
            if classify_read_failure(tier_plural, exc) == "not-served":
                notes.append(
                    f"{tier_kind} is not installed on this cluster (its API is not served), so no policy of that "
                    "kind can decide this answer"
                )
            elif admin_tier_inert and tier_kind in {ANP_KIND, BANP_KIND}:
                notes.append(
                    f"{tier_kind} could not be read ({exc}), and this CNI does not enforce it, so it cannot "
                    "change this answer"
                )
            else:
                notes.append(
                    f"{tier_kind} could not be read ({exc}); a failed read is not the same as the tier being absent"
                )
                unreadable.append(tier_kind)
            continue
        ccnp_served = ccnp_served or tier_plural == "ciliumclusterwidenetworkpolicies"
        objects += [{**item, "kind": tier_kind} for item in items]
    cni_unknown = "could not be read"
    if not caller_cni and not cni and not cni_unread:
        # No Calico. "So OVN-Kubernetes" was the assumption here, and on Cilium -- which states no support for
        # AdminNetworkPolicy -- or kindnet, flannel or OpenShift SDN it decided an answer the CNI may not enforce
        # (G279). The CNI is identified from what the cluster serves, or it is not identified.
        if ccnp_served:
            cni = "cilium"
            notes.append("CNI read from the cluster: Cilium (ciliumclusterwidenetworkpolicies.cilium.io is served)")
        elif namespaces and _serves(backend, "egressfirewalls", namespaces[0]):
            cni = "ovn-kubernetes"
            notes.append("CNI read from the cluster: OVN-Kubernetes (egressfirewalls.k8s.ovn.org is served)")
        else:
            cni_unread, cni_unknown = True, "was not identified"
            notes.append(
                "the cluster's CNI was not identified: none of Calico's clusterinformations, Cilium's clusterwide "
                "policy or OVN-Kubernetes' EgressFirewall is served (or readable), so whether it enforces "
                "AdminNetworkPolicy, BaselineAdminNetworkPolicy and ClusterNetworkPolicy is not known and an answer "
                "one of them decides is undetermined. Pass --cni if you know it"
            )
    inv = Inventory(objects, cni=cni, cni_unread=cni_unread, cni_unknown=cni_unknown)
    inv.notes.extend(notes)
    inv.tier_unreadable = unreadable
    inv.namespace_unread = namespace_unread
    inv.np_unread = np_unread
    return inv
