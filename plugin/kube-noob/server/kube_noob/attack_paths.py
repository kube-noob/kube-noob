"""Attack paths: from what is exposed to what a compromised pod could do (requirements R3.2). Read-only, tier R.

A path starts at an exposure (a Route, an Ingress, a LoadBalancer, NodePort or externalIPs Service), goes to the
Service and the workloads it selects, and ends at what those pods can do if an attacker runs code in them:

- on the node: a privileged container, a hostPath volume (the container runtime socket or a system directory is
  worst), the host's PID, network or IPC namespace, a capability the audit's KN-S005 calls dangerous, an unmasked
  /proc, or a Windows HostProcess pod or container;
- through the Kubernetes API, with the ServiceAccount token in the pod (automounted, or projected by a volume): the
  RBAC it is bound to (read Secrets, exec or attach, ephemeral containers, create or change workloads, mint
  ServiceAccount tokens, escalate, bind or impersonate, nodes/proxy, PersistentVolume creation, admission webhook
  control, client certificate issuance, full control), and on OpenShift a privileged SecurityContextConstraints it
  may use together with the right to create workloads.

Each path scores exposure x blast radius (internet 3, node network or restricted load balancer 2, internal network 1;
blast radius 1-10, cluster-wide above namespace) and lists every step with the field that proves it. Paths are ranked
by score, then by fewer steps.

What it reads: Routes, Ingresses, Services, workloads, ServiceAccounts, Roles, RoleBindings, ClusterRoles,
ClusterRoleBindings and SecurityContextConstraints, from manifests or (``--live``) the cluster's read-only allowlist.
Never Secrets: Secret objects in a bundle are dropped before analysis, and the live allowlist refuses them. Not
modelled: NetworkPolicies on the entry edge (``kube-noob policy reach`` checks them), cloud IAM and admission-time
mutation (an SCC adding a UID).

The built-in ClusterRoles cluster-admin, admin, edit and view stand in by their documented meaning when a bundle
does not carry them (https://kubernetes.io/docs/reference/access-authn-authz/rbac/#user-facing-roles: edit and admin
can read Secrets and run pods as any ServiceAccount of the namespace; view cannot read Secrets). admin, edit and view
also aggregate every ClusterRole labelled ``rbac.authorization.k8s.io/aggregate-to-<name>``, which the input applies
when it carries one. The inventory is put in one canonical order before anything is read, so the same objects give
the same bytes whatever order the documents came in.
"""

from __future__ import annotations

import json
import posixpath
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any

from kube_noob.audit.podspec import (
    EMBEDDED_CONTAINER_KEYS,
    EMBEDDED_POD_SPEC_PATHS,
    INJECTED_CONTAINERS,
    POD_SPEC_PATHS,
    PodTemplate,
    pod_templates,
    selector_decides,
    selector_matches,
)
from kube_noob.audit.rules import (
    DANGEROUS_CAPS,
    ESCALATION_VERBS,
    INTERNAL_LB_ANNOTATIONS,
    RUNTIME_SOCKETS,
    WORKLOAD_RESOURCES,
)
from kube_noob.yamlio import PathT

#: True of every scan, whatever the input. Named so a renderer can tell them from the per-scan ones that follow
#: and print those, which is the half a text reader needs and was not getting (G231, after G221).
STANDING_LIMITATIONS: tuple[str, ...] = (
    "NetworkPolicies on the entry edge are not applied: check a path with `kube-noob policy reach`.",
    "Cloud IAM and admission-time mutation are not modelled.",
    "Roles that are not in the input are reported in notRead; cluster-admin, admin, edit and view stand in by their "
    "documented rules, and admin, edit and view aggregate rules the input may not carry.",
)

MAX_OBJECTS = 50_000
MAX_PATHS = 200
DEFAULT_TOP = 20

# kind of each list the live scan reads (API list items carry no kind of their own)
LIVE_RESOURCES: dict[str, str] = {
    "routes": "Route",
    "ingresses": "Ingress",
    "services": "Service",
    "pods": "Pod",
    "deployments": "Deployment",
    "statefulsets": "StatefulSet",
    "daemonsets": "DaemonSet",
    "replicasets": "ReplicaSet",
    "jobs": "Job",
    "cronjobs": "CronJob",
    "deploymentconfigs": "DeploymentConfig",
    # Workload CRDs that carry pod specs of their own. A cluster without the operator answers 404, which lands in
    # `notRead` rather than counting as "no such workloads" (G229).
    "inferenceservices": "InferenceService",
    "rayclusters": "RayCluster",
    "rayservices": "RayService",
    "rayjobs": "RayJob",
    "serviceaccounts": "ServiceAccount",
    "roles": "Role",
    "rolebindings": "RoleBinding",
    "clusterroles": "ClusterRole",
    "clusterrolebindings": "ClusterRoleBinding",
    "securitycontextconstraints": "SecurityContextConstraints",
}
CLUSTER_SCOPED = frozenset({"clusterroles", "clusterrolebindings", "securitycontextconstraints"})
KINDS = frozenset(LIVE_RESOURCES.values())
_POD_PATHS: dict[str, tuple[str, ...]] = {
    "Pod": ("spec",),
    "CronJob": ("spec", "jobTemplate", "spec", "template", "spec"),
}
_WORKLOAD_KINDS = frozenset(
    {"Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob", "DeploymentConfig"}
) | frozenset(EMBEDDED_POD_SPEC_PATHS)
WORKLOAD_KINDS = _WORKLOAD_KINDS  # the kinds whose pods the scan scores
# The capabilities the audit's KN-S005 calls dangerous are the ones this scan counts: one list, so the audit and the
# blast radius cannot disagree about NET_RAW or SYS_BOOT (G273). The near-root subset weighs more.
_NEAR_ROOT_CAPS = frozenset({"SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH", "BPF", "NET_ADMIN", "ALL"})
if not _NEAR_ROOT_CAPS <= DANGEROUS_CAPS:  # pragma: no cover -- a module-load invariant
    raise ImportError("attack_paths: the near-root capabilities must be a subset of the audit's dangerous list")
#: What the node leg reads, named so a `none` answer says what was checked rather than implying everything was.
#: hostPort is deliberately not here: it opens the pod on the node's network (an exposure, which Pod Security
#: Baseline restricts for that reason) and gives no access to the node itself.
NODE_CHECKS = (
    "securityContext.privileged; capabilities.add against the audit's dangerous list "
    f"({', '.join(sorted(DANGEROUS_CAPS))}); hostPath volumes; hostPID, hostNetwork, hostIPC; procMount Unmasked; "
    "windowsOptions.hostProcess (pod and container)"
)
_SYSTEM_PATHS = frozenset({"/", "/etc", "/var/lib/kubelet", "/proc", "/root", "/var/run", "/run"})
PRIVILEGED_SCCS = frozenset(
    {"privileged", "hostaccess", "hostmount-anyuid", "hostnetwork", "hostnetwork-v2", "node-exporter"}
)
_RBAC_GROUP = "rbac.authorization.k8s.io"
_IDENTITY_RESOURCES = frozenset({"roles", "clusterroles", "users", "groups", "serviceaccounts"})

# Documented meaning of the user-facing ClusterRoles, used only when the input does not carry them.
BUILTIN_CLUSTER_ROLES: dict[str, list[dict[str, Any]]] = {
    "cluster-admin": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}],
    "admin": [
        {"apiGroups": [""], "resources": ["secrets"], "verbs": ["get", "list", "watch", "create", "update", "delete"]},
        {"apiGroups": [""], "resources": ["pods/exec", "pods/attach"], "verbs": ["create", "get"]},
        {
            "apiGroups": ["", "apps", "batch"],
            "resources": ["pods", "deployments", "statefulsets", "daemonsets", "replicasets", "jobs", "cronjobs"],
            "verbs": ["create", "update", "patch", "delete"],
        },
        {"apiGroups": [_RBAC_GROUP], "resources": ["roles", "rolebindings"], "verbs": ["create", "update", "patch"]},
    ],
    "edit": [
        {"apiGroups": [""], "resources": ["secrets"], "verbs": ["get", "list", "watch", "create", "update", "delete"]},
        {"apiGroups": [""], "resources": ["pods/exec", "pods/attach"], "verbs": ["create", "get"]},
        {
            "apiGroups": ["", "apps", "batch"],
            "resources": ["pods", "deployments", "statefulsets", "daemonsets", "replicasets", "jobs", "cronjobs"],
            "verbs": ["create", "update", "patch", "delete"],
        },
    ],
    "view": [{"apiGroups": ["", "apps", "batch"], "resources": ["pods", "services", "deployments"], "verbs": ["get"]}],
}


class ScanError(ValueError):
    """The input cannot be scanned (too many objects, nothing to read)."""


@dataclass(frozen=True)
class Step:
    source: str
    target: str
    edge: str
    evidence: str

    def as_dict(self) -> dict[str, str]:
        return {"from": self.source, "to": self.target, "edge": self.edge, "evidence": self.evidence}


@dataclass(frozen=True)
class Capability:
    name: str
    scope: str  # "node", "cluster" or "namespace <ns>"
    weight: int
    evidence: str
    fix: str
    #: The field that proves it, from the object's root (`spec.template.spec.containers[0].securityContext
    #: .privileged`), for a node capability. The blast-radius graph carries it as an edge's evidence (G273).
    at: str = ""
    #: The RBAC grants an API capability came from, so the blast-radius graph can name the binding as well as
    #: print the evidence line. Not part of equality: two routes to one capability are one capability.
    grants: tuple[Grant, ...] = field(default=(), compare=False)
    #: The capability reaches every Secret in its scope without a read rule: a pod it creates mounts any Secret of
    #: the namespace ("Escalation paths", https://kubernetes.io/docs/reference/access-authn-authz/authorization/
    #: #escalation-paths), and escalate, bind or impersonate can take any right in the scope (G273).
    implies_reads: bool = False


@dataclass(frozen=True)
class Entry:
    exposure: str
    weight: int
    steps: tuple[Step, ...]
    namespace: str
    service: str
    fix: str
    #: Set when the object DECLARES its own exposure and the Service that implements it is created by an
    #: operator, so there is nothing in this input to match a selector against. `("RayCluster/ns/r", path)` says
    #: which object and which pod spec path the edge lands on. Without this a RayCluster asking for
    #: `serviceType: LoadBalancer` scored `0 attack paths from 0 exposures` -- an internet-facing Ray head with a
    #: privileged container, reported as nothing at all (G233).
    declared_on: tuple[str, PathT] | None = None


@dataclass
class AttackPath:
    entry: Entry
    steps: list[Step]
    capability: Capability
    score: int = field(init=False)

    def __post_init__(self) -> None:
        self.score = self.entry.weight * self.capability.weight

    def as_dict(self, rank: int) -> dict[str, Any]:
        return {
            "rank": rank,
            "score": self.score,
            "exposure": {"kind": self.entry.exposure, "weight": self.entry.weight},
            "blastRadius": {
                "capability": self.capability.name,
                "scope": self.capability.scope,
                "weight": self.capability.weight,
            },
            "summary": " -> ".join([self.steps[0].source, *(s.target for s in self.steps)]),
            "steps": [s.as_dict() for s in self.steps],
            "fix": [self.capability.fix, self.entry.fix],
        }


def _ref(obj: dict[str, Any]) -> str:
    meta = obj.get("metadata") or {}
    ns = meta.get("namespace")
    return f"{obj.get('kind')}/{ns}/{meta.get('name')}" if ns else f"{obj.get('kind')}/{meta.get('name')}"


object_ref = _ref  # Kind/namespace/name (Kind/name without a namespace), as audit findings name resources


def _ns(obj: dict[str, Any]) -> str:
    return str((obj.get("metadata") or {}).get("namespace") or "default")


def _name(obj: dict[str, Any]) -> str:
    return str((obj.get("metadata") or {}).get("name") or "")


object_namespace = _ns  # "default" when the object names none, as kubectl would apply it
object_name = _name


def _get(obj: Any, *path: str) -> Any:
    for key in path:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(key)
    return obj


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _strs(value: Any) -> set[str]:
    return {str(x) for x in _list(value)}


strs = _strs


def _plain(value: Any) -> Any:
    """`value` with every mapping key a string and every mapping sorted, so YAML with mixed key types (`1:` beside
    `a:`) still has one canonical form; `json.dumps(sort_keys=True)` raises on it."""
    if isinstance(value, dict):
        return [
            [str(k), _plain(v)] for k, v in sorted(value.items(), key=lambda kv: (str(kv[0]), type(kv[0]).__name__))
        ]
    if isinstance(value, list | tuple):
        return [_plain(v) for v in value]
    return value


def _canonical_form(obj: Any) -> str:
    return json.dumps(_plain(obj), default=str)


canonical_form = _canonical_form  # one canonical form of an object, for ordering and for telling duplicates apart


@dataclass
class Inventory:
    objects: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    not_read: list[str] = field(default_factory=list)
    dropped_secrets: int = 0

    def add(self, obj: Any, kind: str | None = None) -> None:
        if not isinstance(obj, dict):
            return
        k = kind or str(obj.get("kind") or "")
        if k == "Secret":
            self.dropped_secrets += 1  # never analysed, never echoed
            return
        if k not in KINDS:
            # An object of a kind this scan does not model is normally nothing to say: a ConfigMap is not a path.
            # One that carries a pod spec is different -- those pods can hold every capability this scan ranks,
            # and dropping them unmentioned reported "0 workloads" for a file full of Argo Rollouts (G232).
            from kube_noob.audit.podspec import unread_pod_specs
            from kube_noob.yamlio import Document

            if unread_pod_specs(Document(index=0, data=obj)):
                self.not_read.append(f"{_ref(obj)}: carries a pod spec kube-noob has no reader for, so not ranked")
            return
        if sum(len(v) for v in self.objects.values()) >= MAX_OBJECTS:
            raise ScanError(f"more than {MAX_OBJECTS} objects; scan fewer namespaces")
        obj = {**obj, "kind": k}
        self.objects.setdefault(k, []).append(obj)

    def of(self, *kinds: str) -> list[dict[str, Any]]:
        return [o for k in kinds for o in self.objects.get(k, [])]

    def canonicalize(self) -> None:
        """Sort every kind's objects by their content, so that which of two equal-weight proofs a path names, and
        which of two same-named objects the scan meets first, does not depend on the order of the documents.
        Same input, same bytes -- for `posture scan` and the blast radius alike, since both read this (G273)."""
        self.objects = {k: sorted(v, key=_canonical_form) for k, v in sorted(self.objects.items())}

    @classmethod
    def from_documents(cls, docs: Iterable[Any]) -> Inventory:
        inv = cls()
        for d in docs:
            kind = str(d.get("kind") or "") if isinstance(d, dict) else ""
            if kind.endswith("List") and isinstance(d, dict) and "items" in d:
                # `kubectl get rolebindings -o yaml` writes a `List`; the typed form (`RoleBindingList`) carries
                # items without a kind of their own. Dropping either left "no RoleBinding is in the input" (G273).
                items = d.get("items")
                if not isinstance(items, list):
                    inv.not_read.append(f"{kind}: items is not a list, so none of its objects were read")
                    continue
                item_kind = kind.removesuffix("List") or None
                for item in items:
                    inv.add(item, None if isinstance(item, dict) and item.get("kind") else item_kind)
            else:
                inv.add(d)
        inv.canonicalize()
        return inv


def _pod_spec(obj: dict[str, Any]) -> dict[str, Any] | None:
    spec = _get(obj, *_POD_PATHS.get(str(obj.get("kind")), ("spec", "template", "spec")))
    return spec if isinstance(spec, dict) else None


def _template_labels(obj: dict[str, Any]) -> dict[str, str]:
    if obj.get("kind") == "Pod":
        labels = _get(obj, "metadata", "labels")
    elif obj.get("kind") == "CronJob":
        labels = _get(obj, "spec", "jobTemplate", "spec", "template", "metadata", "labels")
    else:
        labels = _get(obj, "spec", "template", "metadata", "labels")
    return {str(k): str(v) for k, v in labels.items()} if isinstance(labels, dict) else {}


@dataclass
class _Site:
    """One pod spec to score, and the object it came from.

    An ordinary workload is one site. The kinds in ``EMBEDDED_POD_SPEC_PATHS`` are several -- a RayCluster head
    plus one per worker group, an InferenceService predictor/transformer/explainer -- each with its own
    containers, its own service account and its own labels, so each is scored on its own and named by its
    component. Before this the scan read only ``spec.template.spec``, found nothing in these kinds, and reported
    zero paths through them (G229).

    It wraps the audit's own `PodTemplate` rather than re-deriving the spec, the path and the labels, so the scan
    and the audit cannot disagree about where a pod spec is or what labels it carries (G231).
    """

    obj: dict[str, Any]
    ref: str
    template: PodTemplate

    @property
    def spec(self) -> dict[str, Any]:
        return self.template.spec

    @property
    def path(self) -> PathT:
        return self.template.path

    @property
    def labels(self) -> dict[str, str]:
        return self.template.labels()

    @property
    def embedded(self) -> bool:
        """True for a kind whose pod labels an operator merges from objects outside this input."""
        return not self.template.labels_complete


def _sites_of(obj: dict[str, Any]) -> list[_Site]:
    from kube_noob.yamlio import Document

    base = _ref(obj)
    doc = Document(index=0, data=obj)
    return [_Site(obj, base if not pt.component else f"{base}[{pt.component}]", pt) for pt in pod_templates(doc)]


def _sites(inv: Inventory, *, owned: bool = True) -> list[_Site]:
    """Every pod spec in the inventory's workloads, in workload order. ``owned=False`` drops the workloads another
    controller owns, as the scan does so that a Deployment's ReplicaSets and Pods are not counted three times."""
    present = frozenset((str(o.get("kind")), _name(o)) for k in POD_SPEC_PATHS for o in inv.of(k))
    return [site for obj in inv.of(*_WORKLOAD_KINDS) if owned or not _owned(obj, present) for site in _sites_of(obj)]


def _owned(obj: dict[str, Any], present: frozenset[tuple[str, str]] | None = None) -> bool:
    """True when another object in this input already accounts for these pods.

    The point of this is de-duplication: a Deployment, its ReplicaSet and its Pods are one workload, and scoring
    all three would treble every path. But "has a controller" is too broad a test for that. On a live cluster the
    Deployment a KServe InferenceService creates is controller-owned BY the InferenceService, so a privileged
    predictor behind a LoadBalancer scored nothing at all -- and `--live`, the remedy the scan's own limitation
    text recommends, was where it happened (G233).

    So two conditions, not one: the controller must be a kind whose own pod template carries the same spec (an
    ordinary workload kind -- never a CRD, whose spec this scan may not read at all), and that owner must
    actually be in `present`, the (kind, name) of every ordinary workload in this input, built ONCE by the
    caller -- building it per object made the scan quadratic, which the complexity guard VUL1 added caught in the
    same run. Without that second condition, scanning a namespace's ReplicaSets without their
    Deployments would drop every one of them and report nothing, which is the same silent miss in a new place.
    At worst this scores one duplicate; the alternative is losing an internet-facing privileged pod.
    """
    return any(present is None or (str(o.get("kind")), str(o.get("name"))) in present for o in controller_refs(obj))


def controller_refs(obj: dict[str, Any]) -> list[dict[str, Any]]:
    """The controller ownerReferences that `_owned` follows: an ordinary workload kind, never a CRD -- a CRD
    controller's pods are these pods, and nothing else in the input scores them. The blast radius resolves a Pod
    to its owner through the same filter, so it anchors on what the scan scores (G273)."""
    return [
        o
        for o in _list(_get(obj, "metadata", "ownerReferences"))
        if isinstance(o, dict) and o.get("controller") is True and str(o.get("kind")) in POD_SPEC_PATHS
    ]


def _containers(spec: dict[str, Any], site: _Site | None = None) -> Iterator[dict[str, Any]]:
    """Every container of this pod spec, including the ones that are a field rather than a list entry.

    `site` carries the path and the object, which is what says whether a field like `model:` is a container here
    (a KServe predictor) or an ordinary mapping. Without it only the three list keys are read, which is how a
    privileged `model:` container scored no node capability at all while the audit reported it (G231).
    """
    for _at, c in _located_containers(spec, site):
        yield c


def _dotted(path: PathT) -> str:
    return ".".join(str(k) for k in path)


def _located_containers(spec: dict[str, Any], site: _Site | None = None) -> Iterator[tuple[str, dict[str, Any]]]:
    """`_containers`, with where each one is from the object's root, so a capability can name its field (G273)."""
    base = _dotted(site.path) + "." if site is not None and site.path else ""
    for key in ("initContainers", "containers", "ephemeralContainers"):
        for i, c in enumerate(_list(spec.get(key))):
            if isinstance(c, dict):
                yield f"{base}{key}[{i}]", c
    if site is None:
        return
    for key in EMBEDDED_CONTAINER_KEYS.get(site.path, ()):
        c = spec.get(key)
        if isinstance(c, dict):
            yield f"{base}{key}", c
    for where, joins in INJECTED_CONTAINERS.get(str(site.obj.get("kind")), ()):
        if joins != site.path:
            continue
        c = _get(site.obj, *(str(k) for k in where))
        if isinstance(c, dict) and ("image" in c or "securityContext" in c):
            yield _dotted(where), c


# --- exposure ----------------------------------------------------------------------------------------------------


def _service_exposure(svc: dict[str, Any]) -> tuple[str, int, str, str] | None:
    """(exposure, weight, evidence, fix) for a Service that is itself an entry, else None."""
    spec = svc.get("spec") or {}
    stype = spec.get("type") or "ClusterIP"
    if stype == "LoadBalancer":
        ann = _get(svc, "metadata", "annotations") or {}
        internal = isinstance(ann, dict) and any(
            str(ann.get(k, "")).strip().lower() in v for k, v in INTERNAL_LB_ANNOTATIONS.items()
        )
        ranges = _strs(spec.get("loadBalancerSourceRanges"))
        if internal:
            return (
                "internal network (internal load balancer)",
                1,
                "spec.type=LoadBalancer, internal annotation",
                "keep the load balancer internal and limit who can reach it",
            )
        if ranges and not ranges & {"0.0.0.0/0", "::/0"}:
            return (
                "restricted internet (load balancer source ranges)",
                2,
                f"spec.type=LoadBalancer, loadBalancerSourceRanges={sorted(ranges)}",
                "keep loadBalancerSourceRanges as narrow as the clients",
            )
        return (
            "internet (public load balancer)",
            3,
            "spec.type=LoadBalancer, no source ranges, not internal",
            "set loadBalancerSourceRanges or make the load balancer internal",
        )
    if stype == "NodePort":
        return ("node network (NodePort)", 2, "spec.type=NodePort", "use ClusterIP behind a Route or Ingress")
    if _list(spec.get("externalIPs")):
        return (
            "node network (externalIPs)",
            2,
            f"spec.externalIPs={_list(spec.get('externalIPs'))[:3]}",
            "remove spec.externalIPs",
        )
    return None


def _entries(inv: Inventory) -> list[Entry]:
    services = {(_ns(s), _name(s)) for s in inv.of("Service")}
    out: list[Entry] = []
    for r in inv.of("Route"):
        backends = [_get(r, "spec", "to")] + _list(_get(r, "spec", "alternateBackends"))
        host = _get(r, "spec", "host") or "the router's default host"
        for b in backends:
            if isinstance(b, dict) and b.get("name") and (b.get("kind") or "Service") == "Service":
                svc = str(b["name"])
                step = Step("internet", _ref(r), "exposed by", f"Route host {host}")
                step2 = Step(_ref(r), f"Service/{_ns(r)}/{svc}", "routes to", f"spec.to.name={svc}")
                if (_ns(r), svc) in services:
                    out.append(
                        Entry(
                            "internet (Route)",
                            3,
                            (step, step2),
                            _ns(r),
                            svc,
                            "remove the Route or put authentication in front of it",
                        )
                    )
    for ing in inv.of("Ingress"):
        names: list[str] = []
        default = _get(ing, "spec", "defaultBackend", "service", "name")
        if default:
            names.append(str(default))
        for rule in _list(_get(ing, "spec", "rules")):
            for p in _list(_get(rule, "http", "paths")):
                n = _get(p, "backend", "service", "name")
                if n:
                    names.append(str(n))
        for svc in dict.fromkeys(names):
            if (_ns(ing), svc) in services:
                hosts = [str(_get(x, "host")) for x in _list(_get(ing, "spec", "rules")) if _get(x, "host")]
                step = Step("internet", _ref(ing), "exposed by", f"Ingress hosts {hosts[:3] or ['*']}")
                step2 = Step(_ref(ing), f"Service/{_ns(ing)}/{svc}", "routes to", f"backend.service.name={svc}")
                out.append(
                    Entry(
                        "internet (Ingress)",
                        3,
                        (step, step2),
                        _ns(ing),
                        svc,
                        "remove the Ingress rule or put authentication in front of it",
                    )
                )
    for s in inv.of("Service"):
        exp = _service_exposure(s)
        if exp:
            label, weight, evidence, fix = exp
            src = label.split(" (")[0]
            out.append(Entry(label, weight, (Step(src, _ref(s), "exposed by", evidence),), _ns(s), _name(s), fix))
    out += _declared_entries(inv)
    return out


#: Exposures a workload CRD asks for in its own spec, where the Service or Ingress that implements it is created
#: by the operator and so is never in the manifest. (field path, which pod spec it exposes, how to read the
#: value, label, weight, fix). Every path is from the published CRD: `headGroupSpec.serviceType` and
#: `headGroupSpec.enableIngress` in ray.io_rayclusters.yaml v1 and v1alpha1, `spec.serveService` in
#: ray.io_rayservices.yaml, read 2026-11-06.
_DECLARED_EXPOSURES: tuple[tuple[str, PathT, PathT], ...] = (
    ("RayCluster", ("spec", "headGroupSpec"), ("spec", "headGroupSpec", "template", "spec")),
    (
        "RayService",
        ("spec", "rayClusterConfig", "headGroupSpec"),
        ("spec", "rayClusterConfig", "headGroupSpec", "template", "spec"),
    ),
    (
        "RayJob",
        ("spec", "rayClusterSpec", "headGroupSpec"),
        ("spec", "rayClusterSpec", "headGroupSpec", "template", "spec"),
    ),
)


def _declared_entries(inv: Inventory) -> list[Entry]:
    """Exposures the object asks for itself.

    A `RayCluster` with `headGroupSpec.serviceType: LoadBalancer` is asking the operator for a load balancer in
    front of its head pod -- the Ray dashboard and the job submission API, on a pod that often runs privileged.
    The Service does not exist in the manifest, so nothing matched a selector and the scan answered `0 attack
    paths from 0 exposures`: a declared internet exposure reported as no exposure (G233).
    """
    out: list[Entry] = []
    for kind, head, pods in _DECLARED_EXPOSURES:
        for obj in inv.of(kind):
            ref, target = _ref(obj), (_ref(obj), pods)
            node = _get(obj, *(str(k) for k in head))
            if not isinstance(node, dict):
                continue
            service_type = str(node.get("serviceType") or "")
            if service_type in {"LoadBalancer", "NodePort"}:
                label, weight = (
                    ("internet (LoadBalancer)", 3) if service_type == "LoadBalancer" else ("node network", 2)
                )
                out.append(
                    Entry(
                        label,
                        weight,
                        (
                            Step(
                                label.split(" (")[0],
                                ref,
                                "exposed by",
                                f"{'.'.join(str(k) for k in head)}.serviceType={service_type}, so the operator "
                                "creates that Service for the head pod",
                            ),
                        ),
                        _ns(obj),
                        "",
                        "set serviceType: ClusterIP and reach the head through a Route or Ingress with "
                        "authentication in front of it",
                        declared_on=target,
                    )
                )
            if node.get("enableIngress") is True:
                out.append(
                    Entry(
                        "internet (Ingress)",
                        3,
                        (
                            Step(
                                "internet",
                                ref,
                                "exposed by",
                                f"{'.'.join(str(k) for k in head)}.enableIngress=true, so the operator creates an "
                                "Ingress for the head pod",
                            ),
                        ),
                        _ns(obj),
                        "",
                        "set enableIngress: false, or put authentication in front of the generated Ingress",
                        declared_on=target,
                    )
                )
    return out


# --- what a pod can do -------------------------------------------------------------------------------------------


def _node_capabilities(w: dict[str, Any], spec: dict[str, Any], site: _Site | None = None) -> list[Capability]:
    out: list[Capability] = []
    base = _dotted(site.path) + "." if site is not None and site.path else ""
    if _get(spec, "securityContext", "windowsOptions", "hostProcess") is True:
        out.append(
            Capability(
                "Windows HostProcess pod: privileged access to the host",
                "node",
                9,
                "spec.securityContext.windowsOptions.hostProcess=true",
                "remove windowsOptions.hostProcess",
                at=f"{base}securityContext.windowsOptions.hostProcess",
            )
        )
    for at, c in _located_containers(spec, site):
        # A KServe `model:` is a container without a name: call it by its field, not "None".
        name = c.get("name") or at.rsplit(".", 1)[-1]
        raw_sc = c.get("securityContext")
        sc: dict[str, Any] = raw_sc if isinstance(raw_sc, dict) else {}
        if _get(sc, "windowsOptions", "hostProcess") is True:
            out.append(
                Capability(
                    "Windows HostProcess container: privileged access to the host",
                    "node",
                    9,
                    f"container {name} securityContext.windowsOptions.hostProcess=true",
                    "remove windowsOptions.hostProcess",
                    at=f"{at}.securityContext.windowsOptions.hostProcess",
                )
            )
        if sc.get("procMount") == "Unmasked":
            out.append(
                Capability(
                    "unmasked /proc: host kernel interfaces",
                    "node",
                    6,
                    f"container {name} securityContext.procMount=Unmasked",
                    "remove securityContext.procMount: Unmasked",
                    at=f"{at}.securityContext.procMount",
                )
            )
        if sc.get("privileged") is True:
            out.append(
                Capability(
                    "privileged container: full access to the node",
                    "node",
                    9,
                    f"container {name} securityContext.privileged=true",
                    "remove privileged; grant only the capability needed",
                    at=f"{at}.securityContext.privileged",
                )
            )
        caps = {str(x).upper().removeprefix("CAP_") for x in _list(_get(sc, "capabilities", "add"))}
        if caps & DANGEROUS_CAPS:
            near = bool(caps & _NEAR_ROOT_CAPS)
            out.append(
                Capability(
                    f"{'near-root' if near else 'dangerous'} capabilities {sorted(caps & DANGEROUS_CAPS)}",
                    "node",
                    7 if near else 5,
                    f"container {name} capabilities.add={sorted(caps)}",
                    "drop the added capabilities",
                    at=f"{at}.securityContext.capabilities.add",
                )
            )
    for vi, v in enumerate(_list(spec.get("volumes"))):
        path = _get(v, "hostPath", "path")
        if isinstance(path, str):
            # `/etc/../`, `//etc` and `/var/run/docker.sock/` are the paths they resolve to.
            norm = "/" + posixpath.normpath("/" + path).lstrip("/")
            worst = norm in _SYSTEM_PATHS or any(norm.endswith(s) for s in RUNTIME_SOCKETS)
            out.append(
                Capability(
                    f"host path {path}" + (": node takeover" if worst else ""),
                    "node",
                    9 if worst else 7,
                    f"volume {v.get('name')} hostPath.path={path}",
                    "replace the hostPath volume with a PVC, emptyDir or ConfigMap",
                    at=f"{base}volumes[{vi}].hostPath.path",
                )
            )
    for fld, weight in (("hostPID", 8), ("hostNetwork", 6), ("hostIPC", 5)):
        if spec.get(fld) is True:
            out.append(
                Capability(
                    f"host namespace {fld}", "node", weight, f"spec.{fld}=true", f"remove {fld}", at=f"{base}{fld}"
                )
            )
    return out


@dataclass(frozen=True)
class Grant:
    """One RBAC rule that applies to a ServiceAccount, with where it came from."""

    rule: dict[str, Any]
    cluster: bool
    namespace: str
    evidence: str
    role_ref: str
    #: Where the grant came from, for the blast-radius graph (G273): the binding (or SCC) that names the account,
    #: the subject that matched and its field, and the rule's field in the role.
    binding: str = ""
    subject: str = ""
    subject_at: str = ""
    rule_at: str = ""


@dataclass(frozen=True)
class Gap:
    """A binding that names the account, whose rules this input cannot show in full (G273)."""

    binding: str
    subject: str
    subject_at: str
    role_ref: str
    reason: str


#: The user-facing ClusterRoles are aggregated: "To add rules to the admin, edit, or view roles, create a ClusterRole
#: with one or more of the following labels" (https://kubernetes.io/docs/reference/access-authn-authz/rbac/
#: #user-facing-roles, read 2026-11-12). The page names one label per role and says nothing about edit feeding admin
#: or view feeding edit, so no such chain is assumed here.
BUILTIN_AGGREGATION: dict[str, list[dict[str, Any]]] = {
    name: [{"matchLabels": {f"rbac.authorization.k8s.io/aggregate-to-{name}": "true"}}]
    for name in ("admin", "edit", "view")
}
_RULE_LISTS = ("apiGroups", "resources", "verbs", "resourceNames", "nonResourceURLs")


@dataclass
class RoleBook:
    """Every role's effective rules, and what about each the input cannot show (G273).

    `rules` maps "Role/ns/name" or "ClusterRole/name" to its rules, `None` when the object is not in the input.
    `open` maps a role to why its rules are not the whole answer: an aggregated ClusterRole (its sources are whatever
    the cluster holds), a built-in stand-in, a duplicated name, or `rules` that is not a list.
    """

    rules: dict[str, list[Any]] = field(default_factory=dict)
    open: dict[str, str] = field(default_factory=dict)
    #: Role refs whose `rules` cannot be read at all (not a list): nothing about them is known.
    unreadable: set[str] = field(default_factory=set)
    #: Aggregated ClusterRoles in the input with no rules of their own and no source in it: the scan's notRead.
    empty: set[str] = field(default_factory=set)

    def get(self, ref: str) -> list[Any] | None:
        return self.rules.get(ref)


def _labels(obj: dict[str, Any]) -> dict[str, str]:
    raw = _get(obj, "metadata", "labels")
    return {str(k): str(v) for k, v in raw.items()} if isinstance(raw, dict) else {}


def _role_book(inv: Inventory) -> RoleBook:
    book = RoleBook()
    seen: dict[str, int] = {}
    labels: dict[str, dict[str, str]] = {}
    selectors: dict[str, list[dict[str, Any]]] = {}
    for r in inv.of("Role", "ClusterRole"):
        cluster = r.get("kind") == "ClusterRole"
        ref = f"ClusterRole/{_name(r)}" if cluster else f"Role/{_ns(r)}/{_name(r)}"
        seen[ref] = seen.get(ref, 0) + 1
        raw = r.get("rules")
        if raw is not None and not isinstance(raw, list):
            book.unreadable.add(ref)
            book.open[ref] = f"{ref}: rules is a {type(raw).__name__}, not a list, so what it grants is not known"
        # Two objects of one name: the API keeps one, the input does not say which, so both count (the worst case).
        book.rules.setdefault(ref, []).extend(_list(raw))
        if cluster:
            labels[ref] = {**labels.get(ref, {}), **_labels(r)}
            agg = r.get("aggregationRule")
            if agg is not None:
                sel = _get(agg, "clusterRoleSelectors")
                if not isinstance(sel, list):
                    book.open[ref] = f"{ref}: aggregationRule.clusterRoleSelectors is not a list"
                selectors.setdefault(ref, []).extend(s for s in _list(sel) if isinstance(s, dict))
    for ref, n in seen.items():
        if n > 1:
            book.open.setdefault(ref, f"{n} objects named {ref} are in the input; the rules of all of them are counted")
    stand_ins: set[str] = set()
    for name, rules in BUILTIN_CLUSTER_ROLES.items():
        ref = f"ClusterRole/{name}"
        if ref not in book.rules:
            book.rules[ref] = list(rules)
            stand_ins.add(ref)
            if name in BUILTIN_AGGREGATION:
                selectors[ref] = BUILTIN_AGGREGATION[name]
    # Aggregation to a fixed point: a role's rules are its own plus those of every ClusterRole its selectors reach,
    # directly or through another aggregated role. A reachability walk, so the answer cannot depend on the order the
    # roles or their label names sort in. The own rules are kept too: the control plane overwrites them in a
    # cluster, so in an export they ARE the aggregated rules, and in a hand-written bundle they are the worst case.
    sources = {
        ref: sorted(o for o, lab in labels.items() if o != ref and any(selector_matches(s, lab) for s in sels))
        for ref, sels in selectors.items()
    }
    own = {ref: list(rules) for ref, rules in book.rules.items()}
    for ref in sorted(selectors):
        reached: list[str] = []
        todo = list(sources.get(ref, []))
        while todo:
            nxt = todo.pop(0)
            if nxt in reached or nxt == ref:
                continue
            reached.append(nxt)
            todo += sources.get(nxt, [])
        reached.sort()
        book.rules[ref] = own[ref] + [rule for src in reached for rule in own.get(src, [])]
        counted = f"{len(reached)} in the input counted ({', '.join(reached[:5])}{' ...' if len(reached) > 5 else ''})"
        if ref in stand_ins:
            book.open.setdefault(
                ref,
                f"{ref} is not in the input: its documented rules stand in for it, and it aggregates every ClusterRole "
                f"labelled rbac.authorization.k8s.io/aggregate-to-{ref.split('/')[-1]}: "
                + (counted if reached else "none in the input does")
                + "; those elsewhere in the cluster are not known",
            )
        else:
            if not book.rules[ref]:
                book.empty.add(ref)
            book.open.setdefault(
                ref,
                f"{ref} aggregates the rules of ClusterRoles selected by label (aggregationRule.clusterRoleSelectors): "
                + (counted if reached else "none in the input matches")
                + "; those elsewhere in the cluster are not known",
            )
    return book


def _role_rules(inv: Inventory) -> tuple[dict[tuple[str, str], list[Any]], dict[str, list[Any]]]:
    """(Role rules by (namespace, name), ClusterRole rules by name), aggregation applied: the older shape."""
    book = _role_book(inv)
    roles = {
        (ref.split("/")[1], ref.split("/")[2]): rules for ref, rules in book.rules.items() if ref.startswith("Role/")
    }
    cluster_roles = {ref.split("/", 1)[1]: rules for ref, rules in book.rules.items() if ref.startswith("ClusterRole/")}
    return roles, cluster_roles


def _sa_groups(sa_ns: str) -> set[str]:
    return {"system:serviceaccounts", f"system:serviceaccounts:{sa_ns}", "system:authenticated"}


def _subject_matches(subj: Any, sa_ns: str, sa: str, binding_ns: str | None) -> str | None:
    if not isinstance(subj, dict):
        return None
    kind, name = subj.get("kind"), str(subj.get("name") or "")
    if kind == "ServiceAccount":
        ns = subj.get("namespace") or binding_ns
        return f"subject ServiceAccount {ns}/{name}" if name == sa and ns == sa_ns else None
    if kind == "Group" and name in {
        "system:serviceaccounts",
        f"system:serviceaccounts:{sa_ns}",
        "system:authenticated",
    }:
        return f"subject Group {name}"
    if kind == "User" and name == f"system:serviceaccount:{sa_ns}:{sa}":
        return f"subject User {name}"
    return None


def _malformed_rule(rule: Any) -> str | None:
    """Why a rule cannot be read, or None. A scalar where the API requires a list (`verbs: "*"`) read as no verbs at
    all, so a rule granting everything scored nothing (G273)."""
    if not isinstance(rule, dict):
        return f"is a {type(rule).__name__}, not a rule"
    bad = [k for k in _RULE_LISTS if k in rule and rule[k] is not None and not isinstance(rule[k], list)]
    return f"{', '.join(bad)} {'is' if len(bad) == 1 else 'are'} not a list" if bad else None


def _grants(inv: Inventory, sa_ns: str, sa: str, gaps: list[Gap] | None = None) -> list[Grant]:
    """Every RBAC rule that applies to the ServiceAccount. ``gaps`` collects the bindings that name it, or may name
    it, whose rules the input cannot show in full: a role not in it, an aggregated or duplicated role, a stand-in for a
    built-in, or a field that is not the shape the API requires (G273)."""
    book = _role_book(inv)
    out: list[Grant] = []

    def gap(b: dict[str, Any], who: str, at: str, role_ref: str, reason: str) -> None:
        if gaps is not None:
            gaps.append(Gap(_ref(b), who, at, role_ref, reason))

    for b in inv.of("RoleBinding", "ClusterRoleBinding"):
        cluster = b.get("kind") == "ClusterRoleBinding"
        bns = None if cluster else _ns(b)
        ref = b.get("roleRef")
        rname = str(ref.get("name") or "") if isinstance(ref, dict) else ""
        role_ref = (
            f"Role/{bns}/{rname}"
            if isinstance(ref, dict) and ref.get("kind") == "Role" and not cluster
            else f"ClusterRole/{rname}"
        )
        subjects = b.get("subjects")
        if subjects is not None and not isinstance(subjects, list):
            # Who it binds cannot be read, so it may bind this account: an unknown, not a "no".
            gap(
                b,
                "subjects unreadable",
                "subjects",
                role_ref,
                f"{_ref(b)}: subjects is not a list, so whom it binds is not known",
            )
            continue
        # No shortcut on the binding's namespace: a RoleBinding in another namespace grants this account rights
        # there through a ServiceAccount subject, and just as much through the groups system:serviceaccounts,
        # system:serviceaccounts:<its namespace> and system:authenticated, or the User system:serviceaccount:ns:name.
        # Skipping all but the first dropped those grants from the scan without a word (G273).
        matched = next(
            ((j, m) for j, s in enumerate(_list(subjects)) if (m := _subject_matches(s, sa_ns, sa, bns))),
            None,
        )
        if matched is None:
            continue
        j, who = matched
        if not isinstance(ref, dict) or not rname:
            gap(b, who, f"subjects[{j}]", role_ref, f"{_ref(b)}: roleRef does not name a role")
            continue
        rules = book.get(role_ref)
        if rules is None:
            inv.not_read.append(f"{role_ref} (bound by {_ref(b)}) is not in the input")
            gap(b, who, f"subjects[{j}]", role_ref, f"{role_ref} is not in the input")
            continue
        if role_ref in book.open:
            reason = book.open[role_ref]
            if role_ref in book.empty:
                inv.not_read.append(
                    f"{role_ref} (bound by {_ref(b)}) aggregates ClusterRoles by label and none in the input matches"
                )
            gap(b, who, f"subjects[{j}]", role_ref, reason)
        for i, rule in enumerate(rules):
            why = _malformed_rule(rule)
            if why is not None:
                gap(b, who, f"subjects[{j}]", role_ref, f"{role_ref} rules[{i}] {why}, so what it grants is not known")
                continue
            out.append(
                Grant(
                    rule,
                    cluster,
                    str(bns or ""),
                    f"{_ref(b)} ({who}) -> {role_ref} rules[{i}]",
                    role_ref,
                    binding=_ref(b),
                    subject=who,
                    subject_at=f"subjects[{j}]",
                    rule_at=f"rules[{i}]",
                )
            )
    # OpenShift legacy: an SCC listing the ServiceAccount (or its groups) lets it use the SCC
    for scc in inv.of("SecurityContextConstraints"):
        users = _strs(scc.get("users"))
        groups = _strs(scc.get("groups"))
        user = f"system:serviceaccount:{sa_ns}:{sa}"
        if user in users or groups & _sa_groups(sa_ns):
            subject_at, subject = (
                ("users", f"user {user}")
                if user in users
                else ("groups", f"group {sorted(groups & _sa_groups(sa_ns))[0]}")
            )
            rule = {
                "apiGroups": ["security.openshift.io"],
                "resources": ["securitycontextconstraints"],
                "verbs": ["use"],
                "resourceNames": [_name(scc)],
            }
            out.append(
                Grant(
                    rule,
                    True,
                    "",
                    f"{_ref(scc)} users/groups name the ServiceAccount",
                    _ref(scc),
                    binding=_ref(scc),
                    subject=subject,
                    subject_at=subject_at,
                    rule_at=subject_at,
                )
            )
    return out


def _privileged_scc_names(inv: Inventory) -> set[str]:
    names = set(PRIVILEGED_SCCS)
    for scc in inv.of("SecurityContextConstraints"):
        if scc.get("allowPrivilegedContainer") is True or scc.get("allowHostDirVolumePlugin") is True:
            names.add(_name(scc))
    return names


def reads_secrets(rule: dict[str, Any]) -> bool:
    """True when an RBAC rule lets its holder read Secret objects (get, list or watch, or every verb)."""
    verbs, res, groups = _strs(rule.get("verbs")), _strs(rule.get("resources")), _strs(rule.get("apiGroups"))
    core = bool(groups & {"", "*"}) or not groups
    return core and bool(res & {"*", "secrets"}) and bool(verbs & {"*", "get", "list", "watch"})


_READ = frozenset({"get", "list", "watch"})
#: Reads that are not reads: Secret contents, exec and attach over WebSocket (an HTTP GET, so the verb is `get`:
#: https://kubernetes.io/blog/2024/08/20/websockets-transition/ and the verb table at
#: https://kubernetes.io/docs/reference/access-authn-authz/authorization/#determine-the-request-verb), port-forward
#: the same way, and the kubelet API through nodes/proxy ("get permission on nodes/proxy is not a read-only
#: permission", https://kubernetes.io/docs/concepts/security/rbac-good-practices/).
_NOT_READ_ONLY = frozenset({"secrets", "pods/exec", "pods/attach", "pods/portforward", "nodes/proxy"})
_RBAC_OBJECTS = frozenset({"roles", "rolebindings", "clusterroles", "clusterrolebindings"})


def _known_harmless(rule: dict[str, Any]) -> bool:
    """A rule this scan knows grants nothing it ranks. Everything else that matched no capability is reported as
    not classified, never as "nothing" (G273)."""
    verbs, res = _strs(rule.get("verbs")), _strs(rule.get("resources"))
    if not verbs:
        return True  # a rule with no verbs grants nothing
    if "*" in verbs:
        return False
    if not res and rule.get("nonResourceURLs") is not None:
        return verbs <= _READ  # /healthz, /metrics, /version
    if verbs <= _READ:
        return "*" not in res and not res & _NOT_READ_ONLY
    # Creating or changing roles and bindings is not an escalation without `escalate` or `bind`: the API refuses a
    # role or binding carrying rights the caller does not already hold
    # (https://kubernetes.io/docs/reference/access-authn-authz/rbac/#privilege-escalation-prevention-and-bootstrapping).
    if res and res <= _RBAC_OBJECTS and not verbs & ESCALATION_VERBS:
        return True
    return bool(res) and res <= {"events"} and "*" not in res


def _api_capabilities(inv: Inventory, grants: list[Grant], unclassified: list[Grant] | None = None) -> list[Capability]:
    """What the grants let the account do. ``unclassified`` collects the grants that matched no capability and are
    not known to be harmless: the blast radius reports those as not determined instead of as "nothing" (G273).

    The escalation rights are the ones the Kubernetes RBAC good-practices page names
    (https://kubernetes.io/docs/concepts/security/rbac-good-practices/#privilege-escalation-risks, read 2026-11-12):
    reading Secrets, creating workloads, PersistentVolume creation, nodes/proxy, escalate, bind, impersonate, CSR
    creation with approval, TokenRequest (`serviceaccounts/token` create) and control of admission webhooks; plus
    exec and attach (`create`, or `get` over WebSocket), ephemeral containers (`patch`/`update` on
    `pods/ephemeralcontainers`, which "run arbitrary commands" in an existing Pod:
    https://kubernetes.io/docs/concepts/workloads/pods/ephemeral-containers/) and creating a Secret, which mints a
    long-lived token for any ServiceAccount named in its annotation
    (https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/
    #manually-create-a-long-lived-api-token-for-a-serviceaccount).
    """
    found: dict[tuple[str, str], Capability] = {}
    workload_grant: Grant | None = None
    scc_grant: tuple[Grant, str] | None = None
    csr_create: Grant | None = None
    csr_approve: Grant | None = None
    privileged = _privileged_scc_names(inv)
    used: set[int] = set()

    def add(
        name: str, g: Grant, cluster_w: int, ns_w: int, fix: str, named: bool = False, implies_reads: bool = False
    ) -> None:
        used.add(id(g))
        scope = "cluster" if g.cluster else f"namespace {g.namespace}"
        weight = (cluster_w if g.cluster else ns_w) - (2 if named else 0)
        cap = Capability(
            name + (" (named objects only)" if named else ""),
            scope,
            weight,
            g.evidence,
            fix,
            grants=(g,),
            implies_reads=implies_reads and not named,
        )
        key = (cap.name, scope)
        if key not in found or found[key].weight < weight:
            found[key] = cap

    for g in grants:
        verbs, res = _strs(g.rule.get("verbs")), _strs(g.rule.get("resources"))
        groups, names = _strs(g.rule.get("apiGroups")), _strs(g.rule.get("resourceNames"))
        any_res, any_verb = "*" in res, "*" in verbs
        core = bool(groups & {"", "*"}) or not groups
        builtin = g.role_ref.removeprefix("ClusterRole/") in BUILTIN_CLUSTER_ROLES or ":" in g.role_ref.split("/")[-1]
        narrow = (
            f"bind a narrower Role than the built-in {g.role_ref}"
            if builtin
            else f"narrow {g.evidence.split(' -> ')[-1]}"
        )

        def has(*resources: str) -> bool:
            return any_res or bool(res & set(resources))  # noqa: B023 -- called inside this iteration only

        def can(*vs: str) -> bool:
            return any_verb or bool(verbs & set(vs))  # noqa: B023 -- called inside this iteration only

        if any_res and any_verb and "*" in groups:
            add("full control", g, 10, 7, f"bind a narrower role than {g.role_ref}", implies_reads=True)
        if reads_secrets(g.rule):
            add(
                "read Secrets (credentials, tokens of other ServiceAccounts)",
                g,
                8,
                6,
                f"{narrow}: drop secrets",
                named=bool(names),
            )
        if verbs & ESCALATION_VERBS or (any_verb and (any_res or res & _IDENTITY_RESOURCES)):
            add(
                "escalate, bind or impersonate",
                g,
                9,
                6,
                f"{narrow}: drop escalate, bind and impersonate",
                implies_reads=True,
            )
        if core and has("pods/exec", "pods/attach") and can("create", "get"):
            add("exec into pods", g, 7, 5, f"{narrow}: drop pods/exec and pods/attach")
        if core and has("pods/ephemeralcontainers") and can("patch", "update"):
            add(
                "add containers to running pods (pods/ephemeralcontainers)",
                g,
                7,
                5,
                f"{narrow}: drop patch/update on pods/ephemeralcontainers",
            )
        if has(*WORKLOAD_RESOURCES) and can("create", "patch", "update"):
            add(
                "create or change workloads (run as any ServiceAccount of the namespace)",
                g,
                7,
                5,
                f"{narrow}: drop create/patch/update on workloads",
                implies_reads=True,
            )
            workload_grant = workload_grant or g
        if core and has("serviceaccounts/token") and can("create"):
            add(
                "mint tokens for its ServiceAccounts (serviceaccounts/token create)",
                g,
                7,
                5,
                f"{narrow}: drop create on serviceaccounts/token",
            )
        if core and has("secrets") and can("create"):
            add(
                "mint long-lived ServiceAccount tokens (create a service-account-token Secret)",
                g,
                7,
                5,
                f"{narrow}: drop create on secrets",
            )
        if core and has("nodes/proxy") and can("get", "create") and g.cluster:
            add("kubelet API through nodes/proxy", g, 8, 8, f"{narrow}: drop nodes/proxy")
        if g.cluster and core and has("persistentvolumes") and can("create"):
            add(
                "create PersistentVolumes (a hostPath on a node)",
                g,
                8,
                8,
                f"{narrow}: drop create on persistentvolumes",
            )
        admission = bool(groups & {"admissionregistration.k8s.io", "*"})
        if (
            g.cluster
            and admission
            and has("validatingwebhookconfigurations", "mutatingwebhookconfigurations")
            and can("create", "update", "patch")
        ):
            add(
                "control admission webhooks (read and change every admitted object)",
                g,
                9,
                9,
                f"{narrow}: drop write access to webhook configurations",
            )
        certs = bool(groups & {"certificates.k8s.io", "*"})
        if g.cluster and certs and has("certificatesigningrequests") and can("create"):
            csr_create = csr_create or g
        if g.cluster and certs and has("certificatesigningrequests/approval") and can("update"):
            csr_approve = csr_approve or g
        if "securitycontextconstraints" in res and (any_verb or "use" in verbs):
            usable = names & privileged if names else privileged
            if usable:
                scc_grant = (g, sorted(usable)[0])
    if workload_grant and scc_grant:
        g, scc = scc_grant
        used.add(id(g))
        found[("run privileged pods", "node")] = Capability(
            f"run privileged pods (SCC {scc} + create workloads)",
            "node",
            9,
            f"{g.evidence}; and {workload_grant.evidence}",
            f"remove the 'use' grant on SCC {scc} or the right to create workloads",
            grants=(g, workload_grant),
        )
    if csr_create and csr_approve:
        used.update({id(csr_create), id(csr_approve)})
        found[("issue client certificates", "cluster")] = Capability(
            "issue client certificates (create and approve CertificateSigningRequests)",
            "cluster",
            9,
            f"{csr_create.evidence}; and {csr_approve.evidence}",
            "remove create on certificatesigningrequests or update on certificatesigningrequests/approval",
            grants=(csr_create, csr_approve),
        )
    if unclassified is not None:
        unclassified += [g for g in grants if id(g) not in used and not _known_harmless(g.rule)]
    return list(found.values())


@dataclass(frozen=True)
class Mount:
    """How the pod gets its ServiceAccount's token: the account, the evidence line, the field that proves it, and
    the audience a projected token asks for ("" for the API server's own)."""

    service_account: str
    evidence: str
    at: str
    audience: str = ""


def _token(
    no_automount: set[tuple[str, str]], w: dict[str, Any], spec: dict[str, Any], site: _Site | None = None
) -> Mount | None:
    """The token mount when the pod has one, else None. ``no_automount``: the ServiceAccounts that turn automount
    off, by (namespace, name).

    Two ways in: the automounted token, and a projected volume with a `serviceAccountToken` source mounted by a
    container -- which `automountServiceAccountToken: false` does not touch
    (https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/
    #serviceaccount-token-volume-projection). Reading only the first said "no token, no API rights" for a pod that
    holds its account's token at a path of its choosing (G273)."""
    base = _dotted(site.path) + "." if site is not None and site.path else ""
    named_by = next((f for f in ("serviceAccountName", "serviceAccount") if spec.get(f)), None)
    sa = str(spec.get(named_by) if named_by else "default")
    who = f"spec.{named_by}={sa}" if named_by else "spec.serviceAccountName unset, so default"
    sa_at = f"{base}{named_by or 'serviceAccountName'}"
    pod_flag = spec.get("automountServiceAccountToken")
    automount = pod_flag is not False and not (pod_flag is not True and (_ns(w), sa) in no_automount)
    if automount:
        how = "automountServiceAccountToken=true" if pod_flag is True else "token mounted (automount not turned off)"
        return Mount(sa, f"{who}; {how}", sa_at)
    mounted = {
        str(m.get("name"))
        for _at, c in _located_containers(spec, site)
        for m in _list(c.get("volumeMounts"))
        if isinstance(m, dict)
    }
    for i, v in enumerate(_list(spec.get("volumes"))):
        if not isinstance(v, dict) or str(v.get("name")) not in mounted:
            continue
        for j, src in enumerate(_list(_get(v, "projected", "sources"))):
            tok = _get(src, "serviceAccountToken")
            if isinstance(tok, dict):
                audience = str(tok.get("audience") or "")
                return Mount(
                    sa,
                    f"{who}; volume {v.get('name')} projects its token (projected.sources[{j}].serviceAccountToken"
                    + (f", audience {audience}" if audience else "")
                    + ") although automount is off",
                    f"{base}volumes[{i}].projected.sources[{j}].serviceAccountToken",
                    audience,
                )
    return None


# --- the scan ----------------------------------------------------------------------------------------------------


@dataclass
class Reach:
    """What an attacker running code in one workload's pods gets, and how they would arrive (VUL1 ranks findings in
    the workload's images with it)."""

    ref: str
    namespace: str
    images: list[str]
    entries: list[tuple[int, Entry, list[Step]]]  # (index in the entry list, entry, steps up to the workload)
    node: list[Capability]
    api: list[tuple[Capability, list[Step]]]  # capability and the steps from the workload to it
    token: tuple[str, str] | None = None  # (ServiceAccount ref, evidence) when the pods mount its token
    #: How the pods hold the account's token (automount or a projected volume), None when they do not: what the
    #: blast radius prints, read from a field named for what it is (G273).
    mount: Mount | None = None
    #: The carrying object's own `Kind/ns/name`. For an embedded component `ref` is `Kind/ns/name[component]`,
    #: so a consumer that looks an object up by the reach key finds nothing -- which is how `vuln threat` came
    #: to report zero applications for a Ray head the scan had just called internet-reachable. Carried as a
    #: field rather than left to `ref.split("[")` so the next consumer cannot get the parsing wrong (G231).
    object: str = ""
    #: True when an operator merges in this pod's labels, so a non-match proves nothing about its exposure.
    embedded: bool = False

    def paths_from(self, index: int) -> list[AttackPath]:
        out: list[AttackPath] = []
        for i, entry, base in self.entries:
            if i != index:
                continue
            for cap in self.node:
                out.append(AttackPath(entry, [*base, Step(self.ref, "node", "runs on", cap.evidence)], cap))
            for cap, tail in self.api:
                out.append(AttackPath(entry, [*base, *tail], cap))
        return out

    def paths(self) -> list[AttackPath]:
        out = [p for i in dict.fromkeys(i for i, _, _ in self.entries) for p in self.paths_from(i)]
        out.sort(key=lambda p: (-p.score, len(p.steps), p.as_dict(0)["summary"]))
        return out

    @property
    def exposure(self) -> Entry | None:
        """The widest exposure that reaches the workload (internet before node network before internal)."""
        best = sorted(self.entries, key=lambda e: (-e[1].weight, e[0]))
        return best[0][1] if best else None

    @property
    def capabilities(self) -> list[Capability]:
        caps = [*self.node, *(c for c, _ in self.api)]
        return sorted(caps, key=lambda c: (-c.weight, c.name))

    def entry_steps(self) -> list[Step]:
        best = sorted(self.entries, key=lambda e: (-e[1].weight, e[0]))
        return list(best[0][2]) if best else []


@dataclass
class _Index:
    """What every workload's reach needs, built once per scan: which entries reach each workload (through the
    Service whose selector matches its pod template, found through a label index rather than by testing every
    entry against every workload) and which ServiceAccounts turn token automount off. Looking these up per
    workload made the scan cubic in the size of the input (red team, VUL1)."""

    selects: dict[int, list[tuple[int, Entry, dict[str, Any]]]]  # id(site) -> (entry index, entry, selector)
    no_automount: set[tuple[str, str]]

    @classmethod
    def build(cls, inv: Inventory, entries: list[Entry], sites: list[_Site]) -> _Index:
        services: dict[tuple[str, str], dict[str, Any]] = {}
        for s in inv.of("Service"):
            services.setdefault((_ns(s), _name(s)), s)  # the first of a duplicated name, as kubectl apply would keep
        by_label: dict[tuple[str, str, str], list[int]] = {}
        for n, site in enumerate(sites):
            for k, v in site.labels.items():
                by_label.setdefault((_ns(site.obj), k, v), []).append(n)
        selects: dict[int, list[tuple[int, Entry, dict[str, Any]]]] = {}
        by_target = {(site.ref.split("[")[0], site.path): n for n, site in enumerate(sites)}
        for i, e in enumerate(entries):
            if e.declared_on is not None:
                target_n = by_target.get(e.declared_on)
                if target_n is not None:
                    selects.setdefault(id(sites[target_n]), []).append((i, e, {}))
                continue
            svc = services.get((e.namespace, e.service))
            selector = _get(svc, "spec", "selector") if svc else None
            if not isinstance(selector, dict) or not selector:
                continue
            candidates = min((by_label.get((e.namespace, str(k), str(v)), []) for k, v in selector.items()), key=len)
            for n in candidates:
                # True only. A None ("the operator merges in labels this input does not show") must not become
                # an edge the report presents as proven; it becomes a named limitation instead (G231).
                if selector_decides({"matchLabels": selector}, sites[n].template) is True:
                    selects.setdefault(id(sites[n]), []).append((i, e, selector))
        # Off only when EVERY object of that name turns it off: two ServiceAccounts with one name that disagree are
        # an ambiguity, and the scan takes the worst case -- the token is mounted (G273).
        flags: dict[tuple[str, str], set[bool]] = {}
        for sa in inv.of("ServiceAccount"):
            flags.setdefault((_ns(sa), _name(sa)), set()).add(sa.get("automountServiceAccountToken") is False)
        no_automount = {key for key, seen in flags.items() if seen == {True}}
        return cls(selects, no_automount)


def _reach(
    inv: Inventory,
    site: _Site,
    index: _Index,
    sa_caps: dict[tuple[str, str], list[Capability]],
) -> Reach:
    w, spec, ref = site.obj, site.spec, site.ref
    reach_entries: list[tuple[int, Entry, list[Step]]] = []
    for i, entry, selector in index.selects.get(id(site), []):
        if entry.declared_on is not None:
            # The object asked for the exposure itself, so there is no Service in this input to step through.
            # Reusing the selector step here printed `Service/ns/ --selects--> ...  (selector {} matches ...)`:
            # a Service with no name, and an evidence line that was simply untrue (G233).
            to_w = Step(
                entry.declared_on[0],
                ref,
                "runs",
                f"this pod spec is at {'.'.join(str(k) for k in site.path)} of that object",
            )
        else:
            to_w = Step(
                f"Service/{entry.namespace}/{entry.service}",
                ref,
                "selects",
                f"selector {selector} matches the pod template labels",
            )
        reach_entries.append((i, entry, [*entry.steps, to_w]))
    api: list[tuple[Capability, list[Step]]] = []
    mount = _token(index.no_automount, w, spec, site)
    if mount is not None:
        sa, evidence = mount.service_account, mount.evidence
        key = (_ns(w), sa)
        if key not in sa_caps:
            sa_caps[key] = _api_capabilities(inv, _grants(inv, *key))
        sa_ref = f"ServiceAccount/{key[0]}/{sa}"
        for cap in sa_caps[key]:
            # The scope of the GRANT, not the account's namespace: a RoleBinding in `other` gives rights in `other`,
            # and the step said `(shop)` while the same document's graph said `(other)` (G273).
            target = cap.scope if cap.scope in {"node", "cluster"} else cap.scope.removeprefix("namespace ")
            api.append(
                (
                    cap,
                    [
                        Step(ref, sa_ref, "uses token of", evidence),
                        Step(sa_ref, f"{cap.name} ({target})", "is allowed to", cap.evidence),
                    ],
                )
            )
    images = [
        str(c.get("image")) for c in _containers(spec, site) if isinstance(c.get("image"), str) and c.get("image")
    ]
    token = (f"ServiceAccount/{_ns(w)}/{mount.service_account}", mount.evidence) if mount else None
    return Reach(
        ref,
        _ns(w),
        images,
        reach_entries,
        _node_capabilities(w, spec, site),
        api,
        token,
        mount=mount,
        object=_ref(w),
        embedded=site.embedded,
    )


def workload_reach(inv: Inventory) -> dict[str, Reach]:
    """Every workload (not owned by another) with its exposures, node and API capabilities, keyed by Kind/ns/name."""
    sites = _sites(inv, owned=False)
    index = _Index.build(inv, _entries(inv), sites)
    sa_caps: dict[tuple[str, str], list[Capability]] = {}
    out: dict[str, Reach] = {}
    for site in sites:
        out[site.ref] = _reach(inv, site, index, sa_caps)
    return out


def reach_of(inv: Inventory, obj: dict[str, Any]) -> list[tuple[_Site, Reach]]:
    """The reach of one workload object's pod specs, through the same entries, index and RBAC reading the scan
    uses, so the blast radius of a workload and the paths the scan ranks through it cannot disagree (G273)."""
    sites = _sites(inv, owned=False)
    mine = [s for s in sites if s.obj is obj] or _sites_of(obj)
    index = _Index.build(inv, _entries(inv), sites if any(s.obj is obj for s in sites) else [*sites, *mine])
    sa_caps: dict[tuple[str, str], list[Capability]] = {}
    return [(site, _reach(inv, site, index, sa_caps)) for site in mine]


def grants_of(inv: Inventory, namespace: str, service_account: str) -> tuple[list[Grant], list[Gap]]:
    """Every RBAC rule that applies to a ServiceAccount, and the bindings naming it whose rules the input does
    not show in full."""
    gaps: list[Gap] = []
    return _grants(inv, namespace, service_account, gaps), gaps


def unclassified_of(inv: Inventory, grants: list[Grant]) -> list[Grant]:
    """The grants that matched no capability this scan ranks and are not known to be harmless (G273)."""
    out: list[Grant] = []
    _api_capabilities(inv, grants, out)
    return out


def scan(inv: Inventory, *, top: int = DEFAULT_TOP) -> dict[str, Any]:
    if not 1 <= top <= MAX_PATHS:
        raise ScanError(f"top must be 1-{MAX_PATHS}")
    sites = _sites(inv, owned=False)
    entries = _entries(inv)
    index = _Index.build(inv, entries, sites)
    sa_caps: dict[tuple[str, str], list[Capability]] = {}
    reach: list[Reach] = [_reach(inv, site, index, sa_caps) for site in sites]
    by_entry: dict[int, list[AttackPath]] = {}
    for r in reach:  # each workload's paths, grouped by entry in workload order, as the scan always listed them
        for i in dict.fromkeys(i for i, _, _ in r.entries):
            by_entry.setdefault(i, []).extend(r.paths_from(i))
    paths: list[AttackPath] = [p for i in range(len(entries)) for p in by_entry.get(i, [])]
    paths.sort(key=lambda p: (-p.score, len(p.steps), p.as_dict(0)["summary"]))
    out_paths = [p.as_dict(i + 1) for i, p in enumerate(paths[:top])]
    head = out_paths[0]["summary"] if out_paths else "no path from an exposure to a node or to API rights"
    limitations = list(STANDING_LIMITATIONS)
    # A component of an operator CRD has its pod labels merged by that operator from objects outside this input,
    # and the Services it is reached through are created by the operator too. Where no edge was PROVEN, the entry
    # is UNDETERMINED, not absent -- saying nothing would read as "not exposed", the same failure one level up
    # from the one this work started with.
    #
    # Keyed on the kind, not on the labels being empty, because both of the obvious predicates are wrong: a Ray
    # head template with `labels: {app: ray}` is labelled and still unreachable from the manifest (Ray's own head
    # Service selects `ray.io/node-type`, which the operator sets), and a plain label-less Pod would otherwise be
    # told its labels are "set by the operator", which is simply false (G231).
    # Node capabilities first: they come from the pod spec itself, and with more API rights ranked a privileged
    # container fell off the end of a four-name list (G273).
    undetermined = sorted(
        (
            r.ref,
            [*(c.name for c in r.node), *(c.name for c, _ in sorted(r.api, key=lambda x: (-x[0].weight, x[0].name)))],
        )
        for r in reach
        if r.embedded and not r.entries and r.capabilities
    )
    if undetermined:
        # Name what each one can do. "Its capabilities are scored above" was the first wording and it was false:
        # with no entry there is no path, so nothing about it is printed above at all, and the reader is told to
        # look for something that is not there.
        shown = "; ".join(f"{ref} ({', '.join(caps[:4])})" for ref, caps in undetermined[:5])
        more = f" and {len(undetermined) - 5} more" if len(undetermined) > 5 else ""
        limitations.append(
            f"No exposure edge could be traced to {shown}{more}. An operator merges in these pods' labels and "
            "creates the Services they are reached through, so this input cannot show the edge -- what they can "
            "do IS listed here, but no path is scored for them. Scan the Deployments and Services the operator "
            "created alongside them -- `--live` reads those -- to complete the picture."
        )
    return {
        "paths": out_paths,
        "total": len(paths),
        "entries": len(entries),
        # Workload objects scored, not pod specs: one RayCluster with three worker groups is one workload here
        # and four pod specs in the paths (G229).
        "workloads": len({id(site.obj) for site in sites}),
        "summary": f"{len(paths)} attack paths from {len(entries)} exposures; top: {head}",
        "notRead": sorted(set(inv.not_read))[:50],
        "secretsIgnored": inv.dropped_secrets,
        "limitations": limitations,
    }


def scan_manifests(text: str, *, top: int = DEFAULT_TOP) -> dict[str, Any]:
    from kube_noob.yamlio import load_documents

    docs = load_documents(text)
    return scan(Inventory.from_documents(d.data for d in docs), top=top)


def collect_live(backend: Any, namespaces: list[str]) -> Inventory:
    """Read the inventory from the cluster through the read-only backend: never Secrets (not in its allowlist)."""
    from kube_noob.errors import KubeNoobError

    inv = Inventory()
    for resource, kind in LIVE_RESOURCES.items():
        scopes: list[str | None] = [None] if resource in CLUSTER_SCOPED or not namespaces else list(namespaces)
        for ns in scopes:
            try:
                data = backend.get(resource, namespace=ns)
            except KubeNoobError as exc:  # forbidden or not served (no Routes or SCCs on Kubernetes)
                inv.not_read.append(f"{resource}{' in ' + ns if ns else ''}: {str(exc)[:160]}")
                continue
            for item in _list(data.get("items")) if isinstance(data, dict) else []:
                inv.add(item, kind)
    inv.canonicalize()
    return inv
