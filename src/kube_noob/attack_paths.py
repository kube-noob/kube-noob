"""Attack paths: from what is exposed to what a compromised pod could do (requirements R3.2). Read-only, tier R.

A path starts at an exposure (a Route, an Ingress, a LoadBalancer, NodePort or externalIPs Service), goes to the
Service and the workloads it selects, and ends at what those pods can do if an attacker runs code in them:

- on the node: a privileged container, a hostPath volume (the container runtime socket or a system directory is
  worst), the host's PID, network or IPC namespace, or near-root capabilities;
- through the Kubernetes API, with the ServiceAccount token mounted in the pod: the RBAC it is bound to (read
  Secrets, exec into pods, create or change workloads, escalate, bind or impersonate, nodes/proxy, full control), and
  on OpenShift a privileged SecurityContextConstraints it may use together with the right to create workloads.

Each path scores exposure x blast radius (internet 3, node network or restricted load balancer 2, internal network 1;
blast radius 1-10, cluster-wide above namespace) and lists every step with the field that proves it. Paths are ranked
by score, then by fewer steps.

What it reads: Routes, Ingresses, Services, workloads, ServiceAccounts, Roles, RoleBindings, ClusterRoles,
ClusterRoleBindings and SecurityContextConstraints, from manifests or (``--live``) the cluster's read-only allowlist.
Never Secrets: Secret objects in a bundle are dropped before analysis, and the live allowlist refuses them. Not
modelled: NetworkPolicies on the entry edge (``kube-noob policy reach`` checks them), cloud IAM, admission-time
mutation (an SCC adding a UID), and tokens mounted by hand through projected volumes.

The built-in ClusterRoles cluster-admin, admin, edit and view are known by their documented meaning when a bundle
does not carry them (https://kubernetes.io/docs/reference/access-authn-authz/rbac/#user-facing-roles: edit and admin
can read Secrets and run pods as any ServiceAccount of the namespace; view cannot read Secrets).
"""

from __future__ import annotations

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
    "Cloud IAM, admission-time mutation and tokens mounted through projected volumes are not modelled.",
    "Roles that are not in the input are reported in notRead; cluster-admin, admin, edit and view are known.",
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
_NODE_CAPS = frozenset({"SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH", "BPF", "NET_ADMIN", "ALL"})
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

    @classmethod
    def from_documents(cls, docs: Iterable[Any]) -> Inventory:
        inv = cls()
        for d in docs:
            if isinstance(d, dict) and d.get("kind") == "List":
                for item in _list(d.get("items")):
                    inv.add(item)
            else:
                inv.add(d)
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
    owners = [o for o in _list(_get(obj, "metadata", "ownerReferences")) if isinstance(o, dict)]
    for o in owners:
        if o.get("controller") is not True:
            continue
        kind = str(o.get("kind"))
        if kind not in POD_SPEC_PATHS:
            continue  # a CRD controller: its pods are these pods, and nothing else in this input scores them
        if present is None or (kind, str(o.get("name"))) in present:
            return True
    return False


def _containers(spec: dict[str, Any], site: _Site | None = None) -> Iterator[dict[str, Any]]:
    """Every container of this pod spec, including the ones that are a field rather than a list entry.

    `site` carries the path and the object, which is what says whether a field like `model:` is a container here
    (a KServe predictor) or an ordinary mapping. Without it only the three list keys are read, which is how a
    privileged `model:` container scored no node capability at all while the audit reported it (G231).
    """
    for key in ("initContainers", "containers", "ephemeralContainers"):
        for c in _list(spec.get(key)):
            if isinstance(c, dict):
                yield c
    if site is None:
        return
    for key in EMBEDDED_CONTAINER_KEYS.get(site.path, ()):
        c = spec.get(key)
        if isinstance(c, dict):
            yield c
    for where, joins in INJECTED_CONTAINERS.get(str(site.obj.get("kind")), ()):
        if joins != site.path:
            continue
        c = _get(site.obj, *(str(k) for k in where))
        if isinstance(c, dict) and ("image" in c or "securityContext" in c):
            yield c


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
        if not isinstance(s.get("spec") or {}, dict):
            # A spec that is not a mapping is not "not exposed": it was not read (G276).
            inv.not_read.append(f"{_ref(s)}: spec is not a mapping, so whether it is exposed was not read")
            continue
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
    for c in _containers(spec, site):
        name = c.get("name")
        raw_sc = c.get("securityContext")
        sc: dict[str, Any] = raw_sc if isinstance(raw_sc, dict) else {}
        if sc.get("privileged") is True:
            out.append(
                Capability(
                    "privileged container: full access to the node",
                    "node",
                    9,
                    f"container {name} securityContext.privileged=true",
                    "remove privileged; grant only the capability needed",
                )
            )
        caps = {str(x).upper().removeprefix("CAP_") for x in _list(_get(sc, "capabilities", "add"))}
        if caps & _NODE_CAPS:
            out.append(
                Capability(
                    f"near-root capabilities {sorted(caps & _NODE_CAPS)}",
                    "node",
                    7,
                    f"container {name} capabilities.add={sorted(caps)}",
                    "drop the added capabilities",
                )
            )
    for v in _list(spec.get("volumes")):
        path = _get(v, "hostPath", "path")
        if isinstance(path, str):
            norm = path.rstrip("/") or "/"
            worst = norm in _SYSTEM_PATHS or any(norm.endswith(s) for s in RUNTIME_SOCKETS)
            out.append(
                Capability(
                    f"host path {path}" + (": node takeover" if worst else ""),
                    "node",
                    9 if worst else 7,
                    f"volume {v.get('name')} hostPath.path={path}",
                    "replace the hostPath volume with a PVC, emptyDir or ConfigMap",
                )
            )
    for fld, weight in (("hostPID", 8), ("hostNetwork", 6), ("hostIPC", 5)):
        if spec.get(fld) is True:
            out.append(Capability(f"host namespace {fld}", "node", weight, f"spec.{fld}=true", f"remove {fld}"))
    return out


@dataclass(frozen=True)
class Grant:
    """One RBAC rule that applies to a ServiceAccount, with where it came from."""

    rule: dict[str, Any]
    cluster: bool
    namespace: str
    evidence: str
    role_ref: str


def _role_rules(inv: Inventory) -> tuple[dict[tuple[str, str], list[Any]], dict[str, list[Any]]]:
    roles = {(_ns(r), _name(r)): _list(r.get("rules")) for r in inv.of("Role")}
    cluster_roles = {_name(r): _list(r.get("rules")) for r in inv.of("ClusterRole")}
    # aggregated ClusterRoles in a bundle: the controller fills their rules in a cluster; do it here
    labels = {
        _name(r): {str(k): str(v) for k, v in (_get(r, "metadata", "labels") or {}).items()}
        for r in inv.of("ClusterRole")
    }
    for r in inv.of("ClusterRole"):
        selectors = _list(_get(r, "aggregationRule", "clusterRoleSelectors"))
        if selectors and not cluster_roles.get(_name(r)):
            merged: list[Any] = []
            for other, lab in labels.items():
                if other != _name(r) and any(isinstance(s, dict) and selector_matches(s, lab) for s in selectors):
                    merged += cluster_roles.get(other, [])
            cluster_roles[_name(r)] = merged
    for name, rules in BUILTIN_CLUSTER_ROLES.items():
        cluster_roles.setdefault(name, rules)
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


def _grants(inv: Inventory, sa_ns: str, sa: str) -> list[Grant]:
    roles, cluster_roles = _role_rules(inv)
    out: list[Grant] = []
    for b in inv.of("RoleBinding", "ClusterRoleBinding"):
        cluster = b.get("kind") == "ClusterRoleBinding"
        bns = None if cluster else _ns(b)
        if (
            not cluster
            and bns != sa_ns
            and not any(isinstance(s, dict) and s.get("kind") == "ServiceAccount" for s in _list(b.get("subjects")))
        ):
            continue
        who = next((m for s in _list(b.get("subjects")) if (m := _subject_matches(s, sa_ns, sa, bns))), None)
        if who is None:
            continue
        ref = b.get("roleRef") or {}
        rname = str(ref.get("name") or "")
        if ref.get("kind") == "Role" and not cluster:
            rules = roles.get((str(bns), rname))
            role_ref = f"Role/{bns}/{rname}"
        else:
            rules = cluster_roles.get(rname)
            role_ref = f"ClusterRole/{rname}"
        if rules is None:
            inv.not_read.append(f"{role_ref} (bound by {_ref(b)}) is not in the input")
            continue
        for i, rule in enumerate(rules):
            if isinstance(rule, dict):
                out.append(
                    Grant(rule, cluster, str(bns or ""), f"{_ref(b)} ({who}) -> {role_ref} rules[{i}]", role_ref)
                )
    # OpenShift legacy: an SCC listing the ServiceAccount (or its groups) lets it use the SCC
    for scc in inv.of("SecurityContextConstraints"):
        users = _strs(scc.get("users"))
        groups = _strs(scc.get("groups"))
        if f"system:serviceaccount:{sa_ns}:{sa}" in users or groups & _sa_groups(sa_ns):
            rule = {
                "apiGroups": ["security.openshift.io"],
                "resources": ["securitycontextconstraints"],
                "verbs": ["use"],
                "resourceNames": [_name(scc)],
            }
            out.append(Grant(rule, True, "", f"{_ref(scc)} users/groups name the ServiceAccount", _ref(scc)))
    return out


def _privileged_scc_names(inv: Inventory) -> set[str]:
    names = set(PRIVILEGED_SCCS)
    for scc in inv.of("SecurityContextConstraints"):
        if scc.get("allowPrivilegedContainer") is True or scc.get("allowHostDirVolumePlugin") is True:
            names.add(_name(scc))
    return names


def _api_capabilities(inv: Inventory, grants: list[Grant]) -> list[Capability]:
    found: dict[tuple[str, str], Capability] = {}
    workload_grant: Grant | None = None
    scc_grant: tuple[Grant, str] | None = None
    privileged = _privileged_scc_names(inv)

    def add(name: str, g: Grant, cluster_w: int, ns_w: int, fix: str, named: bool = False) -> None:
        scope = "cluster" if g.cluster else f"namespace {g.namespace}"
        weight = (cluster_w if g.cluster else ns_w) - (2 if named else 0)
        cap = Capability(name + (" (named objects only)" if named else ""), scope, weight, g.evidence, fix)
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
        if any_res and any_verb and "*" in groups:
            add("full control", g, 10, 7, f"bind a narrower role than {g.role_ref}")
        if core and (any_res or "secrets" in res) and (any_verb or verbs & {"get", "list", "watch"}):
            add(
                "read Secrets (credentials, tokens of other ServiceAccounts)",
                g,
                8,
                6,
                f"{narrow}: drop secrets",
                named=bool(names),
            )
        if verbs & ESCALATION_VERBS or (any_verb and (any_res or res & _IDENTITY_RESOURCES)):
            add("escalate, bind or impersonate", g, 9, 6, f"{narrow}: drop escalate, bind and impersonate")
        if (any_res or res & {"pods/exec", "pods/attach"}) and (any_verb or "create" in verbs):
            add("exec into pods", g, 7, 5, f"{narrow}: drop pods/exec and pods/attach")
        if (any_res or res & WORKLOAD_RESOURCES) and (any_verb or verbs & {"create", "patch", "update"}):
            add(
                "create or change workloads (run as any ServiceAccount of the namespace)",
                g,
                7,
                5,
                f"{narrow}: drop create/patch/update on workloads",
            )
            workload_grant = workload_grant or g
        if (any_res or "nodes/proxy" in res) and (any_verb or verbs & {"get", "create"}) and g.cluster:
            add("kubelet API through nodes/proxy", g, 8, 8, f"{narrow}: drop nodes/proxy")
        if "securitycontextconstraints" in res and (any_verb or "use" in verbs):
            usable = names & privileged if names else privileged
            if usable:
                scc_grant = (g, sorted(usable)[0])
    if workload_grant and scc_grant:
        g, scc = scc_grant
        found[("run privileged pods", "node")] = Capability(
            f"run privileged pods (SCC {scc} + create workloads)",
            "node",
            9,
            f"{g.evidence}; and {workload_grant.evidence}",
            f"remove the 'use' grant on SCC {scc} or the right to create workloads",
        )
    return list(found.values())


def _token(no_automount: set[tuple[str, str]], w: dict[str, Any], spec: dict[str, Any]) -> tuple[str, str] | None:
    """(ServiceAccount, evidence) when the pod mounts a token, else None. ``no_automount``: the ServiceAccounts that
    turn automount off, by (namespace, name)."""
    sa = str(spec.get("serviceAccountName") or spec.get("serviceAccount") or "default")
    pod_flag = spec.get("automountServiceAccountToken")
    if pod_flag is False:
        return None
    if pod_flag is not True and (_ns(w), sa) in no_automount:
        return None
    how = "automountServiceAccountToken=true" if pod_flag is True else "token mounted (automount not turned off)"
    return sa, f"spec.serviceAccountName={sa}; {how}"


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
        no_automount = {
            (_ns(sa), _name(sa)) for sa in inv.of("ServiceAccount") if sa.get("automountServiceAccountToken") is False
        }
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
    tok = _token(index.no_automount, w, spec)
    if tok is not None:
        sa, evidence = tok
        key = (_ns(w), sa)
        if key not in sa_caps:
            sa_caps[key] = _api_capabilities(inv, _grants(inv, *key))
        sa_ref = f"ServiceAccount/{key[0]}/{sa}"
        for cap in sa_caps[key]:
            target = "node" if cap.scope == "node" else ("cluster" if cap.scope == "cluster" else key[0])
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
    token = (f"ServiceAccount/{_ns(w)}/{tok[0]}", tok[1]) if tok else None
    return Reach(
        ref,
        _ns(w),
        images,
        reach_entries,
        _node_capabilities(w, spec, site),
        api,
        token,
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
    undetermined = sorted(
        (r.ref, [c.name for c in r.capabilities]) for r in reach if r.embedded and not r.entries and r.capabilities
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
    return inv
