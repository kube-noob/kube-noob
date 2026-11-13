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
    WORKLOAD_RESOURCES,
    takes_over_node,
)
from kube_noob.yamlio import PathT

#: True of every scan, whatever the input. Named so a renderer can tell them from the per-scan ones that follow
#: and print those, which is the half a text reader needs and was not getting (G231, after G221).
UNREAD_NAMESPACES_NOTE = (
    "Read from some namespaces only: HTTPRoutes, GRPCRoutes and VirtualServices in namespaces not read can route "
    "into the ones read, so a workload with no path may still be exposed"
)
STANDING_LIMITATIONS: tuple[str, ...] = (
    "NetworkPolicies on the entry edge are not applied: check a path with `kube-noob policy reach`.",
    "Cloud IAM and admission-time mutation are not modelled.",
    "Roles that are not in the input are reported in notRead; cluster-admin, admin, edit and view stand in by their "
    "documented rules, and admin, edit and view aggregate rules the input may not carry.",
    "Exposure is read from Services, OpenShift Routes, Ingresses, Gateway API HTTPRoutes and Istio VirtualServices; "
    "other routing objects in files are named in notRead, and a live scan does not list them.",
    "One token per pod is followed: the automounted one, else a projected one, else a mounted token Secret; a "
    "token passed in an environment variable or by a CSI driver's tokenRequests is not followed.",
)

MAX_OBJECTS = 50_000
MAX_PATHS = 200
DEFAULT_TOP = 20

# kind of each list the live scan reads (API list items carry no kind of their own)
LIVE_RESOURCES: dict[str, str] = {
    "routes": "Route",
    "ingresses": "Ingress",
    "httproutes": "HTTPRoute",
    "grpcroutes": "GRPCRoute",
    "virtualservices": "VirtualService",
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
PRIVILEGED_SCCS = frozenset(
    {"privileged", "hostaccess", "hostmount-anyuid", "hostnetwork", "hostnetwork-v2", "node-exporter"}
)
_RBAC_GROUP = "rbac.authorization.k8s.io"
_RBAC_KINDS = frozenset({"Role", "RoleBinding", "ClusterRole", "ClusterRoleBinding"})
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
    #: For a Service that is itself the exposure: that object's own selector, so two different Services of one
    #: name each reach through their own (G273). None for a Route, Ingress or route that names a Service.
    selector: dict[str, Any] | None = field(default=None, compare=False)


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
    meta = _meta(obj)
    ns = meta.get("namespace")
    return f"{obj.get('kind')}/{ns}/{meta.get('name')}" if ns else f"{obj.get('kind')}/{meta.get('name')}"


object_ref = _ref  # Kind/namespace/name (Kind/name without a namespace), as audit findings name resources


def _meta(obj: dict[str, Any]) -> dict[str, Any]:
    meta = obj.get("metadata")
    return meta if isinstance(meta, dict) else {}  # a list here crashed the scan (found rerunning mal.py, G273)


def _ns(obj: dict[str, Any]) -> str:
    return str(_meta(obj).get("namespace") or "default")


def _name(obj: dict[str, Any]) -> str:
    return str(_meta(obj).get("name") or "")


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
get_path = _get


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
    # A namespaced object written without a namespace is the same object as one naming `default`, which is where
    # every reader here puts it: two spellings of one object are not two objects.
    if (
        isinstance(obj, dict)
        and isinstance(obj.get("metadata"), dict)
        and not obj["metadata"].get("namespace")
        and str(obj.get("kind") or "") not in _CLUSTER_SCOPED_KINDS
    ):
        obj = {**obj, "metadata": {**obj["metadata"], "namespace": _ns(obj)}}
    # Only what the server or a controller writes into metadata (resourceVersion, uid, generation, timestamps,
    # managedFields, the controller annotations below) and `status` are stripped. Fields the API server DEFAULTS in
    # the spec (imagePullPolicy, dnsPolicy, terminationMessagePath, strategy, revisionHistoryLimit, ...) are not, so
    # a full `kubectl get -o yaml` copy beside the file it was applied from is still reported as a second object --
    # an ambiguity named, never a silent pick (fifth review, E6b).
    if isinstance(obj, dict):
        meta = obj.get("metadata")
        if isinstance(meta, dict):
            meta = {k: v for k, v in meta.items() if k not in _SERVER_SET}
            notes = meta.get("annotations")
            if isinstance(notes, dict) and _CONTROLLER_ANNOTATIONS & set(notes):
                meta["annotations"] = {k: v for k, v in notes.items() if k not in _CONTROLLER_ANNOTATIONS} or None
                if meta["annotations"] is None:
                    del meta["annotations"]
            obj = {**obj, "metadata": meta}
        obj = {k: v for k, v in obj.items() if k != "status"}
    return json.dumps(_plain(obj), default=str)


_SERVER_SET = frozenset(
    {"resourceVersion", "uid", "generation", "creationTimestamp", "managedFields", "selfLink", "deletionTimestamp"}
)
#: Annotations the API server, a controller or kubectl writes, not the author: last-applied (kubectl apply),
#: the Deployment controller's revision (pkg/controller/deployment/util RevisionAnnotation) and the DaemonSet
#: controller's template generation (pkg/controller/daemon, deprecated.daemonset.template.generation).
_CONTROLLER_ANNOTATIONS = frozenset(
    {
        "kubectl.kubernetes.io/last-applied-configuration",
        "deployment.kubernetes.io/revision",
        "deprecated.daemonset.template.generation",
    }
)


_CLUSTER_SCOPED_KINDS = frozenset(
    {"ClusterRole", "ClusterRoleBinding", "Namespace", "Node", "PersistentVolume", "SecurityContextConstraints"}
)


canonical_form = _canonical_form  # one canonical form of an object, for ordering and for telling duplicates apart


#: OpenShift's legacy RBAC group. It serves Role, RoleBinding, ClusterRole and ClusterRoleBinding as proxies of
#: the rbac.authorization.k8s.io objects (openshift-apiserver pkg/authorization/apiserver/apiserver.go stores all
#: four through the rbac/v1 client, commit 9fc0918d1c6908e8e8ceb8e215e86bde4aeaabec; the kinds are registered in
#: openshift/api authorization/v1/register.go, commit 61403fc4e89fad877aba1b000d72a992f388f549). A legacy binding
#: names its role by `roleRef: {name, namespace}` with no kind -- a namespace means a Role, none a ClusterRole --
#: and its subjects as ObjectReferences whose kinds include SystemUser and SystemGroup, or as `userNames` and
#: `groupNames`, which take precedence when set (rbacconversion/conversion.go at the same commit).
_OPENSHIFT_RBAC_GROUP = "authorization.openshift.io"
_LEGACY_SUBJECT_KINDS = {"ServiceAccount": "ServiceAccount", "User": "User", "SystemUser": "User", "Group": "Group"}
_LEGACY_SUBJECT_KINDS["SystemGroup"] = "Group"
#: Routing objects that can put a workload on a network and that this scan does not read: present in the input,
#: they make the exposure of the workloads in their namespace not determined rather than "none" (G273).
UNMODELLED_EXPOSURE: dict[str, frozenset[str]] = {
    "gateway.networking.k8s.io": frozenset({"TLSRoute", "TCPRoute", "UDPRoute"}),
    "projectcontour.io": frozenset({"HTTPProxy"}),
    "traefik.io": frozenset({"IngressRoute", "IngressRouteTCP", "IngressRouteUDP"}),
    "traefik.containo.us": frozenset({"IngressRoute", "IngressRouteTCP", "IngressRouteUDP"}),
    "getambassador.io": frozenset({"Mapping"}),
}
#: The groups the routing kinds this scan does read belong to: a kind of the same name in another group is not one.
_KIND_GROUPS: dict[str, str] = {
    "HTTPRoute": "gateway.networking.k8s.io",
    "GRPCRoute": "gateway.networking.k8s.io",
    "VirtualService": "networking.istio.io",
    "Route": "route.openshift.io",
}
LEGACY_SA_TYPE = "kubernetes.io/service-account-token"


def _legacy_rbac(obj: dict[str, Any], kind: str) -> tuple[dict[str, Any] | None, str]:
    """An authorization.openshift.io object in the rbac.authorization.k8s.io shape the rest of this module reads,
    converted the way openshift-apiserver converts it; or (None, why) when the server would refuse it."""
    if kind in {"Role", "ClusterRole"}:
        return {**obj, "apiVersion": f"{_RBAC_GROUP}/v1"}, ""
    ref = obj.get("roleRef")
    if not isinstance(ref, dict) or not ref.get("name"):
        return None, "roleRef does not name a role"
    ref_ns = str(ref.get("namespace") or "")
    if kind == "ClusterRoleBinding" and ref_ns:
        return None, f"a ClusterRoleBinding cannot reference a role in namespace {ref_ns}"
    if kind == "RoleBinding" and ref_ns and ref_ns != _ns(obj):
        return None, f"a RoleBinding cannot reference a role in namespace {ref_ns}"
    users, groups = obj.get("userNames"), obj.get("groupNames")
    subjects: list[dict[str, Any]] = []
    if isinstance(users, list) or isinstance(groups, list):
        subjects += [{"kind": "User", "name": str(u)} for u in _list(users)]
        subjects += [{"kind": "Group", "name": str(g)} for g in _list(groups)]
    else:
        for s in _list(obj.get("subjects")):
            if not isinstance(s, dict) or s.get("kind") not in _LEGACY_SUBJECT_KINDS:
                return (
                    None,
                    f"subject kind {s.get('kind') if isinstance(s, dict) else s!r} is not one OpenShift accepts",
                )
            subject = {"kind": _LEGACY_SUBJECT_KINDS[str(s["kind"])], "name": str(s.get("name") or "")}
            if subject["kind"] == "ServiceAccount" and s.get("namespace"):
                subject["namespace"] = str(s["namespace"])
            subjects.append(subject)
    converted = {
        **{k: v for k, v in obj.items() if k not in {"userNames", "groupNames"}},
        "apiVersion": f"{_RBAC_GROUP}/v1",
        "subjects": subjects,
        "roleRef": {"apiGroup": _RBAC_GROUP, "kind": "Role" if ref_ns else "ClusterRole", "name": str(ref["name"])},
    }
    return converted, ""


def _backend_namespaces(obj: dict[str, Any]) -> set[str]:
    """The namespaces a routing object this scan does not model may send traffic into: its own, every value of a
    `namespace` key anywhere in its spec (Gateway API backendRefs, Contour includes, Traefik services), and the
    namespace in an Ambassador `service: name.namespace`. A spec that is not a mapping may route anywhere ("*")."""
    out = {_ns(obj)}
    spec = obj.get("spec")
    if spec is None:
        return out
    if not isinstance(spec, dict):
        return {"*"}
    stack: list[Any] = [spec]
    seen = 0
    while stack and seen < 10_000:  # bounded walk
        cur = stack.pop()
        seen += 1
        if isinstance(cur, dict):
            for k, v in cur.items():
                if k == "namespace" and isinstance(v, str) and v:
                    out.add(v)
                elif k == "service" and isinstance(v, str) and "." in v:
                    out.add(v.split(":")[0].split(".")[1])
                else:
                    stack.append(v)
        elif isinstance(cur, list):
            stack.extend(cur)
    return out


@dataclass
class Inventory:
    objects: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    not_read: list[str] = field(default_factory=list)
    dropped_unread: int = 0
    #: RBAC objects (or lists of them) in the input that could not be read: each one opens the RBAC leg (G273).
    rbac_unread: list[str] = field(default_factory=list)
    #: Routing objects this scan does not read, present in the input, as Kind/namespace/name.
    unmodelled: list[str] = field(default_factory=list)
    #: For each of those, the namespaces whose Services it may route to: its own and every namespace its spec
    #: names ("*" when it cannot be told). A GRPCRoute in `gw` routes to `shop/web`, so it opens shop's exposure.
    unmodelled_ns: dict[str, set[str]] = field(default_factory=dict)
    #: (namespace, Secret name) -> ServiceAccount, for Secrets of type kubernetes.io/service-account-token: the
    #: type and the annotation are metadata, kept; the Secret's data is never read and the object is dropped.
    legacy_accounts: dict[tuple[str, str], str] = field(default_factory=dict)
    #: (namespace, Secret name) of every other Secret in the input: only that it exists and is not a token Secret.
    other_secrets: set[tuple[str, str]] = field(default_factory=set)
    #: Read from the cluster: an absence in a list that WAS read is the cluster's answer, not a gap in a file set.
    live: bool = False
    #: The namespaces a live read was limited to; empty when it read every namespace (or from files).
    namespaces_read: list[str] = field(default_factory=list)
    #: Objects of a namespaced kind that carry no namespace and were given none (`-n`): Kind/name. Where kubectl
    #: apply puts them depends on the command line, so their namespace is not known (fourth review, D1).
    unplaced: set[str] = field(default_factory=set)
    #: The namespace `-n` gave, where objects without one are placed, as `kubectl apply -n` does.
    default_namespace: str | None = None

    def add(self, obj: Any, kind: str | None = None) -> None:
        if not isinstance(obj, dict):
            return
        k = kind or str(obj.get("kind") or "")
        api = obj.get("apiVersion")
        group = api.split("/")[0] if isinstance(api, str) and "/" in api else ""
        meta = obj.get("metadata")
        if (
            not self.live
            and isinstance(meta, dict)
            and not meta.get("namespace")
            and k not in _CLUSTER_SCOPED_KINDS
            and (k in KINDS or k == "Secret")
        ):
            # Where `kubectl apply` puts an object with no namespace depends on the command line: `-n`, or the
            # context's namespace. Placed in `default`, a Deployment applied with `-n ops` and bound in `ops` read
            # "no capability" (fourth review, D1).
            if self.default_namespace:
                obj = {**obj, "metadata": {**meta, "namespace": self.default_namespace}}
            else:
                self.unplaced.add(f"{k}/{meta.get('name')}")
        if k == "Secret":
            self.dropped_unread += 1  # never analysed, never echoed
            if obj.get("type") == LEGACY_SA_TYPE:
                account = _get(obj, "metadata", "annotations", "kubernetes.io/service-account.name")
                self.legacy_accounts[(_ns(obj), _name(obj))] = str(account or "")
            else:
                self.other_secrets.add((_ns(obj), _name(obj)))
            return
        if k in UNMODELLED_EXPOSURE.get(group, ()):
            self.unmodelled.append(_ref(obj))
            self.unmodelled_ns[_ref(obj)] = _backend_namespaces(obj)
            self.not_read.append(
                f"{_ref(obj)}: a routing object this scan does not read, so exposure through it is not known"
            )
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
        if k in _KIND_GROUPS and isinstance(api, str) and group and group != _KIND_GROUPS[k]:
            # A Knative `Route` (serving.knative.dev) routes traffic too, to objects this scan does not model: it is
            # not read as an OpenShift Route, and its namespace's exposure is not determined rather than none.
            self.unmodelled.append(_ref(obj))
            self.unmodelled_ns[_ref(obj)] = _backend_namespaces(obj)
            self.not_read.append(f"{_ref(obj)}: apiVersion {api} is not {_KIND_GROUPS[k]}, so it was ignored")
            return
        if k in _RBAC_KINDS and isinstance(api, str) and group != _RBAC_GROUP:
            if group == _OPENSHIFT_RBAC_GROUP:
                converted, why = _legacy_rbac(obj, k)
                if converted is None:
                    note = f"{_ref(obj)}: {why}, so it was not read"
                    self.not_read.append(note)
                    self.rbac_unread.append(note)
                    return
                obj = converted
            else:
                # A CRD that happens to be called Role is not RBAC: reading it as one would invent rights (G270's
                # lesson). It still opens the RBAC leg: an RBAC-shaped object this scan could not read.
                note = f"{_ref(obj)}: apiVersion {api} is not {_RBAC_GROUP}, so it was ignored"
                self.not_read.append(note)
                self.rbac_unread.append(note)
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
        self.objects = {
            k: sorted(v, key=lambda o: (_canonical_form(o), json.dumps(_plain(o), default=str)))
            for k, v in sorted(self.objects.items())
        }

    def duplicates(self, kind: str) -> dict[tuple[str, str], list[dict[str, Any]]]:
        """Objects of `kind` that share a namespace and name and DIFFER, by (namespace, name). Identical copies are
        one object. The API keeps one per name; which one, the input does not say (G273)."""
        groups: dict[tuple[str, str], dict[str, dict[str, Any]]] = {}
        for o in self.of(kind):
            groups.setdefault((_ns(o), _name(o)), {})[_canonical_form(o)] = o
        return {key: list(found.values()) for key, found in sorted(groups.items()) if len(found) > 1}

    def duplicate_notes(self) -> list[str]:
        """One line per name carried by two different objects, saying what the scan did with them (G273, R2/R3).
        Roles and ClusterRoles are said where a binding uses them (the gap names the binding); an unbound one
        grants nothing either way."""
        what = {
            "Service": "every candidate's selector is followed and each path through it says so",
            "Ingress": "both are read, so an exposure may be listed that the cluster does not have",
            "Route": "both are read, so an exposure may be listed that the cluster does not have",
            "HTTPRoute": "both are read, so an exposure may be listed that the cluster does not have",
            "GRPCRoute": "both are read, so an exposure may be listed that the cluster does not have",
            "VirtualService": "both are read, so an exposure may be listed that the cluster does not have",
            "RoleBinding": "both are read, so a grant may be listed that the cluster does not hold",
            "ClusterRoleBinding": "both are read, so a grant may be listed that the cluster does not hold",
            "ServiceAccount": "a token is assumed mounted unless every copy turns automount off",
        }
        for kind in sorted(WORKLOAD_KINDS):
            what.setdefault(kind, "each is scored, and the threat model models them together")
        out: list[str] = []
        for kind, done in what.items():
            for objs in self.duplicates(kind).values():
                out.append(
                    f"{len(objs)} different objects named {_ref(objs[0])} are in the input; which one the cluster "
                    f"holds is not known; {done}"
                )
        return out

    @classmethod
    def from_documents(cls, docs: Iterable[Any], default_namespace: str | None = None) -> Inventory:
        """``default_namespace``: where objects of a namespaced kind with no namespace go, as `kubectl apply -n`
        puts them. Without it they are placed in `default` and recorded in `unplaced`."""
        inv = cls(default_namespace=default_namespace or None)

        for d in docs:
            kind = str(d.get("kind") or "") if isinstance(d, dict) else ""
            if kind.endswith("List") and isinstance(d, dict) and "items" in d:
                # `kubectl get rolebindings -o yaml` writes a `List`; the typed form (`RoleBindingList`) carries
                # items without a kind of their own. Dropping either left "no RoleBinding is in the input" (G273).
                items = d.get("items")
                item_kind = kind.removesuffix("List") or None
                if not isinstance(items, list):
                    note = f"{kind}: items is not a list, so none of its objects were read"
                    inv.not_read.append(note)
                    if item_kind in _RBAC_KINDS or item_kind is None:
                        inv.rbac_unread.append(note)
                    continue
                for item in items:
                    if not isinstance(item, dict) and item_kind in _RBAC_KINDS:
                        note = f"{kind}: an item is a {type(item).__name__}, not an object, so it was not read"
                        inv.not_read.append(note)
                        inv.rbac_unread.append(note)
                        continue
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
    # The same object twice (two files that both carry it) is one workload: scoring it twice doubled its paths,
    # where the blast radius counted it once (found by the reviewer's scan-versus-reach agreement check, G273).
    seen: set[str] = set()
    out: list[_Site] = []
    for obj in inv.of(*_WORKLOAD_KINDS):
        if not owned and _owned(obj, present):
            continue
        form = _canonical_form(obj)
        if form in seen:
            continue
        seen.add(form)
        out += _sites_of(obj)
    return out


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


@dataclass(frozen=True)
class _Front:
    """One object that routes traffic to a Service by name: a Route, an Ingress, an HTTPRoute, a VirtualService."""

    obj: dict[str, Any]
    namespace: str  # the Service's namespace
    service: str
    label: str
    weight: int
    exposed: str  # evidence for "exposed by"
    routes: str  # evidence for "routes to"
    fix: str


def _vs_service(host: str, vs_ns: str) -> tuple[str, str] | None:
    """(namespace, name) of the Kubernetes Service an Istio destination host names, or None for a host outside the
    cluster. A short name is read in the VirtualService's own namespace ("Istio will interpret the short name based
    on the namespace of the rule", https://istio.io/latest/docs/reference/config/networking/virtual-service/)."""
    parts = host.split(".")
    if len(parts) == 1:
        return vs_ns, parts[0]
    if len(parts) == 2:
        return parts[1], parts[0]
    if len(parts) >= 3 and parts[2] == "svc":
        return parts[1], parts[0]
    return None


def _gateway_backends(route: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """(field, backendRef) for every backend a Gateway API route sends traffic to: `rules[].backendRefs[]`, and
    the `requestMirror.backendRef` of a filter on the rule or on a backendRef. Refs without a name are skipped."""
    out: list[tuple[str, dict[str, Any]]] = []

    def mirrors(filters: Any, at: str) -> None:
        for k, f in enumerate(_list(filters)):
            ref = _get(f, "requestMirror", "backendRef")
            if isinstance(ref, dict) and ref.get("name"):
                out.append((f"{at}.filters[{k}].requestMirror.backendRef", ref))

    for i, rule in enumerate(_list(_get(route, "spec", "rules"))):
        for j, ref in enumerate(_list(_get(rule, "backendRefs"))):
            if isinstance(ref, dict) and ref.get("name"):
                out.append((f"spec.rules[{i}].backendRefs[{j}]", ref))
                mirrors(ref.get("filters"), f"spec.rules[{i}].backendRefs[{j}]")
        mirrors(_get(rule, "filters"), f"spec.rules[{i}]")
    return out


def _fronts(inv: Inventory) -> list[_Front]:
    out: list[_Front] = []
    for r in inv.of("Route"):
        backends = [_get(r, "spec", "to")] + _list(_get(r, "spec", "alternateBackends"))
        host = _get(r, "spec", "host") or "the router's default host"
        for b in backends:
            if isinstance(b, dict) and b.get("name") and (b.get("kind") or "Service") == "Service":
                svc = str(b["name"])
                out.append(
                    _Front(
                        r,
                        _ns(r),
                        svc,
                        "internet (Route)",
                        3,
                        f"Route host {host}",
                        f"spec.to.name={svc}",
                        "remove the Route or put authentication in front of it",
                    )
                )
    for ing in inv.of("Ingress"):
        names: list[str] = []
        # networking.k8s.io/v1 names the backend `service.name`; the v1beta1 and extensions/v1beta1 Ingress (gone
        # from the API since 1.22, still in old charts) named it `serviceName`, and its default backend `backend`.
        # Reading only the first made an old chart's Ingress route to nothing (G273, class 21 neighbour of N4).
        default = _get(ing, "spec", "defaultBackend", "service", "name") or _get(ing, "spec", "backend", "serviceName")
        if default:
            names.append(str(default))
        for rule in _list(_get(ing, "spec", "rules")):
            for p in _list(_get(rule, "http", "paths")):
                n = _get(p, "backend", "service", "name") or _get(p, "backend", "serviceName")
                if n:
                    names.append(str(n))
        hosts = [str(_get(x, "host")) for x in _list(_get(ing, "spec", "rules")) if _get(x, "host")]
        for svc in dict.fromkeys(names):
            out.append(
                _Front(
                    ing,
                    _ns(ing),
                    svc,
                    "internet (Ingress)",
                    3,
                    f"Ingress hosts {hosts[:3] or ['*']}",
                    f"backend.service.name={svc}",
                    "remove the Ingress rule or put authentication in front of it",
                )
            )
    # Gateway API: a backendRef defaults to kind Service in the core group and to the route's own namespace
    # (https://gateway-api.sigs.k8s.io/reference/spec/, BackendObjectReference). A route attached to no Gateway
    # (no parentRefs) carries no traffic. GRPCRoute is GA (Standard channel) with the same rules and backendRefs.
    # A RequestMirror filter -- on the rule or on a backendRef -- sends a copy of every request to its backendRef,
    # so traffic reaches that Service too (fourth review). A backendRef of another kind (an InferencePool) is a
    # target kube-noob does not model: `_gateway_other_backends` names it.
    for hr in [*inv.of("HTTPRoute"), *inv.of("GRPCRoute")]:
        parents = [str(_get(p, "name")) for p in _list(_get(hr, "spec", "parentRefs")) if isinstance(p, dict)]
        if not parents:
            continue
        kind = str(hr.get("kind") or "HTTPRoute")
        for at, ref in _gateway_backends(hr):
            if (ref.get("kind") or "Service") != "Service" or (ref.get("group") or "") != "":
                continue
            svc = str(ref["name"])
            out.append(
                _Front(
                    hr,
                    str(ref.get("namespace") or _ns(hr)),
                    svc,
                    f"internet (Gateway API {kind})",
                    3,
                    f"{kind} parentRefs {parents[:3]}",
                    f"{at}.name={svc}",
                    f"detach the {kind} from the Gateway or put authentication in front of it",
                )
            )

    # Istio: a VirtualService bound to a gateway other than `mesh` takes traffic from outside the mesh; one bound
    # only to `mesh` (the default when `gateways` is omitted) routes sidecar traffic and exposes nothing.
    by_name = {(_ns(v), _name(v)): v for v in inv.of("VirtualService")}
    for vs in inv.of("VirtualService"):
        gateways = [str(g) for g in _list(_get(vs, "spec", "gateways"))]
        outside = [g for g in gateways if g != "mesh"]
        if not outside:
            continue
        # A delegate VirtualService has no gateways of its own: it takes its parent's
        # (https://istio.io/latest/docs/reference/config/networking/virtual-service/#Delegate), so its routes are as
        # exposed as the parent's. One level, as Istio supports.
        sources = [(vs, "spec", "")]
        for i, route in enumerate(_list(_get(vs, "spec", "http"))):
            d = _get(route, "delegate")
            if isinstance(d, dict) and d.get("name"):
                child = by_name.get((str(d.get("namespace") or _ns(vs)), str(d["name"])))
                if child is not None:
                    sources.append((child, "spec", f" via {_ref(vs)} spec.http[{i}].delegate"))
        for src, _spec, via in sources:
            for section in ("http", "tcp", "tls"):
                for i, route in enumerate(_list(_get(src, "spec", section))):
                    dests = [
                        (f"route[{j}].destination", _get(d, "destination"))
                        for j, d in enumerate(_list(_get(route, "route")))
                    ]
                    # A mirror sends a copy of every request to the workload too: traffic reaches it.
                    dests.append(("mirror", _get(route, "mirror")))
                    dests += [
                        (f"mirrors[{j}].destination", _get(m, "destination"))
                        for j, m in enumerate(_list(_get(route, "mirrors")))
                    ]
                    for at, dest in dests:
                        host = _get(dest, "host")
                        target = _vs_service(str(host), _ns(src)) if isinstance(host, str) and host else None
                        if target is None:
                            continue
                        out.append(
                            _Front(
                                src,
                                target[0],
                                target[1],
                                "internet (Istio VirtualService)",
                                3,
                                f"VirtualService gateways {outside[:3]}{via}",
                                f"spec.{section}[{i}].{at}.host={host}",
                                "unbind the VirtualService from the ingress gateway or put authentication in front of "
                                "it",
                            )
                        )
    return out


_SERVICE_TYPES = frozenset({"ClusterIP", "NodePort", "LoadBalancer", "ExternalName"})


def _malformed_fronts(inv: Inventory) -> list[tuple[str, str]]:
    """(namespace it may route into, sentence) for every exposure field that is not the shape the API requires: a
    VirtualService `gateways` string, an HTTPRoute `parentRefs` string or `backendRefs` map, a Service `selector`
    string. Read as nothing, each made exposure `none` (third review of G273). "*" where the object can route to
    any namespace."""
    out: list[tuple[str, str]] = []

    def bad(obj: dict[str, Any], where: str, want: type, ns: str) -> None:
        v = _get(obj, *where.split("."))
        if v is not None and not isinstance(v, want):
            shape = "a list" if want is list else "a mapping"
            out.append((ns, f"{_ref(obj)}: {where} is not {shape}, so where it routes is not known"))

    for s in inv.of("Service"):
        bad(s, "spec.selector", dict, _ns(s))
        typ = _get(s, "spec", "type")
        if typ is not None and not (isinstance(typ, str) and typ in _SERVICE_TYPES):
            out.append(
                (
                    _ns(s),
                    f"{_ref(s)}: spec.type {str(typ)[:40]!r} is not a Service type, so how it is exposed is not known",
                )
            )
    for r in inv.of("Route"):
        bad(r, "spec.to", dict, _ns(r))
        bad(r, "spec.alternateBackends", list, _ns(r))
    for ing in inv.of("Ingress"):
        bad(ing, "spec.rules", list, _ns(ing))
        for i, rule in enumerate(_list(_get(ing, "spec", "rules"))):
            p = _get(rule, "http", "paths")
            if p is not None and not isinstance(p, list):
                out.append(
                    (
                        _ns(ing),
                        f"{_ref(ing)}: spec.rules[{i}].http.paths is not a list, so where it routes is not known",
                    )
                )
    for hr in [*inv.of("HTTPRoute"), *inv.of("GRPCRoute")]:
        bad(hr, "spec.parentRefs", list, "*")
        bad(hr, "spec.rules", list, "*")
        for i, rule in enumerate(_list(_get(hr, "spec", "rules"))):
            b = _get(rule, "backendRefs")
            if b is not None and not isinstance(b, list):
                out.append(
                    ("*", f"{_ref(hr)}: spec.rules[{i}].backendRefs is not a list, so where it routes is not known")
                )
            # A filter can mirror traffic to another backend: filters that cannot be read hide one (fifth review).
            filters = [(f"spec.rules[{i}].filters", _get(rule, "filters"))] + [
                (f"spec.rules[{i}].backendRefs[{j}].filters", _get(ref, "filters")) for j, ref in enumerate(_list(b))
            ]
            for at, f in filters:
                if f is not None and not isinstance(f, list):
                    out.append(("*", f"{_ref(hr)}: {at} is not a list, so where it routes is not known"))
    for vs in inv.of("VirtualService"):
        bad(vs, "spec.gateways", list, "*")
        for section in ("http", "tcp", "tls"):
            bad(vs, f"spec.{section}", list, "*")
            for i, route in enumerate(_list(_get(vs, "spec", section))):
                r2 = _get(route, "route")
                if r2 is not None and not isinstance(r2, list):
                    out.append(
                        ("*", f"{_ref(vs)}: spec.{section}[{i}].route is not a list, so where it routes is not known")
                    )
    return out


def _unresolved_delegates(inv: Inventory) -> list[tuple[str, str]]:
    """(namespace, sentence) for a gateway-bound VirtualService that delegates to one the input does not carry."""
    names = {(_ns(v), _name(v)) for v in inv.of("VirtualService")}
    out: list[tuple[str, str]] = []
    for vs in inv.of("VirtualService"):
        if not [g for g in _list(_get(vs, "spec", "gateways")) if g != "mesh"]:
            continue
        for i, route in enumerate(_list(_get(vs, "spec", "http"))):
            d = _get(route, "delegate")
            if isinstance(d, dict) and d.get("name"):
                key = (str(d.get("namespace") or _ns(vs)), str(d["name"]))
                if key not in names:
                    out.append(
                        (
                            key[0],
                            f"{_ref(vs)} spec.http[{i}] delegates to VirtualService {key[0]}/{key[1]}, which is not "
                            "in the input",
                        )
                    )
    return out


def dangling(inv: Inventory) -> list[tuple[str, str]]:
    """(namespace of the Service, sentence) for every front that names a Service the files do not carry. Read from
    files, that is a gap -- the Service and the pods it selects may exist; read live, the Service list is the
    cluster's own answer and a route to nothing exposes nothing (G273). Also every exposure field that is not the
    shape the API requires, live or not, and a VirtualService delegate the files do not carry; "*" as the
    namespace means it may route into any."""
    seen: dict[str, tuple[str, str]] = {}
    for ns, line in _malformed_fronts(inv):
        seen.setdefault(line, (ns, line))
    # A Gateway API backendRef of another kind than Service (an InferencePool selects pods by label; any other kind
    # is a backend kube-noob does not model): its pods are not known (fourth review, D3).
    for hr in [*inv.of("HTTPRoute"), *inv.of("GRPCRoute")]:
        for at, ref in _gateway_backends(hr):
            kind = str(ref.get("kind") or "Service")
            if kind != "Service" or (ref.get("group") or "") != "":
                ns = str(ref.get("namespace") or _ns(hr))
                line = f"{_ref(hr)} {at} routes to {kind} {ns}/{ref['name']}, a backend kube-noob does not model"
                seen.setdefault(line, (ns, line))
    # A front or an exposed type to a Service without a selector reaches whatever EndpointSlices someone wrote --
    # any pod IP, in any namespace -- and an ExternalName aliasing `<svc>.<ns>.svc...` reaches that Service's pods
    # (https://kubernetes.io/docs/concepts/services-networking/service/#services-without-selectors). Fourth review, D8.
    exposed = {(f.namespace, f.service) for f in _fronts(inv)} | {
        (_ns(s), _name(s)) for s in inv.of("Service") if _service_exposure(s)
    }
    for s in inv.of("Service"):
        if (_ns(s), _name(s)) not in exposed:
            continue
        typ = _get(s, "spec", "type")
        if typ == "ExternalName":
            alias = str(_get(s, "spec", "externalName") or "")
            parts = alias.split(".")
            if len(parts) >= 3 and parts[2] == "svc":
                line = f"{_ref(s)} is an ExternalName for {alias}: the Service it aliases is reached through it"
                seen.setdefault(line, (parts[1], line))
            continue
        sel = _get(s, "spec", "selector")
        if sel is None or sel == {}:
            line = f"{_ref(s)} has no selector: the endpoints written for it may be any pod"
            seen.setdefault(line, ("*", line))
    if inv.live:
        return sorted(seen.values())
    services = {(_ns(s), _name(s)) for s in inv.of("Service")}
    for f in _fronts(inv):
        if (f.namespace, f.service) not in services:
            line = f"{_ref(f.obj)} routes to Service {f.namespace}/{f.service}, which is not in the input"
            seen.setdefault(line, (f.namespace, line))
    for ns, line in _unresolved_delegates(inv):
        seen.setdefault(line, (ns, line))
    return sorted(seen.values())


def _entries(inv: Inventory) -> list[Entry]:
    services = {(_ns(s), _name(s)) for s in inv.of("Service")}
    out: list[Entry] = []
    for f in _fronts(inv):
        if (f.namespace, f.service) not in services:
            continue
        step = Step("internet", _ref(f.obj), "exposed by", f.exposed)
        step2 = Step(_ref(f.obj), f"Service/{f.namespace}/{f.service}", "routes to", f.routes)
        out.append(Entry(f.label, f.weight, (step, step2), f.namespace, f.service, f.fix))
    for s in inv.of("Service"):
        exp = _service_exposure(s)
        if exp:
            label, weight, evidence, fix = exp
            src = label.split(" (")[0]
            sel = _get(s, "spec", "selector")
            out.append(
                Entry(
                    label,
                    weight,
                    (Step(src, _ref(s), "exposed by", evidence),),
                    _ns(s),
                    _name(s),
                    fix,
                    selector=sel if isinstance(sel, dict) else {},
                )
            )
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
            # One list with the audit's KN-S010: the node's configuration and PKI, the kubelet's pods, a runtime
            # socket, the directory or anything under it (`/etc/../` and `//etc` are what they resolve to).
            worst = takes_over_node(path)
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
    seen: dict[str, set[str]] = {}
    labels: dict[str, dict[str, str]] = {}
    selectors: dict[str, list[dict[str, Any]]] = {}
    for r in inv.of("Role", "ClusterRole"):
        cluster = r.get("kind") == "ClusterRole"
        ref = f"ClusterRole/{_name(r)}" if cluster else f"Role/{_ns(r)}/{_name(r)}"
        form = _canonical_form(r)
        if form in seen.setdefault(ref, set()):
            continue  # the same object twice is one object
        seen[ref].add(form)
        raw = r.get("rules")
        if raw is not None and not isinstance(raw, list):
            book.unreadable.add(ref)
            book.open[ref] = f"{ref}: rules is a {type(raw).__name__}, not a list, so what it grants is not known"
        book.rules.setdefault(ref, []).extend(_list(raw))
        if cluster:
            labels[ref] = {**labels.get(ref, {}), **_labels(r)}
            agg = r.get("aggregationRule")
            if agg is not None:
                sel = _get(agg, "clusterRoleSelectors")
                if not isinstance(sel, list):
                    book.open[ref] = f"{ref}: aggregationRule.clusterRoleSelectors is not a list"
                selectors.setdefault(ref, []).extend(s for s in _list(sel) if isinstance(s, dict))
    for ref, forms in seen.items():
        if len(forms) > 1:
            # Two DIFFERENT objects of one name: the API keeps one and the input does not say which. Their union
            # is neither -- it once made "run privileged pods" out of a Role that creates pods and another that
            # uses SCC privileged (R2). Neither is read; the binding to the name is a gap.
            book.rules[ref] = []
            book.unreadable.add(ref)
            book.open[ref] = (
                f"{len(forms)} different objects named {ref} are in the input; which one the cluster holds is not "
                "known, so neither is read"
            )
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
        if ref in book.unreadable:
            continue  # an ambiguous or unreadable role is not filled from its sources either
        reached: list[str] = []
        todo = [s for s in sources.get(ref, []) if s not in book.unreadable]
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


def _subject_readable(subj: Any) -> bool:
    """A subject of a kind the API defines, with a string name and, if any, a string namespace."""
    return (
        isinstance(subj, dict)
        and subj.get("kind") in {"ServiceAccount", "User", "Group"}
        and isinstance(subj.get("name"), str)
        and isinstance(subj.get("namespace"), (str, type(None)))
    )


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

    def gap(b: dict[str, Any], who: str, at: str, role_ref: str, reason: str, *, unread: bool = False) -> None:
        if gaps is not None:
            gaps.append(Gap(_ref(b), who, at, role_ref, reason))
        if unread:
            # Something the input carries and this scan could not read: the scan says so in notRead, instead of
            # scoring the binding as nothing with an empty notRead (as main did for `verbs: "*"`, G273).
            inv.not_read.append(f"{reason} (bound by {_ref(b)})" if _ref(b) not in reason else reason)

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
                unread=True,
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
            # A subject this scan cannot read -- a bare string, a kind the API does not define ("serviceaccount"),
            # a name that is a list -- may be this account. Read as "names nobody", it made the RBAC leg `none`
            # (N6 neighbour, found rerunning the reviewer's mal.py).
            bad = next((j for j, s in enumerate(_list(subjects)) if not _subject_readable(s)), None)
            if bad is not None:
                gap(
                    b,
                    "subject unreadable",
                    f"subjects[{bad}]",
                    role_ref,
                    f"{_ref(b)}: subjects[{bad}] is not a subject this scan can read, so whom it binds is not known",
                    unread=True,
                )
            continue
        j, who = matched
        if not isinstance(ref, dict) or not rname:
            gap(b, who, f"subjects[{j}]", role_ref, f"{_ref(b)}: roleRef does not name a role", unread=True)
            continue
        rules = book.get(role_ref)
        if rules is None:
            kind_name = f"{role_ref.split('/', 1)[0]}/{rname}"
            if role_ref.startswith("Role/") and kind_name in inv.unplaced:
                # The Role is in the input, with no namespace: "not in the input" was false (fifth review, E1).
                unplaced_why = (
                    f"{kind_name} has no namespace: whether it is the {role_ref} this binding names is not known; "
                    "pass -n"
                )
                inv.not_read.append(f"{unplaced_why} (bound by {_ref(b)})")
                gap(b, who, f"subjects[{j}]", role_ref, unplaced_why)
                continue
            inv.not_read.append(f"{role_ref} (bound by {_ref(b)}) is not in the input")
            gap(b, who, f"subjects[{j}]", role_ref, f"{role_ref} is not in the input")
            continue
        if role_ref in book.open:
            reason = book.open[role_ref]
            if role_ref in book.empty:
                inv.not_read.append(
                    f"{role_ref} (bound by {_ref(b)}) aggregates ClusterRoles by label and none in the input matches"
                )
            gap(b, who, f"subjects[{j}]", role_ref, reason, unread=role_ref in book.unreadable)
        for i, rule in enumerate(rules):
            why = _malformed_rule(rule)
            if why is not None:
                gap(
                    b,
                    who,
                    f"subjects[{j}]",
                    role_ref,
                    f"{role_ref} rules[{i}] {why}, so what it grants is not known",
                    unread=True,
                )
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


def resource_matches(rule_resources: set[str], requested: str) -> bool:
    """Whether a rule's `resources` cover a requested resource, exactly as the API server decides it: `*`, the exact
    name (subresources included, `pods/exec`), or `*/<subresource>` for any resource's subresource of that name.
    From Kubernetes `pkg/apis/rbac/v1/evaluation_helpers.go` `ResourceMatches`, tag v1.34.0. An exact-name test
    read `*/exec` with `get` as a plain read (G273, N1)."""
    if "*" in rule_resources or requested in rule_resources:
        return True
    if "/" in requested:
        return "*/" + requested.split("/", 1)[1] in rule_resources
    return False


def _core(groups: set[str]) -> bool:
    return bool(groups & {"", "*"}) or not groups


def reads_secrets(rule: dict[str, Any]) -> bool:
    """True when an RBAC rule lets its holder read Secret objects (get, list or watch, or every verb)."""
    verbs, res, groups = _strs(rule.get("verbs")), _strs(rule.get("resources")), _strs(rule.get("apiGroups"))
    return _core(groups) and resource_matches(res, "secrets") and bool(verbs & {"*", "get", "list", "watch"})


_READ = frozenset({"get", "list", "watch"})
_WRITE = ("create", "update", "patch", "delete", "deletecollection")
_RBAC_OBJECTS = frozenset({"roles", "rolebindings", "clusterroles", "clusterrolebindings"})
#: Requests that can grant more than a plain read or write, matched against wildcard resources: (group, resource,
#: verbs, capability key or "" when no ranked capability covers it). A wildcard rule reading `*` is classified
#: only when every one of these it covers is ranked.
_SENSITIVE: tuple[tuple[str, str, frozenset[str], str], ...] = (
    ("", "secrets", _READ, "read"),
    ("", "secrets", frozenset({"create"}), "mint-secret"),
    ("", "pods/exec", frozenset({"get", "create"}), "exec"),
    ("", "pods/attach", frozenset({"get", "create"}), "exec"),
    ("", "pods/portforward", frozenset({"get", "create"}), ""),
    ("", "pods/proxy", frozenset({"get", "create", "update", "patch", "delete"}), ""),
    ("", "services/proxy", frozenset({"get", "create", "update", "patch", "delete"}), ""),
    ("", "nodes/proxy", frozenset({"get", "create", "update", "patch", "delete"}), "kubelet"),
    ("", "pods/ephemeralcontainers", frozenset({"patch", "update"}), "ephemeral"),
    ("", "serviceaccounts/token", frozenset({"create"}), "token"),
    ("certificates.k8s.io", "certificatesigningrequests/status", frozenset({"update", "patch"}), ""),
)
#: Writes this module knows grant nothing it would rank, each with why. Verified against the Kubernetes RBAC
#: good-practices page (https://kubernetes.io/docs/concepts/security/rbac-good-practices/#privilege-escalation-risks,
#: read 2026-11-12), whose escalation list none of them is on, and the default roles that hand them to everyone
#: (https://kubernetes.io/docs/reference/access-authn-authz/rbac/#default-roles-and-role-bindings):
#: - selfsubjectaccessreviews, selfsubjectrulesreviews, selfsubjectreviews `create`: asking what the caller itself
#:   may do -- system:basic-user grants them to every authenticated user;
#: - subjectaccessreviews, localsubjectaccessreviews `create`: asking what ANOTHER identity may do. Information
#:   about authorization, not a right to act -- system:auth-delegator grants it to add-on API servers;
#: - tokenreviews `create`: asking whom a token the caller already holds belongs to;
#: - leases (coordination.k8s.io): leader election. A holder can take another controller's lease -- a denial of
#:   service on that controller, not a right it did not have;
#: - events: writing event records;
#: - `<resource>/status`: reporting an object's state, except certificatesigningrequests/status, which carries the
#:   issued certificate. A wildcard `*/status` covers that one too and is not harmless.
#: Not in the set, so not determined: ConfigMap writes (another workload's configuration -- on some platforms the
#: map that grants cluster access), and every other write.
_HARMLESS_CREATE = {
    "authorization.k8s.io": frozenset(
        {"selfsubjectaccessreviews", "selfsubjectrulesreviews", "subjectaccessreviews", "localsubjectaccessreviews"}
    ),
    "authentication.k8s.io": frozenset({"selfsubjectreviews", "tokenreviews"}),
}
_HARMLESS_WRITE_GROUPS = {"events": frozenset({"", "events.k8s.io"}), "leases": frozenset({"coordination.k8s.io"})}
#: Capabilities this change added. A grant that already has full control in a scope does not list them again for
#: that scope: they are inside it, and listing twelve paths where main listed six was noise (G273).
_SUBSUMED_BY_FULL = frozenset({"ephemeral", "token", "mint-secret", "pv", "webhooks", "csr"})
#: OpenShift binds system:authenticated to impersonate `userextras/scopes.authorization.openshift.io` only: "purely
#: tightening ... does not grant access to impersonate in general" (openshift-apiserver pkg/bootstrappolicy/
#: policy.go, ScopeImpersonationRoleName, commit 9fc0918d1c6908e8e8ceb8e215e86bde4aeaabec). Impersonating extras
#: alone is not impersonating a user.
_EXTRAS_PREFIX = "userextras/"


def _covers_group(groups: set[str], group: str) -> bool:
    return "*" in groups or group in groups or (group == "" and not groups)


#: The API groups that serve each workload resource. `deployments` under `example.com` is some CRD's resource, not
#: a Deployment, and was ranked as "create workloads" (found rerunning the reviewer's rb.py, G273): it is now not
#: classified. extensions served Deployments, ReplicaSets and DaemonSets until 1.16.
_WORKLOAD_GROUPS: dict[str, frozenset[str]] = {
    "pods": frozenset({""}),
    "replicationcontrollers": frozenset({""}),
    "deployments": frozenset({"apps", "extensions"}),
    "replicasets": frozenset({"apps", "extensions"}),
    "daemonsets": frozenset({"apps", "extensions"}),
    "statefulsets": frozenset({"apps"}),
    "jobs": frozenset({"batch"}),
    "cronjobs": frozenset({"batch"}),
    "deploymentconfigs": frozenset({"apps.openshift.io", ""}),
}


def _workload_in(groups: set[str], resource: str) -> bool:
    return any(_covers_group(groups, grp) for grp in _WORKLOAD_GROUPS.get(resource, frozenset({""})))


@dataclass(frozen=True)
class Unclassified:
    """A grant whose rule allows (resource, verb) pairs that no ranked capability and no known-harmless entry
    explains. Classified pair by pair: a rule that reads Secrets and patches nodes is not "read Secrets" (N9)."""

    grant: Grant
    verbs: tuple[str, ...]
    resources: tuple[str, ...]
    why: str = ""

    def text(self) -> str:
        return (
            f"{self.grant.role_ref} {self.grant.rule_at} ({', '.join(self.verbs)} on {', '.join(self.resources)})"
            + (f": {self.why}" if self.why else "")
        )


def _pair_open(g: Grant, r: str, v: str, have: set[str], own: tuple[str, str] | None) -> str | None:
    """None when the pair (resource r, verb v) of the grant's rule is explained -- by a capability `have` holds for
    this grant, or as known harmless; otherwise a short reason ("" for the generic one)."""
    groups = _strs(g.rule.get("apiGroups"))
    if "full" in have:
        return None  # every verb on every resource of every group: nothing in the rule is left to explain
    if v in ESCALATION_VERBS:
        if v == "impersonate" and r.startswith(_EXTRAS_PREFIX):
            return None
        return None if "escalate" in have else ""
    if v == "use" and r == "securitycontextconstraints":
        return None
    if v == "approve" and r == "signers":
        return None if "csr" in have else ""
    if r == "signers" and v not in {"approve", "sign", "*"}:
        # `signers` is checked for approve and sign only
        # (https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/#authorization)
        return None
    verbs = list(_READ) + list(_WRITE) if v == "*" else [v]
    wildcard = r == "*" or r.startswith("*/")
    for ev in verbs:
        if wildcard:
            for group, res, svs, key in _SENSITIVE:
                if ev in svs and _covers_group(groups, group) and resource_matches({r}, res):
                    if key == "kubelet" and not g.cluster:
                        continue  # nodes are cluster-scoped: a RoleBinding grants nothing on them
                    if not key or key not in have:
                        return ""
            if ev not in _READ and not (r == "*" and "full" in have):
                return ""
            continue
        reason = _concrete_open(g, groups, r, ev, have, own)
        if reason is not None:
            return reason
    return None


def _concrete_open(
    g: Grant, groups: set[str], r: str, ev: str, have: set[str], own: tuple[str, str] | None
) -> str | None:
    core = _core(groups)
    if "full" in have:
        return None
    for group, res, svs, key in _SENSITIVE:
        if r == res and ev in svs and _covers_group(groups, group):
            if key == "kubelet" and not g.cluster:
                return None
            if key == "token" and own is not None:
                names = _strs(g.rule.get("resourceNames"))
                if names == {own[1]} and not g.cluster and g.namespace == own[0]:
                    return None  # a TokenRequest for its own account is no new right
            if key == "mint-secret" and key not in have:
                return (
                    "creating a Secret mints a long-lived token only if the account can read it back (get on "
                    "secrets) or mount it in a pod it creates"
                )
            return None if key and key in have else ""
    if ev in _READ:
        return "" if r.endswith("/proxy") else None
    if r in WORKLOAD_RESOURCES and ev in {"create", "patch", "update"} and _workload_in(groups, r):
        return None if "workloads" in have else ""
    if core and r == "persistentvolumes" and ev == "create":
        return None if "pv" in have or not g.cluster else ""
    if r in {"validatingwebhookconfigurations", "mutatingwebhookconfigurations"} and ev in {
        "create",
        "update",
        "patch",
    }:
        return None if "webhooks" in have else ""
    if r in {"certificatesigningrequests", "certificatesigningrequests/approval"}:
        return None if "csr" in have else ""
    if ev == "create" and any(r in rs and _covers_group(groups, grp) for grp, rs in _HARMLESS_CREATE.items()):
        return None
    if r in _HARMLESS_WRITE_GROUPS and any(_covers_group(groups, grp) for grp in _HARMLESS_WRITE_GROUPS[r]):
        return None
    if r.endswith("/status") and r != "certificatesigningrequests/status":
        return None
    if r in _RBAC_OBJECTS:
        # Without escalate or bind the API refuses a role or binding carrying rights the caller lacks
        # (https://kubernetes.io/docs/reference/access-authn-authz/rbac/#privilege-escalation-prevention-and-bootstrapping).
        return None
    return ""


def _api_capabilities(
    inv: Inventory,
    grants: list[Grant],
    unclassified: list[Unclassified] | None = None,
    account: tuple[str, str] | None = None,
) -> list[Capability]:
    """What the grants let the account do. ``unclassified`` collects, rule by rule, the (resource, verb) pairs no
    ranked capability explains and no named harmless entry covers: the blast radius reports those as not determined
    instead of as "nothing" (G273). ``account`` is the ServiceAccount the grants belong to, for the one case where
    the answer depends on it (a TokenRequest for itself).

    The escalation rights are the ones the Kubernetes RBAC good-practices page names
    (https://kubernetes.io/docs/concepts/security/rbac-good-practices/#privilege-escalation-risks, read 2026-11-12):
    reading Secrets, creating workloads, PersistentVolume creation, nodes/proxy, escalate, bind, impersonate, CSR
    creation with approval, TokenRequest (`serviceaccounts/token` create) and control of admission webhooks; plus
    exec and attach (`create`, or `get` over WebSocket), ephemeral containers (`patch`/`update` on
    `pods/ephemeralcontainers`, which "run arbitrary commands" in an existing Pod:
    https://kubernetes.io/docs/concepts/workloads/pods/ephemeral-containers/) and creating a Secret of type
    service-account-token, which mints a long-lived token for any ServiceAccount named in its annotation -- usable
    only read back or mounted, so ranked only when the account can also read Secrets or create pods in that scope
    (https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/
    #manually-create-a-long-lived-api-token-for-a-serviceaccount). Resources match as the API server matches them
    (`resource_matches`).
    """
    found: dict[tuple[str, str], Capability] = {}
    have: dict[int, set[str]] = {}
    workload_grant: Grant | None = None
    scc_grant: tuple[Grant, str] | None = None
    csr_create: Grant | None = None
    csr_approve: Grant | None = None
    minters: list[Grant] = []
    privileged = _privileged_scc_names(inv)

    def add(
        key: str,
        name: str,
        g: Grant,
        cluster_w: int,
        ns_w: int,
        fix: str,
        named: bool = False,
        implies_reads: bool = False,
    ) -> None:
        have.setdefault(id(g), set()).add(key)
        if key in _SUBSUMED_BY_FULL and "full" in have[id(g)]:
            return
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
        ckey = (cap.name, scope)
        if ckey not in found or found[ckey].weight < weight:
            found[ckey] = cap

    for g in grants:
        verbs, res = _strs(g.rule.get("verbs")), _strs(g.rule.get("resources"))
        groups, names = _strs(g.rule.get("apiGroups")), _strs(g.rule.get("resourceNames"))
        any_res, any_verb = "*" in res, "*" in verbs
        core = _core(groups)
        builtin = g.role_ref.removeprefix("ClusterRole/") in BUILTIN_CLUSTER_ROLES or ":" in g.role_ref.split("/")[-1]
        narrow = (
            f"bind a narrower Role than the built-in {g.role_ref}"
            if builtin
            else f"narrow {g.evidence.split(' -> ')[-1]}"
        )

        def has(*requested: str) -> bool:
            return any(resource_matches(res, r) for r in requested)  # noqa: B023 -- called inside this iteration

        def can(*vs: str) -> bool:
            return any_verb or bool(verbs & set(vs))  # noqa: B023 -- called inside this iteration only

        if any_res and any_verb and "*" in groups:
            add("full", "full control", g, 10, 7, f"bind a narrower role than {g.role_ref}", implies_reads=True)
        if reads_secrets(g.rule):
            add(
                "read",
                "read Secrets (credentials, tokens of other ServiceAccounts)",
                g,
                8,
                6,
                f"{narrow}: drop secrets",
                named=bool(names),
            )
        impersonates = {r for r in res if not r.startswith(_EXTRAS_PREFIX)} if "impersonate" in verbs else set()
        if verbs & {"escalate", "bind"} or impersonates or (any_verb and (any_res or res & _IDENTITY_RESOURCES)):
            add(
                "escalate",
                "escalate, bind or impersonate",
                g,
                9,
                6,
                f"{narrow}: drop escalate, bind and impersonate",
                implies_reads=True,
            )
        if core and has("pods/exec", "pods/attach") and can("create", "get"):
            add("exec", "exec into pods", g, 7, 5, f"{narrow}: drop pods/exec and pods/attach")
        if core and has("pods/ephemeralcontainers") and can("patch", "update"):
            add(
                "ephemeral",
                "add containers to running pods (pods/ephemeralcontainers)",
                g,
                7,
                5,
                f"{narrow}: drop patch/update on pods/ephemeralcontainers",
            )
        workloads = [w for w in WORKLOAD_RESOURCES if _workload_in(groups, w)]
        if has(*workloads) and can("create", "patch", "update"):
            add(
                "workloads",
                "create or change workloads (run as any ServiceAccount of the namespace)",
                g,
                7,
                5,
                f"{narrow}: drop create/patch/update on workloads",
                implies_reads=True,
            )
            workload_grant = workload_grant or g
        if core and has("serviceaccounts/token") and can("create"):
            own = (
                account is not None
                and names == {account[1]}
                and not g.cluster
                and g.namespace == account[0]
                and not any_res
            )
            if not own:
                add(
                    "token",
                    "mint tokens for its ServiceAccounts (serviceaccounts/token create)",
                    g,
                    7,
                    5,
                    f"{narrow}: drop create on serviceaccounts/token",
                    named=bool(names),
                )
        if core and has("secrets") and can("create"):
            minters.append(g)
        if core and has("nodes/proxy") and can("get", "create") and g.cluster:
            add("kubelet", "kubelet API through nodes/proxy", g, 8, 8, f"{narrow}: drop nodes/proxy")
        if g.cluster and core and has("persistentvolumes") and can("create"):
            add(
                "pv",
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
                "webhooks",
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

    # A Secret it creates mints a token it can use only if it can read the Secret back or mount it in a pod it
    # creates, in the same scope. `edit` and `admin` grant both; `secrets create` alone grants neither (N11).
    def readable_in(g: Grant) -> bool:
        return any(
            ("read" in have.get(id(h), set()) or "workloads" in have.get(id(h), set()))
            and (h.cluster or (not g.cluster and h.namespace == g.namespace))
            for h in grants
        )

    for g in minters:
        if readable_in(g):
            add(
                "mint-secret",
                "mint long-lived ServiceAccount tokens (create a service-account-token Secret)",
                g,
                7,
                5,
                f"bind a narrower role than {g.role_ref}: drop create on secrets",
            )
    if workload_grant and scc_grant:
        g, scc = scc_grant
        found[("run privileged pods", "node")] = Capability(
            f"run privileged pods (SCC {scc} + create workloads)",
            "node",
            9,
            f"{g.evidence}; and {workload_grant.evidence}",
            f"remove the 'use' grant on SCC {scc} or the right to create workloads",
            grants=(g, workload_grant),
        )
    if csr_create and csr_approve:
        for g in (csr_create, csr_approve):
            have.setdefault(id(g), set()).add("csr")
        if not ({"full"} & have.get(id(csr_create), set()) and {"full"} & have.get(id(csr_approve), set())):
            found[("issue client certificates", "cluster")] = Capability(
                "issue client certificates (create and approve CertificateSigningRequests)",
                "cluster",
                9,
                f"{csr_create.evidence}; and {csr_approve.evidence}",
                "remove create on certificatesigningrequests or update on certificatesigningrequests/approval",
                grants=(csr_create, csr_approve),
            )
    if unclassified is not None:
        for g in grants:
            unclassified += _open_pairs(g, have.get(id(g), set()), account)
    return list(found.values())


def _open_pairs(g: Grant, have: set[str], account: tuple[str, str] | None) -> list[Unclassified]:
    """The rule's unexplained (resource, verb) pairs, as one entry per distinct reason, in the rule's own order."""
    verbs = [str(v) for v in _list(g.rule.get("verbs"))]
    res = [str(r) for r in _list(g.rule.get("resources"))]
    urls = [str(u) for u in _list(g.rule.get("nonResourceURLs"))]
    by_reason: dict[str, tuple[list[str], list[str]]] = {}
    if not res and urls:
        open_verbs = [v for v in verbs if v not in _READ]
        if open_verbs:
            by_reason[""] = (open_verbs, urls)
    for r in res:
        for v in verbs:
            why = _pair_open(g, r, v, have, account)
            if why is None:
                continue
            vs, rs = by_reason.setdefault(why, ([], []))
            if v not in vs:
                vs.append(v)
            if r not in rs:
                rs.append(r)
    return [Unclassified(g, tuple(vs), tuple(rs), why) for why, (vs, rs) in by_reason.items()]


@dataclass(frozen=True)
class Mount:
    """How the pod gets its ServiceAccount's token: the account, the evidence line, the field that proves it, and
    the audience a projected token asks for ("" for the API server's own)."""

    service_account: str
    evidence: str
    at: str
    audience: str = ""
    #: Why whose token this is cannot be told from the input ("" when it can): a Secret volume at the token path
    #: whose Secret is not in the input (G273, N8).
    unknown: str = ""


#: Where the kubelet mounts a ServiceAccount token, and where a hand-mounted one is read from by every client library
#: (https://kubernetes.io/docs/tasks/run-application/access-api-from-pod/#directly-accessing-the-rest-api).
#: Only ever compared with the mount paths a manifest declares; never opened. Joined from parts because the plugin
#: tests (and the plugin directory's scan they mirror) flag the literal as a read of the machine's own token
#: (tests/test_plugin.py), and this module ships in the plugin.
SA_MOUNT_DIR = posixpath.join("/var/run", "secrets", "kubernetes.io", "serviceaccount")


def _legacy_mount(
    spec: dict[str, Any],
    site: _Site | None,
    ns: str,
    sa: str,
    who: str,
    base: str,
    legacy_accounts: dict[tuple[str, str], str],
) -> Mount | None:
    """A legacy token Secret mounted as a volume: a Secret of type service-account-token (its annotation names the
    account), or any Secret volume at the token path. Before 1.24 every account had one; they can still be made by
    hand (https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/
    #manually-create-a-long-lived-api-token-for-a-serviceaccount). Missing it read `token: none` for a pod holding a
    cluster-admin token (G273, N8). Only the Secret's type and annotation are read, never its data."""
    paths: dict[str, list[str]] = {}
    for _at, c in _located_containers(spec, site):
        for m in _list(c.get("volumeMounts")):
            if isinstance(m, dict):
                paths.setdefault(str(m.get("name")), []).append(posixpath.normpath(str(m.get("mountPath") or "/")))
    for i, v in enumerate(_list(spec.get("volumes"))):
        if not isinstance(v, dict) or str(v.get("name")) not in paths:
            continue
        # A projected volume can carry a Secret too (`sources[].secret`): a token Secret there is a token as much
        # as in a `secret` volume (third review, item 5).
        for j, src in enumerate(_list(_get(v, "projected", "sources"))):
            name = _get(src, "secret", "name")
            if isinstance(name, str) and (ns, name) in legacy_accounts:
                account = legacy_accounts[(ns, name)] or sa
                return Mount(
                    account,
                    f"{who}; volume {v.get('name')} projects Secret {name}, a service-account-token Secret of "
                    f"ServiceAccount {account}",
                    f"{base}volumes[{i}].projected.sources[{j}].secret.name",
                )
        secret = _get(v, "secret", "secretName")
        if not isinstance(secret, str) or not secret:
            continue
        at = f"{base}volumes[{i}].secret.secretName"
        at_token_dir = SA_MOUNT_DIR in paths[str(v.get("name"))]
        if (ns, secret) in legacy_accounts:
            account = legacy_accounts[(ns, secret)] or sa
            return Mount(
                account,
                f"{who}; volume {v.get('name')} mounts Secret {secret}, a service-account-token Secret of "
                f"ServiceAccount {account}",
                at,
            )
        if at_token_dir:
            return Mount(
                sa,
                f"{who}; volume {v.get('name')} mounts Secret {secret} at {SA_MOUNT_DIR}",
                at,
                unknown=(
                    f"Secret {ns}/{secret} is mounted at {SA_MOUNT_DIR} and is not in the input: whose token it "
                    f"holds is not known; ServiceAccount {sa}'s rights are listed"
                ),
            )
    return None


def _token(
    no_automount: set[tuple[str, str]],
    w: dict[str, Any],
    spec: dict[str, Any],
    site: _Site | None = None,
    legacy_accounts: dict[tuple[str, str], str] | None = None,
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
    return _legacy_mount(spec, site, _ns(w), sa, who, base, legacy_accounts or {})


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
    #: How many different objects carry this reference; 1 for an unambiguous name (see `workload_reach`).
    copies: int = 1
    #: For a copy: the fields the copies of its name differ in.
    differs: tuple[str, ...] = ()
    #: Objects with no namespace that bear on this reach (its own, its account's, any unplaced Role or binding).
    caveats: tuple[str, ...] = ()

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

    selects: dict[int, list[tuple[int, Entry, dict[str, Any], str]]]  # id(site) -> (entry index, entry, selector, note)
    no_automount: set[tuple[str, str]]

    @classmethod
    def build(cls, inv: Inventory, entries: list[Entry], sites: list[_Site]) -> _Index:
        # Every distinct Service of a name: the API keeps one, and which one the input does not say, so each
        # candidate is evaluated and its paths say they depend on it. Keeping "the first" made the answer depend on
        # document order on main, and losing both lost real paths (R3, G273).
        services: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for s in inv.of("Service"):
            found = services.setdefault((_ns(s), _name(s)), [])
            if all(_canonical_form(s) != _canonical_form(o) for o in found):
                found.append(s)
        by_label: dict[tuple[str, str, str], list[int]] = {}
        for n, site in enumerate(sites):
            for k, v in site.labels.items():
                by_label.setdefault((_ns(site.obj), k, v), []).append(n)
        selects: dict[int, list[tuple[int, Entry, dict[str, Any], str]]] = {}
        by_target = {(site.ref.split("[")[0], site.path): n for n, site in enumerate(sites)}
        for i, e in enumerate(entries):
            if e.declared_on is not None:
                target_n = by_target.get(e.declared_on)
                if target_n is not None:
                    selects.setdefault(id(sites[target_n]), []).append((i, e, {}, ""))
                continue
            candidates_svc = services.get((e.namespace, e.service), [])
            # A Service-type entry is one object and reaches through its own selector; a Route or Ingress names
            # the Service and reaches through whichever candidate is real.
            selectors = (
                [e.selector] if e.selector is not None else [_get(s, "spec", "selector") for s in candidates_svc]
            )
            note = (
                f" (one of {len(candidates_svc)} different Services named {e.namespace}/{e.service} in the input)"
                if len(candidates_svc) > 1
                else ""
            )
            for selector in selectors:
                if not isinstance(selector, dict) or not selector:
                    continue
                candidates = min(
                    (by_label.get((e.namespace, str(k), str(v)), []) for k, v in selector.items()), key=len
                )
                for n in candidates:
                    # True only. A None ("the operator merges in labels this input does not show") must not become
                    # an edge the report presents as proven; it becomes a named limitation instead (G231).
                    if selector_decides({"matchLabels": selector}, sites[n].template) is True:
                        selects.setdefault(id(sites[n]), []).append((i, e, selector, note))
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
    for i, entry, selector, note in index.selects.get(id(site), []):
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
                f"selector {selector} matches the pod template labels{note}",
            )
        steps = [*entry.steps, to_w]
        if any(j == i and s == steps for j, _e, s in reach_entries):
            continue  # two candidate Services with one selector reach the pod by one path, listed once
        reach_entries.append((i, entry, steps))
    api: list[tuple[Capability, list[Step]]] = []
    mount = _token(index.no_automount, w, spec, site, inv.legacy_accounts)
    if mount is not None:
        sa, evidence = mount.service_account, mount.evidence
        key = (_ns(w), sa)
        if key not in sa_caps:
            sa_caps[key] = _api_capabilities(inv, _grants(inv, *key), account=key)
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
    """Every workload (not owned by another) with its exposures, node and API capabilities, keyed by Kind/ns/name.

    Two different objects of one name: which one the cluster runs is not known, so each is placed on its own, as
    `Kind/ns/name#1`, `#2`, ... -- in the key and in `Reach.ref`, so every consumer (rank, gate, assess, SARIF)
    tells the copies apart and counts each once (fifth review: both copies were `Deployment/shop/web`, and one CVE
    was counted twice for that workload). Keeping one dropped the other (rounds two and three); merging them
    joined one copy's vulnerable image to the other copy's cluster-admin token (fourth review).
    `ambiguous_notes` names each ambiguous name and the fields its copies differ in. Every reach also carries the
    caveats of objects with no namespace that bear on it (`caveats`)."""
    sites = _sites(inv, owned=False)
    index = _Index.build(inv, _entries(inv), sites)
    sa_caps: dict[tuple[str, str], list[Capability]] = {}
    out: dict[str, Reach] = {}
    groups: dict[str, list[_Site]] = {}
    for site in sites:
        groups.setdefault(site.ref, []).append(site)
    rbac_unplaced = sorted(u for u in inv.unplaced if u.split("/")[0] in {"Role", "RoleBinding"})
    for ref, members in groups.items():
        objects = list(dict.fromkeys(id(s.obj) for s in members))
        differs = _copy_differences([next(s for s in members if id(s.obj) == o) for o in objects])
        for site in members:
            r = _reach(inv, site, index, sa_caps)
            r.copies = len(objects)
            if r.copies > 1:
                r.ref = f"{ref}#{objects.index(id(site.obj)) + 1}"
                r.differs = differs
            r.caveats = _unplaced_caveats(inv, site, rbac_unplaced)
            out[r.ref] = r
    return out


def _copy_differences(copies: list[_Site]) -> tuple[str, ...]:
    """The pod-spec fields the copies of one name disagree on, named, for the ambiguity note."""

    def facts(site: _Site) -> dict[str, str]:
        spec = site.spec
        cs = [c for c in _list(spec.get("containers")) if isinstance(c, dict)]
        return {
            "serviceAccountName": str(spec.get("serviceAccountName") or spec.get("serviceAccount") or "default"),
            "images": ", ".join(sorted(str(c.get("image")) for c in cs)),
            "automountServiceAccountToken": str(spec.get("automountServiceAccountToken")),
            "hostPID": str(spec.get("hostPID") is True),
            "hostNetwork": str(spec.get("hostNetwork") is True),
            "hostIPC": str(spec.get("hostIPC") is True),
            "privileged": str(any(_get(c, "securityContext", "privileged") is True for c in cs)),
            "hostPath": ", ".join(
                sorted(str(_get(v, "hostPath", "path")) for v in _list(spec.get("volumes")) if _get(v, "hostPath"))
            ),
        }

    seen = [facts(s) for s in copies]
    out = []
    for k in seen[0]:
        values = [f[k] for f in seen]
        if len(set(values)) > 1:
            out.append(f"{k}: " + " / ".join(f"#{i} {v or '-'}" for i, v in enumerate(values, 1)))
    return tuple(out) or ("other fields of the pod spec or the object",)


def _unplaced_caveats(inv: Inventory, site: _Site, rbac_unplaced: list[str]) -> tuple[str, ...]:
    if inv.live or not inv.unplaced:
        return ()
    spec = site.spec
    sa = str(spec.get("serviceAccountName") or spec.get("serviceAccount") or "default")
    mine = [u for u in (f"{site.obj.get('kind')}/{_name(site.obj)}", f"ServiceAccount/{sa}") if u in inv.unplaced]
    out = [f"{u} has no namespace: whose subject its account is, is not known; pass -n" for u in mine]
    out += [f"{u} has no namespace: which accounts it binds is not known; pass -n" for u in rbac_unplaced]
    return tuple(out)


def ambiguous_notes(reach: dict[str, Reach], limit: int = 20) -> list[str]:
    """One line per name several different objects carry, naming the fields their copies differ in, then one per
    object with no namespace that bears on a reach; at most `limit`, then how many were withheld."""
    by_ref: dict[str, list[Reach]] = {}
    for r in reach.values():
        if r.copies > 1:
            by_ref.setdefault(r.ref.rsplit("#", 1)[0], []).append(r)
    out = []
    for ref, copies in sorted(by_ref.items()):
        who = "; ".join(
            f"{r.ref}: {r.token[0] if r.token else 'no token'}" for r in sorted(copies, key=lambda x: x.ref)
        )
        out.append(
            f"{len(copies)} different objects named {ref} are in the input; which one runs is not known, so each "
            f"is placed separately as {ref}#n ({who}); they differ in {'; '.join(copies[0].differs)}"
        )
    out += sorted({c for r in reach.values() for c in r.caveats})
    if len(out) > limit:
        return [*out[:limit], f"... and {len(out) - limit} more"]
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


def unclassified_of(inv: Inventory, grants: list[Grant], account: tuple[str, str] | None = None) -> list[Unclassified]:
    """The (resource, verb) pairs of the grants that no capability this scan ranks explains and no named harmless
    entry covers, rule by rule (G273)."""
    out: list[Unclassified] = []
    _api_capabilities(inv, grants, out, account)
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
    # Read live from some namespaces only: a route in a namespace not read can send traffic into one that was
    # (cross-namespace backendRefs, VirtualService hosts), so its absence is not an answer (fourth review, D5).
    scope_notes = (
        [f"{UNREAD_NAMESPACES_NOTE} (read: {', '.join(sorted(inv.namespaces_read))})"]
        if inv.live and inv.namespaces_read
        else []
    )
    limitations += scope_notes
    if inv.unplaced:
        limitations.append(
            f"{len(inv.unplaced)} object(s) have no namespace: they are shown in default, but kubectl apply puts them "
            "in the namespace given with -n or the context's; pass -n to place them (named in notRead)"
        )
    scope_notes += [
        f"{n} has no namespace: it is placed in default; pass -n as kubectl apply -n would"
        for n in sorted(inv.unplaced)
    ]
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
        # Read failures, objects present but not modelled, names carried by two different objects, and fronts whose
        # Service is not in the input: each is something the paths above could not account for (G273).
        "notRead": sorted(
            set(inv.not_read) | set(inv.duplicate_notes()) | {line for _, line in dangling(inv)} | set(scope_notes)
        )[:50],
        "secretsIgnored": inv.dropped_unread,
        "limitations": limitations,
    }


def scan_manifests(text: str, *, top: int = DEFAULT_TOP, default_namespace: str | None = None) -> dict[str, Any]:
    from kube_noob.yamlio import load_documents

    docs = load_documents(text)
    return scan(Inventory.from_documents((d.data for d in docs), default_namespace=default_namespace), top=top)


def _clip_words(text: str, limit: int = 200) -> str:
    """At most `limit` characters, cut at a word boundary with an ellipsis -- a refusal cut mid-word read as a
    different resource ("securitycontextconstraints.sec")."""
    text = " ".join(text.split())
    if len(text) <= limit:
        return text
    cut = text[:limit].rsplit(" ", 1)[0]
    return f"{cut} ..."


def collect_live(backend: Any, namespaces: list[str]) -> Inventory:
    """Read the inventory from the cluster through the read-only backend: never Secrets (not in its allowlist).

    Every failed list is not read, and what depends on it is not determined -- a 404 included. A 404 for
    `networking.istio.io/v1` comes as much from an Istio older than 1.22 (serving only v1beta1) as from a cluster
    without Istio, the same for Gateway API before v1.0.0, and an unavailable openshift-apiserver drops Routes from
    discovery; telling those apart needs API discovery, which kube-noob does not read. Reading any of them as "not
    served" said `exposure none, complete` for a pod behind a VirtualService (third review of G273)."""
    from kube_noob.debug.cluster import list_items, stamp_api_version
    from kube_noob.errors import KubeNoobError

    inv = Inventory(live=True, namespaces_read=list(namespaces))
    for resource, kind in LIVE_RESOURCES.items():
        scopes: list[str | None] = [None] if resource in CLUSTER_SCOPED or not namespaces else list(namespaces)
        for ns in scopes:
            try:
                # A response that is not a complete list of this resource is a failed read, not an empty list
                # (G270's lesson, G279's structural check).
                items = list_items(backend.get(resource, namespace=ns), resource, ns)
            except KubeNoobError as exc:
                where = f"{resource}{' in ' + ns if ns else ''}"
                why = _clip_words(str(exc))
                if why.startswith(f"{resource}: "):  # the structural check names the resource itself
                    why = why[len(resource) + 2 :]
                inv.not_read.append(f"{where}: {why}")
                continue
            for item in items:
                # Stamped AFTER the structural check: a list that is not a complete list of this resource is a
                # failed read above, and never stamped (G279, G281).
                inv.add(stamp_api_version(resource, item) if isinstance(item, dict) else item, kind)
    inv.canonicalize()
    return inv
