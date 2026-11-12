"""Read-only live cluster access (opt-in: ``cluster.enabled: true``): the allowlist, validation and redaction.

The backends that actually reach a cluster (``kubectl``/``oc`` with the operator's kubeconfig, or the pod's
ServiceAccount token) live in ``kube_noob.debug.backends`` and are imported only when cluster access is enabled.
The Claude plugin ships without them.

Guarantees: only GET-style operations on allowlisted resources; Secrets are never read; ConfigMap values, sensitive
env values and token-like strings in logs are redacted; arguments are validated against strict patterns.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal, Protocol

from kube_noob.audit.rules import SENSITIVE_ENV
from kube_noob.config import Settings
from kube_noob.errors import ClusterAccessError, KubeNoobError


@dataclass(frozen=True)
class ResourceDef:
    group_version: str  # "v1" for core
    plural: str
    namespaced: bool

    def path(self, namespace: str | None, name: str | None) -> str:
        base = "/api/v1" if self.group_version == "v1" else f"/apis/{self.group_version}"
        ns = f"/namespaces/{namespace}" if self.namespaced and namespace else ""
        tail = f"/{name}" if name else ""
        return f"{base}{ns}/{self.plural}{tail}"


ALLOWED_RESOURCES: dict[str, ResourceDef] = {
    "pods": ResourceDef("v1", "pods", True),
    "services": ResourceDef("v1", "services", True),
    "endpoints": ResourceDef("v1", "endpoints", True),
    "events": ResourceDef("v1", "events", True),
    "configmaps": ResourceDef("v1", "configmaps", True),
    "persistentvolumeclaims": ResourceDef("v1", "persistentvolumeclaims", True),
    "persistentvolumes": ResourceDef("v1", "persistentvolumes", False),
    "nodes": ResourceDef("v1", "nodes", False),
    "namespaces": ResourceDef("v1", "namespaces", False),
    "resourcequotas": ResourceDef("v1", "resourcequotas", True),
    "limitranges": ResourceDef("v1", "limitranges", True),
    "serviceaccounts": ResourceDef("v1", "serviceaccounts", True),
    "deployments": ResourceDef("apps/v1", "deployments", True),
    "replicasets": ResourceDef("apps/v1", "replicasets", True),
    "statefulsets": ResourceDef("apps/v1", "statefulsets", True),
    "daemonsets": ResourceDef("apps/v1", "daemonsets", True),
    "jobs": ResourceDef("batch/v1", "jobs", True),
    "cronjobs": ResourceDef("batch/v1", "cronjobs", True),
    "ingresses": ResourceDef("networking.k8s.io/v1", "ingresses", True),
    "networkpolicies": ResourceDef("networking.k8s.io/v1", "networkpolicies", True),
    # The two cluster-scoped tiers either side of NetworkPolicy. A cluster without the network-policy-api CRDs
    # answers 404 for both, which the reachability check treats as "not installed" rather than as a failure.
    "clusternetworkpolicies": ResourceDef("policy.networking.k8s.io/v1alpha2", "clusternetworkpolicies", False),
    # Cluster-scoped CNI policies this evaluator records and does not parse. The group, version, plural and
    # scope are the published CRDs: Cilium v1.18.3 cilium.io/v2, Calico v3.30.3 crd.projectcalico.org/v1.
    # A namespace CiliumNetworkPolicy is not here. It is a different resource, and this allowlist does not guess it.
    "ciliumclusterwidenetworkpolicies": ResourceDef("cilium.io/v2", "ciliumclusterwidenetworkpolicies", False),
    "globalnetworkpolicies": ResourceDef("crd.projectcalico.org/v1", "globalnetworkpolicies", False),
    # Calico publishes its own version here, "set automatically by calico/node": group
    # crd.projectcalico.org, version v1 (served and storage), scope Cluster, plural clusterinformations,
    # from projectcalico/calico libcalico-go/config/crd/crd.projectcalico.org_clusterinformations.yaml
    # (retrieved 2026-11-05). Read so that `policy reach --live` can tell whether this cluster's CNI still
    # enforces the admin tier, instead of assuming OVN-Kubernetes semantics on a Calico 3.32 cluster.
    "clusterinformations": ResourceDef("crd.projectcalico.org/v1", "clusterinformations", False),
    "adminnetworkpolicies": ResourceDef("policy.networking.k8s.io/v1alpha1", "adminnetworkpolicies", False),
    "baselineadminnetworkpolicies": ResourceDef(
        "policy.networking.k8s.io/v1alpha1", "baselineadminnetworkpolicies", False
    ),
    "poddisruptionbudgets": ResourceDef("policy/v1", "poddisruptionbudgets", True),
    "horizontalpodautoscalers": ResourceDef("autoscaling/v2", "horizontalpodautoscalers", True),
    "storageclasses": ResourceDef("storage.k8s.io/v1", "storageclasses", False),
    "routes": ResourceDef("route.openshift.io/v1", "routes", True),
    "clusteroperators": ResourceDef("config.openshift.io/v1", "clusteroperators", False),
    "clusterversions": ResourceDef("config.openshift.io/v1", "clusterversions", False),
    # The cluster's audit configuration, from openshift/api config/v1 types_apiserver.go (retrieved 2026-11-06):
    # group config.openshift.io, version v1, scope Cluster, the singleton named "cluster". `spec.audit.profile`
    # is one of Default, WriteRequestBodies, AllRequestBodies or None, and `spec.audit.customRules` is a
    # per-group list evaluated top to bottom whose first match TAKES PRECEDENCE over the top-level profile.
    # Settings only -- no audit event, no log content, nothing about a person.
    "apiservers": ResourceDef("config.openshift.io/v1", "apiservers", False),
    # Workload CRDs whose pod specs are embedded rather than in `spec.template.spec`. Group, version, plural and
    # scope are from the published CRDs (retrieved 2026-11-06): KServe
    # config/crd/full/serving.kserve.io_inferenceservices.yaml (serving.kserve.io, v1beta1, Namespaced) and
    # KubeRay helm-chart/kuberay-operator/crds/ray.io_ray{clusters,services,jobs}.yaml (ray.io, v1, Namespaced).
    # Read so that the audit and the attack-path scan score the pods these objects really run; a cluster without
    # the operator answers 404, which both report as not read rather than as clean (G229).
    "inferenceservices": ResourceDef("serving.kserve.io/v1beta1", "inferenceservices", True),
    "rayclusters": ResourceDef("ray.io/v1", "rayclusters", True),
    "rayservices": ResourceDef("ray.io/v1", "rayservices", True),
    "rayjobs": ResourceDef("ray.io/v1", "rayjobs", True),
    "securitycontextconstraints": ResourceDef("security.openshift.io/v1", "securitycontextconstraints", False),
    "deploymentconfigs": ResourceDef("apps.openshift.io/v1", "deploymentconfigs", True),
    # RBAC objects (who may do what; no credentials): read by the attack-path scan (kube_noob.attack_paths)
    "roles": ResourceDef("rbac.authorization.k8s.io/v1", "roles", True),
    "rolebindings": ResourceDef("rbac.authorization.k8s.io/v1", "rolebindings", True),
    "clusterroles": ResourceDef("rbac.authorization.k8s.io/v1", "clusterroles", False),
    "clusterrolebindings": ResourceDef("rbac.authorization.k8s.io/v1", "clusterrolebindings", False),
    "egressfirewalls": ResourceDef("k8s.ovn.org/v1", "egressfirewalls", True),
    "centrals": ResourceDef("platform.stackrox.io/v1alpha1", "centrals", True),
    "securedclusters": ResourceDef("platform.stackrox.io/v1alpha1", "securedclusters", True),
    # OLM-installed operators, read by the operator inventory (kube_noob.operators). Group, version, plural and scope
    # are the published CRDs, operator-framework/api e1a542ceb01262523627440bde3a0b3387bdeb16
    # crds/operators.coreos.com_{clusterserviceversions,subscriptions}.yaml: operators.coreos.com, v1alpha1 (served,
    # storage), Namespaced. Neither carries a credential; a Subscription's spec.config can carry env values, which the
    # inventory never reads and the redaction above masks. A cluster without OLM answers 404, which the inventory
    # reports as "not an OLM cluster" -- distinct from a 403, which it reports as not determined.
    "clusterserviceversions": ResourceDef("operators.coreos.com/v1alpha1", "clusterserviceversions", True),
    "subscriptions": ResourceDef("operators.coreos.com/v1alpha1", "subscriptions", True),
}

ALIASES = {
    "pod": "pods",
    "po": "pods",
    "svc": "services",
    "service": "services",
    "ep": "endpoints",
    "event": "events",
    "ev": "events",
    "cm": "configmaps",
    "configmap": "configmaps",
    "pvc": "persistentvolumeclaims",
    "pv": "persistentvolumes",
    "node": "nodes",
    "no": "nodes",
    "ns": "namespaces",
    "namespace": "namespaces",
    "quota": "resourcequotas",
    "sa": "serviceaccounts",
    "deploy": "deployments",
    "deployment": "deployments",
    "rs": "replicasets",
    "sts": "statefulsets",
    "statefulset": "statefulsets",
    "ds": "daemonsets",
    "daemonset": "daemonsets",
    "job": "jobs",
    "cj": "cronjobs",
    "cronjob": "cronjobs",
    "ing": "ingresses",
    "ingress": "ingresses",
    "netpol": "networkpolicies",
    "networkpolicy": "networkpolicies",
    "cnp": "clusternetworkpolicies",
    "clusternetworkpolicy": "clusternetworkpolicies",
    "ccnp": "ciliumclusterwidenetworkpolicies",
    "ciliumclusterwidenetworkpolicy": "ciliumclusterwidenetworkpolicies",
    "globalnetworkpolicy": "globalnetworkpolicies",
    "anp": "adminnetworkpolicies",
    "adminnetworkpolicy": "adminnetworkpolicies",
    "banp": "baselineadminnetworkpolicies",
    "baselineadminnetworkpolicy": "baselineadminnetworkpolicies",
    "pdb": "poddisruptionbudgets",
    "hpa": "horizontalpodautoscalers",
    "sc": "storageclasses",
    "storageclass": "storageclasses",
    "route": "routes",
    "co": "clusteroperators",
    "clusteroperator": "clusteroperators",
    "clusterversion": "clusterversions",
    "scc": "securitycontextconstraints",
    "egressfirewall": "egressfirewalls",
    "central": "centrals",
    "securedcluster": "securedclusters",
    "dc": "deploymentconfigs",
    "deploymentconfig": "deploymentconfigs",
    "role": "roles",
    "rolebinding": "rolebindings",
    "clusterrole": "clusterroles",
    "clusterrolebinding": "clusterrolebindings",
    # the CRDs' own short names (operator-framework/api crds/, the commit cited at the resource table)
    "csv": "clusterserviceversions",
    "csvs": "clusterserviceversions",
    "clusterserviceversion": "clusterserviceversions",
    "sub": "subscriptions",
    "subs": "subscriptions",
    "subscription": "subscriptions",
}

_NAME = re.compile(r"^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?\Z")
_SELECTOR = re.compile(r"^[A-Za-z0-9._/\-=!,() ]{1,512}\Z")
_FIELD_SELECTOR = re.compile(r"^[A-Za-z0-9._/\-=!,]{1,512}\Z")
_CONTAINER = re.compile(r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?\Z")

_LOG_REDACTIONS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)(authorization:\s*bearer\s+)[A-Za-z0-9._~+/=-]+"), r"\1***"),
    (re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), "***JWT***"),
    (re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"), "***aws-key-id***"),
    (
        re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)(\"?\s*[:=]\s*\"?)[^\s\"',;]+"),
        r"\1\2***",
    ),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"), "***PRIVATE KEY***"),
    (re.compile(r"(?i)(://[^:/\s]+:)[^@/\s]+@"), r"\1***@"),
    (re.compile(r"\bhv[sbr]\.[A-Za-z0-9_-]{20,}"), "***vault-token***"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}"), "***github-token***"),
    (re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}"), "***slack-token***"),
    # The flag-name prefix is bounded: unbounded, a long "a-a-a-..." token made this quadratic (minutes per 200 KB).
    (
        re.compile(r"(?i)(--?[a-z0-9_.-]{0,64}(?:password|passwd|secret|token|api[-_]?key)[=\s]+)[^\s\"',;]+"),
        r"\1***",
    ),
]


_BARE_SECRET_FLAG = re.compile(r"(?i)^--?[a-z0-9_.-]*(?:password|passwd|secret|token|api[-_]?key)$")


def redact_text(text: str) -> str:
    for pat, repl in _LOG_REDACTIONS:
        text = pat.sub(repl, text)
    return text


def _element_kind(kind: Any) -> str | None:
    if isinstance(kind, str) and kind.endswith("List") and kind != "List":
        return kind[: -len("List")]
    return kind if isinstance(kind, str) else None


def _kind_for(plural: str) -> str | None:
    return {"configmaps": "ConfigMap"}.get(plural)


def _redact_obj(obj: Any, kind_hint: str | None = None) -> Any:
    """Redact everything that could carry a credential before it reaches a model: ConfigMap payloads, sensitive env
    values and annotations, last-applied configs, and credential-looking substrings in every other string."""
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        own = obj.get("kind")
        # A resource-derived hint wins over a generic or missing echo ("List" from kubectl, nothing on list items).
        kind = kind_hint if (kind_hint and own in (None, "", "List")) else (own if isinstance(own, str) else kind_hint)
        for k, v in obj.items():
            if k == "managedFields":
                continue
            if kind == "ConfigMap" and k in {"data", "binaryData"} and isinstance(v, dict):
                out[k] = {key: f"<redacted {len(str(val))} bytes>" for key, val in v.items()}
                continue
            if k == "annotations" and isinstance(v, dict):
                out[k] = {
                    ak: (
                        "<redacted>"
                        if "last-applied-configuration" in ak or SENSITIVE_ENV.search(str(ak))
                        else redact_text(av)
                        if isinstance(av, str)
                        else av
                    )
                    for ak, av in v.items()
                }
                continue
            if k == "env" and isinstance(v, list):
                out[k] = [
                    {**e, "value": "***"}
                    if isinstance(e, dict) and "value" in e and SENSITIVE_ENV.search(str(e.get("name", "")))
                    else _redact_obj(e, kind)
                    for e in v
                ]
                continue
            # API-server lists ("ConfigMapList") omit kind on each item: carry the element kind down explicitly.
            out[k] = _redact_obj(v, _element_kind(kind) if k == "items" else kind)
        return out
    if isinstance(obj, list):
        out_list = [_redact_obj(x, kind_hint) for x in obj]
        # argv style ["--token", "abc"]: the value follows a bare secret flag
        for i in range(len(out_list) - 1):
            if (
                isinstance(out_list[i], str)
                and isinstance(out_list[i + 1], str)
                and _BARE_SECRET_FLAG.match(out_list[i])
            ):
                out_list[i + 1] = "***"
        return out_list
    if isinstance(obj, str):
        return redact_text(obj)
    return obj


def _list_hint(data: Any, plural: str) -> str | None:
    """Kind hint from the requested resource, so redaction never depends on the server echoing ``kind``."""
    kind = _kind_for(plural)
    if kind and isinstance(data, dict) and "items" in data:
        return f"{kind}List"
    return kind


def resolve_resource(resource: str) -> tuple[str, ResourceDef]:
    r = resource.strip().lower()
    if r in {"secret", "secrets"}:
        raise ClusterAccessError("Reading Secrets is not permitted by kube-noob's read-only guard.")
    r = ALIASES.get(r, r)
    if r not in ALLOWED_RESOURCES:
        raise ClusterAccessError(
            f"Resource '{resource}' is not in the read-only allowlist: {', '.join(sorted(ALLOWED_RESOURCES))}"
        )
    return r, ALLOWED_RESOURCES[r]


#: What a failed read says about the thing it tried to read. Only the first two are facts about the cluster:
#: ``not-served`` (this API resource does not exist on this cluster) and ``not-found`` (a named object does not
#: exist, possible only when a name was asked for). ``forbidden`` and ``not-read`` are a read that failed, and
#: neither may be taken as absence.
ReadFailure = Literal["not-served", "not-found", "forbidden", "not-read"]

#: API groups on the allowlist that an AGGREGATED API server answers for (OpenShift's openshift-apiserver serves
#: routes and DeploymentConfigs). With aggregated discovery, client-go v1.35.0 caches a group-version whose
#: discovery failed without logging it (discovery/cached/memory/memcache.go) and the REST mapper drops the partial
#: error (restmapper/discovery.go), so for these kubectl's bare "doesn't have a resource type" can mean "that API
#: server is down". The classifier never calls a resource in one of these groups absent; a test fails if one is
#: added to the list of resources whose absence is acted on. Every group that IS acted on is CRD-backed.
AGGREGATED_GROUPS = frozenset({"route.openshift.io", "apps.openshift.io", "metrics.k8s.io"})


class BackendReadError(ClusterAccessError):
    """A read the backend tried and that failed, carrying what the classifier needs beside the shown message: the
    whole (redacted) stderr of kubectl/oc, or the HTTP status and body the in-cluster client received. The message
    is cut for display; the classifier reads these, so a warning past the cut still counts."""

    def __init__(self, message: str, *, stderr: str | None = None, status: int | None = None, body: str = "") -> None:
        super().__init__(message)
        self.stderr = stderr
        self.status = status
        self.body = body


# kubectl and oc, when discovery does not list the resource. cli-runtime v1.35.0
# staging/src/k8s.io/cli-runtime/pkg/resource/builder.go, mappingFor:
#   fmt.Errorf("the server doesn't have a resource type %q", groupResource.Resource)
# (the resource is the plural alone, quoted; kubectl's checkErr prefixes "error: "). Matched as a WHOLE LINE of
# kubectl's own stderr, never inside other text: a server error body that happens to quote these words is not it.
_NOT_SERVED_LINE = '^(?:error: )?the server (?:doesn\'t|does not) have a resource type "{resource}(?:\\.{group})?"\\Z'
# kubectl for a named object: apimachinery v1.35.0 pkg/api/errors/errors.go NewNotFound,
#   fmt.Sprintf("%s %q not found", qualifiedResource.String(), name)
# printed by kubectl/pkg/cmd/util/helpers.go StandardErrorMessage as "Error from server (%s): %s".
_OBJECT_NOT_FOUND_LINE = '^Error from server \\(NotFound\\): {qualified} "{name}" not found\\Z'
# The same function prints a 403 as "Error from server (Forbidden): <resource> is forbidden: User ..."; the API
# server's own wording, "<resource> is forbidden: ", is accepted at the start of a line too. A name kube-noob
# echoed (a workload called "forbidden") sits in the argv before "failed: " and is never looked at.
_FORBIDDEN_LINE = re.compile(r"^(?:Error from server \(Forbidden\): |[a-z0-9.-]+ is forbidden: |Forbidden by RBAC: )")
# client-go v1.35.0 discovery/cached/memory/memcache.go: a group whose discovery failed is logged as
#   "couldn't get resource list for %v: %v" (and the whole list as "couldn't get current server API group list").
# When it is THIS resource's group, the "doesn't have a resource type" that follows is discovery failing, not
# the API being absent. Another group failing -- an aggregated metrics API that is down -- says nothing about it.
_DISCOVERY_FAILED = "couldn't get resource list for {group}/"
_NO_GROUP_LIST = "couldn't get current server API group list"
_KLOG = re.compile(r"^[EWIF]\d{4} [\d:.]+\s+\d+ [\w.-]+:\d+\] ")
# KubectlBackend's shown message is "<binary> get <up to three arguments> failed: <stderr>"; the argument part
# echoes names the caller chose and is never classified.
_WRAPPER = re.compile(r"^\S+ get [^:\n]*? failed: ")


def _stderr_lines(failure: str | BaseException) -> list[str] | None:
    """kubectl's own stderr, one stripped line each, or None for a message that is not kubectl's."""
    text = getattr(failure, "stderr", None)
    if text is None:
        text = str(failure)
    lines = []
    for raw in str(text).splitlines():
        line = _KLOG.sub("", raw.strip())
        for _ in range(3):  # a wrapper around a wrapper (a caller re-raising with its own prefix)
            line = _WRAPPER.sub("", line)
        if line:
            lines.append(line)
    return lines


def classify_read_failure(resource: str, failure: str | BaseException, name: str | None = None) -> ReadFailure:
    """Say what a backend's failed read means, recognising absence only in the exact words a backend uses for it.

    Pass the exception itself where there is one: it carries the full stderr (kubectl/oc) or the HTTP status and
    body (in-cluster), and the shown message is cut at 800 characters. ``not-served`` is kubectl/oc's "the server
    doesn't have a resource type" for THIS resource as a whole line, or the in-cluster client's 404 with the API
    server's plain-text body for a path no API serves. ``not-found`` is apimachinery's NotFound for THIS named
    object, or an in-cluster 404 whose Status names it. Anything else -- an auth plugin "not found" on PATH, a
    proxy's 404, "the server could not find the requested resource" with no resource named, a namespace that does
    not exist, a 500 whose body quotes kubectl -- is ``not-read``. A forbidden read is ``forbidden`` (RBAC is
    checked before the API server routes the request, so a 403 can hide an API that is not there just as well as
    one that is), recognised in the backend's own line, never in a name kube-noob echoed.

    Limitation: a resource in an :data:`AGGREGATED_GROUPS` group is never ``not-served``, because aggregated
    discovery can hide that group's failure from kubectl entirely.
    """
    try:
        plural, rdef = resolve_resource(resource)
    except ClusterAccessError:
        return "not-read"
    group = rdef.group_version.split("/")[0] if "/" in rdef.group_version else ""
    aggregated = group in AGGREGATED_GROUPS
    status = getattr(failure, "status", None)
    if isinstance(status, int):  # the in-cluster client: decided by the status it received, not by text
        if status == 403:
            return "forbidden"
        if status != 404 or aggregated:
            return "not-read"
        body = str(getattr(failure, "body", "") or "")
        # The API server answers a path no installed API serves with exactly Go's http.NotFound body, "404 page not
        # found". Anything else -- a proxy's HTML page, an ingress "default backend - 404", an empty body, a Status
        # cut short -- is a read that failed, not an absent API (G279).
        if body.rstrip("\n") == "404 page not found":
            return "not-served"
        if name and body.lstrip().startswith("{"):
            try:
                from kube_noob.sanitize import loads_bounded

                parsed = loads_bounded(body)
            except ValueError:
                parsed = None
            if isinstance(parsed, dict):
                details = parsed.get("details")
                named = details.get("name") if isinstance(details, dict) else None
                if parsed.get("kind") == "Status" and parsed.get("reason") == "NotFound" and named == name:
                    return "not-found"
        return "not-read"
    message = str(failure).strip()
    if getattr(failure, "stderr", None) is None and message.startswith("Not found: GET "):
        # the in-cluster backend's legacy text, matched whole against this resource's own path
        base = "/api/v1" if rdef.group_version == "v1" else f"/apis/{rdef.group_version}"
        ns = r"(?:/namespaces/[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?)?"
        path = f"^Not found: GET {re.escape(base)}{ns}/{re.escape(plural)}"
        if name is None:
            return "not-served" if re.match(path + r"\Z", message) and not aggregated else "not-read"
        return "not-found" if re.match(path + f"/{re.escape(name)}\\Z", message) else "not-read"
    if message.startswith("API error "):
        return "not-read"
    lines = _stderr_lines(failure) or []
    if any(_FORBIDDEN_LINE.match(line) for line in lines):
        return "forbidden"
    if group and any(_DISCOVERY_FAILED.format(group=group) in line for line in lines):
        return "not-read"
    if any(_NO_GROUP_LIST in line for line in lines):
        return "not-read"
    not_served = re.compile(_NOT_SERVED_LINE.format(resource=re.escape(plural), group=re.escape(group)))
    served_absent = not aggregated and any(not_served.match(line) for line in lines)
    if name is None:
        return "not-served" if served_absent else "not-read"
    qualified = f"{plural}.{group}" if group else plural
    obj = re.compile(_OBJECT_NOT_FOUND_LINE.format(qualified=re.escape(qualified), name=re.escape(name)))
    if any(obj.match(line) for line in lines):
        return "not-found"
    return "not-served" if served_absent else "not-read"


def _names_kind(kind: str, plural: str) -> bool:
    """Whether ``kind`` (``NetworkPolicy``) is the kind of ``plural`` (``networkpolicies``)."""
    k = kind.lower()
    return plural in {k, k + "s", k + "es", (k[:-1] + "ies") if k.endswith("y") else k}


def list_items(data: Any, resource: str, namespace: str | None = None) -> list[dict[str, Any]]:
    """The ``items`` of a COMPLETE list of ``resource``, or a failed read (G279).

    Not a list of that resource: a response without an ``items`` list, items that are not objects, a ``kind``
    other than ``List`` or ``<Kind>List`` (a ``Status`` with ``items``, a PodList for NetworkPolicies), an item of
    another kind, an item without ``metadata.name``, a namespaced item without a namespace or in another namespace
    than the one asked for, or a page with ``metadata.continue`` set (the rest was never read). Each of these was
    read as "nothing there", or as a list missing exactly the item that decided the answer. A response with no
    ``kind`` at all is refused too: kubectl, oc and the API server always send one."""
    items = data.get("items") if isinstance(data, dict) else None
    if not isinstance(items, list):
        raise ClusterAccessError(f"{resource}: the response held no items list")
    bad = sum(1 for i in items if not isinstance(i, dict))
    if bad:
        raise ClusterAccessError(f"{resource}: the response held {bad} item(s) that are not objects")
    try:
        plural, rdef = resolve_resource(resource)
        namespaced = rdef.namespaced
    except ClusterAccessError:
        plural, namespaced = resource, False
    kind = data.get("kind")
    if kind is None:
        # kubectl, oc and the API server always name a list's kind; an answer without one came from somewhere else
        # (a misrouted endpoint, a proxy's own JSON), and `{"items": []}` from it is not "none exist" (third review).
        raise ClusterAccessError(f"{resource}: the response has no kind, so it is not a list of {plural}")
    if kind != "List" and not (
        isinstance(kind, str) and kind.endswith("List") and _names_kind(kind[: -len("List")], plural)
    ):
        raise ClusterAccessError(f"{resource}: the response was a {str(kind)[:60]!r}, not a list of {plural}")
    meta = data.get("metadata")
    if isinstance(meta, dict) and meta.get("continue"):
        raise ClusterAccessError(f"{resource}: the response was one page of several (metadata.continue is set)")
    for item in items:
        ikind = item.get("kind")
        if ikind is not None and not (isinstance(ikind, str) and _names_kind(ikind, plural)):
            raise ClusterAccessError(f"{resource}: the list held a {str(ikind)[:60]!r}")
        imeta = item.get("metadata")
        if not isinstance(imeta, dict) or not isinstance(imeta.get("name"), str) or not imeta.get("name"):
            raise ClusterAccessError(f"{resource}: the list held an item without metadata.name")
        if namespaced:
            ins = imeta.get("namespace")
            if not isinstance(ins, str) or not ins or (namespace is not None and ins != namespace):
                where = f"namespace {namespace}" if namespace else "the namespaces listed"
                raise ClusterAccessError(f"{resource}: the list for {where} held an item from {ins!r}")
    return items


def read(backend: Any, resource: str, **kwargs: Any) -> Any:
    """``backend.get``, with an answer that could not be decoded reported as the failed read it is, naming the
    resource, rather than escaping as a bare ``JSONDecodeError`` or ``UnicodeDecodeError``."""
    try:
        return backend.get(resource, **kwargs)
    except ClusterAccessError:
        raise
    except (ValueError, UnicodeError) as exc:  # JSONDecodeError is a ValueError
        raise BackendReadError(f"{resource}: the response could not be read ({type(exc).__name__})") from exc


def read_object(backend: Any, resource: str, kind: str, name: str, namespace: str | None = None) -> dict[str, Any]:
    """One named object, or a failed read: a body that is not that object -- ``{}``, a ``Status``, a list,
    another object's name -- is not the object, and is not its absence either."""
    data = read(backend, resource, name=name, namespace=namespace)
    meta = data.get("metadata") if isinstance(data, dict) else None
    if (
        not isinstance(data, dict)
        or data.get("kind") not in (None, kind)
        or not isinstance(meta, dict)
        or meta.get("name") != name
    ):
        raise BackendReadError(f"{resource} {name}: the response was not that {kind}")
    return data


def _check(value: str | None, pattern: re.Pattern[str], what: str) -> None:
    if value is not None and not pattern.match(value):
        raise ClusterAccessError(f"Invalid {what}: {value!r}")


class Backend(Protocol):
    name: str

    def get(
        self,
        resource: str,
        name: str | None = None,
        namespace: str | None = None,
        selector: str | None = None,
        field_selector: str | None = None,
    ) -> dict[str, Any]: ...

    def logs(self, namespace: str, pod: str, container: str | None, tail: int, previous: bool) -> str: ...

    def version(self) -> dict[str, Any]: ...


def get_backend(settings: Settings) -> Backend:
    if not settings.cluster.enabled:
        raise ClusterAccessError(
            "Live cluster access is disabled. Set `cluster.enabled: true` in kube-noob.yaml "
            "or KUBE_NOOB_CLUSTER_ENABLED=true (read-only; Secrets are never read)."
        )
    try:
        from kube_noob.debug.backends import select_backend
    except ImportError as exc:  # the Claude plugin build ships without cluster access
        raise ClusterAccessError(
            "Live cluster access is not part of this build (the Claude plugin). Use the kube-noob CLI or the "
            "in-cluster service for read-only cluster checks."
        ) from exc
    return select_backend(settings)


def _k8s_minor(server: dict[str, Any]) -> str | None:
    major, minor = str(server.get("major", "")), str(server.get("minor", "")).rstrip("+")
    if major.isdigit() and minor.isdigit():
        return f"{major}.{minor}"
    m = re.match(r"v?(\d+)\.(\d+)", str(server.get("gitVersion", "")))
    return f"{m.group(1)}.{m.group(2)}" if m else None


def cluster_info(backend: Backend) -> dict[str, Any]:
    """Versions of the live cluster (read-only), and whether they are newer than kube-noob's knowledge."""
    from kube_noob.knowledge_status import compare

    raw = backend.version()
    server = raw.get("serverVersion") or {}
    out: dict[str, Any] = {
        "backend": backend.name,
        "kubernetes": _k8s_minor(server),
        "serverGitVersion": server.get("gitVersion"),
        "openshift": None,
        "channel": None,
    }
    not_read = ""
    try:
        cv: Any = read(backend, "clusterversions", name="version")
    except (ClusterAccessError, KubeNoobError) as exc:
        cv = {}
        # Only the API not serving ClusterVersion is "not OpenShift". Forbidden, any other failed read, and even
        # NotFound for the object on a served CRD are not "Kubernetes": a ServiceAccount that may not read
        # ClusterVersion is the usual shape on OpenShift itself (G279).
        if classify_read_failure("clusterversions", exc, name="version") != "not-served":
            not_read = f"ClusterVersion could not be read ({str(exc)[:300]}), so whether this is OpenShift is not known"
    else:
        status = cv.get("status") if isinstance(cv, dict) else None
        desired = status.get("desired") if isinstance(status, dict) else None
        version = desired.get("version") if isinstance(desired, dict) else None
        if isinstance(cv, dict) and cv.get("kind") in (None, "ClusterVersion") and isinstance(version, str) and version:
            out["openshift"] = version
            spec = cv.get("spec")
            out["channel"] = spec.get("channel") if isinstance(spec, dict) else None
        else:
            # `{}`, a Status, a list: an answer, but not a ClusterVersion, so not "Kubernetes" either
            not_read = (
                "ClusterVersion could not be read (the response held no ClusterVersion), so whether this is "
                "OpenShift is not known"
            )
    if out["openshift"]:
        out["platform"] = "openshift"
    elif not_read:
        out["platform"] = None
        out["platformNotRead"] = not_read
    else:
        out["platform"] = "kubernetes"
    out.update(compare(out["kubernetes"], out["openshift"]))
    return out
