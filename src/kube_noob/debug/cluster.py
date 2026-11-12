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
from typing import Any, Protocol

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
}

_NAME = re.compile(r"^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?\Z")
_SELECTOR = re.compile(r"^[A-Za-z0-9._/\-=!,() ]{1,512}\Z")
_FIELD_SELECTOR = re.compile(r"^[A-Za-z0-9._/\-=!,]{1,512}\Z")
_CONTAINER = re.compile(r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?\Z")

_LOG_REDACTIONS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)(authorization:\s*bearer\s+)[A-Za-z0-9._~+/=-]+"), r"\1***"),
    # Basic credentials are base64 of user:password, so the value is the password (G274).
    (re.compile(r"(?i)(authorization:\s*basic\s+)[A-Za-z0-9+/=]+"), r"\1***"),
    # A key named by a word and a space rather than `=`: "apikey sk-live-..." (G274).
    (re.compile(r"(?i)\b(api[_-]?key|access[_-]?key)(\s+)[^\s\"',;]{8,}"), r"\1\2***"),
    (re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), "***JWT***"),
    (re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"), "***aws-key-id***"),
    (
        re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)(\"?\s*[:=]\s*\"?)[^\s\"',;]+"),
        r"\1\2***",
    ),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"), "***PRIVATE KEY***"),
    # A key with no END line -- cut by a length limit or pasted in part -- is still a key: everything after BEGIN goes.
    # Complete keys were replaced by the line above, so any BEGIN left here has no END after it.
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*"), "***PRIVATE KEY (cut)***"),
    # Stripe-style live and test keys, which travel without a name in front of them.
    (re.compile(r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{10,}|\b[rs]k-(?:live|test)-[A-Za-z0-9]{10,}"), "***api-key***"),
    (re.compile(r"(?i)(://[^:/\s]+:)[^@/\s]+@"), r"\1***@"),
    (re.compile(r"\bhv[sbr]\.[A-Za-z0-9_-]{20,}"), "***vault-token***"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}"), "***github-token***"),
    (re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}"), "***slack-token***"),
]

# A secret passed as a flag (`--db-password=x`, `--api-key x`). Run through `_sub_flags`, never as a plain `sub`: the
# flag-name prefix is bounded (unbounded, a long "a-a-a-..." token made this quadratic, minutes per 200 KB), but even
# bounded the engine tried it at every dash, about 400 steps each, so a run of 2,000 dashes cost 20 ms and an
# in-bounds Alertmanager payload of them a minute (G274). The text it rewrites is exactly what `sub` rewrote.
_FLAG_SECRET = re.compile(r"(?i)(--?[a-z0-9_.-]{0,64}(?:password|passwd|secret|token|api[-_]?key)[=\s]+)[^\s\"',;]+")
#: A keyword followed by what `_FLAG_SECRET` needs after it. Every match of `_FLAG_SECRET` contains one, starting at
#: most 66 characters after the match does (`--` plus the 64-character prefix), so only those windows are tried.
_FLAG_KEYWORD = re.compile(r"(?i)(?:password|passwd|secret|token|api[-_]?key)[=\s]+[^\s\"',;]")
_FLAG_REACH = 66


def _sub_flags(text: str) -> str:
    """``_FLAG_SECRET.sub(r"\\1***", text)``, in time linear in the text: a match can only start at a dash within
    ``_FLAG_REACH`` characters before a keyword that is followed by a value, so the positions tried are those, each
    at most once and in increasing order -- which is the leftmost-first order ``sub`` itself uses."""
    out: list[str] = []
    cursor = 0  # text before this is already in `out`
    tried = 0  # positions below this were tried and start no match
    while True:
        found = None
        for kw in _FLAG_KEYWORD.finditer(text, cursor):
            for start in range(max(cursor, tried, kw.start() - _FLAG_REACH), kw.start()):
                if text[start] == "-" and (found := _FLAG_SECRET.match(text, start)) is not None:
                    break
            if found is not None:
                break
            tried = max(tried, kw.start())
        if found is None:
            out.append(text[cursor:])
            return "".join(out)
        out.append(text[cursor : found.start()])
        out.append(found.expand(r"\1***"))
        cursor = tried = found.end()


_BARE_SECRET_FLAG = re.compile(r"(?i)^--?[a-z0-9_.-]*(?:password|passwd|secret|token|api[-_]?key)$")


def redact_text(text: str) -> str:
    for pat, repl in _LOG_REDACTIONS:
        text = pat.sub(repl, text)
    return _sub_flags(text)


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
    try:
        cv = backend.get("clusterversions", name="version")
    except (ClusterAccessError, KubeNoobError):
        cv = {}  # not OpenShift, or the ServiceAccount may not read ClusterVersion
    desired = (cv.get("status") or {}).get("desired") or {}
    if desired.get("version"):
        out["openshift"] = desired["version"]
        out["channel"] = (cv.get("spec") or {}).get("channel")
    out["platform"] = "openshift" if out["openshift"] else "kubernetes"
    out.update(compare(out["kubernetes"], out["openshift"]))
    return out
