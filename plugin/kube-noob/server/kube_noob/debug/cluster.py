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
    # Routing objects that put a Service on the network, for the attack-path scan and the blast radius (G273):
    # Gateway API HTTPRoute (gateway.networking.k8s.io/v1, served at v1 since Gateway API v1.0.0, 2023-10-31; older
    # installs serve only v1beta1, https://gateway-api.sigs.k8s.io/api-types/httproute/) and Istio VirtualService
    # (networking.istio.io/v1, served since Istio 1.22; older releases serve v1beta1/v1alpha3,
    # https://istio.io/latest/docs/reference/config/networking/virtual-service/). Namespaced. A route can set or
    # match header values, which may be credentials (`Authorization`, an API key): `_redact_obj` masks every value
    # under a header block. Any failed list -- a 404 included, since an older install serving another version
    # answers it too -- leaves the exposure not determined; kube-noob does not read API discovery.
    "httproutes": ResourceDef("gateway.networking.k8s.io/v1", "httproutes", True),
    # GRPCRoute: GA in the Standard channel at v1 since Gateway API v1.1.0 (https://gateway-api.sigs.k8s.io/api-types/grpcroute/).
    "grpcroutes": ResourceDef("gateway.networking.k8s.io/v1", "grpcroutes", True),
    "virtualservices": ResourceDef("networking.istio.io/v1", "virtualservices", True),
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


def _has_digit_and_letter(value: str) -> bool:
    return any(c.isdigit() for c in value) and any(c.isalpha() for c in value)


def _key_value(m: re.Match[str]) -> str:
    """A key named by a word and a space ("apikey sk-live-..."): redacted only when what follows looks like a key --
    16 characters or more, with letters and digits -- so "rotate the apikey whenever a teammate leaves" stays prose
    (G274)."""
    return m.group(1) + m.group(2) + "***" if _has_digit_and_letter(m.group(3)) else m.group(0)


def _basic(m: re.Match[str]) -> str:
    """``Authorization: Basic <base64 of user:password>``. The whole token goes or none of it ("s3cr3t-Value_9" was cut
    at its dash), and only a value that can be one: eight characters or more of the base64 alphabets, with a digit or
    both cases, so "Authorization: Basic realm missing" stays prose (G274)."""
    value = m.group(2)
    mixed = any(c.isupper() for c in value) and any(c.islower() for c in value)
    return m.group(1) + "***" if mixed or any(c.isdigit() for c in value) else m.group(0)


def _bearer(m: re.Match[str]) -> str:
    """A bearer token without the ``Authorization:`` header name in front (a curl line, a client log)."""
    return m.group(1) + "***" if _has_digit_and_letter(m.group(2)) else m.group(0)


#: Text that proves a credential name is followed by a reference to a Secret rather than its value: what `kubectl
#: describe` prints for an env var (`<set to the key 'password' in secret 'orders-db'>`), the same in words (`secret
#: 'orders-db' key 'password'`), and the manifest's `valueFrom:`/`secretKeyRef:`. A value that merely looks like
#: `<name>/<key>` is not proof: `password=prod-db/secret` is a password, and a third review's exemption for the shape
#: leaked it (G274). Over-redact rather than leak.
_REFERENCE_AHEAD = re.compile(r"(?i)<set to the key |(?:from )?(?:secret|config ?map) '[^']{1,253}' key '")


def _named_value(m: re.Match[str]) -> str:
    return m.group(0) if _REFERENCE_AHEAD.match(m.group(3)) else m.group(1) + m.group(2) + "***"


def _stripe(m: re.Match[str]) -> str:
    return "***api-key***" if _has_digit_and_letter(m.group(1)) else m.group(0)


#: Credential shapes, applied in this order by `redact_text` (with the private-key, token and flag scans between them).
#: Every pattern here is anchored on a literal or a word boundary and has no nested quantifier, so its cost is linear
#: in the text; the three shapes that a plain pattern made quadratic -- a private key, a JWT and a secret flag -- are
#: scanned by functions below instead.
_LOG_REDACTIONS: list[tuple[re.Pattern[str], Any]] = [
    (re.compile(r"(?i)(authorization:\s*bearer\s+)[A-Za-z0-9._~+/=-]+"), r"\1***"),
    (re.compile(r"(?i)(authorization:\s*basic\s+)([A-Za-z0-9+/_-]{8,}={0,2})(?![^\s\"',;])"), _basic),
    (re.compile(r"(?i)\b(api[_-]?key|access[_-]?key)(\s+)([^\s\"',;]{16,})"), _key_value),
]
_AFTER_JWT: list[tuple[re.Pattern[str], Any]] = [
    (re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"), "***aws-key-id***"),
    # A service-account key file's `"private_key": "-----BEGIN ...\n..."`: the key travels JSON-escaped, so the PEM scan
    # (which reads whitespace between lines, not a backslash and an n) would leave its body.
    # Unterminated too, up to the end of the line (a JSON string holds no raw newline): a key file cut short still
    # holds its key.
    (re.compile(r'(?i)("private[_-]?key"\s*:\s*")(?:[^"\\\n]|\\.)*+("?)'), r"\1***\2"),
    # `password=x`, `"token": "x"`, and the same keys with a prefix: `client_secret=`, `aws_secret_access_key=`,
    # `DB_PASSWORD=` (the prefix is at most four words, so a long `a-a-a-...` run costs a bounded amount per word).
    # Not a reference to a secret (`_REFERENCE_AHEAD`): `kubectl describe` prints `DB_PASSWORD: <set to the key
    # 'password' in secret 'orders-db'>`, which holds no value. The value is matched with the spaces a reference needs,
    # then `_named_value` keeps a reference and redacts the first token of anything else.
    (
        re.compile(
            r"(?i)\b((?:[a-z0-9]{1,32}[_-]){0,4}(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key))"
            r"(\"?\s*[:=]\s*\"?)((?:<set to the key [^>\n]{0,300}>|(?:from )?(?:secret|config ?map) '[^'\n]{1,253}' "
            r"key '[^'\n]{1,253}')|[^\s\"',;]+)"
        ),
        _named_value,
    ),
]
_AFTER_KEYS: list[tuple[re.Pattern[str], Any]] = [
    # Stripe-style live and test keys, which travel without a name in front of them: 24 characters or more with letters
    # and digits, so "sk_test_examplevalue1" and "sk-live-1234567890 is a placeholder" are left alone.
    (re.compile(r"\b[rs]k[_-](?:live|test)[_-]([A-Za-z0-9]{24,})"), _stripe),
    (re.compile(r"(?i)(://[^:/\s]+:)[^@/\s]+@"), r"\1***@"),
    (re.compile(r"\bhv[sbr]\.[A-Za-z0-9_-]{20,}"), "***vault-token***"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}"), "***github-token***"),
    (re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}"), "***slack-token***"),
    (re.compile(r"(?i)\b(bearer\s+)([A-Za-z0-9._~+/=-]{16,})"), _bearer),
]

# -- private keys ------------------------------------------------------------------------------------------------------
# `-----BEGIN ... PRIVATE KEY-----` up to the first END line after it is a key, as it always was. A BEGIN with no END
# after it -- a key cut by a length limit or pasted in part -- loses its base64 body and nothing else: the first
# version replaced everything after a lone BEGIN, so one log line quoting the header ("expected -----BEGIN RSA PRIVATE
# KEY----- in key.pem") deleted the rest of the log from every tool that redacts (G274). A header with no body after
# it is left as it is: it holds no key material.
_PEM_BEGIN = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_PEM_END = re.compile(r"-----END [A-Z ]*PRIVATE KEY-----")
#: The body of a cut key: optional RFC 1421 header lines, then base64 lines of 16 characters or more, then one shorter
#: last line when it ends its line. Lines are separated by whitespace, by JSON-escaped newlines (`\\n`), or by a newline
#: and the prefix a log line carries -- an RFC 3339 timestamp, a CRI `stdout F`, `kubectl logs --prefix`'s
#: `[pod/name/container]` -- and the first line may follow the header with nothing between (a key flattened onto one
#: line). Every separator and line is an atomic group or a possessive run, so the engine never re-splits what it has
#: matched and the cost is what it consumes (G274).
_PEM_NL = r"(?:\r?\n|\\r\\n|\\n)"
_PEM_PREFIX = (
    r"(?:[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9:.,]{8,18}(?:Z|[+-][0-9]{2}:?[0-9]{2})?[ \t]++"
    r"(?:std(?:out|err)[ \t]++[FP][ \t]++)?|\[[^\]\n]{1,253}\][ \t]++)"
)
_PEM_SEP = rf"(?>(?:[ \t]|{_PEM_NL})++)(?>{_PEM_PREFIX})?"
_PEM_LINE = r"[A-Za-z0-9+/]{16,}+={0,2}+"
_PEM_BODY = re.compile(
    r"(?:[ \t]*\r?\n(?:Proc-Type|DEK-Info):[^\n]{0,200})*"
    rf"(?P<lines>(?:{_PEM_SEP})?{_PEM_LINE}(?:{_PEM_SEP}{_PEM_LINE})*+)"
    rf"(?:{_PEM_SEP}[A-Za-z0-9+/]{{1,15}}+={{0,2}}+(?=[ \t]*(?:\r?\n|\\[rn]|[\"']|\Z)))?"
)
_PEM_FIRST = re.compile(r"[A-Za-z0-9+/]{16,}")


def _looks_like_base64(token: str) -> bool:
    """A line of key material, not a long word: it has a digit, a + or /, or both cases."""
    return any(c.isdigit() or c in "+/" for c in token) or (
        any(c.isupper() for c in token) and any(c.islower() for c in token)
    )


def _sub_private_keys(text: str) -> str:
    """Private keys replaced, in time linear in the text: each BEGIN is matched once where it starts, the END lines
    are found by a pointer that only moves forward, and a cut key's body is matched once where its header ends."""
    if "-----BEGIN " not in text:
        return text
    out: list[str] = []
    cursor = pos = 0
    end_from = 0  # END lines starting before this were looked at already
    end: re.Match[str] | None = None
    ends_left = True
    while (start := text.find("-----BEGIN ", pos)) >= 0:
        head = _PEM_BEGIN.match(text, start)
        if head is None:
            pos = start + 1
            continue
        # The first END starting at or after this header's end -- what the lazy `[\s\S]*?` of the old pattern found.
        while ends_left and (end is None or end.start() < head.end()):
            found = text.find("-----END ", max(end_from, head.end()))
            if found < 0:
                ends_left, end = False, None
                break
            end_from = found + 1
            end = _PEM_END.match(text, found)
        if ends_left and end is not None:
            out += [text[cursor:start], "***PRIVATE KEY***"]
            cursor = pos = end.end()
            end = None
            continue
        body = _PEM_BODY.match(text, head.end())
        first = _PEM_FIRST.search(body.group("lines")) if body is not None else None
        if body is not None and first is not None and _looks_like_base64(first.group(0)):
            out += [text[cursor:start], "***PRIVATE KEY (cut)***"]
            cursor = pos = body.end()
        else:
            pos = head.end()
    out.append(text[cursor:])
    return "".join(out)


# -- JWTs --------------------------------------------------------------------------------------------------------------
# `eyJ<8+>.<8+>.<8+>` over [A-Za-z0-9_-]. As a plain pattern the engine tried it at every `eyJ` and ran each attempt
# to the end of the run, so 8,000 characters of "eyJeyJ..." took 31 ms and 64,000 took 1.5 s, before any time budget
# (G274). The match is decided by whole runs, so it is found by looking at each run once.
_JWT_RUN = re.compile(r"[A-Za-z0-9_-]+")


def _sub_jwts(text: str) -> str:
    """``re.sub(r"eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}", "***JWT***", text)`` in linear time.
    The first segment runs greedily to the end of its run, so a match starts at the first ``eyJ`` of a run with at
    least eight characters after it, and the next two segments are the whole of the next two runs, each joined by
    exactly one dot and each eight characters or more."""
    if "eyJ" not in text:
        return text
    out: list[str] = []
    cursor = pos = 0
    while (start := text.find("eyJ", pos)) >= 0:
        run = _JWT_RUN.match(text, start)
        run_end = run.end() if run else start + 3
        if run_end - start - 3 >= 8 and text[run_end : run_end + 1] == ".":
            second = _JWT_RUN.match(text, run_end + 1)
            if second and second.end() - second.start() >= 8 and text[second.end() : second.end() + 1] == ".":
                third = _JWT_RUN.match(text, second.end() + 1)
                if third and third.end() - third.start() >= 8:
                    out += [text[cursor:start], "***JWT***"]
                    cursor = pos = third.end()
                    continue
        # No match starts anywhere in this run: every later `eyJ` in it has the same run end and less before it.
        pos = run_end
    out.append(text[cursor:])
    return "".join(out)


# A secret passed as a flag (`--db-password=x`, `--api-key x`, `--pwd x`). Run through `_sub_flags`, never as a plain
# `sub`: the flag-name prefix is bounded (unbounded, a long "a-a-a-..." token made this quadratic, minutes per 200 KB),
# but even bounded the engine tried it at every dash, about 400 steps each, so a run of 2,000 dashes cost 20 ms and an
# in-bounds Alertmanager payload of them a minute (G274). The text it rewrites is exactly what `sub` rewrote.
_FLAG_SECRET = re.compile(
    r"(?i)(--?[a-z0-9_.-]{0,64}(?:password|passwd|pwd|secret|token|api[-_]?key|access[-_]?key)[=\s]+)[^\s\"',;]+"
)
#: A keyword followed by what `_FLAG_SECRET` needs after it. Every match of `_FLAG_SECRET` contains one, starting at
#: most 66 characters after the match does (`--` plus the 64-character prefix), so only those windows are tried.
_FLAG_KEYWORD = re.compile(r"(?i)(?:password|passwd|pwd|secret|token|api[-_]?key|access[-_]?key)[=\s]+[^\s\"',;]")
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
    """Credential shapes replaced by ``***`` markers; ``PRIVACY.md`` lists them and the shapes this does not catch."""
    for pat, repl in _LOG_REDACTIONS:
        text = pat.sub(repl, text)
    text = _sub_jwts(text)
    for pat, repl in _AFTER_JWT:
        text = pat.sub(repl, text)
    text = _sub_private_keys(text)
    for pat, repl in _AFTER_KEYS:
        text = pat.sub(repl, text)
    return _sub_flags(text)


#: What `redact_text` applies, for the safety contract: how many credential shapes (the patterns plus the JWT, private
#: key and flag scans) and the markers a redaction leaves in place of a value.
REDACTION_SHAPES = len(_LOG_REDACTIONS) + len(_AFTER_JWT) + len(_AFTER_KEYS) + 3
REDACTION_MARKERS: tuple[str, ...] = tuple(
    sorted(
        {r for _, r in (*_LOG_REDACTIONS, *_AFTER_JWT, *_AFTER_KEYS) if isinstance(r, str) and r.startswith("***")}
        - {"***"}
        | {"***JWT***", "***PRIVATE KEY***", "***PRIVATE KEY (cut)***", "***api-key***"}
    )
)


def _element_kind(kind: Any) -> str | None:
    if isinstance(kind, str) and kind.endswith("List") and kind != "List":
        return kind[: -len("List")]
    return kind if isinstance(kind, str) else None


def _kind_for(plural: str) -> str | None:
    return {
        "configmaps": "ConfigMap",
        "httproutes": "HTTPRoute",
        "grpcroutes": "GRPCRoute",
        "virtualservices": "VirtualService",
        "routes": "Route",
        "ingresses": "Ingress",
    }.get(plural)


_ROUTING_KINDS = frozenset({"HTTPRoute", "GRPCRoute", "VirtualService"})
_HEADER_KEYS = frozenset(
    {"requestHeaderModifier", "responseHeaderModifier", "headers", "withoutHeaders", "queryParams"}
)
#: An nginx snippet that sets a credential header carries the credential itself (the fourth review; on main too).
_SNIPPET_CREDENTIAL = re.compile(
    r"(?:proxy_set_header|more_set_input_headers|more_set_headers|add_header|grpc_set_header)[^;]*"
    r"(?:authorization|cookie|x-api-key|api-key|token)"
    # nginx `set $var "<value>"` stores a value a later directive sends: the value may be the credential.
    r"|\bset\s+\$\w+\s+\S",
    re.IGNORECASE,
)
#: In an annotation value: an `Authorization`-style scheme and its credential, and a JSON field named like a secret
#: (the ALB `auth-idp-oidc` annotation carries `clientSecret`). Fifth review of G273.
_ANNOTATION_CREDENTIAL = re.compile(r"(?i)\b(basic|bearer)\s+[A-Za-z0-9._~+/=-]+")
_JSON_SECRET = re.compile(r"(?i)(\"[a-z_]*(?:secret|password|token|apikey|api_key)[a-z_]*\"\s*:\s*)\"[^\"]*\"")


def _mask_annotation(value: str) -> str:
    value = _ANNOTATION_CREDENTIAL.sub(lambda m: f"{m.group(1)} <redacted>", value)
    return _JSON_SECRET.sub(lambda m: f'{m.group(1)}"<redacted>"', value)


#: `user:password@` in a hostname or a URL a route rewrites to.
_USERINFO = re.compile(r"[^/@\s:]+:[^/@\s]+@")


def _mask_header_values(v: Any) -> Any:
    """Every string under a header block masked, except a header's `name` and a match `type`."""
    if isinstance(v, dict):
        return {
            k: (x if k in {"name", "type"} and isinstance(x, str) else _mask_header_values(x))
            for k, x in v.items()
            if k != "managedFields"
        }
    if isinstance(v, list):
        return [_mask_header_values(x) for x in v]
    if isinstance(v, str):
        return "<redacted>"
    return v


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
                        if "last-applied-configuration" in ak
                        or SENSITIVE_ENV.search(str(ak))
                        or (isinstance(av, str) and _SNIPPET_CREDENTIAL.search(av))
                        # haproxy-ingress sets a header from an annotation: its value is the header value.
                        or re.search(r"(?:^|\/)(?:request|response)-set-header$", str(ak)) is not None
                        else _mask_annotation(redact_text(av))
                        if isinstance(av, str)
                        else av
                    )
                    for ak, av in v.items()
                }
                continue
            if kind in _ROUTING_KINDS and k in _HEADER_KEYS:
                # A route can set or match a header value -- `Authorization: Basic ...`, an `x-api-key` -- in Gateway
                # API filters (requestHeaderModifier/responseHeaderModifier set/add, matches[].headers) and Istio
                # (headers.request/response set/add, match headers). Every value under them is masked; header names
                # stay (third review of G273: cluster_get returned them in clear).
                out[k] = _mask_header_values(v)
                continue
            if kind == "Route" and k == "httpHeaders":
                # OpenShift Route header actions set a header's value (`Authorization: Bearer ...`) at the router
                # (spec.httpHeaders.actions.request|response[].action.set.value); masked the same way (on main too).
                out[k] = _mask_header_values(v)
                continue
            if kind in _ROUTING_KINDS and isinstance(v, str) and _USERINFO.search(v):
                out[k] = _USERINFO.sub("<redacted>@", v)  # a redirect hostname or rewrite URL with user:password@
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


def classify_read_failure(
    resource: str,
    failure: str | BaseException,
    name: str | None = None,
    *,
    group: str | None = None,
    version: str | None = None,
    _aggregated_can_be_absent: bool = False,
) -> ReadFailure:
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

    ``group`` and ``version``, when given, name the API the caller asked about (the ClusterVersion read is
    ``config.openshift.io/v1``, R5): they must be the ones the resource is read under, or nothing is decided --
    a caller asking about one API never gets an answer about another.

    Limitation: a resource in an :data:`AGGREGATED_GROUPS` group is never ``not-served``, because aggregated
    discovery can hide that group's failure from kubectl entirely.
    """
    try:
        plural, rdef = resolve_resource(resource)
    except ClusterAccessError:
        return "not-read"
    own_group, _, own_version = rdef.group_version.rpartition("/")
    if (group is not None and group != own_group) or (version is not None and version != own_version):
        return "not-read"
    group = own_group
    aggregated = group in AGGREGATED_GROUPS and not _aggregated_can_be_absent
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


def says_not_served(
    resource: str, failure: str | BaseException, *, group: str | None = None, version: str | None = None
) -> bool:
    """Whether the backend's OWN WORDS say the cluster serves no such resource type: what `classify_read_failure`
    calls ``not-served``, and the same words for a resource in an :data:`AGGREGATED_GROUPS` group, which the
    classifier refuses to call absent because there they can also mean that API server is down.

    For one decision only: whether a gate fails on a failed list because the read was REFUSED (a 403, a timeout, a
    response that is not a list) rather than ANSWERED (``posture scan --fail-above``, G276). The verdict is not
    decided here -- a list the cluster did not answer stays not read and what depends on it not determined, for an
    aggregated group and a CRD alike (G279) -- so nothing that acts on absence may call this."""
    return (
        classify_read_failure(resource, failure, group=group, version=version, _aggregated_can_be_absent=True)
        == "not-served"
    )


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
