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
