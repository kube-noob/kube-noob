"""Admission policies generated from kube-noob's audit rules (requirements R3.1, R3.6).

``generate`` turns every rule that can be decided from one object at admission into a ValidatingAdmissionPolicy with
its binding (``admissionregistration.k8s.io/v1``, GA since Kubernetes 1.30, so every supported OpenShift 4.20+) and/or
a Kyverno ValidatingPolicy (``policies.kyverno.io/v1``, Kyverno 1.18+; Kyverno 1.19 deprecates ClusterPolicy and 1.20
removes it: https://kyverno.io/docs/policy-types/overview/). Both carry the same CEL, so one test proves both.

Every policy says which rule it enforces: the name (``kube-noob-kn-s001``), the message (``[KN-S001] title. Fix: ...
Source: ...``) and annotations (rule, severity, fix, source, coverage, limitation). Rules that need more than one object
(a Service and the pods it selects), that the API server already refuses on its own (invalid names, request above
limit), or that do not belong at admission (every Secret carries its data in the cluster) are not generated; each
has a stated reason in ``NOT_GENERATED``.

Semantics, on purpose the same as ``kube-noob audit`` on that one object: a policy fails exactly the objects the
audit reports for that rule at low severity or above (an informational note is not a failure). ``coverage: partial``
marks the few that check less than the audit (named in ``limitation``); none checks more.

Exemptions, written into every policy: namespaces kube-system, kube-public and kube-node-lease (plus any passed
with ``exclude_namespaces``) via ``matchConstraints.namespaceSelector``; on the OpenShift family also ``openshift`` and
``openshift-*`` namespaces and requests from ``system:serviceaccount:openshift-*`` (the platform's operators). Rules
of the calibrate stage (probes, resources, replicas, spread, grace period) skip objects a controller owns, so a
ReplicaSet scaled down by its Deployment is never blocked; security rules never skip them. RBAC rules skip
``system:`` names.

Modes: ``audit`` warns and records (VAP binding ``[Warn, Audit]``, ``failurePolicy: Ignore``); ``enforce`` refuses
(``[Deny]``, ``failurePolicy: Fail``). Kyverno policies run at admission only (background scans off), because the
exemptions read the request.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

import yaml

from kube_noob import __version__
from kube_noob.audit.exceptions import Checked
from kube_noob.audit.rules import (
    COMMAND_META,
    CONFIGMAP_CREDENTIAL_KEY,
    CONFIGMAP_CREDENTIAL_LINE,
    CREDENTIAL_FLAG_NAME,
    CSI_SUBDIR_TRAVERSAL,
    EMBEDDED_CREDENTIAL,
    ESCALATION_VERBS,
    EVERYONE_SUBJECTS,
    INGRESS_NGINX_ANNOTATION_PREFIX,
    INGRESS_NGINX_CLASS,
    INGRESS_NGINX_CONFIGMAP_KEYS,
    INGRESS_NGINX_RISKY_ANNOTATIONS,
    INTERNAL_LB_ANNOTATIONS,
    PATH_TRAVERSAL,
    RBAC_DEFAULTS_LABEL,
    RULES,
    SENSITIVE_ENV,
    WORKLOAD_RESOURCES,
    Rule,
    ingress_nginx_vulnerable_tag_regex,
)
from kube_noob.catalog import OPENSHIFT_FAMILY, PROVISIONERS, ROSA_FAMILY, SOURCES, parse_minor

Engine = Literal["vap", "kyverno"]
Mode = Literal["audit", "enforce"]
ENGINES: tuple[Engine, ...] = ("vap", "kyverno")
MODES: tuple[Mode, ...] = ("audit", "enforce")
DEFAULT_EXCLUDED_NAMESPACES = ("kube-system", "kube-public", "kube-node-lease")
MAX_EXCLUDED_NAMESPACES = 50
PREFIX = "kube-noob-"


@dataclass(frozen=True)
class Target:
    """A kind the policy matches, as admission sees it (group, version, plural resource)."""

    kind: str
    group: str
    version: str
    resource: str
    namespaced: bool = True


TARGETS: dict[str, Target] = {
    t.kind: t
    for t in (
        Target("Pod", "", "v1", "pods"),
        Target("Deployment", "apps", "v1", "deployments"),
        Target("StatefulSet", "apps", "v1", "statefulsets"),
        Target("DaemonSet", "apps", "v1", "daemonsets"),
        Target("ReplicaSet", "apps", "v1", "replicasets"),
        Target("ReplicationController", "", "v1", "replicationcontrollers"),
        Target("Job", "batch", "v1", "jobs"),
        Target("CronJob", "batch", "v1", "cronjobs"),
        Target("DeploymentConfig", "apps.openshift.io", "v1", "deploymentconfigs"),
        Target("Role", "rbac.authorization.k8s.io", "v1", "roles"),
        Target("ClusterRole", "rbac.authorization.k8s.io", "v1", "clusterroles", namespaced=False),
        Target("RoleBinding", "rbac.authorization.k8s.io", "v1", "rolebindings"),
        Target("ClusterRoleBinding", "rbac.authorization.k8s.io", "v1", "clusterrolebindings", namespaced=False),
        Target(
            "SecurityContextConstraints",
            "security.openshift.io",
            "v1",
            "securitycontextconstraints",
            namespaced=False,
        ),
        Target("Route", "route.openshift.io", "v1", "routes"),
        Target("Ingress", "networking.k8s.io", "v1", "ingresses"),
        Target("Service", "", "v1", "services"),
        Target("ConfigMap", "", "v1", "configmaps"),
        Target("Secret", "", "v1", "secrets"),
        Target("PersistentVolume", "", "v1", "persistentvolumes", namespaced=False),
        Target("EgressFirewall", "k8s.ovn.org", "v1", "egressfirewalls"),
        Target("NetworkPolicy", "networking.k8s.io", "v1", "networkpolicies"),
        Target("StorageClass", "storage.k8s.io", "v1", "storageclasses", namespaced=False),
        Target("PodDisruptionBudget", "policy", "v1", "poddisruptionbudgets"),
        Target("MachineConfig", "machineconfiguration.openshift.io", "v1", "machineconfigs", namespaced=False),
        Target("MachineConfigPool", "machineconfiguration.openshift.io", "v1", "machineconfigpools", namespaced=False),
        Target("APIService", "apiregistration.k8s.io", "v1", "apiservices", namespaced=False),
    )
}
OPENSHIFT_GROUPS = frozenset(
    {
        "apps.openshift.io",
        "route.openshift.io",
        "security.openshift.io",
        "k8s.ovn.org",
        "machineconfiguration.openshift.io",
    }
)
_POD_KINDS = ("Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "ReplicationController", "Job", "CronJob")
_LONG_RUNNING = ("Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "DeploymentConfig")
_REPLICATED = ("Deployment", "StatefulSet", "ReplicaSet", "DeploymentConfig")

# Variables every pod-spec policy declares (the template of each workload kind; CronJob one level deeper).
POD_VARIABLES: tuple[tuple[str, str], ...] = (
    (
        "podSpec",
        "object.kind == 'Pod' ? object.spec : (object.kind == 'CronJob' ? "
        "object.spec.jobTemplate.spec.template.spec : object.spec.template.spec)",
    ),
    ("podSC", "has(variables.podSpec.securityContext) ? variables.podSpec.securityContext : {}"),
    ("appContainers", "has(variables.podSpec.containers) ? variables.podSpec.containers : []"),
    (
        "resContainers",
        "variables.appContainers + (has(variables.podSpec.initContainers) ? variables.podSpec.initContainers : [])",
    ),
    (
        "containers",
        "variables.resContainers + "
        "(has(variables.podSpec.ephemeralContainers) ? variables.podSpec.ephemeralContainers : [])",
    ),
)


def _has(var: str, dotted: str) -> str:
    """``has(c.a) && has(c.a.b)`` for ``_has('c', 'a.b')``."""
    parts = dotted.split(".")
    return " && ".join(f"has({var}.{'.'.join(parts[: i + 1])})" for i in range(len(parts)))


def _sc(field_name: str, var: str = "c") -> str:
    return _has(var, f"securityContext.{field_name}")


# The handler paths KEP-4940 forbids a `host` on, matching `rules._s029` exactly: a mismatch between the two
# would show up as a policy that admits what the audit flags, which `test_policy_equals_audit_on_random_objects`
# holds to exact parity.
_PROBE_HOST_PATHS: tuple[str, ...] = (
    "livenessProbe.httpGet",
    "livenessProbe.tcpSocket",
    "readinessProbe.httpGet",
    "readinessProbe.tcpSocket",
    "startupProbe.httpGet",
    "startupProbe.tcpSocket",
    "lifecycle.postStart.httpGet",
    "lifecycle.postStart.tcpSocket",
    "lifecycle.preStop.httpGet",
    "lifecycle.preStop.tcpSocket",
)


def _no_probe_host() -> str:
    """No container, init container or ephemeral container sets a host on any probe or lifecycle handler."""
    clauses = " && ".join(f"!({_has('c', f'{path}.host')} && c.{path}.host != '')" for path in _PROBE_HOST_PATHS)
    return f"variables.containers.all(c, {clauses})"


def _eff(field_name: str, default: str) -> str:
    """A container's securityContext field, else the pod's, else ``default`` (kube_noob.audit.podspec)."""
    return (
        f"({_sc(field_name)} ? c.securityContext.{field_name} : "
        f"(has(variables.podSC.{field_name}) ? variables.podSC.{field_name} : {default}))"
    )


def _list(var: str) -> str:
    return f"(has({var}) ? {var} : [])"


def _quoted(values: Iterable[str]) -> str:
    return "[" + ", ".join("'" + v.replace("'", "\\'") + "'" for v in values) + "]"


# Regular expressions shared with kube_noob.audit.rules (RE2 syntax: CEL's matches() uses RE2).
_SENSITIVE_ENV = "(?i)" + SENSITIVE_ENV.pattern
_EMBEDDED_SECRET = EMBEDDED_CREDENTIAL
_FLAG_NAME = "-{0,2}" + CREDENTIAL_FLAG_NAME
_FLAG_WITH_VALUE = r"(?i)^\s*" + _FLAG_NAME + r"[=:].+$"
_FLAG_WITH_REFERENCE = r"(?i)^\s*" + _FLAG_NAME + r"[=:]\s*(\$\(|\$\{|(-|\*\*\*|<redacted>)?\s*$)"
_REFERENCE = r"(?i)^\s*" + _FLAG_NAME + r"[=:]\s*(\$\(|\$\{|(-|\*\*\*|<redacted>)?\s*$)"
_REFERENCE = r"^\s*(\$\(|\$\{|(-|\*\*\*|<redacted>)?\s*$)"
_ANY_CIDR = r"^\s*(0\.0\.0\.0/0|::/0)\s*$"


def _raw(regex: str) -> str:
    if "'" in regex:
        raise ValueError(f"regex must not contain a single quote: {regex}")
    return f"r'{regex}'"


def _args_ok(field_name: str) -> str:
    return (
        f"(!has(c.{field_name}) || c.{field_name}.all(a, !((a.matches({_raw(_FLAG_WITH_VALUE)}) && "
        f"!a.matches({_raw(_FLAG_WITH_REFERENCE)})) || a.matches({_raw(_EMBEDDED_SECRET)}))))"
    )


def _rbac_rule(cond: str) -> str:
    return f"!has(object.rules) || object.rules.all(r, !({cond}))"


_VERBS = "(has(r.verbs) ? r.verbs : [])"
_RESOURCES = "(has(r.resources) ? r.resources : [])"


def _any_of(lst: str, values: Iterable[str]) -> str:
    return f"{lst}.exists(x, x in {_quoted(sorted(values))})"


_S017 = " || ".join(
    f"({c})"
    for c in (
        _any_of(_VERBS, ESCALATION_VERBS),
        f"'secrets' in {_RESOURCES} && {_any_of(_VERBS, ('get', 'list', 'watch', '*'))}",
        f"{_any_of(_RESOURCES, ('pods/exec', 'pods/attach'))} && {_any_of(_VERBS, ('create', '*'))}",
        f"'nodes/proxy' in {_RESOURCES}",
        f"{_any_of(_RESOURCES, WORKLOAD_RESOURCES)} && {_any_of(_VERBS, ('create', 'patch', 'update', '*'))}",
        f"'pods/ephemeralcontainers' in {_RESOURCES} && {_any_of(_VERBS, ('patch', 'update', '*'))}",
        f"'persistentvolumes' in {_RESOURCES} && {_any_of(_VERBS, ('create', '*'))}",
        f"'controllerrevisions' in {_RESOURCES} && {_any_of(_VERBS, ('create', 'patch', 'update', '*'))}",
    )
)
_SCC_FLAGS = (
    "allowPrivilegedContainer",
    "allowHostNetwork",
    "allowHostPID",
    "allowHostIPC",
    "allowHostDirVolumePlugin",
    "allowHostPorts",
    "allowPrivilegeEscalation",
)


def _internal_lb(key: str, values: Iterable[str]) -> str:
    regex = r"(?i)^\s*(" + "|".join(re.escape(v) for v in sorted(values)) + r")\s*$"
    return f"('{key}' in object.metadata.annotations && object.metadata.annotations['{key}'].matches({_raw(regex)}))"


_INTERNAL_LB = " || ".join(_internal_lb(k, v) for k, v in sorted(INTERNAL_LB_ANNOTATIONS.items()))
_CATCH_ALL = (
    "has(e.to) && has(e.to.cidrSelector) && e.to.cidrSelector in ['0.0.0.0/0', '::/0'] && "
    "(!has(e.ports) || e.ports.size() == 0)"
)
_EGRESS = "(has(object.spec) && has(object.spec.egress) ? object.spec.egress : [])"
_EMPTY_SELECTOR = "(!has({s}.matchLabels) && !has({s}.matchExpressions))"
_ZONAL = sorted(name for name, p in PROVISIONERS.items() if p.zonal)
_REPLICAS = "(has(object.spec.replicas) ? object.spec.replicas : 1)"
# CVE signatures (kube_noob.audit.rules KN-S021..S024, KN-N008..N010, KN-V019), the same tables as the audit.
_SYSCTL_META = r"[+=]"
_PROC_WORKDIR = r"^\s*/proc(/|\s*$)"
_NGINX_IMAGE = (
    r"^(?:[^@]*/)?ingress-nginx/controller(?:-chroot)?:v?" + ingress_nginx_vulnerable_tag_regex() + r"(?:@.*)?$"
)
_NGINX_CLASS = r"^\s*" + re.escape(INGRESS_NGINX_CLASS) + r"\s*$"
_NGINX_RISKY = " || ".join(
    f"'{INGRESS_NGINX_ANNOTATION_PREFIX}{a}' in object.metadata.annotations"
    for a in sorted(INGRESS_NGINX_RISKY_ANNOTATIONS)
)
_NON_BLANK = _raw(r"\S")


def _configmap_value(key: str, unsafe: str) -> str:
    """CEL: the ConfigMap's ``key`` holds ``unsafe`` (whatever the case and the surrounding blanks)."""
    pattern = r"(?i)^\s*" + re.escape(unsafe) + r"\s*$"
    return f"('{key}' in object.data && string(object.data['{key}']).matches({_raw(pattern)}))"


_NGINX_CONFIGMAP = " || ".join(
    _configmap_value(k, unsafe) for k, (unsafe, _, _) in sorted(INGRESS_NGINX_CONFIGMAP_KEYS.items())
)
# Gap review 2026-10 (kube_noob.audit.rules KN-S025..S028, KN-N011, KN-ST006): the same tables as the audit.
_CM_VALUE = "string(object.data[k])"
# CEL charges 0.1 per character times a quarter of the pattern length for matches(); about 10 per character for the
# three KN-S026 value patterns, so 16 values of 4 KiB (and their keys) stay near 700,000, under the API server's
# 1,000,000 per expression (tests/test_gap_review.py computes it).
_CM_MAX_KEYS = 16
_CM_MAX_VALUE = 4096
_CM_CREDENTIAL = (
    f"(k.matches({_raw(CONFIGMAP_CREDENTIAL_KEY)}) && !{_CM_VALUE}.matches({_raw(_REFERENCE)})) || "
    f"{_CM_VALUE}.matches({_raw(_EMBEDDED_SECRET)}) || {_CM_VALUE}.matches({_raw(CONFIGMAP_CREDENTIAL_LINE)})"
)
_EVERYONE = " || ".join(
    f"(s.kind == '{kind}' && s.name in {_quoted(sorted(n for k, n in EVERYONE_SUBJECTS if k == kind))})"
    for kind in sorted({k for k, _ in EVERYONE_SUBJECTS})
)
_RBAC_DEFAULTS = (
    f"(has(object.metadata.labels) && '{RBAC_DEFAULTS_LABEL[0]}' in object.metadata.labels && "
    f"object.metadata.labels['{RBAC_DEFAULTS_LABEL[0]}'] == '{RBAC_DEFAULTS_LABEL[1]}')"
)
_INGRESS_NGINX = (
    f"((has(object.spec.ingressClassName) && string(object.spec.ingressClassName).matches({_raw(_NGINX_CLASS)})) || "
    "(has(object.metadata.annotations) && (('kubernetes.io/ingress.class' in object.metadata.annotations && "
    f"string(object.metadata.annotations['kubernetes.io/ingress.class']).matches({_raw(_NGINX_CLASS)})) || "
    f"object.metadata.annotations.exists(k, k.startsWith('{INGRESS_NGINX_ANNOTATION_PREFIX}')))))"
)
_INGRESS_NO_CLASS = (
    "(!has(object.spec.ingressClassName) && !(has(object.metadata.annotations) && "
    "'kubernetes.io/ingress.class' in object.metadata.annotations))"
)
_IMPLEMENTATION_SPECIFIC = (
    "(has(object.spec.rules) && object.spec.rules.exists(r, has(r.http) && has(r.http.paths) && "
    "r.http.paths.exists(p, has(p.pathType) && p.pathType == 'ImplementationSpecific')))"
)
_CSI = "object.spec.csi"
_CSI_TRAVERSAL = (
    f"has({_CSI}) && has({_CSI}.driver) && {_CSI}.driver in {_quoted(sorted(CSI_SUBDIR_TRAVERSAL))} && "
    f"((has({_CSI}.volumeHandle) && string({_CSI}.volumeHandle).matches({_raw(PATH_TRAVERSAL)})) || "
    f"(has({_CSI}.volumeAttributes) && 'subDir' in {_CSI}.volumeAttributes && "
    f"string({_CSI}.volumeAttributes['subDir']).matches({_raw(PATH_TRAVERSAL)})))"
)


@dataclass(frozen=True)
class Check:
    """One audit rule as admission CEL: every validation must hold for the object to pass."""

    rule_id: str
    kinds: tuple[str, ...]
    validations: tuple[str, ...]
    pod: bool = False  # declares POD_VARIABLES
    operations: tuple[str, ...] = ("CREATE", "UPDATE")
    coverage: Literal["full", "partial"] = "full"
    limitation: str = ""
    skip_owned: bool = False
    rbac_names: bool = False
    variables: tuple[tuple[str, str], ...] = field(default=())
    # The engines a policy for this rule would actually run on. A rule whose kind an engine's default
    # configuration never sends to its policies is generated for the others only, with the reason in
    # ENGINE_SKIPS, rather than as a policy that looks installed and checks nothing (G272).
    engines: tuple[Engine, ...] = ("vap", "kyverno")

    @property
    def rule(self) -> Rule:
        return RULES[self.rule_id]


_OPENSHIFT_ONLY = "OpenShift API: generated with --platform openshift, rosa-classic or rosa-hcp"
_ROSA_ONLY = "a ROSA rule: generated with --platform rosa-classic or rosa-hcp"

# Rules generated for some engines and not others, with the reason for each engine left out.
ENGINE_SKIPS: dict[tuple[str, Engine], str] = {
    ("KN-S037", "kyverno"): "Kyverno's default configuration never sends APIService objects to its policies "
    "(resourceFilters `[APIService,*,*]` in the v1.19.1 install.yaml), so a Kyverno policy for this rule would be "
    "installed and check nothing; the ValidatingAdmissionPolicy is generated",
}

# Rules not turned into admission policies, with the reason. Every rule is in exactly one of NOT_GENERATED and the
# checks (tests/test_policy_generate.py keeps it so).
NOT_GENERATED: dict[str, str] = {
    "KN-V001": "the API server refuses objects without apiVersion, kind or metadata.name before admission",
    "KN-V002": "the API server refuses kinds it does not serve; there is nothing for a policy to admit",
    "KN-V003": "the API server refuses kinds it does not serve; there is nothing for a policy to admit",
    "KN-V004": "whether an operator's API is installed is a fact about the cluster, not about one object",
    "KN-V005": "the API server refuses removed apiVersions itself",
    "KN-V006": "the API server refuses apiVersions it does not serve yet",
    "KN-V009": "the API server refuses invalid object names itself",
    "KN-V010": "apps/v1 refuses a selector that does not match the template labels itself",
    "KN-V011": "needs the pods the Service selects, which are usually created after it; `kube-noob audit` checks the "
    "bundle",
    "KN-V012": "needs the containers the Service selects (another object); `kube-noob audit` checks the bundle",
    "KN-V014": "duplicates are a property of a bundle; admission sees one object at a time",
    "KN-N014": "needs the cluster's CNI and its version, which no admitted object carries; `kube-noob audit --cni` "
    "decides it",
    "KN-V023": "needs the containerPorts the Service's selected pods declare (other objects), and the mismatch is "
    "advisory rather than a refusal; `kube-noob audit` checks the bundle",
    "KN-V020": "the API server refuses a claim name the Pod does not declare itself",
    "KN-V021": "the API server refuses a claim entry with neither or both sources itself",
    "KN-V022": "the API server forbids pod-level resources.claims itself",
    "KN-S032": "the answer depends on the platform and on the cluster's PodSecurity AdmissionConfiguration "
    "default, neither of which is a property of the Namespace object an admission policy sees",
    "KN-C016": "needs the namespace's ResourceQuota and LimitRange (other objects); `kube-noob audit` "
    "checks the bundle",
    "KN-S033": "pausing a pool is a legitimate maintenance step, and the finding is about a pool LEFT "
    "paused, which one object at one moment cannot tell from one paused a minute ago",
    "KN-S035": "admission cannot help: the finding is the state of one cluster-scoped singleton that "
    "already exists, not an object anybody is about to create, and a policy that blocked edits to it "
    "would stop an administrator turning auditing back ON as readily as off",
    "KN-S038": "the kubelet runs a static Pod from a file on the node and the API server holds only its mirror, "
    "which cannot stop it (deleting the mirror leaves the static Pod running), so refusing the mirror at admission "
    "would not stop the container; `kube-noob audit` reads the manifest",
    "KN-S039": "the kubelet runs a static Pod from a file on the node and the API server holds only its mirror, "
    "which cannot stop it, so refusing the mirror at admission would not stop etcd; `kube-noob audit` reads the "
    "manifest",
    "KN-S040": "the finding is the state of the APIServer singleton every OpenShift cluster already has, unset by "
    "default, so a policy would see only later edits and would refuse every one of them -- an audit-profile change "
    "included -- until encryption is turned on; `kube-noob audit` checks it",
    "KN-S041": "the finding is the state of the OAuth singleton every OpenShift cluster already has, so a policy "
    "would see only later edits, and where an insecure provider is already configured it would refuse every edit "
    "of the object -- adding a provider or changing a CA reference included -- until that one is fixed; "
    "`kube-noob audit` checks it",
    "KN-S034": "the webhook and the generated policies exempt openshift-* namespaces, where operator "
    "Subscriptions normally live, so a policy would not see the objects this rule is about",
    "KN-C015": "needs the namespace's ResourceClaims and templates (other objects); `kube-noob audit` checks "
    "the bundle",
    "KN-S031": "the API server's own gate is the namespace label resource.kubernetes.io/admin-access, so it "
    "already refuses adminAccess where that label is absent and permits it where a cluster admin set it; a policy "
    "here would restrict a grant the admin made, which is a decision to ask for rather than to generate",
    "KN-V018": "duplicate YAML keys are lost when the client parses the file; kubectl's strict field validation (the "
    "default) refuses them",
    "KN-S018": "every Secret in a cluster carries its data; the rule is about Secrets committed to Git, so it belongs "
    "in CI (`kube-noob audit`), not at admission",
    "KN-N013": "needs the other NetworkPolicies of the namespace (policies are additive, so another one "
    "may allow port 53); `kube-noob audit` checks the bundle",
    "KN-S030": "the API server does not send webhook configurations to admission webhooks, and a "
    "ValidatingAdmissionPolicy cannot validate another one, so no admission policy can see this object; "
    "`kube-noob audit` checks it",
    "KN-N001": "needs the NetworkPolicies of the namespace (other objects); `kube-noob audit` checks the bundle",
    "KN-ST001": "needs the StorageClass the claim names (another object); `kube-noob audit` checks the bundle",
    "KN-ST002": "needs the claim's access modes (another object); `kube-noob audit` checks the bundle",
    "KN-ST005": "the API server refuses a PersistentVolumeClaim without a storage request itself",
    "KN-C006": "the API server refuses a container whose request is above its limit itself",
    "KN-C008": "needs the PodDisruptionBudgets of the namespace (other objects); `kube-noob audit` checks the bundle",
    "KN-C012": "needs the HorizontalPodAutoscaler's target workload (another object); `kube-noob audit` checks the "
    "bundle",
    "KN-C013": "needs the Secrets of other namespaces, and kube-noob never reads Secrets; `kube-noob audit` checks the "
    "bundle",
    "KN-N012": "needs the pods of the namespace (other objects, usually created after the policy); `kube-noob audit` "
    "checks the bundle",
    "KN-C014": "needs the HorizontalPodAutoscaler that scales the workload (another object); `kube-noob audit` checks "
    "the bundle",
}


#: An allowlist entry this generator will compile: a lower-case hostname with optional port, optionally followed
#: by one or more path segments. Anything else is refused rather than escaped into a CEL string literal, because
#: an operator-supplied string that reaches a generated ENFORCING policy is the last place to be relaxed about
#: quoting -- and a policy that fails to compile denies every request under `failurePolicy: Fail` (G242).
_REGISTRY_ENTRY = re.compile(r"\A[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?(/[a-z0-9]([a-z0-9._-]*[a-z0-9])?)*\Z")
#: An unqualified reference (`nginx`, `bitnami/nginx`) resolves here. Allowing it needs the "is the first path
#: component a host" test, which needs string surgery the API server's CEL cannot do without `split`, so the
#: rule is not generated when an entry names this registry -- stated, not silently half-enforced.
_IMPLICIT_REGISTRY = "docker.io"
#: A reference made only of ASCII whitespace, which the audit skips as "no image" (`BLANK_IMAGE_CHARS`). The
#: same character set on both sides and spelled as a class rather than `\s`: RE2's `\s` leaves out `\v`, and
#: the API server's CEL has no `trim`, so an exact set is the only way the two agree (G245). The escapes are
#: CEL string escapes, which the API server unescapes before RE2 ever sees them.
_BLANK_IMAGE = r"^[ \t\n\r\f\v]*$"


def _looks_like_a_host(head: str) -> bool:
    """Docker's own test, which decides whether a reference names a registry at all.

    It matters here because the audit applies it: with the entry `myregistry` (no dot, no port), the image
    `myregistry/app` comes from Docker Hub, not from `myregistry`, so `_registry_allowed` refuses it. A CEL
    `startsWith('myregistry/')` would ADMIT it, so such an entry is refused by the generator instead of
    compiled into a policy that disagrees with the audit (G242).
    """
    return "." in head or ":" in head or head == "localhost"


def registry_cel(allowed: Sequence[str]) -> str | None:
    """CEL that passes a container whose image comes from one of `allowed`, or None when it cannot be compiled.

    Prefix matching only, which is exactly what a reference that names its registry needs, and it is written to
    agree with `kube_noob.audit.rules._registry_allowed` case by case rather than approximately:

    * `quay.io` admits every reference whose first path component is that host, which is `quay.io/...` and
      nothing else. Not `quay.io` on its own (no slash, so Docker Hub resolves it) and not `quay.io:443/...`
      (a different registry, which the audit also refuses).
    * `quay.io/my-org` admits `quay.io/my-org` itself, `quay.io/my-org/app:1` and `quay.io/my-org@sha256:...`,
      and refuses `quay.io/my-org-evil/app` because every test carries its separator.

    An unqualified `nginx` matches no prefix and is refused, which is the correct verdict whenever Docker Hub is
    not on the list -- and the reason the rule is not generated when it is.
    """
    entries = [e.strip() for e in allowed if e.strip()]
    if not entries:
        return None
    for entry in entries:
        if not _REGISTRY_ENTRY.match(entry):
            return None
        host = entry.split("/", 1)[0]
        if not _looks_like_a_host(host) or host == _IMPLICIT_REGISTRY:
            return None
    tests: list[str] = []
    for entry in sorted(set(entries)):
        if "/" in entry:
            tests.append(f"c.image == '{entry}' || c.image.startsWith('{entry}/') || c.image.startsWith('{entry}@')")
        else:
            tests.append(f"c.image.startsWith('{entry}/')")
    allowed_cel = " || ".join(tests)
    return f"variables.containers.all(c, !has(c.image) || c.image.matches('{_BLANK_IMAGE}') || {allowed_cel})"


def _checks(
    platform: str,
    platform_version: str | None,
    allowed_registries: Sequence[str] = (),
) -> tuple[dict[str, Check], dict[str, str]]:
    """The checks for this platform, and the rules skipped here (with the reason) beyond NOT_GENERATED."""
    openshift = platform in OPENSHIFT_FAMILY
    s003_k8s = (
        f"variables.containers.all(c, {_eff('runAsUser', '-1')} != 0 && "
        f"({_eff('runAsNonRoot', 'false')} == true || {_eff('runAsUser', '-1')} > 0))"
    )
    s003_ocp = f"variables.containers.all(c, {_eff('runAsUser', '-1')} != 0)"
    seccomp = (
        f"(({_sc('seccompProfile.type')} && c.securityContext.seccompProfile.type != '') ? "
        "c.securityContext.seccompProfile.type : "
        "(has(variables.podSC.seccompProfile) && has(variables.podSC.seccompProfile.type) ? "
        "variables.podSC.seccompProfile.type : ''))"
    )
    # A Localhost profile whose localhostProfile is missing or blank (CVE-2023-2431), at whichever level sets the type.
    empty_localhost = (
        f"(({_sc('seccompProfile.type')} && c.securityContext.seccompProfile.type == 'Localhost' && "
        "!(has(c.securityContext.seccompProfile.localhostProfile) && "
        f"string(c.securityContext.seccompProfile.localhostProfile).matches({_NON_BLANK}))) || "
        f"(!({_sc('seccompProfile.type')} && c.securityContext.seccompProfile.type != '') && "
        "has(variables.podSC.seccompProfile) && has(variables.podSC.seccompProfile.type) && "
        "variables.podSC.seccompProfile.type == 'Localhost' && "
        "!(has(variables.podSC.seccompProfile.localhostProfile) && "
        f"string(variables.podSC.seccompProfile.localhostProfile).matches({_NON_BLANK}))))"
    )
    image_ok = (
        "has(c.image) && c.image != '' && (c.image.matches(r'@sha256:[0-9a-f]{64}$') || "
        "(c.image.matches(r'^([^@]*/)?[^/@]*:[^/@]*(@.*)?$') && "
        "!c.image.matches(r'^([^@]*/)?[^/@:]*:latest(@.*)?$')))"
    )
    env_ok = (
        f"(!has(c.env) || c.env.all(e, !has(e.value) || e.value.matches({_raw(_REFERENCE)}) || "
        f"!((has(e.name) && e.name.matches({_raw(_SENSITIVE_ENV)})) || e.value.matches({_raw(_EMBEDDED_SECRET)}))))"
    )
    probe = "c.livenessProbe"
    period = f"(has({probe}.periodSeconds) ? {probe}.periodSeconds : 10)"
    checks = [
        Check(
            "KN-S001",
            _POD_KINDS,
            (f"variables.containers.all(c, !({_sc('privileged')} && c.securityContext.privileged == true))",),
            pod=True,
        ),
        Check(
            "KN-S002",
            _POD_KINDS,
            (
                f"variables.containers.all(c, {_sc('allowPrivilegeEscalation')} && "
                "c.securityContext.allowPrivilegeEscalation == false)",
            ),
            pod=True,
        ),
        Check("KN-S003", _POD_KINDS, (s003_ocp if openshift else s003_k8s,), pod=True),
        Check(
            "KN-S004",
            _POD_KINDS,
            (
                "!(has(variables.podSC.runAsUser) && variables.podSC.runAsUser != 0)",
                "!(has(variables.podSC.fsGroup) && variables.podSC.fsGroup != 0)",
                f"variables.containers.all(c, !({_sc('runAsUser')} && c.securityContext.runAsUser != 0))",
            ),
            pod=True,
        ),
        Check(
            "KN-S005",
            _POD_KINDS,
            (
                f"variables.containers.all(c, !({_sc('capabilities.add')}) || "
                "c.securityContext.capabilities.add.all(x, x.matches(r'(?i)^(CAP_)?NET_BIND_SERVICE$')))",
            ),
            pod=True,
        ),
        Check(
            "KN-S006",
            _POD_KINDS,
            (
                f"variables.containers.all(c, {_sc('capabilities.drop')} && "
                "c.securityContext.capabilities.drop.exists(x, x.matches(r'(?i)^ALL$')))",
            ),
            pod=True,
        ),
        Check(
            "KN-S007",
            _POD_KINDS,
            (
                f"variables.containers.all(c, {_sc('readOnlyRootFilesystem')} && "
                "c.securityContext.readOnlyRootFilesystem == true)",
            ),
            pod=True,
        ),
        Check(
            "KN-S008",
            _POD_KINDS,
            (f"variables.containers.all(c, {seccomp} in ['RuntimeDefault', 'Localhost'] && !{empty_localhost})",),
            pod=True,
        ),
        Check(
            "KN-S009",
            _POD_KINDS,
            tuple(
                f"!(has(variables.podSpec.{f}) && variables.podSpec.{f} == true)"
                for f in ("hostNetwork", "hostPID", "hostIPC")
            ),
            pod=True,
        ),
        Check(
            "KN-S010",
            _POD_KINDS,
            ("!has(variables.podSpec.volumes) || variables.podSpec.volumes.all(v, !has(v.hostPath))",),
            pod=True,
        ),
        Check(
            "KN-S011",
            _POD_KINDS,
            ("variables.containers.all(c, !has(c.ports) || c.ports.all(p, !has(p.hostPort) || p.hostPort == 0))",),
            pod=True,
        ),
        Check("KN-S012", _POD_KINDS, (f"variables.containers.all(c, {image_ok})",), pod=True),
        Check(
            "KN-S013",
            _POD_KINDS,
            (f"variables.containers.all(c, {env_ok} && {_args_ok('command')} && {_args_ok('args')})",),
            pod=True,
            coverage="partial",
            limitation="a credential flag whose value is the next argument (--password hunter2) is left to "
            "`kube-noob audit`",
        ),
        Check(
            "KN-S014",
            _POD_KINDS,
            (
                "has(variables.podSpec.automountServiceAccountToken) && "
                "variables.podSpec.automountServiceAccountToken == false",
            ),
            pod=True,
            coverage="partial",
            limitation="a ServiceAccount that opts out is not visible at admission; set automountServiceAccountToken: "
            "false on the pod too",
        ),
        Check(
            "KN-S015",
            ("Role", "ClusterRole"),
            (
                _rbac_rule(
                    "(has(r.verbs) && '*' in r.verbs) || (has(r.resources) && '*' in r.resources) || "
                    "(has(r.apiGroups) && '*' in r.apiGroups)"
                ),
            ),
            rbac_names=True,
        ),
        Check(
            "KN-S016",
            ("RoleBinding", "ClusterRoleBinding"),
            ("!(has(object.roleRef) && has(object.roleRef.name) && object.roleRef.name == 'cluster-admin')",),
            rbac_names=True,
        ),
        Check("KN-S017", ("Role", "ClusterRole"), (_rbac_rule(_S017),), rbac_names=True),
        Check(
            "KN-S019",
            ("SecurityContextConstraints",),
            (
                *(f"!(has(object.{f}) && object.{f} == true)" for f in _SCC_FLAGS),
                "!(has(object.runAsUser) && has(object.runAsUser.type) && object.runAsUser.type == 'RunAsAny')",
            ),
        ),
        Check(
            "KN-S020",
            _POD_KINDS,
            (f"variables.containers.all(c, !({_sc('procMount')} && c.securityContext.procMount == 'Unmasked'))",),
            pod=True,
        ),
        Check(
            "KN-S029",
            _POD_KINDS,
            (_no_probe_host(),),
            pod=True,
        ),
        Check(
            "KN-S021",
            _POD_KINDS,
            ("!has(variables.podSpec.volumes) || variables.podSpec.volumes.all(v, !has(v.gitRepo))",),
            pod=True,
        ),
        Check(
            "KN-S022",
            _POD_KINDS,
            (
                "!has(variables.podSC.sysctls) || variables.podSC.sysctls.all(s, "
                f"!((has(s.name) && string(s.name).matches({_raw(_SYSCTL_META)})) || "
                f"(has(s.value) && string(s.value).matches({_raw(_SYSCTL_META)}))))",
            ),
            pod=True,
        ),
        Check(
            "KN-S023",
            _POD_KINDS,
            (
                "variables.containers.all(c, !has(c.workingDir) || "
                f"!string(c.workingDir).matches({_raw(_PROC_WORKDIR)}))",
            ),
            pod=True,
        ),
        Check(
            "KN-S024",
            _POD_KINDS,
            (f"variables.containers.all(c, !has(c.image) || !string(c.image).matches({_raw(_NGINX_IMAGE)}))",),
            pod=True,
        ),
        Check(
            "KN-S025",
            _POD_KINDS,
            (
                "variables.containers.all(c, !has(c.volumeMounts) || c.volumeMounts.all(m, !has(m.subPath) || "
                f"!string(m.subPath).matches({_raw(COMMAND_META)})))",
            ),
            pod=True,
        ),
        Check(
            "KN-S026",
            ("ConfigMap",),
            (
                f"!has(object.data) || object.data.size() > {_CM_MAX_KEYS} || "
                f"object.data.exists(k, {_CM_VALUE}.size() > {_CM_MAX_VALUE}) || "
                f"object.data.all(k, !({_CM_CREDENTIAL}))",
            ),
            coverage="partial",
            limitation=f"a ConfigMap with more than {_CM_MAX_KEYS} keys or a value over {_CM_MAX_VALUE // 1024} KiB is "
            "left to `kube-noob audit`: three regular expressions over every value would pass the API server's cost "
            "limit for one CEL expression, and failurePolicy Fail would then refuse it",
        ),
        Check(
            "KN-S027",
            ("Secret",),
            ("!(has(object.type) && object.type == 'kubernetes.io/service-account-token')",),
            operations=("CREATE",),
        ),
        Check(
            "KN-S028",
            ("RoleBinding", "ClusterRoleBinding"),
            (
                f"{_RBAC_DEFAULTS} || !has(object.subjects) || "
                f"!object.subjects.exists(s, has(s.kind) && has(s.name) && ({_EVERYONE}))",
            ),
            rbac_names=True,
        ),
        Check(
            "KN-S029",
            _POD_KINDS,
            (_no_probe_host(),),
            pod=True,
        ),
        Check(
            "KN-N002",
            ("Route",),
            (
                "has(object.spec.tls)",
                "!(has(object.spec.tls) && has(object.spec.tls.insecureEdgeTerminationPolicy) && "
                "object.spec.tls.insecureEdgeTerminationPolicy == 'Allow')",
            ),
        ),
        Check("KN-N003", ("Ingress",), ("has(object.spec.tls) && object.spec.tls.size() > 0",)),
        Check(
            "KN-N004",
            ("Service",),
            (
                "!(has(object.spec.type) && object.spec.type == 'LoadBalancer') || "
                f"(has(object.metadata.annotations) && ({_INTERNAL_LB})) || "
                "(has(object.spec.loadBalancerSourceRanges) && object.spec.loadBalancerSourceRanges.size() > 0 && "
                f"!object.spec.loadBalancerSourceRanges.exists(x, x.matches({_raw(_ANY_CIDR)})))",
            ),
        ),
        Check("KN-N005", ("Service",), ("!(has(object.spec.type) && object.spec.type == 'NodePort')",)),
        Check("KN-N008", ("Service",), ("!has(object.spec.externalIPs) || object.spec.externalIPs.size() == 0",)),
        Check(
            "KN-S037",
            ("APIService",),
            (
                "!(has(object.spec.service) && has(object.spec.insecureSkipTLSVerify) && "
                "object.spec.insecureSkipTLSVerify == true)",
            ),
            engines=("vap",),
        ),
        Check("KN-N009", ("Ingress",), (f"!has(object.metadata.annotations) || !({_NGINX_RISKY})",)),
        Check("KN-N010", ("ConfigMap",), (f"!has(object.data) || !({_NGINX_CONFIGMAP})",)),
        Check(
            "KN-N011",
            ("Ingress",),
            (
                f"!{_IMPLEMENTATION_SPECIFIC} || !{_INGRESS_NGINX}"
                if openshift
                else f"!{_IMPLEMENTATION_SPECIFIC} || !({_INGRESS_NGINX} || {_INGRESS_NO_CLASS})",
            ),
        ),
        Check(
            "KN-N006",
            ("EgressFirewall",),
            (
                "variables.catchAlls == 0 || (variables.catchAlls == 1 && "
                f"[variables.egress[variables.egress.size() - 1]].exists(e, {_CATCH_ALL}))",
            ),
            variables=(
                ("egress", _EGRESS),
                ("catchAlls", f"variables.egress.filter(e, {_CATCH_ALL}).size()"),
            ),
        ),
        Check(
            "KN-N007",
            ("NetworkPolicy",),
            (
                "!has(object.spec.ingress) || object.spec.ingress.all(r, (has(r.from) && r.from.size() > 0) ? "
                "r.from.all(p, !(has(p.ipBlock) && has(p.ipBlock.cidr) && "
                f"p.ipBlock.cidr.matches({_raw(_ANY_CIDR)}) && "
                "!(has(p.ipBlock.except) && p.ipBlock.except.size() > 0)) && "
                f"!(has(p.namespaceSelector) && {_EMPTY_SELECTOR.format(s='p.namespaceSelector')} && "
                f"(!has(p.podSelector) || {_EMPTY_SELECTOR.format(s='p.podSelector')}))) : "
                "(has(r.ports) && r.ports.size() > 0))",
            ),
        ),
        Check(
            "KN-ST003",
            ("StorageClass",),
            (
                f"!(has(object.provisioner) && object.provisioner in {_quoted(_ZONAL)}) || "
                "(has(object.volumeBindingMode) && object.volumeBindingMode != 'Immediate')",
            ),
        ),
        Check(
            "KN-ST004",
            ("StorageClass",),
            (
                "!(has(object.provisioner) && object.provisioner == 'efs.csi.aws.com') || "
                "(has(object.parameters) && 'provisioningMode' in object.parameters && "
                "object.parameters['provisioningMode'] != '' && 'fileSystemId' in object.parameters && "
                "object.parameters['fileSystemId'] != '')",
            ),
        ),
        Check(
            "KN-ST006",
            ("PersistentVolume",),
            (
                "!(has(object.spec.local) && has(object.spec.local.path) && "
                f"string(object.spec.local.path).matches({_raw(COMMAND_META)}))",
                f"!({_CSI_TRAVERSAL})",
            ),
        ),
        Check(
            "KN-C001",
            _LONG_RUNNING,
            ("variables.appContainers.all(c, has(c.readinessProbe))",),
            pod=True,
            skip_owned=True,
        ),
        Check(
            "KN-C002",
            _LONG_RUNNING,
            ("variables.appContainers.all(c, has(c.livenessProbe))",),
            pod=True,
            skip_owned=True,
        ),
        Check(
            "KN-C003",
            _LONG_RUNNING,
            (
                f"variables.appContainers.all(c, !has({probe}) || "
                f"((has({probe}.failureThreshold) ? {probe}.failureThreshold : 3) >= 2 && {period} >= 5 && "
                f"(has({probe}.timeoutSeconds) ? {probe}.timeoutSeconds : 1) < {period}))",
            ),
            pod=True,
            skip_owned=True,
        ),
        Check(
            "KN-C004",
            _POD_KINDS,
            (
                "variables.resContainers.all(c, has(c.resources) && has(c.resources.requests) && "
                "'cpu' in c.resources.requests && 'memory' in c.resources.requests)",
            ),
            pod=True,
            skip_owned=True,
        ),
        Check(
            "KN-C005",
            _POD_KINDS,
            (
                "variables.resContainers.all(c, has(c.resources) && has(c.resources.limits) && "
                "'memory' in c.resources.limits)",
            ),
            pod=True,
            skip_owned=True,
        ),
        Check(
            "KN-C007",
            _REPLICATED,
            (f"{_REPLICAS} >= 2",),
            skip_owned=True,
            coverage="partial",
            limitation="a workload an HorizontalPodAutoscaler scales is not visible as such at admission; "
            "`kube-noob audit` exempts it when the HPA is in the bundle",
        ),
        Check(
            "KN-C009",
            ("PodDisruptionBudget",),
            (
                "has(object.spec.maxUnavailable) ? "
                "!string(object.spec.maxUnavailable).matches(r'^\\s*0+%?\\s*$') : "
                "!(has(object.spec.minAvailable) && "
                "string(object.spec.minAvailable).matches(r'^\\s*0*[1-9][0-9]{2,}%\\s*$'))",
            ),
            coverage="partial",
            limitation="refuses budgets that allow no eviction whatever the replica count (maxUnavailable 0, "
            "minAvailable 100%); minAvailable compared with the replica count needs the workload: `kube-noob audit`",
        ),
        Check(
            "KN-C010",
            _REPLICATED,
            (
                f"{_REPLICAS} < 2 || (has(variables.podSpec.topologySpreadConstraints) && "
                "variables.podSpec.topologySpreadConstraints.size() > 0) || "
                "(has(variables.podSpec.affinity) && has(variables.podSpec.affinity.podAntiAffinity))",
            ),
            pod=True,
            skip_owned=True,
        ),
        Check(
            "KN-C011",
            _POD_KINDS,
            (
                "!(has(variables.podSpec.terminationGracePeriodSeconds) && "
                "variables.podSpec.terminationGracePeriodSeconds == 0)",
            ),
            pod=True,
            skip_owned=True,
        ),
        Check("KN-V008", ("DeploymentConfig",), ("false",), operations=("CREATE",)),
        Check("KN-V015", ("EgressFirewall",), ("object.metadata.name == 'default'",)),
        Check(
            "KN-V016",
            ("Route",),
            (
                "!has(object.spec.tls) || (has(object.spec.tls.termination) && "
                "object.spec.tls.termination in ['edge', 'passthrough', 'reencrypt'])",
                "!has(object.spec.tls) || !has(object.spec.tls.insecureEdgeTerminationPolicy) || "
                "object.spec.tls.insecureEdgeTerminationPolicy in ['', 'None', 'Redirect', 'Allow']",
                "!(has(object.spec.tls) && has(object.spec.tls.termination) && "
                "object.spec.tls.termination == 'passthrough' && "
                "has(object.spec.tls.insecureEdgeTerminationPolicy) && "
                "object.spec.tls.insecureEdgeTerminationPolicy == 'Allow')",
                "!(has(object.spec.tls) && has(object.spec.tls.termination) && "
                "object.spec.tls.termination == 'passthrough' && "
                "((has(object.spec.tls.certificate) && object.spec.tls.certificate != '') || "
                "(has(object.spec.tls.key) && object.spec.tls.key != '') || "
                "(has(object.spec.tls.caCertificate) && object.spec.tls.caCertificate != '')))",
            ),
        ),
        Check("KN-V017", ("MachineConfig", "MachineConfigPool"), ("false",)),
        Check(
            "KN-V019",
            ("Ingress",),
            (
                "!has(object.metadata.annotations) || !object.metadata.annotations.exists(k, "
                f"k.startsWith('{INGRESS_NGINX_ANNOTATION_PREFIX}'))",
                "!(has(object.spec.ingressClassName) && "
                f"string(object.spec.ingressClassName).matches({_raw(_NGINX_CLASS)}))",
                "!has(object.metadata.annotations) || !('kubernetes.io/ingress.class' in object.metadata.annotations "
                f"&& string(object.metadata.annotations['kubernetes.io/ingress.class']).matches({_raw(_NGINX_CLASS)}))",
            ),
            coverage="partial",
            limitation="a workload that runs the ingress-nginx controller image is left to `kube-noob audit`",
        ),
    ]
    out: dict[str, Check] = {}
    skipped: dict[str, str] = {}
    for c in checks:
        groups = {TARGETS[k].group for k in c.kinds}
        if c.rule_id == "KN-S004" and not openshift:
            skipped[c.rule_id] = "an OpenShift SCC rule: generated with --platform openshift, rosa-classic or rosa-hcp"
        elif c.rule_id == "KN-V017" and platform not in ROSA_FAMILY:
            skipped[c.rule_id] = _ROSA_ONLY
        elif c.rule_id == "KN-V008" and openshift and platform_version and parse_minor(platform_version) < (4, 14):
            skipped[c.rule_id] = "DeploymentConfig is deprecated from OpenShift 4.14"
        elif groups <= OPENSHIFT_GROUPS and not openshift:
            skipped[c.rule_id] = _OPENSHIFT_ONLY
        else:
            kinds = tuple(k for k in c.kinds if openshift or TARGETS[k].group not in OPENSHIFT_GROUPS)
            out[c.rule_id] = c if kinds == c.kinds else _with_kinds(c, kinds)
    # KN-S036 is a policy only when an organisation has said which registries it approves. With no list there
    # is no expression to write: emitting one that admits everything would look like enforcement while enforcing
    # nothing, which is the absence-read-as-a-pass failure this whole catalogue is built against. So the rule is
    # recorded as skipped WITH the reason, exactly as the audit declines it (G241, G242).
    registry = registry_cel(allowed_registries)
    if registry is None:
        skipped["KN-S036"] = (
            "no registry allowlist to enforce: set audit.allowedRegistries in the configuration file (entries "
            "like quay.io or quay.io/my-org). An entry naming docker.io, or a host with no dot, port or "
            "`localhost`, is refused here because the resulting CEL would disagree with `kube-noob audit`"
        )
    else:
        out["KN-S036"] = Check("KN-S036", _POD_KINDS, (registry,), pod=True)
    # DeploymentConfig is a pod workload on OpenShift.
    if openshift:
        for rid, c in list(out.items()):
            if c.pod and c.kinds == _POD_KINDS:
                out[rid] = _with_kinds(c, (*c.kinds, "DeploymentConfig"))
    return out, skipped


def _with_kinds(c: Check, kinds: tuple[str, ...]) -> Check:
    return Check(
        c.rule_id,
        kinds,
        c.validations,
        pod=c.pod,
        operations=c.operations,
        coverage=c.coverage,
        limitation=c.limitation,
        skip_owned=c.skip_owned,
        rbac_names=c.rbac_names,
        variables=c.variables,
        engines=c.engines,
    )


def checks_for(
    platform: str,
    platform_version: str | None = None,
    allowed_registries: Sequence[str] = (),
) -> dict[str, Check]:
    return _checks(platform, platform_version, allowed_registries)[0]


def _exempt(c: Check, platform: str, exceptions: Sequence[Checked] = ()) -> str:
    parts: list[str] = []
    accepted = exception_cel([e for e in exceptions if e.rule == c.rule_id])
    if accepted:
        parts.append(accepted)
    if platform in OPENSHIFT_FAMILY:
        parts.append(
            "('namespace' in object.metadata && (object.metadata['namespace'] == 'openshift' || "
            "object.metadata['namespace'].startsWith('openshift-')))"
        )
        parts.append("request.userInfo.username.startsWith('system:serviceaccount:openshift-')")
    if c.skip_owned:
        parts.append(
            "(has(object.metadata.ownerReferences) && "
            "object.metadata.ownerReferences.exists(o, has(o.controller) && o.controller == true))"
        )
    if c.rbac_names:
        parts.append("(has(object.metadata.name) && object.metadata.name.startsWith('system:'))")
    return " || ".join(parts) or "false"


def _glob(value: str) -> str:
    """A CEL test of ``value`` against a name glob (only ``*`` is a wildcard in exception scopes)."""
    return "^" + re.escape(value).replace(r"\*", ".*") + "$"


def _name_test(field: str, pattern: str | None) -> str:
    if pattern is None:
        return "true"
    if "*" in pattern:
        return f"{field}.matches({_raw(_glob(pattern))})"
    return f"{field} == '{pattern}'"


def _owned_by(kind: str, pattern: str | None) -> str:
    return (
        "(has(object.metadata.ownerReferences) && object.metadata.ownerReferences.exists(o, "
        f"o.kind == '{kind}' && {_name_test('o.name', pattern)}))"
    )


# What a controller makes from a workload, so that an exception for the workload also covers its children (else the
# workload is admitted and its ReplicaSets or pods are refused): (child kind, owner kind, owner name suffix).
_CHILDREN: dict[str, tuple[tuple[str, str, str], ...]] = {
    "Deployment": (("ReplicaSet", "Deployment", ""), ("Pod", "ReplicaSet", "-*")),
    "DeploymentConfig": (("ReplicationController", "DeploymentConfig", "-*"), ("Pod", "ReplicationController", "-*")),
    "StatefulSet": (("Pod", "StatefulSet", ""),),
    "DaemonSet": (("Pod", "DaemonSet", ""),),
    "ReplicaSet": (("Pod", "ReplicaSet", ""),),
    "ReplicationController": (("Pod", "ReplicationController", ""),),
    "Job": (("Pod", "Job", ""),),
    "CronJob": (("Job", "CronJob", ""), ("Pod", "Job", "-*")),
}


def exception_cel(entries: Sequence[Checked]) -> str | None:
    """CEL that is true for the objects the active ``entries`` cover, and for the ReplicaSets, Jobs and pods their
    workloads make; None when none is active. Mirrors kube_noob.audit.exceptions.Checked.covers."""
    terms: list[str] = []
    for e in entries:
        if e.status != "active":
            continue
        sc = e.scope
        parts: list[str] = []
        ns = sc.get("namespace")
        if ns is not None:
            test = (
                f"object.metadata['namespace'].startsWith('{ns[:-1]}')"
                if ns.endswith("*")
                else (f"object.metadata['namespace'] == '{ns}'")
            )
            parts.append(f"('namespace' in object.metadata && {test})")
        kind, name = sc.get("kind"), sc.get("name")
        direct = [f"object.kind == '{kind}'"] if kind else []
        direct.append(f"(has(object.metadata.name) && {_name_test('object.metadata.name', name)})" if name else "true")
        shapes = [" && ".join(direct)]
        for child, owner, suffix in _CHILDREN.get(kind or "", ()):
            shapes.append(f"(object.kind == '{child}' && {_owned_by(owner, (name + suffix) if name else None)})")
        if kind is None and name:
            shapes.append(_owned_by_any(name))
        parts.append("(" + " || ".join(shapes) + ")")
        terms.append("(" + " && ".join(parts) + ")")
    return " || ".join(terms) or None


def _owned_by_any(name: str) -> str:
    return (
        "(has(object.metadata.ownerReferences) && object.metadata.ownerReferences.exists(o, "
        f"{_name_test('o.name', name)} || {_name_test('o.name', name + '-*')}))"
    )


def _sources(r: Rule) -> list[str]:
    return [SOURCES[s].url for s in r.citations if s in SOURCES]


def message(c: Check) -> str:
    r = c.rule
    text = f"[{r.rule_id}] {r.title}. Fix: {r.remediation}"
    srcs = _sources(r)
    if srcs:
        text += f" Source: {srcs[0]}"
    return " ".join(text.split())


def _variables(c: Check, platform: str, exceptions: Sequence[Checked] = ()) -> list[dict[str, str]]:
    out = [{"name": "exempt", "expression": _exempt(c, platform, exceptions)}]
    if c.pod:
        out += [{"name": n, "expression": e} for n, e in POD_VARIABLES]
    out += [{"name": n, "expression": e} for n, e in c.variables]
    return out


def _match(c: Check, exclude: Sequence[str]) -> dict[str, Any]:
    grouped: dict[tuple[str, str], list[str]] = {}
    for k in c.kinds:
        grouped.setdefault((TARGETS[k].group, TARGETS[k].version), []).append(TARGETS[k].resource)
    rules = [
        {"apiGroups": [g], "apiVersions": [v], "operations": list(c.operations), "resources": resources}
        for (g, v), resources in grouped.items()
    ]
    return {
        "resourceRules": rules,
        "namespaceSelector": {
            "matchExpressions": [{"key": "kubernetes.io/metadata.name", "operator": "NotIn", "values": list(exclude)}]
        },
    }


def _annotations(c: Check, engine: Engine) -> dict[str, str]:
    r = c.rule
    out = {
        "kube-noob.io/rule": r.rule_id,
        "kube-noob.io/title": r.title,
        "kube-noob.io/severity": r.severity.name.lower(),
        "kube-noob.io/fix": r.remediation,
        "kube-noob.io/source": " ".join(_sources(r)),
        "kube-noob.io/coverage": c.coverage,
    }
    if c.limitation:
        out["kube-noob.io/limitation"] = c.limitation
    if engine == "kyverno":
        out |= {
            "policies.kyverno.io/title": f"{r.rule_id} {r.title}",
            "policies.kyverno.io/category": r.category,
            "policies.kyverno.io/severity": r.severity.name.lower(),
            "policies.kyverno.io/description": f"{r.description} Fix: {r.remediation}",
        }
    return {k: " ".join(v.split()) for k, v in out.items() if v}


def _labels(c: Check, mode: Mode) -> dict[str, str]:
    return {
        "app.kubernetes.io/managed-by": "kube-noob",
        "kube-noob.io/rule": c.rule_id.lower(),
        "kube-noob.io/mode": mode,
    }


def name_of(rule_id: str) -> str:
    return PREFIX + rule_id.lower()


def documents(
    c: Check,
    engine: Engine,
    mode: Mode,
    platform: str,
    exclude: Sequence[str] = DEFAULT_EXCLUDED_NAMESPACES,
    exceptions: Sequence[Checked] = (),
) -> list[dict[str, Any]]:
    """The policy objects for one check: a VAP and its binding, or one Kyverno ValidatingPolicy."""
    name = name_of(c.rule_id)
    msg = message(c)
    validations = [{"expression": f"variables.exempt || ({v})", "message": msg} for v in c.validations]
    meta = {"name": name, "labels": _labels(c, mode), "annotations": _annotations(c, engine)}
    if engine == "vap":
        policy = {
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingAdmissionPolicy",
            "metadata": meta,
            "spec": {
                "failurePolicy": "Fail" if mode == "enforce" else "Ignore",
                "matchConstraints": _match(c, exclude),
                "variables": _variables(c, platform, exceptions),
                "validations": validations,
            },
        }
        binding = {
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingAdmissionPolicyBinding",
            "metadata": {"name": name, "labels": _labels(c, mode)},
            "spec": {"policyName": name, "validationActions": ["Deny"] if mode == "enforce" else ["Warn", "Audit"]},
        }
        return [policy, binding]
    return [
        {
            "apiVersion": "policies.kyverno.io/v1",
            "kind": "ValidatingPolicy",
            "metadata": meta,
            "spec": {
                "validationActions": ["Deny"] if mode == "enforce" else ["Audit", "Warn"],
                "evaluation": {"background": {"enabled": False}},
                "matchConstraints": _match(c, exclude),
                "variables": _variables(c, platform, exceptions),
                "validations": validations,
            },
        }
    ]


@dataclass(frozen=True)
class Generated:
    documents: list[dict[str, Any]]
    generated: list[dict[str, str]]
    skipped: list[dict[str, str]]
    #: The generated rules that read a pod spec. Not part of `summary()`: the header needs it to state, once,
    #: that a pod spec embedded in an operator CRD is audited but not matched at admission (G245).
    pod_rules: tuple[str, ...] = ()

    def yaml(self, header: Sequence[str] = ()) -> str:
        from kube_noob import sanitize
        from kube_noob.yamlio import TerminalSafeDumper

        # The header is kube-noob's own text, and it echoes values from the exceptions file (an id, a namespace, a
        # reason): each line is cleaned and has its CI service messages broken, so `mon##[endgroup]` is not a
        # workflow command in a log that prints the file. Comments are not data, so changing them loses nothing.
        # The documents go through the dumper the other writers use (G279, third review).
        lines = [sanitize.defuse_workflow_commands(f"# {sanitize.visible(h, mark=True)}") for h in header]
        body = str(
            yaml.dump_all(
                self.documents, Dumper=TerminalSafeDumper, sort_keys=False, width=100_000, default_flow_style=False
            )
        )
        return ("\n".join(lines) + "\n" if lines else "") + ("---\n" + body if self.documents else "")

    def summary(self) -> dict[str, Any]:
        return {"generated": self.generated, "skipped": self.skipped, "documents": len(self.documents)}


def _valid_namespace(ns: str) -> bool:
    return 0 < len(ns) <= 63 and all(ch.isdigit() or ("a" <= ch <= "z") or ch == "-" for ch in ns)


def generate(
    *,
    platform: str = "kubernetes",
    platform_version: str | None = None,
    engines: Sequence[Engine] = ENGINES,
    mode: Mode = "audit",
    rules: Sequence[str] | None = None,
    exclude_namespaces: Sequence[str] = (),
    exceptions: Sequence[Checked] = (),
    allowed_registries: Sequence[str] = (),
) -> Generated:
    """Policies for ``rules`` (default: all) on ``platform``, one set per engine, in rule-id order."""
    unknown_engines = [e for e in engines if e not in ENGINES]
    if unknown_engines or not engines:
        raise ValueError(f"engines must be among {list(ENGINES)}")
    if mode not in MODES:
        raise ValueError(f"mode must be one of {list(MODES)}")
    if len(exclude_namespaces) > MAX_EXCLUDED_NAMESPACES:
        raise ValueError(f"at most {MAX_EXCLUDED_NAMESPACES} excluded namespaces")
    bad_ns = [ns for ns in exclude_namespaces if not _valid_namespace(ns)]
    if bad_ns:
        raise ValueError(f"not a namespace name: {bad_ns[:3]}")
    wanted = [r.strip().upper() for r in rules] if rules else sorted(RULES)
    unknown = [r for r in wanted if r not in RULES]
    if unknown:
        raise ValueError(f"unknown rule id(s): {unknown[:5]} (kube-noob rules lists them)")
    checks, platform_skips = _checks(platform, platform_version, allowed_registries)
    exclude = list(dict.fromkeys([*DEFAULT_EXCLUDED_NAMESPACES, *exclude_namespaces]))
    docs: list[dict[str, Any]] = []
    generated: list[dict[str, str]] = []
    skipped: list[dict[str, str]] = []
    for rid in sorted(dict.fromkeys(wanted)):
        c = checks.get(rid)
        if c is None:
            reason = NOT_GENERATED.get(rid) or platform_skips.get(rid) or "not expressible as one-object admission CEL"
            skipped.append({"ruleId": rid, "reason": reason})
            continue
        for engine in engines:
            if engine not in c.engines:
                skipped.append({"ruleId": rid, "reason": f"{engine}: {ENGINE_SKIPS[(rid, engine)]}"})
                continue
            docs.extend(documents(c, engine, mode, platform, exclude, exceptions))
            row = {"ruleId": rid, "engine": engine, "name": name_of(rid), "coverage": c.coverage}
            if c.limitation:
                row["limitation"] = c.limitation
            accepted = [e.id for e in exceptions if e.rule == rid and e.status == "active"]
            if accepted:
                row["exceptions"] = ", ".join(accepted)
            generated.append(row)
    return Generated(
        docs,
        generated,
        skipped,
        tuple(rid for rid in sorted({row["ruleId"] for row in generated}) if checks[rid].pod),
    )


def header(
    g: Generated,
    *,
    platform: str,
    platform_version: str | None,
    mode: Mode,
    engines: Sequence[str],
    exceptions: Sequence[Checked] = (),
) -> list[str]:
    rules = sorted({row["ruleId"] for row in g.generated})
    out = [
        f"Generated by kube-noob {__version__} policy generate: {len(rules)} rules, engines {', '.join(engines)}, "
        f"mode {mode}, platform {platform}{' ' + platform_version if platform_version else ''}.",
        "Apply with: kubectl apply -f <this file> (or oc apply). Audit mode warns and records; enforce refuses.",
        "Each policy names its rule (kube-noob-kn-...), and its message carries the fix and the source.",
    ]
    if exceptions:
        active = [e for e in exceptions if e.status == "active"]
        out.append(f"Exceptions applied as exemptions: {', '.join(f'{e.id} ({e.rule})' for e in active) or 'none'}.")
        out += [f"  not applied, {e.status}: {e.id} ({e.rule}): {e.reason}" for e in exceptions if e.status != "active"]
    if g.pod_rules:
        # Said once, here, rather than on every pod policy: the audit reads the pod specs embedded in operator
        # CRDs (a KServe predictor, a Ray worker group) and these policies match the core pod workloads, so a
        # container in one of those is audited and NOT refused at admission. A reader who takes "the policies
        # refuse exactly what the audit reports" literally would otherwise believe a gap closed that is not
        # (G245; closing it is R6 in docs/roadmap.md).
        out.append(
            "Pod rules match Pods and the core workload kinds. A pod spec embedded in an operator CRD "
            "(KServe InferenceService, KubeRay RayCluster and the other kinds kube-noob audit reads) is not "
            "matched here, so those containers are checked by kube-noob audit and not at admission."
        )
    if g.skipped:
        out.append("Not generated:")
        out += [f"  {row['ruleId']}: {row['reason']}" for row in g.skipped]
    return out


__all__ = [
    "ENGINES",
    "MODES",
    "NOT_GENERATED",
    "POD_VARIABLES",
    "TARGETS",
    "Check",
    "Generated",
    "checks_for",
    "documents",
    "generate",
    "header",
    "message",
    "name_of",
]
