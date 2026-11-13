"""Deterministic rule set.

Each rule has stable metadata (id, title, stage, default severity, remediation, citations) and a check function
``check(ctx) -> Iterable[Finding]``. Rule ids are part of the public contract (graders, exercises and the training
reward refer to them), so never renumber; retire with ``deprecated=True`` instead.
"""

from __future__ import annotations

import math
import re
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any

from kube_noob.audit.controls import controls_for
from kube_noob.audit.model import Finding, Severity, Stage
from kube_noob.audit.podspec import (
    LONG_RUNNING_EMBEDDED_KINDS,
    LONG_RUNNING_KINDS,
    REPLICATED_KINDS,
    ContainerRef,
    PodTemplate,
    containers,
    effective_security,
    pdb_allows_no_disruption,
    pod_template,
    pod_templates,
    replicas,
    selector_decides,
    selector_matches,
)
from kube_noob.audit.quantity import parse_quantity
from kube_noob.catalog import (
    ADDON_GROUPS_ON_VANILLA,
    KIND_API_VERSIONS,
    KNOWN_STORAGE_CLASSES,
    OPENSHIFT_FAMILY,
    OPENSHIFT_ONLY_GROUPS,
    PROVISIONERS,
    ROSA_FAMILY,
    api_group,
    claims_a_known_group,
    deprecated_api,
    parse_minor,
    removed_api,
)
from kube_noob.debug.netpol import ANP_KIND, BANP_KIND, policy_types
from kube_noob.yamlio import Document, PathT, fmt_path, get_path, locator

#: The two cluster-scoped tiers `kube_noob.debug.anp` evaluates, and the kinds KN-N014 reports when the CNI
#: named on the command line does not enforce them.
ADMIN_TIER_KINDS = (ANP_KIND, BANP_KIND)


@dataclass
class AuditContext:
    docs: list[Document]
    platform: str
    k8s_version: str
    platform_version: str | None = None
    # True when the caller knows these documents are only part of the namespace: `audit -f one.yaml`, a
    # pre-commit hook over staged files. A rule that fires because another object was ABSENT cannot tell
    # "there is no NetworkPolicy" from "you did not pass it", so those rules say nothing here instead of
    # reporting a finding the reader cannot act on. Never inferred from len(docs): the admission webhook
    # audits a one-document bundle on purpose and needs those rules to fire (tests/test_admission.py).
    partial_bundle: bool = False
    # The cluster's CNI, as NAME or NAME:VERSION, when the caller knows it. No manifest states it, so a rule that
    # depends on it (KN-N014) declines to decide without it rather than reporting the policy as fine.
    cni: str | None = None
    # Rules that declined to DECIDE on this input: the partial-bundle guard returned before they could
    # evaluate anything. `run_rules` keeps them out of the evaluated list, because "it skipped" and "it ran
    # and found nothing" are the two states a compliance record must never merge -- G186 made these rules
    # silent, G191 started calling a silent rule clean, and together they said a skipped rule had passed
    # (G202). A rule whose guard skips one branch but evaluates the rest does NOT register here.
    # Registries an image may come from, from the configuration file. A POLICY: no manifest states which
    # registries an organisation approved, so KN-S036 declines without it rather than passing every image.
    allowed_registries: tuple[str, ...] = ()
    undecided: set[str] = field(default_factory=set)

    def cannot_decide(self, rule_id: str) -> None:
        self.undecided.add(rule_id)

    @property
    def is_openshift(self) -> bool:
        return self.platform in OPENSHIFT_FAMILY

    @property
    def is_rosa(self) -> bool:
        return self.platform in ROSA_FAMILY

    def by_kind(self, *kinds: str) -> list[Document]:
        return [d for d in self.docs if d.kind in kinds]

    def workloads(self) -> Iterator[tuple[Document, PodTemplate]]:
        """Every pod spec in the bundle, including the ones embedded in an operator's own kind.

        One object can yield several: a RayCluster has a head and a template per worker group, an
        InferenceService up to three components. Before this read them, every pod-level rule returned nothing
        for those kinds and the bundle came back clean (G229).
        """
        for d in self.docs:
            yield from ((d, pt) for pt in pod_templates(d))

    def ns(self, doc: Document) -> str:
        return doc.namespace or "<default>"


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    stage: Stage
    category: str
    severity: Severity
    remediation: str
    description: str
    citations: tuple[str, ...] = ()
    stackrox_policies: tuple[str, ...] = ()
    check: Callable[[AuditContext, Rule], Iterable[Finding]] | None = field(default=None, compare=False)

    def finding(
        self,
        doc: Document | None,
        path: PathT,
        message: str,
        *,
        severity: Severity | None = None,
        remediation: str | None = None,
        resource: str | None = None,
    ) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            title=self.title,
            severity=severity if severity is not None else self.severity,
            stage=self.stage,
            category=self.category,
            resource=resource or (doc.ref() if doc else "<bundle>"),
            message=message,
            remediation=remediation or self.remediation,
            path=fmt_path(path),
            locator=locator(doc.data, path, doc.ambiguous_keys) if doc else fmt_path(path),
            line=doc.line_for(path) if doc else None,
            doc_index=doc.index if doc else None,
            citations=list(self.citations),
            stackrox_policies=list(self.stackrox_policies),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "ruleId": self.rule_id,
            "title": self.title,
            "stage": self.stage.value,
            "category": self.category,
            "defaultSeverity": self.severity.name.lower(),
            "description": self.description,
            "remediation": self.remediation,
            "citations": list(self.citations),
            "stackroxPolicies": list(self.stackrox_policies),
            "controls": controls_for(self.rule_id),
        }


RULES: dict[str, Rule] = {}


def rule(
    rule_id: str,
    title: str,
    stage: Stage,
    category: str,
    severity: Severity,
    remediation: str,
    description: str,
    citations: tuple[str, ...] = (),
    stackrox: tuple[str, ...] = (),
) -> Callable[[Callable[[AuditContext, Rule], Iterable[Finding]]], Callable[[AuditContext, Rule], Iterable[Finding]]]:
    def deco(
        fn: Callable[[AuditContext, Rule], Iterable[Finding]],
    ) -> Callable[[AuditContext, Rule], Iterable[Finding]]:
        if rule_id in RULES:
            raise RuntimeError(f"duplicate rule id {rule_id}")
        RULES[rule_id] = Rule(
            rule_id, title, stage, category, severity, remediation, description, citations, stackrox, fn
        )
        return fn

    return deco


DNS1123_SUBDOMAIN = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*\Z")

# =====================================================================================================
# ingress-nginx (kubernetes/ingress-nginx): CVE signatures and retirement
# =====================================================================================================
# The project is retired: best-effort maintenance ended in March 2026 and the repository was archived on
# 2026-03-24 (ingress-nginx-retired). Every fact below is from the Kubernetes CVE feed issue or the project
# document named in the citation; the fixed versions are the releases those issues name.

INGRESS_NGINX_ANNOTATION_PREFIX = "nginx.ingress.kubernetes.io/"
INGRESS_NGINX_CLASS = "nginx"
# docs/user-guide/nginx-configuration/annotations-risk.md: the annotations rated Critical and High.
INGRESS_NGINX_CRITICAL_ANNOTATIONS = frozenset(
    {"configuration-snippet", "auth-snippet", "modsecurity-snippet", "server-snippet", "stream-snippet"}
)
INGRESS_NGINX_HIGH_ANNOTATIONS = frozenset(
    {
        "server-alias",
        "auth-tls-error-page",
        "auth-tls-match-cn",
        "auth-signin",
        "auth-url",
        "mirror-host",
        "mirror-target",
        "modsecurity-transaction-id",
        "proxy-ssl-name",
        "upstream-hash-by",
    }
)
# Annotation -> the CVEs that used it, with the fix each feed issue names.
INGRESS_NGINX_ANNOTATION_CVES: dict[str, tuple[tuple[str, str], ...]] = {
    "configuration-snippet": (
        ("CVE-2021-25742", "snippets read every Secret in the cluster; keep allow-snippet-annotations false"),
        ("CVE-2023-5043", "configuration injection; mitigated by v1.9.0 with --enable-annotation-validation"),
    ),
    "auth-snippet": (("CVE-2021-25742", "snippets read every Secret in the cluster"),),
    "modsecurity-snippet": (("CVE-2021-25742", "snippets read every Secret in the cluster"),),
    "server-snippet": (("CVE-2021-25742", "snippets read every Secret in the cluster"),),
    "stream-snippet": (("CVE-2021-25742", "snippets read every Secret in the cluster"),),
    "auth-url": (
        ("CVE-2025-24514", "configuration injection, fixed in v1.11.5 and v1.12.1"),
        ("CVE-2026-24513", "validation bypass, fixed in v1.13.7 and v1.14.3"),
    ),
    "auth-tls-match-cn": (("CVE-2025-1097", "configuration injection, fixed in v1.11.5 and v1.12.1"),),
    "mirror-target": (("CVE-2025-1098", "configuration injection, fixed in v1.11.5 and v1.12.1"),),
    "mirror-host": (("CVE-2025-1098", "configuration injection, fixed in v1.11.5 and v1.12.1"),),
    "permanent-redirect": (("CVE-2023-5044", "configuration injection, fixed in v1.9.0"),),
    "auth-proxy-set-headers": (("CVE-2025-15566", "configuration injection, fixed in v1.12.5 and v1.13.1"),),
    "auth-method": (("CVE-2026-1580", "configuration injection, fixed in v1.13.7 and v1.14.3"),),
    "rewrite-target": (("CVE-2026-3288", "configuration injection, fixed in v1.13.8, v1.14.4 and v1.15.0"),),
}
# Every annotation KN-N009 flags (short name, without the prefix); kube_noob.generate.policies puts it into CEL.
INGRESS_NGINX_RISKY_ANNOTATIONS = frozenset(
    INGRESS_NGINX_CRITICAL_ANNOTATIONS | INGRESS_NGINX_HIGH_ANNOTATIONS | set(INGRESS_NGINX_ANNOTATION_CVES)
)
# ConfigMap keys that widen what an Ingress may ask of the controller (configmap.md gives the defaults).
INGRESS_NGINX_CONFIGMAP_KEYS: dict[str, tuple[str, str, str]] = {
    # key: (value that is unsafe, lower-cased; default; what it allows)
    "allow-snippet-annotations": ("true", "false", "snippet annotations"),
    "annotations-risk-level": ("critical", "High", "Critical-risk annotations (the snippets)"),
    "strict-validate-path-type": ("false", "true", "unvalidated spec.rules[].http.paths[].path values"),
}


@dataclass(frozen=True)
class ComponentAdvisory:
    """CVEs of a component with the first fixed release of each affected minor (later minors are fixed too)."""

    cves: tuple[str, ...]
    fixed: tuple[str, ...]
    summary: str
    citations: tuple[str, ...]

    def affects(self, version: tuple[int, int, int]) -> bool:
        fixed = [_semver(f) for f in self.fixed]
        same = [f[2] for f in fixed if f[:2] == version[:2]]
        if same:
            return version[2] < min(same)
        return version[:2] < max(f[:2] for f in fixed)


_SEMVER = re.compile(r"^v?(\d{1,6})\.(\d{1,6})\.(\d{1,6})\Z")
_INGRESS_NGINX_IMAGE = re.compile(r"(?:^|/)ingress-nginx/controller(?:-chroot)?\Z")


def _semver(text: str) -> tuple[int, int, int]:
    m = _SEMVER.match(text.strip())
    if not m:
        raise ValueError(f"not a version: {text!r}")
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


# Oldest first. CVE-2025-1974 (CVSS 9.8, unauthenticated, through the validating admission webhook) is the one that
# makes the finding critical when the webhook is on (--validating-webhook).
INGRESS_NGINX_ADVISORIES: tuple[ComponentAdvisory, ...] = (
    ComponentAdvisory(
        ("CVE-2021-25742",),
        ("0.49.1", "1.0.1"),
        "custom snippets read every Secret in the cluster (also set allow-snippet-annotations to false)",
        ("k8s-cve-2021-25742",),
    ),
    ComponentAdvisory(
        ("CVE-2021-25745", "CVE-2021-25746"),
        ("1.2.0",),
        "a spec.rules[].http.paths[].path that reads the controller's ServiceAccount token, and directive injection "
        "through annotation values",
        ("k8s-cve-2021-25745", "k8s-cve-2021-25746"),
    ),
    ComponentAdvisory(
        ("CVE-2022-4886",),
        ("1.8.0",),
        "path sanitization bypass through spec.rules[].http.paths[].path",
        ("k8s-cve-2022-4886",),
    ),
    ComponentAdvisory(
        ("CVE-2023-5043", "CVE-2023-5044"),
        ("1.9.0",),
        "configuration injection through the configuration-snippet and permanent-redirect annotations",
        ("k8s-cve-2023-5043", "k8s-cve-2023-5044"),
    ),
    ComponentAdvisory(
        ("CVE-2024-7646",),
        ("1.10.4", "1.11.2"),
        "annotation validation bypass by anyone who can create an Ingress",
        ("k8s-cve-2024-7646",),
    ),
    ComponentAdvisory(
        ("CVE-2025-1974", "CVE-2025-24514", "CVE-2025-1097", "CVE-2025-1098", "CVE-2025-24513"),
        ("1.11.5", "1.12.1"),
        "unauthenticated code execution in the controller through the validating admission webhook "
        "(CVE-2025-1974, CVSS 9.8), configuration injection through the auth-url, auth-tls-match-cn, "
        "mirror-target and mirror-host annotations, and auth secret path traversal",
        ("k8s-cve-2025-1974", "k8s-cve-2025-24514", "k8s-cve-2025-1097", "k8s-cve-2025-1098", "k8s-cve-2025-24513"),
    ),
    ComponentAdvisory(
        ("CVE-2025-15566",),
        ("1.12.5", "1.13.1"),
        "configuration injection through the auth-proxy-set-headers annotation",
        ("k8s-cve-2025-15566",),
    ),
    ComponentAdvisory(
        ("CVE-2026-1580", "CVE-2026-24512", "CVE-2026-24513", "CVE-2026-24514"),
        ("1.13.7", "1.14.3"),
        "configuration injection through the auth-method annotation and ImplementationSpecific paths, auth-url "
        "validation bypass, and a denial of service of the validating admission controller",
        ("k8s-cve-2026-1580", "k8s-cve-2026-24512", "k8s-cve-2026-24513", "k8s-cve-2026-24514"),
    ),
    ComponentAdvisory(
        ("CVE-2026-3288",),
        ("1.13.8", "1.14.4", "1.15.0"),
        "configuration injection through the rewrite-target annotation",
        ("k8s-cve-2026-3288",),
    ),
    ComponentAdvisory(
        ("CVE-2026-4342",),
        ("1.13.9", "1.14.5", "1.15.1"),
        "configuration injection through a combination of annotations",
        ("k8s-cve-2026-4342",),
    ),
)
_WEBHOOK_RCE = "CVE-2025-1974"


def ingress_nginx_version(image: str) -> tuple[int, int, int] | None:
    """The release an ingress-nginx controller image reference names, when its tag is a plain vX.Y.Z."""
    ref = image.split("@", 1)[0]
    last = ref.rsplit("/", 1)[-1]
    name, _, tag = last.partition(":")
    repo = ref[: len(ref) - len(last)] + name
    if not _INGRESS_NGINX_IMAGE.search(repo):
        return None
    m = _SEMVER.match(tag)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None


def is_ingress_nginx_image(image: str) -> bool:
    ref = image.split("@", 1)[0]
    last = ref.rsplit("/", 1)[-1]
    return bool(_INGRESS_NGINX_IMAGE.search(ref[: len(ref) - len(last)] + last.partition(":")[0]))


def _lt(n: int) -> str:
    """RE2 for a decimal integer from 0 to ``n - 1`` (no leading zeros)."""
    if not 0 < n < 100:
        raise ValueError(f"patch threshold out of range: {n}")
    if n == 1:
        return "0"
    if n <= 10:
        return f"[0-{n - 1}]"
    tens, ones = divmod(n, 10)
    parts = [r"\d"]
    if tens >= 2:
        parts.append(r"1\d" if tens == 2 else rf"[1-{tens - 1}]\d")
    if ones:
        parts.append(f"{tens}0" if ones == 1 else f"{tens}[0-{ones - 1}]")
    return "(?:" + "|".join(parts) + ")"


def ingress_nginx_vulnerable_tag_regex() -> str:
    """RE2 (no anchors) for every ``X.Y.Z`` an advisory in INGRESS_NGINX_ADVISORIES affects: what KN-S024 flags."""
    fixed = [_semver(f) for a in INGRESS_NGINX_ADVISORIES for f in a.fixed]
    alternatives: list[str] = []
    for major in sorted({f[0] for f in fixed}):
        top = max(f[1] for f in fixed if f[0] == major)
        thresholds: list[float] = []
        for minor in range(top + 1):
            t = 0.0
            for a in INGRESS_NGINX_ADVISORIES:
                own = [_semver(f) for f in a.fixed]
                same = [f[2] for f in own if f[:2] == (major, minor)]
                if same:
                    t = max(t, float(min(same)))
                elif (major, minor) < max(f[:2] for f in own):
                    t = math.inf
            thresholds.append(t)
        whole = 0
        while whole < len(thresholds) and thresholds[whole] == math.inf:
            whole += 1
        if whole == len(thresholds):
            alternatives.append(rf"{major}\.\d+\.\d+")
        elif whole:
            alternatives.append(rf"{major}\.{_lt(whole)}\.\d+")
        for minor in range(whole, len(thresholds)):
            t = thresholds[minor]
            if t == math.inf:
                alternatives.append(rf"{major}\.{minor}\.\d+")
            elif t > 0:
                alternatives.append(rf"{major}\.{minor}\.{_lt(int(t))}")
    return "(?:" + "|".join(alternatives) + ")"


# =====================================================================================================
# VALIDATE
# =====================================================================================================


@rule(
    "KN-V001",
    "Object is missing apiVersion, kind or metadata.name",
    Stage.VALIDATE,
    "schema",
    Severity.HIGH,
    "Every object needs apiVersion, kind and metadata.name (or metadata.generateName).",
    "kubectl/oc reject objects without these identity fields.",
)
def _v001(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d in ctx.docs:
        if not isinstance(d.data, dict):
            yield r.finding(
                d, (), "Document is not a mapping; it cannot be a Kubernetes object.", resource=f"doc[{d.index}]"
            )
            continue
        missing = [k for k in ("apiVersion", "kind") if not d.data.get(k)]
        meta = d.data.get("metadata")
        if not isinstance(meta, dict) or not (meta.get("name") or meta.get("generateName")):
            missing.append("metadata.name")
        if missing:
            yield r.finding(d, (), f"Missing required field(s): {', '.join(missing)}.", resource=f"doc[{d.index}]")


@rule(
    "KN-V002",
    "apiVersion does not serve this kind",
    Stage.VALIDATE,
    "api",
    Severity.CRITICAL,
    "Use the apiVersion that serves this kind (see message).",
    "A kind sent to an API group/version that does not serve it fails with 'no matches for kind'. "
    "Classic example: Route is route.openshift.io/v1, not apps.openshift.io/v1 (that group serves DeploymentConfig).",
    ("k8s-deprecation-guide", "ocp-routes"),
)
def _v002(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d in ctx.docs:
        if not isinstance(d.data, dict):
            continue
        valid = KIND_API_VERSIONS.get(d.kind)
        if not valid or d.api_version in valid:
            continue
        if not claims_a_known_group(d.api_version):
            # A kind name is unique only inside its group. `Service` is core v1 AND serving.knative.dev/v1;
            # `Job` is batch/v1 AND batch.volcano.sh/v1alpha1. Firing on the name alone called a correct Knative
            # Service invalid, as a CRITICAL (G233). An unknown group is somebody else's CRD: the report already
            # says there is no bundled schema for it, and that is the honest statement.
            continue
        if removed_api(d.api_version, d.kind, "99.0") is not None:
            continue  # handled by the deprecation rules with a precise version message
        yield r.finding(d, ("apiVersion",), f"{d.kind} is not served by '{d.api_version}'. Use {' or '.join(valid)}.")


@rule(
    "KN-V003",
    "OpenShift-only API used on a non-OpenShift target",
    Stage.VALIDATE,
    "platform",
    Severity.CRITICAL,
    "Target an OpenShift platform, or replace with the upstream equivalent (Route -> Ingress/Gateway API "
    "HTTPRoute, DeploymentConfig -> Deployment, SCC -> Pod Security Admission labels).",
    "Groups such as route.openshift.io or security.openshift.io do not exist on vanilla Kubernetes.",
    ("ocp-routes", "k8s-pss"),
)
def _v003(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    if ctx.is_openshift:
        return
    for d in ctx.docs:
        g = api_group(d.api_version)
        if g in OPENSHIFT_ONLY_GROUPS:
            yield r.finding(
                d,
                ("apiVersion",),
                f"{d.kind} ({d.api_version}) only exists on OpenShift; target platform is '{ctx.platform}'.",
            )


@rule(
    "KN-V004",
    "API requires an add-on on this platform",
    Stage.VALIDATE,
    "platform",
    Severity.MEDIUM,
    "Install the add-on (or its CRDs) before applying, or remove the object.",
    "Some API groups are present by default on OpenShift but need an operator/CRDs on vanilla Kubernetes.",
)
def _v004(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d in ctx.docs:
        g = api_group(d.api_version)
        if g in ADDON_GROUPS_ON_VANILLA:
            if ctx.is_openshift and g in {"k8s.ovn.org", "monitoring.coreos.com", "operators.coreos.com"}:
                continue
            # OpenShift 4.19+ ships the standard-channel Gateway API CRDs, managed by the Ingress Operator.
            if (
                ctx.is_openshift
                and g == "gateway.networking.k8s.io"
                and (ctx.platform_version is None or parse_minor(ctx.platform_version) >= (4, 19))
            ):
                continue
            yield r.finding(d, ("apiVersion",), f"{d.kind} needs: {ADDON_GROUPS_ON_VANILLA[g]}.")


@rule(
    "KN-V005",
    "API removed in the target Kubernetes version",
    Stage.VALIDATE,
    "deprecation",
    Severity.CRITICAL,
    "Migrate to the replacement apiVersion (see message); `kube-noob fix` performs mechanical migrations.",
    "Removed APIs are rejected by the API server; the object will not apply.",
    ("k8s-deprecation-guide",),
)
def _v005(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d in ctx.docs:
        rem = removed_api(d.api_version, d.kind, ctx.k8s_version)
        if rem:
            repl = f"use {rem.replacement}" if rem.replacement else "no replacement API"
            note = f" Note: {rem.notes}." if rem.notes else ""
            yield r.finding(
                d,
                ("apiVersion",),
                f"{d.kind} {d.api_version} was removed in Kubernetes "
                f"{rem.removed_in} (target {ctx.k8s_version}); {repl}.{note}",
            )


@rule(
    "KN-V006",
    "Deprecated API in the target Kubernetes version",
    Stage.VALIDATE,
    "deprecation",
    Severity.MEDIUM,
    "Migrate before the removal release.",
    "Deprecated APIs still work but will be removed.",
    ("k8s-deprecation-guide",),
)
def _v006(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d in ctx.docs:
        dep = deprecated_api(d.api_version, d.kind, ctx.k8s_version)
        if dep:
            yield r.finding(
                d,
                ("apiVersion",),
                f"{d.kind} {d.api_version} is deprecated and is removed in "
                f"Kubernetes {dep.removed_in}; migrate to {dep.replacement or 'a supported API'}.",
            )


@rule(
    "KN-V008",
    "DeploymentConfig is deprecated",
    Stage.VALIDATE,
    "deprecation",
    Severity.MEDIUM,
    "Use apps/v1 Deployment (with image triggers via the image.openshift.io/triggers annotation if needed).",
    "DeploymentConfig (apps.openshift.io/v1) is deprecated since OpenShift 4.14.",
    ("ocp-deploymentconfig-deprecation",),
)
def _v008(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    if not ctx.is_openshift:
        return
    if ctx.platform_version and parse_minor(ctx.platform_version) < (4, 14):
        return
    for d in ctx.by_kind("DeploymentConfig"):
        yield r.finding(
            d, ("kind",), "DeploymentConfig is deprecated (OpenShift 4.14+); new workloads should use Deployment."
        )


@rule(
    "KN-V009",
    "metadata.name is not a valid DNS-1123 name",
    Stage.VALIDATE,
    "schema",
    Severity.HIGH,
    "Use lowercase alphanumerics, '-' and '.', starting and ending with an alphanumeric, max 253 chars "
    "(63 for Services, Namespaces and labels).",
    "The API server rejects invalid object names.",
)
def _v009(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d in ctx.docs:
        name = d.name
        if not name:
            continue
        label_only = d.kind in {"Service", "Namespace", "Project"}  # DNS label (Service: DNS-1035, must start a-z)
        limit = 63 if label_only else 253
        if (
            len(name) > limit
            or not DNS1123_SUBDOMAIN.match(name)
            or (label_only and "." in name)
            or (d.kind == "Service" and not name[0].isalpha())
        ):
            yield r.finding(d, ("metadata", "name"), f"'{name}' is not a valid name for {d.kind} (limit {limit}).")


@rule(
    "KN-V010",
    "Workload selector does not match its pod template labels",
    Stage.VALIDATE,
    "schema",
    Severity.CRITICAL,
    "Make spec.selector.matchLabels a subset of spec.template.metadata.labels.",
    "apps/v1 rejects workloads whose selector does not select their own template ('selector does not match "
    "template labels').",
)
def _v010(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, pt in ctx.workloads():
        if d.kind not in {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet"}:
            continue
        sel = get_path(d.data, ("spec", "selector"))
        if not isinstance(sel, dict) or not sel:
            yield r.finding(d, ("spec", "selector"), "spec.selector is required for apps/v1 workloads.")
            continue
        if not selector_matches(sel, pt.labels()):
            yield r.finding(
                d,
                ("spec", "selector"),
                f"Selector {sel.get('matchLabels') or sel} does not match template labels {pt.labels()}.",
            )


@rule(
    "KN-V011",
    "Service selects no pods in this bundle",
    Stage.VALIDATE,
    "wiring",
    Severity.MEDIUM,
    "Align Service spec.selector with the pod template labels of the workload it fronts.",
    "A Service whose selector matches no pods has no endpoints; Routes/Ingresses in front of it return 503.",
)
def _v011(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    workloads = list(ctx.workloads())
    if not workloads:
        return
    for svc in ctx.by_kind("Service"):
        sel = get_path(svc.data, ("spec", "selector"))
        if not isinstance(sel, dict) or not sel:
            continue  # headless/external services without selectors are legitimate
        ns = ctx.ns(svc)
        same_ns = [pt for d, pt in workloads if ctx.ns(d) == ns]
        if not same_ns:
            continue
        verdicts = [selector_decides({"matchLabels": sel}, pt) for pt in same_ns]
        if any(v is True for v in verdicts):
            continue
        if any(v is None for v in verdicts):
            # A component whose pod labels an operator merges in from outside this input might well be selected
            # by this Service. Reporting "no endpoints" there told the reader their working Service was broken
            # (G231), so the rule declines instead.
            ctx.cannot_decide(r.rule_id)
            continue
        yield r.finding(
            svc,
            ("spec", "selector"),
            f"Selector {sel} matches no pod template in namespace {ns}; the Service will have no endpoints.",
        )


@rule(
    "KN-V012",
    "Service targetPort name is not declared by the selected containers",
    Stage.VALIDATE,
    "wiring",
    Severity.HIGH,
    "Declare the named containerPort or use the numeric port.",
    "A named targetPort that no selected container exposes results in a Service without ready endpoints.",
)
def _v012(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    workloads = list(ctx.workloads())
    for svc in ctx.by_kind("Service"):
        sel = get_path(svc.data, ("spec", "selector"))
        if not isinstance(sel, dict) or not sel:
            continue
        pods = [
            pt
            for d, pt in workloads
            if ctx.ns(d) == ctx.ns(svc) and selector_matches({"matchLabels": sel}, pt.labels())
        ]
        if not pods:
            continue
        names = {
            str(p.get("name"))
            for pt in pods
            for c in containers(pt, include_init=False)
            for p in (c.container.get("ports") or [])
            if isinstance(p, dict) and p.get("name")
        }
        for i, port in enumerate(get_path(svc.data, ("spec", "ports")) or []):
            tp = port.get("targetPort") if isinstance(port, dict) else None
            if isinstance(tp, str) and not tp.isdigit() and tp not in names:
                yield r.finding(
                    svc,
                    ("spec", "ports", i, "targetPort"),
                    f"targetPort '{tp}' is not a named "
                    f"containerPort of the selected pods (named ports: {sorted(names) or 'none'}).",
                )


@rule(
    "KN-V023",
    "Service numeric targetPort is not a declared containerPort",
    Stage.VALIDATE,
    "wiring",
    Severity.LOW,
    "Point the Service at a port these containers declare, or declare the one it points at.",
    "A numeric targetPort outside the ports the selected containers declare is usually a typo, though Kubernetes "
    "does not require the declaration.",
)
def _v023(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    """The numeric half of KN-V012, and it has to be weaker.

    A named targetPort must resolve or the Service gets no endpoints, which is why KN-V012 is HIGH. A numeric one
    needs no declaration at all: ``containerPort`` is informational, so a Service pointing at 8080 works whenever
    something listens on 8080. Reporting every undeclared numeric port would therefore fire on correct
    repositories. The signal this rule reports is narrower: these containers DO declare ports, and the Service
    points outside that set, so either the declaration or the Service is wrong. Where the containers declare no
    ports, there is no signal and the rule says nothing.
    """
    workloads = list(ctx.workloads())
    for svc in ctx.by_kind("Service"):
        sel = get_path(svc.data, ("spec", "selector"))
        if not isinstance(sel, dict) or not sel:
            continue  # endpoints come from an EndpointSlice this bundle need not carry
        pods = [
            pt
            for d, pt in workloads
            if ctx.ns(d) == ctx.ns(svc) and selector_matches({"matchLabels": sel}, pt.labels())
        ]
        if not pods:
            continue  # the claim needs the pod spec; without it there is nothing to compare
        # Init containers are excluded deliberately: a Service never reaches one, so a port declared only there
        # would clear a target the running containers do not serve.
        declared = {
            int(p["containerPort"])
            for pt in pods
            for c in containers(pt, include_init=False)
            for p in (c.container.get("ports") or [])
            if isinstance(p, dict) and isinstance(p.get("containerPort"), int)
        }
        if not declared:
            continue  # the declaration is optional, so its absence is not evidence of anything
        for i, port in enumerate(get_path(svc.data, ("spec", "ports")) or []):
            if not isinstance(port, dict):
                continue
            tp = port.get("targetPort")
            if tp is None:
                # An absent targetPort is not an absent target: it defaults to `port`, so the same mismatch is
                # there and reporting only the explicit case would read the default as safe.
                target, field, prefix = port.get("port"), "port", "no targetPort, so it defaults to port "
            elif isinstance(tp, int) or (isinstance(tp, str) and tp.isdigit()):
                target, field, prefix = tp, "targetPort", "targetPort "
            else:
                continue  # a named target belongs to KN-V012, and two findings for one mistake is one too many
            if not isinstance(target, int) and not (isinstance(target, str) and target.isdigit()):
                continue  # a malformed port is the schema rule's to report
            if int(target) in declared:
                continue
            yield r.finding(
                svc,
                ("spec", "ports", i, field),
                f"{prefix}{int(target)}, which is not a declared containerPort of the selected pods "
                f"(declared: {', '.join(str(x) for x in sorted(declared))}). Kubernetes does not require the "
                "declaration, so the Service still works if a container listens there -- this is a likely typo, "
                "not proof of a broken Service.",
            )


@rule(
    "KN-V014",
    "Duplicate object in bundle",
    Stage.VALIDATE,
    "schema",
    Severity.HIGH,
    "Remove or rename the duplicate; the later object silently overwrites the earlier one on apply.",
    "Two objects with the same kind, namespace and name collide.",
)
def _v014(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    seen: dict[tuple[str, str, str], Document] = {}
    for d in ctx.docs:
        if not d.kind or not d.name:
            continue
        key = (d.kind, d.namespace or "", d.name)
        if key in seen:
            yield r.finding(d, ("metadata", "name"), f"Duplicates doc[{seen[key].index}] ({d.ref()}).")
        else:
            seen[key] = d


@rule(
    "KN-V015",
    "EgressFirewall must be named 'default'",
    Stage.VALIDATE,
    "network",
    Severity.HIGH,
    "Rename the EgressFirewall to 'default' and keep one per namespace.",
    "OVN-Kubernetes accepts a single EgressFirewall per namespace and it must be named 'default'; other names "
    "are rejected/ignored.",
    ("ocp-egressfirewall",),
)
def _v015(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    per_ns: dict[str, int] = {}
    for d in ctx.by_kind("EgressFirewall"):
        per_ns[ctx.ns(d)] = per_ns.get(ctx.ns(d), 0) + 1
        if d.name != "default":
            yield r.finding(d, ("metadata", "name"), f"EgressFirewall is named '{d.name}', must be 'default'.")
    for ns, n in per_ns.items():
        if n > 1:
            yield r.finding(
                None,
                (),
                f"{n} EgressFirewall objects in namespace {ns}; only one is allowed.",
                resource=f"EgressFirewall/{ns}/*",
            )


@rule(
    "KN-V016",
    "Route TLS configuration is invalid",
    Stage.VALIDATE,
    "network",
    Severity.HIGH,
    "termination must be edge, passthrough or reencrypt; passthrough supports insecureEdgeTerminationPolicy "
    "None or Redirect only; certificates are not allowed with passthrough.",
    "The router rejects Routes with invalid TLS settings.",
    ("ocp-routes",),
)
def _v016(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d in ctx.by_kind("Route"):
        tls = get_path(d.data, ("spec", "tls"))
        if not isinstance(tls, dict):
            continue
        term = tls.get("termination")
        if term not in {"edge", "passthrough", "reencrypt"}:
            yield r.finding(d, ("spec", "tls", "termination"), f"Invalid termination {term!r}.")
            continue
        policy = tls.get("insecureEdgeTerminationPolicy")
        if policy not in {None, "", "None", "Redirect", "Allow"}:
            yield r.finding(d, ("spec", "tls", "insecureEdgeTerminationPolicy"), f"Invalid policy {policy!r}.")
        if term == "passthrough" and policy == "Allow":
            yield r.finding(
                d,
                ("spec", "tls", "insecureEdgeTerminationPolicy"),
                "passthrough Routes cannot use insecureEdgeTerminationPolicy: Allow.",
            )
        if term == "passthrough" and any(tls.get(k) for k in ("certificate", "key", "caCertificate")):
            yield r.finding(
                d, ("spec", "tls"), "passthrough Routes must not carry certificates; the backend terminates TLS."
            )


@rule(
    "KN-V017",
    "MachineConfig is not a customer lever on ROSA",
    Stage.VALIDATE,
    "platform",
    Severity.HIGH,
    "Use the managed interfaces instead: `rosa create kubeletconfig` for kubelet tuning and machine pools "
    "(`rosa create/edit machinepool`) for node sizing, labels and taints.",
    "ROSA is a managed service. On ROSA with HCP the Machine Config Operator does not run in the hosted cluster "
    "(HyperShift applies node configuration from the management side via NodePool config), and Red Hat's guidance "
    "is not to rely on customer-owned MachineConfig changes on ROSA.",
    ("rosa-hcp-architecture",),
)
def _v017(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    if not ctx.is_rosa:
        return
    for d in ctx.by_kind("MachineConfig", "MachineConfigPool"):
        yield r.finding(d, ("kind",), f"{d.kind} is not a supported customer lever on {ctx.platform}.")


@rule(
    "KN-V018",
    "Duplicate key in a YAML mapping",
    Stage.VALIDATE,
    "schema",
    Severity.CRITICAL,
    "Remove the duplicate key and merge its fields into a single mapping.",
    "YAML parsers keep the last value silently, so the object you review is not the one you wrote; kubectl's strict "
    "field validation (the default) rejects duplicate fields outright.",
)
def _v018(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d in ctx.docs:
        for path, line in d.duplicate_keys:
            f = r.finding(d, path, f"Duplicate key '{fmt_path(path)}' (second occurrence on line {line}).")
            f.line = line
            yield f


_RETIRED = (
    "the kubernetes/ingress-nginx project is retired: best-effort maintenance ended in March 2026, there are no "
    "further releases or bug fixes, and the repository was archived on 2026-03-24."
)


@rule(
    "KN-V019",
    "Ingress targets the retired ingress-nginx",
    Stage.VALIDATE,
    "deprecation",
    Severity.MEDIUM,
    "Move to a Gateway API implementation (Gateway and HTTPRoute; on OpenShift 4.19+ the Ingress Operator manages "
    "Gateway API) or to a maintained ingress controller, and drop the nginx.ingress.kubernetes.io annotations.",
    "ingress-nginx stopped receiving releases and bug fixes when the project was archived on 2026-03-24, so every "
    "later vulnerability stays unfixed; the project itself asks users to identify a Gateway API implementation.",
    ("ingress-nginx-retired",),
)
def _v019(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d in ctx.by_kind("Ingress"):
        ann = get_path(d.data, ("metadata", "annotations"))
        ann = ann if isinstance(ann, dict) else {}
        nginx = sorted(str(k) for k in ann if str(k).startswith(INGRESS_NGINX_ANNOTATION_PREFIX))
        if nginx:
            more = ", ..." if len(nginx) > 1 else ""
            yield r.finding(
                d,
                ("metadata", "annotations", nginx[0]),
                f"Ingress carries {len(nginx)} ingress-nginx annotation(s) ({nginx[0]}{more}); " + _RETIRED,
            )
            continue
        if str(get_path(d.data, ("spec", "ingressClassName")) or "").strip() == INGRESS_NGINX_CLASS:
            path: PathT = ("spec", "ingressClassName")
        elif str(ann.get("kubernetes.io/ingress.class", "")).strip() == INGRESS_NGINX_CLASS:
            path = ("metadata", "annotations", "kubernetes.io/ingress.class")
        else:
            continue
        yield r.finding(
            d,
            path,
            f"Ingress names the ingress class '{INGRESS_NGINX_CLASS}' (ingress-nginx's class name); if ingress-nginx "
            "serves it, " + _RETIRED,
            severity=Severity.LOW,
        )
    for d, _pt, c in _containers(ctx):
        image = c.container.get("image")
        if isinstance(image, str) and is_ingress_nginx_image(image):
            yield r.finding(
                d,
                (*c.path, "image"),
                f"Container '{c.name}' runs the ingress-nginx controller image '{image}'; " + _RETIRED,
            )


# =====================================================================================================
# VALIDATE - Dynamic Resource Allocation (DRA)
# =====================================================================================================
# DRA went GA in Kubernetes 1.34 and the claim wiring is three names deep: a container names a pod-level
# claim, which names a ResourceClaim or a template. Both checks below mirror upstream's own object validation
# (`pkg/apis/core/validation/validation.go`: `validateResourceClaimNames`, `validatePodResourceClaim`), which
# the bundled OpenAPI schemas cannot express -- one is a cross-field reference, the other a mutual exclusion
# the schema declares no `oneOf` for. So the API server refuses these manifests and nothing before
# `kubectl apply` says so. That is the whole gap these two close (G192): both are decided inside one
# document, so neither needs the bundle and `partial_bundle` does not silence them.


def _declared_pod_claims(pt: PodTemplate) -> list[str]:
    """``spec.resourceClaims[].name``, in order, skipping entries that are not name-carrying mappings."""
    claims = pt.spec.get("resourceClaims")
    if not isinstance(claims, list):
        return []
    out: list[str] = []
    for item in claims:
        if isinstance(item, dict) and isinstance(item.get("name"), str) and item["name"]:
            out.append(str(item["name"]))
    return out


@rule(
    "KN-V020",
    "Container claims a resource the Pod does not declare",
    Stage.VALIDATE,
    "wiring",
    Severity.HIGH,
    "Name a claim the Pod declares: every resources.claims[].name has to match a spec.resourceClaims[].name.",
    "A container's resources.claims entry refers to a pod-level claim by name, so a name the Pod never declares "
    "resolves to nothing. The API server refuses the object, and a typo here reads at a glance as a device "
    "request that was made.",
)
def _v020(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, pt, c in _resource_containers(ctx):
        resources = c.container.get("resources")
        claims = resources.get("claims") if isinstance(resources, dict) else None
        if not isinstance(claims, list):
            continue
        declared = _declared_pod_claims(pt)
        for i, item in enumerate(claims):
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            if not isinstance(name, str) or not name or name in declared:
                continue
            where = f"the Pod declares {', '.join(declared)}" if declared else "the Pod declares none"
            yield r.finding(
                d,
                (*c.path, "resources", "claims", i, "name"),
                f"Container '{c.name}' claims {name!r}, which is not one of the Pod's resource claims: {where}.",
            )


@rule(
    "KN-V021",
    "Pod resource claim names no source, or two",
    Stage.VALIDATE,
    "wiring",
    Severity.HIGH,
    "Set exactly one of resourceClaimName (share a ResourceClaim that already exists) or "
    "resourceClaimTemplateName (give this Pod its own, created from a ResourceClaimTemplate).",
    "A spec.resourceClaims entry has to name exactly one source. With neither there is no device to allocate, "
    "and with both which one applies is undefined; the API server refuses the object either way.",
)
def _v021(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, pt in ctx.workloads():
        claims = pt.spec.get("resourceClaims")
        if not isinstance(claims, list):
            continue
        seen: set[str] = set()
        for i, item in enumerate(claims):
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            label = repr(str(name)) if isinstance(name, str) and name else f"resourceClaims[{i}]"
            path: PathT = (*pt.path, "resourceClaims", i)
            if isinstance(name, str) and name:
                if name in seen:
                    yield r.finding(
                        d,
                        path,
                        f"Pod declares the resource claim {label} more than once. Claim names identify an entry "
                        "for the containers that reference it, so they have to be unique within the Pod; the API "
                        "server refuses this object.",
                    )
                    continue
                seen.add(name)
            # PRESENCE, not truthiness. Upstream tests whether the pointer is set, and an empty string decodes
            # to a non-nil *string -- so `resourceClaimName: ""` beside a template name really is "both", and
            # reading it as unset let that case through. An empty name is its own error, not a missing source.
            sources = {k: item[k] for k in _CLAIM_SOURCE_KINDS if k in item and item[k] is not None}
            if len(sources) == 2:
                yield r.finding(
                    d,
                    path,
                    f"Pod resource claim {label} sets both resourceClaimName and resourceClaimTemplateName; "
                    "exactly one source may be named.",
                )
            elif not sources:
                yield r.finding(
                    d,
                    path,
                    f"Pod resource claim {label} names neither resourceClaimName nor resourceClaimTemplateName, "
                    "so there is no device for it to allocate.",
                )
            else:
                field_name, value = next(iter(sources.items()))
                if isinstance(value, str) and not value:
                    yield r.finding(
                        d,
                        path,
                        f"Pod resource claim {label} sets {field_name} to an empty name. The field is set, so "
                        "this is not a missing source; it names an object that cannot exist, because an empty "
                        "string is not a valid name.",
                    )


# A pod-level claim names its source by one of two fields, each naming a different kind.
_CLAIM_SOURCE_KINDS = {"resourceClaimName": "ResourceClaim", "resourceClaimTemplateName": "ResourceClaimTemplate"}
# Upstream `DRAAdminNamespaceLabelKey`: set to the string "true" (case-sensitive) on a namespace, it is what
# permits `adminAccess: true` in that namespace's ResourceClaims and ResourceClaimTemplates at all.
_ADMIN_NS_LABEL = "resource.kubernetes.io/admin-access"
# ResourceClaim carries the request tree at spec.devices; ResourceClaimTemplate wraps it one deeper.
_REQUEST_ROOTS: tuple[tuple[str, PathT], ...] = (
    ("ResourceClaim", ("spec",)),
    ("ResourceClaimTemplate", ("spec", "spec")),
)
# v1beta1 FLATTENS the request: adminAccess and deviceClassName sit directly on it, where v1 and v1beta2 put
# them under `exactly`. Upstream normalises between the two shapes for exactly this reason, and the bundled
# schemas still serve v1beta1, so reading only `exactly` missed every v1beta1 claim. The group-version gate
# matters in the other direction too: on v1 the request has no adminAccess property at all, so a key of that
# name there is a schema error for KN-V007 to report, not this field.
_FLATTENED_GROUP_VERSION = "resource.k8s.io/v1beta1"


@rule(
    "KN-C015",
    "Pod names a resource claim that is not in this bundle",
    Stage.AUDIT,
    "wiring",
    Severity.HIGH,
    "Add the ResourceClaim or ResourceClaimTemplate to this bundle, in the Pod's own namespace, or point the "
    "entry at one that is already there.",
    "A pod-level claim names a ResourceClaim or a ResourceClaimTemplate in the Pod's own namespace. If no such "
    "object exists the Pod is admitted and then stays Pending, so the failure arrives after the deploy rather "
    "than during it.",
)
def _c015(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    if ctx.partial_bundle:
        # a claim that lives in a file you did not pass is not a missing claim (G186)
        ctx.cannot_decide(r.rule_id)
        return
    present: dict[tuple[str, str], set[str]] = {}
    for kind in _CLAIM_SOURCE_KINDS.values():
        for d in ctx.by_kind(kind):
            name = get_path(d.data, ("metadata", "name"))
            if isinstance(name, str) and name:
                present.setdefault((kind, ctx.ns(d)), set()).add(name)
    for d, pt in ctx.workloads():
        claims = pt.spec.get("resourceClaims")
        if not isinstance(claims, list):
            continue
        ns = ctx.ns(d)
        names = [i["name"] for i in claims if isinstance(i, dict) and isinstance(i.get("name"), str)]
        duplicated = {n for n in names if names.count(n) > 1}
        for i, item in enumerate(claims):
            if not isinstance(item, dict):
                continue
            # A duplicate claim name, and an entry naming two sources, are both refused by the API server, so
            # the Pod never reaches Pending and "is admitted and then stays Pending" would be a false sentence.
            # KN-V021 owns those two shapes; skipping them here also stops two findings on one entry from
            # sharing a name-keyed identity, which a baseline would then collapse into one.
            if isinstance(item.get("name"), str) and item["name"] in duplicated:
                continue
            if len([k for k in _CLAIM_SOURCE_KINDS if k in item and item[k] is not None]) == 2:
                continue
            for field_name, kind in _CLAIM_SOURCE_KINDS.items():
                target = item.get(field_name)
                if not isinstance(target, str) or not target:
                    continue
                if target in present.get((kind, ns), set()):
                    continue
                yield r.finding(
                    d,
                    (*pt.path, "resourceClaims", i, field_name),
                    f"Pod resource claim names the {kind} {target!r}, which no document in this bundle defines in "
                    f"namespace {ns}. The Pod is admitted and then stays Pending.",
                )


@rule(
    "KN-S031",
    "Device claim requests administrative access",
    Stage.AUDIT,
    "security",
    Severity.HIGH,
    "Drop adminAccess unless this really is a monitoring or device-management workload, and keep such claims in "
    'a namespace labelled resource.kubernetes.io/admin-access: "true" that only operators can write to.',
    "A request with adminAccess ignores every ordinary claim to the device with respect to access modes and "
    "resource allocations, so the workload reaches devices another tenant holds exclusively. It is the DRA "
    "equivalent of a privileged container, and the only thing standing between it and any namespace is a label.",
)
def _s031(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    in_bundle: set[str] = set()
    labelled: set[str] = set()
    for d in ctx.by_kind("Namespace"):
        name = get_path(d.data, ("metadata", "name"))
        if not isinstance(name, str) or not name:
            continue
        in_bundle.add(name)
        labels = get_path(d.data, ("metadata", "labels"))
        if isinstance(labels, dict) and labels.get(_ADMIN_NS_LABEL) == "true":
            labelled.add(name)
    for kind, base in _REQUEST_ROOTS:
        for d in ctx.by_kind(kind):
            flattened = str(get_path(d.data, ("apiVersion",)) or "") == _FLATTENED_GROUP_VERSION
            requests = get_path(d.data, (*base, "devices", "requests"))
            if not isinstance(requests, list):
                continue
            for i, req in enumerate(requests):
                if not isinstance(req, dict):
                    continue
                # Only ExactDeviceRequest carries adminAccess; DeviceSubRequest under firstAvailable omits it
                # on purpose, so a key of that name there is not the API field and means nothing.
                if flattened:
                    holder: dict[str, Any] | None = req
                    tail: PathT = ()
                else:
                    exactly = req.get("exactly")
                    holder = exactly if isinstance(exactly, dict) else None
                    tail = ("exactly",)
                if holder is None or holder.get("adminAccess") is not True:
                    continue
                ns = ctx.ns(d)
                where = f"request '{req.get('name')}'" if isinstance(req.get("name"), str) else f"request {i}"
                path: PathT = (*base, "devices", "requests", i, *tail, "adminAccess")
                if ns in in_bundle and ns not in labelled:
                    yield r.finding(
                        d,
                        path,
                        f"{kind} {where} sets adminAccess: true, and namespace {ns} in this bundle does not carry "
                        f'{_ADMIN_NS_LABEL}: "true". The API server will refuse this object, so the claim does not '
                        "exist and nothing that depends on it will schedule.",
                    )
                else:
                    yield r.finding(
                        d,
                        path,
                        f"{kind} {where} sets adminAccess: true, so it ignores every ordinary claim to the device "
                        "and reaches devices another workload holds exclusively.",
                    )


@rule(
    "KN-V022",
    "Resource claims set at pod level, where they are forbidden",
    Stage.VALIDATE,
    "schema",
    Severity.HIGH,
    "Move the claims onto the containers that use the devices: resources.claims belongs on a container, and "
    "spec.resourceClaims is where the Pod declares them.",
    "Pod-level resources carries no claims: the API server forbids the field outright, whatever names are in "
    "it. The schema accepts it, because PodSpec.resources really does have a claims property, so nothing before "
    "apply says the object will be refused.",
)
def _v022(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, pt in ctx.workloads():
        resources = pt.spec.get("resources")
        if not isinstance(resources, dict):
            continue
        # Upstream tests `spec.Resources.Claims != nil`, so an empty list is set and refused while an explicit
        # null is not set at all. Presence of a non-null value is the condition, not a non-empty one.
        if "claims" not in resources or resources["claims"] is None:
            continue
        yield r.finding(
            d,
            (*pt.path, "resources", "claims"),
            "spec.resources.claims is set, and claims may not be set for resources at pod-level: the API server "
            "refuses this object regardless of which claims are named.",
        )


# =====================================================================================================
# AUDIT - security
# =====================================================================================================


@rule(
    "KN-C016",
    "Namespace has workloads but no ResourceQuota or LimitRange",
    Stage.CALIBRATE,
    "resources",
    Severity.LOW,
    "Add a ResourceQuota for the namespace's aggregate limits and a LimitRange for per-container defaults, or "
    "confirm a ClusterResourceQuota or a cluster default already covers it.",
    "Without a quota one namespace can take the cluster's schedulable capacity, and without a LimitRange a "
    "container that declares no limits inherits none. A ClusterResourceQuota or a cluster-wide default can "
    "supply either, and no manifest in the namespace shows that, so this is advisory.",
)
def _c016(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    if ctx.partial_bundle:
        # The namespace's ResourceQuota and LimitRange were not passed, so their absence here means nothing.
        ctx.cannot_decide(r.rule_id)
        return
    quota_ns = {ctx.ns(d) for d in ctx.by_kind("ResourceQuota")}
    limit_ns = {ctx.ns(d) for d in ctx.by_kind("LimitRange")}
    # An object with no `metadata.namespace` lands wherever it is applied, so a bundle carrying one is
    # ambiguous rather than missing it -- the kustomize and `apply -n` shape. Claiming "none in this bundle"
    # about a bundle that contains one is the false statement this rule's hedging exists to avoid.
    any_quota = "<default>" in quota_ns or bool(ctx.by_kind("ClusterResourceQuota"))
    any_limit = "<default>" in limit_ns
    # The remediation tells the reader to confirm a ClusterResourceQuota covers it; one in the same bundle is
    # that confirmation. Presence is enough here: matching its selector is a finer answer than the message
    # claims, and over-claiming is the failure being fixed.
    # Only namespaces this bundle DECLARES. A workload whose Namespace is managed elsewhere has its quota
    # managed elsewhere too, and firing there would report nearly every application repository for an object
    # it is not responsible for. If you ship the Namespace, you own its guardrails.
    declared = {
        name
        for d in ctx.by_kind("Namespace")
        if isinstance(name := get_path(d.data, ("metadata", "name")), str) and name
    }
    flagged: set[str] = set()
    for d, _pt in ctx.workloads():
        ns = ctx.ns(d)
        # Every workload kind, not just the long-running ones. A bare Pod was reported and a recurring
        # CronJob was not, which is backwards: a runaway CronJob is the textbook reason a namespace needs
        # `count/jobs.batch`, and a Job's pod inherits no limits just as a Deployment's does.
        if ns in flagged or ns not in declared or platform_owned_namespace(ctx, ns):
            continue
        missing = [
            label
            for label, have, blanket in (
                ("ResourceQuota", quota_ns, any_quota),
                ("LimitRange", limit_ns, any_limit),
            )
            if ns not in have and not blanket
        ]
        if not missing:
            continue
        flagged.add(ns)
        yield r.finding(
            d,
            ("metadata",),
            f"Namespace {ns} has workloads and no {' or '.join(missing)} in this bundle. A "
            "ClusterResourceQuota or a cluster default may still cover it; this bundle cannot show that.",
        )


@rule(
    "KN-S033",
    "MachineConfigPool is paused",
    Stage.AUDIT,
    "platform",
    Severity.MEDIUM,
    'Unpause the pool (oc patch machineconfigpool/<name> --type merge -p \'{"spec":{"paused":false}}\') once '
    "the maintenance that needed it is over, and track the pause so it cannot be forgotten.",
    "A paused MachineConfigPool stops generating a new desiredMachineConfig and stops updating machines, so "
    "every node in the pool keeps the OS, kubelet and container runtime it has -- including their unpatched "
    "flaws -- until the pool is unpaused. Pausing is a legitimate maintenance step; leaving it paused is how a "
    "cluster silently stops receiving them.",
)
def _s033(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d in ctx.by_kind("MachineConfigPool"):
        if api_group(str(d.data.get("apiVersion", ""))) != "machineconfiguration.openshift.io":
            continue  # other APIs can use the kind; this rule is about OpenShift's pools
        spec = d.data.get("spec") if isinstance(d.data, dict) else None
        if not isinstance(spec, dict) or spec.get("paused") is not True:
            continue
        name = get_path(d.data, ("metadata", "name"))
        yield r.finding(
            d,
            ("spec", "paused"),
            f"MachineConfigPool {name if isinstance(name, str) else '<unnamed>'} is paused, so no machine in it "
            "receives a new rendered MachineConfig: OS, kubelet and runtime updates stop for every node in the "
            "pool until it is unpaused.",
        )


@rule(
    "KN-S034",
    "Operator Subscription upgrades without review",
    Stage.AUDIT,
    "supply-chain",
    Severity.MEDIUM,
    "Set spec.installPlanApproval: Manual and approve each InstallPlan deliberately, or record that automatic "
    "upgrades on this channel are an accepted risk for this operator.",
    "An OLM Subscription with automatic approval installs whatever the channel publishes next, with no review "
    "of what changed, and the field is Automatic unless it explicitly says Manual -- so omitting it chooses "
    "automatic upgrades rather than deferring the decision.",
)
def _s034(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d in ctx.by_kind("Subscription"):
        if api_group(str(d.data.get("apiVersion", ""))) != "operators.coreos.com":
            continue  # other APIs use the kind too; this rule is about OLM
        spec = d.data.get("spec") if isinstance(d.data, dict) else None
        spec = spec if isinstance(spec, dict) else {}
        approval = spec.get("installPlanApproval")
        if isinstance(approval, str) and approval == "Manual":
            continue
        name = get_path(d.data, ("metadata", "name"))
        name = name if isinstance(name, str) else "<unnamed>"
        channel = spec.get("channel")
        where: PathT = ("spec", "installPlanApproval") if approval is not None else ("spec",)
        stated = f"installPlanApproval: {approval!r}" if approval is not None else "no installPlanApproval"
        yield r.finding(
            d,
            where,
            f"Subscription {name} has {stated}, so OLM installs whatever "
            f"{f'channel {channel} ' if isinstance(channel, str) and channel else 'the channel '}publishes next "
            "without anyone approving the InstallPlan. Absent, the field means Automatic: upstream returns "
            "Manual only when it is set to Manual.",
        )


# Pod Security admission reads three labels per mode off the NAMESPACE, not off the workload. The constants are
# upstream's (`staging/src/k8s.io/pod-security-admission/api/constants.go`): the prefix, and the three levels.
PSA_ENFORCE_LABEL = "pod-security.kubernetes.io/enforce"
PSA_LEVELS = ("privileged", "baseline", "restricted")
# `SYSTEM_NAMESPACES` mixes the two platforms: `openshift` belongs to OpenShift and the `kube-*` ones to every
# cluster. Skipping `openshift` and `openshift-*` on vanilla Kubernetes gave an ordinary namespace on EKS or
# GKE a silent pass, because the reason for the skip -- OpenShift owns those namespaces and its Pod Security
# syncer is permanently off for them -- is an OpenShift fact (G204).
_PLATFORM_NAMESPACES = frozenset({"kube-system", "kube-public", "kube-node-lease", "default"})


def platform_owned_namespace(ctx: AuditContext, name: str) -> bool:
    """True when the platform owns this namespace, so its guardrails are not the author's to set."""
    if name in _PLATFORM_NAMESPACES:
        return True
    return ctx.is_openshift and (name == "openshift" or name.startswith("openshift-"))


@rule(
    "KN-S032",
    "Namespace does not enforce a pod security level",
    Stage.AUDIT,
    "security",
    Severity.MEDIUM,
    "Set pod-security.kubernetes.io/enforce: restricted on the Namespace (baseline where a workload genuinely "
    "needs more), and pin pod-security.kubernetes.io/enforce-version so a cluster upgrade cannot change what "
    "the label means.",
    "Pod Security admission is configured per namespace by a label. Without it the namespace runs at whatever "
    "the cluster's AdmissionConfiguration default is, which is privileged on a default install -- so the "
    "namespace enforces nothing, and no manifest in it will say so.",
)
def _s032(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    seen: set[str] = set()
    for d in ctx.by_kind("Namespace"):
        name = get_path(d.data, ("metadata", "name"))
        if not isinstance(name, str) or not name:
            continue  # KN-V007 already refuses the object, and a nameless namespace is not actionable here
        if platform_owned_namespace(ctx, name) or name in seen:
            continue
        seen.add(name)
        labels = get_path(d.data, ("metadata", "labels"))
        level = labels.get(PSA_ENFORCE_LABEL) if isinstance(labels, dict) else None
        if level is not None and not (isinstance(level, str) and level in PSA_LEVELS):
            # The enum is exactly the three lowercase strings, so `Privileged` is not a level. Reporting
            # nothing here made the rule QUIETER about a namespace that looks privileged than about one with
            # no label at all. What the cluster does with an invalid value is not claimed.
            yield r.finding(
                d,
                ("metadata", "labels", PSA_ENFORCE_LABEL),
                f"Namespace {name} sets {PSA_ENFORCE_LABEL}: {level!r}, which is not one of Pod Security's "
                "levels -- they are privileged, baseline or restricted, lower-case. The namespace does not "
                "enforce the level this label appears to name.",
            )
            continue
        if level == "privileged":
            yield r.finding(
                d,
                ("metadata", "labels", PSA_ENFORCE_LABEL),
                f"Namespace {name} sets {PSA_ENFORCE_LABEL}: privileged, which is Pod Security's "
                "no-restrictions level: every pod in it may run as root, share host namespaces and mount host "
                "paths, whatever its own securityContext says.",
                severity=Severity.HIGH,
            )
            continue
        if level is not None:
            continue  # baseline or restricted is a judgement about the workload, not a defect
        if ctx.is_openshift:
            # OpenShift's label syncer sets `warn` and `audit` from the SCCs the namespace's service accounts
            # can use, and deliberately NOT `enforce`: the platform enforces the privileged profile globally
            # and leaves real enforcement to SCCs. Reporting the absent label here would report the platform's
            # own design as a defect, which is absence read as a defect (G193).
            continue
        yield r.finding(
            d,
            ("metadata",),
            f"Namespace {name} sets no {PSA_ENFORCE_LABEL} label, so the level enforced for it is the "
            "cluster's AdmissionConfiguration default -- privileged on a default install, and not something "
            "these manifests show. Set the label to say what this namespace enforces rather than inheriting "
            "an answer the repository cannot see.",
        )


DANGEROUS_CAPS = frozenset(
    {
        "ALL",
        "SYS_ADMIN",
        "NET_ADMIN",
        "SYS_PTRACE",
        "SYS_MODULE",
        "DAC_READ_SEARCH",
        "NET_RAW",
        "SYS_RAWIO",
        "SYS_BOOT",
        "MAC_ADMIN",
        "MAC_OVERRIDE",
        "BPF",
        "PERFMON",
        "SYS_CHROOT",
        "SETFCAP",
        "SYS_TIME",
        "SYSLOG",
        "DAC_OVERRIDE",
        "LINUX_IMMUTABLE",
    }
)
PSS_RESTRICTED_ALLOWED_ADD = frozenset({"NET_BIND_SERVICE"})
SENSITIVE_ENV = re.compile(
    r"(PASS(WORD|WD)?|SECRET|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY|CREDENTIAL|ACCESS[_-]?KEY)", re.IGNORECASE
)
RUNTIME_SOCKETS = ("docker.sock", "containerd.sock", "crio.sock", "cri-dockerd.sock")
# --password=x / --token x / password=x style arguments (group 1: dashes, group 3: inline value). CREDENTIAL_FLAG_NAME
# and EMBEDDED_CREDENTIAL are written for RE2 too: kube_noob.generate.policies puts them into admission CEL.
CREDENTIAL_FLAG_NAME = r"[a-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[-_]?key|access[-_]?key|credentials?)"
_SECRET_FLAG = re.compile(r"(?i)^(-{1,2})?(" + CREDENTIAL_FLAG_NAME + r")(?:[=:](.+))?$")
EMBEDDED_CREDENTIAL = (
    r"://[^:/\s@]+:[^@/\s$]+@|-----BEGIN [A-Z ]*PRIVATE KEY-----|\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"
    r"|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
)
_EMBEDDED_SECRET = re.compile(EMBEDDED_CREDENTIAL)


def _is_reference(value: str) -> bool:
    v = value.strip()
    return v.startswith(("$(", "${")) or v in {"", "-", "***", "<redacted>"}


def _secret_flag_value(arg: str) -> bool:
    m = _SECRET_FLAG.match(arg.strip())
    return bool(m and m.group(3) and not _is_reference(m.group(3)))


def _bare_secret_flag(arg: str) -> bool:
    m = _SECRET_FLAG.match(arg.strip())
    return bool(m and m.group(1) and m.group(3) is None)


def _containers(ctx: AuditContext) -> Iterator[tuple[Document, PodTemplate, ContainerRef]]:
    for d, pt in ctx.workloads():
        for c in containers(pt):
            yield d, pt, c


def _resource_containers(ctx: AuditContext) -> Iterator[tuple[Document, PodTemplate, ContainerRef]]:
    """App and init containers: the API refuses resources on ephemeral (debug) containers, so they cannot be fixed."""
    for d, pt in ctx.workloads():
        for c in containers(pt, ephemeral=False):
            yield d, pt, c


@rule(
    "KN-S001",
    "Privileged container",
    Stage.AUDIT,
    "security",
    Severity.CRITICAL,
    "Remove securityContext.privileged; grant only the specific capability required.",
    "A privileged container has full access to the host (all devices, all capabilities). On OpenShift it is "
    "rejected unless the ServiceAccount is granted the 'privileged' SCC.",
    ("k8s-pss", "ocp-scc"),
    ("Privileged Container",),
)
def _s001(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, _pt, c in _containers(ctx):
        sc = c.container.get("securityContext")
        if isinstance(sc, dict) and sc.get("privileged") is True:
            yield r.finding(d, (*c.path, "securityContext", "privileged"), f"Container '{c.name}' is privileged.")


@rule(
    "KN-S002",
    "Privilege escalation not disabled",
    Stage.AUDIT,
    "security",
    Severity.MEDIUM,
    "Set securityContext.allowPrivilegeEscalation: false on every container.",
    "Required by the Pod Security 'restricted' profile; prevents setuid binaries from gaining privileges. "
    "OpenShift's restricted-v2 SCC (default for new 4.11+ installs) defaults it to false and rejects an explicit "
    "true; clusters upgraded from 4.10 or earlier may still admit pods under the legacy 'restricted' SCC.",
    ("k8s-pss", "ocp-scc"),
    ("Container with privilege escalation allowed",),
)
def _s002(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, _pt, c in _containers(ctx):
        raw_sc = c.container.get("securityContext")
        sc: dict[str, Any] = raw_sc if isinstance(raw_sc, dict) else {}
        val = sc.get("allowPrivilegeEscalation")
        path = (*c.path, "securityContext", "allowPrivilegeEscalation")
        if val is True:
            yield r.finding(
                d, path, f"Container '{c.name}' explicitly allows privilege escalation.", severity=Severity.HIGH
            )
        elif val is None:
            # restricted-v2 (new 4.11+ installs) defaults it to false; clusters upgraded from <=4.10 still
            # admit pods under the legacy 'restricted' SCC, which does not.
            sev = Severity.LOW if ctx.is_openshift else Severity.MEDIUM
            yield r.finding(
                d, path, f"Container '{c.name}' does not set allowPrivilegeEscalation: false.", severity=sev
            )


@rule(
    "KN-S003",
    "Container may run as root",
    Stage.AUDIT,
    "security",
    Severity.MEDIUM,
    "Set runAsNonRoot: true (pod or container securityContext) and build images with a non-root USER.",
    "Running as UID 0 widens the impact of a container breakout. On OpenShift the restricted-v2 SCC assigns an "
    "arbitrary non-root UID, so images must also work as a random UID in group 0.",
    ("k8s-pss", "ocp-scc"),
    ("Docker CIS 4.1: Ensure That a User for the Container Has Been Created",),
)
def _s003(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, pt, c in _containers(ctx):
        uid = effective_security(pt, c, "runAsUser")
        non_root = effective_security(pt, c, "runAsNonRoot")
        if uid == 0:
            yield r.finding(
                d,
                (*c.path, "securityContext", "runAsUser"),
                f"Container '{c.name}' runs as UID 0.",
                severity=Severity.HIGH,
            )
        elif non_root is not True and not (isinstance(uid, int) and uid > 0):
            sev = Severity.INFO if ctx.is_openshift else Severity.MEDIUM
            yield r.finding(
                d,
                (*c.path, "securityContext"),
                f"Container '{c.name}' does not enforce runAsNonRoot: true.",
                severity=sev,
            )


@rule(
    "KN-S004",
    "Fixed UID/fsGroup conflicts with OpenShift restricted-v2 SCC",
    Stage.AUDIT,
    "platform",
    Severity.HIGH,
    "Remove runAsUser/fsGroup and let OpenShift assign IDs from the namespace range; keep runAsNonRoot: true. If a "
    "fixed UID is truly required, bind the ServiceAccount to the nonroot-v2 SCC. (runAsGroup is not governed by "
    "SCCs and is left alone.)",
    "restricted-v2 uses MustRunAsRange for UIDs and MustRunAs for fsGroup: pods requesting IDs outside the "
    "namespace's openshift.io/sa.scc.uid-range / supplemental-groups annotations are rejected ('unable to validate "
    "against any security context constraint').",
    ("ocp-scc",),
)
def _s004(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    if not ctx.is_openshift:
        return
    for d, pt in ctx.workloads():
        psc = pt.spec.get("securityContext")
        if isinstance(psc, dict):
            for f in ("runAsUser", "fsGroup"):
                if isinstance(psc.get(f), int) and psc[f] != 0:
                    yield r.finding(
                        d,
                        (*pt.path, "securityContext", f),
                        f"Pod sets {f}: {psc[f]}; restricted-v2 will reject IDs outside the namespace range.",
                    )
        for c in containers(pt):
            csc = c.container.get("securityContext")
            if isinstance(csc, dict):
                for f in ("runAsUser",):
                    if isinstance(csc.get(f), int) and csc[f] != 0:
                        yield r.finding(
                            d,
                            (*c.path, "securityContext", f),
                            f"Container '{c.name}' sets {f}: "
                            f"{csc[f]}; restricted-v2 will reject IDs outside the namespace range.",
                        )


@rule(
    "KN-S005",
    "Dangerous Linux capabilities added",
    Stage.AUDIT,
    "security",
    Severity.HIGH,
    "Remove the capability; the Pod Security 'restricted' profile only allows adding NET_BIND_SERVICE.",
    "Capabilities like SYS_ADMIN or NET_ADMIN are near-root and enable container escapes.",
    ("k8s-pss",),
    ("CAP_SYS_ADMIN capability added",),
)
def _s005(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, _pt, c in _containers(ctx):
        add = get_path(c.container, ("securityContext", "capabilities", "add")) or []
        for i, cap in enumerate(add if isinstance(add, list) else []):
            cap_u = str(cap).upper().removeprefix("CAP_")
            if cap_u in DANGEROUS_CAPS:
                yield r.finding(
                    d, (*c.path, "securityContext", "capabilities", "add", i), f"Container '{c.name}' adds {cap_u}."
                )
            elif cap_u not in PSS_RESTRICTED_ALLOWED_ADD:
                yield r.finding(
                    d,
                    (*c.path, "securityContext", "capabilities", "add", i),
                    f"Container '{c.name}' adds {cap_u} (not allowed by PSS restricted).",
                    severity=Severity.MEDIUM,
                )


@rule(
    "KN-S006",
    "Capabilities not dropped",
    Stage.AUDIT,
    "security",
    Severity.LOW,
    'Set securityContext.capabilities.drop: ["ALL"].',
    "Pod Security 'restricted' requires dropping ALL capabilities. OpenShift restricted-v2 drops them for you, the "
    "legacy 'restricted' SCC (clusters upgraded from <=4.10) does not.",
    ("k8s-pss", "ocp-scc"),
    ("Drop All Capabilities",),
)
def _s006(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, _pt, c in _containers(ctx):
        drop = get_path(c.container, ("securityContext", "capabilities", "drop")) or []
        if not any(str(x).upper() == "ALL" for x in (drop if isinstance(drop, list) else [])):
            yield r.finding(
                d, (*c.path, "securityContext", "capabilities"), f"Container '{c.name}' does not drop ALL capabilities."
            )


@rule(
    "KN-S007",
    "Writable root filesystem",
    Stage.AUDIT,
    "security",
    Severity.LOW,
    "Set readOnlyRootFilesystem: true and mount emptyDir volumes for paths the app writes (e.g. /tmp).",
    "A read-only root filesystem blocks tampering and many post-exploitation techniques.",
    ("k8s-pss",),
    ("Container using read-write root filesystem",),
)
def _s007(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, _pt, c in _containers(ctx):
        if get_path(c.container, ("securityContext", "readOnlyRootFilesystem")) is not True:
            yield r.finding(d, (*c.path, "securityContext"), f"Container '{c.name}' has a writable root filesystem.")


@rule(
    "KN-S008",
    "Seccomp profile not set to RuntimeDefault",
    Stage.AUDIT,
    "security",
    Severity.LOW,
    "Set securityContext.seccompProfile.type: RuntimeDefault at pod level.",
    "Pod Security 'restricted' requires RuntimeDefault or Localhost seccomp; Unconfined disables syscall "
    "filtering. OpenShift restricted-v2 applies RuntimeDefault by default. A Localhost profile must name its file: "
    "an empty localhostProfile is the CVE-2023-2431 pattern, which kubelets before v1.24.14, v1.25.10, v1.26.5 and "
    "v1.27.2 ran without any seccomp filter.",
    ("k8s-pss", "ocp-scc", "k8s-cve-2023-2431"),
    ("Docker CIS 5.21: Ensure the default seccomp profile is not disabled",),
)
def _s008(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, pt in ctx.workloads():
        pod_profile = get_path(pt.spec, ("securityContext", "seccompProfile"))
        pod_t = pod_profile.get("type") if isinstance(pod_profile, dict) else None
        for c in containers(pt):
            c_profile = get_path(c.container, ("securityContext", "seccompProfile"))
            ct = c_profile.get("type") if isinstance(c_profile, dict) else None
            eff = ct or pod_t
            profile = c_profile if ct else pod_profile
            if eff == "Unconfined":
                yield r.finding(
                    d,
                    (*c.path, "securityContext", "seccompProfile"),
                    f"Container '{c.name}' runs with seccomp Unconfined.",
                    severity=Severity.MEDIUM,
                )
            elif eff == "Localhost" and not (
                isinstance(profile, dict)
                and profile.get("localhostProfile") is not None
                and str(profile.get("localhostProfile")).strip()
            ):
                yield r.finding(
                    d,
                    (*c.path, "securityContext", "seccompProfile")
                    if ct
                    else (*pt.path, "securityContext", "seccompProfile"),
                    f"Container '{c.name}' uses seccomp type Localhost with an empty or missing localhostProfile: "
                    "CVE-2023-2431 (kubelet, fixed in v1.24.14, v1.25.10, v1.26.5 and v1.27.2) ran such containers "
                    "with no seccomp filter at all. Name the profile file (localhostProfile: profiles/app.json) or "
                    "use RuntimeDefault.",
                    severity=Severity.MEDIUM,
                )
            elif eff not in {"RuntimeDefault", "Localhost"}:
                yield r.finding(
                    d,
                    (*pt.path, "securityContext", "seccompProfile"),
                    f"Container '{c.name}' has no RuntimeDefault seccomp profile.",
                )


@rule(
    "KN-S009",
    "Host namespaces shared",
    Stage.AUDIT,
    "security",
    Severity.HIGH,
    "Remove hostNetwork/hostPID/hostIPC unless this is a node agent that truly needs it.",
    "Sharing host namespaces exposes host processes and network; OpenShift requires a privileged/hostnetwork SCC.",
    ("k8s-pss", "ocp-scc"),
    (
        "Docker CIS 5.9 and 5.20: Ensure that the host's network namespace is not shared",
        "Docker CIS 5.15: Ensure that the host's process namespace is not shared",
        "Docker CIS 5.16: Ensure that the host's IPC namespace is not shared",
    ),
)
def _s009(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, pt in ctx.workloads():
        for f in ("hostNetwork", "hostPID", "hostIPC"):
            if pt.spec.get(f) is True:
                yield r.finding(d, (*pt.path, f), f"Pod sets {f}: true.")


@rule(
    "KN-S010",
    "hostPath volume",
    Stage.AUDIT,
    "security",
    Severity.HIGH,
    "Replace hostPath with a PVC, emptyDir, ConfigMap/Secret or a CSI ephemeral volume.",
    "hostPath mounts let a container read or modify the node filesystem; container runtime sockets give full "
    "node takeover.",
    ("k8s-pss",),
    ("Mounting Sensitive Host Directories", "Mount Container Runtime Socket"),
)
def _s010(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, pt in ctx.workloads():
        for i, v in enumerate(pt.spec.get("volumes") or []):
            if not isinstance(v, dict) or not isinstance(v.get("hostPath"), dict):
                continue
            p = str(v["hostPath"].get("path", ""))
            crit = p in {"/", "/etc", "/var/lib/kubelet", "/proc"} or any(p.endswith(s) for s in RUNTIME_SOCKETS)
            yield r.finding(
                d,
                (*pt.path, "volumes", i, "hostPath"),
                f"Volume '{v.get('name')}' mounts host path '{p}'.",
                severity=Severity.CRITICAL if crit else Severity.HIGH,
            )


@rule(
    "KN-S011",
    "hostPort used",
    Stage.AUDIT,
    "security",
    Severity.MEDIUM,
    "Expose the container through a Service instead of hostPort.",
    "hostPort binds directly on the node, bypasses NetworkPolicy expectations and limits scheduling.",
    ("k8s-pss",),
)
def _s011(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, _pt, c in _containers(ctx):
        for i, p in enumerate(c.container.get("ports") or []):
            if isinstance(p, dict) and p.get("hostPort"):
                yield r.finding(
                    d, (*c.path, "ports", i, "hostPort"), f"Container '{c.name}' binds hostPort {p['hostPort']}."
                )


_DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")


def image_tag(image: str) -> tuple[str | None, bool]:
    """Return (tag, has_digest). Handles registry ports ('host:5000/app')."""
    has_digest = bool(_DIGEST.search(image))
    ref = image.split("@", 1)[0]
    last = ref.rsplit("/", 1)[-1]
    tag = last.split(":", 1)[1] if ":" in last else None
    return tag, has_digest


def image_registry(image: str) -> str:
    """The registry an image reference names, as the container runtime resolves it.

    Docker's rule, which is not obvious and is the whole of this function: the first path component is the
    registry only when it looks like a host -- it contains a dot or a colon, or it is exactly `localhost`.
    Everything else is a Docker Hub repository, so `nginx` and `bitnami/nginx` both come from `docker.io`
    however little they look like it, and an allowlist that missed that would pass every unqualified image
    (G241).
    """
    ref = image.split("@", 1)[0]
    head = ref.split("/", 1)[0]
    if "/" in ref and ("." in head or ":" in head or head == "localhost"):
        return head
    return "docker.io"


#: The whitespace a blank image reference may be made of. ASCII only, and spelled out rather than left to
#: `str.strip()`, because the generated admission policy decides the same question with an RE2 character class
#: and `str.strip()` also removes U+00A0 and other Unicode spaces, which RE2 would not (G245).
BLANK_IMAGE_CHARS = " \t\n\r\f\v"


def image_repository(image: str) -> str:
    """The repository path a reference names, as the runtime resolves it: no registry host, Docker Hub expanded.

    This is the part an `host/org` allowlist entry is compared against, and it has to be the path the runtime
    would pull, not the text after the first slash. Two normalisations, and without either one the same image
    written three ways got three verdicts (G245):

    * The registry host is removed when the reference states it, so `docker.io/bitnami/nginx` is the
      `bitnami/nginx` repository and not a repository called `docker.io/bitnami/nginx`.
    * A single-component Docker Hub path is expanded to the organisation it really lives in, so `nginx`,
      `library/nginx` and `docker.io/library/nginx` are all `library/nginx`.
    """
    ref = image.split("@", 1)[0]
    registry = image_registry(image)
    head, _, rest = ref.partition("/")
    path = rest if (head == registry and rest) else ref
    if registry == "docker.io" and "/" not in path:
        path = f"library/{path}"
    return path


def _registry_allowed(image: str, allowed: tuple[str, ...]) -> bool:
    """Whether this image comes from an allowed registry, honouring an `host/org` entry.

    An entry with a path narrows the allowance to that organisation: `quay.io/my-org` permits
    `quay.io/my-org/app` and refuses `quay.io/someone-else/app`, which is the point of an allowlist for a
    registry anyone can push to. The entry's path is an organisation prefix, not a repository, so it is NOT
    put through `image_repository`: `docker.io/library` means the organisation every official image lives in.
    """
    registry = image_registry(image)
    path = image_repository(image)
    for entry in allowed:
        host, _, prefix = entry.strip().partition("/")
        if host != registry:
            continue
        if not prefix or path == prefix or path.startswith(prefix.rstrip("/") + "/"):
            return True
    return False


@rule(
    "KN-S036",
    "Image from a registry outside the allowlist",
    Stage.AUDIT,
    "supply-chain",
    Severity.HIGH,
    "Mirror the image into an approved registry and reference it there, or add the registry to "
    "`audit.allowedRegistries` if it is approved.",
    "An image from an unapproved registry is code of unknown provenance running with the pod's identity, and it "
    "is the step every other supply-chain control depends on: a signature, an SBOM and a scan all describe an "
    "artifact somebody chose to trust.",
    ("k8s-images",),
)
def _s036(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    if not ctx.allowed_registries:
        # No manifest states which registries an organisation has approved. Reporting every image as fine
        # because no policy was configured is the absence-read-as-pass failure this catalogue is built against,
        # so the rule declines and `run_rules` keeps it out of the evaluated list (G241).
        ctx.cannot_decide(r.rule_id)
        return
    for d, pt in ctx.workloads():
        for c in containers(pt):
            image = c.container.get("image")
            if not isinstance(image, str) or not image.strip(BLANK_IMAGE_CHARS):
                continue  # no image to measure; KN-S012 reports that
            if _registry_allowed(image, ctx.allowed_registries):
                continue
            where = image_registry(image)
            implicit = " (an unqualified name resolves to Docker Hub)" if "/" not in image.split("@", 1)[0] else ""
            yield r.finding(
                d,
                (*c.path, "image"),
                f"Container '{c.name}' pulls from '{where}'{implicit}, which is not in "
                f"audit.allowedRegistries ({', '.join(ctx.allowed_registries)}).",
            )


@rule(
    "KN-S012",
    "Mutable image reference",
    Stage.AUDIT,
    "supply-chain",
    Severity.MEDIUM,
    "Pin an explicit version tag, ideally an immutable digest (image@sha256:...).",
    "':latest' or untagged images change underneath you, break rollbacks and defeat image scanning/signing.",
    ("k8s-images",),
    ("Latest tag",),
)
def _s012(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, _pt, c in _containers(ctx):
        image = c.container.get("image")
        if not isinstance(image, str) or not image:
            if c.label:
                # A field-shaped container -- a KServe `model:`, one of its framework shorthands, KubeRay's
                # injected autoscaler -- gets its image from the ServingRuntime or the operator, so an absent
                # one is the canonical form rather than a defect. The report says the image was not read
                # instead of calling the upstream sample a HIGH finding (G252).
                continue
            yield r.finding(d, c.path, f"Container '{c.name}' has no image.", severity=Severity.HIGH)
            continue
        tag, digest = image_tag(image)
        if digest:
            continue
        if tag in (None, "latest"):
            yield r.finding(d, (*c.path, "image"), f"Container '{c.name}' uses mutable image '{image}'.")
        else:
            yield r.finding(
                d,
                (*c.path, "image"),
                f"Container '{c.name}' image '{image}' is not pinned by digest.",
                severity=Severity.INFO,
            )


@rule(
    "KN-S013",
    "Secret value hard-coded in environment",
    Stage.AUDIT,
    "secrets",
    Severity.HIGH,
    "Move the value to a Secret and reference it with valueFrom.secretKeyRef (or an external secret store).",
    "Literal credentials in manifests leak through Git history, `oc get -o yaml`, logs and audit trails.",
    ("k8s-secrets-good-practices",),
    ("Environment Variable Contains Secret",),
)
def _s013(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, _pt, c in _containers(ctx):
        for i, e in enumerate(c.container.get("env") or []):
            if not isinstance(e, dict) or not isinstance(e.get("value"), str) or _is_reference(e["value"]):
                continue
            if SENSITIVE_ENV.search(str(e.get("name", ""))):
                yield r.finding(
                    d, (*c.path, "env", i, "value"), f"Container '{c.name}' sets {e['name']} as a literal value."
                )
            elif _EMBEDDED_SECRET.search(e["value"]):
                yield r.finding(
                    d,
                    (*c.path, "env", i, "value"),
                    f"Container '{c.name}' env {e.get('name')} embeds a credential (URL password, key or token).",
                )
        for field_name in ("command", "args"):
            items = c.container.get(field_name)
            if not isinstance(items, list):
                continue
            strs = [x if isinstance(x, str) else "" for x in items]
            for i, arg in enumerate(strs):
                nxt = strs[i + 1] if i + 1 < len(strs) else ""
                if (
                    _secret_flag_value(arg)
                    or _EMBEDDED_SECRET.search(arg)
                    or (_bare_secret_flag(arg) and nxt and not nxt.startswith("-") and not _is_reference(nxt))
                ):
                    yield r.finding(
                        d,
                        (*c.path, field_name, i),
                        f"Container '{c.name}' passes a literal credential in {field_name}[{i}] (visible in the pod "
                        "spec and the process list).",
                    )


@rule(
    "KN-S014",
    "ServiceAccount token automounted",
    Stage.AUDIT,
    "security",
    Severity.LOW,
    "Set automountServiceAccountToken: false on the pod (or ServiceAccount) unless the app calls the API.",
    "A mounted token turns any RCE into authenticated Kubernetes API access.",
    ("k8s-rbac-good-practices",),
    ("Pod Service Account Token Automatically Mounted",),
)
def _s014(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    sa_opt_out = {
        (ctx.ns(d), d.name)
        for d in ctx.by_kind("ServiceAccount")
        if isinstance(d.data, dict) and d.data.get("automountServiceAccountToken") is False
    }
    for d, pt in ctx.workloads():
        if pt.spec.get("automountServiceAccountToken") is False:
            continue
        sa = str(pt.spec.get("serviceAccountName") or "default")
        if (ctx.ns(d), sa) in sa_opt_out and pt.spec.get("automountServiceAccountToken") is not True:
            continue
        yield r.finding(d, pt.path, f"Pod automounts the token of ServiceAccount '{sa}'.")


def _rules_of(d: Document) -> list[tuple[int, dict[str, Any]]]:
    rules = d.data.get("rules") if isinstance(d.data, dict) else None
    return [(i, x) for i, x in enumerate(rules or []) if isinstance(x, dict)]


@rule(
    "KN-S015",
    "RBAC wildcard grants",
    Stage.AUDIT,
    "rbac",
    Severity.HIGH,
    "Enumerate the exact apiGroups, resources and verbs needed.",
    "Wildcards grant every current and future resource/verb, including secrets and escalation paths.",
    ("k8s-rbac-good-practices",),
)
def _s015(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d in ctx.by_kind("Role", "ClusterRole"):
        for i, rr in _rules_of(d):
            wild = [k for k in ("verbs", "resources", "apiGroups") if "*" in (rr.get(k) or [])]
            if wild:
                yield r.finding(d, ("rules", i), f"Rule uses '*' in {', '.join(wild)}.")


@rule(
    "KN-S016",
    "Binding to cluster-admin",
    Stage.AUDIT,
    "rbac",
    Severity.CRITICAL,
    "Bind a narrowly scoped Role instead; cluster-admin should only be held by break-glass identities.",
    "cluster-admin is full control of the cluster.",
    ("k8s-rbac-good-practices",),
)
def _s016(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d in ctx.by_kind("ClusterRoleBinding", "RoleBinding"):
        if get_path(d.data, ("roleRef", "name")) == "cluster-admin":
            subjects = [f"{s.get('kind')}/{s.get('name')}" for s in d.data.get("subjects") or [] if isinstance(s, dict)]
            sev = Severity.CRITICAL if d.kind == "ClusterRoleBinding" else Severity.HIGH
            yield r.finding(d, ("roleRef", "name"), f"{d.kind} grants cluster-admin to {subjects}.", severity=sev)


ESCALATION_VERBS = frozenset({"escalate", "bind", "impersonate"})


WORKLOAD_RESOURCES = frozenset(
    {
        "pods",
        "deployments",
        "replicasets",
        "statefulsets",
        "daemonsets",
        "jobs",
        "cronjobs",
        "replicationcontrollers",
        "deploymentconfigs",
    }
)


WRITE_VERBS = frozenset({"create", "patch", "update", "*"})


def _writes(rr: dict[str, Any], resource: str) -> bool:
    return resource in {str(x) for x in rr.get("resources") or []} and bool(
        {str(v) for v in rr.get("verbs") or []} & WRITE_VERBS
    )


@rule(
    "KN-S017",
    "RBAC privilege-escalation paths",
    Stage.AUDIT,
    "rbac",
    Severity.HIGH,
    "Remove escalate/bind/impersonate, cluster-wide secret reads, nodes/proxy, pod exec, ephemeral containers, "
    "ControllerRevision writes and workload creation unless essential; where they are, enforce Pod Security "
    "restricted in that namespace, and run kube-controller-manager v1.34.12, v1.35.9, v1.36.5, v1.37.1 or later.",
    "These permissions let a subject obtain more privileges than it was granted. Only the StatefulSet and DaemonSet "
    "controllers need to write ControllerRevisions (the built-in edit and admin roles do not grant it): with write "
    "access to StatefulSets too, CVE-2026-2270 (kube-controller-manager up to v1.34.11, v1.35.8, v1.36.4 and "
    "v1.37.0) let a namespace user create pods in other namespaces.",
    ("k8s-rbac-good-practices", "k8s-cve-2026-2270", "k8s-rbac-bootstrap-policy"),
)
def _s017(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d in ctx.by_kind("Role", "ClusterRole"):
        role_rules = _rules_of(d)
        writes_sts = any(_writes(x, "statefulsets") for _, x in role_rules)
        for i, rr in role_rules:
            if _writes(rr, "controllerrevisions"):
                pair = (
                    "this role also writes StatefulSets, the pair CVE-2026-2270 needs"
                    if writes_sts
                    else "with write access to StatefulSets from any role, this is CVE-2026-2270"
                )
                yield r.finding(
                    d,
                    ("rules", i, "resources"),
                    f"Can write ControllerRevisions: {pair} (kube-controller-manager up to v1.34.11, v1.35.8, v1.36.4 "
                    "and v1.37.0; fixed in v1.34.12, v1.35.9, v1.36.5 and v1.37.1), which lets a namespace user "
                    "create pods in other namespaces. Only controllers need to write ControllerRevisions.",
                    severity=Severity.HIGH if writes_sts else Severity.MEDIUM,
                )
        for i, rr in role_rules:
            verbs = {str(v) for v in rr.get("verbs") or []}
            resources = {str(x) for x in rr.get("resources") or []}
            if verbs & ESCALATION_VERBS:
                yield r.finding(d, ("rules", i, "verbs"), f"Grants {sorted(verbs & ESCALATION_VERBS)}.")
            if "secrets" in resources and verbs & {"get", "list", "watch", "*"}:
                # `list` and `watch` return the Secrets' CONTENTS, so one grant hands over every value in scope;
                # a `get` hands over the ones whose names the holder already knows. All three external reviews
                # of this catalogue asked for that distinction and it was not being made: a namespaced `list`
                # was reported at LOW, the same as a `get` (G240).
                #
                # The severity does NOT depend on `resourceNames` for `list` and `watch`, deliberately. Whether
                # `resourceNames` narrows a list request is a question about the authorizer that this project
                # has not verified against the published reference, so the rule takes the conservative reading
                # in which it does not -- which is right whichever way that falls, instead of resting on it.
                values = bool(verbs & {"list", "watch", "*"})
                names = [str(n) for n in (rr.get("resourceNames") or [])]
                if not values and names:
                    # `get` restricted to named Secrets is the least-privilege pattern the upstream RBAC guidance
                    # recommends. Reporting it as an escalation path told people their correct configuration was
                    # a defect, which is the one thing a security rule must not do.
                    continue
                if values:
                    sev = Severity.HIGH if d.kind == "ClusterRole" else Severity.MEDIUM
                    scope = (
                        "every Secret in the cluster" if d.kind == "ClusterRole" else "every Secret in the namespace"
                    )
                    message = (
                        f"{d.kind} grants {sorted(verbs & {'list', 'watch', '*'})} on Secrets, which returns their "
                        f"contents: this hands over the values of {scope}, not only the names."
                    )
                else:
                    sev = Severity.HIGH if d.kind == "ClusterRole" else Severity.LOW
                    message = f"{d.kind} can read Secrets."
                yield r.finding(d, ("rules", i, "resources"), message, severity=sev)
            if resources & {"pods/exec", "pods/attach"} and verbs & {"create", "*"}:
                yield r.finding(d, ("rules", i, "resources"), "Grants exec/attach into pods.", severity=Severity.MEDIUM)
            if "nodes/proxy" in resources:
                yield r.finding(d, ("rules", i, "resources"), "Grants nodes/proxy (kubelet API access).")
            # Kubernetes RBAC good practices, "Workload creation" and "Persistent volume creation":
            # https://github.com/kubernetes/website/blob/main/content/en/docs/concepts/security/rbac-good-practices.md
            if resources & WORKLOAD_RESOURCES and verbs & {"create", "patch", "update", "*"}:
                sev = Severity.HIGH if d.kind == "ClusterRole" else Severity.MEDIUM
                yield r.finding(
                    d,
                    ("rules", i, "resources"),
                    f"Can create or change {', '.join(sorted(resources & WORKLOAD_RESOURCES))}: their pods can run as "
                    "any ServiceAccount in the namespace and mount its Secrets and volumes.",
                    severity=sev,
                )
            if "pods/ephemeralcontainers" in resources and verbs & {"patch", "update", "*"}:
                yield r.finding(
                    d,
                    ("rules", i, "resources"),
                    "Can add ephemeral containers to running pods: code runs in the pod, like exec.",
                    severity=Severity.MEDIUM,
                )
            if "persistentvolumes" in resources and verbs & {"create", "*"}:
                yield r.finding(d, ("rules", i, "resources"), "Can create PersistentVolumes, including hostPath.")


@rule(
    "KN-S018",
    "Secret material committed in manifests",
    Stage.AUDIT,
    "secrets",
    Severity.MEDIUM,
    "Deliver secrets with an external secret store (External Secrets Operator, Vault, AWS Secrets Manager on "
    "ROSA) or Sealed Secrets; never commit base64 'data' to Git.",
    "base64 is an encoding, not encryption.",
    ("k8s-secrets-good-practices",),
)
def _s018(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d in ctx.by_kind("Secret"):
        if isinstance(d.data, dict) and (d.data.get("data") or d.data.get("stringData")):
            if d.data.get("type") == "kubernetes.io/service-account-token":
                continue
            yield r.finding(
                d, ("data",) if d.data.get("data") else ("stringData",), "Secret contains inline key material."
            )


@rule(
    "KN-S019",
    "Permissive SecurityContextConstraints",
    Stage.AUDIT,
    "security",
    Severity.HIGH,
    "Prefer the built-in restricted-v2 / nonroot-v2 SCCs; custom SCCs must not allow privileged, host "
    "namespaces, host directories or RunAsAny UIDs.",
    "A permissive SCC bound to a ServiceAccount defeats OpenShift's default pod isolation.",
    ("ocp-scc",),
)
def _s019(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d in ctx.by_kind("SecurityContextConstraints"):
        data = d.data
        bad = [
            k
            for k in (
                "allowPrivilegedContainer",
                "allowHostNetwork",
                "allowHostPID",
                "allowHostIPC",
                "allowHostDirVolumePlugin",
                "allowHostPorts",
                "allowPrivilegeEscalation",
            )
            if data.get(k) is True
        ]
        if get_path(data, ("runAsUser", "type")) == "RunAsAny":
            bad.append("runAsUser: RunAsAny")
        if bad:
            yield r.finding(d, (), f"SCC allows: {', '.join(bad)}.")


@rule(
    "KN-S020",
    "Unmasked /proc",
    Stage.AUDIT,
    "security",
    Severity.HIGH,
    "Remove securityContext.procMount: Unmasked.",
    "Unmasked /proc exposes host kernel interfaces.",
    ("k8s-pss",),
)
def _s020(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, _pt, c in _containers(ctx):
        if get_path(c.container, ("securityContext", "procMount")) == "Unmasked":
            yield r.finding(d, (*c.path, "securityContext", "procMount"), f"Container '{c.name}' unmasks /proc.")


@rule(
    "KN-S029",
    "Probe or lifecycle handler with a host",
    Stage.AUDIT,
    "security",
    Severity.MEDIUM,
    "Remove the host field from the probe or lifecycle handler. A handler with no host is sent to the pod's own "
    "IP, which is what you almost always want; to reach another address, do it from the application.",
    "A host on an httpGet or tcpSocket handler makes the kubelet -- a trusted node component -- open a "
    "connection to that address on the pod's behalf, so anyone who can create a pod can have the kubelet reach "
    "an address the pod itself may not be allowed to, including node-local and cluster-internal endpoints that "
    "NetworkPolicy never sees. KEP-4940 adds this to the Pod Security baseline as the `probeHost` check, "
    "enabled by a namespace label `pod-security.kubernetes.io/enforce-version: v1.34` or later, so on such a "
    "namespace the pod is refused at admission rather than merely questionable.",
    ("k8s-pss",),
)
def _s029(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    # The field paths KEP-4940 names, for containers and initContainers alike. `_containers` already yields both.
    handlers = (
        ("livenessProbe", "httpGet"),
        ("livenessProbe", "tcpSocket"),
        ("readinessProbe", "httpGet"),
        ("readinessProbe", "tcpSocket"),
        ("startupProbe", "httpGet"),
        ("startupProbe", "tcpSocket"),
        ("lifecycle", "postStart", "httpGet"),
        ("lifecycle", "postStart", "tcpSocket"),
        ("lifecycle", "preStop", "httpGet"),
        ("lifecycle", "preStop", "tcpSocket"),
    )
    for d, _pt, c in _containers(ctx):
        for path in handlers:
            host = get_path(c.container, (*path, "host"))
            if not isinstance(host, str) or not host.strip():
                continue
            where = ".".join(path)
            yield r.finding(
                d,
                (*c.path, *path, "host"),
                f"Container '{c.name}' sets {where}.host: {host.strip()}, so the kubelet connects to that "
                f"address instead of the pod.",
            )


@rule(
    "KN-S021",
    "gitRepo volume",
    Stage.AUDIT,
    "security",
    Severity.HIGH,
    "Clone with an init container into an emptyDir volume that the app container mounts (the replacement the "
    "Kubernetes docs give), and remove the gitRepo volume.",
    "gitRepo volumes are deprecated since Kubernetes 1.11, off by default from 1.33 (GitRepoVolumeDriver feature "
    "gate) and gone after 1.35. CVE-2024-10220 (CVSS 8.1; kubelet, fixed in v1.28.12, v1.29.7, v1.30.3 and v1.31.0) "
    "let a user who can create a pod run commands outside the container through a gitRepo volume, and "
    "CVE-2025-1767 (every version, no fix) lets a pod read local git repositories on the node through one.",
    ("k8s-cve-2024-10220", "k8s-cve-2025-1767", "k8s-volumes-gitrepo"),
)
def _s021(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    target = parse_minor(ctx.k8s_version)
    for d, pt in ctx.workloads():
        for i, v in enumerate(pt.spec.get("volumes") or []):
            if not isinstance(v, dict) or "gitRepo" not in v:
                continue
            raw_git = v.get("gitRepo")
            git: dict[str, Any] = raw_git if isinstance(raw_git, dict) else {}
            repo = str(git.get("repository") or "")
            local = (
                f" Its repository '{repo}' is a path on the node: the CVE-2025-1767 pattern."
                if repo.startswith("/")
                else ""
            )
            if target >= (1, 36):
                state = (
                    f"Kubernetes {ctx.k8s_version} no longer has the gitRepo driver (last served by v1.35): the pod "
                    "cannot start."
                )
            elif target >= (1, 33):
                state = (
                    f"On Kubernetes {ctx.k8s_version} the GitRepoVolumeDriver feature gate is off by default, so the "
                    "pod does not start unless the cluster turned it on."
                )
            else:
                state = "gitRepo is deprecated since Kubernetes 1.11 and disabled by default from 1.33."
            yield r.finding(
                d,
                (*pt.path, "volumes", i, "gitRepo"),
                f"Volume '{v.get('name')}' is a gitRepo volume: CVE-2024-10220 (kubelet, fixed in v1.28.12, v1.29.7, "
                "v1.30.3 and v1.31.0) ran attacker-chosen commands on the node through gitRepo volumes, and "
                f"CVE-2025-1767 (every version, no fix) reads local git repositories through them.{local} {state} "
                "Clone with an init container into an emptyDir volume instead.",
            )


_SYSCTL_META = ("+", "=")


@rule(
    "KN-S022",
    "Pod sysctl name or value contains '+' or '='",
    Stage.AUDIT,
    "security",
    Severity.HIGH,
    "Remove the sysctl, or write it as one plain name and one plain value (a sysctl never needs '+' or '=' in "
    "either); on OpenShift keep to the safe sysctls or the ones a Tuned profile allows.",
    "CVE-2022-0811 ('cr8escape', CRI-O 1.19 to 1.24.0, fixed in 1.19.6, 1.20.7, 1.21.6, 1.22.3, 1.23.2 and 1.24.0) "
    "passed a sysctl whose value carried '+' to set kernel.core_pattern and escape the container with root on the "
    "node; OpenShift's container runtime is CRI-O, and the GitHub advisory names an admission webhook that denies "
    "pods with a '+' in a sysctl value as the mitigation.",
    ("ghsa-cve-2022-0811",),
)
def _s022(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, pt in ctx.workloads():
        sysctls = get_path(pt.spec, ("securityContext", "sysctls"))
        for i, s in enumerate(sysctls if isinstance(sysctls, list) else []):
            if not isinstance(s, dict):
                continue
            name, value = str(s.get("name", "")), str(s.get("value", ""))
            if any(ch in name or ch in value for ch in _SYSCTL_META):
                yield r.finding(
                    d,
                    (*pt.path, "securityContext", "sysctls", i),
                    f"Pod sysctl '{name}' = '{value}' contains '+' or '=': the CVE-2022-0811 (cr8escape) pattern, "
                    "which CRI-O before 1.19.6, 1.20.7, 1.21.6, 1.22.3, 1.23.2 and 1.24.0 turned into a container "
                    "escape through kernel.core_pattern. Remove the sysctl or write one plain name and value.",
                )


_PROC_DIR = re.compile(r"^/proc(?:/|\Z)")


@rule(
    "KN-S023",
    "Container workingDir under /proc",
    Stage.AUDIT,
    "security",
    Severity.HIGH,
    "Set workingDir to a directory that exists in the image (/app, /opt/app-root) or leave it unset, and run nodes "
    "with runc 1.1.12 or later.",
    "CVE-2024-21626 ('Leaky Vessels', CVSS 8.6; runc 1.0.0-rc93 to 1.1.11, fixed in 1.1.12) let a container whose "
    "working directory was under /proc/self/fd/ start with a working directory in the host filesystem through a "
    "leaked file descriptor: a container breakout to the host filesystem. The advisory's mitigation is to permit "
    "only a process.cwd of / and to deny working directories under /proc.",
    ("ghsa-cve-2024-21626",),
)
def _s023(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, _pt, c in _containers(ctx):
        wd = c.container.get("workingDir")
        if isinstance(wd, str) and _PROC_DIR.match(wd.strip()):
            yield r.finding(
                d,
                (*c.path, "workingDir"),
                f"Container '{c.name}' sets workingDir '{wd.strip()}' under /proc: the CVE-2024-21626 (Leaky Vessels) "
                "pattern, which runc before 1.1.12 turned into a breakout to the node filesystem through a leaked "
                "file descriptor. Use a directory inside the image.",
            )


@rule(
    "KN-S024",
    "ingress-nginx controller image below the fixed releases",
    Stage.AUDIT,
    "supply-chain",
    Severity.HIGH,
    "Run a release that fixes every advisory below (v1.13.9, v1.14.5, v1.15.1 or later), disable the validating "
    "webhook (--validating-webhook) until the controller is at least v1.11.5 or v1.12.1, and plan the move to a "
    "Gateway API implementation: the project is retired and fixes nothing found after its last release.",
    "The controller image tag is a release; the Kubernetes CVE feed names the releases that fix each ingress-nginx "
    "CVE. CVE-2025-1974 (CVSS 9.8, fixed in v1.11.5 and v1.12.1) gives anyone on the pod network code execution "
    "in the controller through its validating admission webhook; the later fixes close configuration injection "
    "through annotations and paths (CVE-2025-15566 in v1.12.5/v1.13.1; CVE-2026-1580, CVE-2026-24512, "
    "CVE-2026-24513 and CVE-2026-24514 in v1.13.7/v1.14.3; CVE-2026-3288 in v1.13.8/v1.14.4/v1.15.0; CVE-2026-4342 "
    "in v1.13.9/v1.14.5/v1.15.1).",
    tuple(dict.fromkeys(c for a in INGRESS_NGINX_ADVISORIES for c in a.citations)) + ("ingress-nginx-retired",),
)
def _s024(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, _pt, c in _containers(ctx):
        image = c.container.get("image")
        if not isinstance(image, str):
            continue
        version = ingress_nginx_version(image)
        if version is None:
            continue
        hits = [a for a in INGRESS_NGINX_ADVISORIES if a.affects(version)]
        if not hits:
            continue
        args = c.container.get("args")
        webhook = any(str(a).startswith("--validating-webhook") for a in (args if isinstance(args, list) else []))
        rce = any(_WEBHOOK_RCE in a.cves for a in hits)
        parts = [f"{', '.join(a.cves)}: {a.summary} (fixed in {', '.join('v' + f for f in a.fixed)})" for a in hits]
        tag = "v{}.{}.{}".format(*version)
        yield r.finding(
            d,
            (*c.path, "image"),
            f"Container '{c.name}' runs ingress-nginx {tag}, which is affected by {len(hits)} published advisory(ies): "
            + "; ".join(parts)
            + "."
            + (
                " The validating webhook is on (--validating-webhook), so CVE-2025-1974 is reachable from the pod "
                "network without credentials."
                if webhook and rce
                else ""
            ),
            severity=Severity.CRITICAL if webhook and rce else Severity.HIGH,
        )


# Characters a shell or PowerShell treats as syntax. A volume path (a subPath, a local PersistentVolume path) never
# needs them; RE2 too (kube_noob.generate.policies puts it into CEL), with quotes and the backtick as \x escapes.
COMMAND_META = r"[$;&|<>\x60\x27\x22\r\n]"
_COMMAND_META = re.compile(COMMAND_META)


def _meta_chars(value: str) -> str:
    """The shell characters in ``value``, quoted: "the shell character(s) '$' ';'"."""
    return "the shell character(s) " + " ".join(sorted({repr(ch) for ch in value if _COMMAND_META.match(ch)}))


def _targets_windows(pt: PodTemplate) -> bool:
    if str(get_path(pt.spec, ("os", "name")) or "").lower() == "windows":
        return True
    sel = pt.spec.get("nodeSelector")
    if isinstance(sel, dict) and str(sel.get("kubernetes.io/os", "")).lower() == "windows":
        return True
    required = get_path(pt.spec, ("affinity", "nodeAffinity", "requiredDuringSchedulingIgnoredDuringExecution"))
    terms = required.get("nodeSelectorTerms") if isinstance(required, dict) else None
    for term in terms if isinstance(terms, list) else []:
        exprs = term.get("matchExpressions") if isinstance(term, dict) else None
        for e in exprs if isinstance(exprs, list) else []:
            if isinstance(e, dict) and e.get("key") == "kubernetes.io/os" and "windows" in (e.get("values") or []):
                return True
    return False


@rule(
    "KN-S025",
    "volumeMount subPath carries shell or PowerShell characters",
    Stage.AUDIT,
    "security",
    Severity.HIGH,
    "Use a plain relative path for subPath (letters, digits, '-', '_', '.', '/'), and run Windows nodes with kubelet "
    "v1.24.17, v1.25.13, v1.26.8, v1.27.5, v1.28.1 or later.",
    "CVE-2023-3676 (CVSS 8.8; kubelet up to v1.24.16, v1.25.12, v1.26.7, v1.27.4 and v1.28.0, fixed in v1.24.17, "
    "v1.25.13, v1.26.8, v1.27.5 and v1.28.1): on Windows nodes kubelet put a pod's subPath into a PowerShell "
    "command, so anyone who could create a pod ran commands as SYSTEM on the node. The fix passes the path in an "
    "environment variable; the feed names pod create events with embedded PowerShell commands as the sign of "
    "exploitation. A subPath is a path inside the volume and never needs these characters.",
    ("k8s-cve-2023-3676", "k8s-fix-cve-2023-3676"),
)
def _s025(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, pt, c in _containers(ctx):
        mounts = c.container.get("volumeMounts")
        windows = _targets_windows(pt)
        for i, m in enumerate(mounts if isinstance(mounts, list) else []):
            sub = m.get("subPath") if isinstance(m, dict) else None
            if not isinstance(sub, str) or not _COMMAND_META.search(sub):
                continue
            where = "a Windows node" if windows else "any Windows node it lands on"
            yield r.finding(
                d,
                (*c.path, "volumeMounts", i, "subPath"),
                f"Container '{c.name}' mounts '{m.get('name')}' with subPath {sub!r}, which carries "
                f"{_meta_chars(sub)}: the CVE-2023-3676 pattern, where kubelet before v1.24.17, v1.25.13, v1.26.8, "
                f"v1.27.5 and v1.28.1 ran the subPath through PowerShell as SYSTEM on {where}. Use a plain relative "
                "path.",
                severity=Severity.HIGH if windows else Severity.MEDIUM,
            )


# A ConfigMap key that names a credential (DB_PASSWORD, redis.password, api-key, client_secret, credentials), and a
# line of a config file in a value that sets one (password=..., "token": "..."). A key that ends in plain "secret"
# usually names a Secret, so it is left out. RE2 too: kube_noob.generate.policies puts both into CEL.
CREDENTIAL_NAME = (
    r"(?:password|passwd|token|api[-_]?key|access[-_]?key|secret[-_]?key|private[-_]?key|client[-_]?secret|"
    r"credentials?)"
)
CONFIGMAP_CREDENTIAL_KEY = r"(?i)^(?:[a-z0-9]+[._-])*" + CREDENTIAL_NAME + r"$"
CONFIGMAP_CREDENTIAL_LINE = (
    r"(?im)^[ \t]*(?:export[ \t]+)?[\x22\x27]?[a-z0-9_.-]*" + CREDENTIAL_NAME + r"[\x22\x27]?[ \t]*[=:][ \t]*"
    r"[\x22\x27]?[^\s$<{*#%\x22\x27-]"
)
_CM_KEY = re.compile(CONFIGMAP_CREDENTIAL_KEY[:-1] + r"\Z")
_CM_LINE = re.compile(CONFIGMAP_CREDENTIAL_LINE)


@rule(
    "KN-S026",
    "Credential stored in a ConfigMap",
    Stage.AUDIT,
    "secrets",
    Severity.HIGH,
    "Move the value into a Secret (created outside Git: an external secret store or Sealed Secrets) and mount or "
    "reference it; in a Helm chart, render credentials into a Secret template, never into a ConfigMap.",
    "A ConfigMap does not provide secrecy or encryption: it is not covered by encryption of Secrets at rest, and the "
    "built-in view role reads ConfigMaps but not Secrets, so everyone with read access to the namespace reads the "
    "credential. Flags a key that names a credential with a literal value, a URL with a password, a private key, an "
    "access key id or a token in any value, and a password=... or token: ... line in a config file value.",
    ("k8s-configmap", "k8s-secrets-good-practices", "k8s-rbac-bootstrap-policy"),
)
def _s026(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d in ctx.by_kind("ConfigMap"):
        data = d.data.get("data") if isinstance(d.data, dict) else None
        if not isinstance(data, dict):
            continue
        for key in sorted(data, key=str):
            value = "" if data[key] is None else str(data[key])
            if _CM_KEY.match(str(key)) and not _is_reference(value):
                why = "names a credential and holds a literal value"
            elif _EMBEDDED_SECRET.search(value):
                why = "embeds a credential (a URL password, a private key, an access key id or a token)"
            elif _CM_LINE.search(value):
                why = "sets a credential on a line of the file it holds (password=..., token: ...)"
            else:
                continue
            yield r.finding(
                d,
                ("data", str(key)),
                f"ConfigMap key '{key}' {why}; a ConfigMap is not secret (readable with the view role, not "
                "encrypted at rest). Move it to a Secret.",
            )


@rule(
    "KN-S027",
    "Legacy ServiceAccount token Secret",
    Stage.AUDIT,
    "secrets",
    Severity.MEDIUM,
    "Delete the Secret and get short-lived tokens instead: a projected serviceAccountToken volume in the pod, or the "
    "TokenRequest API (kubectl create token) for a client outside the cluster.",
    "A Secret of type kubernetes.io/service-account-token is a legacy mechanism that holds a long-lived, non-expiring "
    "ServiceAccount token; the Kubernetes docs say to create one only when the TokenRequest API cannot be used and "
    "the exposure of a non-expiring token in a readable API object is acceptable. Anyone who can read Secrets in the "
    "namespace can act as that ServiceAccount until the Secret is deleted.",
    ("k8s-secret-sa-token", "k8s-rbac-good-practices"),
)
def _s027(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d in ctx.by_kind("Secret"):
        if isinstance(d.data, dict) and d.data.get("type") == "kubernetes.io/service-account-token":
            sa = get_path(d.data, ("metadata", "annotations", "kubernetes.io/service-account.name"))
            yield r.finding(
                d,
                ("type",),
                f"Secret is a legacy token Secret for ServiceAccount '{sa or '?'}': the token never expires and anyone "
                "who can read Secrets in the namespace can use it. Use a projected serviceAccountToken volume or "
                "kubectl create token.",
            )


# Subjects that are everyone of a kind, with what a binding to them means and the severity of a cluster-wide grant.
_ANYONE = "anyone who can reach the API server"
EVERYONE_SUBJECTS: dict[tuple[str, str], tuple[str, Severity]] = {
    ("Group", "system:unauthenticated"): (f"every unauthenticated request, {_ANYONE}", Severity.CRITICAL),
    ("User", "system:anonymous"): (f"anonymous requests, {_ANYONE}", Severity.CRITICAL),
    ("Group", "system:authenticated"): ("every user and every ServiceAccount of every namespace", Severity.HIGH),
    ("Group", "system:serviceaccounts"): ("every ServiceAccount of every namespace", Severity.HIGH),
    ("Group", "system:authenticated:oauth"): ("every user who logs in through OpenShift OAuth", Severity.HIGH),
}
RBAC_DEFAULTS_LABEL = ("kubernetes.io/bootstrapping", "rbac-defaults")


@rule(
    "KN-S028",
    "RBAC binding grants a role to everyone",
    Stage.AUDIT,
    "rbac",
    Severity.HIGH,
    "Bind the role to the ServiceAccounts, users or groups that need it, never to system:unauthenticated, "
    "system:anonymous, system:authenticated or system:serviceaccounts.",
    "The Kubernetes RBAC good practices ask to review bindings for the system:unauthenticated group and remove them, "
    "as they give access to anyone who can contact the API server at a network level. system:authenticated is every "
    "user and every ServiceAccount token in the cluster (a token stolen from any pod works), and "
    "system:serviceaccounts every ServiceAccount of every namespace. The built-in bindings (system: names, label "
    "kubernetes.io/bootstrapping: rbac-defaults) are left alone.",
    ("k8s-rbac-good-practices", "k8s-rbac-subjects"),
)
def _s028(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    key, value = RBAC_DEFAULTS_LABEL
    for d in ctx.by_kind("RoleBinding", "ClusterRoleBinding"):
        labels = get_path(d.data, ("metadata", "labels"))
        if d.name.startswith("system:") or (isinstance(labels, dict) and labels.get(key) == value):
            continue
        role = get_path(d.data, ("roleRef", "name"))
        subjects = get_path(d.data, ("subjects",))
        for i, s in enumerate(subjects if isinstance(subjects, list) else []):
            if not isinstance(s, dict):
                continue
            hit = EVERYONE_SUBJECTS.get((str(s.get("kind")), str(s.get("name"))))
            if hit is None:
                continue
            who, sev = hit
            if d.kind == "RoleBinding":
                sev = Severity(sev - 1)
            scope = "in every namespace" if d.kind == "ClusterRoleBinding" else f"in namespace {ctx.ns(d)}"
            yield r.finding(
                d,
                ("subjects", i),
                f"{d.kind} grants {get_path(d.data, ('roleRef', 'kind')) or 'role'} '{role}' {scope} to "
                f"{s.get('kind')} {s.get('name')}: {who}.",
                severity=sev,
            )


# =====================================================================================================
# AUDIT - network exposure
# =====================================================================================================


@rule(
    "KN-N001",
    "Namespace has workloads but no NetworkPolicy",
    Stage.AUDIT,
    "network",
    Severity.MEDIUM,
    "Add a default-deny ingress NetworkPolicy plus explicit allows (router/ingress controller, monitoring, "
    "same-app traffic).",
    "Without NetworkPolicy every pod in the cluster can reach these pods (lateral movement).",
    ("k8s-networkpolicy",),
    ("Deployments should have at least one ingress Network Policy",),
)
def _n001(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    if ctx.partial_bundle:
        # the namespace's NetworkPolicies were not passed, so their absence here means nothing
        ctx.cannot_decide(r.rule_id)
        return
    netpol_ns = {ctx.ns(d) for d in ctx.by_kind("NetworkPolicy")}
    flagged: set[str] = set()
    for d, _pt in ctx.workloads():
        ns = ctx.ns(d)
        long_running = LONG_RUNNING_KINDS | LONG_RUNNING_EMBEDDED_KINDS | {"Pod"}
        if d.kind in long_running and ns not in netpol_ns and ns not in flagged:
            flagged.add(ns)
            yield r.finding(d, ("metadata",), f"No NetworkPolicy for namespace {ns} in this bundle.")


@rule(
    "KN-N002",
    "Route without TLS",
    Stage.AUDIT,
    "network",
    Severity.HIGH,
    "Add spec.tls with termination: edge (or reencrypt/passthrough) and insecureEdgeTerminationPolicy: Redirect.",
    "Plain-HTTP Routes expose credentials and session cookies to anyone on the path.",
    ("ocp-routes",),
)
def _n002(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d in ctx.by_kind("Route"):
        tls = get_path(d.data, ("spec", "tls"))
        if not isinstance(tls, dict):
            yield r.finding(d, ("spec",), "Route serves plain HTTP (no spec.tls).")
        elif tls.get("insecureEdgeTerminationPolicy") == "Allow":
            yield r.finding(
                d,
                ("spec", "tls", "insecureEdgeTerminationPolicy"),
                "insecureEdgeTerminationPolicy: Allow also serves plain HTTP.",
                severity=Severity.MEDIUM,
            )


@rule(
    "KN-N003",
    "Ingress without TLS",
    Stage.AUDIT,
    "network",
    Severity.MEDIUM,
    "Add spec.tls with a certificate Secret (cert-manager can issue it).",
    "Plain-HTTP ingress exposes traffic in transit.",
    ("k8s-networkpolicy",),
)
def _n003(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d in ctx.by_kind("Ingress"):
        if not get_path(d.data, ("spec", "tls")):
            yield r.finding(d, ("spec",), "Ingress has no spec.tls.")


# Annotation -> values that make a cloud load balancer internal-only (documented by each provider / controller).
INTERNAL_LB_ANNOTATIONS: dict[str, frozenset[str]] = {
    "service.beta.kubernetes.io/aws-load-balancer-internal": frozenset({"true", "0.0.0.0/0"}),
    "service.beta.kubernetes.io/aws-load-balancer-scheme": frozenset({"internal"}),  # AWS Load Balancer Controller
    "service.beta.kubernetes.io/azure-load-balancer-internal": frozenset({"true"}),
    "networking.gke.io/load-balancer-type": frozenset({"internal"}),
    "cloud.google.com/load-balancer-type": frozenset({"internal"}),
    "service.beta.kubernetes.io/openstack-internal-load-balancer": frozenset({"true"}),
    "service.beta.kubernetes.io/oci-load-balancer-internal": frozenset({"true"}),
    "service.kubernetes.io/ibm-load-balancer-cloud-provider-ip-type": frozenset({"private"}),
}


@rule(
    "KN-N004",
    "LoadBalancer Service open to the internet",
    Stage.AUDIT,
    "network",
    Severity.MEDIUM,
    "Set spec.loadBalancerSourceRanges, or make it internal (on AWS/ROSA: annotation "
    'service.beta.kubernetes.io/aws-load-balancer-internal: "true"), or front it with a Route/Ingress.',
    "A public cloud load balancer without source ranges is reachable from anywhere.",
    ("k8s-service-lb",),
    ("Deployments with externally exposed endpoints",),
)
def _n004(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d in ctx.by_kind("Service"):
        if get_path(d.data, ("spec", "type")) != "LoadBalancer":
            continue
        ann = get_path(d.data, ("metadata", "annotations")) or {}
        internal = isinstance(ann, dict) and any(
            str(ann.get(k, "")).strip().lower() in vals for k, vals in INTERNAL_LB_ANNOTATIONS.items()
        )
        ranges = get_path(d.data, ("spec", "loadBalancerSourceRanges")) or []
        if internal:
            continue
        if not ranges:
            yield r.finding(
                d, ("spec", "type"), "type: LoadBalancer without loadBalancerSourceRanges or an internal annotation."
            )
        elif isinstance(ranges, list) and any(str(x).strip() in {"0.0.0.0/0", "::/0"} for x in ranges):
            yield r.finding(
                d,
                ("spec", "loadBalancerSourceRanges"),
                "loadBalancerSourceRanges includes 0.0.0.0/0 or ::/0, which allows the whole internet.",
            )


@rule(
    "KN-N005",
    "NodePort Service",
    Stage.AUDIT,
    "network",
    Severity.LOW,
    "Prefer ClusterIP + Route/Ingress; NodePorts open a port on every node.",
    "NodePorts widen the attack surface.",
    ("k8s-service-lb",),
)
def _n005(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d in ctx.by_kind("Service"):
        if get_path(d.data, ("spec", "type")) == "NodePort":
            yield r.finding(d, ("spec", "type"), "type: NodePort exposes a port on every node.")


_ANY_CIDR = {"0.0.0.0/0", "::/0"}


@rule(
    "KN-N006",
    "EgressFirewall rule is shadowed",
    Stage.AUDIT,
    "network",
    Severity.HIGH,
    "Put specific Allow rules first and the catch-all Deny 0.0.0.0/0 last.",
    "EgressFirewall rules are evaluated in order and the first match wins, so an early catch-all Deny makes every "
    "later Allow dead code.",
    ("ocp-egressfirewall",),
)
def _n006(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d in ctx.by_kind("EgressFirewall"):
        egress = get_path(d.data, ("spec", "egress")) or []
        catch_all_at: int | None = None
        for i, e in enumerate(egress):
            if not isinstance(e, dict):
                continue
            cidr = get_path(e, ("to", "cidrSelector"))
            if catch_all_at is not None:
                yield r.finding(
                    d,
                    ("spec", "egress", i),
                    f"Rule {i} ({e.get('type')}) can never match: rule "
                    f"{catch_all_at} already matches all destinations.",
                )
            elif cidr in _ANY_CIDR and not e.get("ports"):
                catch_all_at = i


@rule(
    "KN-N007",
    "NetworkPolicy allows all ingress",
    Stage.AUDIT,
    "network",
    Severity.MEDIUM,
    "Restrict 'from' to specific namespaceSelector/podSelector peers and ports.",
    "An ingress rule of {} admits traffic from every pod and every external source.",
    ("k8s-networkpolicy",),
)
def _n007(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d in ctx.by_kind("NetworkPolicy"):
        for i, rule_ in enumerate(get_path(d.data, ("spec", "ingress")) or []):
            if not isinstance(rule_, dict):
                continue
            peers = rule_.get("from")
            if not peers:
                if not rule_.get("ports"):
                    yield r.finding(d, ("spec", "ingress", i), "Ingress rule admits all sources on all ports.")
                continue
            for j, peer in enumerate(peers if isinstance(peers, list) else []):
                if not isinstance(peer, dict):
                    continue
                ipb = peer.get("ipBlock")
                if isinstance(ipb, dict) and str(ipb.get("cidr", "")).strip() in _ANY_CIDR and not ipb.get("except"):
                    yield r.finding(
                        d,
                        ("spec", "ingress", i, "from", j, "ipBlock"),
                        f"ipBlock {ipb.get('cidr')} admits every source address.",
                    )
                ns_sel, pod_sel = peer.get("namespaceSelector"), peer.get("podSelector")
                if ns_sel == {} and pod_sel in (None, {}):
                    yield r.finding(
                        d,
                        ("spec", "ingress", i, "from", j, "namespaceSelector"),
                        "namespaceSelector: {} without a podSelector admits every pod in every namespace.",
                    )


@rule(
    "KN-N008",
    "Service uses externalIPs",
    Stage.AUDIT,
    "network",
    Severity.HIGH,
    "Remove spec.externalIPs and publish the Service through a LoadBalancer Service, a Route or an Ingress; enable "
    "the DenyServiceExternalIPs admission controller on the API server (on a managed platform, ask the provider).",
    "CVE-2020-8554 (every Kubernetes version; the Kubernetes CVE feed says there is no patch, the flaw is in the "
    "design): anyone who can create or update a Service can set externalIPs to any address and so intercept "
    "cluster traffic meant for that address (man in the middle). The Kubernetes docs describe the feature as very "
    "powerful (it allows network traffic interception), say most users do not need it, and recommend the "
    "DenyServiceExternalIPs admission controller, which rejects all net-new use of the field. The field is now "
    "on its way out as well: KEP-5707 deprecates it in Kubernetes 1.36 behind a kube-proxy feature gate "
    "AllowServiceExternalIPs, which the KEP plans to switch off by default about four releases later and to lock "
    "off three releases after that -- tentatively 1.40 and 1.43, both of which the KEP itself marks as tentative. "
    "The KEP gives no replacement inside the Service API: it points to a LoadBalancer Service with a cloud "
    "provider, an Ingress controller, or the Gateway API, which it recommends for new deployments. So this is "
    "worth fixing on a schedule rather than only on principle.",
    ("k8s-cve-2020-8554", "k8s-kep-5707", "k8s-admission-deny-external-ips"),
)
def _n008(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d in ctx.by_kind("Service"):
        ips = get_path(d.data, ("spec", "externalIPs"))
        if isinstance(ips, list) and ips:
            yield r.finding(
                d,
                ("spec", "externalIPs"),
                f"Service declares externalIPs {[str(x) for x in ips]}: CVE-2020-8554 (every version, no patch) lets "
                "anyone who can create a Service intercept traffic to those addresses from inside the cluster. "
                "Remove externalIPs and enable the DenyServiceExternalIPs admission controller.",
            )


def _annotation_cves(short: str) -> str:
    return "; ".join(f"{cve} ({what})" for cve, what in INGRESS_NGINX_ANNOTATION_CVES.get(short, ()))


@rule(
    "KN-N009",
    "Ingress uses a risky ingress-nginx annotation",
    Stage.AUDIT,
    "network",
    Severity.HIGH,
    "Remove the annotation (move the behaviour into the application or the controller's own configuration); if it "
    "must stay, run a fixed controller release with --enable-annotation-validation, keep allow-snippet-annotations "
    "false and annotations-risk-level at High or below in the controller ConfigMap, and plan the move to a Gateway "
    "API implementation, since ingress-nginx is retired.",
    "ingress-nginx turns some annotation values into nginx configuration. Its annotation risk list rates the five "
    "snippet annotations Critical (raw configuration) and ten more High; these annotations carried the published "
    "injection CVEs: CVE-2021-25742 (snippets read every Secret in the cluster), CVE-2021-25746 (directive "
    "injection through annotation values), CVE-2023-5043 and CVE-2023-5044 (configuration-snippet, "
    "permanent-redirect), CVE-2025-24514, CVE-2025-1097 and CVE-2025-1098 (auth-url, auth-tls-match-cn, "
    "mirror-target and mirror-host), CVE-2025-15566 (auth-proxy-set-headers), CVE-2026-1580 (auth-method), "
    "CVE-2026-24513 (auth-url) and CVE-2026-3288 (rewrite-target). Through the snippets, CVE-2021-25742 obtained "
    "all Secrets in the cluster from an Ingress alone.",
    (
        "ingress-nginx-annotations-risk",
        "k8s-cve-2021-25742",
        "k8s-cve-2021-25746",
        "k8s-cve-2023-5043",
        "k8s-cve-2023-5044",
        "k8s-cve-2025-24514",
        "k8s-cve-2025-1097",
        "k8s-cve-2025-1098",
        "k8s-cve-2025-15566",
        "k8s-cve-2026-1580",
        "k8s-cve-2026-24513",
        "k8s-cve-2026-3288",
        "ingress-nginx-retired",
    ),
)
def _n009(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d in ctx.by_kind("Ingress"):
        ann = get_path(d.data, ("metadata", "annotations"))
        if not isinstance(ann, dict):
            continue
        for key in sorted(str(k) for k in ann):
            if not key.startswith(INGRESS_NGINX_ANNOTATION_PREFIX):
                continue
            short = key[len(INGRESS_NGINX_ANNOTATION_PREFIX) :]
            if short not in INGRESS_NGINX_RISKY_ANNOTATIONS:
                continue
            cves = _annotation_cves(short)
            path = ("metadata", "annotations", key)
            if short in INGRESS_NGINX_CRITICAL_ANNOTATIONS:
                yield r.finding(
                    d,
                    path,
                    f"Annotation {key} is a snippet, rated Critical risk by ingress-nginx because it injects raw nginx "
                    f"configuration into the controller; {cves}. Remove it and keep allow-snippet-annotations "
                    '"false" in the controller ConfigMap.',
                )
            elif short in INGRESS_NGINX_HIGH_ANNOTATIONS:
                detail = cves or "CVE-2021-25746 (directive injection through annotation values, fixed in v1.2.0)"
                yield r.finding(
                    d,
                    path,
                    f"Annotation {key} is rated High risk by ingress-nginx (its value reaches the nginx "
                    f"configuration); {detail}. Remove it or run a fixed controller with "
                    "--enable-annotation-validation.",
                    severity=Severity.MEDIUM,
                )
            else:
                yield r.finding(
                    d,
                    path,
                    f"Annotation {key} carried a published injection vulnerability: {cves}. Remove it or run a fixed "
                    "controller with --enable-annotation-validation.",
                    severity=Severity.MEDIUM,
                )


@rule(
    "KN-N010",
    "ingress-nginx ConfigMap widens what an Ingress may ask of the controller",
    Stage.AUDIT,
    "network",
    Severity.HIGH,
    'Set allow-snippet-annotations: "false" (the default), leave annotations-risk-level at High (the default) and '
    'strict-validate-path-type: "true" (the default) in the ingress-nginx controller ConfigMap, or remove the keys.',
    "The controller ConfigMap decides which annotations an Ingress may use. allow-snippet-annotations: true re-enables "
    "the snippet annotations through which CVE-2021-25742 read every Secret in the cluster (the feed's fix is to set "
    "it to false); annotations-risk-level: Critical accepts the Critical-risk annotations, which the default High "
    "refuses; strict-validate-path-type: false drops the path validation added for CVE-2022-4886.",
    (
        "ingress-nginx-configmap",
        "k8s-cve-2021-25742",
        "k8s-cve-2023-5043",
        "k8s-cve-2022-4886",
        "ingress-nginx-annotations-risk",
    ),
)
def _n010(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d in ctx.by_kind("ConfigMap"):
        data = d.data.get("data") if isinstance(d.data, dict) else None
        if not isinstance(data, dict):
            continue
        for key, (unsafe, default, allows) in INGRESS_NGINX_CONFIGMAP_KEYS.items():
            value = data.get(key)
            if value is None or str(value).strip().lower() != unsafe:
                continue
            cve = {
                "allow-snippet-annotations": "CVE-2021-25742 (snippets read every Secret in the cluster)",
                "annotations-risk-level": "CVE-2021-25742, CVE-2023-5043 (snippet injection)",
                "strict-validate-path-type": "CVE-2022-4886 (path sanitization bypass)",
            }[key]
            yield r.finding(
                d,
                ("data", key),
                f"ConfigMap sets {key}: {str(value).strip()!r} (default {default}), which lets every Ingress use "
                f"{allows}; {cve}. Set it back to the default.",
                severity=Severity.HIGH if key != "strict-validate-path-type" else Severity.MEDIUM,
            )


def ingress_targets_nginx(d: Document) -> bool:
    """The Ingress names ingress-nginx: class 'nginx' (field or annotation) or an nginx.ingress.kubernetes.io/ key."""
    ann = get_path(d.data, ("metadata", "annotations"))
    ann = ann if isinstance(ann, dict) else {}
    spec = get_path(d.data, ("spec",))
    cls = spec.get("ingressClassName") if isinstance(spec, dict) else None
    return (
        (cls is not None and str(cls).strip() == INGRESS_NGINX_CLASS)
        or str(ann.get("kubernetes.io/ingress.class", "")).strip() == INGRESS_NGINX_CLASS
        or any(str(k).startswith(INGRESS_NGINX_ANNOTATION_PREFIX) for k in ann)
    )


def ingress_names_no_class(d: Document) -> bool:
    ann = get_path(d.data, ("metadata", "annotations"))
    spec = get_path(d.data, ("spec",))
    return not (isinstance(spec, dict) and "ingressClassName" in spec) and not (
        isinstance(ann, dict) and "kubernetes.io/ingress.class" in ann
    )


@rule(
    "KN-N011",
    "Ingress path type ImplementationSpecific on ingress-nginx",
    Stage.AUDIT,
    "network",
    Severity.HIGH,
    "Use pathType Prefix or Exact (ingress-nginx validates those paths when strict-validate-path-type is true, the "
    "default), and run ingress-nginx v1.13.7, v1.14.3 or later; a regular-expression path (use-regex) can only be "
    "ImplementationSpecific, so upgrade before keeping one. Plan the move to a Gateway API implementation.",
    "CVE-2026-24512 (ingress-nginx before v1.13.7 and v1.14.3): a rules.http.paths.path value injected nginx "
    "configuration into the controller, which can read every Secret in the cluster. Before upgrading, the advisory's "
    "mitigation is a validating admission controller that rejects Ingress resources with the ImplementationSpecific "
    "path type, the one path type whose paths ingress-nginx does not validate. An Ingress that names no class is "
    "served by the cluster's default IngressClass, which may be ingress-nginx (not on OpenShift, whose router serves "
    "it).",
    ("k8s-cve-2026-24512", "ingress-nginx-configmap", "ingress-nginx-retired"),
)
def _n011(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d in ctx.by_kind("Ingress"):
        if ingress_targets_nginx(d):
            sev, who = Severity.HIGH, "ingress-nginx serves this Ingress"
        elif ingress_names_no_class(d) and not ctx.is_openshift:
            sev = Severity.LOW
            who = (
                "the Ingress names no class, so the cluster's default IngressClass serves it (if that is ingress-nginx)"
            )
        else:
            continue
        for i, rule_ in enumerate(get_path(d.data, ("spec", "rules")) or []):
            paths = get_path(rule_, ("http", "paths")) if isinstance(rule_, dict) else None
            for j, p in enumerate(paths if isinstance(paths, list) else []):
                if isinstance(p, dict) and p.get("pathType") == "ImplementationSpecific":
                    yield r.finding(
                        d,
                        ("spec", "rules", i, "http", "paths", j, "pathType"),
                        f"Path {p.get('path', '')!r} has pathType ImplementationSpecific and {who}: CVE-2026-24512 "
                        "(fixed in v1.13.7 and v1.14.3) injected nginx configuration through such paths, and the "
                        "advisory's mitigation is to reject the ImplementationSpecific path type at admission. Use "
                        "Prefix or Exact.",
                        severity=sev,
                    )


def _selects_something(selector: dict[str, Any]) -> bool:
    return bool(selector.get("matchLabels") or selector.get("matchExpressions"))


@rule(
    "KN-N012",
    "NetworkPolicy selects no pod in this bundle",
    Stage.AUDIT,
    "network",
    Severity.MEDIUM,
    "Make spec.podSelector match the pod template labels of the workloads the policy is for (or use podSelector: {} "
    "for every pod in the namespace).",
    "A NetworkPolicy applies only to the pods its podSelector selects. One that selects none of the namespace's pods "
    "(often a label typo) protects nothing, while the namespace still looks covered (KN-N001 passes): the pods it "
    "was written for accept traffic from every pod.",
    ("k8s-networkpolicy",),
)
def _n012(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    by_ns: dict[str, list[PodTemplate]] = {}
    for d, pt in ctx.workloads():
        by_ns.setdefault(ctx.ns(d), []).append(pt)
    for d in ctx.by_kind("NetworkPolicy"):
        sel = get_path(d.data, ("spec", "podSelector"))
        pods = by_ns.get(ctx.ns(d))
        if not isinstance(sel, dict) or not _selects_something(sel) or not pods:
            continue
        verdicts = [selector_decides(sel, pt) for pt in pods]
        if any(v is True for v in verdicts):
            continue
        if any(v is None for v in verdicts):
            # Same reason as KN-V011: an operator-merged label could be exactly the one this selector asks for,
            # and "this policy protects nothing" is the most alarming thing this rule can say (G231).
            ctx.cannot_decide(r.rule_id)
            continue
        yield r.finding(
            d,
            ("spec", "podSelector"),
            f"podSelector {sel.get('matchLabels') or sel} selects none of the {len(pods)} pod template(s) in "
            f"namespace {ctx.ns(d)}: this policy protects nothing.",
        )


_DNS_PORTS = frozenset({53, 5353})  # 53 is the Service port; OpenShift CoreDNS pods listen on 5353


def _rule_allows_dns(rule: dict[str, Any]) -> bool:
    """True when this one egress rule lets UDP reach a DNS port.

    UDP, not TCP. ``NetworkPolicyPort.protocol`` defaults to TCP, so a bare ``{port: 53}`` permits TCP
    only, and a resolver queries UDP first -- glibc falls back to TCP only on a truncated answer and
    musl does not fall back at all. Allowing TCP 53 alone leaves lookups timing out, which is the
    commonest forgotten-``protocol: UDP`` mistake, so it must not clear the finding.

    A rule with no ``ports`` permits every port and protocol to its peers, and an empty rule permits
    everything. A port range is honoured (``{port: 1, endPort: 1024}`` covers 53). A named port cannot
    be resolved from the manifest -- the DNS pod that declares it is never in the bundle -- so it is
    treated as permitting DNS: the manifest does not prove stranding, and reporting it would flag a
    policy that works.
    """
    ports = rule.get("ports")
    if ports is None:
        return True
    if not isinstance(ports, list):
        return False
    for entry in ports:
        if not isinstance(entry, dict):
            continue
        if str(entry.get("protocol") or "TCP").upper() != "UDP":
            continue
        port = entry.get("port")
        if port is None:
            return True  # every port to these peers
        if isinstance(port, int) or (isinstance(port, str) and port.isdigit()):
            lo = int(port)
            hi = int(entry["endPort"]) if str(entry.get("endPort") or "").isdigit() else lo
            if any(lo <= dns <= hi for dns in _DNS_PORTS):
                return True
        else:
            return True  # a named port: not resolvable here, and not disprovable either
    return False


def _egress_allows_dns(spec: dict[str, Any]) -> bool:
    """True when this policy lets the pods it selects reach cluster DNS.

    Peers are deliberately not checked: cluster DNS is reached by a Service address that a manifest need
    not mention, and demanding a kube-system peer here would report a policy that works.
    """
    rules = spec.get("egress")
    if not isinstance(rules, list):
        return False
    return any(_rule_allows_dns(r) for r in rules if isinstance(r, dict))


@rule(
    "KN-N013",
    "Egress is denied without allowing cluster DNS",
    Stage.AUDIT,
    "network",
    Severity.MEDIUM,
    "Add an egress rule allowing UDP and TCP port 53 to the cluster DNS namespace, or widen this policy.",
    "A policy that restricts egress and allows no route to port 53 stops every pod it selects from resolving "
    "names. The pods keep running and every outbound connection fails on lookup, which reads as an application "
    "outage rather than as a policy change.",
    ("k8s-networkpolicy",),
)
def _n013(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    if ctx.partial_bundle:
        # another policy in the namespace may allow 53, and it was not passed
        ctx.cannot_decide(r.rule_id)
        return
    by_ns: dict[str, list[dict[str, str]]] = {}
    for d, pt in ctx.workloads():
        if (pt.spec or {}).get("hostNetwork") is True:
            continue  # NetworkPolicy does not govern host-networked pods on the common plugins
        by_ns.setdefault(ctx.ns(d), []).append(pt.labels())
    egress_policies: dict[str, list[Document]] = {}
    for d in ctx.by_kind("NetworkPolicy"):
        spec = d.data.get("spec")
        if isinstance(spec, dict) and "Egress" in policy_types(spec):
            egress_policies.setdefault(ctx.ns(d), []).append(d)
    for ns, policies in egress_policies.items():
        pods = by_ns.get(ns) or []
        for d in policies:
            spec = d.data.get("spec") or {}
            sel = spec.get("podSelector")
            if not isinstance(sel, dict):
                continue
            selected = [labels for labels in pods if selector_matches(sel, labels)]
            if not selected:
                continue
            # Policies are additive, so DNS is reachable when ANY egress policy selecting the pod allows it.
            stranded = [
                labels
                for labels in selected
                if not any(
                    _egress_allows_dns(other.data.get("spec") or {})
                    for other in policies
                    if selector_matches((other.data.get("spec") or {}).get("podSelector") or {}, labels)
                )
            ]
            if stranded:
                yield r.finding(
                    d,
                    ("spec", "egress"),
                    f"Egress is restricted for {len(stranded)} pod template(s) in namespace {ns} and no policy "
                    "selecting them allows UDP to port 53 or 5353, so they cannot resolve any name.",
                )


@rule(
    "KN-N014",
    "Admin network policy the cluster's CNI does not enforce",
    Stage.AUDIT,
    "network",
    Severity.HIGH,
    "Replace it with the kind this CNI does enforce (ClusterNetworkPolicy for Calico 3.32+), or remove it and move "
    "the rules into NetworkPolicies.",
    "An AdminNetworkPolicy or BaselineAdminNetworkPolicy a CNI stopped enforcing is in the cluster and decides "
    "nothing: Calico removed support in 3.32 without reporting an error.",
)
def _n014(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    """The inert-policy case as a finding a gate can fail on.

    No manifest states which CNI runs the cluster, so without ``--cni`` this rule cannot decide and says so --
    "nobody told me the CNI" is not "the policy is enforced", and a coverage record that counted it clean would be
    reporting a check that never ran (G202). The same holds for a CNI upstream does not characterise, and for a
    version too coarse to sit on either side of the removal. HIGH for the same reason KN-S030 is: a policy gate
    that silently stopped applying is worse than one that was never there, because somebody is relying on it.
    """
    from kube_noob.debug.cni import REPLACEMENT, admin_tier_reason, admin_tier_support, parse_cni

    docs = ctx.by_kind(ADMIN_TIER_KINDS[0], ADMIN_TIER_KINDS[1])
    if not ctx.cni:
        if docs:
            ctx.cannot_decide(r.rule_id)
        return  # nothing of this kind is nothing to decide, whatever the CNI
    try:
        name, version = parse_cni(ctx.cni)
    except ValueError:
        if docs:
            ctx.cannot_decide(r.rule_id)
        return
    support = admin_tier_support(name, version)
    if support == "enforced" or not docs:
        return
    if support == "unknown":
        ctx.cannot_decide(r.rule_id)
        return
    reason = admin_tier_reason(name, version, support)
    for d in docs:
        yield r.finding(
            d,
            ("kind",),
            f"{d.kind} is evaluated by kube-noob and by nothing on this cluster: {reason}. "
            f"Move its rules into a {REPLACEMENT} or into NetworkPolicies.",
        )


@rule(
    "KN-S030",
    "Admission webhook fails open",
    Stage.AUDIT,
    "security",
    Severity.HIGH,
    "Set failurePolicy: Fail, and scope the webhook with namespaceSelector or objectSelector so a failure "
    "cannot stall the whole cluster.",
    "failurePolicy: Ignore means the API server admits the object when the webhook cannot be reached. The "
    "control appears to be in place and is silently not applied whenever the service is down, upgrading or "
    "unreachable, which is also when a bad object is most likely to be admitted. The API default is Fail, so "
    "Ignore is a decision rather than an oversight.",
    ("k8s-admission-webhook-failure-policy",),
)
def _s030(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d in ctx.by_kind("ValidatingWebhookConfiguration", "MutatingWebhookConfiguration"):
        hooks = d.data.get("webhooks")
        if not isinstance(hooks, list):
            continue
        for i, hook in enumerate(hooks):
            if not isinstance(hook, dict):
                continue
            policy = hook.get("failurePolicy")
            if policy is None or policy == "Fail":
                continue  # absent means Fail, which is the safe default
            name = str(hook.get("name") or f"webhooks[{i}]")
            if policy != "Ignore":
                # Invalid is not the safe default. The API server refuses the object, so the control the
                # manifest describes does not exist at all -- the same stance selectors take (G185).
                yield r.finding(
                    d,
                    ("webhooks", i, "failurePolicy"),
                    f"Webhook '{name}' sets failurePolicy: {policy!r}, which is neither Fail nor Ignore. The API "
                    "server refuses this object, so the check it describes is not running at all.",
                )
                continue
            yield r.finding(
                d,
                ("webhooks", i, "failurePolicy"),
                f"Webhook '{name}' sets failurePolicy: Ignore, so the object is admitted whenever this webhook "
                "cannot be reached and the check it performs is skipped without rejecting anything.",
            )


# =====================================================================================================
# AUDIT - storage
# =====================================================================================================


def _storage_classes(ctx: AuditContext) -> dict[str, dict[str, Any]]:
    return {d.name: d.data for d in ctx.by_kind("StorageClass") if isinstance(d.data, dict)}


def _provisioner_for(ctx: AuditContext, sc_name: str | None) -> str | None:
    if sc_name is None:
        return None
    local = _storage_classes(ctx).get(sc_name)
    if local and local.get("provisioner"):
        return str(local["provisioner"])
    return KNOWN_STORAGE_CLASSES.get(sc_name)


def _pvc_like(ctx: AuditContext) -> Iterator[tuple[Document, PathT, dict[str, Any]]]:
    for d in ctx.by_kind("PersistentVolumeClaim"):
        if isinstance(d.data.get("spec"), dict):
            yield d, ("spec",), d.data["spec"]
    for d in ctx.by_kind("StatefulSet"):
        for i, vct in enumerate(get_path(d.data, ("spec", "volumeClaimTemplates")) or []):
            if isinstance(vct, dict) and isinstance(vct.get("spec"), dict):
                yield d, ("spec", "volumeClaimTemplates", i, "spec"), vct["spec"]


@rule(
    "KN-ST001",
    "ReadWriteMany requested from a ReadWriteOnce-only StorageClass",
    Stage.AUDIT,
    "storage",
    Severity.HIGH,
    "Use a shared-filesystem class: efs-sc (AWS EFS CSI) on ROSA/EKS, ocs-storagecluster-cephfs (ODF) or NFS on "
    "OpenShift on-prem, azurefile-csi on Azure. gp3-csi/gp2-csi (EBS) are block volumes and only support "
    "ReadWriteOnce.",
    "The provisioner cannot satisfy RWX, so the PVC stays Pending (ProvisioningFailed).",
    ("k8s-pv-access-modes", "aws-ebs-csi", "aws-efs-csi", "odf-access-modes"),
)
def _st001(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, path, spec in _pvc_like(ctx):
        modes = spec.get("accessModes") or []
        if "ReadWriteMany" not in modes:
            continue
        sc = spec.get("storageClassName")
        prov = _provisioner_for(ctx, sc)
        if prov is None:
            if sc is None:
                if ctx.is_rosa:
                    yield r.finding(
                        d,
                        (*path, "accessModes"),
                        "RWX without storageClassName: the ROSA default "
                        "class (gp3-csi, EBS) is RWO-only, so this PVC will not bind.",
                    )
                elif ctx.is_openshift:
                    yield r.finding(
                        d,
                        (*path, "accessModes"),
                        "RWX without storageClassName: verify the cluster "
                        "default StorageClass supports ReadWriteMany (most block classes do not).",
                        severity=Severity.MEDIUM,
                    )
            elif sc != "":
                # "" = static binding to a pre-created PV, no provisioner involved. Only this branch of the rule
                # reads another object; the rest decide from the claim alone and still fire on a partial bundle.
                if ctx.partial_bundle:
                    # Declining is not the same as passing. Skipping this branch silently left the rule in
                    # evaluated_rules, so a per-control summary counted it `clean` while the report's own
                    # assumptions said an undeclared StorageClass was not evaluated -- the two halves of one
                    # report disagreeing, with the reassuring half the one a reader sees first.
                    ctx.cannot_decide(r.rule_id)
                    continue
                yield r.finding(
                    d,
                    (*path, "storageClassName"),
                    f"StorageClass '{sc}' is neither defined in this bundle nor a known platform class: cannot verify "
                    "that its provisioner supports ReadWriteMany. Include the StorageClass or use a known RWX class.",
                    severity=Severity.MEDIUM,
                )
            continue
        p = PROVISIONERS.get(prov)
        if p is None:
            yield r.finding(
                d,
                (*path, "storageClassName"),
                f"Provisioner '{prov}' of StorageClass '{sc}' is not in kube-noob's catalog: verify it supports "
                "ReadWriteMany before relying on it.",
                severity=Severity.MEDIUM,
            )
            continue
        block = spec.get("volumeMode") == "Block"
        if not (p.rwx_filesystem or (block and p.rwx_block)):
            hint = " (RWX is only possible with volumeMode: Block)" if p.rwx_block else ""
            yield r.finding(
                d,
                (*path, "storageClassName"),
                f"StorageClass '{sc}' ({prov}: {p.description}) cannot provide ReadWriteMany{hint}.",
            )


@rule(
    "KN-ST002",
    "ReadWriteOnce volume shared by a rolling Deployment",
    Stage.AUDIT,
    "storage",
    Severity.HIGH,
    "Use a StatefulSet with volumeClaimTemplates, strategy: Recreate with replicas: 1, or a RWX class if the app "
    "supports concurrent writers.",
    "A RWO volume attaches to one node. Extra replicas or surge pods scheduled elsewhere hang in "
    "ContainerCreating with 'Multi-Attach error for volume'.",
    ("k8s-pv-access-modes",),
)
def _st002(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    pvcs = {(ctx.ns(d), d.name): d.data.get("spec", {}) for d in ctx.by_kind("PersistentVolumeClaim")}
    for d in ctx.by_kind("Deployment", "DeploymentConfig"):
        pt = pod_template(d)
        if pt is None:
            continue
        for i, v in enumerate(pt.spec.get("volumes") or []):
            claim = get_path(v, ("persistentVolumeClaim", "claimName")) if isinstance(v, dict) else None
            if not claim:
                continue
            spec = pvcs.get((ctx.ns(d), str(claim)))
            modes = (spec or {}).get("accessModes") or []
            if spec is None or "ReadWriteMany" in modes or "ReadOnlyMany" in modes:
                continue
            reps = replicas(d) or 1
            strategy = get_path(d.data, ("spec", "strategy", "type")) or "RollingUpdate"
            if reps > 1:
                yield r.finding(
                    d,
                    (*pt.path, "volumes", i),
                    f"{reps} replicas share RWO PVC '{claim}'; pods on other nodes cannot attach it.",
                )
            elif strategy in {"RollingUpdate", "Rolling"}:
                yield r.finding(
                    d,
                    ("spec", "strategy"),
                    f"RollingUpdate with RWO PVC '{claim}': the surge pod "
                    "can deadlock on Multi-Attach. Use strategy: Recreate.",
                    severity=Severity.MEDIUM,
                )


@rule(
    "KN-ST003",
    "Zonal storage with Immediate volume binding",
    Stage.AUDIT,
    "storage",
    Severity.MEDIUM,
    "Set volumeBindingMode: WaitForFirstConsumer so the volume is created in the zone the pod is scheduled to.",
    "Immediate binding may create the volume in a zone where the pod cannot run, leaving it Pending.",
    ("k8s-storageclass-binding",),
)
def _st003(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d in ctx.by_kind("StorageClass"):
        p = PROVISIONERS.get(str(d.data.get("provisioner")))
        mode = d.data.get("volumeBindingMode", "Immediate")
        if p and p.zonal and mode == "Immediate":
            yield r.finding(d, ("volumeBindingMode",), f"{p.name} is zonal but volumeBindingMode is Immediate.")


@rule(
    "KN-ST004",
    "EFS StorageClass is missing required parameters",
    Stage.AUDIT,
    "storage",
    Severity.HIGH,
    "Set parameters.provisioningMode: efs-ap and parameters.fileSystemId: fs-xxxxxxxx (plus directoryPerms).",
    "Dynamic provisioning with the AWS EFS CSI driver uses access points and needs the file system id.",
    ("aws-efs-csi", "rosa-efs"),
)
def _st004(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d in ctx.by_kind("StorageClass"):
        if d.data.get("provisioner") != "efs.csi.aws.com":
            continue
        params = d.data.get("parameters") or {}
        missing = [k for k in ("provisioningMode", "fileSystemId") if not params.get(k)]
        if missing:
            yield r.finding(d, ("parameters",), f"Missing parameter(s): {', '.join(missing)}.")


@rule(
    "KN-ST005",
    "PVC has no storage request",
    Stage.VALIDATE,
    "storage",
    Severity.HIGH,
    "Set spec.resources.requests.storage (e.g. 10Gi).",
    "The API server rejects PersistentVolumeClaims without a storage request.",
    ("k8s-pv-access-modes",),
)
def _st005(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, path, spec in _pvc_like(ctx):
        if not get_path(spec, ("resources", "requests", "storage")):
            yield r.finding(d, (*path, "resources"), "spec.resources.requests.storage is missing.")


# A '..' path segment ('/', '\' and '#', the NFS and SMB volumeHandle separator, delimit segments). RE2 too.
PATH_TRAVERSAL = r"(^|[/\\#])\.\.([/\\#]|$)"
_PATH_TRAVERSAL = re.compile(PATH_TRAVERSAL[:-2] + r"\Z)")
# CSI drivers whose subDir traversal deleted directories outside the share: driver -> (CVE, project, fixed release).
CSI_SUBDIR_TRAVERSAL: dict[str, tuple[str, str, str]] = {
    "nfs.csi.k8s.io": ("CVE-2026-3864", "CSI Driver for NFS", "v4.13.1"),
    "smb.csi.k8s.io": ("CVE-2026-3865", "CSI Driver for SMB", "v1.20.1"),
}


@rule(
    "KN-ST006",
    "PersistentVolume path carries command or traversal characters",
    Stage.AUDIT,
    "storage",
    Severity.HIGH,
    "Use a plain absolute local path, and a volumeHandle and subDir without '..' segments; run Windows nodes with "
    "kubelet v1.25.16, v1.26.11, v1.27.8, v1.28.4 or later, csi-driver-nfs v4.13.1 or later and csi-driver-smb "
    "v1.20.1 or later; let only cluster administrators create PersistentVolumes.",
    "CVE-2023-5528 (CVSS 7.2; kubelet from v1.8.0, fixed in v1.25.16, v1.26.11, v1.27.8 and v1.28.4): on Windows "
    "nodes the in-tree storage plugin ran a local PersistentVolume path as part of a command, so a user who could "
    "create pods and PersistentVolumes got admin rights on the node; the feed names PersistentVolume create events "
    "with local path fields containing special characters as the sign of exploitation. CVE-2026-3864 (csi-driver-nfs "
    "before v4.13.1) and CVE-2026-3865 (csi-driver-smb before v1.20.1): a '../' in the subDir of a volume identifier "
    "made the driver delete directories outside the share; the advisories say to look for traversal sequences in the "
    "volumeHandle of PersistentVolumes using these drivers.",
    ("k8s-cve-2023-5528", "k8s-cve-2026-3864", "k8s-cve-2026-3865"),
)
def _st006(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d in ctx.by_kind("PersistentVolume"):
        local = get_path(d.data, ("spec", "local", "path"))
        if isinstance(local, str) and _COMMAND_META.search(local):
            yield r.finding(
                d,
                ("spec", "local", "path"),
                f"Local path {local!r} carries {_meta_chars(local)}: the CVE-2023-5528 pattern, where kubelet on "
                "Windows nodes (before v1.25.16, v1.26.11, v1.27.8 and v1.28.4) ran the path as part of a command "
                "with admin rights on the node. Use a plain path.",
            )
        csi = get_path(d.data, ("spec", "csi"))
        hit = CSI_SUBDIR_TRAVERSAL.get(str(csi.get("driver"))) if isinstance(csi, dict) else None
        if hit is None or not isinstance(csi, dict):
            continue
        cve, project, fixed = hit
        attrs = csi.get("volumeAttributes")
        fields: list[tuple[PathT, object]] = [(("spec", "csi", "volumeHandle"), csi.get("volumeHandle"))]
        if isinstance(attrs, dict):
            fields.append((("spec", "csi", "volumeAttributes", "subDir"), attrs.get("subDir")))
        for path, value in fields:
            if isinstance(value, str) and _PATH_TRAVERSAL.search(value):
                yield r.finding(
                    d,
                    path,
                    f"{path[-1]} {value!r} of the {csi.get('driver')} volume has a '..' segment: {cve} ({project} "
                    f"before {fixed}) deleted directories outside the share through such a subDir. Remove the "
                    "traversal and upgrade the driver.",
                )


# =====================================================================================================
# CALIBRATE - reliability, HA, efficiency
# =====================================================================================================


def _long_running_containers(ctx: AuditContext) -> Iterator[tuple[Document, PodTemplate, ContainerRef]]:
    for d, pt in ctx.workloads():
        if d.kind in LONG_RUNNING_KINDS:
            for c in containers(pt, include_init=False):
                yield d, pt, c


@rule(
    "KN-C001",
    "No readiness probe",
    Stage.CALIBRATE,
    "reliability",
    Severity.MEDIUM,
    "Add a readinessProbe (httpGet on a /ready endpoint, or tcpSocket) so traffic only reaches ready pods.",
    "Without readiness, Services route to pods that are still starting or degraded, and rollouts cannot detect "
    "bad versions.",
    ("k8s-probes",),
)
def _c001(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, _pt, c in _long_running_containers(ctx):
        if not c.container.get("readinessProbe"):
            yield r.finding(d, c.path, f"Container '{c.name}' has no readinessProbe.")


@rule(
    "KN-C002",
    "No liveness probe",
    Stage.CALIBRATE,
    "reliability",
    Severity.LOW,
    "Add a livenessProbe that checks the process itself (not its dependencies); use a startupProbe for slow starts.",
    "Deadlocked processes are never restarted without liveness.",
    ("k8s-probes",),
)
def _c002(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, _pt, c in _long_running_containers(ctx):
        if not c.container.get("livenessProbe"):
            yield r.finding(d, c.path, f"Container '{c.name}' has no livenessProbe.")


@rule(
    "KN-C003",
    "Liveness probe is aggressive",
    Stage.CALIBRATE,
    "reliability",
    Severity.MEDIUM,
    "Use periodSeconds >= 10, failureThreshold >= 3 and timeoutSeconds < periodSeconds; add a startupProbe "
    "for slow boots.",
    "Aggressive liveness turns a slow dependency or GC pause into a restart storm (red-team: cascading failure).",
    ("k8s-probes",),
)
def _c003(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, _pt, c in _long_running_containers(ctx):
        p = c.container.get("livenessProbe")
        if not isinstance(p, dict):
            continue
        period, fail = p.get("periodSeconds", 10), p.get("failureThreshold", 3)
        timeout = p.get("timeoutSeconds", 1)
        issues = []
        if isinstance(fail, int) and fail < 2:
            issues.append(f"failureThreshold={fail}")
        if isinstance(period, int) and period < 5:
            issues.append(f"periodSeconds={period}")
        if isinstance(timeout, int) and isinstance(period, int) and timeout >= period:
            issues.append(f"timeoutSeconds({timeout}) >= periodSeconds({period})")
        if issues:
            yield r.finding(d, (*c.path, "livenessProbe"), f"Container '{c.name}': {', '.join(issues)}.")


@rule(
    "KN-C004",
    "Missing CPU/memory requests",
    Stage.CALIBRATE,
    "resources",
    Severity.MEDIUM,
    "Set resources.requests.cpu and resources.requests.memory from observed usage (p95).",
    "Without requests the scheduler overcommits nodes, pods get BestEffort QoS and are evicted first; HPA cannot "
    "compute utilization.",
    ("k8s-resources",),
    ("No CPU request or memory limit specified",),
)
def _c004(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, _pt, c in _resource_containers(ctx):
        req = get_path(c.container, ("resources", "requests")) or {}
        missing = [k for k in ("cpu", "memory") if k not in req]
        if missing:
            yield r.finding(d, (*c.path, "resources"), f"Container '{c.name}' has no {'/'.join(missing)} request.")


@rule(
    "KN-C005",
    "Missing memory limit",
    Stage.CALIBRATE,
    "resources",
    Severity.MEDIUM,
    "Set resources.limits.memory (typically 1-2x the request).",
    "An unbounded container can exhaust node memory and trigger node-level OOM kills of other workloads.",
    ("k8s-resources",),
    ("No CPU request or memory limit specified",),
)
def _c005(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, _pt, c in _resource_containers(ctx):
        if not get_path(c.container, ("resources", "limits", "memory")):
            yield r.finding(d, (*c.path, "resources"), f"Container '{c.name}' has no memory limit.")


@rule(
    "KN-C006",
    "Request exceeds limit",
    Stage.VALIDATE,
    "resources",
    Severity.HIGH,
    "Make every request <= its limit.",
    "The API server rejects containers whose request is greater than the limit.",
    ("k8s-resources",),
)
def _c006(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, _pt, c in _resource_containers(ctx):
        req = get_path(c.container, ("resources", "requests")) or {}
        lim = get_path(c.container, ("resources", "limits")) or {}
        for k in ("cpu", "memory", "ephemeral-storage"):
            if k in req and k in lim:
                try:
                    if parse_quantity(req[k]) > parse_quantity(lim[k]):
                        yield r.finding(
                            d,
                            (*c.path, "resources", "requests", k),
                            f"Container '{c.name}' {k} request {req[k]} > limit {lim[k]}.",
                        )
                except ValueError as exc:
                    yield r.finding(d, (*c.path, "resources"), f"Container '{c.name}': {exc}.")


@rule(
    "KN-C007",
    "Single replica",
    Stage.CALIBRATE,
    "availability",
    Severity.MEDIUM,
    "Run at least 2 replicas (3 across zones for production) with a PodDisruptionBudget.",
    "One replica means downtime on every node drain, upgrade or node failure.",
    ("k8s-pdb",),
)
def _c007(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d in ctx.by_kind(*REPLICATED_KINDS):
        reps = replicas(d)
        if reps is not None and reps < 2 and not _has_hpa(ctx, d):
            yield r.finding(d, ("spec", "replicas"), f"{d.kind} runs {reps} replica(s).")


def _has_hpa(ctx: AuditContext, d: Document) -> bool:
    for h in ctx.by_kind("HorizontalPodAutoscaler"):
        ref = get_path(h.data, ("spec", "scaleTargetRef")) or {}
        if ref.get("name") == d.name and ref.get("kind") == d.kind and ctx.ns(h) == ctx.ns(d):
            return True
    return False


def _pdbs_for(ctx: AuditContext, d: Document, labels: dict[str, str]) -> list[Document]:
    return [
        p
        for p in ctx.by_kind("PodDisruptionBudget")
        if ctx.ns(p) == ctx.ns(d) and selector_matches(get_path(p.data, ("spec", "selector")), labels)
    ]


@rule(
    "KN-C008",
    "No PodDisruptionBudget",
    Stage.CALIBRATE,
    "availability",
    Severity.LOW,
    "Add a PodDisruptionBudget with maxUnavailable: 1 for replicated workloads.",
    "Without a PDB a node drain may evict all replicas at once.",
    ("k8s-pdb",),
)
def _c008(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    if ctx.partial_bundle:
        # the namespace's PodDisruptionBudgets were not passed, so no match here means nothing
        ctx.cannot_decide(r.rule_id)
        return
    for d, pt in ctx.workloads():
        if d.kind in REPLICATED_KINDS and (replicas(d) or 1) >= 2 and not _pdbs_for(ctx, d, pt.labels()):
            yield r.finding(d, ("spec",), "No PodDisruptionBudget selects this workload.")


@rule(
    "KN-C009",
    "PodDisruptionBudget blocks all voluntary evictions",
    Stage.CALIBRATE,
    "availability",
    Severity.HIGH,
    "Use maxUnavailable: 1 (or minAvailable < replicas).",
    "A PDB that allows zero disruptions blocks node drains, so cluster upgrades (including managed ROSA "
    "upgrades) stall on this node.",
    ("k8s-pdb",),
)
def _c009(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, pt in ctx.workloads():
        if d.kind not in REPLICATED_KINDS:
            continue
        reps = replicas(d) or 1
        for p in _pdbs_for(ctx, d, pt.labels()):
            spec = p.data.get("spec") or {}
            if pdb_allows_no_disruption(spec, reps):
                yield r.finding(p, ("spec",), f"{p.ref()} allows no disruptions for {d.ref()} ({reps} replicas).")


@rule(
    "KN-C010",
    "Replicas not spread across zones/nodes",
    Stage.CALIBRATE,
    "availability",
    Severity.LOW,
    "Add topologySpreadConstraints on topology.kubernetes.io/zone (and kubernetes.io/hostname) or pod anti-affinity.",
    "Replicas may all land on one node or zone; a single failure takes the app down.",
    ("k8s-topology-spread",),
)
def _c010(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, pt in ctx.workloads():
        if d.kind not in REPLICATED_KINDS or (replicas(d) or 1) < 2:
            continue
        if pt.spec.get("topologySpreadConstraints") or get_path(pt.spec, ("affinity", "podAntiAffinity")):
            continue
        sev = Severity.MEDIUM if ctx.is_rosa else Severity.LOW
        yield r.finding(d, pt.path, "No topologySpreadConstraints or podAntiAffinity.", severity=sev)


@rule(
    "KN-C011",
    "terminationGracePeriodSeconds is 0",
    Stage.CALIBRATE,
    "reliability",
    Severity.LOW,
    "Allow time for graceful shutdown (default 30s) and handle SIGTERM.",
    "A zero grace period kills in-flight requests and can corrupt state.",
    ("k8s-probes",),
)
def _c011(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for d, pt in ctx.workloads():
        if pt.spec.get("terminationGracePeriodSeconds") == 0:
            yield r.finding(d, (*pt.path, "terminationGracePeriodSeconds"), "Grace period is 0.")


@rule(
    "KN-C012",
    "HPA cannot compute CPU utilization",
    Stage.CALIBRATE,
    "resources",
    Severity.MEDIUM,
    "Set CPU requests on every container of the target workload.",
    "Utilization-based HPA divides usage by the request; missing requests leave the HPA at <unknown>.",
    ("k8s-resources",),
)
def _c012(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for h in ctx.by_kind("HorizontalPodAutoscaler"):
        ref = get_path(h.data, ("spec", "scaleTargetRef")) or {}
        metrics = get_path(h.data, ("spec", "metrics")) or []
        uses_cpu_util = any(
            get_path(m, ("resource", "name")) == "cpu" and get_path(m, ("resource", "target", "type")) == "Utilization"
            for m in metrics
            if isinstance(m, dict)
        )
        if not uses_cpu_util:
            continue
        for d, pt in ctx.workloads():
            is_target = d.name == ref.get("name") and d.kind == ref.get("kind") and ctx.ns(d) == ctx.ns(h)
            if is_target and any(
                not get_path(c.container, ("resources", "requests", "cpu")) for c in containers(pt, include_init=False)
            ):
                yield r.finding(h, ("spec", "metrics"), f"Target {d.ref()} has containers without CPU requests.")


def _pull_secret_names(spec: object) -> list[str]:
    refs = get_path(spec, ("imagePullSecrets",)) if isinstance(spec, dict) else None
    return [str(x["name"]) for x in refs or [] if isinstance(x, dict) and x.get("name")]


@rule(
    "KN-C013",
    "Pull secret exists only in another namespace",
    Stage.VALIDATE,
    "reliability",
    Severity.HIGH,
    "Create (or sync) the pull secret in the workload's namespace and link it to its ServiceAccount; on OpenShift put "
    "a registry every project uses in the global pull secret, and grant system:image-puller for another project's "
    "internal registry.",
    "imagePullSecrets name Secrets in the pod's own namespace (LocalObjectReference): kubelet never looks in another "
    "namespace, reports FailedToRetrieveImagePullSecret and the pull fails with ImagePullBackOff.",
    ("k8s-images",),
)
def _c013(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    secrets: dict[str, set[str]] = {}
    for s in ctx.by_kind("Secret"):
        if s.name:
            secrets.setdefault(s.name, set()).add(ctx.ns(s))
    if not secrets:
        return  # the bundle carries no Secrets: nothing to compare with

    def check(doc: Document, path: PathT, names: list[str]) -> Iterator[Finding]:
        ns = ctx.ns(doc)
        for i, name in enumerate(names):
            elsewhere = secrets.get(name, set()) - {ns}
            if elsewhere and ns not in secrets.get(name, set()):
                yield r.finding(
                    doc,
                    (*path, "imagePullSecrets", i),
                    f"Pull secret '{name}' is defined in namespace {', '.join(sorted(elsewhere))}, not in {ns}, "
                    f"where kubelet looks for it.",
                )

    for d, pt in ctx.workloads():
        yield from check(d, pt.path, _pull_secret_names(pt.spec))
    for sa in ctx.by_kind("ServiceAccount"):
        yield from check(sa, (), _pull_secret_names(sa.data))


@rule(
    "KN-C014",
    "Workload scaled by an HPA also sets spec.replicas",
    Stage.CALIBRATE,
    "availability",
    Severity.MEDIUM,
    "Remove spec.replicas from the manifest of a workload a HorizontalPodAutoscaler scales (in a Helm chart: "
    "{{- if not .Values.autoscaling.enabled }} replicas: ... {{- end }}); set the floor with the HPA's minReplicas.",
    "The Kubernetes docs recommend removing spec.replicas when an HPA is enabled: otherwise every kubectl apply (or "
    "GitOps sync) of the manifest scales the workload back to that number, which may not be desired and causes "
    "thrashing or flapping while the HPA is active, for example down to 2 replicas in the middle of a traffic peak. "
    "A target whose replica count is 0 deactivates an HPA whose minReplicas is above 0.",
    ("k8s-hpa-replicas",),
)
def _c014(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    for h in ctx.by_kind("HorizontalPodAutoscaler"):
        ref = get_path(h.data, ("spec", "scaleTargetRef"))
        if not isinstance(ref, dict):
            continue
        for d in ctx.by_kind(*REPLICATED_KINDS):
            if d.name != ref.get("name") or d.kind != ref.get("kind") or ctx.ns(d) != ctx.ns(h):
                continue
            spec = d.data.get("spec") if isinstance(d.data, dict) else None
            if not isinstance(spec, dict) or "replicas" not in spec:
                continue
            count = spec["replicas"]
            low = get_path(h.data, ("spec", "minReplicas"))
            low = low if isinstance(low, int) else 1
            if count == 0 and low > 0:
                yield r.finding(
                    d,
                    ("spec", "replicas"),
                    f"{d.ref()} sets replicas: 0 and {h.ref()} (minReplicas {low}) scales it: a target at 0 replicas "
                    "deactivates the HPA until someone scales it by hand. Remove spec.replicas.",
                    severity=Severity.HIGH,
                )
            else:
                yield r.finding(
                    d,
                    ("spec", "replicas"),
                    f"{d.ref()} sets replicas: {count} and {h.ref()} scales it: every apply or GitOps sync of this "
                    f"manifest resets the count to {count} and fights the HPA. Remove spec.replicas.",
                )


#: The one audit profile that logs nothing, from openshift/api config/v1 types_apiserver.go (retrieved
#: 2026-11-06). The other three -- Default, WriteRequestBodies, AllRequestBodies -- differ in how much of each
#: request they record, not in whether they record it.
AUDIT_PROFILE_NONE = "None"

#: The API group the cluster audit configuration lives in. An `APIServer` kind in any other group is a
#: different resource that happens to share a name.
APISERVER_GROUP = "config.openshift.io"


@rule(
    "KN-S035",
    "Cluster audit logging is turned off, for everyone or for one group",
    Stage.AUDIT,
    "security",
    Severity.HIGH,
    "Set spec.audit.profile to Default or higher on the APIServer named 'cluster', and remove any customRules "
    "entry whose profile is None. If a group genuinely must be excluded, record why: an assessor will ask.",
    "An OpenShift cluster can be configured to log no API requests at all, or -- less visibly -- to log none of "
    "the requests made by one group, through a customRules entry that overrides a healthy-looking top-level "
    "profile.",
)
def _s035(ctx: AuditContext, r: Rule) -> Iterator[Finding]:
    """Audit configuration, read as settings rather than inferred from the absence of a log.

    This is the only check in the logging family that a read-only client can actually decide. `spec.audit` on the
    cluster-scoped `APIServer` singleton is configuration, not audit content: no event, no request body, nothing
    about a person. Everything else a reader might want here -- whether events reach a SIEM, whether anyone reads
    them, whether retention holds -- needs a system kube-noob has no credentials for, and forty rules that answer
    "not evaluated" would be coverage theatre rather than coverage.

    The second finding is the one worth having. `customRules` is evaluated top to bottom and the first match
    takes precedence over `spec.audit.profile`, so a cluster reporting `profile: Default` can log nothing at all
    for a named group. A reader who checks only the top-level profile sees a configured cluster; this is that
    same shape again, in someone else's API (G202, G216).

    On a bundle that does not carry the object this declines rather than passing: on OpenShift the singleton
    always exists, so its absence means it was not collected, not that auditing is on.
    """
    if not ctx.is_openshift:
        return  # the resource does not exist off OpenShift; see N15 on telling that apart from a pass
    # Exact group, not a prefix. `apiVersion` is a Kubernetes group/version, and comparing the group
    # itself says what is meant -- any served version of config.openshift.io, and nothing whose group
    # merely begins with those characters. CodeQL reads a dotted literal in `startswith` as URL
    # validation and flags it; it was not exploitable here (the trailing slash makes it a true prefix),
    # but a split on the separator is what the data model actually is.
    docs = [d for d in ctx.by_kind("APIServer") if d.api_version.split("/", 1)[0] == APISERVER_GROUP]
    if not docs:
        ctx.cannot_decide(r.rule_id)
        return
    for d in docs:
        spec = d.data.get("spec") if isinstance(d.data, dict) else None
        audit = spec.get("audit") if isinstance(spec, dict) else None
        if not isinstance(audit, dict):
            continue  # the default is Default; an absent audit block is not an absent profile
        if str(audit.get("profile", "")) == AUDIT_PROFILE_NONE:
            yield r.finding(
                d,
                ("spec", "audit", "profile"),
                "spec.audit.profile is None, so the API server records no requests at all: there is no audit "
                "evidence for anything that happens on this cluster, and nothing to forward to a SIEM.",
            )
        rules = audit.get("customRules")
        if not isinstance(rules, list):
            continue
        for i, entry in enumerate(rules):
            if not isinstance(entry, dict) or str(entry.get("profile", "")) != AUDIT_PROFILE_NONE:
                continue
            group = str(entry.get("group") or "(unnamed group)")
            yield r.finding(
                d,
                ("spec", "audit", "customRules", i, "profile"),
                f"spec.audit.customRules[{i}] logs nothing for group {group!r}. customRules are evaluated in "
                f"order and the first match overrides spec.audit.profile "
                f"({str(audit.get('profile') or 'Default')!r}), so this cluster looks audited and is not, for "
                f"everyone in that group.",
            )


def run_rules(ctx: AuditContext, stages: set[Stage] | None = None, evaluated: list[str] | None = None) -> list[Finding]:
    """Every rule in ``stages``, appending the ids that actually ran to ``evaluated`` when given.

    The caller needs that list because a rule producing no findings and a rule that never ran look
    identical in the output otherwise, and a compliance record built on that cannot tell a control
    that was checked and is clean from one nothing looked at.

    The id is appended AFTER the check runs, and only when the rule did not call ``cannot_decide``: a rule
    the partial-bundle guard skipped produces no findings, and recording it as evaluated made the control
    summary report it as checked-and-clean (G202).
    """
    findings: list[Finding] = []
    for r in RULES.values():
        if stages is not None and r.stage not in stages:
            continue
        if r.check is not None:
            findings.extend(r.check(ctx, r))
            if evaluated is not None and r.rule_id not in ctx.undecided:
                evaluated.append(r.rule_id)
    return findings
