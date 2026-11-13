"""Entry points: validate / audit / red-team a manifest bundle."""

from __future__ import annotations

from kube_noob.audit import detection
from kube_noob.audit.model import Report, Severity, Stage
from kube_noob.audit.podspec import (
    EMBEDDED_POD_SPEC_GROUPS,
    operator_supplied_images,
    refused_group,
    unread_pod_specs,
)
from kube_noob.audit.redteam import red_team
from kube_noob.audit.rules import RULES, AuditContext, run_rules
from kube_noob.catalog import OPENSHIFT_FAMILY, PLATFORMS, k8s_version_for
from kube_noob.errors import ConfigError
from kube_noob.schemas.validate import validate_documents
from kube_noob.yamlio import Document, load_documents

ALL_STAGES = frozenset(Stage)


def build_context(
    docs: list[Document],
    platform: str,
    version: str | None,
    partial_bundle: bool = False,
    cni: str | None = None,
    allowed_registries: tuple[str, ...] = (),
) -> AuditContext:
    if platform not in PLATFORMS:
        raise ValueError(f"Unknown platform {platform!r}; use one of {', '.join(PLATFORMS)}")
    k8s = k8s_version_for(platform, version)
    platform_version = version if platform in OPENSHIFT_FAMILY else None
    return AuditContext(
        docs=docs,
        platform=platform,
        k8s_version=k8s,
        platform_version=platform_version,
        partial_bundle=partial_bundle,
        cni=cni,
        # Blank entries dropped here, not at every reader: a list of whitespace is not a configured policy,
        # and left in it made KN-S036 report every image against an allowlist of "  " (G245). The settings
        # validator already refuses them; a programmatic caller gets the same treatment.
        allowed_registries=tuple(e.strip() for e in allowed_registries if e.strip()),
    )


def analyze(
    manifests: str | list[Document],
    platform: str = "kubernetes",
    version: str | None = None,
    stages: frozenset[Stage] | set[Stage] = ALL_STAGES,
    min_severity: Severity = Severity.INFO,
    schema: bool = True,
    partial_bundle: bool = False,
    cni: str | None = None,
    allowed_registries: tuple[str, ...] = (),
) -> Report:
    docs = load_documents(manifests) if isinstance(manifests, str) else manifests
    ctx = build_context(docs, platform, version, partial_bundle, cni, allowed_registries)
    report = Report(
        platform=platform,
        kubernetes_version=ctx.k8s_version,
        platform_version=ctx.platform_version,
        resources=[d.ref() for d in docs],
    )
    if platform in OPENSHIFT_FAMILY and version is None:
        report.assumptions.append(f"No OpenShift version given; assumed Kubernetes {ctx.k8s_version} semantics.")
    if platform == "kubernetes" and version is None:
        report.assumptions.append(f"No Kubernetes version given; assumed {ctx.k8s_version}.")
    if partial_bundle:
        report.assumptions.append(
            "Audited part of a namespace, so rules that fire because another object is absent "
            "(no NetworkPolicy selects this workload, no PodDisruptionBudget, an undeclared StorageClass) "
            "were not evaluated: from these documents alone they cannot tell a real gap from an object you "
            "did not pass. Pass the whole namespace to evaluate them: a directory on the command line, or "
            "partial_bundle=false with every object of the namespace in one call."
        )
    unread: list[str] = []
    for d in docs:
        for path in unread_pod_specs(d):
            unread.append(f"{d.ref()} at spec path {'.'.join(str(x) for x in path) or '(root)'}")
    if unread:
        # A pod spec in a kind with no reader used to produce nothing at all -- no finding, no declined rule, no
        # word -- so a privileged container sat inside a document that reported clean. The shape is detectable
        # even where the path is not known, and saying so is the whole of the difference (G232).
        report.assumptions.append(
            f"{len(unread)} pod spec(s) are in kinds kube-noob has no reader for, so their containers were NOT "
            f"audited: {', '.join(unread[:5])}"
            f"{f' and {len(unread) - 5} more' if len(unread) > 5 else ''}. Audit the Deployments the operator "
            "creates from them, or ask for the kind to be added with its published schema."
        )
    supplied: list[str] = []
    for d in docs:
        for path in operator_supplied_images(d):
            supplied.append(f"{d.ref()} at {'.'.join(str(x) for x in path)}")
    if supplied:
        # Said, not assumed silently: the container is audited for everything else, and its image -- the one
        # thing a registry allowlist, a digest pin and a scanner all work from -- is in a ServingRuntime this
        # bundle does not carry (G252).
        report.assumptions.append(
            f"{len(supplied)} container(s) take their image from an operator rather than from this manifest, "
            f"so no image rule was evaluated for them: {', '.join(supplied[:5])}"
            f"{f' and {len(supplied) - 5} more' if len(supplied) > 5 else ''}. The ServingRuntime or operator "
            "that supplies the image decides what actually runs."
        )
    for d in docs:
        group = refused_group(d)
        if group is not None:
            # The object names a kind this reader knows pod specs for, in a group it does not. Not reading it is
            # right -- another project's CRD of the same name has another schema -- but saying nothing about it
            # leaves a privileged container in a document that reported clean (G231).
            report.assumptions.append(
                f"{d.ref()} declares API group {group}, which is not where kube-noob knows this kind's pod specs "
                f"to be ({', '.join(sorted(EMBEDDED_POD_SPEC_GROUPS[d.kind]))}); the pods it may carry were not "
                "audited."
            )
    if not docs:
        report.assumptions.append("Input contained no YAML documents.")
        return report
    rule_stages: set[Stage] = {s for s in stages if s is not Stage.RED_TEAM}
    evaluated: list[str] = []
    findings = run_rules(ctx, rule_stages, evaluated) if rule_stages else []
    report.evaluated_rules = evaluated
    # A projection of what was already read, not a rule: the audit configuration says which categories of API
    # activity this cluster can record, where `KN-S035` reports only the two settings that record nothing (R4).
    # Gated exactly as that rule is gated. Off OpenShift the resource does not exist, and a report that
    # ignores the object (the rule returns early) while drawing an AU-2 conclusion from it says two things at
    # once; `kube-noob validate` is a schema command and has no business carrying a coverage statement (G249).
    if platform in OPENSHIFT_FAMILY and Stage.AUDIT in stages:
        report.detection_coverage = detection.coverage(docs, version, platform)
    if schema and Stage.VALIDATE in stages:
        schema_findings, notes = validate_documents(docs)
        findings.extend(schema_findings)
        report.assumptions.extend(notes)
    if Stage.RED_TEAM in stages:
        # Red team always reasons over the complete finding set, even if the caller filters the output.
        all_findings = findings if rule_stages >= {Stage.AUDIT, Stage.CALIBRATE} else run_rules(ctx, None)
        report.scenarios = red_team(ctx, all_findings)
    # Recorded BEFORE the filter: a rule that fired must not look clean because this view hides its finding.
    report.fired_rules = sorted({f.rule_id for f in findings})
    report.findings = [f for f in findings if f.severity >= min_severity]
    return report


def explain_rule(rule_id: str) -> dict[str, object]:
    r = RULES.get(rule_id.upper())
    if r is None:
        build_checks: list[str] = []
        try:
            from kube_noob.build import containerfile
        except ImportError:  # the Claude plugin build ships without the Containerfile checks
            pass
        else:
            built = containerfile.explain(rule_id)
            if built is not None:
                return built
            build_checks = sorted(containerfile.CHECKS)
        known = ", ".join([*sorted(RULES), *build_checks])
        raise KeyError(f"Unknown rule {rule_id!r}. Known rules: {known}")
    from kube_noob.audit.controls import CATALOG, describe
    from kube_noob.catalog import SOURCES

    out = r.as_dict()
    out["citations"] = [SOURCES[c].as_dict() for c in r.citations if c in SOURCES]
    out["controls"] = describe(r.rule_id)
    out["controlCatalog"] = CATALOG
    return out


def list_rules() -> list[dict[str, object]]:
    return [r.as_dict() for r in sorted(RULES.values(), key=lambda x: x.rule_id)]


# The scaffold keys `helm create` writes and every chart keeps. Two of them, with no Kubernetes object anywhere in
# the file, is a confident read: this is a values file, not a manifest.
_VALUES_KEYS = frozenset(
    {
        "replicaCount",
        "image",
        "imagePullSecrets",
        "nameOverride",
        "fullnameOverride",
        "serviceAccount",
        "podAnnotations",
        "podSecurityContext",
        "securityContext",
        "resources",
        "nodeSelector",
        "tolerations",
        "affinity",
        "autoscaling",
        "ingress",
    }
)


def refuse_if_not_manifests(manifests: str | list[Document]) -> None:
    """Raise when nothing in the input is a Kubernetes object.

    The audit reads Kubernetes objects. Given something else it used to read the whole file as one unnamed object,
    report that it was missing `apiVersion`, and return a score -- 90 out of 100 for a Helm values file whose
    images were `:latest` and whose `securityContext` and `resources` were empty. A score says the rules were
    applied, so a score on a file the rules never saw is a wrong answer, not a thin one. One Kubernetes document is
    enough to proceed: a values block pasted above a manifest must not refuse the manifest.
    """
    docs = manifests if isinstance(manifests, list) else load_documents(manifests)
    objects = [d.data for d in docs if isinstance(d.data, dict)]
    if any("apiVersion" in o and "kind" in o for o in objects):
        return
    keys: set[str] = set()
    for o in objects:
        keys |= {k for k in o if isinstance(k, str)}
    looks_like_values = len(keys & _VALUES_KEYS) >= 2
    what = "a Helm values file" if looks_like_values else "not a Kubernetes manifest"
    how = (
        "Render the chart first and audit the output: helm template <release> <chart> -f <this file> | "
        "kube-noob audit -f -"
        if looks_like_values
        else "Pass Kubernetes objects: every document needs apiVersion and kind."
    )
    raise ConfigError(
        f"nothing here is a Kubernetes manifest ({'this looks like ' + what if looks_like_values else what}): "
        f"no document has both apiVersion and kind, so none of the audit rules apply. {how}"
    )
