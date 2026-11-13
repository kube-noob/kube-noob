"""Entry points: validate / audit / red-team a manifest bundle."""

from __future__ import annotations

from typing import Any

from kube_noob import sanitize
from kube_noob.audit import detection
from kube_noob.audit.model import Report, Severity, Stage
from kube_noob.audit.podspec import operator_supplied_images, unread_pod_specs
from kube_noob.audit.redteam import red_team
from kube_noob.audit.rules import RULES, SUBJECT_GROUPS, AuditContext, refusal, run_rules
from kube_noob.catalog import LEGACY_OPENSHIFT_V1, OPENSHIFT_FAMILY, PLATFORMS, api_group, k8s_version_for
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


def _group_label(kind: str, group: str) -> str:
    """A group as the note names it: `apps`, `the legacy ungrouped API (v1)` for an OpenShift 3.x kind, else `core`.
    Kubernetes' core never served a Route; the "" OpenShift's own kinds carry comes from `LEGACY_OPENSHIFT_V1` (R9)."""
    if group:
        return group
    return "the legacy ungrouped API (v1)" if kind in LEGACY_OPENSHIFT_V1 else "core"


def _not_audited_row(d: Document, why: str) -> dict[str, Any]:
    """One `notAudited` row. `object` is `Kind/namespace/name` cleaned to one line and bounded, built HERE and
    nowhere else; `kind` and `apiGroup` are cleaned the same way (the kind is the input's own text when the rules
    do not know it); `line` is the document's first line in the input, for the SARIF location."""
    return {
        "object": sanitize.one_line(d.ref())[:120],
        "kind": sanitize.one_line(d.kind)[:63],
        "apiGroup": sanitize.one_line(api_group(d.api_version))[:253],
        "why": why,
        "line": d.start_line,
    }


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
        # A display list, cleaned to one line: a bidi override in a name reached every JSON that carried it.
        resources=[sanitize.one_line(d.ref())[:120] for d in docs],
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
    for d, why in ctx.not_audited():
        # An object the rules did not read: a kind they know under an apiVersion they refuse (not a string, not
        # shaped like an API, or a group the kind is not known under), a `kind` that is not a kind name, or a pod
        # spec in a kind with no reader. Not reading it is right -- another project's CRD of the same name has
        # another schema -- and saying nothing was the absence-read-as-pass this work is about: a privileged
        # container sat in a document that reported clean while KN-V011 concluded from its absence (G231, review
        # 3). So it is named here, listed under `notAudited` from the ONE helper the subject reasons read, and the
        # verdict is undetermined (reviews 4 and 5). The object is cleaned ONCE, here, and every surface -- the
        # note, the gate's failure line, the SARIF -- reads this field: a newline in a name forged a second note
        # row and reached the SARIF raw (review 5, item 2). The declared apiVersion is shown once, quoted.
        report.not_audited.append(_not_audited_row(d, why))
        raw = d.data.get("apiVersion") if isinstance(d.data, dict) else None
        if refusal(d) is not None:
            shown = (
                f'"{sanitize.one_line(raw)[:80]}"'
                if isinstance(raw, str)
                else f"a non-string value ({type(raw).__name__})"
            )
            known = ", ".join(_group_label(d.kind, g) for g in sorted(SUBJECT_GROUPS[d.kind]))
            detail = f"declares apiVersion {shown}: {why} (kube-noob knows {d.kind} under {known})"
        else:
            detail = why
        report.assumptions.append(
            f"{report.not_audited[-1]['object']} {detail}; it was not audited, so this verdict is undetermined."
        )
    if not docs:
        report.assumptions.append("Input contained no YAML documents.")
        return report
    rule_stages: set[Stage] = {s for s in stages if s is not Stage.RED_TEAM}
    evaluated: list[str] = []
    findings = run_rules(ctx, rule_stages, evaluated) if rule_stages else []
    report.evaluated_rules = evaluated
    # Every rule that is not in `evaluated` is here with its reason, so the record never has a rule that is
    # neither checked nor accounted for: the stage the caller left out, the guard that declined, or the kind
    # that was not in the input (G281). Sorted by id: the same input gives the same bytes.
    not_evaluated = {
        **{r.rule_id: f"stage {r.stage.value} was not requested" for r in RULES.values() if r.stage not in rule_stages},
        **ctx.declined,
        **ctx.no_subject,
    }
    report.not_evaluated = dict(sorted(not_evaluated.items()))
    report.absent_subjects = dict(sorted(ctx.absent_subjects.items()))
    for rid, why in sorted(ctx.partly_declined.items()):
        report.assumptions.append(f"{rid} reported findings and declined to decide on part of this input: {why}.")
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
