"""Entry points: validate / audit / red-team a manifest bundle."""

from __future__ import annotations

from typing import Any

from kube_noob import sanitize
from kube_noob.audit import detection
from kube_noob.audit.controls import NO_REASON_RECORDED
from kube_noob.audit.model import Report, Severity, Stage
from kube_noob.audit.podspec import has_reader, operator_supplied_images, unread_pod_specs
from kube_noob.audit.redteam import red_team
from kube_noob.audit.rules import RULES, SUBJECT_GROUPS, AuditContext, refusal, run_rules
from kube_noob.catalog import (
    KIND_API_VERSIONS,
    LEGACY_OPENSHIFT_V1,
    OPENSHIFT_FAMILY,
    PLATFORMS,
    api_group,
    k8s_version_for,
)
from kube_noob.errors import ConfigError
from kube_noob.schemas.validate import validate_documents
from kube_noob.yamlio import Document, is_empty_list, load_documents

ALL_STAGES = frozenset(Stage)
#: How many reasons one declined rule lists before it says how many more there were.
MAX_DECLINE_REASONS = 3
#: How many further declined objects that line names before it gives a count instead.
MAX_DECLINE_NAMES = 20
#: How many (object, reason) entries one rule keeps in the report's `declined` map.
MAX_DECLINED_ENTRIES = 50
#: How the two assumptions about the version begin. They are the only caveats that are how the audit READ the
#: input rather than what it did not read, and the gate's Markdown lists exactly these under "Assumptions" (G272).
ASSUMED_VERSION_PREFIXES = ("No Kubernetes version given", "No OpenShift version given")


def _label(d: Document) -> str:
    """How a caveat names a document: its reference, or its position when it is not a mapping (a sequence of
    Pods given as one item of a list), which has no kind or name to be called by (G272)."""
    return d.ref() if isinstance(d.data, dict) else f"document {d.index + 1} (line {d.start_line})"


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
        version_stated=version is not None,
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
        # A display list, cleaned to one line: a bidi override in a name reached every JSON that carried it
        # (G281). An empty list wrapper is the record that a kind held nothing, not a resource (G272, seventh
        # review) -- both hold, so both are applied here.
        resources=[sanitize.one_line(d.ref())[:120] for d in docs if not is_empty_list(d.data)],
    )
    if platform in OPENSHIFT_FAMILY and version is None:
        report.assumptions.append(f"{ASSUMED_VERSION_PREFIXES[1]}; assumed Kubernetes {ctx.k8s_version} semantics.")
    if platform == "kubernetes" and version is None:
        report.assumptions.append(f"{ASSUMED_VERSION_PREFIXES[0]}; assumed {ctx.k8s_version}.")
    if partial_bundle:
        report.assumptions.append(
            "Audited part of a namespace, so rules that fire because another object is absent "
            "(no NetworkPolicy selects this workload, no PodDisruptionBudget, an undeclared StorageClass) "
            "were not evaluated: from these documents alone they cannot tell a real gap from an object you "
            "did not pass. Pass the whole namespace to evaluate them: a directory on the command line, or "
            "partial_bundle=false with every object of the namespace in one call."
        )
    unread: list[str] = []
    misplaced: list[str] = []
    for d in docs:
        for path in unread_pod_specs(d):
            # Two lists for two facts. A kind WITH a reader is never put in the sentence that says the kind has
            # none: that sentence ends "ask for the kind to be added", and the kind is already supported (G360).
            if has_reader(d):
                # The path is made of the document's own KEYS, which are input: cleaned to one line and bounded
                # here, so a newline or a bidi override in a key reaches no view of this line, the JSON one
                # included (class 7; a name did exactly that in G281).
                where = sanitize.one_line(".".join(str(x) for x in path))[:160] or "(root)"
                misplaced.append(f"{sanitize.one_line(_label(d))[:120]} at {where}")
                continue
            unread.append(f"{_label(d)} at spec path {'.'.join(str(x) for x in path) or '(root)'}")
            # No `notAudited` row here: `ctx.not_audited()` below already yields THIS document with the
            # unread-pod-spec reason, and a row from each would list one fact twice, in two shapes, with only one
            # of them carrying the `apiGroup` and `line` the exceptions gate and the SARIF read (class 9).
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
    if misplaced:
        # A container in a kind kube-noob DOES read, at a place its reader does not look: `template.Spec` for
        # `template.spec`, `explainer.alibi`, a pod spec at a path the registry does not list. Until G360 the
        # detector returned nothing for such a kind by its NAME, so a privileged container there printed a score
        # and gated `passed`. The sentence states the mitigating fact as well as the gap, because the gap is easy
        # to overstate: where the field is not in the kind's schema the container never runs, and what was wrong
        # was the number, not the cluster.
        report.assumptions.append(
            f"{len(misplaced)} field(s) hold a container where kube-noob does not read one in that kind, so those "
            f"containers were NOT audited: {', '.join(misplaced[:5])}"
            f"{f' and {len(misplaced) - 5} more' if len(misplaced) > 5 else ''}. The rest of each object was "
            "audited and its findings stand. If the field is not one the kind's schema defines (a misspelt or "
            "misplaced key), a current API server prunes or rejects it and the container does not run as written; "
            "kube-noob cannot tell that from the manifest, and states no score over a container no rule read. Move "
            "the container to where the kind carries it, or remove the field."
        )
    supplied: list[str] = []
    for d in docs:
        for path in operator_supplied_images(d):
            supplied.append(f"{d.ref()} at {'.'.join(str(x) for x in path)}")
            # G272's own case, and the one `ctx.not_audited()` does not reach: the object IS read, and the image
            # of one of its containers is not in this bundle at all, so no image rule was evaluated for it. It
            # goes through the one row builder so every row carries the same keys, and once per object rather
            # than once per container: the row is what an exception accepts, and an exception is about an object.
            # The per-container paths stay in the assumption line just below.
            row = _not_audited_row(d, "an operator supplies this container's image, which is not in this input")
            if row not in report.not_audited:
                report.not_audited.append(row)
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
    # G276's two summary lines, kept beside the per-object rows above. The rows say which object and make the
    # verdict undetermined; these say how many and in what way, which is what a reader of the summary alone had.
    # Both are the same fact, so neither may contradict the other: they are built from `docs`, not from a second
    # idea of what "not an object" means.
    # `shape_why`, not `why`: the loop above binds `why` as a `str`, and a walrus in a comprehension binds in
    # the enclosing scope, so reusing the name made it `str | None` there. mypy caught it on the merge.
    unaudited = [
        f"document {d.index + 1} ({shape_why})" for d in docs if (shape_why := _not_an_object(d.data)) is not None
    ]
    if unaudited:
        # `kind: [Pod]`, `kind: pod`, a document with no kind or one that is a bare number all used to count as an
        # audited resource with nothing found: no rule recognised the kind, so none fired (G276).
        report.assumptions.append(
            f"{len(unaudited)} document(s) are not Kubernetes objects any rule can read, so they are NOT audited: "
            f"{', '.join(unaudited[:10])}{f' and {len(unaudited) - 10} more' if len(unaudited) > 10 else ''}."
        )
    odd_api = [
        f"document {d.index + 1}"
        for d in docs
        if isinstance(d.data, dict)
        and isinstance(d.data.get("kind"), str)
        and _not_an_object(d.data) is None
        and not isinstance(d.data.get("apiVersion"), str | None)
    ]
    if odd_api:
        # G281 names these per object above and withholds the verdict; this line keeps G276's count beside it.
        report.assumptions.append(
            f"{len(odd_api)} document(s) have an apiVersion that is not a string: {', '.join(odd_api[:10])}. They "
            "were read by their kind, and kubectl and oc would refuse to apply them."
        )
    if not docs:
        report.assumptions.append("Input contained no YAML documents.")
        return report
    rule_stages: set[Stage] = {s for s in stages if s is not Stage.RED_TEAM}
    evaluated: list[str] = []
    findings = run_rules(ctx, rule_stages, evaluated) if rule_stages else []
    report.evaluated_rules = evaluated
    fired = {f.rule_id for f in findings}
    # A rule that declined and said why gets one line, sorted by id so the same input gives the same bytes. The
    # line gives the first few reasons in full and then NAMES every further object, up to a cap, with a count of
    # the ones it could not name: capping reasons alone left the fourth and fifth declined objects named nowhere
    # in any format (G272). The JSON carries the bounded map in `declined`.
    for rid in sorted(ctx.declined):
        entries = ctx.declined[rid]
        # `shown_entries`, not `shown`: the G281 not-audited loop above binds `shown` as the displayed
        # apiVersion in this same scope, and one name for a string and a list of (object, reason) pairs is how a
        # merge turns two correct blocks into one wrong one. mypy caught it on the merge.
        shown_entries = entries[:MAX_DECLINE_REASONS]
        named = {res for res, _ in shown_entries if res}
        rest = list(dict.fromkeys(res for res, _ in entries[MAX_DECLINE_REASONS:] if res and res not in named))
        unnamed = sum(1 for res, _ in entries[MAX_DECLINE_REASONS:] if not res)
        tail = f"; also not evaluated: {', '.join(rest[:MAX_DECLINE_NAMES])}" if rest else ""
        withheld = max(0, len(rest) - MAX_DECLINE_NAMES) + unnamed
        if withheld:
            tail += f"; and {withheld} more not named"
        # How many objects it DID read in full: a partial verdict says "clean or found on N, declined on M"
        # rather than letting the N decide the rule's word (G272).
        decided = len(ctx.examined.get(rid, set()) - {res for res, _ in entries})
        if decided:
            tail += f"; {decided} other object{'s' if decided != 1 else ''} read in full"
        report.assumptions.append(
            f"{rid} was not evaluated in full, so it is not counted as clean: "
            f"{'; '.join(reason for _, reason in shown_entries)}{tail}."
        )
        report.declined[rid] = {
            "entries": [{"resource": res, "reason": reason} for res, reason in entries[:MAX_DECLINED_ENTRIES]],
            "withheld": max(0, len(entries) - MAX_DECLINED_ENTRIES),
            "decided": decided,
        }
    if ctx.unreadable_shapes:
        # A field of the wrong type (`resources: 1`) used to crash the whole audit, exit 1 (G276). Now each rule that
        # cannot read it is named here and left out of the evaluated list; the schema check reports the field.
        # `shapes_named`, not `named`: the G272 loop above holds a set of that name in the same scope, and one
        # name for a set of objects and a joined string is how a merge turns two correct blocks into one wrong one.
        shapes_named = ", ".join(f"{rid} ({kind})" for rid, kind in sorted(ctx.unreadable_shapes.items()))
        report.assumptions.append(
            f"{len(ctx.unreadable_shapes)} rule(s) were not evaluated because a field in the input has the wrong type "
            f"for what the rule reads: {shapes_named}. Fix the field (the schema findings name it) and audit again."
        )
    # Every rule that did not run is here with its reason, so the record never has a rule that is neither checked
    # nor accounted for: the stage the caller left out, the guard that declined, the kind that was not in the
    # input (G281), or a field whose type the rule cannot read (G276). Rules G272 and G276 could not run were
    # named in an assumption line and NOWHERE in this record, so `controlSummary`, the KSI page, the OSCAL
    # document and the gate each had a rule they did not account for -- the gap this record exists to close.
    # ONE builder, not a `setdefault` into a dict two earlier loops had already filled: the weakest reason goes
    # first and the most specific last, because a later key wins.
    # The rule's own words for a decline come from `ctx.declined`, the one store of them, rather than from a
    # "declined on N objects" count beside it: `Report.declined` already carries the per-object detail, and
    # `coverage_line` groups records by this text, which a count fragments by N.
    # `declined_rows`, not `entries`: the G272 loop above binds a name of its own in this same scope, and one
    # name for two things is how a merge turns two correct blocks into one wrong one (mypy caught it).
    declined_reasons = {rid: declined_rows[0][1] for rid, declined_rows in ctx.declined.items() if declined_rows}
    not_evaluated = {
        **{r.rule_id: f"stage {r.stage.value} was not requested" for r in RULES.values() if r.stage not in rule_stages},
        # A QUIET decline -- `cannot_decide(rid)` with no words, which is how a control-plane rule says "no API
        # server in this input at all" -- put the rule in no list at all: not `evaluated_rules`, not `declined`,
        # not `no_subject`. It was then in NEITHER bucket, which is the one state this record must never have.
        **dict.fromkeys(ctx.undecided, NO_REASON_RECORDED),
        **ctx.no_verdict_reasons,
        **{rid: f"could not read the input: {why}" for rid, why in ctx.unreadable_shapes.items()},
        **declined_reasons,
        **ctx.no_subject,
    }
    # A rule that reported on one object and declined on another RAN: it is partly evaluated, stays in
    # `evaluated_rules`, is named by `partlyEvaluatedRules`, and is never here as well (G272, D4). Sorted by id:
    # same input, same bytes.
    ran = set(evaluated) | fired
    report.not_evaluated = {rid: why for rid, why in sorted(not_evaluated.items()) if rid not in ran}
    report.absent_subjects = dict(sorted(ctx.absent_subjects.items()))
    # The RECORD of which rules were partly evaluated, which `controlSummary` and the KSI page read. No
    # assumption line of its own: a rule that declined with its own words already has G272's "was not evaluated
    # in full" line above, and one that stopped on a field it could not read already has G276's summary line, so
    # a third sentence repeated the same reason verbatim -- two caveats for one fact, and both of them long.
    report.partly_evaluated = dict(sorted(ctx.partly_declined.items()))
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
        # With the rows, so a scenario is not `mitigated` about an object this report lists as not audited (G363).
        report.scenarios = red_team(ctx, all_findings, report.not_audited)
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
    if any("apiVersion" in o and "kind" in o and not is_empty_list(o) for o in objects):
        return
    # Only lists that held nothing, in either spelling, at the top or inside a `kind: List` (the seventh review
    # found a List of empty PodLists scoring 100): nothing to audit, said in those words (G272). An empty list
    # with a key twice is for KN-V018 to refuse, which is the answer, so it is not refused here.
    if objects and all(is_empty_list(o) for o in objects) and not any(d.duplicate_keys or d.refused_keys for d in docs):
        kinds = sorted({str(o.get("kind")) for o in objects})
        raise ConfigError(
            f"nothing here is a Kubernetes object: the input is {len(objects)} list{'s' if len(objects) != 1 else ''} "
            f"({', '.join(kinds)}) that held no items, so there is nothing to audit. Pass the objects themselves, "
            "or a list with items."
        )
    if any(d.from_list for d in docs) or any(d.duplicate_keys or d.refused_keys for d in docs):
        # The list wrapper had apiVersion and kind; what it held is for the audit to report (KN-V001 on an item
        # that is not an object, the pods inside a sequence item named as not audited). Refusing it here said
        # "no document has both apiVersion and kind" about a file whose wrapper and Pods all did (G272).
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


_KINDS_BY_FOLDED = {k.lower(): k for k in KIND_API_VERSIONS}


def _not_an_object(data: object) -> str | None:
    """Why no rule can read this document as a Kubernetes object, or None when one can (G276). A kind kube-noob does
    not know (a CRD's) is an object: no rule is written for it, and that is not news. A kind that is a known one
    spelt in another case or with spaces is not: the API server would refuse it, and every rule passed it by."""
    if not isinstance(data, dict):
        return "not a mapping"
    kind = data.get("kind")
    if kind is None or kind == "":
        return "no kind"
    if not isinstance(kind, str):
        return f"kind is {type(kind).__name__}, not a string"
    if kind not in KIND_API_VERSIONS and kind.strip().lower() in _KINDS_BY_FOLDED:
        return f"kind {kind!r} is not {_KINDS_BY_FOLDED[kind.strip().lower()]!r}: kinds are exact"
    return None
