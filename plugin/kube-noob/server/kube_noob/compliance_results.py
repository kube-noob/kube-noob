"""OpenShift Compliance Operator results (N1), read as evidence rather than repeated as a score.

The Compliance Operator's own output is the one place where "compliant" is easiest to get wrong. A suite can report
``result: COMPLIANT`` while a ``TailoredProfile`` removed the rules that would have failed, while a
``ComplianceCheckResult`` says ``NOT-APPLICABLE``, while a ``ComplianceScan`` never left ``RUNNING``, or while a rule
the profile claimed to run produced no result at all. Each of those is an absence, and this module refuses to read any
of them as a pass -- the same rule kube-noob applies to its own findings, turned on somebody else's.

So the answer here is not a restatement of check statuses. It is the set of rules the profile said would be
evaluated, each with one of three outcomes -- ``pass``, ``fail``, ``not-evaluated`` -- and, for every
``not-evaluated`` rule, the reason and the object that proves it. **A suite that is all green because checks were
tailored out comes out undetermined, never compliant.**

Two inputs feed one builder: manifest files (``from_manifests`` / ``from_sources``) and a must-gather
(``kube_noob.mustgather.compliance``, which the Claude plugin does not ship). There is deliberately **no live read**:
nothing here asks a cluster for anything, so no credential and no allowlist entry is involved, and an input with no
Compliance Operator objects is `undetermined`, never "the operator is not installed" -- a file set cannot prove that.

Every field, label and annotation below was read in the source that defines it. ComplianceAsCode/compliance-operator
at ``91efc035c5fc126fd061014c05567e9428aa4b53`` (branch ``master``):

- ``pkg/apis/compliance/v1alpha1/compliancecheckresult_types.go``: a ``ComplianceCheckResult`` carries ``id``,
  ``status``, ``severity``, ``description``, ``rationale``, ``instructions``, ``warnings`` and ``valuesUsed``
  **inline**, not under ``spec`` or ``status``. ``status`` is one of ``PASS``, ``FAIL``, ``INFO``, ``MANUAL``,
  ``ERROR``, ``NOT-APPLICABLE``, ``INCONSISTENT`` or the empty string (``CheckResultNoResult``, "didn't yield a
  usable result"). ``severity`` is ``unknown``, ``info``, ``low``, ``medium`` or ``high``. The rule it came from is
  the annotation ``compliance.openshift.io/rule`` (``ComplianceCheckResultRuleAnnotation``), its error text the
  annotation ``compliance.openshift.io/error-msg``, and an inconsistent check names its diverging sources in
  ``compliance.openshift.io/inconsistent-source`` with the majority in ``compliance.openshift.io/most-common-status``.
- ``pkg/apis/compliance/v1alpha1/compliancescan_types.go``: ``compliance.openshift.io/scan-name``
  (``ComplianceScanLabel``) ties an object to its scan. ``status.phase`` is ``PENDING``, ``LAUNCHING``, ``RUNNING``,
  ``AGGREGATING`` or ``DONE``; ``status.result`` is ``NOT-AVAILABLE``, ``COMPLIANT``, ``NOT-APPLICABLE``, ``ERROR``,
  ``NON-COMPLIANT`` or ``INCONSISTENT``; the error string is ``status.errormsg`` -- that spelling, lower case and no
  camel hump, and only on the scan.
- ``pkg/apis/compliance/v1alpha1/compliancesuite_types.go``: ``compliance.openshift.io/suite`` (``SuiteLabel``);
  ``status.phase``, ``status.result``, ``status.errorMessage`` (camel-cased here, unlike the scan's) and
  ``status.scanStatuses[]``, each an inlined scan status with a ``name``.
- ``pkg/apis/compliance/v1alpha1/rule_types.go``: a ``Rule`` carries ``id``, ``title``, ``description``,
  ``rationale``, ``severity``, ``instructions`` and ``checkType`` (``Platform``, ``Node`` or empty) inline.
- ``pkg/apis/compliance/v1alpha1/tailoredprofile_types.go``: ``spec.extends``, and ``spec.disableRules``,
  ``spec.enableRules`` and ``spec.manualRules``, each a list of ``{name, rationale, kind}``; ``status.state`` is
  ``PENDING``, ``READY`` or ``ERROR`` with ``status.errorMessage``.
- ``pkg/apis/compliance/v1alpha1/profile_types.go``: a ``Profile`` carries ``title``, ``description``, ``id``,
  ``rules`` and ``values`` inline. ``profilebundle_types.go``: ``status.dataStreamStatus`` is ``PENDING``, ``VALID``
  or ``INVALID`` with ``status.errorMessage``.
- ``pkg/profileparser/profileparser.go``: the control crosswalk is written as annotations
  ``control.compliance.openshift.io/<standard>`` (``controlAnnotationBase``) with the ids joined by **``;``**
  (``profileOperatorFormatter``). The standards registered are ``NIST-800-53``, ``BSI``, ``CIS-OCP``, ``CIS-RHEL``,
  ``NERC-CIP``, ``PCI-DSS``, ``PCI-DSS-4-0``, ``STIG``, ``SRG``, ``STIGID``, ``STIG-RULE`` and ``CCI``.

What reads as an answer, and what does not. ``undeterminedBecause`` is the ONE predicate (``_undetermined``): it is
computed once in ``_assemble`` and every renderer -- the text view, JSON, YAML, the MCP tool result and the CLI's
``--require-complete`` exit -- reads the field it wrote, as ``audit.model.Report.undetermined`` is read by the audit,
the gate and the eval grader. While it is non-empty, ``complete`` is false, ``passRate`` is null with
``passRateWithheld`` beside it, and the verdict can never be ``compliant``.

The NIST crosswalk joins the operator's ``NIST-800-53`` ids to kube-noob's own ``audit.controls.RULE_CONTROLS``, which
is imported rather than copied. A control is ``evidenced-by-compliance-operator`` only when a rule it names was
actually evaluated -- a rule tailored out, skipped or errored evidences nothing -- ``kube-noob-rule`` when kube-noob
has a rule mapped to it, ``both``, or ``neither``. There is no ``satisfied``: the operator's reference is to 800-53
**Rev 4** and kube-noob's catalogue is Rev 5, the ids are matched as written, and a mapping is evidence about a
control, never an assessment of it.

Safety: no network, no cluster, no credential, nothing written and no Secret read (Secret objects in the input are
counted and dropped). Only named fields are read. Every string shown is made printable by ``sanitize.visible`` and
redacted; a name that is not a valid name is flattened and marked, so a rule name carrying invisible Unicode can
neither pose as a rule nor silently join to one. The output is bounded and sorted, and evidence names an object and
its file rather than a document position, so the same objects in any order give the same bytes.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel

from kube_noob.debug.cluster import redact_text
from kube_noob.sanitize import visible

GROUP = "compliance.openshift.io"
RESOURCES = (
    "compliancecheckresults",
    "compliancescans",
    "compliancesuites",
    "rules",
    "tailoredprofiles",
    "profiles",
    "profilebundles",
)
KIND_TO_RESOURCE = {
    "ComplianceCheckResult": "compliancecheckresults",
    "ComplianceScan": "compliancescans",
    "ComplianceSuite": "compliancesuites",
    "Rule": "rules",
    "TailoredProfile": "tailoredprofiles",
    "Profile": "profiles",
    "ProfileBundle": "profilebundles",
}
RESOURCE_TO_KIND = {r: k for k, r in KIND_TO_RESOURCE.items()}
#: What an answer needs: the results themselves, and a profile or tailored profile to say which rules were expected.
#: Without the results nothing was read; without a profile the silent case -- a rule that produced no result at all --
#: cannot be seen, which is the one thing this reader exists to say.
NEEDED = ("compliancecheckresults",)
PROFILE_KINDS = ("profiles", "tailoredprofiles")

#: compliancecheckresult_types.go. The empty string is upstream's own CheckResultNoResult. The two statuses that
#: are an evaluation are written out where they are compared: naming one of them trips ruff's hardcoded-credential
#: check, and a per-line suppression in a compliance module reads worse than a literal (review class 10).
CHECK_STATUSES = frozenset({"PASS", "FAIL", "INFO", "MANUAL", "ERROR", "NOT-APPLICABLE", "INCONSISTENT"})
#: Statuses the operator writes that are NOT an evaluation: each keeps its own reason, never folded into a pass.
NOT_EVALUATED_STATUSES = {
    "INFO": "info",
    "MANUAL": "manual",
    "ERROR": "error",
    "NOT-APPLICABLE": "not-applicable",
    "INCONSISTENT": "inconsistent",
}
SCAN_PHASES = frozenset({"PENDING", "LAUNCHING", "RUNNING", "AGGREGATING", "DONE"})
DONE = "DONE"
SCAN_RESULTS = frozenset({"NOT-AVAILABLE", "COMPLIANT", "NOT-APPLICABLE", "ERROR", "NON-COMPLIANT", "INCONSISTENT"})
SEVERITIES = frozenset({"unknown", "info", "low", "medium", "high"})
CHECK_TYPES = frozenset({"Platform", "Node", ""})

RULE_ANNOTATION = f"{GROUP}/rule"
ERROR_ANNOTATION = f"{GROUP}/error-msg"
MOST_COMMON_ANNOTATION = f"{GROUP}/most-common-status"
INCONSISTENT_SOURCE_ANNOTATION = f"{GROUP}/inconsistent-source"
SCAN_LABEL = f"{GROUP}/scan-name"
SUITE_LABEL = f"{GROUP}/suite"
STATUS_LABEL = f"{GROUP}/check-status"
CONTROL_PREFIX = "control.compliance.openshift.io/"
NIST = "NIST-800-53"

MAX_RULES = 5_000
MAX_ITEMS = 50_000
MAX_NAMED = 20
MAX_UNREADABLE = 50
MAX_CONTROLS = 500
MAX_LIST = 50
TEXT_LIMIT = 300

NOT_COVERED = (
    "This reads the Compliance Operator's own objects and runs nothing: it cannot re-check a rule, cannot say whether "
    "a NOT-APPLICABLE check should have applied, and cannot see a rule no profile in the input names. Node checks "
    "come from the operator's scans, never from kube-noob."
)
#: Kinds kube-noob never reads, wherever they appear: counted and dropped.
_NEVER_READ = frozenset({"Secret", "SecretList"})

_NAME = re.compile(r"^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?\Z")
_CONTROL = re.compile(r"^[A-Z]{2}-[0-9]{1,3}(?:\([0-9]{1,3}\))?\Z")
_XCCDF_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,252}\Z")

Outcome = Literal["pass", "fail", "not-evaluated"]
Verdict = Literal["compliant", "non-compliant", "undetermined"]
ReadState = Literal["read", "partial", "not-read"]
Evidence = Literal["compliance-operator", "kube-noob-rule", "both", "neither"]
ControlStatus = Literal["failing", "passing", "partly-evaluated", "not-evaluated"]

#: Why a rule counts as not evaluated, and the one line each reason prints. Every renderer uses this table, so the
#: text view cannot carry fewer reasons than the JSON (review class 6).
REASONS: dict[str, str] = {
    "disabled-by-tailoring": "a TailoredProfile disabled this rule, so the suite never evaluated it",
    "manual-by-tailoring": "a TailoredProfile marked this rule manual, so no automated check evaluated it",
    "missing-from-results": "the profile lists this rule and no ComplianceCheckResult names it: nothing evaluated it",
    "not-applicable": "the check reported NOT-APPLICABLE: it did not run",
    "info": "the check reported INFO: it is not a pass or a fail",
    "manual": "the check reported MANUAL: an administrator has to evaluate it by hand",
    "error": "the check reported ERROR: it could not complete",
    "inconsistent": "the check reported INCONSISTENT: its nodes disagreed, so there is no one result",
    "no-result": "the check carries an empty status, which the operator writes for no usable result",
    "unrecognised-status": "the check carries a status the operator does not define, so it is not read as anything",
    "scan-not-done": "its ComplianceScan never reached DONE, so a pass from it is not a pass",
    "scan-errored": "its ComplianceScan reported an error, so a pass from it is not a pass",
    "scan-not-read": "the ComplianceScan that produced it was not read, so whether that scan completed is not known",
    "results-disagree": "two ComplianceCheckResults for this rule disagree, and neither is taken as the answer",
    "profile-not-read": "the profile this rule was expected from was not read, so what should have run is not known",
}


class _Out(BaseModel):
    model_config = ConfigDict(extra="forbid", alias_generator=to_camel, populate_by_name=True)


class SourceRead(_Out):
    """What one input could see of one resource."""

    resource: str
    state: ReadState
    objects: int = 0
    reason: str = ""


class CheckRow(_Out):
    """One ComplianceCheckResult, as read."""

    name: str
    status: str
    outcome: Outcome
    reason: str | None = None
    severity: str | None = None
    rule: str | None = None
    scan: str | None = None
    suite: str | None = None
    check_id: str | None = None
    detail: str | None = None
    notes: list[str] = []
    evidence: list[str] = []


class RuleRow(_Out):
    """One rule the profile said would be evaluated, and what became of it."""

    rule: str
    outcome: Outcome
    reason: str | None = None
    why: str | None = None
    detail: str | None = None
    severity: str | None = None
    check_type: str | None = None
    title: str | None = None
    expected_from: list[str] = []
    checks: list[str] = []
    scans: list[str] = []
    controls: list[str] = []
    frameworks: dict[str, list[str]] = {}
    notes: list[str] = []


class ControlRow(_Out):
    """One NIST control, and which side -- if either -- has evidence about it."""

    control: str
    title: str | None = None
    evidence: Evidence
    status: ControlStatus
    operator_passing: int = 0
    operator_failing: int = 0
    operator_not_evaluated: int = 0
    operator_rules: list[str] = []
    kube_noob_rules: list[str] = []
    note: str | None = None


class ScanRow(_Out):
    name: str
    phase: str | None = None
    result: str | None = None
    usable: bool
    why: str | None = None
    suite: str | None = None
    error: str | None = None


class SuiteRow(_Out):
    """A suite and whether its own ``status.result`` survives this reading of its evidence."""

    name: str
    phase: str | None = None
    claimed_result: str | None = None
    error: str | None = None
    agrees: bool
    why: str | None = None
    scans: list[str] = []


@dataclass
class Obj:
    doc: dict[str, Any]
    where: str
    namespace: str
    name: str
    notes: list[str] = field(default_factory=list)
    wheres: list[str] = field(default_factory=list)


@dataclass
class Collected:
    """The Compliance Operator objects one input held, and what it could and could not read."""

    source: Literal["manifests", "must-gather"]
    objects: dict[str, list[Obj]] = field(default_factory=lambda: {r: [] for r in RESOURCES})
    reads: dict[str, SourceRead] = field(default_factory=dict)
    caveats: list[str] = field(default_factory=list)
    unreadable: list[dict[str, str]] = field(default_factory=list)
    #: Files read whole whose YAML the API server refuses (a key twice): named, and the answer is undetermined.
    refused_files: list[dict[str, str]] = field(default_factory=list)
    dropped_unread: int = 0  # objects of a kind never read (Secrets)
    dropped: Counter[str] = field(default_factory=Counter)  # objects past MAX_ITEMS, per resource
    rejected: Counter[str] = field(default_factory=Counter)  # items where that kind was promised and not delivered
    foreign: Counter[str] = field(default_factory=Counter)  # named like a compliance kind, another API group

    def add(self, doc: Any, where: str, default_ns: str = "", expect: str = "") -> bool:
        """Keep one object; returns whether it was kept. ``expect`` is the kind the context promises (a typed list, a
        must-gather path): there, anything that is not a usable object of that kind is counted as rejected, which
        makes the answer undetermined. Without it, other kinds are simply not compliance objects."""
        expected = KIND_TO_RESOURCE.get(expect)
        if not isinstance(doc, dict):
            if expected:
                self.rejected[expected] += 1
            return False
        stated = doc.get("kind")
        kind = stated if isinstance(stated, str) and stated else expect
        if kind in _NEVER_READ:
            self.dropped_unread += 1
            return False
        resource = KIND_TO_RESOURCE.get(kind)
        if resource is None or (expected and resource != expected):
            if expected:
                self.rejected[expected] += 1
            return False
        api = doc.get("apiVersion")
        if api not in (None, "") and not (isinstance(api, str) and api.startswith(GROUP + "/")):
            self.foreign[f"{RESOURCE_TO_KIND[resource]} {_text(api, 80) or '<not a string>'}"] += 1
            if expected:
                self.rejected[expected] += 1
            return False
        meta = _d(doc.get("metadata"))
        name, ns = meta.get("name"), meta.get("namespace")
        if not isinstance(name, str) or not name:
            self.rejected[resource] += 1
            return False
        notes: list[str] = []
        if isinstance(ns, str) and ns:
            if default_ns and ns != default_ns:
                notes.append(
                    f"its metadata.namespace {_shown(ns)} differs from the namespace in its path "
                    f"{_shown(default_ns)}: it is attributed to {_shown(ns)}"
                )
        else:
            ns = default_ns
        if len(self.objects[resource]) < MAX_ITEMS:
            self.objects[resource].append(Obj(doc, where, ns, name, notes))
        else:
            self.dropped[resource] += 1
        return True

    def overflow(self, resource: str, n: int) -> None:
        """``n`` more objects of ``resource`` than were looked at: a list sliced at MAX_ITEMS."""
        if n > 0:
            self.dropped[resource] += n


# ------------------------------------------------------------------------------------------------- helpers ----


def _d(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _l(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _text(value: Any, limit: int = TEXT_LIMIT) -> str:
    """One safe line: non-printing characters removed, whitespace collapsed, credentials redacted, length capped."""
    if not isinstance(value, str):
        return ""
    s = " ".join(visible(value[: limit * 4]).split())
    s = redact_text(s)
    return s if len(s) <= limit else s[: limit - 3] + "..."


def _shown(value: str) -> str:
    """A name as it may be shown: a valid name as is, anything else flattened and marked with <> so it is not
    mistaken for a name -- and so a name carrying invisible Unicode cannot pose as the rule it resembles."""
    return value if _NAME.match(value) else f"<{_text(value, 120) or 'unnamed'}>"


def _valid(value: Any, rx: re.Pattern[str] = _NAME) -> str | None:
    return value if isinstance(value, str) and rx.match(value) else None


def _one_of(value: Any, choices: frozenset[str]) -> str | None:
    """The value when it is one of the strings upstream defines, else None. A YAML list or mapping where a string
    was expected is simply not one of them: ``value in choices`` would raise TypeError on an unhashable value, and
    an unexpected exception is exit 4 rather than an answer (review classes 4 and 16)."""
    return value if isinstance(value, str) and value in choices else None


def _annotations(doc: dict[str, Any]) -> dict[str, Any]:
    return _d(_d(doc.get("metadata")).get("annotations"))


def _labels(doc: dict[str, Any]) -> dict[str, Any]:
    return _d(_d(doc.get("metadata")).get("labels"))


def _fingerprint(doc: dict[str, Any]) -> str:
    return json.dumps(doc, sort_keys=True, default=str)


def _frameworks(doc: dict[str, Any], notes: list[str]) -> dict[str, list[str]]:
    """The control crosswalk a Rule CR carries: ``control.compliance.openshift.io/<standard>`` values split on ';'.
    An id that is not a control id is still shown -- flattened and marked -- because dropping it would read as a
    standard the rule does not cite."""
    out: dict[str, list[str]] = {}
    for key, raw in sorted(_annotations(doc).items()):
        if not (isinstance(key, str) and key.startswith(CONTROL_PREFIX)):
            continue
        standard = key[len(CONTROL_PREFIX) :]
        if not isinstance(raw, str):
            notes.append(f"the {_text(key, 80)} annotation is not a string, so its controls were not read")
            continue
        ids: list[str] = []
        for part in raw[:8192].split(";"):
            item = part.strip()
            if not item:
                continue
            ids.append(item if _CONTROL.match(item) or _XCCDF_ID.match(item) else f"<{_text(item, 60) or '?'}>")
        if ids:
            out[_text(standard, 60) or "?"] = sorted(dict.fromkeys(ids))[:MAX_LIST]
    return out


def _rule_references(spec: dict[str, Any], key: str, notes: list[str], what: str) -> dict[str, str]:
    """``spec.disableRules`` and friends: ``{name: rationale}``. A list element that is not a usable reference is
    noted rather than skipped, because a disable this cannot read is a rule whose fate is unknown."""
    out: dict[str, str] = {}
    raw = spec.get(key)
    if raw is None:
        return out
    if not isinstance(raw, list):
        notes.append(f"spec.{key} is not a list ({type(raw).__name__}), so the rules it {what} were not read")
        return out
    for item in raw[:MAX_RULES]:
        name = _valid(_d(item).get("name")) if isinstance(item, dict) else None
        if name is None:
            notes.append(f"an entry in spec.{key} names no usable rule, so a rule it {what} may not be in this answer")
            continue
        out[name] = _text(_d(item).get("rationale"), 200)
    if len(raw) > MAX_RULES:
        notes.append(f"spec.{key} holds {len(raw)} entries; only the first {MAX_RULES} were read")
    return out


# ------------------------------------------------------------------------------------------------- inputs ----


def _finish_file_set(c: Collected) -> Collected:
    for resource in RESOURCES:
        kept = len(c.objects[resource])
        gaps = c.rejected[resource] + c.dropped[resource]
        if kept or resource in c.reads:
            state: ReadState = "partial" if gaps else "read"
            reason = f"{gaps} object(s) of this kind were not usable or not read" if gaps else ""
            c.reads[resource] = SourceRead(resource=resource, state=state, objects=kept, reason=reason)
        elif c.rejected[resource]:
            c.reads[resource] = SourceRead(
                resource=resource,
                state="not-read",
                reason=f"{c.rejected[resource]} item(s) in the input were not usable "
                f"{RESOURCE_TO_KIND[resource]} objects",
            )
        else:
            c.reads[resource] = SourceRead(
                resource=resource,
                state="not-read",
                reason=f"no {RESOURCE_TO_KIND[resource]} in the input, so it was not read",
            )
    return c


def _add_document(c: Collected, doc: Any, label: str) -> None:
    if not isinstance(doc, dict):
        return
    kind = str(doc.get("kind") or "")
    items = doc.get("items")
    if kind.endswith("List") and kind not in _NEVER_READ:
        element = kind[: -len("List")]
        typed = element in KIND_TO_RESOURCE
        if not isinstance(items, list):
            # The wrapper's own defect, not its contents': a List whose items are a mapping or a scalar held
            # nothing this could read, and saying so is the difference between zero objects and none read.
            if typed:
                c.rejected[KIND_TO_RESOURCE[element]] += 1
            else:
                c.caveats.append(
                    f"a {_text(kind, 60)} in {_text(label, 120)} has no items list "
                    f"({type(items).__name__}), so whether it held compliance objects is not known"
                )
            return
        if typed:
            c.reads.setdefault(KIND_TO_RESOURCE[element], SourceRead(resource=KIND_TO_RESOURCE[element], state="read"))
        for item in items[:MAX_ITEMS]:
            c.add(item, label, expect=element if typed else "")
        if typed:
            c.overflow(KIND_TO_RESOURCE[element], len(items) - MAX_ITEMS)
        elif len(items) > MAX_ITEMS:
            c.caveats.append(f"a List in {_text(label, 120)} held {len(items)} items; only the first were read")
            c.overflow("compliancecheckresults", len(items) - MAX_ITEMS)
        return
    c.add(doc, label)


def from_sources(
    sources: Iterable[tuple[str, list[Any]]],
    unreadable: list[dict[str, str]] | None = None,
    refused: list[dict[str, str]] | None = None,
) -> Collected:
    """Collect Compliance Operator objects from parsed documents, grouped by the file they came from."""
    c = Collected("manifests")
    c.unreadable = [dict(u) for u in (unreadable or [])]
    c.refused_files = [dict(u) for u in (refused or [])]
    for label, docs in sources:
        for doc in docs:
            _add_document(c, doc, label)
    return _finish_file_set(c)


def from_documents(docs: Iterable[Any], label: str = "manifest") -> Collected:
    return from_sources([(label, list(docs))])


def from_manifests(text: str, label: str = "manifest") -> Collected:
    """Collect from YAML text (the ``yamlio`` caps on size, documents, depth and aliases apply). A file whose YAML
    gives a key twice is named through ``operators.duplicate_key_note`` -- one note for every reader, so there is no
    second opinion on what the API server refuses."""
    from kube_noob.operators import duplicate_key_note
    from kube_noob.yamlio import load_documents

    grouped: list[Any] = []
    marker = "__from_list__"
    docs = load_documents(text)
    refused = [{"path": label, "reason": note}] if (note := duplicate_key_note(docs)) is not None else []
    for d in docs:
        if d.from_list and d.from_list != "List":
            if grouped and isinstance(grouped[-1], dict) and grouped[-1].get(marker) == d.from_list:
                grouped[-1]["items"].append(d.data)
            else:
                grouped.append({"kind": d.from_list, "items": [d.data], marker: d.from_list})
        else:
            grouped.append(d.data)
    for g in grouped:
        if isinstance(g, dict):
            g.pop(marker, None)
    return from_sources([(label, grouped)], refused=refused)


# ------------------------------------------------------------------------------------------------- builder ----


def _dedupe(objs: list[Obj], conflicts: list[str]) -> list[Obj]:
    """One object per namespace and name. Identical duplicates merge; duplicates that differ keep the one that sorts
    first by content -- not by position, so input order never decides -- and are flagged."""
    by_key: dict[tuple[str, str], list[Obj]] = {}
    for o in objs:
        by_key.setdefault((o.namespace, o.name), []).append(o)
    out: list[Obj] = []
    for (ns, name), group in sorted(by_key.items()):
        wheres = sorted({w for o in group for w in [o.where, *o.wheres]})
        notes = sorted({n for o in group for n in o.notes})
        if len(group) == 1:
            keep = group[0]
        else:
            prints = sorted(((_fingerprint(o.doc), i) for i, o in enumerate(group)))
            keep = group[prints[0][1]]
            if len({p for p, _ in prints}) > 1:
                kind = str(keep.doc.get("kind") or "object")
                conflicts.append(f"{kind} {_shown(ns)}/{_shown(name)}")
                notes.append(
                    f"{len({p for p, _ in prints})} different objects of this name were in the input; neither is "
                    "taken as the answer"
                )
        out.append(Obj(keep.doc, keep.where, ns, name, notes, wheres))
    return out


def _scan_rows(scans: list[Obj]) -> dict[str, ScanRow]:
    """Every ComplianceScan read, and whether a result it produced can be taken as evaluated. Only ``DONE`` with no
    error counts: a scan still running, aggregating or errored has passes that were never finished."""
    rows: dict[str, ScanRow] = {}
    for o in scans:
        status = _d(o.doc.get("status"))
        phase_raw = status.get("phase")
        phase = _one_of(phase_raw, SCAN_PHASES)
        error = _text(status.get("errormsg"), 240)
        result_raw = status.get("result")
        usable, why = True, None
        if phase is None:
            usable, why = (
                False,
                (
                    "its status.phase is not in the input"
                    if phase_raw in (None, "")
                    else f"its status.phase {_text(str(phase_raw), 60)!r} is not one the operator defines"
                ),
            )
        elif phase != DONE:
            usable, why = False, f"it is in phase {phase}, not {DONE}"
        elif error:
            usable, why = False, f"it reported an error: {error}"
        rows[o.name] = ScanRow(
            name=_shown(o.name),
            phase=phase or (_text(str(phase_raw), 60) or None),
            result=_one_of(result_raw, SCAN_RESULTS) or (_text(str(result_raw), 60) or None),
            usable=usable,
            why=why,
            suite=_valid(_labels(o.doc).get(SUITE_LABEL)),
            error=error or None,
        )
    return rows


@dataclass
class _Expected:
    """Which rules the profiles said would be evaluated, and what tailoring did to each."""

    rules: dict[str, set[str]] = field(default_factory=dict)  # rule -> the profiles that expected it
    disabled: dict[str, tuple[str, str]] = field(default_factory=dict)  # rule -> (tailored profile, rationale)
    manual: dict[str, tuple[str, str]] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    unresolved_extends: list[str] = field(default_factory=list)  # tailored profiles whose base was not read
    no_profile: bool = True


def _profile_rules(o: Obj, notes: list[str]) -> list[str]:
    """A Profile's ``rules`` list. A scalar or a mapping there is not an empty profile: it is a rule list that was
    not read, and it says so (review class 4)."""
    raw = o.doc.get("rules")
    if raw is None:
        notes.append(f"Profile {_shown(o.name)} carries no rules list, so what it would evaluate is not known")
        return []
    if not isinstance(raw, list):
        notes.append(
            f"Profile {_shown(o.name)} has a rules field that is not a list ({type(raw).__name__}), so what it "
            "would evaluate is not known"
        )
        return []
    out: list[str] = []
    for item in raw[:MAX_RULES]:
        name = _valid(item)
        if name is None:
            notes.append(
                f"Profile {_shown(o.name)} lists a rule that is not a usable name, so it is not joined to a result"
            )
            continue
        out.append(name)
    if len(raw) > MAX_RULES:
        notes.append(f"Profile {_shown(o.name)} lists {len(raw)} rules; only the first {MAX_RULES} were read")
    return out


def _expected(profiles: list[Obj], tailored: list[Obj]) -> _Expected:
    e = _Expected()
    by_name = {o.name: o for o in profiles}
    e.no_profile = not profiles and not tailored
    for o in profiles:
        for rule in _profile_rules(o, e.notes):
            e.rules.setdefault(rule, set()).add(f"Profile {_shown(o.name)}")
    for o in tailored:
        spec = _d(o.doc.get("spec"))
        label = f"TailoredProfile {_shown(o.name)}"
        extends = _valid(spec.get("extends"))
        if extends is None:
            if spec.get("extends") not in (None, ""):
                e.notes.append(f"{label} extends a name this cannot read, so its base rule set is not known")
        elif extends in by_name:
            for rule in _profile_rules(by_name[extends], e.notes):
                e.rules.setdefault(rule, set()).add(f"{label} (extends {_shown(extends)})")
        else:
            e.unresolved_extends.append(f"{label} extends {_shown(extends)}, which was not read")
        for rule in _rule_references(spec, "enableRules", e.notes, "enables"):
            e.rules.setdefault(rule, set()).add(f"{label} (enableRules)")
        for rule, rationale in _rule_references(spec, "disableRules", e.notes, "disables").items():
            e.rules.setdefault(rule, set()).add(f"{label} (disableRules)")
            e.disabled.setdefault(rule, (_shown(o.name), rationale))
        for rule, rationale in _rule_references(spec, "manualRules", e.notes, "marks manual").items():
            e.rules.setdefault(rule, set()).add(f"{label} (manualRules)")
            e.manual.setdefault(rule, (_shown(o.name), rationale))
        state = _d(o.doc.get("status")).get("state")
        if state in ("ERROR", "PENDING"):
            message = _text(_d(o.doc.get("status")).get("errorMessage"), 200)
            e.notes.append(f"{label} is in state {state}{': ' + message if message else ''}")
    return e


def _check_rows(checks: list[Obj], scans: dict[str, ScanRow]) -> list[CheckRow]:
    """Every ComplianceCheckResult, with its own three-valued outcome. Only ``PASS`` from a usable scan is a pass; a
    ``FAIL`` stays a fail whatever its scan did, because a reported failure is never withdrawn by an absence."""
    rows: list[CheckRow] = []
    for o in checks:
        notes = list(o.notes)
        raw = o.doc.get("status")
        status = _one_of(raw, CHECK_STATUSES)
        rule = _valid(_annotations(o.doc).get(RULE_ANNOTATION))
        rule_raw = _annotations(o.doc).get(RULE_ANNOTATION)
        if rule is None and rule_raw not in (None, ""):
            notes.append(
                f"its {RULE_ANNOTATION} annotation {_shown(str(rule_raw))} is not a usable rule name, so it is not "
                "joined to a rule"
            )
        elif rule is None:
            notes.append(
                f"it carries no {RULE_ANNOTATION} annotation, so the rule it came from is not known and it is not "
                "joined to one"
            )
        scan = _valid(_labels(o.doc).get(SCAN_LABEL))
        severity = o.doc.get("severity")
        if severity not in (None, "") and _one_of(severity, SEVERITIES) is None:
            notes.append(f"its severity {_text(str(severity), 40)!r} is not one the operator defines")
        detail = None
        outcome: Outcome
        reason: str | None = None
        if status == "FAIL":
            outcome, detail = "fail", _text(o.doc.get("description"), 200) or None
            if scan is not None and scan in scans and not scans[scan].usable:
                notes.append(
                    f"its scan {scans[scan].name} is not usable ({scans[scan].why}); the failure is reported anyway, "
                    "because an incomplete scan does not withdraw a failure it found"
                )
        elif status == "PASS":
            row = scans.get(scan) if scan is not None else None
            if scan is None:
                outcome, reason = "not-evaluated", "scan-not-read"
                notes.append(
                    f"it carries no {SCAN_LABEL} label, so the scan that produced it is not known and whether that "
                    "scan completed cannot be checked"
                )
            elif row is None:
                outcome, reason = "not-evaluated", "scan-not-read"
                detail = f"ComplianceScan {_shown(scan)} was not in the input"
            elif not row.usable:
                reason = "scan-errored" if row.error else "scan-not-done"
                outcome, detail = "not-evaluated", f"ComplianceScan {row.name}: {row.why}"
            else:
                outcome = "pass"
        elif status is not None:
            outcome, reason = "not-evaluated", NOT_EVALUATED_STATUSES[status]
            detail = _text(_annotations(o.doc).get(ERROR_ANNOTATION), 200) or None
            if status == "INCONSISTENT":
                most = _text(_annotations(o.doc).get(MOST_COMMON_ANNOTATION), 60)
                sources = _text(_annotations(o.doc).get(INCONSISTENT_SOURCE_ANNOTATION), 200)
                detail = "; ".join(p for p in (f"most common {most}" if most else "", sources) if p) or detail
        elif raw in (None, ""):
            outcome, reason = "not-evaluated", "no-result"
        else:
            outcome, reason = "not-evaluated", "unrecognised-status"
            detail = f"status {_text(str(raw), 60)!r}"
        warnings = [_text(w, 160) for w in _l(o.doc.get("warnings"))[:MAX_LIST] if isinstance(w, str)]
        notes += [f"warning: {w}" for w in warnings if w]
        rows.append(
            CheckRow(
                name=_shown(o.name),
                status=status if status is not None else (_text(str(raw), 60) if raw not in (None, "") else ""),
                outcome=outcome,
                reason=reason,
                severity=_one_of(severity, SEVERITIES),
                rule=_shown(rule) if rule else None,
                scan=_shown(scan) if scan else None,
                suite=_valid(_labels(o.doc).get(SUITE_LABEL)),
                check_id=_valid(o.doc.get("id"), _XCCDF_ID),
                detail=detail,
                notes=sorted(dict.fromkeys(notes))[:MAX_NAMED],
                evidence=sorted({_text(w, 300) for w in [o.where, *o.wheres]})[:5],
            )
        )
    rows.sort(key=lambda r: (r.rule or "", r.name))
    return rows


def _rule_rows(
    e: _Expected,
    checks: list[CheckRow],
    rule_crs: dict[str, Obj],
) -> list[RuleRow]:
    """One row per rule the profiles expected, plus any rule only the results name. The outcome follows one order:
    a failure first, then tailoring, then what the checks say, then the silence of no result at all."""
    by_rule: dict[str, list[CheckRow]] = {}
    for row in checks:
        if row.rule is not None:
            by_rule.setdefault(row.rule, []).append(row)
    names = sorted(set(e.rules) | set(by_rule))
    out: list[RuleRow] = []
    for name in names:
        shown = _shown(name)
        rows_for = by_rule.get(name, [])
        notes: list[str] = []
        cr = rule_crs.get(name)
        frameworks = _frameworks(cr.doc, notes) if cr is not None else {}
        expected_from = sorted(e.rules.get(name, set()))
        if not expected_from:
            notes.append(
                "no profile in the input lists this rule, so it was read from the results alone and whether it "
                "belonged to the scanned profile is not known"
            )
        outcome: Outcome
        reason: str | None = None
        detail: str | None = None
        statuses = {r.status for r in rows_for}
        if any(r.outcome == "fail" for r in rows_for):
            outcome = "fail"
            detail = next((r.detail for r in rows_for if r.outcome == "fail" and r.detail), None)
        elif name in e.disabled:
            profile, rationale = e.disabled[name]
            outcome, reason = "not-evaluated", "disabled-by-tailoring"
            detail = f"TailoredProfile {profile}" + (f": {rationale}" if rationale else ": no rationale given")
            if rows_for:
                notes.append(
                    f"{len(rows_for)} result(s) for it are in the input ({', '.join(sorted(statuses) or ['no status'])}"
                    "), and the tailoring that disabled it is reported instead of them"
                )
        elif name in e.manual:
            profile, rationale = e.manual[name]
            outcome, reason = "not-evaluated", "manual-by-tailoring"
            detail = f"TailoredProfile {profile}" + (f": {rationale}" if rationale else ": no rationale given")
        elif not rows_for:
            outcome, reason = "not-evaluated", "missing-from-results"
        elif len({(r.outcome, r.reason) for r in rows_for}) > 1:
            outcome, reason = "not-evaluated", "results-disagree"
            detail = ", ".join(sorted({f"{r.name}: {r.status or 'no status'}" for r in rows_for})[:MAX_LIST])
        elif all(r.outcome == "pass" for r in rows_for):
            outcome = "pass"
        else:
            outcome = "not-evaluated"
            reason = next((r.reason for r in sorted(rows_for, key=lambda r: r.name) if r.reason), "no-result")
            detail = next((r.detail for r in sorted(rows_for, key=lambda r: r.name) if r.detail), None)
        for row in rows_for:
            notes += row.notes
        controls = sorted(dict.fromkeys(frameworks.get(NIST, [])))
        out.append(
            RuleRow(
                rule=shown,
                outcome=outcome,
                reason=reason,
                why=REASONS.get(reason or "") if reason else None,
                detail=detail,
                severity=_severity(cr, rows_for),
                check_type=_check_type(cr, notes),
                title=_text(cr.doc.get("title"), 160) or None if cr is not None else None,
                expected_from=expected_from[:MAX_LIST],
                checks=sorted({r.name for r in rows_for})[:MAX_LIST],
                scans=sorted({r.scan for r in rows_for if r.scan})[:MAX_LIST],
                controls=controls,
                frameworks=frameworks,
                notes=sorted(dict.fromkeys(notes))[:MAX_NAMED],
            )
        )
    out.sort(key=lambda r: (_OUTCOME_ORDER[r.outcome], r.reason or "", r.rule))
    return out


_OUTCOME_ORDER = {"fail": 0, "not-evaluated": 1, "pass": 2}


def _severity(cr: Obj | None, rows: list[CheckRow]) -> str | None:
    for row in sorted(rows, key=lambda r: r.name):
        if row.severity:
            return row.severity
    if cr is not None:
        value = cr.doc.get("severity")
        if _one_of(value, SEVERITIES):
            return str(value)
    return None


def _check_type(cr: Obj | None, notes: list[str]) -> str | None:
    if cr is None:
        return None
    value = cr.doc.get("checkType")
    if value in (None, ""):
        return None
    if _one_of(value, CHECK_TYPES) is not None:
        return str(value)
    notes.append(f"its Rule's checkType {_text(str(value), 40)!r} is neither Platform nor Node")
    return None


def _control_rows(rules: list[RuleRow]) -> list[ControlRow]:
    """Which NIST controls either side has evidence about. The operator evidences a control only through a rule it
    actually evaluated: a control whose only operator rule was tailored out, skipped or errored, and that kube-noob
    has no rule for, is reported as ``neither``. There is no ``satisfied``."""
    from kube_noob.audit.controls import RULE_CONTROLS, TITLES

    kube_noob: dict[str, list[str]] = {}
    for rid, controls in RULE_CONTROLS.items():
        for c in controls:
            kube_noob.setdefault(c, []).append(rid)
    operator: dict[str, dict[str, list[str]]] = {}
    for row in rules:
        for c in row.controls:
            bucket = operator.setdefault(c, {"pass": [], "fail": [], "not-evaluated": []})
            bucket[row.outcome].append(row.rule)
    out: list[ControlRow] = []
    for c in sorted(set(operator) | set(kube_noob)):
        bucket = operator.get(c, {"pass": [], "fail": [], "not-evaluated": []})
        passing, failing, skipped = len(bucket["pass"]), len(bucket["fail"]), len(bucket["not-evaluated"])
        kn = sorted(kube_noob.get(c, []))
        evaluated = passing + failing
        if evaluated and kn:
            evidence: Evidence = "both"
        elif evaluated:
            evidence = "compliance-operator"
        elif kn:
            evidence = "kube-noob-rule"
        else:
            evidence = "neither"
        if failing:
            status: ControlStatus = "failing"
        elif passing and not skipped:
            status = "passing"
        elif passing:
            status = "partly-evaluated"
        else:
            status = "not-evaluated"
        note = None
        if evidence == "neither":
            note = (
                "the Compliance Operator names this control on a rule it did not evaluate, and kube-noob has no rule "
                "mapped to it: nothing in this answer is evidence about it"
            )
        elif evidence == "kube-noob-rule":
            note = (
                "the Compliance Operator evaluated no rule for this control"
                if c in operator
                else "no Rule read here names this control, so the Compliance Operator gives no evidence about it"
            ) + "; kube-noob has rules for it, which this command does not run -- run kube-noob audit for them"
        elif status == "partly-evaluated":
            note = f"{skipped} rule(s) the operator names for this control were not evaluated"
        out.append(
            ControlRow(
                control=c,
                title=TITLES.get(c),
                evidence=evidence,
                status=status,
                operator_passing=passing,
                operator_failing=failing,
                operator_not_evaluated=skipped,
                operator_rules=sorted(dict.fromkeys(bucket["pass"] + bucket["fail"] + bucket["not-evaluated"]))[
                    :MAX_LIST
                ],
                kube_noob_rules=kn[:MAX_LIST],
                note=note,
            )
        )
    return out[:MAX_CONTROLS]


def _suite_rows(suites: list[Obj], scans: dict[str, ScanRow], rules: list[RuleRow]) -> list[SuiteRow]:
    """Each suite, and whether its own ``status.result`` survives. A suite claiming COMPLIANT over rules that were
    never evaluated is the headline this reader exists to print."""
    skipped = [r for r in rules if r.outcome == "not-evaluated"]
    failed = [r for r in rules if r.outcome == "fail"]
    out: list[SuiteRow] = []
    for o in suites:
        status = _d(o.doc.get("status"))
        claimed = status.get("result")
        phase = status.get("phase")
        named: list[str] = []
        for entry in _l(status.get("scanStatuses"))[:MAX_LIST]:
            name = _valid(_d(entry).get("name"))
            if name:
                named.append(name)
        for name in sorted({s for s, row in scans.items() if row.suite == o.name}):
            if name not in named:
                named.append(name)
        unusable = sorted({scans[n].name for n in named if n in scans and not scans[n].usable})
        reasons: list[str] = []
        if claimed == "COMPLIANT" and (skipped or failed or unusable):
            if skipped:
                reasons.append(f"{len(skipped)} rule(s) in its profile were never evaluated")
            if failed:
                reasons.append(f"{len(failed)} rule(s) failed")
            if unusable:
                reasons.append(f"its scan(s) {', '.join(unusable)} did not complete")
        elif _one_of(claimed, SCAN_RESULTS) is None:
            reasons.append(
                "its status.result is not in the input"
                if claimed in (None, "")
                else f"its status.result {_text(str(claimed), 60)!r} is not one the operator defines"
            )
        elif phase != DONE:
            reasons.append(
                f"it is in phase {_text(str(phase), 60) or 'none'}, not {DONE}, so its result is not a final one"
            )
        out.append(
            SuiteRow(
                name=_shown(o.name),
                phase=_text(str(phase), 60) or None,
                claimed_result=_one_of(claimed, SCAN_RESULTS) or (_text(str(claimed), 60) or None),
                error=_text(status.get("errorMessage"), 240) or None,
                agrees=not reasons,
                why="; ".join(reasons) or None,
                scans=sorted({_shown(n) for n in named})[:MAX_LIST],
            )
        )
    out.sort(key=lambda r: r.name)
    return out


def assess(c: Collected, *, top: int = MAX_RULES) -> dict[str, Any]:
    """Read ``c`` as evidence. Deterministic: the same objects in any order give the same bytes."""
    conflicts: list[str] = []
    objects = {r: _dedupe(c.objects[r], conflicts) for r in RESOURCES}
    scans = _scan_rows(objects["compliancescans"])
    e = _expected(objects["profiles"], objects["tailoredprofiles"])
    checks = _check_rows(objects["compliancecheckresults"], scans)
    rule_crs = {o.name: o for o in objects["rules"]}
    unjoined = [r for r in checks if r.rule is None]
    rules = _rule_rows(e, checks, rule_crs)
    controls = _control_rows(rules)
    suites = _suite_rows(objects["compliancesuites"], scans, rules)
    return _assemble(c, objects, e, scans, suites, checks, unjoined, rules, controls, conflicts, top)


def _undetermined(
    c: Collected,
    e: _Expected,
    scans: dict[str, ScanRow],
    suites: list[SuiteRow],
    checks: list[CheckRow],
    unjoined: list[CheckRow],
    rules: list[RuleRow],
    conflicts: list[str],
) -> list[str]:
    """Why this reading is not a verdict. The ONE predicate: ``_assemble`` calls it once and every renderer reads the
    field it wrote, so the text view, the JSON, the YAML, the MCP result and ``--require-complete`` cannot disagree
    about whether the evidence was complete (review classes 13 and 25)."""
    out: list[str] = []
    results = c.reads["compliancecheckresults"]
    if results.state == "not-read":
        out.append(f"no ComplianceCheckResult was read: {results.reason}")
    elif results.state == "partial":
        out.append(f"ComplianceCheckResults were only partly read: {results.reason}")
    if e.no_profile:
        out.append(
            "no Profile or TailoredProfile was read, so the rules the scan claimed to run are not known and a rule "
            "that produced no result at all cannot be seen"
        )
    for note in e.unresolved_extends:
        out.append(f"{note}, so its base rule set is not known")
    for resource in PROFILE_KINDS:
        read = c.reads[resource]
        if read.state == "partial":
            out.append(f"{RESOURCE_TO_KIND[resource]}s were only partly read: {read.reason}")
    if c.reads["rules"].state != "read":
        out.append(
            f"Rule objects were not read in full ({c.reads['rules'].reason}), so the control crosswalk is incomplete"
        )
    skipped = [r for r in rules if r.outcome == "not-evaluated"]
    if skipped:
        by_reason = Counter(r.reason or "unknown" for r in skipped)
        out.append(
            f"{len(skipped)} rule(s) were not evaluated: "
            + ", ".join(f"{n} {reason}" for reason, n in sorted(by_reason.items()))
        )
    unusable = sorted(row.name for row in scans.values() if not row.usable)
    if unusable:
        out.append(f"{len(unusable)} ComplianceScan(s) are not a completed scan: {', '.join(unusable[:MAX_NAMED])}")
    if unjoined:
        out.append(
            f"{len(unjoined)} ComplianceCheckResult(s) name no rule this could join, so what they were about is not "
            "known: " + ", ".join(sorted(r.name for r in unjoined)[:MAX_NAMED])
        )
    disagreeing = [s for s in suites if not s.agrees]
    for s in disagreeing:
        out.append(f"ComplianceSuite {s.name} reports {s.claimed_result or 'no result'} and {s.why}")
    if not checks:
        out.append("no ComplianceCheckResult was in the input, which is not the same as nothing to report")
    if c.unreadable:
        out.append(f"{len(c.unreadable)} file(s) could not be read; results in them are not in this answer")
    for refused in c.refused_files[:MAX_UNREADABLE]:
        out.append(
            f"{_text(refused['path'], 160)} {refused['reason']}, so what was read from it may not be what the "
            "cluster serves"
        )
    for resource, n in sorted(c.dropped.items()):
        out.append(f"{n} {resource} past the first {MAX_ITEMS} were not read")
    for resource, n in sorted(c.rejected.items()):
        out.append(f"{n} item(s) where a {RESOURCE_TO_KIND[resource]} was expected were not usable objects of it")
    for what, n in sorted(c.foreign.items()):
        out.append(f"{n} {what} object(s) of another API group were ignored: not the Compliance Operator's ({GROUP})")
    if conflicts:
        out.append(
            f"{len(conflicts)} object(s) appeared more than once with different content: "
            + ", ".join(conflicts[:5])
            + ("" if len(conflicts) <= 5 else f" and {len(conflicts) - 5} more")
        )
    out += [_text(n, 240) for n in e.notes]
    out += [_text(n, 240) for n in c.caveats]
    return sorted(dict.fromkeys(out))


def _assemble(
    c: Collected,
    objects: dict[str, list[Obj]],
    e: _Expected,
    scans: dict[str, ScanRow],
    suites: list[SuiteRow],
    checks: list[CheckRow],
    unjoined: list[CheckRow],
    rules: list[RuleRow],
    controls: list[ControlRow],
    conflicts: list[str],
    top: int,
) -> dict[str, Any]:
    because = _undetermined(c, e, scans, suites, checks, unjoined, rules, conflicts)
    complete = not because
    outcomes = Counter(r.outcome for r in rules)
    reasons = Counter(r.reason or "" for r in rules if r.outcome == "not-evaluated")
    counts = {
        "rules": len(rules),
        "passing": outcomes["pass"],
        "failing": outcomes["fail"],
        "notEvaluated": outcomes["not-evaluated"],
        "tailoredOut": reasons["disabled-by-tailoring"] + reasons["manual-by-tailoring"],
        "missingFromResults": reasons["missing-from-results"],
        "notApplicable": reasons["not-applicable"],
        "fromAnUnfinishedScan": reasons["scan-not-done"] + reasons["scan-errored"] + reasons["scan-not-read"],
        "checks": len(checks),
        "checksNotEvaluated": sum(1 for r in checks if r.outcome == "not-evaluated"),
        "checksWithoutARule": len(unjoined),
        "scans": len(scans),
        "scansNotDone": sum(1 for r in scans.values() if not r.usable),
        "controlsEvidencedByNeither": sum(1 for r in controls if r.evidence == "neither"),
    }
    verdict: Verdict = "non-compliant" if counts["failing"] else ("undetermined" if because else "compliant")
    withheld = (
        None
        if complete
        else (
            f"{counts['notEvaluated']} of {counts['rules']} rule(s) were not evaluated"
            if counts["notEvaluated"]
            else "the evidence was not read in full"
        )
    )
    shown = rules[:top]
    out: dict[str, Any] = {
        "source": c.source,
        "verdict": verdict,
        "complete": complete,
        "summary": _summary(verdict, counts, because),
        "undeterminedBecause": because,
        "counts": counts,
        # A rate over rules the operator actually evaluated, and only when nothing was left unevaluated: the same
        # shape audit.model.Report uses for its score, so a number never sits beside an unread rule (G272).
        "passRate": None if withheld else (round(100.0 * counts["passing"] / counts["rules"], 1) if rules else None),
        **({"passRateWithheld": withheld} if withheld else {}),
        "suites": [s.model_dump(by_alias=True, exclude_none=True) for s in suites],
        "scans": [scans[k].model_dump(by_alias=True, exclude_none=True) for k in sorted(scans)],
        "rules": [r.model_dump(by_alias=True, exclude_none=True) for r in shown],
        "rulesTotal": len(rules),
        "notEvaluated": [r.model_dump(by_alias=True, exclude_none=True) for r in rules if r.outcome == "not-evaluated"][
            :top
        ],
        "checksWithoutARule": [r.model_dump(by_alias=True, exclude_none=True) for r in unjoined][:MAX_LIST],
        "controls": [r.model_dump(by_alias=True, exclude_none=True) for r in controls],
        "reasons": {k: REASONS[k] for k in sorted(reasons) if k in REASONS},
    }
    if len(rules) > len(shown):
        out["notShown"] = len(rules) - len(shown)
    reads = []
    for r in RESOURCES:
        read = c.reads[r].model_copy()
        if read.state in ("read", "partial"):
            read.objects = len(objects[r])
        reads.append(read.model_dump(by_alias=True))
    out["sources"] = reads
    out["unreadable"] = c.unreadable[:MAX_UNREADABLE]
    out["unreadableTotal"] = len(c.unreadable)
    out["droppedUnread"] = c.dropped_unread
    out["notCovered"] = NOT_COVERED
    return out


def _summary(verdict: Verdict, counts: dict[str, int], because: list[str]) -> str:
    head = (
        f"{counts['rules']} rule(s) the profile expected: {counts['passing']} evaluated and passing, "
        f"{counts['failing']} failing, {counts['notEvaluated']} not evaluated"
    )
    if verdict == "compliant":
        return f"{head}; every rule the profile expected was evaluated and passed"
    if verdict == "non-compliant":
        tail = "" if not because else f", and {len(because)} thing(s) were not evaluated or not read"
        return f"{head}; the Compliance Operator reported {counts['failing']} failing rule(s){tail}"
    parts = []
    if counts["tailoredOut"]:
        parts.append(f"{counts['tailoredOut']} tailored out")
    if counts["missingFromResults"]:
        parts.append(f"{counts['missingFromResults']} with no result at all")
    if counts["notApplicable"]:
        parts.append(f"{counts['notApplicable']} NOT-APPLICABLE")
    if counts["fromAnUnfinishedScan"]:
        parts.append(f"{counts['fromAnUnfinishedScan']} from a scan that did not complete")
    detail = f" ({', '.join(parts)})" if parts else ""
    return (
        f"{head}{detail}; undetermined, not compliant: {len(because)} reason(s) below. "
        "A suite that is green because checks were tailored out or never ran is not a compliant one."
    )


# ------------------------------------------------------------------------------------------------- text ----


def render_text(out: dict[str, Any]) -> str:
    """The text view. It carries every reason the JSON does (review class 6): a reader of the text acts on the
    list too, and the headline word comes from the same ``undeterminedBecause`` the JSON carries."""
    c = out["counts"]
    rate = out["passRate"]
    lines = [
        f"compliance results ({out['source']}): {out['verdict']} -- {out['summary']}",
        f"counts: {c['rules']} rule(s), {c['passing']} passing, {c['failing']} failing, "
        f"{c['notEvaluated']} not evaluated ({c['tailoredOut']} tailored out, "
        f"{c['missingFromResults']} missing from results, {c['notApplicable']} not applicable, "
        f"{c['fromAnUnfinishedScan']} from an unfinished scan); {c['checks']} check(s), "
        f"{c['scans']} scan(s) of which {c['scansNotDone']} not done; "
        f"{c['controlsEvidencedByNeither']} control(s) evidenced by neither side",
        f"pass rate: {rate}%" if rate is not None else f"pass rate withheld: {out['passRateWithheld']}",
    ]
    for s in out["suites"]:
        head = f"  suite {s['name']}  phase {s.get('phase') or 'unknown'}  reports {s.get('claimedResult') or 'none'}"
        lines.append(head + ("  AGREES" if s["agrees"] else "  DOES NOT HOLD"))
        if s.get("why"):
            lines.append(f"      {s['why']}")
        if s.get("error"):
            lines.append(f"      error: {s['error']}")
    for s in out["scans"]:
        state = "DONE and usable" if s["usable"] else f"NOT a completed scan: {s.get('why')}"
        lines.append(
            f"  scan {s['name']}  phase {s.get('phase') or 'unknown'}  result {s.get('result') or 'unknown'}  {state}"
        )
    for r in out["rules"]:
        head = f"  {r['rule']}  {r['outcome'].upper()}"
        if r.get("reason"):
            head += f" [{r['reason']}]"
        if r.get("severity"):
            head += f"  severity {r['severity']}"
        if r.get("checkType"):
            head += f"  {r['checkType']}"
        lines.append(head)
        if r.get("why"):
            lines.append(f"      {r['why']}")
        if r.get("detail"):
            lines.append(f"      {r['detail']}")
        if r.get("expectedFrom"):
            lines.append(f"      expected from: {', '.join(r['expectedFrom'][:5])}")
        if r.get("checks"):
            lines.append(f"      results: {', '.join(r['checks'][:5])}")
        if r.get("controls"):
            lines.append(f"      NIST 800-53: {', '.join(r['controls'][:10])}")
        for other, ids in sorted(r.get("frameworks", {}).items()):
            if other != NIST:
                lines.append(f"      {other}: {', '.join(ids[:10])}")
        for note in r.get("notes", [])[:5]:
            lines.append(f"      note: {note}")
    for r in out["checksWithoutARule"]:
        lines.append(f"  check {r['name']}  status {r['status'] or 'none'}  NOT JOINED TO A RULE")
        for note in r.get("notes", [])[:3]:
            lines.append(f"      note: {note}")
    for row in out["controls"]:
        lines.append(
            f"  control {row['control']} ({row.get('title') or 'no title'})  evidence {row['evidence']}  "
            f"{row['status']}  operator {row['operatorPassing']} passing / {row['operatorFailing']} failing / "
            f"{row['operatorNotEvaluated']} not evaluated  kube-noob rules "
            f"{', '.join(row['kubeNoobRules'][:5]) or 'none'}"
        )
        if row.get("note"):
            lines.append(f"      {row['note']}")
    if out.get("notShown"):
        lines.append(f"  {out['notShown']} more rule(s) not shown")
    for read in out["sources"]:
        if read["state"] != "read":
            lines.append(f"not read: {read['resource']} ({read['state']}) {read['reason']}")
    for u in out["unreadable"]:
        lines.append(f"unreadable: {u['path']} -- {u['reason']}")
    if out["unreadableTotal"] > len(out["unreadable"]):
        lines.append(f"unreadable: {out['unreadableTotal'] - len(out['unreadable'])} more not listed")
    if out["droppedUnread"]:
        lines.append(f"{out['droppedUnread']} Secret object(s) in the input were dropped unread")
    for reason in out["undeterminedBecause"]:
        lines.append(f"undetermined because: {reason}")
    lines.append(out["notCovered"])
    return "\n".join(lines)
