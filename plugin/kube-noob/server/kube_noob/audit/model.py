"""Finding / report data model shared by validation, audit, calibration and red-team stages."""

from __future__ import annotations

import enum
import hashlib
from dataclasses import dataclass, field
from typing import Any

from kube_noob.audit.controls import controls_for
from kube_noob.audit.controls import summary as control_summary
from kube_noob.catalog import SOURCES, Citation, not_checked_beyond


class Severity(enum.IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str | int | Severity) -> Severity:
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return cls(value)
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            raise ValueError(f"Unknown severity {value!r}; use one of {[s.name.lower() for s in cls]}") from exc


class Stage(enum.Enum):
    VALIDATE = "validate"
    AUDIT = "audit"
    CALIBRATE = "calibrate"
    RED_TEAM = "red-team"


def fingerprint_for(rule_id: str, resource: str, locator: str) -> str:
    """The one definition of a finding's identity: the rule, the object and the name-keyed location.

    A function rather than only a method, because the receipt (``kube_noob.receipt``) needs it for data that is
    no longer a ``Finding``: the gate's finding dicts, which carry CVE and SAST results beside audit rules. A
    second implementation of this key would drift from this one, which is the defect class where a private copy
    of a shared list turns out to be a subset of it -- so there is one definition, here, and
    ``Finding.fingerprint`` calls it. The identity is unchanged: G190's reasons are in that method's docstring.
    """
    key = "\x1f".join((rule_id, resource, locator))
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    stage: Stage
    category: str
    resource: str
    message: str
    remediation: str
    path: str = ""
    locator: str = ""
    line: int | None = None
    doc_index: int | None = None
    citations: list[str] = field(default_factory=list)
    stackrox_policies: list[str] = field(default_factory=list)

    def fingerprint(self) -> str:
        """A stable identity for this finding, for baselines and for tracking it across runs.

        Hashes the rule, the object and the name-keyed location. Deliberately NOT the message, the
        file path, the line, the document index or the severity: messages carry counts and sorted
        lists that change on their own, a file move or a gate run from a subdirectory rewrites the
        path, the document index shifts when a file is added to the bundle, and several rules override
        severity per finding. Each of those would rotate the identity of a finding that did not change.

        This is separate from the SARIF ``partialFingerprints`` that gate.py emits, and does not touch
        it: that one is GitHub's alert-matching key and redefining it would reset every alert's history.
        """
        return fingerprint_for(self.rule_id, self.resource, self.locator or self.path)

    def citation_objects(self) -> list[Citation]:
        return [SOURCES[c] for c in self.citations if c in SOURCES]

    def as_dict(self) -> dict[str, Any]:
        return {
            "ruleId": self.rule_id,
            "title": self.title,
            "severity": self.severity.name.lower(),
            "stage": self.stage.value,
            "category": self.category,
            "resource": self.resource,
            "docIndex": self.doc_index,
            "path": self.path,
            "fingerprint": self.fingerprint(),
            "line": self.line,
            "message": self.message,
            "remediation": self.remediation,
            "citations": [c.as_dict() for c in self.citation_objects()],
            "stackroxPolicies": self.stackrox_policies,
            "controls": controls_for(self.rule_id),
        }


@dataclass
class RedTeamScenario:
    scenario_id: str
    question: str
    verdict: str  # "exposed" | "mitigated" | "not-applicable" | "undecided" (an input it could not read, G276)
    severity: Severity
    evidence: list[str]
    blast_radius: str
    safeguards: list[str]
    verification: list[str]

    def as_dict(self) -> dict[str, Any]:
        return {
            "scenarioId": self.scenario_id,
            "question": self.question,
            "verdict": self.verdict,
            "severity": self.severity.name.lower(),
            "evidence": self.evidence,
            "blastRadius": self.blast_radius,
            "safeguards": self.safeguards,
            "verification": self.verification,
        }


#: How many declined rules, or unread objects, the undetermined reason names before it gives a count.
MAX_WITHHELD_NAMED = 10


@dataclass
class Report:
    platform: str
    kubernetes_version: str
    platform_version: str | None
    resources: list[str]
    findings: list[Finding] = field(default_factory=list)
    scenarios: list[RedTeamScenario] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    # Every rule that actually ran. Empty means the caller did not record it, and the control summary
    # then omits its coverage columns rather than claiming a coverage it cannot support.
    evaluated_rules: list[str] = field(default_factory=list)
    # Every rule that produced a finding BEFORE `min_severity` filtered the report. Without it a rule whose
    # finding this view withheld was counted clean, so `--min-severity high` could turn a bundle with a
    # privileged container into a clean compliance record (G199).
    fired_rules: list[str] = field(default_factory=list)
    # Rule -> why it reached no verdict at all on this input, whatever the cause: the stage was not requested,
    # the rule declined on every object it had (the summary of `declined`, which keeps the per-object detail),
    # or none of the kinds it reads were in the input ("no Service in the input") -- a rule about a kind that is
    # absent used to count as evaluated and clean (G281). A partly evaluated rule (a finding on one object, a
    # decline on another) stays in `evaluated_rules` and is not here. Carried in `as_dict` as `notEvaluated`.
    not_evaluated: dict[str, str] = field(default_factory=dict)
    # Rules that ran on part of what they read: the kinds they asked for and did not get, per rule (G281).
    absent_subjects: dict[str, list[str]] = field(default_factory=dict)
    # Rule -> the note for a rule that reported a finding on one object and declined on another. It RAN, so it
    # is in `evaluated_rules` and never in `not_evaluated` (G281, D4) -- which is exactly why this field has to
    # exist: G272 inferred "partly evaluated" from a rule having findings and NOT being in the evaluated list,
    # and once such a rule is correctly recorded as having run, that inference can never fire again and the
    # list it fills was silently empty for every input. Carried into `controlSummary` as `partlyEvaluatedRules`.
    partly_evaluated: dict[str, str] = field(default_factory=dict)
    # Rule -> the objects it declined and why, bounded, with how many entries were withheld (G272). Only when a
    # rule declined with a reason, so every result that had none stays byte-identical.
    declined: dict[str, dict[str, Any]] = field(default_factory=dict)
    # Every object, or part of one, that was NOT audited: an object of a kind the rules know that this reader
    # REFUSED (an apiVersion that is not a string, not shaped like an API, or a group the kind is not known
    # under -- G281), a pod spec in a kind with no reader, a container where the reader for its kind does not
    # look (G360), a container whose image an operator supplies, or an object in a group this reader refuses
    # (G272). Each entry is {"object", "kind", "why"} with `why` a fixed
    # phrase, never input text, plus `acceptedBy` once an exception accepted it. Not a finding and not an
    # absence: `undetermined` reads it beside `declined`, and while one row no exception accepted is here the
    # verdict is undetermined and `audit` and `gate` exit 1 whatever `--fail-on` says (R1; the sixth review
    # found "containers were NOT audited" printed under `score 100.0`, G272). `as_dict` carries it as
    # `notAudited`, always, so a reader never has to tell "nothing was unread" from "this view does not say".
    not_audited: list[dict[str, Any]] = field(default_factory=list)
    # What the cluster's audit configuration can and cannot record, when the bundle carries the object that
    # says so (kube_noob.audit.detection). None when it does not: the absence of the singleton means it was
    # not collected, and a coverage statement is exactly the thing not to invent (R4, G244).
    detection_coverage: dict[str, Any] | None = None

    def max_severity(self) -> Severity | None:
        return max((f.severity for f in self.findings), default=None)

    def counts(self) -> dict[str, int]:
        out = {s.name.lower(): 0 for s in Severity}
        for f in self.findings:
            out[f.severity.name.lower()] += 1
        return out

    def score(self) -> float:
        """0..100 posture score over the findings. Deterministic; used by the learning grader and the training
        reward, which ask for it by name. The REPORT withholds it while anything was not read: see
        `undetermined`."""
        weights = {Severity.CRITICAL: 25.0, Severity.HIGH: 10.0, Severity.MEDIUM: 4.0, Severity.LOW: 1.0}
        penalty = sum(weights.get(f.severity, 0.0) for f in self.findings)
        return max(0.0, 100.0 - penalty)

    def undetermined(self) -> str | None:
        """Why this report is not a verdict, or None when it is one: the ONE predicate every renderer reads.

        A score is computed from findings, and a rule that declined on an object (`declined` names it: an API
        server started through a script it did not read, a partly evaluated rule) found nothing there BECAUSE it
        did not look. `score=100.0` printed above "KN-S038 was not evaluated in full" was a number beside an
        unread rule, the one thing the product rule forbids (G272). The same holds for every other record that
        something was not read or not evaluated: an object this reader refused, and a rule whose subject kind
        was absent from the input, which is not evaluated and never clean (`not_audited`, G281). While this is
        not None: `score` is null with this text beside it as `verdictReason` under `verdict: undetermined`,
        `audit` and `gate` exit 1 whatever `--fail-on` says, the gate is `incomplete` and not `passed`, and the
        eval grader marks every finding-derived check not evaluated (seventh review: an undetermined audit
        exited 0 and the gate said passed). The quiet declines of a partial bundle (no NetworkPolicy here to
        judge) and a stage the caller did not ask for are not an unread object, and keep the number; neither is
        a `not_audited` row an exception accepted, which stays listed and no longer withholds the score
        (G281, review 5).

        The text before the first colon is the short form the text view prints.
        """
        heads: list[str] = []
        details: list[str] = []
        # A rule whose every decline names an object an exception ACCEPTED is covered by that same reviewed
        # decision, and no longer withholds the score. Without this, G281's accept path died against G272's
        # new channel: the owner accepted "this Knative Service is not audited", the row went quiet, and the
        # two control-plane rules that declined BECAUSE of that very object still held the verdict open -- one
        # object blocking the verdict twice, through two mechanisms, only one of which an exception can reach.
        # A decline that names no object ("" for the bundle) is never covered: nobody signed off on that.
        accepted = {str(row.get("object")) for row in self.not_audited if row.get("acceptedBy")}
        open_declined = sorted(rid for rid, record in self.declined.items() if not _all_accepted(record, accepted))
        if open_declined:
            heads.append(f"{len(open_declined)} rule{'s' if len(open_declined) != 1 else ''} not evaluated in full")
            details.append(_named(open_declined))
        if (phrases := _not_audited_phrases(self.not_audited)) is not None:
            heads.append(phrases[0])
            details.append(phrases[1])
        if not heads:
            return None
        return f"{' and '.join(heads)}: {'; '.join(details)}"

    def as_dict(self) -> dict[str, Any]:
        return {
            "platform": self.platform,
            "platformVersion": self.platform_version,
            "kubernetesVersion": self.kubernetes_version,
            "resources": self.resources,
            "summary": {
                "counts": self.counts(),
                "maxSeverity": top.name.lower() if (top := self.max_severity()) is not None else None,
                # A number beside "undetermined" was two verdicts in one line: the score is withheld, and the
                # verdict word is in the summary itself, not only in a note (G281, review 5, item 3). The
                # reason is `verdictReason`, the name `alert_report` already gives the same thing (G272's
                # `scoreWithheld` said it a second way).
                "score": None if (why := self.undetermined()) else round(self.score(), 1),
                **({"verdict": "undetermined", "verdictReason": why} if why else {}),
            },
            "assumptions": self.assumptions,
            "notAudited": list(self.not_audited),
            "findings": [f.as_dict() for f in sorted(self.findings, key=_sort_key)],
            "controlSummary": control_summary(
                [f.rule_id for f in self.findings],
                None,
                self.evaluated_rules or None,
                self.fired_rules or None,
                not_evaluated=self.not_evaluated or None,
                absent_subjects=self.absent_subjects or None,
                partly_evaluated=self.partly_evaluated or None,
            ),
            "redTeam": [s.as_dict() for s in self.scenarios],
            # Only when the target is past the minor the removal table was read at, so every result that was
            # already complete stays byte-identical. See `catalog.not_checked_beyond`.
            **({"notCheckedBeyond": limit} if (limit := not_checked_beyond(self.kubernetes_version)) else {}),
            # Only when the bundle carried the cluster audit configuration, so every result that never saw one
            # stays byte-identical (R4, G244).
            **({"detectionCoverage": self.detection_coverage} if self.detection_coverage else {}),
            **({"declined": self.declined} if self.declined else {}),
            **({"notEvaluated": self.not_evaluated} if self.not_evaluated else {}),
        }


def _all_accepted(record: dict[str, Any], accepted: set[str]) -> bool:
    """Whether every object this rule declined on is one an exception accepted.

    `record` is a `Report.declined` row: `{"entries": [{"resource", "reason"}], "withheld": n, "decided": n}`.
    A row with entries it could not list (`withheld`) cannot be shown to be fully covered, and a decline that
    names no object ("" for the bundle) is never covered, because nobody signed off on that.
    """
    entries = record.get("entries") if isinstance(record, dict) else None
    if not isinstance(entries, list) or not entries or record.get("withheld"):
        return False
    return all(isinstance(e, dict) and str(e.get("resource") or "") in accepted and e.get("resource") for e in entries)


def _named(items: list[str]) -> str:
    """`MAX_WITHHELD_NAMED` of these names, then a count of the rest: the one bound both halves of the
    undetermined reason are held to, so neither can grow without the other."""
    return ", ".join(items[:MAX_WITHHELD_NAMED]) + (
        f" and {len(items) - MAX_WITHHELD_NAMED} more" if len(items) > MAX_WITHHELD_NAMED else ""
    )


def open_not_audited(not_audited: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The `notAudited` rows no exception accepted: the ones that still stop the verdict being a pass.

    An accepted row stays listed -- the object was still not audited -- and is not counted here
    (`audit.exceptions.accept_not_audited` stamps `acceptedBy`, G281 review 5).
    """
    return [r for r in not_audited if isinstance(r, dict) and not r.get("acceptedBy")]


def _not_audited_phrases(not_audited: list[dict[str, Any]]) -> tuple[str, str] | None:
    """The (head, detail) the unaccepted `notAudited` rows imply, or None when no row is left.

    The ONE place that phrase is built, so `Report.undetermined` and `undetermined_reason` -- which a caller
    holding only a serialised report reaches for -- cannot drift apart. A row whose `kind` is missing still
    counts; it is named "object" rather than dropped, because an unrecognised shape is not an absence.
    """
    rows = open_not_audited(not_audited)
    if not rows:
        return None
    counts: dict[str, int] = {}
    for entry in rows:
        what = str(entry.get("kind") or "object")
        counts[what] = counts.get(what, 0) + 1
    head = " and ".join(f"{n} {what}{'s' if n != 1 else ''}" for what, n in sorted(counts.items())) + " not audited"
    names = list(dict.fromkeys(str(entry.get("object", "")) for entry in rows))
    return head, "not read in full: " + _named(names)


def undetermined_reason(not_audited: list[dict[str, Any]]) -> str | None:
    """Why a list of `notAudited` rows on its own leaves the verdict undetermined, or None when it does not.

    For a caller that holds a serialised report and no `Report` (the drift snapshot's `coverage.notAudited`).
    It reads the same `_not_audited_phrases` as `Report.undetermined`, so the two cannot say different things
    about the same rows.
    """
    if (phrases := _not_audited_phrases(not_audited)) is None:
        return None
    return f"{phrases[0]}: {phrases[1]}"


def _sort_key(f: Finding) -> tuple[int, int, int, str]:
    return (-int(f.severity), f.doc_index if f.doc_index is not None else -1, f.line or 0, f.rule_id)


#: What an `unreadable` row's `acceptedBy` holds when the caller passed the flag. The same key an accepted
#: `notAudited` row carries, for the same reason (AGENTS.md, "a waiver the person asked for"): the person has
#: said "decide without that file", so a verdict IS reached on the files that were read, and the file stays named.
SKIP_UNREADABLE = "--skip-unreadable"


def unread_rows(report: dict[str, Any]) -> list[dict[str, str]]:
    """The files a report could not read, as `{"path", "why"}` rows, whichever command wrote the report.

    A GATE report's `unreadable` rows carry `file` and an AUDIT report's carry `path` -- the gate names a file the
    way `files` and `skipped` do, the audit the way `cli._dir_yaml` does. `sarif_of_gate` normalised the two
    inline (G331) and two renderers further along did not: the HTML page printed "File not read." beside an
    empty name and the OSCAL remark said "could not be read and were skipped: ?." for every gate report (G341).
    One reader, so the next renderer of these rows cannot pick the wrong key (review classes 9 and 21).

    Every row, accepted or not: a file is NAMED whatever was decided about it. `open_unread` is the predicate.
    """
    return [
        {
            "path": str(u.get("file") or u.get("path") or ""),
            "why": str(u.get("why") or ""),
            **({"acceptedBy": str(u["acceptedBy"])} if u.get("acceptedBy") else {}),
        }
        for u in report.get("unreadable") or []
        if isinstance(u, dict)
    ]


def open_unread(report: dict[str, Any]) -> list[dict[str, str]]:
    """The unread files nobody accepted: the ones that withhold the verdict (G340).

    The ONE predicate for it, read by `gate.run` for `incomplete`, by `incomplete_reason` and by the OSCAL emitter,
    as `open_not_audited` is for objects. A row `--skip-unreadable` accepted is still listed and does not
    withhold anything: a waiver is an answer about less evidence, never a cleaner answer about the same evidence.
    """
    return [u for u in unread_rows(report) if not u.get("acceptedBy")]


def blocked_manifests(report: dict[str, Any]) -> list[dict[str, Any]]:
    """The files a gate's walk declined to read as manifests: the `skipped` rows marked `forbidsVerdict` (G325).

    `gate.run` puts the marker on the row; this is the reader for a caller that holds the report. `incomplete_reason`
    reads it, and so do the gate's exit code and the receipt that records that code (`receipt.gate_exit_code`,
    G359), so the code a receipt records and the reason beside it are taken from the same rows.
    """
    return [s for s in report.get("skipped") or [] if isinstance(s, dict) and s.get("forbidsVerdict")]


def incomplete_reason(report: dict[str, Any]) -> str:
    """Why this gate report is incomplete, as one line, or an empty string when it is not.

    Three reasons make a gate incomplete and only the first has a key of its own (`undetermined`, the audit's).
    The SARIF invocation assembled the second inline (G325) and the HTML masthead read the first alone, so a
    report incomplete for a file printed "The gate is incomplete: None". Every renderer that states the reason
    reads this.
    """
    parts = [str(report["undetermined"])] if report.get("undetermined") else []
    blocked = blocked_manifests(report)
    if blocked:
        named = "; ".join(f"{s['file']}: {s['why']}" for s in blocked[:5])
        parts.append(f"{len(blocked)} file(s) were not read as manifests: {named}")
    unread = open_unread(report)
    if unread:
        named = "; ".join(f"{u['path']}: {u['why']}" for u in unread[:5])
        parts.append(f"{len(unread)} file(s) could not be read: {named}")
    return "; ".join(parts)
