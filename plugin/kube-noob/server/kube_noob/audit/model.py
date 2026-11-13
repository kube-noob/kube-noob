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
        key = "\x1f".join((self.rule_id, self.resource, self.locator or self.path))
        return hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]

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
    verdict: str  # "exposed" | "mitigated" | "not-applicable"
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
    # Every rule NOT in `evaluated_rules`, with why: the stage was not requested, the rule declined, or none of
    # the kinds it reads were in the input ("no Service in the input"). A rule about a kind that is absent used
    # to count as evaluated and clean (G281).
    not_evaluated: dict[str, str] = field(default_factory=dict)
    # Rules that ran on part of what they read: the kinds they asked for and did not get, per rule.
    absent_subjects: dict[str, list[str]] = field(default_factory=dict)
    # Objects of a kind the rules know that they REFUSED to read (an apiVersion that is not a string, not shaped
    # like an API, or in a group the kind is not known under): `{"object", "kind", "why"}` each. Not a finding and
    # not an absence: the verdict is undetermined while this is non-empty, and `audit` and `gate` exit 1 (R1).
    not_audited: list[dict[str, Any]] = field(default_factory=list)

    def undetermined(self) -> str | None:
        """Why this report's verdict is not a pass and not a fail, or `None` when it is determined.

        The ONE predicate every surface reads (summary.score/verdict, the text headline, the exit code, the gate's
        headline and `passed`, `fix.after`, the KSI page, the posture report): a record that stops the verdict
        being a pass -- today an object the rules did not read and no exception accepted (review 5, item 3).
        """
        return undetermined_reason(self.not_audited)

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
        """0..100 posture score. Deterministic; used by the learning grader and the training reward."""
        weights = {Severity.CRITICAL: 25.0, Severity.HIGH: 10.0, Severity.MEDIUM: 4.0, Severity.LOW: 1.0}
        penalty = sum(weights.get(f.severity, 0.0) for f in self.findings)
        return max(0.0, 100.0 - penalty)

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
                # verdict word is in the summary itself, not only in a note (review 5, item 3).
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
            ),
            "redTeam": [s.as_dict() for s in self.scenarios],
            # Only when the target is past the minor the removal table was read at, so every result that was
            # already complete stays byte-identical. See `catalog.not_checked_beyond`.
            **({"notCheckedBeyond": limit} if (limit := not_checked_beyond(self.kubernetes_version)) else {}),
            # Only when the bundle carried the cluster audit configuration, so every result that never saw one
            # stays byte-identical (R4, G244).
            **({"detectionCoverage": self.detection_coverage} if self.detection_coverage else {}),
        }


def undetermined_reason(not_audited: list[dict[str, Any]]) -> str | None:
    """The verdict word for a list of `notAudited` rows: rows no exception accepted stop the verdict being a pass."""
    open_rows = [r for r in not_audited if isinstance(r, dict) and not r.get("acceptedBy")]
    return f"{len(open_rows)} object(s) not audited" if open_rows else None


def _sort_key(f: Finding) -> tuple[int, int, int, str]:
    return (-int(f.severity), f.doc_index if f.doc_index is not None else -1, f.line or 0, f.rule_id)
