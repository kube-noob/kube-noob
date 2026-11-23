"""A rule that FIRED must never be counted clean because the caller filtered its finding out (G199).

`--min-severity high` filters the report's findings but not the record of which rules ran, so every rule whose
finding was withheld used to land in `clean`: `CP-10` went from "3 findings, 6 clean" to "0 findings, 9 clean",
and the compliance output then said nine rules ran and found nothing. Three of them had found something.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from kube_noob import oscal
from kube_noob.audit.controls import summary
from kube_noob.audit.engine import analyze
from kube_noob.audit.model import Severity
from kube_noob.cli import main

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / "examples" / "insecure-deployment.yaml"
WHEN = datetime(2026, 11, 5, 12, 0, 0, tzinfo=UTC)


def _controls(min_severity: Severity) -> dict[str, dict]:
    rep = analyze(BUNDLE.read_text(encoding="utf-8"), "openshift", "4.22", min_severity=min_severity).as_dict()
    return {c["id"]: c for c in rep["controlSummary"]["controls"]}


def test_a_withheld_finding_does_not_become_clean() -> None:
    low = _controls(Severity.LOW)["CP-10"]
    high = _controls(Severity.HIGH)["CP-10"]
    # `clean` was 6 before G281; the CP-10 rules whose kind this bundle lacks (no PodDisruptionBudget, no
    # HorizontalPodAutoscaler) are not evaluated now, so compare the two filters rather than pin the number.
    assert low["findings"] == 3 and low["clean"] >= 1
    # The three rules whose findings were withheld may not migrate into `clean`.
    assert high["clean"] == low["clean"], (
        f"clean grew from {low['clean']} to {high['clean']}: a fired rule was counted clean"
    )
    assert high["withheld"] == 3, high
    assert high["findings"] == 0, "the view really does hide them; that part is the caller's choice"


def test_the_buckets_always_account_for_every_rule_of_a_control() -> None:
    """findings + excepted + clean + withheld + notEvaluated is the control's whole rule set, at any filter."""
    from kube_noob.audit.controls import RULE_CONTROLS

    total = dict.fromkeys({x for cs in RULE_CONTROLS.values() for x in cs}, 0)
    for cs in RULE_CONTROLS.values():
        for c in cs:
            total[c] += 1
    for sev in (Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL):
        for cid, entry in _controls(sev).items():
            got = (
                entry["findings"]
                + entry.get("excepted", 0)
                + entry["clean"]
                + entry.get("withheld", 0)
                + entry["notEvaluated"]
            )
            assert got == total[cid], (sev, cid, entry, total[cid])


def test_no_control_is_clean_only_because_of_the_filter() -> None:
    """The number of clean rules per control must not depend on --min-severity at all."""
    base = {k: v["clean"] for k, v in _controls(Severity.INFO).items()}
    for sev in (Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL):
        got = {k: v["clean"] for k, v in _controls(sev).items()}
        assert got == base, f"clean changed at {sev}: {[k for k in base if base[k] != got.get(k)]}"


def test_summary_without_the_fired_set_keeps_the_old_shape() -> None:
    out = summary(["KN-S001"], None, ["KN-S001", "KN-S002"])
    assert all("withheld" not in c for c in out["controls"]), "no fired set means no claim about withholding"


def _oscal_states(min_severity: Severity) -> dict[str, dict]:
    rep = analyze(BUNDLE.read_text(encoding="utf-8"), "openshift", "4.22", min_severity=min_severity).as_dict()
    entries = {c["id"]: c for c in rep["controlSummary"]["controls"]}
    doc = oscal.assessment_results(rep, timestamp=WHEN)
    out = {}
    for f in doc["assessment-results"]["results"][0].get("findings", []):
        label = f["title"].split()[0]
        out[label] = {**f["target"]["status"], "entry": entries[label]}
    return out


def test_oscal_satisfies_a_control_only_when_nothing_was_found_or_withheld() -> None:
    states = _oscal_states(Severity.CRITICAL)
    assert states, "the controls are still reviewed"
    for label, s in states.items():
        if s["state"] == "satisfied":
            assert not s["entry"].get("withheld") and not s["entry"]["findings"], (label, s)
    withheld = [label for label, s in states.items() if s["entry"].get("withheld")]
    assert withheld, "this bundle does have controls whose findings the filter withheld"
    assert all(states[label]["state"] == "not-satisfied" for label in withheld)
    assert all(states[label]["reason"] == "other" for label in withheld)


def test_the_oscal_verdict_no_longer_depends_on_the_severity_filter() -> None:
    """The point of the fix: a filter changes what you SEE, never whether an objective is met."""
    base = {k: v["state"] for k, v in _oscal_states(Severity.INFO).items()}
    for sev in (Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL):
        got = {k: v["state"] for k, v in _oscal_states(sev).items()}
        assert got == base, f"verdict changed at {sev}: {[k for k in base if base[k] != got.get(k)]}"


def _cli_states(capsys: pytest.CaptureFixture[str], *extra: str) -> dict[str, str]:
    main(["audit", "-f", str(BUNDLE), "--platform", "openshift", "--oscal", *extra])
    doc = json.loads(capsys.readouterr().out)
    findings = doc["assessment-results"]["results"][0].get("findings", [])
    assert findings
    return {f["title"].split()[0]: f["target"]["status"]["state"] for f in findings}


def test_the_cli_oscal_document_cannot_be_laundered_by_min_severity(capsys: pytest.CaptureFixture[str]) -> None:
    """It used to report ALL 28 controls satisfied for a bundle with a privileged container and a root user."""
    unfiltered = _cli_states(capsys)
    assert "not-satisfied" in unfiltered.values()
    for level in ("medium", "high", "critical"):
        filtered = _cli_states(capsys, "--min-severity", level)
        assert filtered == unfiltered, (
            f"--min-severity {level} changed the OSCAL verdict for "
            f"{[k for k in unfiltered if unfiltered[k] != filtered.get(k)]}"
        )
