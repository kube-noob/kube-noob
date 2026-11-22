"""`satisfied` is the strongest word this document says, so it has to mean the objective was evidenced.

It did not. On a report the gate itself called undetermined -- a privileged container in a `Deployment` under an
apiVersion the audit refuses -- three objectives read `satisfied/pass`: CM-3(2), CM-6 and SA-22. CM-6 said
satisfied on 7 clean rules with 26 not evaluated, a fifth of its evidence. The gap WAS stated, in the finding's
`description`, which is prose a GRC tool does not parse while it reads `status.state` (review class 6).

`not-satisfied` was the other candidate and is wrong for the same reason `satisfied` is: it asserts the objective
is not met, and partial evidence does not say that either. So such a control is EXCLUDED -- an exclusion asserts
nothing, and this document already had that mechanism for a control no rule ran over at all. G335 extends it from
no coverage to partial coverage.

The discrimination that makes it usable: a rule that did not run because its SUBJECT is absent ("no Secret in the
input") is this report's scope, not a gap in its evidence. Counting those as gaps took a clean input from 23
satisfied objectives to 1, and a compliance report that can never say satisfied is one nobody reads.
"""

from __future__ import annotations

import collections
from pathlib import Path
from typing import Any

import pytest

from kube_noob import gate, oscal

#: Absolute, because `tests/conftest.py` chdirs into a tmp_path: a relative fixture path resolves to nothing.
ROOT = Path(__file__).resolve().parent.parent

#: A workload kind under a group the audit refuses: something was here and went unread.
REFUSED = """\
apiVersion: apps.k8s.io/v1
kind: Deployment
metadata: {name: web, namespace: shop}
spec:
  template:
    spec:
      containers:
      - name: c
        image: registry.example.com/c:1
        securityContext: {privileged: true}
"""


def _result(sources: list[Any]) -> dict[str, Any]:
    rep = gate.run(sources, fail_on="never", platform="openshift", version="4.20")
    return oscal.assessment_results(rep)["assessment-results"]["results"][0]


def _states(res: dict[str, Any]) -> collections.Counter[str]:
    out: collections.Counter[str] = collections.Counter()
    for f in res.get("findings") or []:
        status = (f.get("target") or {}).get("status") or {}
        out[f"{status.get('state')}/{status.get('reason')}"] += 1
    return out


def _clean_dir() -> list[Any]:
    return gate.collect(
        [str(ROOT / "tests" / "fixtures" / "gate" / "good")], lambda q: Path(q).read_text(encoding="utf-8")
    )


def test_an_undetermined_report_claims_no_objective_satisfied() -> None:
    """The regression. CM-3(2), CM-6 and SA-22 read satisfied/pass here."""
    rep = gate.run([gate.Source("m.yaml", REFUSED)], fail_on="never")
    assert rep["undetermined"], "nothing was undetermined, so this test proves nothing"
    res = oscal.assessment_results(rep)["assessment-results"]["results"][0]
    assert _states(res)["satisfied/pass"] == 0, "an objective is satisfied in a run that reached no verdict"


def test_a_control_whose_evidence_was_not_gathered_is_excluded_not_failed() -> None:
    """Excluded, not `not-satisfied`: the evidence does not say the objective is unmet, only that it was not
    shown. An exclusion asserts nothing, which is what partial evidence supports."""
    res = _result([gate.Source("m.yaml", REFUSED)])
    assert _states(res)["not-satisfied/other"] == 0
    sel = res["reviewed-controls"]["control-selections"][0]
    excluded = {e["control-id"] for e in sel.get("exclude-controls") or []}
    assert {oscal.control_id("CM-6"), oscal.control_id("CM-3(2)"), oscal.control_id("SA-22")} <= excluded


def test_the_excluded_partial_controls_are_named_with_their_counts() -> None:
    """An assessor querying this document will ask about exactly this group: these controls DID have rules run
    clean, and before G335 they read satisfied on that alone."""
    res = _result([gate.Source("m.yaml", REFUSED)])
    remarks = res["reviewed-controls"]["control-selections"][0].get("remarks") or ""
    assert "had rules run clean and others reach no verdict" in remarks
    # The counts come from the report, not from this test's arithmetic: CM-6 is the clearest case, six rules
    # clean against twenty-seven that reached no verdict.
    assert "CM-6 (6 clean, 27 not evaluated)" in remarks
    assert "CM-3(2) (7 clean, 9 not evaluated)" in remarks


def test_a_rule_whose_subject_is_absent_is_scope_and_not_a_gap() -> None:
    """The discrimination this rests on, and the reason `satisfied` is still reachable.

    Every reason on a clean manifest bundle reads "no Secret in the input", "no networking.k8s.io Ingress in the
    input". Nothing of that kind was here to audit. Counting those as evidence gaps left 1 satisfied objective of
    23, and a report that can never say satisfied is one nobody reads.
    """
    res = _result(_clean_dir())
    assert _states(res)["satisfied/pass"] > 10, "treating an absent subject as a gap makes satisfied unreachable"


def test_a_finding_is_still_reported_however_many_rules_went_unread() -> None:
    """A gap elsewhere does not withdraw something that was found. A control with a finding, a withheld rule or
    an accepted exception is never excluded."""
    res = _result(
        gate.collect([str(ROOT / "tests" / "fixtures" / "gate" / "bad")], lambda q: Path(q).read_text(encoding="utf-8"))
    )
    assert _states(res)["not-satisfied/fail"] > 0
    sel = res["reviewed-controls"]["control-selections"][0]
    assert sel.get("include-controls"), "the failing controls were excluded"


def test_the_coverage_behind_an_objective_is_machine_readable() -> None:
    """The counts were in the description, which is prose. A GRC tool reads props: the same class-6 gap
    `status.state` had, one field over."""
    res = _result(
        gate.collect([str(ROOT / "tests" / "fixtures" / "gate" / "bad")], lambda q: Path(q).read_text(encoding="utf-8"))
    )
    assert res.get("findings")
    for f in res["findings"]:
        names = {p["name"]: p["value"] for p in f.get("props") or []}
        assert "rules-clean" in names and "rules-not-evaluated" in names, f["title"]
        assert all(v.isdigit() for v in names.values()), names
        assert all(p["ns"] == oscal.PROP_NS for p in f["props"])


def test_a_rule_with_no_recorded_reason_counts_as_a_gap() -> None:
    """`notEvaluatedRules` is truncated at a limit with the remainder in `moreNotEvaluated`. An unknown reason
    must not read as a pass, which is the rule this whole product applies."""
    reasons = {"KN-X001": "no Secret in the input"}
    absent_only = {"id": "AC-1", "clean": 2, "notEvaluatedRules": ["KN-X001"]}
    assert oscal._evidence_gaps(absent_only, reasons) == []
    truncated = {**absent_only, "moreNotEvaluated": 3}
    assert oscal._evidence_gaps(truncated, reasons), "an unseen reason was treated as no gap"
    assert oscal._partly_evidenced(truncated, reasons)


def test_an_unread_object_is_a_gap_but_an_absent_kind_is_not() -> None:
    reasons = {"KN-A": "no Secret in the input", "KN-B": "Deployment/shop/web was not read in full"}
    assert oscal._evidence_gaps({"clean": 1, "notEvaluatedRules": ["KN-A"]}, reasons) == []
    assert oscal._evidence_gaps({"clean": 1, "notEvaluatedRules": ["KN-A", "KN-B"]}, reasons) == ["KN-B"]


@pytest.mark.parametrize("key", ["findings", "excepted", "withheld"])
def test_something_found_is_never_excluded_by_a_gap(key: str) -> None:
    reasons = {"KN-B": "Deployment/shop/web was not read in full"}
    row = {"id": "AC-1", "clean": 1, key: 1, "notEvaluatedRules": ["KN-B"]}
    assert not oscal._partly_evidenced(row, reasons)
