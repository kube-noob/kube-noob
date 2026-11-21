"""An empty list is how GitLab's Code Quality widget spells "no issues".

So an undetermined gate wrote `[]` and the widget told the reviewer the change was clean -- the third renderer of
the same report to lose the honest half of the answer, after `audit --format sarif` (G328) and `sarif_of_gate`
(G331). Review class 21, twice removed and still one function along.

The coverage issues carry `severity: info` deliberately. The gate's exit code is what stops a pipeline; a coverage
gap raised as a blocker would be read as a false positive and the whole report would be dismissed. Saying it at
all is the point.
"""

from __future__ import annotations

import json
from typing import Any

from kube_noob import gate
from kube_noob.gate import NOT_AUDITED_RULE, NOT_EVALUATED_RULE, NOT_READ_RULE

#: A workload kind under a group the audit refuses, so the gate reaches no verdict.
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

PRIVILEGED = REFUSED.replace("apps.k8s.io/v1", "apps/v1")


def _cq(text: str, **over: Any) -> list[dict[str, Any]]:
    rep = gate.run([gate.Source("m.yaml", text)], fail_on="never")
    return gate.codequality({**rep, **over})


def _by_rule(rows: list[dict[str, Any]], rule: str) -> list[dict[str, Any]]:
    return [r for r in rows if r["check_name"] == rule]


def test_an_undetermined_gate_is_not_an_empty_report() -> None:
    """The regression. Zero issues, and GitLab says the change is clean."""
    rep = gate.run([gate.Source("m.yaml", REFUSED)], fail_on="never")
    assert rep["undetermined"], "nothing was undetermined, so this test proves nothing"
    rows = gate.codequality(rep)
    assert rows, "an empty code quality report reads as no issues"
    assert len(_by_rule(rows, NOT_AUDITED_RULE)) == 1
    assert _by_rule(rows, NOT_AUDITED_RULE)[0]["severity"] == "info"


def test_the_rules_that_reached_no_verdict_are_named() -> None:
    """Not a count alone: the ids, so a reviewer can tell which control is unevidenced from the widget."""
    rep = gate.run([gate.Source("m.yaml", PRIVILEGED)], fail_on="never")
    unevaluated = [r for r in rep["controlSummary"]["rulesNotEvaluated"] if r.get("ruleId")]
    assert len(unevaluated) > 1
    rows = _by_rule(gate.codequality(rep), NOT_EVALUATED_RULE)
    assert len(rows) == 1, "the claim is about the run, so it is one issue carrying every id"
    assert rows[0]["description"].startswith(f"{NOT_EVALUATED_RULE}: {len(unevaluated)} rules reached no verdict")
    for row in unevaluated:
        assert str(row["ruleId"]) in rows[0]["description"]


def test_the_findings_are_untouched() -> None:
    """The coverage issues are added beside the findings, never in place of one, and keep their own severities."""
    rep = gate.run([gate.Source("m.yaml", PRIVILEGED)], fail_on="never")
    rows = gate.codequality(rep)
    findings = [r for r in rows if not r["check_name"].startswith("KN-NOT-")]
    assert len(findings) == len(rep["findings"]) > 0
    assert {r["severity"] for r in findings} - {"info"}, "every finding came out as info"


def test_a_run_that_evaluated_everything_raises_no_coverage_issue() -> None:
    """An issue on every pipeline is one a reviewer mutes, and a muted report is worse than the gap it replaces."""
    rows = _cq(PRIVILEGED, controlSummary={"rulesNotEvaluated": []}, unreadable=[], skipped=[], undetermined=None)
    assert [r for r in rows if r["check_name"].startswith("KN-NOT-")] == []


def test_a_file_that_was_not_read_is_one_issue_anchored_to_that_file() -> None:
    """A reviewer fixes these file by file, so each gets its own issue at its own path -- the gate's `unreadable`
    rows key on `file` and the audit's on `path`, and both are read."""
    rows = _cq(
        PRIVILEGED,
        unreadable=[{"file": "charts/broken.yaml", "why": "while parsing a flow node (line 3)"}],
        skipped=[{"file": "k8s/pod.json", "why": "not opened by the directory walk", "forbidsVerdict": True}],
    )
    read = _by_rule(rows, NOT_READ_RULE)
    assert {r["location"]["path"] for r in read} == {"charts/broken.yaml", "k8s/pod.json"}
    assert len({r["fingerprint"] for r in read}) == 2, "two files, two tracked issues"
    assert all(r["severity"] == "info" for r in read)


def test_a_skipped_file_that_does_not_forbid_the_verdict_is_not_raised() -> None:
    """A Helm template or a file that is simply not a manifest is not a gap in the evidence: `forbidsVerdict` is
    the one marker, and reading it wrong would raise an issue for every chart in the repository."""
    rows = _cq(PRIVILEGED, skipped=[{"file": "chart/templates/deploy.yaml", "why": "a Helm template: render it"}])
    assert _by_rule(rows, NOT_READ_RULE) == []


def test_every_issue_has_the_fields_gitlab_requires() -> None:
    """GitLab drops an issue with a missing field silently, which would put this straight back where it started."""
    rows = _cq(REFUSED, unreadable=[{"file": "charts/broken.yaml", "why": "not valid UTF-8"}])
    assert rows
    for r in rows:
        assert set(r) >= {"description", "check_name", "fingerprint", "severity", "location"}
        assert r["description"] and r["check_name"] and r["fingerprint"]
        assert r["severity"] in {"blocker", "critical", "major", "minor", "info"}
        assert r["location"]["path"] and r["location"]["lines"]["begin"] >= 1


def test_the_same_report_gives_the_same_bytes() -> None:
    rep = gate.run([gate.Source("m.yaml", REFUSED)], fail_on="never")
    assert json.dumps(gate.codequality(rep), sort_keys=True) == json.dumps(gate.codequality(rep), sort_keys=True)
