"""What the audit did not evaluate has to reach `runs[].results`, not only the invocation's notifications.

`toolExecutionNotifications` is where SARIF puts what a tool says about its own run, and it is not what the
consumers this file is written for read: GitHub code scanning shows alerts from `results`, and DefectDojo and the
scanner operators import findings from `results`. So an audit that emitted twelve findings and "fifty-five rules
reached no verdict" only as a notification arrived at the other end as twelve findings and nothing else -- the
honest half of the answer destroyed at the first hop, which is this product's own defect one layer out from the
verdict.

`sarif_of_gate` already fixed this for the gate (G272, seventh review: "as a property of the invocation AND one
note-level result, so a consumer that reads only results sees it") and `_not_audited_results` already fixed it for
objects no rule read. `sarif_of_audit`'s unevaluated RULES were the neighbour nobody fixed -- review class 21.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from kube_noob.gate import NOT_EVALUATED_RULE, NOT_READ_RULE, sarif_of_audit
from kube_noob.toolkit import Toolkit

SCHEMA = Path(__file__).parent / "fixtures" / "sarif" / "sarif-schema-2.1.0.json"

PRIVILEGED = """
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: prod}
spec:
  replicas: 1
  selector: {matchLabels: {app: web}}
  template:
    metadata: {labels: {app: web}}
    spec:
      containers:
      - name: web
        image: nginx:1.27
        securityContext: {privileged: true}
"""


def _audit(kit: Toolkit, text: str) -> dict[str, Any]:
    import kube_noob.toolkit as tk

    return dict(kit.audit(tk.AuditIn(manifests=text)))


def _review(doc: dict[str, Any], rule: str) -> list[dict[str, Any]]:
    return [r for r in doc["runs"][0]["results"] if r["ruleId"] == rule]


def test_the_rules_that_reached_no_verdict_are_a_result_and_not_only_a_notification(settings: Any) -> None:
    """The regression. A Deployment on its own leaves most of the catalogue unevaluated."""
    rep = _audit(Toolkit(settings), PRIVILEGED)
    assert rep["controlSummary"]["rulesNotEvaluated"], "nothing was unevaluated, so this test proves nothing"
    doc = sarif_of_audit(rep)

    rows = _review(doc, NOT_EVALUATED_RULE)
    assert len(rows) == 1, "the claim is about the run, so it is one alert carrying every reason"
    assert rows[0]["kind"] == "review", "SARIF's word for 'a reviewer should look, this is not a defect'"
    # Findings are still findings: the coverage result does not displace or dilute them.
    assert [r for r in doc["runs"][0]["results"] if r.get("kind", "fail") == "fail"], "the findings went missing"


def test_the_count_in_the_result_is_the_count_in_the_json(settings: Any) -> None:
    """Review class 9, the defect G281 was: a renderer that states its own number can disagree with the report's.

    The SARIF result is a renderer like any other, so it reads the one list and states its length.
    """
    rep = _audit(Toolkit(settings), PRIVILEGED)
    expected = len([r for r in rep["controlSummary"]["rulesNotEvaluated"] if r.get("ruleId")])
    assert expected > 1
    text = _review(sarif_of_audit(rep), NOT_EVALUATED_RULE)[0]["message"]["text"]
    assert text.startswith(f"{expected} rules reached no verdict")


def test_every_unevaluated_rule_id_is_named_in_the_result(settings: Any) -> None:
    """Not a count alone: the ids, so a reviewer can tell which control is unevidenced without the JSON."""
    rep = _audit(Toolkit(settings), PRIVILEGED)
    text = _review(sarif_of_audit(rep), NOT_EVALUATED_RULE)[0]["message"]["text"]
    for row in rep["controlSummary"]["rulesNotEvaluated"]:
        if row.get("ruleId"):
            assert str(row["ruleId"]) in text, f"{row['ruleId']} was not evaluated and the result does not name it"


def test_an_input_that_leaves_nothing_unevaluated_raises_no_coverage_alert(settings: Any) -> None:
    """The other direction. A coverage alert on every run is an alert a reviewer mutes, and a muted rule is a
    worse outcome than the notification this replaced."""
    rep = _audit(Toolkit(settings), PRIVILEGED)
    rep["controlSummary"] = {**rep["controlSummary"], "rulesNotEvaluated": []}
    rep["unreadable"] = []
    doc = sarif_of_audit(rep)
    assert _review(doc, NOT_EVALUATED_RULE) == []
    assert _review(doc, NOT_READ_RULE) == []
    # And the rule itself is not declared, so the tool does not advertise a check it did not report.
    declared = {r["id"] for r in doc["runs"][0]["tool"]["driver"].get("rules") or []}
    assert NOT_EVALUATED_RULE not in declared and NOT_READ_RULE not in declared


def test_a_file_that_was_not_read_is_one_result_per_file_with_its_own_location(settings: Any) -> None:
    """Unlike the unevaluated rules, this one IS about a place: a reviewer fixes it file by file, so it is one
    alert each, anchored to the file, and the fingerprint keeps them apart."""
    rep = _audit(Toolkit(settings), PRIVILEGED)
    rep["unreadable"] = [
        {"path": "charts/broken.yaml", "why": "while parsing a flow node (line 3)"},
        {"path": "charts/other.yaml", "why": "not valid UTF-8"},
    ]
    rows = _review(sarif_of_audit(rep), NOT_READ_RULE)
    assert len(rows) == 2
    assert {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in rows} == {
        "charts/broken.yaml",
        "charts/other.yaml",
    }
    assert len({r["partialFingerprints"]["kubeNoob/v1"] for r in rows}) == 2, "two files, two tracked alerts"
    assert all(r["kind"] == "review" for r in rows)


def test_the_notifications_are_still_there_so_neither_kind_of_consumer_loses_it(settings: Any) -> None:
    """Both channels, deliberately. A reader of the invocation keeps what it had; a reader of `results` gains it.
    Saying it twice is the better failure of the two."""
    rep = _audit(Toolkit(settings), PRIVILEGED)
    doc = sarif_of_audit(rep)
    notes = doc["runs"][0]["invocations"][0]["toolExecutionNotifications"]
    assert any("not evaluated" in n["message"]["text"] for n in notes)
    assert _review(doc, NOT_EVALUATED_RULE)


def test_the_document_is_valid_sarif(settings: Any) -> None:
    rep = _audit(Toolkit(settings), PRIVILEGED)
    rep["unreadable"] = [{"path": "charts/broken.yaml", "why": "while parsing a flow node (line 3)"}]
    jsonschema.validate(sarif_of_audit(rep), json.loads(SCHEMA.read_text(encoding="utf-8")))


def test_the_same_report_gives_the_same_bytes(settings: Any) -> None:
    """Determinism: the groups are ordered by `grouped_reasons`, and the fingerprint is over the ordered text, so
    an alert does not churn between runs on identical input."""
    rep = _audit(Toolkit(settings), PRIVILEGED)
    first = json.dumps(sarif_of_audit(rep), sort_keys=True)
    second = json.dumps(sarif_of_audit(rep), sort_keys=True)
    assert first == second


@pytest.mark.parametrize("rule", [NOT_EVALUATED_RULE, NOT_READ_RULE])
def test_the_coverage_rules_say_what_to_do_and_never_that_it_passed(settings: Any, rule: str) -> None:
    """A note-level alert with no remedy is an alert that gets dismissed. Each one says how to close the gap, and
    says in words that it is not a pass -- because the whole point is that a reader not conclude otherwise."""
    rep = _audit(Toolkit(settings), PRIVILEGED)
    rep["unreadable"] = [{"path": "charts/broken.yaml", "why": "while parsing a flow node (line 3)"}]
    declared = {r["id"]: r for r in sarif_of_audit(rep)["runs"][0]["tool"]["driver"]["rules"]}
    assert rule in declared
    text = (declared[rule]["help"]["text"] + declared[rule]["fullDescription"]["text"]).lower()
    assert "not" in text and ("pass" in text or "clean" in text or "audited" in text)
    assert declared[rule]["helpUri"]
