"""`gate --sarif` is the file the GitHub Action uploads, so it decides what a reviewer actually sees.

G328 gave `audit --format sarif` a coverage result: the rules that reached no verdict, in `runs[].results`, where
code scanning raises alerts and DefectDojo imports findings. `sarif_of_gate` was not changed, so the uploaded file
carried fourteen findings and nothing else for a report whose own `controlSummary` said fifty-two rules reached no
verdict -- and, for an input made only of kinds no rule reads, zero results of any sort. An empty SARIF run is
read as a clean scan; it is the plainest form of this product's own defect.

That the lesson was recorded in the same module and not carried one function along is review class 21 exactly.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

import jsonschema

from kube_noob import gate
from kube_noob.gate import NOT_EVALUATED_RULE, NOT_READ_RULE

SCHEMA = Path(__file__).parent / "fixtures" / "sarif" / "sarif-schema-2.1.0.json"

PRIVILEGED = """\
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
        image: registry.example.com/web:1
        securityContext: {privileged: true}
"""

#: A kind no rule reads. The gate calls this a pass, which is the separate product question; what this file holds
#: is that the uploaded SARIF does not say so with an empty list of results.
ONLY_A_CRD = """\
apiVersion: fleet.acme.io/v1
kind: WidgetFleet
metadata: {name: fleet, namespace: prod}
spec:
  runtime: {privileged: true}
"""


def _doc(text: str, uri: str = "manifests.yaml") -> dict[str, Any]:
    return gate.sarif_of_gate(gate.run([gate.Source(uri, text)], fail_on="never"))


def _ids(doc: dict[str, Any]) -> Counter[str]:
    return Counter(r["ruleId"] for r in doc["runs"][0]["results"])


def test_the_uploaded_file_says_what_the_run_did_not_evaluate() -> None:
    """The regression. Fourteen findings, and fifty-odd rules unevaluated nowhere in `results`."""
    rep = gate.run([gate.Source("manifests.yaml", PRIVILEGED)], fail_on="never")
    unevaluated = [r for r in rep["controlSummary"]["rulesNotEvaluated"] if r.get("ruleId")]
    assert len(unevaluated) > 1, "nothing was unevaluated, so this test proves nothing"

    doc = gate.sarif_of_gate(rep)
    rows = [r for r in doc["runs"][0]["results"] if r["ruleId"] == NOT_EVALUATED_RULE]
    assert len(rows) == 1, "the claim is about the run, so it is one alert carrying every reason"
    assert rows[0]["kind"] == "review"
    assert rows[0]["message"]["text"].startswith(f"{len(unevaluated)} rules reached no verdict")
    # The findings are untouched: the coverage alert is added beside them, never in place of one.
    assert len([r for r in doc["runs"][0]["results"] if r.get("kind", "fail") == "fail"]) == len(rep["findings"])


def test_an_input_of_kinds_no_rule_reads_is_not_an_empty_run() -> None:
    """Zero results is how SARIF spells "nothing found". For this input nothing was looked for."""
    doc = _doc(ONLY_A_CRD)
    assert doc["runs"][0]["results"], "an empty run reads as a clean scan"
    assert _ids(doc)[NOT_EVALUATED_RULE] == 1


def test_the_gate_and_the_audit_agree_on_the_coverage_they_report() -> None:
    """Class 9. Two renderers of one report, and the number each states has to come from the same list."""
    rep = gate.run([gate.Source("manifests.yaml", PRIVILEGED)], fail_on="never")
    of_gate = [r for r in gate.sarif_of_gate(rep)["runs"][0]["results"] if r["ruleId"] == NOT_EVALUATED_RULE]
    of_audit = [r for r in gate.sarif_of_audit(rep)["runs"][0]["results"] if r["ruleId"] == NOT_EVALUATED_RULE]
    assert len(of_gate) == len(of_audit) == 1
    assert of_gate[0]["message"]["text"] == of_audit[0]["message"]["text"]


def test_a_file_the_walk_would_not_read_as_a_manifest_is_a_result(tmp_path: Path) -> None:
    """G325's absence, through G328's channel: nothing in that file was audited, so a clean run over the rest of
    the input says nothing about it, and `results` is where a consumer learns that."""
    rep = gate.run([gate.Source("manifests.yaml", PRIVILEGED)], fail_on="never")
    rep = {
        **rep,
        "skipped": [{"file": "charts/values.yaml", "why": "no apiVersion or kind", "forbidsVerdict": True}],
    }
    rows = [r for r in gate.sarif_of_gate(rep)["runs"][0]["results"] if r["ruleId"] == NOT_READ_RULE]
    assert len(rows) == 1
    assert rows[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "charts/values.yaml"
    assert "not read as a manifest" in rows[0]["message"]["text"]


def test_an_unreadable_file_keyed_on_file_rather_than_path_still_anchors(tmp_path: Path) -> None:
    """The gate's `unreadable` rows carry `file`; the audit's carry `path`. Read with the wrong key the result
    would exist with no location, and a code-scanning alert with no location is shown against the repository root
    or not at all."""
    rep = gate.run([gate.Source("manifests.yaml", PRIVILEGED)], fail_on="never")
    rep = {**rep, "unreadable": [{"file": "charts/broken.yaml", "why": "while parsing a flow node (line 3)"}]}
    rows = [r for r in gate.sarif_of_gate(rep)["runs"][0]["results"] if r["ruleId"] == NOT_READ_RULE]
    assert len(rows) == 1
    assert rows[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "charts/broken.yaml"


def test_a_run_that_evaluated_everything_raises_no_coverage_alert() -> None:
    """The other direction. An alert on every run is an alert a reviewer mutes."""
    rep = gate.run([gate.Source("manifests.yaml", PRIVILEGED)], fail_on="never")
    rep = {**rep, "controlSummary": {**rep["controlSummary"], "rulesNotEvaluated": []}, "unreadable": []}
    doc = gate.sarif_of_gate(rep)
    assert _ids(doc)[NOT_EVALUATED_RULE] == 0 and _ids(doc)[NOT_READ_RULE] == 0
    declared = {r["id"] for r in doc["runs"][0]["tool"]["driver"].get("rules") or []}
    assert NOT_EVALUATED_RULE not in declared and NOT_READ_RULE not in declared


def test_the_undetermined_result_is_still_there() -> None:
    """G272's result is not displaced by this one: they answer different questions, and both stay."""
    doc = gate.sarif_of_gate(
        gate.run(
            [gate.Source("manifests.yaml", PRIVILEGED.replace("apiVersion: apps/v1", "apiVersion: apps.k8s.io/v1"))],
            fail_on="never",
        )
    )
    assert _ids(doc)["kube-noob/undetermined"] == 1
    assert _ids(doc)[NOT_EVALUATED_RULE] == 1


def test_the_document_is_valid_sarif_and_stable() -> None:
    rep = gate.run([gate.Source("manifests.yaml", PRIVILEGED)], fail_on="never")
    rep = {**rep, "unreadable": [{"file": "charts/broken.yaml", "why": "not valid UTF-8"}]}
    doc = gate.sarif_of_gate(rep)
    jsonschema.validate(doc, json.loads(SCHEMA.read_text(encoding="utf-8")))
    assert json.dumps(doc, sort_keys=True) == json.dumps(gate.sarif_of_gate(rep), sort_keys=True)
