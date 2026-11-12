"""`audit --format sarif`, with the NIST controls on the rules and the run's blind spots in the document (G269).

SARIF is a list of results, and a list of results has one way to say "nothing found": be empty. An audit that could
not read a file, or that was told it was looking at part of a namespace and so declined its cross-object rules,
produces a shorter list and nothing else -- and a consumer reading only results cannot tell that from a clean
cluster. The format has a place for it (`invocations[].toolExecutionNotifications`), so the audit's own caveats
travel with the findings instead of staying behind in the report the SARIF replaced.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from kube_noob.audit.controls import RULE_CONTROLS
from kube_noob.cli import main

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / "examples" / "insecure-deployment.yaml"
SCHEMA = ROOT / "tests" / "fixtures" / "sarif" / "sarif-schema-2.1.0.json"
VALIDATOR = ROOT / "scripts" / "json_schema_validate.mjs"
ARGS = ["--platform", "openshift", "--version", "4.22"]
POD = "apiVersion: v1\nkind: Pod\nmetadata: {name: p, namespace: a}\nspec:\n  containers: [{name: c, image: nginx}]\n"


def _run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str]:
    code = main(list(argv))
    return code, capsys.readouterr().out


def _sarif(capsys: pytest.CaptureFixture[str], path: Path = BUNDLE) -> tuple[int, dict[str, Any]]:
    code, out = _run(capsys, "audit", "-f", str(path), *ARGS, "--format", "sarif")
    return code, json.loads(out)


def test_the_audit_writes_one_sarif_document_and_nothing_else(capsys: pytest.CaptureFixture[str]) -> None:
    _, doc = _sarif(capsys)
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["tool"]["driver"]["name"] == "kube-noob"


def test_every_finding_in_the_report_is_a_result(capsys: pytest.CaptureFixture[str]) -> None:
    _, out = _run(capsys, "audit", "-f", str(BUNDLE), *ARGS, "--format", "json")
    report = json.loads(out)
    _, doc = _sarif(capsys)
    results = doc["runs"][0]["results"]
    assert len(results) == len(report["findings"]) > 0
    assert [r["ruleId"] for r in results] == [f["ruleId"] for f in report["findings"]]
    assert all(r["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1 for r in results)


def test_the_exit_code_is_the_same_as_without_the_flag(capsys: pytest.CaptureFixture[str]) -> None:
    plain, _ = _run(capsys, "audit", "-f", str(BUNDLE), *ARGS, "--format", "json")
    code, _ = _sarif(capsys)
    assert code == plain == 1


def test_each_rule_carries_the_controls_the_catalogue_maps_it_to(capsys: pytest.CaptureFixture[str]) -> None:
    _, doc = _sarif(capsys)
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    mapped = [r for r in rules if RULE_CONTROLS.get(r["id"])]
    assert mapped, "the insecure example fires rules that have controls; without them this proves nothing"
    for rule in mapped:
        want = list(RULE_CONTROLS[rule["id"]])
        assert rule["properties"]["nist-800-53"] == want, rule["id"]
        for control in want:
            assert f"NIST-800-53/{control}" in rule["properties"]["tags"], (rule["id"], control)


def test_a_rule_with_no_mapped_control_claims_none(capsys: pytest.CaptureFixture[str]) -> None:
    """An empty list would read as "checked, maps to nothing"; the property is absent instead."""
    _, doc = _sarif(capsys)
    for rule in doc["runs"][0]["tool"]["driver"]["rules"]:
        if not RULE_CONTROLS.get(rule["id"]):
            assert "nist-800-53" not in rule["properties"], rule["id"]


def test_what_a_partial_audit_did_not_evaluate_is_in_the_document(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """One Pod from a namespace: the cross-object rules decline. Results alone would read as a short clean list."""
    pod = tmp_path / "pod.yaml"
    pod.write_text(POD, encoding="utf-8")
    _, out = _run(capsys, "audit", "-f", str(pod), *ARGS, "--format", "json", "--fail-on", "never")
    report = json.loads(out)
    assumptions = report["assumptions"]
    assert assumptions, "this input is expected to make the audit record an assumption"
    _, out = _run(capsys, "audit", "-f", str(pod), *ARGS, "--format", "sarif", "--fail-on", "never")
    invocation = json.loads(out)["runs"][0]["invocations"][0]
    notes = [n["message"]["text"] for n in invocation["toolExecutionNotifications"]]
    # The assumptions first, then the coverage record's reasons, one notification per reason group (G281):
    # the rules that never ran because their kind was not in the file are in the document, not only in JSON.
    from kube_noob.audit.controls import grouped_reasons

    expected = [f"not evaluated, {why}: {', '.join(ids)}" for why, ids in grouped_reasons(report["controlSummary"])]
    assert expected, "a one-Pod file leaves rules without a subject"
    assert notes == assumptions + expected
    assert any(n.startswith("not evaluated, no Service in the input: ") for n in notes)
    assert all(n["level"] == "warning" for n in invocation["toolExecutionNotifications"])
    assert invocation["executionSuccessful"] is True


def test_a_file_the_audit_could_not_read_is_in_the_document() -> None:
    from kube_noob import gate

    doc = gate.sarif_of_audit(
        {"findings": [], "assumptions": [], "unreadable": [{"path": "k8s/broken.yaml", "why": "not valid YAML"}]}
    )
    notes = doc["runs"][0]["invocations"][0]["toolExecutionNotifications"]
    assert [n["message"]["text"] for n in notes] == ["not read: k8s/broken.yaml (not valid YAML)"]
    assert notes[0]["level"] == "error"


def test_the_gate_carries_the_controls_too(tmp_path: Path) -> None:
    out = tmp_path / "gate.sarif.json"
    main(["gate", "-f", str(BUNDLE), *ARGS, "--sarif", str(out), "--quiet"])
    rules = json.loads(out.read_text(encoding="utf-8"))["runs"][0]["tool"]["driver"]["rules"]
    mapped = [r for r in rules if RULE_CONTROLS.get(r["id"])]
    assert mapped and all(r["properties"]["nist-800-53"] == list(RULE_CONTROLS[r["id"]]) for r in mapped)


def test_sarif_is_refused_for_a_command_that_has_no_findings_to_put_in_it(capsys: pytest.CaptureFixture[str]) -> None:
    """`--format` is shared by every command. A search result printed as YAML under `--format sarif` would be a
    file named .sarif that is not SARIF."""
    code = main(["search", "route 503", "--format", "sarif"])
    captured = capsys.readouterr()
    assert code == 2
    assert captured.out == ""
    assert "sarif" in captured.err and "audit" in captured.err


def test_oscal_and_sarif_together_are_refused_rather_than_guessed(capsys: pytest.CaptureFixture[str]) -> None:
    """Each flag replaces the report with one document. Both at once used to mean OSCAL printed as YAML."""
    code = main(["audit", "-f", str(BUNDLE), *ARGS, "--format", "sarif", "--oscal"])
    captured = capsys.readouterr()
    assert code == 2 and captured.out == ""
    assert "one document" in captured.err


def test_the_document_validates_against_the_oasis_schema(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    node = shutil.which("node")
    probe = node and subprocess.run(
        [
            node,
            "-e",
            "Promise.all([import('ajv'),import('ajv-draft-04'),import('ajv-formats')]).then(()=>process.exit(0),()=>process.exit(1))",
        ],
        capture_output=True,
        check=False,
        cwd=ROOT,
    )
    if not node or not probe or probe.returncode != 0:
        pytest.skip("ajv is not installed: npm install --no-save ajv@8.17.1 ajv-formats@3.0.1 ajv-draft-04@1.0.0")
    for name, text in (("full", BUNDLE.read_text(encoding="utf-8")), ("partial", POD)):
        src = tmp_path / f"{name}.yaml"
        src.write_text(text, encoding="utf-8")
        _, out = _run(capsys, "audit", "-f", str(src), *ARGS, "--format", "sarif", "--fail-on", "never")
        doc = tmp_path / f"{name}.sarif.json"
        doc.write_text(out, encoding="utf-8")
        done = subprocess.run(
            [node, str(VALIDATOR), str(SCHEMA), str(doc)], capture_output=True, text=True, check=False, cwd=ROOT
        )
        assert done.returncode == 0, name + ": " + done.stdout + done.stderr
