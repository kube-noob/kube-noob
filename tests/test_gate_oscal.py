"""`gate --oscal`: the same document from the CI gate, with the gate's own coverage record (G201).

The gate already runs `analyze`, so it has the coverage record; it just never published it. Without it the
emitter's honest degradation reported only controls with findings and nothing as satisfied, which is a weaker
document than the same input gives through `audit`.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from kube_noob.cli import main

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / "examples" / "insecure-deployment.yaml"
SCHEMA = ROOT / "tests" / "fixtures" / "oscal" / "oscal_assessment-results_schema.json"


def _gate_json(capsys: pytest.CaptureFixture[str], *extra: str) -> dict[str, Any]:
    main(["--format", "json", "gate", "-f", str(BUNDLE), "--platform", "openshift", "--version", "4.22", *extra])
    return json.loads(capsys.readouterr().out)


def test_the_gate_report_carries_the_coverage_record(capsys: pytest.CaptureFixture[str]) -> None:
    rep = _gate_json(capsys)
    controls = {c["id"]: c for c in rep["controlSummary"]["controls"]}
    assert controls, "the gate audits manifests, so it can say which controls it covered"
    assert all("clean" in c and "notEvaluated" in c and "withheld" in c for c in controls.values())
    assert rep["kubernetesVersion"] and rep["resources"]


def test_the_gate_and_the_audit_agree_when_given_the_same_scope(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Two commands over one COMPLETE bundle must not disagree about what was checked.

    They are compared on a directory on purpose. `gate -f rendered.yaml` is documented as the whole rendered
    namespace and treats it as complete, while `audit -f one-file.yaml` is a partial bundle by design (G186)
    and withholds the rules that read other objects -- a real difference in what each was told, not a
    disagreement about the same input.
    """
    folder = tmp_path / "k8s"
    folder.mkdir()
    (folder / "app.yaml").write_text(BUNDLE.read_text(encoding="utf-8"), encoding="utf-8")
    keys = ("findings", "clean", "withheld", "notEvaluated")

    def buckets(cmd: str) -> dict[str, tuple[int, ...]]:
        main(["--format", "json", cmd, "-f", str(folder), "--platform", "openshift", "--version", "4.22"])
        out = json.loads(capsys.readouterr().out)
        return {c["id"]: tuple(c[k] for k in keys) for c in out["controlSummary"]["controls"]}

    assert buckets("gate") == buckets("audit")


def test_gate_oscal_emits_a_document_and_keeps_the_exit_code(capsys: pytest.CaptureFixture[str]) -> None:
    plain = main(["gate", "-f", str(BUNDLE), "--platform", "openshift", "--version", "4.22"])
    capsys.readouterr()
    with_flag = main(["gate", "-f", str(BUNDLE), "--platform", "openshift", "--version", "4.22", "--oscal"])
    out = capsys.readouterr().out
    assert plain == with_flag == 1, "a gate must read the same verdict with the flag as without"
    doc = json.loads(out)
    assert "assessment-results" in doc
    assert "kube-noob gate" not in out, "the document replaces the markdown summary"


def test_gate_oscal_reports_controls_satisfied_where_the_gate_checked_them(
    capsys: pytest.CaptureFixture[str],
) -> None:
    main(["gate", "-f", str(BUNDLE), "--platform", "openshift", "--version", "4.22", "--oscal"])
    findings = json.loads(capsys.readouterr().out)["assessment-results"]["results"][0]["findings"]
    states = {f["target"]["status"]["state"] for f in findings}
    assert states == {"satisfied", "not-satisfied"}, (
        "without the coverage record the gate could only ever say not-satisfied"
    )


def test_a_gate_finding_outside_the_rule_catalogue_is_declared(capsys: pytest.CaptureFixture[str]) -> None:
    """The gate also reports Containerfile and vulnerability findings, which map to no 800-53 control here."""
    main(["gate", "-f", str(BUNDLE), "--platform", "openshift", "--version", "4.22", "--oscal"])
    doc = json.loads(capsys.readouterr().out)
    result = doc["assessment-results"]["results"][0]
    uncontrolled = [o for o in result["observations"] if not any(p["name"] == "rule-id" for p in o["props"])]
    assert uncontrolled == [], "every observation names its rule"


def test_gate_oscal_refuses_a_bad_import_ap(capsys: pytest.CaptureFixture[str]) -> None:
    """`main` turns a ConfigError into an exit code and a message, so assert both, not the exception."""
    code = main(
        [
            "gate",
            "-f",
            str(BUNDLE),
            "--platform",
            "openshift",
            "--version",
            "4.22",
            "--oscal",
            "--oscal-import-ap",
            "ap plan.json",
        ]
    )
    captured = capsys.readouterr()
    assert code not in {0, 1}, "a refused flag is a usage error, not a gate failure"
    assert "not a URI reference" in captured.err
    assert "assessment-results" not in captured.out, "no document is emitted around a bad reference"


def test_the_gate_document_validates_against_nists_schema(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed")
    probe = subprocess.run(
        [node, "-e", "import('ajv').then(()=>process.exit(0),()=>process.exit(1))"],
        capture_output=True,
        check=False,
        cwd=ROOT,
    )
    if probe.returncode != 0:
        pytest.skip("ajv is not installed: npm install --no-save ajv@8.17.1 ajv-formats@3.0.1 ajv-draft-04@1.0.0")
    main(["gate", "-f", str(BUNDLE), "--platform", "openshift", "--version", "4.22", "--oscal"])
    out = tmp_path / "gate.json"
    out.write_text(capsys.readouterr().out, encoding="utf-8")
    done = subprocess.run(
        [node, str(ROOT / "scripts" / "json_schema_validate.mjs"), str(SCHEMA), str(out)],
        capture_output=True,
        text=True,
        check=False,
        cwd=ROOT,
    )
    assert done.returncode == 0, done.stdout + done.stderr
