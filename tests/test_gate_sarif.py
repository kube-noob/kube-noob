"""`gate --sarif` against the schema it names, rather than against nothing at all (G268).

The gate has always written `"$schema": "https://json.schemastore.org/sarif-2.1.0.json"` into every SARIF file it
produces, and nothing has ever read that schema. The one artifact kube-noob hands to GitHub code scanning named a
contract it never checked itself against -- in a tool whose argument is that it works with no network. The document
turns out to be valid, which is the good case and not the point: it was valid by luck, and the next field added to
it would have been checked by whoever consumed it, in their pipeline, not here.

The schema is vendored from OASIS, the technical committee that owns SARIF, rather than from schemastore: a build
with no general network cannot reach schemastore, and schemastore republishes rather than publishes. The URI in the
output stays as it is, because code-scanning consumers recognise it and changing a published contract to match a
test would be the wrong way round.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from kube_noob.cli import main

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / "examples" / "insecure-deployment.yaml"
FIX = ROOT / "tests" / "fixtures" / "sarif"
SCHEMA = FIX / "sarif-schema-2.1.0.json"
VALIDATOR = ROOT / "scripts" / "json_schema_validate.mjs"
NPM = "npm install --no-save ajv@8.17.1 ajv-formats@3.0.1 ajv-draft-04@1.0.0"


def _ajv() -> str | None:
    node = shutil.which("node")
    if node is None:
        return None
    probe = subprocess.run(
        [
            node,
            "-e",
            "Promise.all([import('ajv'),import('ajv-draft-04'),import('ajv-formats')]).then(()=>process.exit(0),()=>process.exit(1))",
        ],
        capture_output=True,
        check=False,
        cwd=ROOT,
    )
    return node if probe.returncode == 0 else None


def _validate(node: str, document: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [node, str(VALIDATOR), str(SCHEMA), str(document)],
        capture_output=True,
        text=True,
        check=False,
        cwd=ROOT,
    )


def _gate_sarif(tmp_path: Path) -> Path:
    out = tmp_path / "gate.sarif.json"
    code = main(
        ["gate", "-f", str(BUNDLE), "--platform", "openshift", "--version", "4.22", "--sarif", str(out), "--quiet"]
    )
    assert code == 1, f"the insecure example should fail the gate; exit was {code}"
    assert out.is_file(), "the gate was asked for SARIF and wrote none"
    return out


# -- the vendored schema ----------------------------------------------------------------------------------------


def test_the_schema_is_vendored_with_its_provenance() -> None:
    assert SCHEMA.is_file(), "run: python scripts/vendor_schemas.py --sarif"
    prov = json.loads((FIX / "PROVENANCE.json").read_text(encoding="utf-8"))
    entry = next(f for f in prov["files"] if f["file"] == SCHEMA.name)
    assert entry["source"].startswith("https://raw.githubusercontent.com/oasis-tcs/sarif-spec/")
    assert len(entry["sha256Upstream"]) == 64


def test_the_schema_is_the_draft_the_validator_branches_on() -> None:
    """ajv 8 refuses draft-04's `id` keyword outright, so the dialect decides which compiler runs. A re-vendor
    that changed dialect would otherwise be validated under the wrong one, silently."""
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    assert "draft-04" in schema["$schema"], "json_schema_validate.mjs picks ajv-draft-04 on this string"
    assert "id" in schema, "the draft-04 keyword that ajv 8 will not compile"
    assert "sarif" in schema["title"].lower() and "2.1.0" in json.dumps(schema["properties"]["version"])


# -- the gate's output ------------------------------------------------------------------------------------------


def test_the_gate_writes_sarif_that_validates_against_the_oasis_schema(tmp_path: Path) -> None:
    node = _ajv()
    if node is None:
        pytest.skip(f"ajv is not installed: {NPM}")
    done = _validate(node, _gate_sarif(tmp_path))
    assert done.returncode == 0, done.stdout + done.stderr
    assert "VALID" in done.stdout


def test_the_validator_refuses_a_document_the_schema_does_not_allow(tmp_path: Path) -> None:
    """Without this the check above passes when ajv compiles the schema to nothing and waves everything through,
    which is the shape of failure this project exists to refuse, aimed at its own gate."""
    node = _ajv()
    if node is None:
        pytest.skip(f"ajv is not installed: {NPM}")
    doc = json.loads(_gate_sarif(tmp_path).read_text(encoding="utf-8"))
    assert doc["runs"][0]["results"], "the insecure example has findings; without them this proves nothing"
    doc["runs"][0]["results"][0]["level"] = "severe"
    broken = tmp_path / "broken.sarif.json"
    broken.write_text(json.dumps(doc), encoding="utf-8")
    done = _validate(node, broken)
    assert done.returncode == 1, done.stdout + done.stderr
    assert "INVALID" in done.stdout
    assert "level" in done.stdout


def test_the_output_names_the_schema_it_was_checked_against(tmp_path: Path) -> None:
    """Two URIs for one document: the output names schemastore, which consumers recognise, and the test reads the
    OASIS copy, which a build with no general network can fetch. If they ever diverge this is where it shows."""
    doc = json.loads(_gate_sarif(tmp_path).read_text(encoding="utf-8"))
    assert doc["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    assert doc["version"] == "2.1.0"
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    assert doc["version"] in json.dumps(schema["properties"]["version"]), (
        "the vendored schema does not describe the version the gate writes"
    )
