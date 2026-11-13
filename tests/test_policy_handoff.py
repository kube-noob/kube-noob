"""The handoff paragraph on the gate and admission pages is held by the command it quotes.

The offline gate is preflight; native admission enforces. The docs say that `policy generate --platform openshift
--version 4.22 --engine vap --mode enforce --rule KN-S001` emits `failurePolicy: Fail` and a binding with
`validationActions: [Deny]`. A doc sentence is written only after a test holds it (brief, class 8), so this runs that
exact command and reads those two fields, and the two pages are checked to quote the same command.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from kube_noob.cli import main

ROOT = Path(__file__).resolve().parents[1]
COMMAND = [
    "policy",
    "generate",
    "--platform",
    "openshift",
    "--version",
    "4.22",
    "--engine",
    "vap",
    "--mode",
    "enforce",
    "--rule",
    "KN-S001",
]


def test_the_documented_enforce_command_emits_fail_and_deny(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(COMMAND) == 0
    docs = [d for d in yaml.safe_load_all(capsys.readouterr().out) if isinstance(d, dict)]
    policies = [d for d in docs if d.get("kind") == "ValidatingAdmissionPolicy"]
    bindings = [d for d in docs if d.get("kind") == "ValidatingAdmissionPolicyBinding"]
    assert len(policies) == 1 and len(bindings) == 1
    assert policies[0]["spec"]["failurePolicy"] == "Fail"
    assert bindings[0]["spec"]["validationActions"] == ["Deny"]
    assert policies[0]["metadata"]["name"] == "kube-noob-kn-s001"


def test_both_pages_quote_the_command_the_test_runs() -> None:
    text = (ROOT / "docs" / "use-cases.md").read_text(encoding="utf-8")
    flat = re.sub(r"\s+", " ", text)
    quoted = "kube-noob " + " ".join(COMMAND)
    assert flat.count(quoted) >= 2, "the gate page and the admission page each carry the handoff paragraph"
    assert flat.count("failurePolicy: Fail") >= 2 and flat.count("validationActions: [Deny]") >= 2
