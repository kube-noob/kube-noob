"""The air-gap claim is a transcript, not a sentence (G294).

scripts/airgap_check.sh installs the wheel from a local directory inside a network namespace with no interface
(`unshare -rn`), then runs doctor, an audit, a must-gather analysis and one MCP request over stdio, and asserts the
exit code of each. Inside that namespace any DNS lookup or socket connect fails loudly, which the script proves
first on itself. Here the five checks run against this venv's own kube-noob, and the refusals are held: no wheel
is exit 2 and says so; a transcript line per check; "network: disabled" only after the probe failed.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "airgap_check.sh"
EXE = Path(sys.executable).parent / "kube-noob"


BASH = shutil.which("bash") or "/bin/bash"
SH = shutil.which("sh") or "/bin/sh"


def _run(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    full = {**os.environ, **(env or {})}
    return subprocess.run([BASH, str(SCRIPT), *args], check=False, capture_output=True, text=True, cwd=ROOT, env=full)


def _namespace_available() -> bool:
    unshare = shutil.which("unshare")
    if unshare is None:
        return False
    return subprocess.run([unshare, "-rn", "true"], check=False, capture_output=True).returncode == 0


def test_the_script_is_executable_and_parses() -> None:
    assert os.access(SCRIPT, os.X_OK)
    assert subprocess.run([BASH, "-n", str(SCRIPT)], check=False).returncode == 0
    assert subprocess.run([SH, "-n", str(SCRIPT)], check=False).returncode == 0, "POSIX sh too"
    proc = _run("--help")
    assert proc.returncode == 0 and "prepare" in proc.stdout and "verify" in proc.stdout and "checks" in proc.stdout


def test_no_wheel_is_a_refusal_that_names_what_is_missing_never_a_pass(tmp_path: Path) -> None:
    proc = _run("verify", str(tmp_path))
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "no kube_noob-*.whl" in proc.stderr and str(tmp_path) in proc.stderr
    assert "PASS" not in proc.stdout
    proc = _run("verify", str(tmp_path / "missing"))
    assert proc.returncode == 2 and "missing" in proc.stderr


def test_an_unknown_subcommand_or_a_missing_executable_is_exit_2(tmp_path: Path) -> None:
    assert _run("frobnicate").returncode == 2
    proc = _run("checks", str(tmp_path / "kube-noob"))
    assert proc.returncode == 2 and "kube-noob" in proc.stderr


@pytest.mark.skipif(not _namespace_available(), reason="unshare -rn is not permitted here")
def test_the_five_checks_run_in_a_namespace_with_no_network_and_each_exit_is_asserted(tmp_path: Path) -> None:
    assert EXE.is_file(), "the venv's kube-noob"
    proc = _run("checks", str(EXE), env={"KN_AIRGAP_WORK": str(tmp_path)})
    out = proc.stdout
    assert proc.returncode == 0, out + proc.stderr
    assert "network: disabled (DNS lookup and a connect both failed inside unshare -rn)" in out
    steps = (("doctor", 0), ("audit insecure-deployment.yaml", 1), ("must-gather analyze", 0), ("mcp tools/list", 0))
    for step, code in steps:
        assert re.search(rf"^ok\s+{re.escape(step)}.*exit {code}", out, re.M), (step, out)
    assert "PASS: 5 checks, 0 network attempts could have succeeded" in out
    assert "KN-PLANTED-SECRET" not in out, "the sample's planted secret never reaches the transcript"


@pytest.mark.skipif(not _namespace_available(), reason="unshare -rn is not permitted here")
def test_a_check_that_exits_with_the_wrong_code_fails_the_transcript(tmp_path: Path) -> None:
    """A stub that exits 0 for the audit (which must find high findings and exit 1) is caught, and named."""
    stub = tmp_path / "kube-noob"
    stub.write_text('#!/bin/sh\nif [ "$1" = mcp ]; then exec ' + str(EXE) + " mcp; fi\nexit 0\n", encoding="utf-8")
    stub.chmod(0o755)
    py = tmp_path / "python3"  # the script writes the sample with the python beside the exe
    py.write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n', encoding="utf-8")
    py.chmod(0o755)
    proc = _run("checks", str(stub), env={"KN_AIRGAP_WORK": str(tmp_path / "w")})
    assert proc.returncode == 1
    assert re.search(r"^FAIL\s+audit insecure-deployment.yaml.*expected exit 1, got 0", proc.stdout, re.M), proc.stdout
    assert "PASS" not in proc.stdout


def test_ci_runs_the_transcript_on_the_built_wheel_and_install_md_says_what_it_proves() -> None:
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "scripts/airgap_check.sh prepare" in ci and "scripts/airgap_check.sh verify" in ci
    assert "needs: [publishable]" in ci.split("airgap:")[1][:600], "it reuses the wheel the publishable job built"
    doc = (ROOT / "docs" / "install.md").read_text(encoding="utf-8")
    assert "## Offline install, verified" in doc
    section = doc.split("## Offline install, verified")[1]
    phrases = ("unshare -rn", "scripts/airgap_check.sh", "does not establish", "mirrored index", "requirements.lock")
    for phrase in phrases:
        assert phrase in section, phrase
    assert "scripts/airgap_check.sh checks" in (ROOT / "scripts" / "check.sh").read_text(encoding="utf-8")
