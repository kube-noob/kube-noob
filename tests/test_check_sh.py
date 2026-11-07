"""scripts/check.sh is described as the gate to run before pushing, so it has to BE that gate.

It claimed to run "every gate CI runs on code" while running eleven fewer -- the coverage floor among them --
and it passed four times running while CI failed: test (3.13) on a missing numpy, helm-and-dogfood on a flag
bundle in quotes, and twice on main at the 0.9.0 release commit. A gate that passes while the real gate fails
is an absence reading as a pass, which is the defect this project exists to refuse, aimed at its own gate.

These tests make the drift impossible to add quietly: a new step in a CI code job must either appear in
check.sh or be named in NOT_LOCAL with a reason, and a tool check must record rather than exit.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
CHECK = ROOT / "scripts" / "check.sh"
CI = ROOT / ".github" / "workflows" / "ci.yml"

# The jobs that test the code itself on a plain runner. The rest stand up a cluster (gate-ci, admission-kind,
# policy-kind, e2e-kind, db-image) or need a recording toolchain (videos), and are out of a local gate's reach.
CODE_JOBS = ("lint", "test", "plugin", "publishable")

# A step CI runs that check.sh does not, each with the reason it cannot. Anything else must be in check.sh.
NOT_LOCAL = {
    "scripts/check_publishable.sh --python-version": "CI plumbing: writes the matrix python to $GITHUB_OUTPUT",
}


def _ci_steps() -> list[tuple[str, str]]:
    spec: dict[str, Any] = yaml.safe_load(CI.read_text())
    out: list[tuple[str, str]] = []
    for job in CODE_JOBS:
        for step in spec["jobs"][job]["steps"]:
            run = step.get("run")
            if not run:
                continue
            for raw in run.replace("\\\n", " ").splitlines():
                line = raw.strip()
                if line and not line.startswith("#"):
                    out.append((job, line))
    return out


# Gates that are not one of the repo's own scripts. Matching only `scripts/*` let the plugin's
# `uv export | pip-audit` gate go unnoticed in check.sh AND unnoticed by the first version of this test --
# the hole and the guard with the same blind spot.
_TOOL_GATES = (
    ("pip-audit", "pip-audit"),
    ("uv lock", "uv lock"),
    ("uv export", "uv export"),
    ("python -m build", "-m build"),
    ("--cov-fail-under", "--cov-fail-under"),
    ("ajv@", "ajv@"),
)


def _signatures(line: str) -> set[str]:
    """What check.sh must contain for this CI line to count as run. Setup and plumbing yield nothing."""
    found = set(re.findall(r"scripts/[\w./-]+\.(?:py|sh|mjs)", line))
    for needle, signature in _TOOL_GATES:
        if needle in line:
            found.add(signature)
    return found


def test_every_gate_a_ci_code_job_runs_is_run_by_check_sh() -> None:
    """If CI runs a gate and check.sh does not, local green means less than it says it does."""
    body = CHECK.read_text()
    missing: list[str] = []
    for job, line in _ci_steps():
        if any(k in line for k in NOT_LOCAL):
            continue
        for signature in _signatures(line):
            if signature not in body:
                missing.append(f"{job}: {signature} (from: {line[:90]})")
    assert not missing, "CI runs these and scripts/check.sh does not:\n" + "\n".join(sorted(set(missing)))


def test_check_sh_enforces_the_same_coverage_floor_as_ci() -> None:
    """`pytest -q` passes where `--cov-fail-under=80` would not, and the floor is part of the gate."""
    body = CHECK.read_text()
    floors = {m for _, line in _ci_steps() for m in re.findall(r"--cov-fail-under=(\d+)", line)}
    assert floors, "ci.yml no longer sets a coverage floor; this test is measuring nothing"
    for floor in floors:
        assert f"--cov-fail-under={floor}" in body, f"CI requires {floor}% coverage and check.sh does not ask for it"


def test_a_missing_tool_is_recorded_rather_than_passed_over() -> None:
    """A tool this machine lacks must reach the NOT RUN list; silence would be the absence-as-a-pass again."""
    body = CHECK.read_text()
    assert "notrun" in body and "NOT RUN" in body, "check.sh must collect and print what it could not run"
    assert "this is not a pass" in body, "the NOT RUN list has to say what it means"
    # `need X && cmd` returns non-zero under `set -e` when X is missing, which exits instead of recording.
    assert not re.search(r"^\s*need\s+\S+\s+\"[^\"]*\"\s*\\?\s*$\n\s*&&", body, re.M), (
        "`need ... && cmd` aborts under set -e when the tool is missing; use `if need ...; then`"
    )


def test_check_sh_does_not_claim_to_run_what_it_cannot() -> None:
    """The old header said "every gate CI runs on code". It did not, and the claim is what made it trusted."""
    header = "\n".join(CHECK.read_text().splitlines()[:20])
    assert "every gate CI runs on code" not in header or "NAME the ones" in header, (
        "check.sh must not claim completeness it does not have"
    )
