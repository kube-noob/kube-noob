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
CODE_JOBS = ("lint", "test", "plugin", "publishable", "airgap")

# A step CI runs that check.sh does not, each with the reason it cannot. Anything else must be in check.sh.
NOT_LOCAL = {
    "scripts/check_publishable.sh --python-version": "CI plumbing: writes the matrix python to $GITHUB_OUTPUT",
    # The air-gap transcript (G294): CI mirrors the dependency wheels (network) and installs from that directory
    # with --no-index inside the namespace. check.sh runs the same checks, through the script's `checks`
    # subcommand, on the wheel it has just installed with network; the --no-index install itself is CI's.
    "scripts/airgap_check.sh prepare": "needs network to mirror the dependency wheels",
    "scripts/airgap_check.sh verify": "the --no-index install from the mirror; check.sh runs `airgap_check.sh checks`",
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


def test_the_headline_does_not_announce_a_pass_above_the_list_of_what_did_not_run() -> None:
    """`notrun` was honest and the line above it was not (G375).

    `check.sh` collected every gate it could not run and printed them under "NOT RUN ... this is not a pass" --
    beneath the unconditional line `echo "All checks passed!"`. On a machine without helm, where
    `ci/helm-and-dogfood` cannot run at all, that is what a reader saw first, and `AGENTS.md` names this script as
    "the one command that decides whether you are done".
    """
    body = CHECK.read_text()
    i = body.index('echo "All checks passed!"')
    j = body.index("NOT RUN on this machine")
    assert j < i, "the NOT RUN list must be decided before anything announces a pass"


def test_a_gate_that_could_not_run_exits_five_and_not_zero() -> None:
    """The exit status is what a wrapper and an agent read, and `AGENTS.md` tells the agent to read it.

    The header's old rule was that the status is 0 "if everything ATTEMPTED passed", and a step whose tool is
    missing was never attempted -- so 0 was the answer on a machine that could not run a required CI job. 5 is the
    product's own word for evidence incomplete, and `AGENTS.md` publishes that 1 and 5 are not two answers to the
    same question.
    """
    body = CHECK.read_text()
    tail = body[body.index("NOT RUN on this machine") :]
    assert "exit 5" in tail, "a gate that could not run has to leave a status that is not a pass"
    assert re.search(r"if \[ \$\{#notrun\[@\]\} -gt 0 \]; then(?:.|\n)*?exit 5", body), (
        "the 5 must be reached exactly when the NOT RUN list is non-empty"
    )


def test_a_clean_machine_still_exits_zero() -> None:
    """The negative control, and the reason this is not just a stricter script.

    If nothing is in `notrun`, every gate ran, and the script must still say so and exit 0 -- otherwise the 5
    becomes the normal answer, which is how a real signal gets trained out of a reader.
    """
    body = CHECK.read_text()
    after = body[body.index("exit 5") :]
    assert 'echo "All checks passed!"' in after, "the pass line must still be reachable when nothing was skipped"
    assert "exit 5" not in after.split('echo "All checks passed!"')[1], "nothing may force a 5 after a clean run"


def test_the_header_and_agents_md_both_state_the_new_contract() -> None:
    """A behaviour change with the old promise still written next to it is the next reader's bug."""
    header = "\n".join(CHECK.read_text().splitlines()[:30])
    assert "0 every gate ran and passed" in header
    assert "everything ATTEMPTED passed" not in header or "It used to" in header
    agents = (ROOT / "AGENTS.md").read_text()
    assert "Exit 5 is not a pass" in agents, "AGENTS.md names this command; it has to say what 5 means"
