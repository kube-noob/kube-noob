"""Every job in ci.yml ends on a clock this repository chose, not on GitHub's six hours.

`videos` had a budget and a comment arguing for it. `test` -- four legs, the longest job here, and four of the
eight checks every merge waits for -- had none, and neither did ten others. A job without `timeout-minutes` runs
until GitHub's default of 360, and this account runs one `ci` workflow at a time, so one hung leg would have held
every other pull request's checks for six hours (G348).

A budget can be wrong in both directions, and each is its own defect. Too low, and it fires on a slow healthy
run: a failure that says nothing about the code, which is what G326 removed from the tests themselves. Too high,
and it is decoration. So the `test` budget is held against a measured number from both sides.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
GITHUB_DEFAULT = 360

# The slowest green `test` leg in the 30 successful runs before 2026-11-22: test (3.12), 59.1 minutes (median
# 47.8). Re-measure before changing it:
#   gh api 'repos/kube-noob/kube-noob/actions/runs/<id>/jobs' --jq '.jobs[] | [.name, .started_at, .completed_at]'
SLOWEST_GREEN_TEST_LEG = 60


def _jobs() -> dict[str, dict[str, Any]]:
    spec: dict[str, Any] = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
    # A job that calls a reusable workflow cannot carry timeout-minutes; the called workflow's jobs do.
    return {name: job for name, job in spec["jobs"].items() if "uses" not in job}


def test_every_ci_job_has_a_timeout_of_its_own() -> None:
    jobs = _jobs()
    assert len(jobs) >= 12, f"only {len(jobs)} jobs read from ci.yml; this would be checking less than it says"
    unbounded = sorted(name for name, job in jobs.items() if not isinstance(job.get("timeout-minutes"), int))
    assert unbounded == [], (
        f"no timeout-minutes on: {', '.join(unbounded)}. Without one a hung job runs for {GITHUB_DEFAULT} "
        "minutes, and one `ci` workflow runs at a time here. Measure the job's slowest green run and say in "
        "ci.yml why the number is what it is."
    )


def test_no_ci_job_budget_is_so_loose_it_is_the_default_by_another_name() -> None:
    budgets = {name: job.get("timeout-minutes", GITHUB_DEFAULT) for name, job in _jobs().items()}
    loose = {name: minutes for name, minutes in budgets.items() if minutes > 120}
    assert loose == {}, f"over two hours is not a budget for a job in the merge path: {loose}"


def test_the_test_job_budget_clears_its_slowest_green_run_without_being_decorative() -> None:
    budget = _jobs()["test"].get("timeout-minutes", GITHUB_DEFAULT)
    assert budget >= SLOWEST_GREEN_TEST_LEG * 5 // 4, (
        f"{budget} minutes is within a quarter of the slowest green run ({SLOWEST_GREEN_TEST_LEG}); runner variance "
        "alone would meet it, and a timeout on working code is a false failure"
    )
    assert budget <= SLOWEST_GREEN_TEST_LEG * 2, (
        f"{budget} minutes is more than twice the slowest green run ({SLOWEST_GREEN_TEST_LEG}); a hang would "
        "hold the queue longer than two full healthy runs"
    )
