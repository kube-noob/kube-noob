"""Every job in every workflow ends on a clock this repository chose, not on GitHub's six hours.

`videos` had a budget and a comment arguing for it. `test` -- four legs, the longest job here, and four of the
eight checks every merge waits for -- had none, and neither did ten others. A job without `timeout-minutes` runs
until GitHub's default of 360, and this account runs one `ci` workflow at a time, so one hung leg would have held
every other pull request's checks for six hours (G348).

A budget can be wrong in both directions, and each is its own defect. Too low, and it fires on a slow healthy
run: a failure that says nothing about the code, which is what G326 removed from the tests themselves. Too high,
and it is decoration. So the `test` budget is held against a measured number from both sides.

G348 fixed ci.yml and this file checked ci.yml, so fifteen jobs in six other workflows kept GitHub's default:
`release.yml` (nine jobs, the whole publishing path), `brew.yml` (two), `codeql.yml`, `scorecard.yml`,
`risk-review.yml` and `db-image.yml`'s `publish`. A fix applied to one surface and not its siblings is review
class 25, and a hung job there reads as "still running" for six hours rather than as a failure -- an unknown
presenting as not-yet-a-verdict. `test_every_job_in_every_workflow_has_a_timeout_of_its_own` walks every file in
`.github/workflows` now, so a workflow added later cannot omit one (G372).
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


def _workflow_jobs() -> dict[tuple[str, str], dict[str, Any]]:
    """Every job of every workflow, keyed by file and job id.

    A job whose body is `uses:` calls a reusable workflow and cannot carry `timeout-minutes` of its own; the
    called workflow is a file in this directory, so walking every file still bounds it.
    """
    jobs: dict[tuple[str, str], dict[str, Any]] = {}
    for path in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
        spec: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8"))
        for name, job in (spec.get("jobs") or {}).items():
            if "uses" not in job:
                jobs[path.name, name] = job
    return jobs


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


def test_every_job_in_every_workflow_has_a_timeout_of_its_own() -> None:
    """Not only ci.yml: `release.yml`, `brew.yml`, `codeql.yml`, `scorecard.yml`, `risk-review.yml` and
    `db-image.yml` had fifteen jobs between them running on GitHub's default (G372)."""
    jobs = _workflow_jobs()
    files = {file for file, _ in jobs}
    assert len(jobs) >= 36 and len(files) >= 13, (
        f"only {len(jobs)} jobs in {len(files)} workflow files were read; this would be checking less than it says"
    )
    unbounded = sorted(
        f"{file}:{name}" for (file, name), job in jobs.items() if not isinstance(job.get("timeout-minutes"), int)
    )
    assert unbounded == [], (
        f"no timeout-minutes on: {', '.join(unbounded)}. Without one a hung job runs for {GITHUB_DEFAULT} "
        "minutes and reads as still running rather than as failed. Measure the job's slowest green run "
        "(`gh api 'repos/kube-noob/kube-noob/actions/workflows/<file>/runs'`, then that run's jobs endpoint) and "
        "say in the workflow why the number is what it is."
    )


def test_no_workflow_job_budget_is_github_s_default_by_another_name() -> None:
    """A budget is a number this repository chose. 360 chosen by hand is the default written out."""
    budgets = {f"{file}:{name}": job["timeout-minutes"] for (file, name), job in _workflow_jobs().items()}
    wrong = {name: minutes for name, minutes in budgets.items() if not 0 < minutes < GITHUB_DEFAULT}
    assert wrong == {}, f"these budgets are not a finite bound below GitHub's default of {GITHUB_DEFAULT}: {wrong}"
