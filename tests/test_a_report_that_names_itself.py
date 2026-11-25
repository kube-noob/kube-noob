"""`release-ready` would have named itself as the thing blocking every release.

The workflow reads every check run on main's head and reports a release not ready if any of them is not green.
A workflow run triggered by `schedule` creates a check run on that same commit -- measured on this repository:
scorecard's scheduled run 45411849676 appears as the `analysis` check run on the commit it ran against, beside
the push run's. So `release-ready`, which runs Mondays on a schedule, is in the list it reads, with a null
conclusion and status `in_progress`.

`(.conclusion // .status) != "success"` is true of itself, and `.conclusion != "skipped"` is true of null, so the
filter selected it. `notgreen` could never be empty, and the weekly issue would have said **Not ready**, naming
`in_progress release-ready`, for as long as the workflow existed. Its first scheduled run had not happened yet,
so nothing had ever shown it.

This test runs the workflow's own lines. A test that searched the YAML for the exclusion would pass on an
exclusion that does not work, which is the defect G-numbered at #129: the string `3840` sat in a comment and the
size check that was deleted still "passed".
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "release-ready.yml"

RUN_ID = "99999999"
MINE = f"https://github.com/kube-noob/kube-noob/actions/runs/{RUN_ID}/job/1"
OTHER_RUN = "https://github.com/kube-noob/kube-noob/actions/runs/12345678/job/2"


def _script() -> str:
    """The workflow's own lines, from the self-exclusion to the line that names what is not green."""
    text = WORKFLOW.read_text(encoding="utf-8")
    start = text.index('          mine="/actions/runs/')
    end = text.index("\n", text.index("          notgreen=$(", start))
    body = text[start:end]
    lines = [line[10:] if line.startswith("          ") else line for line in body.splitlines()]
    extracted = "\n".join(lines)
    assert "jq" in extracted, "the block read from the workflow has no jq in it, so this test runs nothing"
    return "set -uo pipefail\n" + extracted + '\necho "TOTAL=${total}"\necho "NOTGREEN=${notgreen}"\n'


def _run(check_runs: list[dict[str, object]], tmp_path: Path) -> tuple[int, str, str, str]:
    """Run the workflow's lines over a crafted check-run list.

    Returns (exit code, total, notgreen, everything it printed). `total` is empty when the block exited before
    echoing it, which is itself an answer: the `exit 1` path ran.
    """
    (tmp_path / "checks.json").write_text(json.dumps({"check_runs": check_runs}), encoding="utf-8")
    script = _script().replace("/tmp/checks.json", str(tmp_path / "checks.json"))
    done = subprocess.run(  # the workflow's own lines, over a file this test wrote
        ["bash", "-c", script],  # noqa: S607 - bash on PATH is the shell the runner uses
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin:/usr/local/bin", "GITHUB_RUN_ID": RUN_ID},
        check=False,
        timeout=60,
    )
    total = next((m for m in re.findall(r"^TOTAL=(.*)$", done.stdout, re.M)), "")
    notgreen = next((m for m in re.findall(r"^NOTGREEN=(.*)$", done.stdout, re.M)), "")
    return done.returncode, total, notgreen, done.stdout + done.stderr


def _check(name: str, conclusion: str | None, status: str, url: str) -> dict[str, object]:
    return {"name": name, "conclusion": conclusion, "status": status, "details_url": url}


_SELF = _check("release-ready", None, "in_progress", MINE)
_GREEN = _check("test (3.11)", "success", "completed", OTHER_RUN)
_SKIPPED = _check("db-image", "skipped", "completed", OTHER_RUN)
_FAILED = _check("gate-ci", "failure", "completed", OTHER_RUN)


def test_a_green_main_reads_green_while_this_workflow_is_running(tmp_path: Path) -> None:
    """The defect, in one case: its own in-progress run beside nothing but green.

    Before the fix this returned `in_progress release-ready` and the weekly issue said Not ready.
    """
    code, total, notgreen, _said = _run([_SELF, _GREEN, _SKIPPED], tmp_path)
    assert code == 0, f"the block exited {code}"
    assert notgreen == "", f"a green main reported as not green: {notgreen}"
    assert total == "2", f"counted {total} checks; the workflow's own run should be the only one dropped"


def test_a_real_failure_is_still_named(tmp_path: Path) -> None:
    """The exclusion must not be a way to report green. A failing job is still named."""
    code, _total, notgreen, _said = _run([_SELF, _GREEN, _FAILED], tmp_path)
    assert code == 0, f"the block exited {code}"
    assert "failure gate-ci" in notgreen, f"a failing check was not named: {notgreen!r}"
    assert "release-ready" not in notgreen, f"the workflow still names itself: {notgreen!r}"


def test_another_jobs_in_progress_run_is_still_named(tmp_path: Path) -> None:
    """Excluded by run id, not by name.

    A second job called `release-ready` from a DIFFERENT run -- a manual dispatch overlapping the schedule -- is
    somebody else's unfinished answer about main, and dropping it would be the absence-reads-as-pass defect.
    """
    other_same_name = _check("release-ready", None, "in_progress", OTHER_RUN)
    code, _total, notgreen, _said = _run([_SELF, _GREEN, other_same_name], tmp_path)
    assert code == 0, f"the block exited {code}"
    assert "in_progress release-ready" in notgreen, (
        f"another run's unfinished job was dropped by name instead of by run id: {notgreen!r}"
    )


def test_a_list_holding_only_this_workflow_is_not_known(tmp_path: Path) -> None:
    """Nothing left after the exclusion is an unanswered question, not a green main."""
    code, _total, _notgreen, said = _run([_SELF], tmp_path)
    assert code == 1, f"a list with no other check run exited {code}, so the report would have gone on"
    assert "unanswered question" in said, f"it stopped without saying the answer is not known: {said!r}"
    assert "not a green main" in said, f"it did not refuse to call this green: {said!r}"


def test_a_check_run_with_no_details_url_is_kept(tmp_path: Path) -> None:
    """`details_url` can be absent. A check with no url is not this run's, so it stays in the answer."""
    no_url = {"name": "analysis", "conclusion": "failure", "status": "completed"}
    code, _total, notgreen, _said = _run([_SELF, _GREEN, no_url], tmp_path)
    assert code == 0, f"the block exited {code}"
    assert "failure analysis" in notgreen, f"a check with no url was dropped: {notgreen!r}"


@pytest.mark.parametrize("marker", ['mine="/actions/runs/${GITHUB_RUN_ID}/"', "contains($mine)"])
def test_the_exclusion_is_by_run_id(marker: str) -> None:
    """Named so a rewrite to a name match has to change this file too, and say why in the diff."""
    assert marker in WORKFLOW.read_text(encoding="utf-8"), f"{marker!r} is gone from the workflow"
