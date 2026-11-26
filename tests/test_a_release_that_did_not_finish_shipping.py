"""`release-ready` said "in step with v0.10.0" over a release that never finished shipping (G399).

A tag publishes to PyPI, the image, the chart, the MCP Registry, Homebrew and the videos, each its own job of one
release run. v0.10.0's run concluded failure -- four video renders, the video attach and the Homebrew push -- and
`release-ready` compared only the CHANGELOG with the tag, so with nothing under `## Unreleased` it would have
closed its issue as "the website is in step". Measured on 2026-11-25: 4 of the last 8 release runs concluded
failure and nothing said so.

These tests EXECUTE the workflow's own script, not a copy of it, against a stub `gh` that answers each API read
from a scenario and records every write. A string check would pass with the guard deleted; this cannot.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "release-ready.yml"
REPO = "kube-noob/kube-noob"

GREEN = {"check_runs": [{"name": "lint", "status": "completed", "conclusion": "success", "details_url": "u/1/"}]}
SHIPPED = {"workflow_runs": [{"id": 41, "status": "completed", "conclusion": "success"}]}
UNSHIPPED = {"workflow_runs": [{"id": 45115366977, "status": "completed", "conclusion": "failure"}]}
# The v0.10.0 run as the jobs endpoint reported it, trimmed to one of each conclusion.
V0100_JOBS = {
    "jobs": [
        {"name": "publish-pypi", "status": "completed", "conclusion": "success"},
        {"name": "homebrew", "status": "completed", "conclusion": "failure"},
        {"name": "videos / render (mcp)", "status": "completed", "conclusion": "failure"},
        {"name": "brew", "status": "completed", "conclusion": "skipped"},
        {"name": "site-videos", "status": "completed", "conclusion": "skipped"},
    ]
}
EMPTY_CHANGELOG = "# Changelog\n\n## Unreleased\n\n## 0.10.0 - 2026-11-23\n\n- old (G1)\n"
WAITING_CHANGELOG = "# Changelog\n\n## Unreleased\n\n- a (G2)\n- b (G3)\n\n## 0.10.0 - 2026-11-23\n\n- old (G1)\n"

# Answers by a substring of the command line, first match wins. A value of None makes that read fail.
STUB = r"""
import json, os, subprocess, sys
args = sys.argv[1:]
line = " ".join(args)
scenario = json.load(open(os.environ["STUB_SCENARIO"]))
if args[:2] in (["issue", "close"], ["issue", "edit"], ["issue", "create"], ["label", "create"]):
    with open(os.environ["STUB_LOG"], "a") as f:
        f.write(json.dumps(args) + "\n")
    sys.exit(0)
for key, answer in scenario:
    if key in line:
        break
else:
    sys.stderr.write("stub gh: no answer for " + line + "\n")
    sys.exit(2)
if answer is None:
    sys.stderr.write("stub gh: refused " + line + "\n")
    sys.exit(1)
paged = isinstance(answer, dict) and "__pages__" in answer
text = "\n".join(json.dumps(x) for x in answer["__pages__"]) if paged else json.dumps(answer)
if "--jq" in args:
    expr = args[args.index("--jq") + 1]
    text = subprocess.run(["jq", "-r", expr], input=text, capture_output=True, text=True, check=True).stdout
sys.stdout.write(text if text.endswith("\n") else text + "\n")
"""


def _script() -> str:
    spec: dict[str, Any] = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    return "\n".join(str(s.get("run", "")) for s in spec["jobs"]["ready"]["steps"] if "run" in s)


def _run(
    tmp_path: Path,
    *,
    changelog: str,
    runs: Any,
    jobs: Any = V0100_JOBS,
    existing: Any = (),
    answers: Any = (),
) -> tuple[int, str, list[list[str]]]:
    for tool in ("jq", "awk", "paste", "date", "grep"):
        assert shutil.which(tool), f"{tool} is not on PATH, so the workflow's script could not be executed"
    bash = shutil.which("bash")
    assert bash, "bash is not on PATH, so the workflow's script could not be executed"
    work = tmp_path / "work"
    scratch = tmp_path / "scratch"
    bindir = tmp_path / "bin"
    for d in (work, scratch, bindir):
        d.mkdir()
    (work / "CHANGELOG.md").write_text(changelog, encoding="utf-8")
    gh = bindir / "gh"
    gh.write_text(f"#!{sys.executable}\n{STUB}", encoding="utf-8")
    gh.chmod(0o755)
    scenario = [
        *[list(a) for a in answers],
        ["release list", [{"tagName": "v0.10.0"}]],
        ["release view", {"publishedAt": "2026-11-23T05:30:00Z"}],
        ["commits/main", {"sha": "340d243b2f0c0c1d6a7e4f5b8a9c0d1e2f3a4b5c"}],
        ["check-runs", GREEN],
        ["workflows/release.yml/runs", runs],
        ["/jobs", jobs],
        ["issue list", [{"number": n, "title": "Release ready"} for n in existing]],
    ]
    (tmp_path / "scenario.json").write_text(json.dumps(scenario), encoding="utf-8")
    log = tmp_path / "writes.jsonl"
    log.touch()
    # The script keeps its intermediate files under /tmp; give each test its own.
    script = _script().replace("/tmp/", f"{scratch}/")
    env = {
        **os.environ,
        "PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}",
        "GH_TOKEN": "stub",
        "GITHUB_REPOSITORY": REPO,
        "GITHUB_RUN_ID": "999",
        "GITHUB_SERVER_URL": "https://github.com",
        "STUB_SCENARIO": str(tmp_path / "scenario.json"),
        "STUB_LOG": str(log),
    }
    # The shell GitHub runs a `run:` block with on ubuntu-latest.
    out = subprocess.run(
        [bash, "--noprofile", "--norc", "-eo", "pipefail", "-c", script],
        check=False,
        cwd=work,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    writes = [json.loads(x) for x in log.read_text(encoding="utf-8").splitlines() if x.strip()]
    return out.returncode, out.stdout + out.stderr, writes


def _body(writes: list[list[str]]) -> str:
    issue = [w for w in writes if w[:1] == ["issue"]]
    assert len(issue) == 1, writes
    if issue[0][:2] == ["issue", "create"]:
        # G413: the label must exist before the issue that carries it is created.
        assert writes.index(issue[0]) > 0 and writes[writes.index(issue[0]) - 1][:3] == [
            "label",
            "create",
            "release-ready",
        ], writes
    args = issue[0]
    assert args[:2] in (["issue", "create"], ["issue", "edit"]), args
    return args[args.index("--body") + 1]


def test_an_empty_changelog_over_a_failed_release_run_is_not_in_step(tmp_path: Path) -> None:
    """v0.10.0 exactly: nothing unreleased, the release run red. It used to close the issue as in step."""
    code, out, writes = _run(tmp_path, changelog=EMPTY_CHANGELOG, runs=UNSHIPPED, existing=(7,))
    assert code == 0, out
    assert not any(w[:2] == ["issue", "close"] for w in writes), f"closed as in step over a red release: {writes}"
    body = _body(writes)
    assert body.startswith("**Not finished.**"), body
    assert "`v0.10.0` did not finish shipping." in body
    assert "failure homebrew" in body and "failure videos / render (mcp)" in body, "each unshipped job is named"
    assert "https://github.com/kube-noob/kube-noob/actions/runs/45115366977" in body, "the run is linked"
    assert "publish-pypi" not in body, "a job that succeeded is not named as unshipped"
    assert "skipped" not in body.split("did not succeed:")[1].split("What those")[0], (
        "a skipped job is a consequence, named in prose, not listed as a failure of its own"
    )


def test_an_empty_changelog_over_a_release_that_shipped_still_closes(tmp_path: Path) -> None:
    code, out, writes = _run(tmp_path, changelog=EMPTY_CHANGELOG, runs=SHIPPED, existing=(7,))
    assert code == 0, out
    assert len(writes) == 1 and writes[0][:3] == ["issue", "close", "7"], writes
    comment = writes[0][writes[0].index("--comment") + 1]
    assert "release run concluded success" in comment and "nothing is waiting to be released after v0.10.0" in comment


def test_ready_still_says_ready_and_carries_the_unfinished_release(tmp_path: Path) -> None:
    """A new release is the fix for an unfinished one, so it does not block `ready`; it is stated beside it."""
    code, out, writes = _run(tmp_path, changelog=WAITING_CHANGELOG, runs=UNSHIPPED)
    assert code == 0, out
    body = _body(writes)
    assert body.startswith("**Ready.**"), body
    assert "`v0.10.0` did not finish shipping." in body and "failure homebrew" in body


def test_ready_over_a_shipped_release_says_nothing_about_shipping(tmp_path: Path) -> None:
    code, out, writes = _run(tmp_path, changelog=WAITING_CHANGELOG, runs=SHIPPED)
    assert code == 0, out
    body = _body(writes)
    assert body.startswith("**Ready.**") and "did not finish shipping" not in body, body


@pytest.mark.parametrize(
    ("runs", "jobs", "said"),
    [
        (None, V0100_JOBS, "the release run for v0.10.0 could not be read"),
        ({"workflow_runs": []}, V0100_JOBS, "no release run exists for v0.10.0"),
        ({"workflow_runs": [{"id": 9, "status": "in_progress", "conclusion": None}]}, V0100_JOBS, "still in_progress"),
        (UNSHIPPED, None, "the jobs of v0.10.0's release run could not be read"),
    ],
    ids=["runs-unreadable", "no-run", "still-running", "jobs-unreadable"],
)
def test_a_release_run_that_cannot_be_read_is_not_known(tmp_path: Path, runs: Any, jobs: Any, said: str) -> None:
    """Each is exit 1 with NOT KNOWN and writes nothing: no issue may be closed, edited or opened on a guess."""
    for changelog in (EMPTY_CHANGELOG, WAITING_CHANGELOG):
        sub = tmp_path / str(len(changelog))
        sub.mkdir()
        code, out, writes = _run(sub, changelog=changelog, runs=runs, jobs=jobs, existing=(7,))
        assert code == 1, out
        assert said in out and "NOT KNOWN" in out, out
        assert writes == [], writes


def test_a_failed_run_whose_jobs_all_read_green_still_names_itself(tmp_path: Path) -> None:
    """A run can conclude failure with no failed job in the latest attempt's list (a startup failure, a cancelled
    workflow). That is still not shipped, and the body must not be an empty list."""
    jobs = {"jobs": [{"name": "publish-pypi", "status": "completed", "conclusion": "success"}]}
    code, out, writes = _run(tmp_path, changelog=EMPTY_CHANGELOG, runs=UNSHIPPED, jobs=jobs)
    assert code == 0, out
    assert "no job names itself; the run concluded failure" in _body(writes)


# G403: a reading that came back in the wrong SHAPE is a reading that was not taken. Every case below used to reach
# an answer -- most of them "Ready" or a closed issue -- because the script runs without `-e` and only checked that
# `gh` exited 0. Each must now exit 1, say NOT KNOWN or name the unanswered question, and write nothing.
@pytest.mark.parametrize(
    ("answers", "changelog", "said"),
    [
        ([["check-runs", {}]], WAITING_CHANGELOG, "not a list of check runs"),
        ([["check-runs", []]], WAITING_CHANGELOG, "not a list of check runs"),
        ([["check-runs", {"message": "Not Found"}]], WAITING_CHANGELOG, "not a list of check runs"),
        ([["check-runs", {"check_runs": None}]], WAITING_CHANGELOG, "not a list of check runs"),
        (
            [["check-runs", {"check_runs": [{"name": "x", "status": "completed", "conclusion": "skipped"}]}]],
            WAITING_CHANGELOG,
            "no check on main concluded success",
        ),
        ([["release view", None]], WAITING_CHANGELOG, "when v0.10.0 was published could not be read"),
        ([["release view", {"publishedAt": None}]], WAITING_CHANGELOG, "when v0.10.0 was published could not be read"),
        ([["commits/main", {}]], WAITING_CHANGELOG, "main's head commit could not be read"),
        ([["issue list", None]], WAITING_CHANGELOG, "could duplicate it"),
        ([], "# Changelog\n\n## [Unreleased]\n\n## 0.10.0 - 2026-11-23\n", "no line that is exactly '## Unreleased'"),
        ([], EMPTY_CHANGELOG.replace("\n", "\r\n"), "no line that is exactly '## Unreleased'"),
        ([], "# Changelog\n\n## 0.10.0 - 2026-11-23\n\n- old (G1)\n", "no line that is exactly '## Unreleased'"),
    ],
    ids=[
        "checks-empty-object",
        "checks-empty-list",
        "checks-not-found-body",
        "checks-null",
        "checks-all-skipped",
        "release-view-fails",
        "release-view-null-date",
        "head-sha-missing",
        "issue-lookup-fails",
        "heading-bracketed",
        "heading-crlf",
        "heading-missing",
    ],
)
def test_a_malformed_reading_is_not_known_and_writes_nothing(
    tmp_path: Path, answers: Any, changelog: str, said: str
) -> None:
    code, out, writes = _run(tmp_path, changelog=changelog, runs=SHIPPED, answers=answers, existing=(7,))
    assert code == 1, out
    assert said in out, out
    assert writes == [], f"a reading that was not taken still wrote to the issue: {writes}"


def test_every_page_of_check_runs_is_read(tmp_path: Path) -> None:
    """`--paginate` writes one JSON document per page. A failure on the second page must be named, and the count
    must be one number -- it printed `1\n1` before every page was slurped (G403)."""
    pages = {
        "__pages__": [
            {"check_runs": [{"name": "lint", "status": "completed", "conclusion": "success", "details_url": "u/1/"}]},
            {
                "check_runs": [
                    {"name": "gate-ci", "status": "completed", "conclusion": "failure", "details_url": "u/2/"}
                ]
            },
        ]
    }
    code, out, writes = _run(tmp_path, changelog=WAITING_CHANGELOG, runs=SHIPPED, answers=[["check-runs", pages]])
    assert code == 0, out
    body = _body(writes)
    assert body.startswith("**Not ready.**") and "failure gate-ci" in body, body

    green = {
        "__pages__": [pages["__pages__"][0], {"check_runs": [dict(pages["__pages__"][0]["check_runs"][0], name="t")]}]
    }
    sub = tmp_path / "green"
    sub.mkdir()
    code, out, writes = _run(sub, changelog=WAITING_CHANGELOG, runs=SHIPPED, answers=[["check-runs", green]])
    assert code == 0, out
    assert "all **2** checks on" in _body(writes), "two pages of one check each are two checks, counted once"


def test_the_first_run_creates_the_label_it_files_under(tmp_path: Path) -> None:
    """G413: with no open issue the workflow creates one, and `gh issue create --label` refuses a label the
    repository lacks. The label is created first, with `--force` so an existing one is left as it is."""
    code, out, writes = _run(tmp_path, changelog=WAITING_CHANGELOG, runs=SHIPPED)
    assert code == 0, out
    assert [w[:3] for w in writes] == [["label", "create", "release-ready"], ["issue", "create", "--repo"]], writes
    assert "--force" in writes[0]


def test_an_existing_issue_is_edited_without_touching_labels(tmp_path: Path) -> None:
    code, out, writes = _run(tmp_path, changelog=WAITING_CHANGELOG, runs=SHIPPED, existing=(7,))
    assert code == 0, out
    assert [w[:2] for w in writes] == [["issue", "edit"]], writes
