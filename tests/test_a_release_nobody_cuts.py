"""kube-noob.com is built from the latest RELEASE, so a week with no release is a week of stale facts.

The site repository rebuilds every six hours and skips when nothing changed, so rebuild frequency was never the
thing: if no release is cut, nothing the site does changes what it says. G358 was that at its worst -- the site
could not build at all for six days and `site-sync` stayed green, because the published site and the latest
release agreed while nothing moved.

`release-ready` checks the cadence itself, once a week, with three answers and never two: ready (with the command),
not ready (naming what stops it), or not known (which is not ready). A report that said ready because it could not
take a reading would be the defect this project exists to refuse, pointed at the release (G361).
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "release-ready.yml"
# The expression the workflow uses to count what is waiting. Kept here verbatim so a change to either side fails.
AWK = "/^## Unreleased$/{f=1;next} /^## /{f=0} f && /^- /{n++} END{print n+0}"


def _spec() -> dict[str, Any]:
    spec: dict[str, Any] = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    if True in spec and "on" not in spec:  # YAML 1.1 reads a bare `on:` key as the boolean True
        spec["on"] = spec.pop(True)
    return spec


def _script() -> str:
    return "\n".join(str(s.get("run", "")) for s in _spec()["jobs"]["ready"]["steps"])


def _count(changelog: str) -> str:
    awk = shutil.which("awk")
    assert awk, "awk is not on PATH, so the expression the workflow depends on was never run"
    out = subprocess.run([awk, AWK], input=changelog, capture_output=True, text=True, check=True)
    return out.stdout.strip()


def test_the_cadence_is_checked_weekly_and_can_be_asked_by_hand() -> None:
    spec = _spec()
    crons = [c["cron"] for c in spec["on"]["schedule"]]
    assert len(crons) == 1, crons
    minute, _hour, dom, month, dow = crons[0].split()
    assert dom == "*" and month == "*" and dow != "*", f"not weekly: {crons[0]}"
    assert minute not in {"0", "30"}, "a jittered minute, so the run is not queued behind every other :00 job"
    assert "workflow_dispatch" in spec["on"], "it must be askable by hand after a fix"
    assert isinstance(spec["jobs"]["ready"].get("timeout-minutes"), int)


def test_the_awk_counts_only_what_is_waiting_to_be_released() -> None:
    """The count decides whether anything is said at all, so the expression is held here as well as in the yaml."""
    assert AWK in WORKFLOW.read_text(encoding="utf-8")
    rolled = "# Changelog\n\n## Unreleased\n\n## 0.10.0 - 2026-11-23\n\n- a (G1)\n- b (G2)\n"
    assert _count(rolled) == "0", "a rolled release leaves Unreleased empty; that is nothing to cut"
    waiting = "# Changelog\n\n## Unreleased\n\n- a (G1)\n- b (G2)\n\n## 0.10.0 - 2026-11-23\n\n- old (G0)\n"
    assert _count(waiting) == "2", "bullets from an older section must not be counted"
    assert _count("# Changelog\n") == "0", "no section at all prints a number, not an awk error"


def test_every_check_counts_not_only_the_required_eight() -> None:
    """gate-ci is the one job that runs the gate as the real Action, a Tekton Task and the GitLab template, and it
    is not a required check: a merge queue can be green while it is red."""
    script = _script()
    assert "check-runs" in script and "--paginate" in script
    assert "gate-ci" in script, "the reason every check counts has to be stated where someone will read it"
    assert "required" in script
    for forbidden in ("required_status_checks", "contexts"):
        assert forbidden not in script, f"{forbidden} would narrow this to the eight that auto-merge already has"
    assert '.conclusion != "skipped"' in script, "a skipped job is not a failure"


def test_a_reading_that_could_not_be_taken_is_not_ready() -> None:
    """Eight separate refusals, each its own non-zero exit, before any verdict is reported. The last four are
    G399's: whether the latest release finished shipping is a reading too, and one that cannot be taken is not
    "it did"."""
    script = _script()
    for phrase in (
        "whether there is anything to release is NOT KNOWN",
        "no release exists",
        "whether a release would be safe is NOT KNOWN",
        # Was "no check runs at all", which this workflow can no longer truthfully say: it is ITSELF a check run
        # on main's head while it runs (G393), so after excluding its own run the list it refuses over is "no
        # check runs OTHER than this workflow's own". The refusal is the same refusal; only the count it is
        # honest about changed.
        "no check runs other than this workflow's own",
        "whether ${tag} finished shipping is NOT KNOWN",
        "no release run exists for ${tag}",
        "whether it finishes shipping is NOT KNOWN yet",
        "so what it did not ship is NOT KNOWN",
        # G403: shape, not only transport.
        "has no line that is exactly '## Unreleased'",
        "how long the website has stated it is NOT KNOWN",
        "which checks to read is NOT KNOWN",
        "came back in a shape that is not a list of check runs",
        "no check on main concluded success",
    ):
        assert phrase in script, f"missing refusal: {phrase!r}"
    assert "This is not 'nothing to release'." in script
    assert "it is an unanswered question" in script
    head = script[: script.index("existing=$(gh issue list")]
    assert head.count("exit 1") == 13, head.count("exit 1")
    assert "exit 0" not in head, "nothing may pass before all thirteen readings are in"


def test_nothing_to_release_closes_the_issue_instead_of_nagging() -> None:
    script = _script()
    tail = script[script.index('if [ "${bullets}" = "0" ]') :]
    assert "gh issue close" in tail.split("exit 0")[0]
    assert "nothing is waiting to be released after" in tail, "the close comment should say why it is closing"
    assert "in step with" not in tail, "the workflow never reads the site, so it must not say the site is in step"


def test_the_ready_answer_carries_the_command_and_the_not_ready_answer_carries_the_reason() -> None:
    script = _script()
    assert "**Ready.**" in script and "**Not ready.**" in script
    assert "git/refs -f ref=refs/tags/v" in script, "ready must hand over the tag command"
    assert "scripts/bump_version.py" in script
    assert "are not green:" in script and "${notgreen}" in script, "not-ready must name the checks"
    assert "G356" in script, "the twelve-minute figure should cite the change that made it true"


def test_it_cannot_write_to_the_repository_itself() -> None:
    spec = _spec()
    assert spec["permissions"] == {"contents": "read"}
    job = spec["jobs"]["ready"]["permissions"]
    assert job == {"contents": "read", "issues": "write", "checks": "read", "actions": "read"}, job
    script = _script()
    for forbidden in ("git push", "git commit", "git tag", "refs/heads"):
        assert forbidden not in script, f"this workflow reports; it must not {forbidden}"


def test_the_real_changelog_is_readable_by_the_same_expression() -> None:
    """Run it against the file as committed, so a CHANGELOG reshape fails here rather than in a Monday run."""
    assert _count((ROOT / "CHANGELOG.md").read_text(encoding="utf-8")).isdigit()
