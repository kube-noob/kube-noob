"""`brew install kube-noob` served 0.9.2 for a repository that said 0.10.0 everywhere else.

v0.10.0 reached PyPI, the chart, the MCP Registry and the GitHub release. The release workflow's `homebrew` job
then tried to push the regenerated formula straight to `main`, which is protected with eight required checks, and
GITHUB_TOKEN is not an admin: `remote: error: GH006: Protected branch update failed for refs/heads/main`. The job
failed -- correctly and loudly -- and nothing else closed the gap, so the documented
`brew tap kube-noob/kube-noob … && brew install kube-noob` kept installing the PREVIOUS release.

The test that was meant to hold this asserted the formula is `<=` the package: it catches a formula AHEAD of the
package, a version PyPI does not have, and is silent about one BEHIND it. An update that never happened read as a
pass (G357).

Two things changed. The assertion in `tests/test_distribution.py` is equality, so `main` is red for as long as its
formula serves a version this repository is not. And the job commits to a branch -- which protection allows --
then FAILS with the command to land it, because the formula cannot be written before the tag: its URLs carry the
PyPI-assigned path, which does not exist until the upload.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

ROOT = Path(__file__).resolve().parents[1]
RELEASE = ROOT / ".github" / "workflows" / "release.yml"
FORMULA = ROOT / "Formula" / "kube-noob.rb"


def _homebrew_script() -> str:
    jobs: dict[str, Any] = yaml.safe_load(RELEASE.read_text(encoding="utf-8"))["jobs"]
    steps = jobs["homebrew"]["steps"]
    return "\n".join(str(s.get("run", "")) for s in steps)


def test_the_formula_serves_exactly_the_version_this_repository_is() -> None:
    """The one that matters to a user typing the documented command."""
    import kube_noob

    found = re.search(r'^  url ".*/kube_noob-([0-9][0-9.]*)\.tar\.gz"', FORMULA.read_text(encoding="utf-8"), re.M)
    assert found, "the formula has no sdist url"
    assert found.group(1) == kube_noob.__version__, (
        f"the documented `brew install kube-noob` would serve {found.group(1)} from this branch while this "
        f"repository is {kube_noob.__version__}"
    )


def test_the_job_never_pushes_to_protected_main_again() -> None:
    script = _homebrew_script()
    assert "HEAD:main" not in script, (
        "the homebrew job pushes straight to main again. main is protected with eight required checks and "
        "GITHUB_TOKEN is not an admin, so the push is refused with GH006 and the formula reaches nobody."
    )
    assert "refs/heads/${branch}" in script and 'branch="chore/brew-formula-${version}"' in script


def test_a_formula_that_reached_only_a_branch_fails_the_job() -> None:
    """A branch nobody merges is an update that did not happen; reporting success would hide it."""
    script = _homebrew_script()
    tail = script[script.index('branch="chore/brew-formula') :]
    assert "exit 1" in tail, "the job must not report success when the formula is only on a branch"
    assert "::error title=homebrew::" in tail
    assert "still serves the previous release" in tail, "the error must say what a user would actually get"
    assert "gh api repos/${GITHUB_REPOSITORY}/pulls -X POST" in tail, "it must name the command that lands it"
    assert "exit 0" not in tail, "no path after the commit may end in success"


def test_the_unchanged_formula_is_still_the_one_quiet_success() -> None:
    """Re-running a release whose formula is already current must stay a no-op, not a failure."""
    script = _homebrew_script()
    head = script[: script.index('branch="chore/brew-formula')]
    assert 'if git diff --quiet -- Formula/kube-noob.rb; then echo "formula already at $version"; exit 0; fi' in head


def test_the_job_still_waits_for_pypi_before_writing_anything() -> None:
    """The formula pins PyPI-assigned URLs, so it cannot be written before the upload -- which is why this gap
    exists at all and cannot be closed by moving the work into the release pull request."""
    jobs = yaml.safe_load(RELEASE.read_text(encoding="utf-8"))["jobs"]
    assert jobs["homebrew"]["needs"] == "publish-pypi"
    script = _homebrew_script()
    assert "PyPI files for $version not available" in script and "for attempt in" in script
    # By host, not by substring. `"files.pythonhosted.org" in url` also matches
    # https://elsewhere.example/files.pythonhosted.org/... -- review class 3, and CodeQL flagged exactly
    # that here as "incomplete URL substring sanitization" when this line was first written as one.
    urls = re.findall(r'url "(https://[^"]+)"', FORMULA.read_text(encoding="utf-8"))
    assert urls, "the formula pins no urls at all"
    assert {urlsplit(u).netloc for u in urls} == {"files.pythonhosted.org"}, sorted({urlsplit(u).netloc for u in urls})
