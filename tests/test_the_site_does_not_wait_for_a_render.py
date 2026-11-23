"""kube-noob.com served the previous release's facts for two hours after every release.

`release.yml`'s `site` job asked the private kube-noob-site repository to publish, and it depended on `videos`. At
v0.9.2 everything that actually publishes -- PyPI, the image, the chart, the MCP Registry, Homebrew, the GitHub
release -- finished in 12 minutes, and `videos / render (walkthrough)` then ran for 128.7 more. The website, which
is built from the latest release, spent that window stating the PREVIOUS version, rule counts and install commands.

The dependency had a real reason once: a site built the moment the release existed published a Videos page saying
the release had none, and 0.7.0 shipped that page. kube-noob-site has since fixed it at its own end -- its deploy
walks back through the last eight releases until one yields media and warns which one it used -- so the comment in
this repository outlived the behaviour it described. One fact about the website lived in two repositories and only
one of them was updated (review class 9), and the cost of the stale half was the entire render.

So `site` now runs on `github-release`, `site-videos` asks again when the renders land, and both go through one
reusable workflow rather than two copies of the same dispatch (G356).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
PUBLISH = "./.github/workflows/site-publish.yml"
# v0.9.2's run: the publishing jobs against the longest render. Re-measure before changing either:
#   gh api 'repos/kube-noob/kube-noob/actions/runs/<id>/jobs' --jq '.jobs[] | [.name, .started_at, .completed_at]'
PUBLISH_MINUTES = 12
LONGEST_RENDER_MINUTES = 128.7


def _spec(name: str) -> dict[str, Any]:
    spec: dict[str, Any] = yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))
    # YAML 1.1 reads a bare `on:` key as the boolean True, so the triggers are not under "on".
    if True in spec and "on" not in spec:
        spec["on"] = spec.pop(True)
    return spec


def _needs(job: dict[str, Any]) -> list[str]:
    n = job.get("needs") or []
    return [n] if isinstance(n, str) else list(n)


def test_the_first_publish_does_not_wait_for_the_videos() -> None:
    """The whole point: the website must not be gated on a render that takes ten times longer than the release."""
    site = _spec("release.yml")["jobs"]["site"]
    assert "videos" not in _needs(site), (
        f"site depends on videos again. That held kube-noob.com on the previous release's facts for "
        f"{LONGEST_RENDER_MINUTES:.0f} minutes while the release itself was published in {PUBLISH_MINUTES}. "
        "kube-noob-site never empties its Videos page -- it falls back through the last eight releases -- so "
        "there is nothing left to wait for."
    )
    assert _needs(site) == ["github-release"], _needs(site)


def test_the_website_is_asked_again_once_the_renders_land() -> None:
    """Publishing early is only honest if the release's own videos arrive afterwards."""
    jobs = _spec("release.yml")["jobs"]
    assert "site-videos" in jobs, (
        "site publishes before the videos exist and nothing asks again, so the Videos page would stay on an "
        "older release until the next deploy. Publishing early without a second ask is not the same change."
    )
    assert set(_needs(jobs["site-videos"])) == {"site", "videos"}
    assert "needs.videos.result == 'success'" in jobs["site-videos"]["if"], (
        "the second ask must be conditional on the renders succeeding: a failed render leaves the first publish "
        "standing, and asking anyway would report a publish of videos that do not exist"
    )


def test_both_asks_go_through_one_definition() -> None:
    """Two copies of the dispatch would be two things that know how to publish the site; one would drift."""
    jobs = _spec("release.yml")["jobs"]
    assert jobs["site"].get("uses") == PUBLISH
    assert jobs["site-videos"].get("uses") == PUBLISH
    body = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
    assert "kube-noob-site/dispatches" not in body, (
        "release.yml carries a dispatch of its own again; the reusable workflow is the only place that should "
        "know the endpoint, the payload and what to say when the token is missing"
    )
    assert body.count(PUBLISH) == 2, body.count(PUBLISH)


def test_each_ask_says_what_it_is_for() -> None:
    """Two publishes of one tag are indistinguishable in a log unless each names its reason."""
    jobs = _spec("release.yml")["jobs"]
    first, second = jobs["site"]["with"]["why"], jobs["site-videos"]["with"]["why"]
    assert first and second and first != second, (first, second)
    for job in (jobs["site"], jobs["site-videos"]):
        assert job["with"]["tag"] == "${{ github.ref_name }}"


def test_a_missing_token_fails_loudly_and_is_stated_once() -> None:
    """A publish that never happened must not report success -- the website would sit on the old release."""
    text = (WORKFLOWS / "site-publish.yml").read_text(encoding="utf-8")
    spec = _spec("site-publish.yml")
    assert spec["on"]["workflow_call"]["secrets"]["dispatch-token"]["required"] is True
    assert text.count("::error title=site::no SITE_DISPATCH_TOKEN") == 1
    assert "was never told about" in text and "exit 1" in text
    assert 'if [ "${code}" != "204" ]' in text, "a dispatch that was refused must not pass either"


def test_the_reusable_workflow_is_bounded_and_read_only() -> None:
    spec = _spec("site-publish.yml")
    job = spec["jobs"]["dispatch"]
    assert isinstance(job.get("timeout-minutes"), int) and job["timeout-minutes"] <= 15, job.get("timeout-minutes")
    assert spec["permissions"] == {"contents": "read"}, spec["permissions"]


def test_no_release_job_lost_its_place_in_the_chain() -> None:
    """Splitting one job in two must not reorder what publishes before the release exists."""
    jobs = _spec("release.yml")["jobs"]
    assert set(_needs(jobs["github-release"])) == {"publish-pypi", "image", "demos", "chart"}
    assert _needs(jobs["videos"]) == ["github-release"]
    assert _needs(jobs["publish-pypi"]) == ["build-dist"]
