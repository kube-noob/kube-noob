"""kube-noob.com could not rebuild itself for six days and the watchdog was green for all of it.

Every scheduled deploy in kube-noob-site failed from 2026-11-17 to 2026-11-23 -- twelve runs in a row, on
`ImportError: cannot import name 'render_text' from 'kube_noob.debug.diagnose'`, because the site's generator had
started using a symbol that was on the product's `main` and in no release, while the site builds from the latest
release. `git tag --contains` puts that symbol first in v0.10.0.

`site-sync`'s `drift` job ran every six hours through all of it and reported success every time. It is not broken:
it asks whether the published site is behind the latest release, and the answer was no. The site served v0.9.2 and
v0.9.2 WAS the latest release. **Equality held by stagnation is indistinguishable from equality held by a working
system**, so a site that could not build at all was invisible for as long as nothing was released -- and the
workflow's own header claimed that "a deploy that breaks ... shows up as a red run here".

The `deploys` job measures the mechanism rather than the gap: it reads the site's own deploy conclusions and fails
when the last one failed, whatever the two versions say. And when it cannot read them -- a token without
Actions: read -- it fails, because a watchdog that cannot see the thing it watches has not found it healthy (G358).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
SYNC = WORKFLOWS / "site-sync.yml"


def _spec() -> dict[str, Any]:
    spec: dict[str, Any] = yaml.safe_load(SYNC.read_text(encoding="utf-8"))
    if True in spec and "on" not in spec:  # YAML 1.1 reads a bare `on:` key as the boolean True
        spec["on"] = spec.pop(True)
    return spec


def _script(job: str) -> str:
    return "\n".join(str(s.get("run", "")) for s in _spec()["jobs"][job]["steps"])


def test_a_job_reads_the_sites_own_deploy_history() -> None:
    jobs = _spec()["jobs"]
    assert "deploys" in jobs, (
        "nothing reads whether the site's last deploy succeeded. drift compares the published version with the "
        "latest release, and between releases those agree even while the site cannot build at all -- twelve "
        "consecutive failures were invisible that way."
    )
    script = _script("deploys")
    assert "actions/workflows/deploy.yml/runs" in script and "${SITE_REPO}" in script
    assert "status=completed" in script, "an in-progress run is not a verdict about the last one"


def test_a_failed_deploy_fails_this_workflow_whatever_the_versions_say() -> None:
    script = _script("deploys")
    assert "::error title=site-sync::the last deploy of" in script
    assert "exit 1" in script
    for phrase in ("cannot replace it", "drift does not catch this between releases"):
        assert phrase in script, f"the error must explain why drift stayed green: missing {phrase!r}"
    tail = script[script.index('case "${conclusion}"') :]
    assert tail.count("exit 0") == 2, "only success and skipped may pass"
    assert "success)" in tail and "skipped)" in tail


def test_not_being_able_to_look_is_a_failure_and_names_the_scope() -> None:
    """The defect this whole project refuses, pointed at the watchdog: unknown must not read as healthy."""
    script = _script("deploys")
    assert "Actions: read" in script, "a permission error must name the scope that is missing"
    assert "Not being able to look is not the same as nothing being wrong." in script
    assert "it is simply unknown" in script, "a missing token must not read as a healthy site"
    assert "no completed deploy runs at all" in script, "an empty history is an unanswered question"
    # Three distinct refusals, each with its own exit 1: no token, a non-200 read, and an empty history.
    head = script[: script.index('case "${conclusion}"')]
    assert head.count("exit 1") == 3, head.count("exit 1")
    assert "exit 0" not in head, "no path before the conclusion is known may pass"


def test_drift_is_unchanged_and_still_passes_on_equality() -> None:
    """This adds a question; it must not weaken the one that was already right."""
    drift = _script("drift")
    assert "build.json" in drift and "GRACE_MINUTES" in drift
    assert "at or past release" in drift, "the ahead-of-release case stays a pass"
    assert "non-release ref" in drift, "the branch-build case stays handled"
    assert "still serves" in drift and "exit 1" in drift


def test_the_header_claims_only_what_the_jobs_do() -> None:
    """The old header said a broken deploy 'shows up as a red run here'. For twelve runs it did not."""
    header = SYNC.read_text(encoding="utf-8").split("on:", 1)[0]
    assert "deploys fails when the site's own most recent deploy FAILED" in header
    assert "twelve runs in a row" in header, "the header should carry the measurement, not a claim"
    for job in ("notify", "drift", "deploys"):
        assert f"#   {job}" in header or f"#   {job} " in header, f"{job} is undocumented in the header"
        assert job in _spec()["jobs"]


def test_the_watchdog_still_cannot_write_to_this_repository() -> None:
    spec = _spec()
    assert spec["permissions"] == {"contents": "read"}
    uses = [str(step.get("uses", "")) for job in spec["jobs"].values() for step in job["steps"]]
    assert not [u for u in uses if u.startswith("actions/checkout")], uses
