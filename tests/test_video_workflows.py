"""The videos are built where they must be: a fast check on every change (ci.yml, silent voice), and the 4K masters
with their 1080p copies, captions and description for every release (videos.yml, called by release.yml), rendered
from the release's own code and the sidecar transcript its CI recorded, measured before they are attached."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WF = ROOT / ".github" / "workflows"


def _wf(name: str) -> dict[str, Any]:
    return yaml.safe_load((WF / name).read_text(encoding="utf-8"))  # type: ignore[no-any-return]


def _run(job: dict[str, Any]) -> str:
    return "\n".join(str(s.get("run", "")) for s in job["steps"])


def test_every_action_in_the_video_workflows_is_pinned() -> None:
    for name in ("videos.yml", "ci.yml", "release.yml"):
        for job in _wf(name)["jobs"].values():
            for step in job.get("steps", []):
                uses = step.get("uses", "")
                local = uses.startswith("./")  # this repository's own action
                assert not uses or local or re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", uses), (name, uses)


def test_ci_checks_every_video_on_every_change_without_the_voice_model() -> None:
    job = _wf("ci.yml")["jobs"]["videos"]
    run = _run(job)
    spec = json.loads((ROOT / "demos" / "video" / "stage" / "videos.json").read_text(encoding="utf-8"))
    assert re.search(r"for v in (.+); do", run).group(1).split() == list(spec["videos"])  # type: ignore[union-attr]
    assert "--engine silent" in run and 'capture.js "out/$v" --check' in run and "--stills" in run
    assert "build_scenes.py walkthrough" in run and "thumbnail.js" in run
    assert "tests/fixtures/video-sidecar-transcript.txt" in str(job["steps"])


def test_every_step_of_the_ci_videos_job_is_bounded_on_its_own() -> None:
    """A job timeout is not a diagnosis.

    A run of this job was cancelled at 30m19s with every other check green and no failing step, so the 30 minutes
    said only "something took too long". The whole render takes about 90 seconds on this code, so each step now
    carries its own budget and a hang fails with its own name. The budgets must also leave the job's own limit
    room, or a step timeout would never be the thing that fires.
    """
    job = _wf("ci.yml")["jobs"]["videos"]
    runnable = [s for s in job["steps"] if s.get("run")]
    assert runnable, "the videos job runs commands"
    for step in runnable:
        assert step.get("timeout-minutes"), step.get("name")
    assert sum(int(s["timeout-minutes"]) for s in runnable) <= int(job["timeout-minutes"])


def test_apt_can_neither_prompt_nor_wait_forever_for_the_dpkg_lock() -> None:
    """Both ways apt hangs a runner: a prompt with no tty, and the dpkg lock unattended-upgrades holds.

    A 12-minute step died on one of them. DEBIAN_FRONTEND answers the first and needs `sudo -E`, which plain sudo
    would drop; DPkg::Lock::Timeout answers the second, where apt's default is to wait with no limit.
    """
    steps = _wf("ci.yml")["jobs"]["videos"]["steps"]
    apt = [s for s in steps if "apt-get" in str(s.get("run", ""))]
    assert apt, "the videos job installs ffmpeg"
    for step in apt:
        assert step.get("env", {}).get("DEBIAN_FRONTEND") == "noninteractive", step.get("name")
        assert "sudo -E apt-get" in step["run"], "sudo drops the environment without -E"
        for line in step["run"].splitlines():
            if "apt-get" in line:
                assert "-o DPkg::Lock::Timeout=" in line, line


def test_the_apt_step_survives_a_slow_mirror_and_still_fails_loudly() -> None:
    """A bound that is below the slowest real transfer turns someone else's slow mirror into a red pull request.

    The 4-minute bound this step carried was guessed: the measurements beside it cover pip, npm and the render,
    and the comment itself named apt as the thing they could not measure. Then a run measured it -- on 2026-11-05
    at 21:19Z the Azure Ubuntu mirror served one 13.6 MB package in 62 seconds and the step was killed mid-
    download on a commit whose other 19 checks were green. So the step now skips apt when the runner image
    already ships ffmpeg, lets apt retry a dropped connection, and tries twice. What it must NOT do is pass when
    ffmpeg is still missing: a silent pass here would surface three steps later as a render failure, which is the
    diagnosis problem this job was split up to solve, one step further along.
    """
    steps = _wf("ci.yml")["jobs"]["videos"]["steps"]
    step = next(s for s in steps if s.get("name") == "ffmpeg")
    assert int(step["timeout-minutes"]) >= 8, "below the slowest transfer measured on a real runner"
    run = step["run"]
    assert "command -v ffmpeg" in run, "do not pay for apt when the image already has it"
    assert "Acquire::Retries=" in run, "let apt retry a dropped connection itself"
    assert "for attempt in" in run, "one slow mirror should not be one red build"
    assert run.rstrip().endswith("exit 1"), "the last word of a failed install is a non-zero exit, not a shrug"


def test_the_browser_install_does_not_shell_out_to_apt_again() -> None:
    """`playwright install --with-deps` runs apt inside Playwright's own sudo, where neither the frontend setting
    nor the lock timeout above reaches it. A missing library instead fails the render in seconds, by name."""
    run = _run(_wf("ci.yml")["jobs"]["videos"])
    assert "playwright install chromium" in run and "--with-deps" not in run


def test_every_release_renders_and_attaches_measured_4k_masters() -> None:
    release = _wf("release.yml")["jobs"]["videos"]
    assert release["uses"] == "./.github/workflows/videos.yml" and release["needs"] == "github-release"
    assert release["permissions"] == {"contents": "write", "actions": "read"}
    assert release["with"]["tag"] == "${{ github.ref_name }}"
    videos = _wf("videos.yml")
    jobs = videos["jobs"]
    assert jobs["transcript"]["permissions"]["actions"] == "read" and "sidecar-transcript-4.22" in _run(
        jobs["transcript"]
    )
    spec = json.loads((ROOT / "demos" / "video" / "stage" / "videos.json").read_text(encoding="utf-8"))
    assert set(jobs["render"]["strategy"]["matrix"]["video"]) == {"walkthrough", *spec["videos"]}
    render = _run(jobs["render"])
    assert "KN_VIDEO_SCALE=2" in render and "KN_SCALE=2" in render  # 3840x2160 masters
    assert "scale=1920:1080" in render
    assert "loudness.py --verify dist/*.mp4" in render and ".vtt" in render and "youtube-description.txt" in render
    install = next(s for s in jobs["render"]["steps"] if "pip install" in str(s.get("run", "")))
    assert "./product" in install["run"] and "kube_noob.__version__" in install["run"]  # the tag's own code
    assert all(
        re.search(r"==\d", d) for d in re.findall(r'"(numpy[^"]*|kokoro-onnx[^"]*|onnxruntime[^"]*)"', install["run"])
    )
    assert jobs["attach"]["permissions"] == {"contents": "write"} and "gh release upload" in _run(jobs["attach"])
    assert "SHA256SUMS-videos.txt" in _run(jobs["attach"])
    render_step = next(s for s in jobs["render"]["steps"] if s.get("name") == "Render the 4K master")
    assert render_step["env"]["KN_PRODUCT_ROOT"].endswith("/product")  # the facts describe the tag, not pipeline_ref


def test_one_failed_leg_or_one_red_ci_job_does_not_cost_the_release_its_videos() -> None:
    jobs = _wf("videos.yml")["jobs"]
    # every leg that rendered is attached, and the run still goes red when one did not
    assert "!cancelled()" in jobs["attach"]["if"] and "!cancelled()" in jobs["render"]["if"]
    attach = _run(jobs["attach"])
    assert '"$RENDER" != success' in attach and '"$TRANSCRIPT" != success' in attach
    transcript_dl = [s for s in jobs["render"]["steps"] if "transcript-for-videos" in str(s.get("with", {}))]
    assert [s["if"] for s in transcript_dl] == ["matrix.video == 'sidecar'"]  # only that leg needs the cluster run
    # the transcript: the one kept with the release, else a ci run whose sidecar step passed, of this version
    run = _run(jobs["transcript"])
    assert "gh release download" in run and "-p sidecar-transcript-4.22.txt" in run
    assert 'select(.conclusion == "success")' not in run  # a red unrelated job no longer disqualifies the run
    kind = _wf("ci.yml")["jobs"]["e2e-kind"]
    assert kind["name"].startswith("e2e-kind (OpenShift ") and "4.22" in str(kind["strategy"]["matrix"])
    step = next(s for s in kind["steps"] if "demo_sidecar_kind.sh" in str(s.get("run", "")))
    assert step["name"].startswith("Sidecar under Pod Security") and "Sidecar under Pod Security" in run
    assert 'startswith("e2e-kind (OpenShift 4.22")' in run
    assert "connected to kube_noob_mcp ${TAG#v} at" in run
    assert "transcript-for-videos" in str(jobs["attach"]["steps"])  # attached for re-renders of this tag
    assert "[ -f dist/kube-noob-sidecar-4k.mp4 ]" in attach  # only the one the sidecar video was rendered from
    facts_step = next(s for s in kind["steps"] if str(s.get("name", "")).startswith("The sidecar video's facts"))
    assert facts_step["if"] == "matrix.ocp == '4.22'" and "kube_noob.__version__" in facts_step["run"]
    assert kind["steps"].index(facts_step) > kind["steps"].index(step)  # every ci run checks the new recording


def test_the_playwright_version_is_locked() -> None:
    pkg = json.loads((ROOT / "demos" / "video" / "package.json").read_text(encoding="utf-8"))
    lock = json.loads((ROOT / "demos" / "video" / "package-lock.json").read_text(encoding="utf-8"))
    assert all(re.fullmatch(r"\d+\.\d+\.\d+", v) for v in pkg["devDependencies"].values())
    assert lock["packages"]["node_modules/playwright"]["version"] == pkg["devDependencies"]["playwright"]
    assert all(p.get("integrity", "").startswith("sha512-") for k, p in lock["packages"].items() if k)


def test_only_merged_code_renders_the_videos() -> None:
    """A dispatched run writes to the default branch's cache scope (CodeQL: cache poisoning via execution of untrusted
    code), so the refs typed into the inputs are resolved to commits on the default branch first, and every checkout
    uses those commits."""
    jobs = _wf("videos.yml")["jobs"]
    verify = _run(jobs["verify"])
    assert "^v[0-9]+\\.[0-9]+\\.[0-9]+$" in verify and "inherit_errexit" in verify
    assert "printf '%s' \"$TAG\" | grep" not in verify  # grep matches per line: "v0.6.0\nevil" would pass
    assert '[[ "$TAG" =~ $release ]]' in verify
    # the default branch is compared as the commit the branches API names, never as a bare name a tag could shadow
    assert '/branches/${default}" --jq .commit.sha' in verify and "/compare/${sha}...${default_sha}" in verify
    assert 'pipeline_ref="heads/${default}"' in verify and 'pipeline_ref="refs/tags/${PIPELINE}"' in verify
    assert '"$status" != ahead' in verify and "identical" in verify
    assert jobs["verify"]["permissions"] == {"contents": "read"}
    assert set(jobs["verify"]["outputs"]) == {"product", "pipeline"}
    refs = [s["with"]["ref"] for s in jobs["render"]["steps"] if str(s.get("uses", "")).startswith("actions/checkout")]
    assert refs == ["${{ needs.verify.outputs.pipeline }}", "${{ needs.verify.outputs.product }}"]
    for name in ("transcript", "render", "attach"):
        needs = jobs[name]["needs"]
        assert "verify" in ([needs] if isinstance(needs, str) else needs), name
    assert "needs.verify.result == 'success'" in jobs["render"]["if"] + jobs["attach"]["if"]
    assert "${{ needs.verify.outputs.product }}" in str(jobs["transcript"]["steps"][0]["env"])


def test_no_workflow_checks_out_a_ref_typed_into_its_inputs() -> None:
    for path in sorted(WF.glob("*.yml")):
        for job in (yaml.safe_load(path.read_text(encoding="utf-8")).get("jobs") or {}).values():
            for step in job.get("steps", []):
                if str(step.get("uses", "")).startswith("actions/checkout"):
                    ref = str((step.get("with") or {}).get("ref", ""))
                    assert "inputs." not in ref.replace("inputs.default_branch", ""), (path.name, ref)
    assert _wf("release.yml")["jobs"]["brew"]["with"] == {"default_branch": True}


#: An ffprobe that answers honestly for whichever `-of` format the script asks for. Both spellings are real:
#: `default=nw=1:nk=1` prints one value per line, `csv=p=0` prints them comma-joined -- with a trailing comma on
#: some builds, which was the whole of G388's cause. A size check worth having gets the same answer from either.
_FFPROBE_STUB = r"""#!/bin/sh
w=3840; h=2160
for a in "$@"; do case "$a" in *1080p*) w=1920; h=1080 ;; esac; done
case " $* " in
  *default=nw=1:nk=1*) printf '%s\n%s\n' "$w" "$h" ;;
  *csv=p=0*)           printf '%s,%s,\n' "$w" "$h" ;;
  *)                   printf '%s,%s\n' "$w" "$h" ;;
esac
"""


def _size_check_script() -> str:
    """The lines of the render step that decide whether the master is 4K, as a runnable script."""
    lines = _run(_wf("videos.yml")["jobs"]["render"]).splitlines()
    start = next(
        (i for i, ln in enumerate(lines) if "ffprobe" in ln and "-4k.mp4" in "".join(lines[i : i + 2])),
        None,
    )
    assert start is not None, "no ffprobe call reads the 4k master, so nothing checks the master's size"
    # To the end of the block, not to a closing brace: the check's SHAPE is the workflow's business, and an
    # extractor tied to one shape crashes on another instead of running it (which is how a reverted check
    # would have escaped with a StopIteration rather than a verdict).
    end = next((i for i in range(start, len(lines)) if lines[i].lstrip().startswith("ls -l")), len(lines))
    return "\n".join(lines[start:end])


@pytest.mark.parametrize(
    ("size", "code"), [("4k", 0), ("1080p", 1)], ids=["a-4k-master-passes", "a-1080p-file-is-rejected"]
)
def test_the_size_check_is_run_not_read(size: str, code: int, tmp_path: Path) -> None:
    """Execute the check; do not look at how it is spelled.

    The version that shipped with G388 asserted `"3840" in render and "2160" in render`. Both numbers appear in
    the COMMENT that commit added to the step, so deleting the comparison itself left the test green -- measured
    as `1 passed`. It replaced one spelling assertion with another and was called proved on the single mutation
    it happened to survive.
    """
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "ffprobe").write_text(_FFPROBE_STUB, encoding="utf-8")
    (bindir / "ffprobe").chmod(0o755)
    (tmp_path / "dist").mkdir()
    body = _size_check_script()
    if size != "4k":
        body = body.replace("-4k.mp4", "-1080p.mp4")  # the stub answers 1080p for that name
    script = tmp_path / "check.sh"
    script.write_text(body, encoding="utf-8")
    out = subprocess.run(
        [shutil.which("bash") or "/bin/bash", str(script)],
        cwd=tmp_path,
        env={**os.environ, "PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}", "VIDEO": "teaser"},
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert out.returncode == code, f"stdout={out.stdout!r} stderr={out.stderr!r}"


def test_every_video_the_release_renders_is_one_build_sh_accepts(tmp_path: Path) -> None:
    """G414: #125 added `scan` to videos.json and to the release matrix, and `build.sh` kept its own list of three.
    The release leg `render (scan)` calls `build.sh out scan`, which stopped on "unknown video: scan" -- from the
    tag's own copy of the file, so no re-run could fix it -- and no CI job runs `build.sh`. Asked of the script
    itself: every name in the release matrix but the walkthrough (rendered by render.sh) must be one it accepts."""
    bash = shutil.which("bash")
    assert bash, "bash is not on PATH, so build.sh could not be asked"
    wf = yaml.safe_load((ROOT / ".github" / "workflows" / "videos.yml").read_text(encoding="utf-8"))
    matrix = wf["jobs"]["render"]["strategy"]["matrix"]["video"]
    staged = [v for v in matrix if v != "walkthrough"]
    assert "scan" in staged and "walk" in staged, matrix
    out = subprocess.run(
        [bash, str(ROOT / "demos" / "video" / "stage" / "build.sh"), str(tmp_path / "out"), "not-a-video"],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert out.returncode == 2, out.stderr
    known = re.search(r"\(known: ([^)]*)\)", out.stderr)
    assert known, out.stderr
    accepted = set(known.group(1).split())
    assert accepted == set(json.loads((ROOT / "demos/video/stage/videos.json").read_text(encoding="utf-8"))["videos"])
    missing = [v for v in staged if v not in accepted]
    assert not missing, f"the release renders {missing}, which build.sh refuses"


def test_the_release_ffmpeg_install_is_its_own_bounded_step() -> None:
    """G417: inline with pip and Playwright, the install was bounded only by the leg's 240 minutes."""
    wf = yaml.safe_load((ROOT / ".github" / "workflows" / "videos.yml").read_text(encoding="utf-8"))
    steps = wf["jobs"]["render"]["steps"]
    ff = [s for s in steps if s.get("name") == "ffmpeg"]
    assert len(ff) == 1, [s.get("name") for s in steps]
    assert 0 < ff[0]["timeout-minutes"] <= 30
    assert "for attempt in 1 2" in ff[0]["run"]
    others = "\n".join(str(s.get("run", "")) for s in steps if s.get("name") != "ffmpeg")
    assert "apt-get install" not in others or "ffmpeg" not in others.split("apt-get install", 1)[1].split("\n", 1)[0]


def test_a_push_to_main_does_not_cancel_the_run_the_tag_needs() -> None:
    """G418: the release reads the sidecar transcript from the tagged commit's CI run."""
    ci = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
    cancel = str(ci["concurrency"]["cancel-in-progress"])
    assert cancel.replace(" ", "") == "${{github.event_name=='pull_request'}}", cancel
