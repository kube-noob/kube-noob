"""The three CI wrappers carry every exit the gate has, and merge status is not evidence status (G291).

action.yml wrote `result=passed` for exit 0, `result=failed` for exit 1 and nothing for 2, 3, 4 or 5. A gate that
could not read its inputs (2), was incomplete (5) or crashed (4) left `steps.gate.outputs.result` empty, and a
workflow that gates on `result == 'failed'` let the change through. The Tekton Task wrote `failed` for every
non-zero code, so a crash read as policy violations. The GitLab template wrote nothing a later job could read.

The shell the three wrappers run is now one script, scripts/ci/gate.sh, driven here with a stub `kube-noob` that
exits 0..5 (and a code the contract does not name) and prints the report shapes. The wrappers only wire it: the
action calls the file, the Tekton Task and the GitLab template carry a copy that scripts/ci_wrappers.py --check
holds byte-for-byte against the script.
"""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ci" / "gate.sh"
SYNC = ROOT / "scripts" / "ci_wrappers.py"

STUB = r"""#!/bin/sh
# A kube-noob that does what KN_STUB_RC says and writes what the real gate writes for that exit.
printf '%s\n' "$@" > "$KN_STUB_ARGS"
sarif=; summary=
while [ $# -gt 0 ]; do
  case "$1" in
    --sarif) sarif=$2; shift ;;
    --summary) summary=$2; shift ;;
    --github-annotations) ann=1 ;;
  esac
  shift
done
case "$KN_STUB_RC" in
  0|1|5)
    printf '{"runs":[]}\n' > "$sarif"
    if [ "$KN_STUB_RC" = 1 ]; then v=failed; else v=passed; fi
    printf '## kube-noob gate %s\n\n1 manifest file(s) checked.\n\n### Not run\n\n- x\n' "$v" > "$summary"
    if [ -n "$ann" ]; then printf '::warning file=a.yaml,line=1::KN-S001 a finding\n'; fi
    cat "$KN_STUB_JSON"
    ;;
  2) printf 'error: no such file: missing.yaml\n' >&2 ;;
  3) printf 'clarification needed\n' >&2 ;;
  4) printf 'error: kube-noob: boom\n' >&2 ;;
esac
exit "$KN_STUB_RC"
"""


def _report(**over: object) -> dict[str, object]:
    base: dict[str, object] = {
        "passed": True,
        "failures": [],
        "counts": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
        "unreadable": [],
        "notRun": [],
    }
    base.update(over)
    return base


def _run(
    tmp_path: Path, rc: int, report: object, *, env: dict[str, str] | None = None, python_ok: bool = True
) -> tuple[subprocess.CompletedProcess[str], dict[str, Path]]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    stub = bin_dir / "kube-noob"
    stub.write_text(STUB, encoding="utf-8")
    stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
    if python_ok:
        if not (bin_dir / "python3").exists():
            (bin_dir / "python3").symlink_to(sys.executable)
    else:
        broken = bin_dir / "python3"
        broken.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        broken.chmod(broken.stat().st_mode | stat.S_IXUSR)
    work = tmp_path / "work"
    work.mkdir(exist_ok=True)
    report_in = tmp_path / "stub-report.json"
    report_in.write_text(report if isinstance(report, str) else json.dumps(report), encoding="utf-8")
    sinks = {
        "github_output": tmp_path / "github-output",
        "step_summary": tmp_path / "step-summary.md",
        "dotenv": tmp_path / "kube-noob.env",
        "result": tmp_path / "tekton-result",
        "exit": tmp_path / "tekton-exit",
        "evidence": tmp_path / "tekton-evidence",
        "because": tmp_path / "tekton-because",
        "counts": tmp_path / "tekton-counts",
        "args": tmp_path / "stub-args",
    }
    for p in sinks.values():
        if p.exists():
            p.unlink()
    full = {
        "PATH": f"{bin_dir}:/usr/bin:/bin",
        "KN_STUB_RC": str(rc),
        "KN_STUB_JSON": str(report_in),
        "KN_STUB_ARGS": str(sinks["args"]),
        "KN_PATHS": "k8s",
        "KN_PLATFORM": "openshift",
        "KN_VERSION": "4.20",
        "KN_FAIL_ON": "high",
        "KN_WORK": str(work),
        "KN_SARIF": str(work / "kube-noob.sarif"),
        "KN_SUMMARY": str(work / "kube-noob-summary.md"),
        "KN_REPORT": str(work / "kube-noob-gate.json"),
        "GITHUB_OUTPUT": str(sinks["github_output"]),
        "GITHUB_STEP_SUMMARY": str(sinks["step_summary"]),
        "KN_DOTENV": str(sinks["dotenv"]),
        "KN_RESULT_PATH": str(sinks["result"]),
        "KN_EXIT_PATH": str(sinks["exit"]),
        "KN_EVIDENCE_PATH": str(sinks["evidence"]),
        "KN_BECAUSE_PATH": str(sinks["because"]),
        "KN_COUNTS_PATH": str(sinks["counts"]),
    }
    full.update(env or {})
    proc = subprocess.run(["/bin/sh", str(SCRIPT)], check=False, env=full, capture_output=True, text=True, cwd=tmp_path)
    return proc, sinks


def _outputs(sinks: dict[str, Path]) -> dict[str, str]:
    """GITHUB_OUTPUT, the dotenv and the Tekton result files, which must all say the same thing."""
    gh = dict(line.split("=", 1) for line in sinks["github_output"].read_text(encoding="utf-8").splitlines())
    dotenv = dict(line.split("=", 1) for line in sinks["dotenv"].read_text(encoding="utf-8").splitlines())
    tekton = {k: sinks[k].read_text(encoding="utf-8") for k in ("result", "exit", "evidence", "because", "counts")}
    assert dotenv == {
        "KUBE_NOOB_RESULT": gh["result"],
        "KUBE_NOOB_EXIT": gh["exit-code"],
        "KUBE_NOOB_EVIDENCE": gh["evidence"],
        "KUBE_NOOB_BECAUSE": gh["because"],
    }
    assert tekton["result"] == gh["result"] and tekton["exit"] == gh["exit-code"]
    assert tekton["evidence"] == gh["evidence"] and tekton["because"] == gh["because"]
    return gh


RESULTS = {
    0: "passed",
    1: "failed",
    2: "config-error",
    3: "clarification",
    4: "internal-error",
    5: "evidence-incomplete",
}


@pytest.mark.parametrize("rc", sorted(RESULTS))
def test_every_exit_code_names_its_result_and_nothing_is_left_unset(tmp_path: Path, rc: int) -> None:
    report = _report(unreadable=[{"file": "k8s/a.yaml", "why": "permission denied"}]) if rc == 5 else _report()
    proc, sinks = _run(tmp_path, rc, report)
    assert proc.returncode == rc, proc.stderr
    out = _outputs(sinks)
    assert out["result"] == RESULTS[rc] and out["exit-code"] == str(rc)
    assert set(out) == {"result", "exit-code", "evidence", "because"}
    if rc in (0, 1):
        assert out["evidence"] == "complete" and out["because"] == ""
    elif rc == 5:
        assert out["evidence"] == "incomplete" and out["because"] == "k8s/a.yaml could not be read"
    else:
        assert out["evidence"] == "not-run" and out["because"] == "the gate wrote no report"


def test_a_code_the_contract_does_not_name_is_an_internal_error_with_its_number(tmp_path: Path) -> None:
    """An OOM kill (137), a missing binary (127) or SIGPIPE (141) must not leave the result empty either."""
    proc, sinks = _run(tmp_path, 137, _report())
    assert proc.returncode == 137
    out = _outputs(sinks)
    assert out == {
        "result": "internal-error",
        "exit-code": "137",
        "evidence": "not-run",
        "because": "the gate wrote no report",
    }


def test_the_bytes_of_every_sink_for_a_pass_whose_evidence_is_incomplete(tmp_path: Path) -> None:
    """A manifest-only gate at fail-on never: merge allowed, but three checks did not run. Byte-for-byte."""
    report = _report(notRun=["Containerfile audit: pass a build file with --containerfile", "code checks: pass SARIF"])
    proc, sinks = _run(tmp_path, 0, report, env={"KN_FAIL_ON": "never"})
    assert proc.returncode == 0, proc.stderr
    because = "Containerfile audit: pass a build file with --containerfile; code checks: pass SARIF"
    assert sinks["github_output"].read_text(encoding="utf-8") == (
        f"result=passed\nexit-code=0\nevidence=incomplete\nbecause={because}\n"
    )
    assert sinks["dotenv"].read_text(encoding="utf-8") == (
        f"KUBE_NOOB_RESULT=passed\nKUBE_NOOB_EXIT=0\nKUBE_NOOB_EVIDENCE=incomplete\nKUBE_NOOB_BECAUSE={because}\n"
    )
    assert sinks["result"].read_text() == "passed" and sinks["exit"].read_text() == "0"
    assert sinks["evidence"].read_text() == "incomplete" and sinks["because"].read_text() == because
    assert sinks["counts"].read_text() == '{"critical": 0, "high": 1, "info": 0, "low": 0, "medium": 0}'


def test_the_step_summary_never_says_passed_beside_incomplete_evidence(tmp_path: Path) -> None:
    report = _report(notRun=["vulnerability checks: pass the images' scanner output with --scanner-report"])
    proc, sinks = _run(tmp_path, 0, report)
    summary = sinks["step_summary"].read_text(encoding="utf-8")
    assert "passed" not in summary and "passed" not in proc.stdout
    head = (
        "## kube-noob gate: merge allowed · evidence: incomplete "
        "(`vulnerability checks: pass the images' scanner output with --scanner-report`)"
    )
    assert summary.startswith(head + "\n\n")
    assert proc.stdout.startswith(head + "\n\n")
    assert "1 manifest file(s) checked." in summary and "### Not run" in summary, "the gate's own summary follows"
    assert "## kube-noob gate passed" not in summary


def test_a_complete_pass_and_a_failure_keep_their_words(tmp_path: Path) -> None:
    proc, sinks = _run(tmp_path, 0, _report())
    assert (
        sinks["step_summary"]
        .read_text(encoding="utf-8")
        .startswith("## kube-noob gate: merge allowed · evidence: complete\n\n1 manifest")
    )
    proc, sinks = _run(tmp_path, 1, _report(passed=False, failures=["2 finding(s) at high or above"]))
    text = sinks["step_summary"].read_text(encoding="utf-8")
    assert text.startswith("## kube-noob gate failed (exit 1): merge blocked · evidence: complete\n\n1 manifest")
    assert "kube-noob gate failed" in proc.stdout, "ci.yml greps the GitLab log for these words"
    proc, sinks = _run(tmp_path, 2, _report())
    assert sinks["step_summary"].read_text(encoding="utf-8") == (
        "## kube-noob gate config-error (exit 2): merge blocked · evidence: not-run (`the gate wrote no report`)\n\n"
    )


@pytest.mark.parametrize(
    ("report", "evidence", "because"),
    [
        ('{"notRun": []}', "complete", ""),
        ("{}", "not-run", "the report has no notRun list"),
        ('{"notRun": "all"}', "not-run", "the report has no notRun list"),
        ("[]", "not-run", "the report is not an object"),
        ("not json {", "not-run", "the report is not JSON"),
        ("", "not-run", "the gate wrote no report"),
        ('{"notRun": [], "knownIssuesVerdict": "not-determined"}', "incomplete", "reported issues: not-determined"),
        ('{"notRun": [], "knownIssuesVerdict": "assessed"}', "complete", ""),
        ('{"notRun": [], "requiredEvaluated": false}', "incomplete", "required checks: not all evaluated"),
        ('{"notRun": [], "requiredEvaluated": true}', "complete", ""),
        (
            '{"notRun": [], "unreadable": [{"file": "b.yaml"}, {"file": "a.yaml"}]}',
            "incomplete",
            "b.yaml could not be read; a.yaml could not be read",
        ),
    ],
)
def test_evidence_is_read_from_the_report_and_a_missing_key_is_not_run(
    tmp_path: Path, report: str, evidence: str, because: str
) -> None:
    """`complete` is never assumed: a report without the key, a report that is not an object, no report."""
    _, sinks = _run(tmp_path, 0, report)
    out = _outputs(sinks)
    assert (out["result"], out["evidence"], out["because"]) == ("passed", evidence, because)


def test_a_report_the_helper_cannot_read_still_sets_every_output(tmp_path: Path) -> None:
    """python3 missing or broken on the runner: the result still comes from the exit code; evidence is not-run."""
    proc, sinks = _run(tmp_path, 0, _report(), python_ok=False)
    assert proc.returncode == 0, proc.stderr
    out = _outputs(sinks)
    assert out == {
        "result": "passed",
        "exit-code": "0",
        "evidence": "not-run",
        "because": "the gate report could not be read",
    }
    assert sinks["counts"].read_text() == "{}"
    assert "passed" not in sinks["step_summary"].read_text(encoding="utf-8")


def test_an_input_derived_reason_cannot_forge_an_output_or_a_workflow_command(tmp_path: Path) -> None:
    alm, shy = chr(0x61C), chr(0xAD)  # Arabic letter mark, soft hyphen: invisible, so ruff refuses them literal
    hostile = f"k8s/a\n::set-output name=result::failed\nresult=failed{alm}{shy}.yaml"
    report = _report(unreadable=[{"file": hostile, "why": "x"}])
    proc, sinks = _run(tmp_path, 5, report)
    gh = sinks["github_output"].read_text(encoding="utf-8")
    assert gh.count("\n") == 4 and sum(1 for line in gh.splitlines() if line.startswith("result=")) == 1, gh
    out = _outputs(sinks)
    assert "::" not in out["because"] and alm not in out["because"] and shy not in out["because"]
    assert out["because"] == "k8s/a : :set-output name=result: :failed result=failed .yaml could not be read"
    assert "::set-output" not in proc.stdout and "::set-output" not in sinks["step_summary"].read_text(encoding="utf-8")


def test_the_arguments_the_action_used_to_build_are_the_ones_the_script_builds(tmp_path: Path) -> None:
    env = {
        "KN_PATHS": "a.yaml k8s",
        "KN_CHART": "chart",
        "KN_VALUES": "v1.yaml v2.yaml",
        "KN_NAMESPACE": "shop",
        "KN_CONTAINERFILES": "Containerfile=img:1",
        "KN_SCANNER_REPORTS": "trivy.json",
        "KN_VEX": "vex",
        "KN_KEV": "kev.json",
        "KN_TRUST_REPORT_VEX": "true",
        "KN_SARIF_REPORTS": "s1.sarif s2.sarif",
        "KN_EXCEPTIONS": "ex.yaml",
        "KN_ANNOTATIONS": "true",
        "KN_CODEQUALITY": "gl.json",
    }
    _, sinks = _run(tmp_path, 0, _report(), env=env)
    args = sinks["args"].read_text(encoding="utf-8").splitlines()
    work = tmp_path / "work"
    assert args == [
        "gate", "--platform", "openshift", "--fail-on", "high", "--namespace", "shop",
        "-f", "a.yaml", "-f", "k8s", "--chart", "chart", "--values", "v1.yaml", "--values", "v2.yaml",
        "--containerfile", "Containerfile=img:1", "--scanner-report", "trivy.json", "--vex", "vex", "--kev", "kev.json",
        "--trust-report-vex", "--sarif-report", "s1.sarif", "--sarif-report", "s2.sarif", "--version", "4.20",
        "--exceptions", "ex.yaml", "--github-annotations",
        "--sarif", str(work / "kube-noob.sarif"), "--summary", str(work / "kube-noob-summary.md"),
        "--codequality", "gl.json", "--format", "json",
    ]  # fmt: skip
    proc, sinks = _run(tmp_path, 0, _report(), env={"KN_ANNOTATIONS": "true"})
    assert proc.stdout.startswith("::warning file=a.yaml,line=1::KN-S001 a finding\n"), "annotations reach the log"
    body = json.loads((tmp_path / "work" / "kube-noob-gate.json").read_text(encoding="utf-8"))
    assert body["notRun"] == [], "and the report file holds no workflow command"
    _, sinks = _run(tmp_path, 0, _report(), env={"KN_ANNOTATIONS": "false"})
    assert "--github-annotations" not in sinks["args"].read_text(encoding="utf-8")
    _, sinks = _run(tmp_path, 0, _report())
    assert "--github-annotations" not in sinks["args"].read_text(encoding="utf-8"), "unset (Tekton, GitLab) is off"


def test_a_sink_that_is_not_configured_is_simply_not_written(tmp_path: Path) -> None:
    off = ("GITHUB_OUTPUT", "GITHUB_STEP_SUMMARY", "KN_DOTENV", "KN_RESULT_PATH", "KN_EXIT_PATH")
    off += ("KN_EVIDENCE_PATH", "KN_BECAUSE_PATH", "KN_COUNTS_PATH")
    proc, sinks = _run(tmp_path, 1, _report(passed=False), env=dict.fromkeys(off, ""))
    assert proc.returncode == 1
    assert not any(sinks[k].exists() for k in ("github_output", "step_summary", "dotenv", "result", "counts"))
    assert proc.stdout.startswith("## kube-noob gate failed (exit 1): merge blocked · evidence: complete\n")


# -- the wrappers only wire the script ---------------------------------------------------------------------------


def test_the_github_action_calls_the_script_and_declares_every_output() -> None:
    action = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
    gate = next(s for s in action["runs"]["steps"] if s.get("id") == "gate")
    assert gate["run"].strip() == 'sh "$GITHUB_ACTION_PATH/scripts/ci/gate.sh"'
    assert {"KN_WORK", "KN_SARIF", "KN_SUMMARY", "KN_REPORT", "KN_ANNOTATIONS"} <= set(gate["env"])
    outs = action["outputs"]
    assert set(outs) == {"result", "exit-code", "evidence", "because", "sarif"}
    for name in ("result", "exit-code", "evidence", "because"):
        assert outs[name]["value"] == f"${{{{ steps.gate.outputs.{name} }}}}"
    assert "config-error" in outs["result"]["description"] and "evidence-incomplete" in outs["result"]["description"]
    assert "not-run" in outs["evidence"]["description"]


def _sync(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(SYNC), *args], check=False, capture_output=True, text=True, cwd=ROOT)


def test_the_tekton_task_and_the_gitlab_template_carry_the_script_verbatim() -> None:
    proc = _sync("--check")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    task = yaml.safe_load((ROOT / "deploy" / "tekton" / "kube-noob-gate.yaml").read_text(encoding="utf-8"))
    assert {r["name"] for r in task["spec"]["results"]} == {"result", "exit-code", "evidence", "because", "counts"}
    step = task["spec"]["steps"][0]["script"]
    for name in ("result", "exit-code", "evidence", "because", "counts"):
        assert f"$(results.{name}.path)" in step
    gl = yaml.safe_load((ROOT / "deploy" / "gitlab" / "kube-noob-gate.gitlab-ci.yml").read_text(encoding="utf-8"))
    job = gl[".kube-noob-gate"]
    assert job["artifacts"]["reports"]["dotenv"] == "kube-noob.env"
    assert "KN_DOTENV=kube-noob.env" in job["script"][0]
    assert "KN_CODEQUALITY=gl-code-quality-report.json" in job["script"][0]
    body = SCRIPT.read_text(encoding="utf-8").split("\n", 1)[1]
    assert body in step and body in job["script"][0]
    assert "${" not in body and "$(" not in body, "POSIX sh, and nothing Tekton would substitute"


def test_the_sync_script_refuses_a_stale_copy(tmp_path: Path) -> None:
    proc = _sync("--check", "--root", str(tmp_path))
    assert proc.returncode != 0
    copies = ("deploy/tekton/kube-noob-gate.yaml", "deploy/gitlab/kube-noob-gate.gitlab-ci.yml", "scripts/ci/gate.sh")
    for rel in copies:
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text((ROOT / rel).read_text(encoding="utf-8"), encoding="utf-8")
    sh = tmp_path / "scripts" / "ci" / "gate.sh"
    sh.write_text(sh.read_text(encoding="utf-8") + "echo drift\n", encoding="utf-8")
    proc = _sync("--check", "--root", str(tmp_path))
    assert proc.returncode == 1 and "stale" in proc.stdout + proc.stderr
    assert _sync("--root", str(tmp_path)).returncode == 0
    assert _sync("--check", "--root", str(tmp_path)).returncode == 0
    assert "echo drift" in (tmp_path / "deploy/tekton/kube-noob-gate.yaml").read_text(encoding="utf-8")


def test_ci_runs_the_wrapper_sync_check() -> None:
    ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "scripts/ci_wrappers.py --check" in ci
    assert "scripts/ci_wrappers.py --check" in (ROOT / "scripts/check.sh").read_text(encoding="utf-8")
    assert os.access(SCRIPT, os.X_OK)


# -- round-1 review (G291) ---------------------------------------------------------------------------------------


def test_a_skipped_input_is_a_gap_in_the_gate_report_and_in_the_wrapper(tmp_path: Path) -> None:
    """pod.yaml beside an unrendered chart: the template was never audited, so neither the gate's own `notRun`
    nor the wrapper's `evidence` may say complete, and both name the template (review finding 1)."""
    from kube_noob import gate

    d = tmp_path / "dir3"
    (d / "chart" / "templates").mkdir(parents=True)
    pod = "apiVersion: v1\nkind: Pod\nmetadata: {name: p, namespace: n}\n"
    pod += "spec:\n  containers:\n  - {name: c, image: i}\n"
    (d / "pod.yaml").write_text(pod, encoding="utf-8")
    (d / "chart" / "Chart.yaml").write_text("apiVersion: v2\nname: c\nversion: 0.1.0\n", encoding="utf-8")
    template = "apiVersion: v1\nkind: Pod\n{{- if .Values.x }}\n"
    (d / "chart" / "templates" / "p.yaml").write_text(template, encoding="utf-8")
    rep = gate.run(gate.collect([str(d)], lambda p: Path(p).read_text(encoding="utf-8")), fail_on="never")
    assert any("templates/p.yaml" in n and "Helm template" in n for n in rep["notRun"]), rep["notRun"]
    assert any("Chart.yaml" in n for n in rep["notRun"]), rep["notRun"]
    # and through the wrapper, with the real binary
    real = {"PATH": f"{Path(sys.executable).parent}:/usr/bin:/bin", "KN_PATHS": str(d), "KN_FAIL_ON": "never"}
    _run(tmp_path, 0, _report(), env=real)  # writes the stub; the real binary is first on PATH from here on
    (tmp_path / "bin" / "kube-noob").unlink()
    proc, sinks = _run(tmp_path, 0, _report(), env=real)
    assert proc.returncode == 0, proc.stderr
    out = _outputs(sinks)
    assert out["result"] == "passed" and out["evidence"] == "incomplete"
    assert "templates/p.yaml" in out["because"] and "Helm template" in out["because"], out["because"]


def test_markdown_in_a_file_name_cannot_render_in_the_step_summary(tmp_path: Path) -> None:
    """The reviewer's file name: an image, a link, a mention, an HTML tag, a code span, a table pipe and an
    unterminated comment that would swallow the rest of the summary (finding 2). The headline carries the reason
    inside a code span with backticks removed, so Markdown and HTML in it are text; the plain sinks keep plain text."""
    name = "![x](https://evil.example/p.png)[click](https://evil.example) @octocat"
    name += " <img src=x onerror=1> `tick` | pipe <!-- hide"
    proc, sinks = _run(tmp_path, 0, _report(unreadable=[{"file": name, "why": "x"}]))
    head = proc.stdout.splitlines()[0]
    summary = sinks["step_summary"].read_text(encoding="utf-8")
    assert head.startswith("## kube-noob gate: merge allowed · evidence: incomplete (`") and head.endswith("`)")
    inner = head.split("(`", 1)[1][:-2]
    assert "`" not in inner and "\n" not in inner
    assert "<!--" not in inner and "<img" not in inner and "![" not in inner and "\\](" in inner, inner
    assert summary.startswith(head + "\n") and "### Not run" in summary, "nothing after the headline is swallowed"
    out = _outputs(sinks)
    assert out["because"].startswith("\\!\\[x\\](https://evil.example/p.png)") and "&lt;img" in out["because"]
    assert "\\`tick\\`" in out["because"], "escaped in the plain sinks, as gate.py's _cell escapes it"


def test_the_wrapper_escapes_markdown_with_the_gate_s_own_table() -> None:
    from kube_noob.gate import _MD_ESCAPE

    text = SCRIPT.read_text(encoding="utf-8")
    assert 'ESCAPE = {"&": "&amp;", "<": "&lt;", ">": "&gt;", "|": "\\\\|"}' in text
    assert 'for c in "\\\\`*_[]!#~":' in text
    table = {"&": "&amp;", "<": "&lt;", ">": "&gt;", "|": "\\|"} | {c: "\\" + c for c in "\\`*_[]!#~"}
    assert table == _MD_ESCAPE


@pytest.mark.parametrize(
    ("report", "because"),
    [
        ('{"notRun": [], "unreadable": ["x.yaml"]}', "unreadable: unrecognised shape"),
        ('{"notRun": [], "unreadable": "x.yaml"}', "unreadable: unrecognised shape"),
        ('{"notRun": [], "unreadable": [{"path": "x.yaml"}]}', "unreadable: unrecognised shape"),
        ('{"notRun": [null, {"a": 1}, "::error::x\\nline2", 5]}', "None; {'a': 1}; : :error: :x line2; 5"),
        ('{"notRun": [], "knownIssuesVerdict": "Not-Determined"}', "reported issues: not-determined"),
        ('{"notRun": [], "knownIssuesVerdict": 7}', "knownIssuesVerdict: unrecognised shape"),
        ('{"notRun": [], "requiredEvaluated": null}', "required checks: not all evaluated"),
        ('{"notRun": [], "requiredEvaluated": "false"}', "required checks: not all evaluated"),
    ],
)
def test_an_unrecognised_shape_is_never_complete(tmp_path: Path, report: str, because: str) -> None:
    """Finding 7: a list that is not a list of dicts, a verdict in another case, a flag that is not True."""
    _, sinks = _run(tmp_path, 0, report)
    out = _outputs(sinks)
    assert (out["evidence"], out["because"]) == ("incomplete", because)


def test_the_forward_looking_keys_are_read_when_a_gate_emits_them(tmp_path: Path) -> None:
    """knownIssuesVerdict and requiredEvaluated are written by the fix/live-false-passes work (G284/G290); a stub
    that emits them is read today, and their absence is not a gap."""
    _, sinks = _run(tmp_path, 0, '{"notRun": [], "knownIssuesVerdict": "assessed", "requiredEvaluated": true}')
    assert _outputs(sinks)["evidence"] == "complete"
    _, sinks = _run(tmp_path, 0, '{"notRun": [], "knownIssuesVerdict": "not-determined", "requiredEvaluated": true}')
    assert _outputs(sinks)["because"] == "reported issues: not-determined"


def test_exit_5_is_never_beside_complete_evidence(tmp_path: Path) -> None:
    """Finding 8: the gate's 5 means incomplete whatever the report says."""
    _, sinks = _run(tmp_path, 5, _report())
    out = _outputs(sinks)
    assert out == {
        "result": "evidence-incomplete",
        "exit-code": "5",
        "evidence": "incomplete",
        "because": "the gate exited 5 (evidence incomplete)",
    }


def test_a_cut_reason_says_how_much_was_cut(tmp_path: Path) -> None:
    gaps = [f"check {i:04d} did not run" for i in range(2000)]
    _, sinks = _run(tmp_path, 0, _report(notRun=gaps))
    because = _outputs(sinks)["because"]
    full = "; ".join(gaps)
    assert re.fullmatch(r".{1,600} … \(\+\d+ chars\)", because), because[-60:]
    assert because.endswith(f" … (+{len(full) - 600} chars)")


def test_an_unwritable_work_directory_is_a_configuration_error_with_outputs(tmp_path: Path) -> None:
    """Finding 10: KN_WORK that cannot be created is exit 2, never 1, and the sinks still get their four lines."""
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory", encoding="utf-8")
    proc, sinks = _run(tmp_path, 0, _report(), env={"KN_WORK": str(blocker / "work")})
    assert proc.returncode == 2, proc.stdout + proc.stderr
    out = _outputs(sinks)
    assert out["result"] == "config-error" and out["exit-code"] == "2" and out["evidence"] == "not-run"
    assert "KN_WORK" in out["because"] and "work" in out["because"]
    assert "config-error (exit 2)" in proc.stdout and "passed" not in proc.stdout
    assert not (tmp_path / "stub-args").exists(), "the gate was not run"
