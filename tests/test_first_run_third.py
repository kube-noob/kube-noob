"""G277, third round: what the second review of the first-run fixes found. Written before the fixes, red first.

Named after the behaviour; each also tries a neighbouring input (class 21)."""

from __future__ import annotations

import errno
import json
import os
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from kube_noob import demo, known_issues
from kube_noob import examples as ex
from kube_noob import toolkit as tk
from kube_noob.cli import main
from kube_noob.config import load_settings
from kube_noob.debug import diagnose as dx

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = demo.examples_dir()
ETCD = "etcd leader changed"
ISSUE = "catalog sync triggered high I/O on masters, and caused etcd leader election and TTL counter resets"
NIGHTLY = "4.16.0-0.nightly-2024-05-01-111111"


def _kit() -> tk.Toolkit:
    return tk.Toolkit(load_settings())


def _out(argv: list[str], capsys: pytest.CaptureFixture[str], code: int = 0) -> str:
    got = main(argv)
    cap = capsys.readouterr()
    assert got == code, (argv, got, cap.err[-800:])
    return cap.out


# -- 1. the window the known-issue matcher reads --------------------------------------------------------------------


def _paste(size: int, where: str) -> str:
    filler_line = "ok\n"  # words that name no issue, so the issue text decides the match
    filler = (filler_line * (size // len(filler_line) + 2))[: size - len(ISSUE) - 2]
    at = {"start": 0, "middle": len(filler) // 2, "end": len(filler)}[where]
    return f"{filler[:at]}\n{ISSUE}\n{filler[at:]}"


@pytest.mark.parametrize("where", ["start", "middle", "end"])
def test_a_paste_under_the_window_is_matched_wherever_the_issue_is(where: str) -> None:
    out = known_issues.match(_paste(98_000, where), "openshift", "4.21.0")
    assert "OCPBUGS-73881" in [m["id"] for m in out["matches"]]
    assert "inputTruncated" not in out and out["versionCoverage"]["status"] == "determined"


@pytest.mark.parametrize("where", ["start", "middle", "end"])
def test_a_paste_over_the_window_reads_the_end_and_says_what_it_did_not_read(where: str) -> None:
    out = known_issues.match(_paste(105_515, where), "openshift", "4.21.0")
    assert out["inputTruncated"]["read"] == known_issues.MATCH_TEXT
    cov = out["versionCoverage"]
    assert cov["status"] == "not-determined" and "last" in cov["why"]
    if where == "end":
        assert "OCPBUGS-73881" in [m["id"] for m in out["matches"]]


def test_a_megabyte_paste_to_diagnose_reads_the_same_end_as_the_matcher(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    f = tmp_path / "big.txt"
    f.write_text(_paste(1_000_000, "end"), encoding="utf-8")
    rep = json.loads(
        _out(["diagnose", "-f", str(f), "--platform", "openshift", "--version", "4.21.0", "--format", "json"], capsys)
    )
    assert "OCPBUGS-73881" in [m["id"] for m in rep["knownIssues"]]
    assert rep["knownIssuesCoverage"]["status"] == "not-determined" and rep["inputTruncated"]


def test_known_issues_on_the_command_line_takes_a_long_paste_and_says_it_was_cut(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    f = tmp_path / "big.txt"
    f.write_text(_paste(150_000, "end"), encoding="utf-8")
    rep = json.loads(_out(["known-issues", "-f", str(f), "--version", "4.21.0", "--format", "json"], capsys))
    assert rep["inputTruncated"] and rep["versionCoverage"]["status"] == "not-determined"
    assert "NOT DETERMINED" in _out(["known-issues", "-f", str(f), "--version", "4.21.0"], capsys)


# -- 2. one version grammar on every surface -------------------------------------------------------------------------

ACCEPTED = {
    "4.21.3": "determined",
    "4.22.18": "determined",
    "4.22.19": "not-determined",
    "4.21.0-rc.1": "not-determined",
    "4.20.0-okd-scos.6": "not-determined",
    "4.21": "determined",
    " 4.21 ": "determined",
    "4.16.20": "not-determined",
    "v4.21.3": "determined",
    NIGHTLY: "not-determined",
    "4.21.3-x86_64": "determined",
}
REFUSED = ["latest", "4.20.x", "4.09", "4", "4.21.3; rm -rf /", "4.21." + "9" * 50]


def _memory_repo(tmp: Path) -> Path:
    from kube_noob.memory import repo

    root = tmp / "team"
    repo.init_repo(root)
    return root


def _cli_surfaces(tmp: Path) -> dict[str, list[str]]:
    log = tmp / "build.log"
    log.write_text("STEP 1/3: FROM registry.redhat.io/ubi9\nerror: build error: etcd leader changed\n")
    return {
        "known-issues": ["known-issues", ETCD, "--platform", "openshift"],
        "diagnose": ["diagnose", ETCD, "--platform", "openshift"],
        "insight": ["insight", ETCD, "--platform", "openshift"],
        "build diagnose": ["build", "diagnose", "-f", str(log), "--platform", "openshift"],
        "ticket": ["ticket", "OCPBUGS-73881"],
        "gate": ["gate", "-f", str(EXAMPLES / "insecure-deployment.yaml"), "--platform", "openshift"],
        "memory match": ["memory", "match", ETCD, "--dir", str(_memory_repo(tmp))],
    }


def _status(rep: dict[str, Any]) -> str | None:
    cov = rep.get("versionCoverage") or rep.get("knownIssuesCoverage")
    return cov.get("status") if cov else None


@pytest.mark.parametrize("version", sorted(ACCEPTED))
def test_an_accepted_version_gets_the_same_decision_on_every_command(
    version: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    for name, argv in _cli_surfaces(tmp_path).items():
        got = main([*argv, "--version", version, "--format", "json"])
        cap = capsys.readouterr()
        # gate: findings in the example; ticket: no local Jira copy here, so "not found" (exit 1) -- not a refusal
        assert got in ({1} if name == "gate" else {0, 1} if name == "ticket" else {0}), (name, got, cap.err)
        rep = json.loads(cap.out)
        if name in {"known-issues", "diagnose", "insight", "build diagnose", "gate"}:
            assert _status(rep) == ACCEPTED[version], (name, version, rep.get("knownIssuesCoverage"))


@pytest.mark.parametrize("version", REFUSED)
def test_a_refused_version_is_exit_2_with_one_sentence_on_every_command(
    version: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    for name, argv in _cli_surfaces(tmp_path).items():
        assert main([*argv, "--version", version]) == 2, name
        err = capsys.readouterr().err
        assert "validation error" not in err and "pydantic" not in err and len(err.strip().splitlines()) == 1, err


@pytest.mark.parametrize("version", sorted(ACCEPTED))
def test_every_tool_accepts_what_the_command_line_accepts(version: str) -> None:
    kit = _kit()
    log = "STEP 1/3: FROM registry.redhat.io/ubi9\nerror: build error: etcd leader changed\n"
    calls = [
        (tk.KnownIssuesIn, {"text": ETCD, "platform": "openshift", "version": version}, kit.known_issues),
        (tk.DiagnoseIn, {"text": ETCD, "platform": "openshift", "version": version}, kit.diagnose),
        (tk.InsightIn, {"text": ETCD, "platform": "openshift", "version": version}, kit.insight),
        (tk.BuildDiagnoseIn, {"log": log, "platform": "openshift", "version": version}, kit.build_diagnose),
        (tk.TicketIn, {"key": "OCPBUGS-73881", "version": version}, kit.ticket),
    ]
    for model, args, fn in calls:
        rep = fn(model(**args))
        if model is not tk.TicketIn:
            assert _status(rep) == ACCEPTED[version], (model.__name__, version)


@pytest.mark.parametrize("version", REFUSED)
def test_every_tool_refuses_what_the_command_line_refuses(version: str) -> None:
    for model, args in [
        (tk.KnownIssuesIn, {"text": ETCD}),
        (tk.DiagnoseIn, {"text": ETCD}),
        (tk.InsightIn, {"text": ETCD}),
        (tk.BuildDiagnoseIn, {"log": "error: x\nerror: y"}),
        (tk.TicketIn, {"key": "OCPBUGS-1"}),
        (tk.MemoryMatchIn, {"text": ETCD}),
    ]:
        with pytest.raises(ValidationError):
            model(**args, version=version)


def test_selftest_takes_every_accepted_version_and_refuses_the_file_for_a_bad_one(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cases = tmp_path / "c.yaml"
    rows = "".join(
        f"  - input: 'etcd leader changed'\n    platform: openshift\n    version: {json.dumps(v)}\n" for v in ACCEPTED
    )
    cases.write_text("cases:\n" + rows, encoding="utf-8")
    rep = json.loads(_out(["selftest", "--cases", str(cases), "--format", "json"], capsys))
    assert rep["cases"] == len(ACCEPTED)
    cases.write_text("cases:\n  - input: 'etcd leader changed'\n    version: latest\n", encoding="utf-8")
    assert main(["selftest", "--cases", str(cases)]) == 2
    assert "validation error" not in capsys.readouterr().err


def test_memory_reads_versions_like_the_known_issue_index() -> None:
    from kube_noob.memory.model import vkey

    assert vkey("v4.21.3") == vkey("4.21.3") == (4, 21, 3)
    assert vkey("4.21.3-x86_64") == (4, 21, 3)


def test_a_flag_and_a_label_that_name_the_same_release_do_not_conflict(capsys: pytest.CaptureFixture[str]) -> None:
    payload = str(EXAMPLES / "alertmanager-etcd.json")  # its label says 4.21.0
    for same in ("4.21.0", "v4.21.0", " 4.21.0 "):
        rep = json.loads(_out(["diagnose", "-f", payload, "--version", same, "--format", "json"], capsys))
        assert "versionConflict" not in rep["input"], same
    rep = json.loads(_out(["diagnose", "-f", payload, "--version", "4.21", "--format", "json"], capsys))
    assert "versionConflict" not in rep["input"]  # 4.21 does not contradict 4.21.0
    rep = json.loads(_out(["diagnose", "-f", payload, "--version", "4.21.5", "--format", "json"], capsys))
    assert "versionConflict" in rep["input"]


def test_a_release_image_tag_is_the_release_with_an_architecture() -> None:
    from kube_noob.versions import read_version

    cv = read_version("4.21.3-x86_64")
    assert cv is not None and cv.numeric == "4.21.3" and cv.build == "" and cv.arch == "x86_64"


def test_a_minor_without_a_z_stream_gets_no_update_advice() -> None:
    out = known_issues.match(ETCD, "openshift", "4.21")
    fixed = [m for m in out["matches"] if m["kind"] == "fixed"]
    assert fixed and all("updating to" not in m["status"] for m in fixed)
    assert all("4.21.x" in m["status"] or "z-stream" in m["status"] for m in fixed)


# -- 4. examples copy: interrupts, a swapped directory, no hard links ------------------------------------------------


@pytest.mark.parametrize("phase", ["_write_temp", "_place"])
def test_an_interrupt_in_either_phase_leaves_nothing_and_exits_130(
    phase: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    real = getattr(ex, phase)
    calls = {"n": 0}

    def interrupted(*a: Any, **k: Any) -> Any:
        calls["n"] += 1
        if calls["n"] == 3:
            raise KeyboardInterrupt
        return real(*a, **k)

    monkeypatch.setattr(ex, phase, interrupted)
    dest = tmp_path / "ex"
    assert main(["examples", "copy", str(dest)]) == 130
    err = capsys.readouterr().err
    assert "Traceback" not in err and len(err.strip().splitlines()) == 1
    assert not dest.exists() or list(dest.iterdir()) == []


def test_a_directory_swapped_for_a_link_after_the_check_is_not_followed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dest, moved, outside = tmp_path / "ex", tmp_path / "moved", tmp_path / "outside"
    dest.mkdir()
    outside.mkdir()
    real = ex._write_temp
    swapped = {"done": False}

    def swap(*a: Any, **k: Any) -> Any:
        if not swapped["done"]:
            dest.rename(moved)
            dest.symlink_to(outside)
            swapped["done"] = True
        return real(*a, **k)

    monkeypatch.setattr(ex, "_write_temp", swap)
    ex.copy(dest)
    assert list(outside.iterdir()) == []
    assert sorted(p.name for p in moved.iterdir()) == ex.names()


@pytest.mark.parametrize("code", [errno.ENOSYS, errno.EPERM, errno.EOPNOTSUPP])
def test_a_file_system_without_hard_links_still_gets_every_file(
    code: int, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def no_links(*a: Any, **k: Any) -> None:
        raise OSError(code, os.strerror(code))

    monkeypatch.setattr(ex.os, "link", no_links)
    written = ex.copy(tmp_path / "ex")
    assert [p.name for p in written] == ex.names()
    assert not [p for p in (tmp_path / "ex").iterdir() if p.name.startswith(".")]


@pytest.mark.parametrize("name", ["evil\u202ename", "zero\u200bwidth", "tag\U000e0041x"])
def test_a_directory_name_with_an_invisible_character_is_refused(
    name: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["examples", "copy", str(tmp_path / name)]) == 2
    assert not (tmp_path / name).exists()


# -- 5. the README fallback works in every shell and every install shape --------------------------------------------


def _fallback() -> str:
    import re

    text = (ROOT / "README.md").read_text(encoding="utf-8")
    blocks = re.findall(r"```bash\n(.*?)```", text, re.S)
    lines = [ln.strip() for b in blocks for ln in b.splitlines() if ln.strip().startswith("curl ")]
    assert len(lines) == 1, "the README's fallback for releases without `examples copy` is gone"
    return lines[0]


@pytest.mark.parametrize("shell", ["bash", "zsh", "fish"])
def test_the_readme_fallback_runs_in_every_shell_without_kube_noob_on_path(shell: str, tmp_path: Path) -> None:
    exe = shutil.which(shell)
    if exe is None:
        pytest.skip(f"{shell} is not installed")
    # A curl that serves this repository's examples/ for the raw GitHub URLs the README names, and records its argv.
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake = bin_dir / "curl"
    fake.write_text(
        "#!/usr/bin/env python3\n"
        "import sys, pathlib\n"
        f"src = pathlib.Path({str(ROOT / 'examples')!r})\n"
        "args = sys.argv[1:]\n"
        "outs = [args[i + 1] for i, a in enumerate(args) if a == '-o']\n"
        "urls = [a for a in args if a.startswith('https://')]\n"
        "assert len(outs) == len(urls) and urls, args\n"
        "for o, u in zip(outs, urls):\n"
        "    assert u.startswith('https://raw.githubusercontent.com/kube-noob/kube-noob/'), u\n"
        "    p = pathlib.Path(o); p.parent.mkdir(parents=True, exist_ok=True)\n"
        "    p.write_bytes((src / u.rsplit('/', 1)[1]).read_bytes())\n"
    )
    fake.chmod(0o755)
    work = tmp_path / "w"
    work.mkdir()
    env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "HOME": str(tmp_path)}  # no kube-noob, no python venv on PATH
    proc = subprocess.run([exe, "-c", _fallback()], check=False, cwd=work, env=env, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for used in ("netpol-admin-tiers.yaml", "denial-multi.txt"):
        assert f"examples/{used}" in readme and (work / "examples" / used).is_file()


def test_the_readme_fallback_names_only_files_that_exist_and_no_release_number() -> None:
    import re

    line = _fallback()
    for url in re.findall(r"https://\S+", line):
        assert (ROOT / "examples" / url.rsplit("/", 1)[1]).is_file(), url
        assert re.search(r"/v?\d+\.\d+\.\d+/", url) is None, url  # bump_version must not have to rewrite it


# -- 6. one_line is visible() plus a whitespace collapse ---------------------------------------------------------------


def test_one_line_is_visible_with_whitespace_collapsed() -> None:
    from kube_noob import sanitize

    for text in ("a\x1b[31mb\x9bc", "x\u202ey\u200bz", "keep  double\tand\nnew", "\ud800lone", "café 日"):
        assert sanitize.one_line(text) == " ".join(sanitize.visible(text).split()), repr(text)


def test_a_lone_surrogate_prints_as_the_replacement_character(capsys: pytest.CaptureFixture[str]) -> None:
    from kube_noob.cli import _tprint

    _tprint("a\ud800b")
    assert capsys.readouterr().out == "a�b\n"


# -- 7. team memory in the diagnose text view ------------------------------------------------------------------------


def _memory_entry() -> dict[str, Any]:
    return {
        "citation": "[mem:MEM-7]",
        "id": "MEM-7",
        "state": "fix",
        "kind": "fix",
        "status": "approved",
        "symptom": "etcd leader changes after the update",
        "cause": "catalog sync wrote to the control-plane disks",
        "fix": {
            "text": "Update to 4.21.1.",
            "commands": [
                {"command": "oc get co etcd  -o  wide", "label": "read-only"},
                {"command": "oc adm upgrade --to=4.21.1", "label": "needs-approval"},
            ],
            "patch": "a: 1\nb: 2\n",
        },
        "versions": {"introduced": "4.21.0", "fixedIn": "4.21.1"},
        "outcomes": {"summary": "matched 3 times, resolved 2"},
        "platform": "openshift",
        "owners": ["platform-team"],
        "sources": [],
        "evidence": [{"kind": "ticket", "ref": "OCPBUGS-73881"}],
        "repository": "/x",
        "file": "entries/MEM-7.yaml",
        "matchedBy": {"signals": [], "words": ["etcd"]},
        "riskAccepted": {"owner": "sec", "reason": "reviewed"},
    }


def test_team_memory_shows_its_cause_commands_and_versions() -> None:
    text = dx.render_text({"diagnoses": [], "memory": [_memory_entry()]})
    assert "catalog sync wrote to the control-plane disks" in text
    assert "oc get co etcd  -o  wide" in text  # verbatim: the double spaces are part of the command
    assert "oc adm upgrade --to=4.21.1" in text and "needs approval" in text
    assert "4.21.0" in text and "4.21.1" in text and "risk accepted" in text


def test_every_field_of_a_memory_match_has_a_decision() -> None:
    assert set(_memory_entry()) <= dx.MEMORY_RENDERED | set(dx.MEMORY_OMITTED)


def test_a_command_from_memory_cannot_carry_an_escape_or_forge_a_line() -> None:
    entry = _memory_entry()
    entry["fix"]["commands"] = [{"command": "oc get pods\nDBG-FAKE  all fine\x1b[2J", "label": "read-only"}]
    text = dx.render_text({"diagnoses": [], "memory": [entry]})
    assert "\x1b" not in text and not any(line.startswith("DBG-FAKE") for line in text.splitlines())


# -- 8. silence where a version could have been named --------------------------------------------------------------


def test_the_gate_without_a_version_says_reported_issues_were_not_looked_up() -> None:
    from kube_noob import gate

    cm = gate.Source("cm.yaml", "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: c, namespace: shop}\n")
    rep = gate.run([cm], platform="openshift")
    assert rep["knownIssuesCoverage"]["status"] == "not-determined"
    assert any(n.startswith("reported issues:") for n in rep["notRun"])
    assert "knownIssuesCoverage" not in gate.run([cm], platform="kubernetes")


def test_a_live_debug_whose_version_could_not_be_read_says_so() -> None:
    from kube_noob.errors import ClusterAccessError

    class Backend:
        name = "fake"

        def version(self) -> dict[str, Any]:
            raise ClusterAccessError("forbidden: version")

        def get(self, resource: str, namespace: str | None = None, name: str | None = None, **_: Any) -> dict[str, Any]:
            if resource == "events":
                return {"items": [{"type": "Warning", "reason": "Unhealthy", "message": ETCD}]}
            if resource == "deployments":
                return {"metadata": {"name": "api"}, "spec": {"selector": {"matchLabels": {"app": "api"}}}}
            return {"items": []}

        def logs(self, *a: Any, **k: Any) -> str:
            return ETCD

    out = dx.debug_workload(Backend(), "openshift-etcd", "deployment", "api", platform="openshift")
    why = out["knownIssuesCoverage"]["why"]
    assert "could not be read" in why and "No version was given" not in why


# -- 9. the smaller ones --------------------------------------------------------------------------------------------


def test_insight_carries_the_payload_version_and_a_conflict(capsys: pytest.CaptureFixture[str]) -> None:
    payload = str(EXAMPLES / "alertmanager-etcd.json")
    rep = json.loads(_out(["insight", "-f", payload, "--version", "4.21.5", "--format", "json"], capsys))
    assert rep["payloadVersion"] == "4.21.0" and "differs" in rep["versionConflict"]
    assert "version conflict" in _out(["insight", "-f", payload, "--version", "4.21.5"], capsys)


def test_insight_lists_what_it_recognises_in_json_for_unrecognised_input(capsys: pytest.CaptureFixture[str]) -> None:
    from kube_noob import insight

    rep = json.loads(_out(["insight", "paste anything", "--format", "json"], capsys))
    assert [r["kind"] for r in rep["recognises"]] == list(insight.KINDS)
    known = json.loads(_out(["insight", "-f", str(EXAMPLES / "events-scc.txt"), "--format", "json"], capsys))
    assert "recognises" not in known


def test_the_kept_demo_directory_is_quoted_for_a_shell(tmp_path: Path) -> None:
    keep = tmp_path / "with space"
    lines: list[str] = []
    demo.run("diagnose", load_settings(), lines.append, keep=keep)
    kept = next(ln for ln in lines if "Kept in" in ln)
    assert shlex.quote(str(keep)) in kept


def test_the_must_gather_text_line_cuts_the_summary_not_the_status() -> None:
    from kube_noob.cli import _known_issue_line

    m = {
        "id": "OCPBUGS-1",
        "status": "Reported and fixed in OpenShift 4.21.1. " + "s" * 200 + " end.",
        "summary": "x" * 400,
    }
    line = _known_issue_line(m)
    assert m["status"] in line and len(line) <= 300 + len(m["status"])


def test_the_demo_listing_in_json_does_not_list_an_alias_as_a_demo(capsys: pytest.CaptureFixture[str]) -> None:
    rows = json.loads(_out(["demo", "--list", "--format", "json"], capsys))
    names = [r["name"] for r in rows]
    assert "posture" not in names and "doctor" in names
    assert next(r for r in rows if r["name"] == "doctor")["aliases"] == ["posture"]


def test_diagnose_header_fields_stay_apart(capsys: pytest.CaptureFixture[str]) -> None:
    first = _out(["diagnose", "-f", str(EXAMPLES / "events-scc.txt")], capsys).splitlines()[0]
    assert first.startswith("DBG-SCC · Pod rejected by SecurityContextConstraints · confidence 1.0")
