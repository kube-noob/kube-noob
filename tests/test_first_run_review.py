"""G277, second round: seventeen defects an adversarial review found in the first-run fixes, each held here.

Named after the behaviour; each also tries the neighbouring input the review did not name (class 21)."""

from __future__ import annotations

import errno
import io
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path
from typing import Any

import pytest

from kube_noob import demo, known_issues
from kube_noob import examples as ex
from kube_noob import toolkit as tk
from kube_noob.cli import main
from kube_noob.config import load_settings
from kube_noob.debug import diagnose as dx
from kube_noob.sanitize import one_line

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "kube_noob"
EXAMPLES = demo.examples_dir()
ETCD = "etcd leader changed"
NIGHTLY_416 = "4.16.0-0.nightly-2024-05-01-111111"
OKD_415 = "4.15.0-0.okd-2024-03-10-010116"


def _kit() -> tk.Toolkit:
    return tk.Toolkit(load_settings())


def _out(argv: list[str], capsys: pytest.CaptureFixture[str], code: int = 0) -> str:
    assert main(argv) == code, capsys.readouterr()
    return capsys.readouterr().out


# -- 1. the README works for the version a user can install today, and after the release ------------------------


def _readme_blocks() -> list[str]:
    return re.findall(r"```bash\n(.*?)```", (ROOT / "README.md").read_text(encoding="utf-8"), re.S)


def _fallback_line() -> str:
    lines = [ln.strip() for b in _readme_blocks() for ln in b.splitlines() if ln.strip().startswith("curl ")]
    assert len(lines) == 1, "the README's fallback for installs without `examples copy` is gone"
    return lines[0]


def _fake_install(where: Path, src: Path | None) -> dict[str, str]:
    """A `kube-noob` on PATH the way pip, uv, pipx and brew write it: a script whose shebang names its Python."""
    bin_dir = where / "bin"
    bin_dir.mkdir(parents=True)
    script = bin_dir / "kube-noob"
    script.write_text(f"#!{sys.executable}\nimport sys\nfrom kube_noob.cli import main\nsys.exit(main())\n")
    script.chmod(0o755)
    # curl as the README runs it, serving this repository's examples/ (what raw.githubusercontent.com serves from
    # main), so the fallback is exercised without the network.
    curl = bin_dir / "curl"
    curl.write_text(
        f"#!{sys.executable}\n"
        "import pathlib, sys\n"
        f"src = pathlib.Path({str(ROOT / 'examples')!r})\n"
        "a = sys.argv[1:]\n"
        "outs = [a[i + 1] for i, x in enumerate(a) if x == '-o']\n"
        "urls = [x for x in a if x.startswith('https://raw.githubusercontent.com/kube-noob/kube-noob/main/examples/')]\n"
        "assert outs and len(outs) == len(urls), a\n"
        "for o, u in zip(outs, urls):\n"
        "    p = pathlib.Path(o); p.parent.mkdir(parents=True, exist_ok=True)\n"
        "    p.write_bytes((src / u.rsplit('/', 1)[1]).read_bytes())\n"
    )
    curl.chmod(0o755)
    env = {**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}", "KUBE_NOOB_DATA_DIR": str(where / "d")}
    if src is not None:
        env["PYTHONPATH"] = str(src)
    return env


def _readme_uses() -> list[str]:
    return [
        ln.strip()
        for b in _readme_blocks()
        for ln in b.splitlines()
        if ln.strip().startswith("kube-noob ")
        and "examples/" in ln
        and not ln.strip().startswith("kube-noob examples ")
    ]


def _run_readme(env: dict[str, str], work: Path) -> None:
    bash = shutil.which("bash") or "/bin/bash"
    proc = subprocess.run([bash, "-c", _fallback_line()], check=False, cwd=work, env=env, capture_output=True)
    assert proc.returncode == 0, proc.stderr
    assert sorted(p.name for p in (work / "examples").iterdir())
    for line in _readme_uses():
        proc = subprocess.run(shlex.split(line), check=False, cwd=work, env=env, capture_output=True, text=True)
        assert proc.returncode in {0, 1} and proc.stdout.strip(), (line, proc.returncode, proc.stderr)


def _release_092(tmp: Path) -> Path | None:
    """The source of the release users install today, from its tag (fetched if this clone is shallow)."""
    git = shutil.which("git")
    if git is None:
        return None
    have = subprocess.run([git, "-C", str(ROOT), "cat-file", "-e", "v0.9.2^{commit}"], check=False, capture_output=True)
    if have.returncode != 0:
        subprocess.run(
            [git, "-C", str(ROOT), "fetch", "--depth=1", "origin", "tag", "v0.9.2"],
            check=False,
            capture_output=True,
            timeout=120,
        )
    archive = subprocess.run(
        [git, "-C", str(ROOT), "archive", "v0.9.2", "src", "examples"], check=False, capture_output=True
    )
    if archive.returncode != 0:
        return None
    out = tmp / "v092"
    out.mkdir()
    with tarfile.open(fileobj=io.BytesIO(archive.stdout)) as tf:
        tf.extractall(out, filter="data")
    return out


def test_the_readme_fallback_and_its_commands_work_with_the_released_0_9_2(tmp_path: Path) -> None:
    release = _release_092(tmp_path)
    if release is None:
        pytest.skip("the v0.9.2 tag is not reachable from this clone")
    env = _fake_install(tmp_path / "inst", release / "src")
    work = tmp_path / "stranger"
    work.mkdir()
    old = subprocess.run(
        [str(tmp_path / "inst" / "bin" / "kube-noob"), "examples", "copy", "examples"],
        check=False,
        cwd=work,
        env=env,
        capture_output=True,
        text=True,
    )
    assert old.returncode == 2 and "invalid choice" in old.stderr  # why the fallback is in the README at all
    _run_readme(env, work)


def test_the_readme_fallback_works_with_this_version_too(tmp_path: Path) -> None:
    env = _fake_install(tmp_path / "inst", None)
    work = tmp_path / "stranger"
    work.mkdir()
    _run_readme(env, work)


# -- 2. pre-release, nightly and OKD versions ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "version", ["4.21.0-rc.1", NIGHTLY_416, OKD_415, "4.21.0-0.okd-2026-01-01-000000", "4.16.0-rc.1"]
)
def test_a_build_version_is_not_determined_and_still_narrowed_by_its_minor(version: str) -> None:
    out = known_issues.match(ETCD, "openshift", version)
    assert out["versionCoverage"]["status"] == "not-determined", out["versionCoverage"]
    assert out["versionCoverage"]["version"] == version
    minor = version.split("-", maxsplit=1)[0].rsplit(".", 1)[0]
    for m in out["matches"]:  # nothing fixed in another minor's z-stream is offered as if it applied
        assert m["kind"] != "fixed" or str(m["fixedIn"]).startswith(minor + "."), m
        assert "updating to" not in m["status"]


def test_okd_is_never_answered_from_openshift_release_notes() -> None:
    cov = known_issues.match(ETCD, "openshift", OKD_415)["versionCoverage"]
    assert "OKD" in cov["why"] or "4.15" in cov["why"]
    inside = known_issues.match(ETCD, "openshift", "4.21.0-0.okd-2026-01-01-000000")["versionCoverage"]
    assert inside["status"] == "not-determined" and "OKD" in inside["why"]


def test_a_supplied_version_is_never_silently_dropped_from_a_text_view() -> None:
    for version in ("latest", "4.21.x", NIGHTLY_416):
        cov = known_issues.match(ETCD, "openshift", version)["versionCoverage"]
        assert known_issues.coverage_line(cov, listed=False), version


def test_the_gate_says_not_determined_for_a_build_of_an_unindexed_minor(capsys: pytest.CaptureFixture[str]) -> None:
    out = _out(
        [
            "gate",
            "-f",
            str(EXAMPLES / "insecure-deployment.yaml"),
            "--platform",
            "openshift",
            "--version",
            "4.16.0-rc.1",
            "--format",
            "json",
        ],
        capsys,
        code=1,
    )
    rep = json.loads(out)
    assert rep["knownIssuesCoverage"]["status"] == "not-determined"
    assert any(n.startswith("reported issues:") and "4.16.0-rc.1" in n for n in rep["notRun"])


def _mustgather_at(tmp_path: Path, version: str) -> Path:
    from kube_noob.mustgather import sample

    sample.write(tmp_path)
    root = tmp_path / sample.TOP
    for f in root.rglob("*"):
        if f.is_file() and not f.name.endswith(".gz"):
            data = f.read_bytes()
            if b"4.20.3" in data:
                f.write_bytes(data.replace(b"4.20.4", b"4.16.21").replace(b"4.20.3", version.encode()))
    return root


@pytest.mark.parametrize("version", [NIGHTLY_416, OKD_415])
def test_a_nightly_or_okd_must_gather_does_not_print_the_old_all_clear(tmp_path: Path, version: str) -> None:
    from kube_noob.mustgather import analyse, ingest, report

    b = ingest.open_bundle(_mustgather_at(tmp_path / "mg", version))
    r = report.build(b, analyse.analyse(b), data_dir=tmp_path / "data")
    assert r["cluster"]["version"] == version
    md, draft = report.markdown(r), report.case_draft(r)
    assert "None of the findings matches a known issue" not in md and "None matched" not in draft
    assert "NOT DETERMINED" in md and "NOT DETERMINED" in draft
    assert all("updating to" not in str(m.get("status")) for m in r["knownIssues"])


# -- 3. one reading of the version ---------------------------------------------------------------------------------


@pytest.mark.parametrize("noisy", [" 4.21.30 ", "4.21.30\n", "4.21.30\u200b", "\t4.21.30"])
def test_the_statement_and_the_matching_read_the_same_version(noisy: str) -> None:
    clean = known_issues.match(ETCD, "openshift", "4.21.30")
    got = known_issues.match(ETCD, "openshift", noisy)
    assert [m["id"] for m in got["matches"]] == [m["id"] for m in clean["matches"]]
    assert got["versionCoverage"]["status"] == clean["versionCoverage"]["status"]


def test_a_huge_z_stream_is_not_a_version_and_raises_nothing() -> None:
    huge = "4.21." + "9" * 5000
    out = known_issues.match(ETCD, "openshift", huge)
    assert out["versionCoverage"]["status"] == "not-narrowed" and len(out["versionCoverage"]["version"]) <= 80
    assert known_issues.vkey(huge) and known_issues.coverage(huge)


def test_the_gate_reads_a_padded_version_like_a_clean_one(capsys: pytest.CaptureFixture[str]) -> None:
    from kube_noob import gate

    cm = gate.Source("cm.yaml", "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: c, namespace: shop}\n")
    clean = gate.run([cm], platform="openshift", version="4.20.0")
    padded = gate.run([cm], platform="openshift", version=" 4.20.0")
    assert [k["id"] for k in padded["knownIssues"]] == [k["id"] for k in clean["knownIssues"]]
    assert clean["knownIssues"]
    base = ["gate", "-f", str(EXAMPLES / "insecure-deployment.yaml"), "--platform", "openshift", "--format", "json"]
    assert main([*base, "--version", "4.20." + "9" * 5000]) == 2
    assert main([*base, "--version", "4.20.0; rm -rf /"]) == 2
    capsys.readouterr()
    assert json.loads(_out([*base, "--version", " 4.20.0"], capsys, code=1))["version"] == "4.20.0"


def test_memory_matching_survives_a_huge_version(tmp_path: Path) -> None:
    from kube_noob.memory.model import vkey

    assert vkey("4.21." + "9" * 5000)


# -- 4. selftest ---------------------------------------------------------------------------------------------------


def test_selftest_scores_an_undetermined_answer_as_not_determined(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cases = tmp_path / "cases.yaml"
    cases.write_text(
        'cases:\n  - id: etcd-416\n    input: "etcd leader changed frequently, apiserver timeouts after upgrade"\n'
        '    platform: openshift\n    version: "4.16.20"\n    expect:\n      playbook: DBG-ETCD\n'
        "      notMention: [OCPBUGS-]\n",
        encoding="utf-8",
    )
    rep = json.loads(_out(["selftest", "--cases", str(cases), "--format", "json"], capsys))
    row = rep["results"][0]
    assert row["status"] == "not-determined" and rep["passed"] == 0 and rep["notDetermined"] == 1
    assert "NOT DETERMINED" in row["misses"][0]
    text = _out(["selftest", "--cases", str(cases)], capsys)
    assert "Passed | 0 of 1" in text and "Not determined" in text
    # The neighbour: the same case inside the index is scored as before.
    cases.write_text(cases.read_text(encoding="utf-8").replace("4.16.20", "4.21.3"), encoding="utf-8")
    assert json.loads(_out(["selftest", "--cases", str(cases), "--format", "json"], capsys))["passed"] == 1


# -- 5. every consumer's text view ---------------------------------------------------------------------------------

_CONSUMES = re.compile(
    r"known_issue_match\(|known_issues\.match\(|issue_status\(|_known_coverage\(|\b_known\(|kit\.known_issues\("
)


def _consumers() -> set[str]:
    out = set()
    for f in SRC.rglob("*.py"):
        rel = f.relative_to(SRC).as_posix()
        if rel in {"known_issues.py"}:
            continue
        if _CONSUMES.search(f.read_text(encoding="utf-8")):
            out.add(rel)
    return out


def _text_toolkit(tmp: Path, capsys: pytest.CaptureFixture[str]) -> str:
    log = tmp / "build.log"
    log.write_text("STEP 1/3: FROM registry.redhat.io/ubi9\nerror: build error: etcd leader changed\n")
    views = [
        _out(["known-issues", ETCD, "--version", "4.16.20"], capsys),
        _out(["diagnose", ETCD, "--platform", "openshift", "--version", "4.16.20"], capsys),
        _out(["build", "diagnose", "-f", str(log), "--platform", "openshift", "--version", "4.16.20"], capsys),
    ]
    # Every one of them, not the concatenation: one view saying it must not cover for another that does not.
    return views[0] if all("NOT DETERMINED" in v for v in views) else ""


def _text_insight(tmp: Path, capsys: pytest.CaptureFixture[str]) -> str:
    return _out(["insight", "OCPBUGS-73881", "--platform", "openshift", "--version", "4.16.20"], capsys)


def _text_bundle(tmp: Path, capsys: pytest.CaptureFixture[str]) -> str:
    cov = known_issues.match(ETCD, "openshift", "4.16.20")["versionCoverage"]
    return dx.bundle_markdown({"target": "d/s/a", "backend": "t", "knownIssues": [], "knownIssuesCoverage": cov})


def _text_watch(tmp: Path, capsys: pytest.CaptureFixture[str]) -> str:
    from datetime import UTC, datetime

    from kube_noob.incidents import Observation, _headline
    from kube_noob.watch import Watcher

    w = Watcher(load_settings(), backend=None, namespaces=["openshift-etcd"], platform="openshift")
    w.version = "4.16.20"
    obs = Observation(namespace="openshift-etcd", workload="etcd", signal="LeaderChanged", evidence=[ETCD])
    analysis = w.analyse(obs, {}, datetime(2026, 11, 11, tzinfo=UTC))
    head = _headline(
        {"signal": "LeaderChanged", "workload": "etcd", "namespace": "openshift-etcd", "analysis": analysis}
    )
    return head.replace("not determined", "NOT DETERMINED")


def _text_mustgather(tmp: Path, capsys: pytest.CaptureFixture[str]) -> str:
    from kube_noob.mustgather import analyse, ingest, report

    b = ingest.open_bundle(_mustgather_at(tmp / "mg", "4.16.20"))
    r = report.build(b, analyse.analyse(b), data_dir=tmp / "data")
    return report.markdown(r) + report.case_draft(r)


def _text_gate(tmp: Path, capsys: pytest.CaptureFixture[str]) -> str:
    from kube_noob import gate

    cm = gate.Source("cm.yaml", "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: c, namespace: shop}\n")
    return gate.markdown(gate.run([cm], platform="openshift", version="4.16"))


def _text_selftest(tmp: Path, capsys: pytest.CaptureFixture[str]) -> str:
    cases = tmp / "c.yaml"
    cases.write_text(
        "cases:\n  - input: 'etcd leader changed'\n    platform: openshift\n    version: '4.16.20'\n"
        "    expect: {notMention: [OCPBUGS-]}\n",
        encoding="utf-8",
    )
    return _out(["selftest", "--cases", str(cases)], capsys)


TEXT_VIEWS = {
    "toolkit.py": _text_toolkit,
    "cli.py": _text_toolkit,  # the known-issues command calls the toolkit tool
    "insight.py": _text_insight,
    "debug/diagnose.py": _text_bundle,
    "watch.py": _text_watch,
    "mustgather/report.py": _text_mustgather,
    "gate.py": _text_gate,
    "evals/problems.py": _text_selftest,
}


def test_the_list_of_index_consumers_comes_from_the_code() -> None:
    assert _consumers() == set(TEXT_VIEWS), "a module consults the known-issue index without a text-view test here"


@pytest.mark.parametrize("module", sorted(TEXT_VIEWS))
def test_every_consumer_says_not_determined_in_its_text_view(
    module: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    text = TEXT_VIEWS[module](tmp_path, capsys)
    assert "NOT DETERMINED" in text, (module, text[-2000:])


# -- 6. a z-stream newer than the notes ----------------------------------------------------------------------------


def test_a_z_stream_newer_than_the_notes_is_not_determined_and_says_how_far_they_reach(
    capsys: pytest.CaptureFixture[str],
) -> None:
    through = known_issues.get_index().newest()["4.22"]
    major, minor, z = through.split(".")
    later = f"{major}.{minor}.{int(z) + 22}"
    cov = known_issues.match(ETCD, "openshift", later)["versionCoverage"]
    assert cov["status"] == "not-determined" and cov["indexedThrough"] == through and through in cov["why"]
    assert known_issues.match(ETCD, "openshift", through)["versionCoverage"]["status"] == "determined"
    assert "NOT DETERMINED" in _out(["known-issues", ETCD, "--version", later], capsys)


# -- 7. examples copy never crashes and never leaves a partial copy --------------------------------------------------


def test_a_dangling_link_as_the_directory_is_refused_with_exit_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    link = tmp_path / "dangling"
    link.symlink_to(tmp_path / "nowhere")
    assert main(["examples", "copy", str(link)]) == 2
    assert "symbolic link to nothing" in capsys.readouterr().err
    assert main(["demo", "diagnose", "--keep", str(link)]) == 2
    assert not (tmp_path / "nowhere").exists()


def test_a_full_disk_part_way_leaves_nothing_and_exits_4(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    real = ex._write_temp
    calls = {"n": 0}

    def full(dir_fd: int, name: str, data: bytes) -> str:
        calls["n"] += 1
        if calls["n"] == 4:
            raise OSError(errno.ENOSPC, "No space left on device", name)
        return real(dir_fd, name, data)

    monkeypatch.setattr(ex, "_write_temp", full)
    dest = tmp_path / "ex"
    assert main(["examples", "copy", str(dest)]) == 4
    assert "nothing was written" in capsys.readouterr().err
    assert not dest.exists() or list(dest.iterdir()) == []
    monkeypatch.setattr(ex, "_write_temp", real)
    assert main(["examples", "copy", str(dest)]) == 0
    assert sorted(p.name for p in dest.iterdir()) == ex.names()


def test_a_failure_while_placing_removes_the_files_this_run_placed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = ex._place
    calls = {"n": 0}

    def flaky(dir_fd: int, tmp: str, name: str, replace: bool) -> None:
        calls["n"] += 1
        if calls["n"] == 3:
            raise OSError(errno.EIO, "I/O error", name)
        real(dir_fd, tmp, name, replace)

    monkeypatch.setattr(ex, "_place", flaky)
    dest = tmp_path / "ex"
    dest.mkdir()
    (dest / "mine.txt").write_text("keep", encoding="utf-8")
    with pytest.raises(ex.ExamplesWriteError, match="nothing was written"):
        ex.copy(dest)
    assert sorted(p.name for p in dest.iterdir()) == ["mine.txt"]


# -- 8. the text sanitiser -----------------------------------------------------------------------------------------

# Control, format, surrogate and private-use characters: what `sanitize.visible` handles today. Blank-looking
# characters of other categories (Braille blank, Hangul fillers, variation selectors) and the script-aware rule for
# ZWJ and ZWNJ come with the shared fixed table on fix/absent-vs-unread, which `one_line` delegates to.
_HIDDEN = [
    "\x00", "\x07", "\x1b", "\x7f", "\x80", "\x9b", "\x9f", "\ud800", "\ue000", "\xad", "\u200b", "\u200e",
    "\u202e", "\u2066", "\u206a", "\u206f", "\ufeff", "\ufff9", "\ufffb", "\u0600", "\u0605", "\u06dd", "\u070f",
    "\U000110bd", "\U0001bca0", "\U0001d173", "\U0001d17a", "\U000e0041", "\u200d", "\u200c",
]  # fmt: skip


@pytest.mark.parametrize("ch", _HIDDEN, ids=[f"U+{ord(c):04X}" for c in _HIDDEN])
def test_one_line_removes_what_a_terminal_would_hide_or_act_on(ch: str) -> None:
    out = one_line(f"ab{ch}cd")
    assert ch not in out and out.replace(" ", "") == "abcd"


def test_one_line_keeps_visible_text() -> None:
    for text in ("caf\u00e9", "\u65e5\u672c\u8a9e", "a b\tc\nd", "\U0001f600 ok"):
        assert one_line(text) == " ".join(text.split())


def test_the_terminal_filter_drops_c1_controls(capsys: pytest.CaptureFixture[str]) -> None:
    from kube_noob.cli import _tprint

    _tprint("a\x9b31mb\x85c\x1b[0md")
    assert capsys.readouterr().out == "a31mbc[0md\n"


def test_the_diagnose_text_view_carries_no_hidden_character(capsys: pytest.CaptureFixture[str]) -> None:
    paste = "Back-off restarting failed container api in pod api-1 " + "".join(c for c in _HIDDEN if c != "\ud800")
    out = _out(["diagnose", paste], capsys)
    for ch in _HIDDEN:
        if ch not in "\u200d\u200c":
            assert ch not in out, f"U+{ord(ch):04X}"


def test_a_lone_surrogate_in_a_status_response_does_not_fail_the_write(capsys: pytest.CaptureFixture[str]) -> None:
    status = '{"kind": "Status", "message": "pods \\"a\\ud800b\\" is forbidden: exceeded quota"}'
    for cmd in ("diagnose", "insight", "known-issues"):
        for fmt in ("text", "yaml", "json"):
            assert main([cmd, status, "--format", fmt]) == 0, (cmd, fmt)
            capsys.readouterr()


# -- 9. the insight hint runs after the README step -----------------------------------------------------------------


def test_copying_twice_is_not_an_error_and_the_insight_hint_runs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    dest = tmp_path / "examples"
    assert main(["examples", "copy", str(dest)]) == 0
    capsys.readouterr()
    out = _out(["examples", "copy", str(dest)], capsys)
    assert "already in" in out and "wrote" not in out
    (dest / "events-scc.txt").write_text("mine", encoding="utf-8")
    assert main(["examples", "copy", str(dest)]) == 2  # a file that differs is still refused
    assert "--force" in capsys.readouterr().err
    (dest / "events-scc.txt").unlink()
    hint = _out(["insight", "paste anything"], capsys)
    cmds = [
        ln.strip() for ln in hint.splitlines() if ln.strip().startswith("kube-noob ") and not ln.strip().endswith(":")
    ]
    os.chdir(tmp_path)
    for line in cmds:
        assert main(shlex.split(line)[1:]) == 0, line
        capsys.readouterr()


# -- 10. a flag and the payload's own version ------------------------------------------------------------------------


def test_the_payload_version_survives_a_version_flag_and_a_disagreement_is_said(
    capsys: pytest.CaptureFixture[str],
) -> None:
    payload = str(EXAMPLES / "alertmanager-etcd.json")
    rep = json.loads(_out(["diagnose", "-f", payload, "--version", "4.21.5", "--format", "json"], capsys))
    i = rep["input"]
    assert i["version"] == "4.21.5" and i["payloadVersion"] == "4.21.0" and "differs" in i["versionConflict"]
    text = _out(["diagnose", "-f", payload, "--version", "4.21.5"], capsys)
    assert "4.21.0" in text and "version conflict" in text
    same = json.loads(_out(["diagnose", "-f", payload, "--version", "4.21.0", "--format", "json"], capsys))
    assert "versionConflict" not in same["input"] and same["input"]["payloadVersion"] == "4.21.0"


# -- 11. the suggested commands survive any directory name ----------------------------------------------------------


@pytest.mark.parametrize("name", ["with space", "-lead", "it's", "a;b", "$(x)"])
def test_the_suggested_commands_name_the_directory_as_one_word(
    name: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    os.chdir(tmp_path)
    out = _out(["examples", "copy", "--", name] if name.startswith("-") else ["examples", "copy", name], capsys)
    for line in [ln.strip() for ln in out.splitlines() if ln.strip().startswith("kube-noob ")]:
        argv = shlex.split(line)
        path = Path(argv[argv.index("-f") + 1])
        assert path.is_file() and not argv[argv.index("-f") + 1].startswith("-"), line


@pytest.mark.parametrize("name", ["new\nline", "tab\there", "esc\x1bx"])
def test_a_directory_name_with_a_control_character_is_refused(
    name: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["examples", "copy", str(tmp_path / name)]) == 2
    assert not (tmp_path / name).exists()


# -- 12. the text view says what is unknown -------------------------------------------------------------------------


def test_causes_the_input_did_not_single_out_are_not_called_likely(capsys: pytest.CaptureFixture[str]) -> None:
    structured = _kit().diagnose(tk.DiagnoseIn(text=(EXAMPLES / "events-scc.txt").read_text(encoding="utf-8")))
    top = structured["diagnoses"][0]
    assert "likelyCause" not in top
    out = _out(["diagnose", "-f", str(EXAMPLES / "events-scc.txt")], capsys)
    assert "likely cause" not in out
    assert f"possible causes ({len(top['rootCauses'])}, not narrowed by the input)" in out


def test_a_likely_cause_does_not_hide_the_other_causes(capsys: pytest.CaptureFixture[str]) -> None:
    text = (EXAMPLES / "events-crashloop.txt").read_text(encoding="utf-8")
    top = _kit().diagnose(tk.DiagnoseIn(text=text))["diagnoses"][0]
    out = _out(["diagnose", "-f", str(EXAMPLES / "events-crashloop.txt")], capsys)
    others = [c for c in top["rootCauses"] if c != top.get("likelyCause")]
    if top.get("likelyCause"):
        assert f"likely cause: {top['likelyCause']}" in out
        assert f"other possible causes: {len(others)}" in out


def test_the_approach_and_untrusted_flags_reach_the_text_view() -> None:
    result: dict[str, Any] = {
        "approach": "Run the read-only steps first.",
        "diagnoses": [{"id": "DBG-X", "title": "t", "confidence": 1.0, "rootCauses": ["a", "b"]}],
        "untrusted": True,
        "injectionSignals": [{"kind": "role-marker", "excerpt": "x"}],
        "injectionSignalsTruncated": 3,
    }
    text = dx.render_text(result)
    assert "Run the read-only steps first." in text and "role-marker" in text and "3 more" in text


@pytest.mark.parametrize("name", ["events-scc.txt", "events-crashloop.txt", "alertmanager-etcd.json"])
def test_every_field_of_every_diagnosis_has_a_decision_and_every_list_is_shown_or_counted(
    name: str, capsys: pytest.CaptureFixture[str]
) -> None:
    structured = _kit().diagnose(tk.DiagnoseIn(text=(EXAMPLES / name).read_text(encoding="utf-8")))
    out = _out(["diagnose", "-f", str(EXAMPLES / name)], capsys)
    for d in structured["diagnoses"]:
        assert set(d) <= dx.DIAGNOSIS_RENDERED | set(dx.DIAGNOSIS_OMITTED), set(d) - dx.DIAGNOSIS_RENDERED
    top = structured["diagnoses"][0]
    shown_ev = [e for e in top["evidence"] if one_line(str(e)) in out]
    assert len(shown_ev) == len(top["evidence"]) or f"+{len(top['evidence']) - len(shown_ev)} more" in out
    assert all(k in out for k in top.get("knowledge", []))


# -- 13. no update advice for a release the index cannot answer for ----------------------------------------------------


def test_a_fix_in_another_release_is_not_update_advice_outside_the_index(capsys: pytest.CaptureFixture[str]) -> None:
    out = _out(["insight", "OCPBUGS-73881", "--platform", "openshift", "--version", "4.16.20"], capsys)
    assert "updating to" not in out and "backport" in out
    inside = _out(["insight", "OCPBUGS-73881", "--platform", "openshift", "--version", "4.21.0"], capsys)
    assert "updating to 4.21.1" in inside


# -- 14. the not-narrowed line only where it means something ----------------------------------------------------------


def test_known_issues_without_a_version_and_without_matches_adds_no_line(capsys: pytest.CaptureFixture[str]) -> None:
    out = _out(["known-issues", "the coffee machine is out of beans again today"], capsys)
    assert "not narrowed by version" not in out
    assert "not narrowed by version" in _out(["known-issues", ETCD], capsys)


# -- 15. nested subcommands take the common options ----------------------------------------------------------------


def test_examples_list_takes_format_after_the_subcommand(capsys: pytest.CaptureFixture[str]) -> None:
    rows = json.loads(_out(["examples", "list", "--format", "json"], capsys))
    assert [r["name"] for r in rows] == ex.names()
    assert json.loads(_out(["examples", "--format", "json", "list"], capsys)) == rows


# -- 16. the old demo name is gone from the docs and the recordings -------------------------------------------------


def test_docs_and_tapes_use_the_demo_names_that_exist() -> None:
    use_cases = (ROOT / "docs" / "use-cases.md").read_text(encoding="utf-8")
    blocks = "\n".join(re.findall(r"```bash\n(.*?)```", use_cases, re.S))
    assert "kube-noob demo posture" not in blocks and "kube-noob demo doctor" in blocks
    for tape in (ROOT / "demos").glob("*.tape"):
        for name in re.findall(r'Type "kube-noob demo (\w[\w-]*)"', tape.read_text(encoding="utf-8")):
            assert name in demo.SCENARIOS, (tape.name, name)
    assert not (ROOT / "demos" / "posture.tape").exists()
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    titles = re.findall(r'grep -q "kube-noob demo: ([^"]+)"', ci)
    assert titles and all(any(s.title.startswith(t) for s in demo.SCENARIOS.values()) for t in titles)


# -- 17. a cut input says it was cut --------------------------------------------------------------------------------


def test_a_cut_input_says_so_in_every_format(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    big = tmp_path / "big.txt"
    big.write_text("x" * 1_000_000, encoding="utf-8")
    for fmt in ("json", "yaml"):
        out = _out(["diagnose", "-f", str(big), "--format", fmt], capsys)
        assert "inputTruncated" in out and "1,000,000" in out
    text = _out(["diagnose", "-f", str(big)], capsys)
    assert "input cut:" in text and "No playbook matched" in text
    assert "input cut:" in _out(["insight", "-f", str(big)], capsys)
    small = _out(["diagnose", "-f", str(EXAMPLES / "events-scc.txt"), "--format", "json"], capsys)
    assert "inputTruncated" not in small


# -- minor ------------------------------------------------------------------------------------------------------------


def test_a_missing_file_names_the_command_that_was_run(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["policy", "explain", "-f", str(tmp_path / "missing.txt")]) == 2
    err = capsys.readouterr().err
    assert "kube-noob policy explain" in err and "kube-noob diagnose" not in err
