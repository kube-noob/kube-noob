"""G277: the first five minutes after `brew install` or `uv tool install`.

The README's headline commands named `examples/...` files that exist only in a checkout, so after an install the
first command a stranger copied answered `[Errno 2] No such file or directory`. The examples were in the wheel all
along (`kube_noob/data/examples`) and no command exposed them. `kube-noob examples copy DIR` writes them out; the
README's own commands are run here, from a directory that is not the checkout, after that one step.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from kube_noob import demo
from kube_noob import examples as ex
from kube_noob.cli import main
from kube_noob.config import load_settings

ROOT = Path(__file__).resolve().parents[1]


def _bundled() -> list[str]:
    return sorted(p.name for p in demo.examples_dir().iterdir() if p.is_file())


# -- examples copy / list ------------------------------------------------------------------------------------------


def test_copy_writes_every_bundled_example_byte_for_byte(tmp_path: Path) -> None:
    written = ex.copy(tmp_path / "examples")
    assert [p.name for p in written] == _bundled()
    for p in written:
        assert p.read_bytes() == (demo.examples_dir() / p.name).read_bytes()


def test_copy_refuses_to_overwrite_and_writes_nothing(tmp_path: Path) -> None:
    dest = tmp_path / "examples"
    dest.mkdir()
    (dest / "events-scc.txt").write_text("mine", encoding="utf-8")
    with pytest.raises(ex.ExamplesError, match=r"events-scc\.txt"):
        ex.copy(dest)
    assert sorted(p.name for p in dest.iterdir()) == ["events-scc.txt"]
    assert (dest / "events-scc.txt").read_text(encoding="utf-8") == "mine"


def test_copy_overwrites_only_when_asked(tmp_path: Path) -> None:
    dest = tmp_path / "examples"
    dest.mkdir()
    (dest / "events-scc.txt").write_text("mine", encoding="utf-8")
    ex.copy(dest, overwrite=True)
    assert (dest / "events-scc.txt").read_bytes() == (demo.examples_dir() / "events-scc.txt").read_bytes()


def test_copy_never_follows_a_symbolic_link_out_of_the_target(tmp_path: Path) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("keep", encoding="utf-8")
    dest = tmp_path / "examples"
    dest.mkdir()
    (dest / "events-scc.txt").symlink_to(outside)
    for overwrite in (False, True):
        with pytest.raises(ex.ExamplesError, match="symbolic link"):
            ex.copy(dest, overwrite=overwrite)
        assert outside.read_text(encoding="utf-8") == "keep"
    assert sorted(p.name for p in dest.iterdir()) == ["events-scc.txt"]


def test_copy_refuses_a_target_that_is_a_file(tmp_path: Path) -> None:
    (tmp_path / "f").write_text("x", encoding="utf-8")
    with pytest.raises(ex.ExamplesError, match="not a directory"):
        ex.copy(tmp_path / "f")


def test_copied_files_get_ordinary_permissions(tmp_path: Path) -> None:
    old = os.umask(0o022)
    try:
        written = ex.copy(tmp_path / "examples")
    finally:
        os.umask(old)
    assert {stat.S_IMODE(p.stat().st_mode) for p in written} == {0o644}


def test_copy_is_deterministic(tmp_path: Path) -> None:
    a = [(p.name, p.read_bytes()) for p in ex.copy(tmp_path / "a")]
    b = [(p.name, p.read_bytes()) for p in ex.copy(tmp_path / "b")]
    assert a == b


def test_list_names_every_bundled_example_with_what_it_is_for() -> None:
    rows = ex.listing()
    assert [r["name"] for r in rows] == _bundled()
    assert all(r["what"] for r in rows)


def test_the_cli_lists_copies_and_refuses_with_exit_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["examples", "list"]) == 0
    assert "netpol-admin-tiers.yaml" in capsys.readouterr().out
    assert main(["examples", "copy", str(tmp_path / "ex")]) == 0
    out = capsys.readouterr().out
    assert f"wrote {len(_bundled())} files" in out and "kube-noob policy reach" in out
    assert main(["examples", "copy", str(tmp_path / "ex")]) == 2
    assert "--force" in capsys.readouterr().err
    assert main(["examples", "copy", str(tmp_path / "ex"), "--force"]) == 0


# -- the README, run as a stranger would ---------------------------------------------------------------------------


def _readme_commands() -> list[str]:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    blocks = re.findall(r"```bash\n(.*?)```", readme, re.S)
    return [line.strip() for b in blocks for line in b.splitlines() if line.strip().startswith("kube-noob ")]


def test_every_readme_command_that_names_examples_runs_after_examples_copy(tmp_path: Path) -> None:
    commands = _readme_commands()
    copy = [c for c in commands if c.startswith("kube-noob examples copy ")]
    uses = [c for c in commands if "examples/" in c and not c.startswith("kube-noob examples ")]
    assert copy and uses, "the README no longer shows the copy step or an examples/ command"
    assert commands.index(copy[0]) < min(commands.index(c) for c in uses), "copy must come before its use"
    work = tmp_path / "stranger"  # not the checkout: nothing named examples/ here until the README's step runs
    work.mkdir()
    env = {**os.environ, "KUBE_NOOB_DATA_DIR": str(tmp_path / "data"), "PYTHONSAFEPATH": "1"}
    for line in [copy[0], *uses]:
        argv = [sys.executable, "-m", "kube_noob", *line.split()[1:]]
        proc = subprocess.run(argv, check=False, cwd=work, env=env, capture_output=True, text=True, timeout=120)
        assert "No such file" not in proc.stderr and "Traceback" not in proc.stderr, (line, proc.stderr)
        # policy reach exits 1 for a denied flow by contract; 2 or more is a broken command
        assert proc.returncode in {0, 1}, (line, proc.returncode, proc.stderr)
        assert proc.stdout.strip(), line


def test_the_install_guide_names_no_example_file_without_the_copy_step() -> None:
    text = (ROOT / "docs" / "install.md").read_text(encoding="utf-8")
    if "examples/" in text:
        assert "kube-noob examples copy" in text


# -- demo -----------------------------------------------------------------------------------------------------------


def test_demo_list_keeps_its_columns_aligned(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["demo", "--list"]) == 0
    rows = [r for r in capsys.readouterr().out.splitlines() if r and not r.startswith("Run:")]
    starts = {len(r) - len(r[len(r.split()[0]) :].lstrip()) for r in rows}
    assert len(starts) == 1, rows


def test_the_doctor_demo_is_named_for_what_it_runs_and_posture_still_works(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert "doctor" in demo.SCENARIOS and "$ kube-noob doctor" in _demo_text("doctor")
    assert main(["demo", "posture"]) == 0  # a public id: kept, and it says what it now is
    out = capsys.readouterr().out
    assert "$ kube-noob doctor" in out and "kube-noob demo doctor" in out
    assert main(["demo", "--list"]) == 0
    listing = capsys.readouterr().out
    assert re.search(r"^posture\s.*doctor", listing, re.M)


def test_demo_all_runs_doctor_once(capsys: pytest.CaptureFixture[str]) -> None:
    lines: list[str] = []
    for name in demo.SCENARIOS:
        lines.append(name)
    assert lines.count("doctor") == 1 and "posture" not in demo.SCENARIOS


def _demo_text(name: str, keep: Path | None = None) -> str:
    lines: list[str] = []
    demo.run(name, load_settings(), lines.append, keep=keep)
    return "\n".join(lines)


def test_demo_must_gather_keep_leaves_the_input_and_the_report_behind(tmp_path: Path) -> None:
    keep = tmp_path / "kept"
    text = _demo_text("must-gather", keep)
    for name in ("must-gather.tar.gz", "report/report.md", "report/report.json", "report/case-draft.md"):
        assert (keep / name).is_file(), name
    assert str(keep) in text


def test_the_commands_a_kept_demo_prints_rerun_there(tmp_path: Path) -> None:
    keep = tmp_path / "kept"
    text = _demo_text("must-gather", keep)
    commands = [line[2:] for line in text.splitlines() if line.startswith("$ kube-noob ")]
    env = {**os.environ, "KUBE_NOOB_DATA_DIR": str(tmp_path / "data")}
    for line in commands:
        argv = [sys.executable, "-m", "kube_noob", *line.split()[1:]]
        if "--report" in argv:
            argv[argv.index("--report") + 1] = "report-again"
        proc = subprocess.run(argv, check=False, cwd=keep, env=env, capture_output=True, text=True, timeout=120)
        assert proc.returncode == 0, (line, proc.stderr)


def test_demo_keep_refuses_to_overwrite(tmp_path: Path) -> None:
    keep = tmp_path / "kept"
    _demo_text("must-gather", keep)
    with pytest.raises(ex.ExamplesError):
        _demo_text("must-gather", keep)


def test_demo_diagnose_keep_writes_the_examples_its_commands_name(tmp_path: Path) -> None:
    keep = tmp_path / "kept"
    text = _demo_text("diagnose", keep)
    for path in re.findall(r"-f (examples/\S+)", text):
        assert (keep / path).is_file(), path


def test_demo_keep_on_the_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["demo", "must-gather", "--keep", str(tmp_path / "k")]) == 0
    assert (tmp_path / "k" / "must-gather.tar.gz").is_file()
    assert main(["demo", "all", "--keep", str(tmp_path / "k2")]) == 2
    assert "one scenario" in capsys.readouterr().err
