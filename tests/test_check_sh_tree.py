"""scripts/check.sh tests the tree it is in, and says so before it runs anything.

`pip install -e .` records one checkout, and every git worktree of this repository shares that site-packages.
check.sh set no import root, so run from `.claude/worktrees/<name>` it collected the worktree's tests and ran them
against the MAIN checkout's modules: `14 failed, 8567 passed` on a branch whose fix was correct, 13 of the 14 that
branch's own new tests failing exactly as they fail without the fix. G264 was this script passing while the real
gate failed. This is the same defect facing the other way -- failing while the code is right -- and the wrong tree
was a working, slightly older copy of the same project, so nothing but the answer looked wrong (G346).

Each test here builds a throwaway tree holding a copy of the real script and a stub package, and runs the copy.
The interpreter running pytest already has some kube_noob importable (an editable install, or PYTHONPATH), and it
is never the throwaway one, which is the situation a worktree is in.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
CHECK = ROOT / "scripts" / "check.sh"
CI = ROOT / ".github" / "workflows" / "ci.yml"


def _tree(at: Path) -> Path:
    """A checkout-shaped directory: the real check.sh, and a kube_noob that exists nowhere else."""
    (at / "scripts").mkdir(parents=True)
    (at / "src" / "kube_noob").mkdir(parents=True)
    shutil.copy(CHECK, at / "scripts" / "check.sh")
    (at / "src" / "kube_noob" / "__init__.py").write_text("", encoding="utf-8")
    return at.resolve()


def _run(script: Path, *args: str, cwd: Path, python: str = sys.executable) -> subprocess.CompletedProcess[str]:
    if shutil.which("bash") is None:
        pytest.skip("bash is not installed")
    # No PYTHONPATH from the caller: the script has to supply its own, which is the behaviour under test.
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env["PYTHON"] = python
    return subprocess.run(
        ["bash", str(script), *args],  # noqa: S607
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )


def test_check_sh_imports_from_its_own_tree_not_the_installed_one(tmp_path: Path) -> None:
    tree = _tree(tmp_path / "worktree")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    out = _run(tree / "scripts" / "check.sh", "--where", cwd=elsewhere)
    assert out.returncode == 0, out.stderr
    mine = tree / "src" / "kube_noob" / "__init__.py"
    assert f"testing {tree} (kube_noob from {mine})" in out.stdout, out.stdout + out.stderr


def test_where_says_it_ran_no_gate(tmp_path: Path) -> None:
    """--where exits 0 having tested nothing, so its output must not be mistakable for a pass."""
    tree = _tree(tmp_path / "worktree")
    out = _run(tree / "scripts" / "check.sh", "--where", cwd=tree)
    assert out.returncode == 0, out.stderr
    assert "no gate was run" in out.stdout and "not a pass" in out.stdout
    assert "All checks passed" not in out.stdout


def test_check_sh_finds_its_tree_through_a_symlink_and_a_relative_one(tmp_path: Path) -> None:
    """`dirname "$0"` on a symlink is the directory the link is in, which has no src/ beside it."""
    tree = _tree(tmp_path / "worktree")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "check").symlink_to(tree / "scripts" / "check.sh")
    (bin_dir / "again").symlink_to("check")  # relative, and a link to a link
    for name in ("check", "again"):
        out = _run(Path(name), "--where", cwd=bin_dir)
        assert out.returncode == 0, f"{name}: {out.stderr}"
        assert f"testing {tree} " in out.stdout, f"{name}: {out.stdout}"


def test_an_interpreter_that_imports_another_tree_stops_the_run_and_both_paths_are_named(tmp_path: Path) -> None:
    """Exporting PYTHONPATH is an intention. An interpreter with its own answer must not be believed.

    Run WITHOUT --where, so that what stops the script is the refusal and not the flag: with the check removed
    this tree fails later and differently, on a generator script it does not have.
    """
    tree = _tree(tmp_path / "worktree")
    other = _tree(tmp_path / "main-checkout")
    pinned = tmp_path / "python-pinned-elsewhere"
    pinned.write_text(f'#!/bin/sh\nPYTHONPATH="{other}/src" exec "{sys.executable}" "$@"\n', encoding="utf-8")
    pinned.chmod(0o755)
    out = _run(tree / "scripts" / "check.sh", cwd=tree, python=str(pinned))
    assert out.returncode == 1, out.stdout + out.stderr
    assert "REFUSING TO RUN" in out.stderr and "No gate was run" in out.stderr
    assert f"expected under: {tree}/src\n" in out.stderr
    assert f"imported from:  {other}/src/kube_noob/__init__.py\n" in out.stderr
    assert "All checks passed" not in out.stdout


def test_an_interpreter_that_cannot_import_it_at_all_stops_the_run_too(tmp_path: Path) -> None:
    tree = _tree(tmp_path / "worktree")
    out = _run(tree / "scripts" / "check.sh", cwd=tree, python=str(tmp_path / "no-such-python"))
    assert out.returncode == 1, out.stdout + out.stderr
    assert "REFUSING TO RUN" in out.stderr and "the import failed" in out.stderr


def test_an_argument_check_sh_does_not_know_is_refused_rather_than_ignored(tmp_path: Path) -> None:
    """`--wher` must not quietly become a twenty-minute run, nor `--fast` a full one that someone believes was fast."""
    tree = _tree(tmp_path / "worktree")
    out = _run(tree / "scripts" / "check.sh", "--wher", cwd=tree)
    assert out.returncode == 2 and "usage:" in out.stderr, out.stdout + out.stderr


# What drives a built artifact rather than the source tree. Each must run without the import root, or it imports
# src/ and the step that proves the wheel (or the plugin's locked environment) works proves only that src/ does.
_ARTIFACT = re.compile(r'"\$w"/bin/(?:pip|python|kube-noob)|scripts/airgap_check\.sh|scripts/e2e_plugin\.py')


def test_every_step_that_drives_a_built_artifact_runs_without_the_import_root() -> None:
    body = CHECK.read_text(encoding="utf-8")
    assert 'installed() { env -u PYTHONPATH "$@"; }' in body
    steps = [
        line.strip()
        for line in body.splitlines()
        if _ARTIFACT.search(line) and not line.lstrip().startswith(("#", "notrun+=")) and "installed()" not in line
    ]
    assert len(steps) >= 8, f"only {len(steps)} artifact steps found; the expression has stopped matching"
    leaking = [s for s in steps if "installed " not in _ARTIFACT.split(s, maxsplit=1)[0]]
    assert leaking == [], "these would import src/ instead of the artifact they claim to drive:\n" + "\n".join(leaking)
    assert re.search(r'^imports_from "\$w" "[^"]+" \\\n  installed "\$w"/bin/python', body, re.M), (
        "the wheel's own import root is not measured"
    )


def test_check_sh_runs_mypy_with_the_arguments_ci_does() -> None:
    """CI runs bare `mypy`, which reads `packages` from pyproject.toml. `mypy src` is a different set of files."""
    spec: dict[str, Any] = yaml.safe_load(CI.read_text(encoding="utf-8"))
    runs = [str(s.get("run", "")).strip() for s in spec["jobs"]["lint"]["steps"]]
    in_ci = {r.removeprefix("mypy").strip() for r in runs if r == "mypy" or r.startswith("mypy ")}
    assert in_ci, "ci/lint no longer runs mypy; this test is comparing nothing"
    here = {m.strip() for m in re.findall(r'^"\$py" -m mypy(.*)$', CHECK.read_text(encoding="utf-8"), re.M)}
    assert here == in_ci, f"check.sh runs `mypy {sorted(here)}` and CI runs `mypy {sorted(in_ci)}`"
