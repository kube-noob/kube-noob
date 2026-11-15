"""The package the suite imports, and the CLI it shells out to, are this checkout -- not an installed copy.

A development environment can have `kube_noob` installed editable from ANOTHER checkout: `pip install -e` records
one absolute path, and a worktree that shares that environment imports whatever that path holds. The suite then
passes or fails against a different branch's code, silently, and the result is worthless in the direction that
matters -- it can report a defect that does not exist, or a fix that is not there.

This happened three times on 2026-11-15 in one session, to three different readers:

* `python -m kube_noob diagnose` on an Alertmanager payload reported that the names in its suggested commands came
  from an attacker-controlled annotation -- the G274 guarantee broken on `main`. The same input through this
  checkout answered correctly. The "regression" was an install pointing at a checkout that predated the fix.
* `tests/test_verify_hook.py` failed locally because the `kube-noob` on PATH had no `verify` subcommand at all: its
  usage line listed the commands of another branch.
* `scripts/safety_contract.py --check` reported the contract document stale against a `kube_noob` in
  site-packages, on two branches where it was current.

So this is not a convenience check. An environment that cannot say which code it just ran is the same defect class
as the product's own: an answer whose provenance is unknown must not read as an answer. CI installs the checkout it
tests, so these pass there and cost nothing; they fail only where a reader was already being misled.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

_HOW = (
    "Create an environment for THIS worktree and install it there:\n"
    '    uv venv -q .venv && . .venv/bin/activate && uv pip install -q -e ".[dev]"\n'
    "or, for one command, put this checkout first on the import path:\n"
    "    PYTHONPATH=src python -m kube_noob ...\n"
    "Until then nothing this environment reports is about this branch."
)


def test_the_imported_package_is_this_checkout_and_not_an_installed_copy() -> None:
    """`import kube_noob` resolves inside this worktree's `src/`, so a passing suite is about this branch."""
    import kube_noob

    where = Path(kube_noob.__file__).resolve()
    assert where.is_relative_to(SRC), (
        f"the suite imported kube_noob from {where}\n"
        f"but this checkout's package is under {SRC}\n"
        f"Every result in this run describes the code at that other path, not this branch.\n\n{_HOW}"
    )


def test_every_source_module_resolves_to_this_checkout() -> None:
    """One module is not enough: a namespace package or a stale `.pth` can split a package across two trees, so
    the half a test imports can differ from the half it asserts about."""
    import kube_noob

    stray = sorted(
        name
        for name, module in sys.modules.items()
        if name == "kube_noob" or name.startswith("kube_noob.")
        if (origin := getattr(getattr(module, "__spec__", None), "origin", None))
        if origin not in (None, "built-in", "frozen")
        if not Path(origin).resolve().is_relative_to(SRC)
    )
    assert not stray, f"imported from outside {SRC}: {stray[:8]}\n\n{_HOW}"
    assert all(Path(p).resolve().is_relative_to(SRC) for p in kube_noob.__path__), kube_noob.__path__


@pytest.mark.skipif(shutil.which("kube-noob") is None, reason="no kube-noob console script on PATH")
def test_the_console_script_on_path_runs_this_checkouts_code() -> None:
    """A test that shells out to `kube-noob` is answered by the console script on PATH, and that is a DIFFERENT
    resolution from `import kube_noob`: the two can point at different checkouts at the same time, which is how
    this surfaced -- as a subcommand this branch adds "not existing" rather than as a stale install.

    Asked without adding anything to the CLI: a console script is a small file whose first line names the
    interpreter of the environment that installed it, and that interpreter's own `import kube_noob` is what the
    script will get. No flag, no product change, nothing to keep in step.
    """
    script = Path(shutil.which("kube-noob") or "")
    shebang = script.read_text(encoding="utf-8", errors="replace").splitlines()[:1]
    if not shebang or not shebang[0].startswith("#!"):
        pytest.skip(f"{script} is not a text console script with a shebang")
    interpreter = Path(shebang[0][2:].strip().split()[0])
    if not interpreter.is_file():
        pytest.fail(f"{script} names the interpreter {interpreter}, which is not there.\n\n{_HOW}")
    out = subprocess.run(
        [str(interpreter), "-c", "import kube_noob, sys; sys.stdout.write(kube_noob.__file__)"],
        capture_output=True,
        text=True,
        timeout=60,
        env={k: v for k, v in os.environ.items() if k != "PYTHONPATH"},
        check=False,
    )
    if out.returncode != 0:
        pytest.fail(
            f"the environment behind {script} cannot import kube_noob at all (exit {out.returncode}): "
            f"{out.stderr.strip()[:300]}\n\n{_HOW}"
        )
    where = Path(out.stdout.strip()).resolve()
    assert where.is_relative_to(SRC), (
        f"the kube-noob on PATH runs {where}, not this checkout's {SRC}\n"
        f"Any test or script that shells out to the CLI is answered by that other checkout.\n\n{_HOW}"
    )
