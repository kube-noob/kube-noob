"""The skill's install hint quoted dependency versions that only a test compared with the lock.

Dependabot bumps `plugin/kube-noob/uv.lock`. `skill/kube-noob/SKILL.md` and `skill/kube-noob/scripts/kn.py` each
carried their own copy of three of those versions, hand-written. That is two sources of truth for one fact
(review class 9): the lock moved, the copies did not, and the only thing that noticed was one assertion deep in
the test suite -- so the bump arrived as four failing `test` legs rather than as "the generator says rewrite the
pins". A dependency bump should never need a human to remember a second file.

`scripts/build_skill.py --write` now derives the pins from the lock and `--check` refuses when they disagree, which
puts the failure in the generator gate that `scripts/check.sh` and CI's lint job run before the suite (G349).
"""

from __future__ import annotations

import importlib.util
import re
import shutil
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "plugin" / "kube-noob" / "uv.lock"
SKILL = ROOT / "skill" / "kube-noob"
PIN_FILES = ("SKILL.md", "scripts/kn.py")


def _load() -> Any:
    spec = importlib.util.spec_from_file_location("build_skill_pins", ROOT / "scripts" / "build_skill.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["build_skill_pins"] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def sandbox(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    """A throwaway copy of the lock and the two pinned files, with the module pointed at it.

    The tests that prove the check fires must move a version, and moving one in the repository would leave the
    working tree dirty for every other test in the run.
    """
    mod = _load()
    (tmp_path / "plugin" / "kube-noob").mkdir(parents=True)
    (tmp_path / "skill" / "kube-noob" / "scripts").mkdir(parents=True)
    shutil.copyfile(LOCK, tmp_path / "plugin" / "kube-noob" / "uv.lock")
    for rel in PIN_FILES:
        shutil.copyfile(SKILL / rel, tmp_path / "skill" / "kube-noob" / rel)
    monkeypatch.setattr(mod, "ROOT", tmp_path)
    monkeypatch.setattr(mod, "PLUGIN_LOCK", tmp_path / "plugin" / "kube-noob" / "uv.lock")
    monkeypatch.setattr(mod, "SKILL", tmp_path / "skill" / "kube-noob")
    return mod


def _pins_in(path: Path) -> set[tuple[str, str]]:
    return set(re.findall(r"\b(pydantic|PyYAML|jsonschema)==([0-9][^\s`'\")]*)", path.read_text(encoding="utf-8")))


def test_the_lock_is_the_only_place_these_three_versions_are_decided() -> None:
    mod = _load()
    pins = mod.lock_pins()
    assert set(pins) == {"pydantic", "PyYAML", "jsonschema"}
    for rel in PIN_FILES:
        quoted = _pins_in(SKILL / rel)
        assert quoted, f"{rel} quotes no dependency version at all"
        for name, version in pins.items():
            assert (name, version) in quoted, f"{rel} pins {name} at {dict(quoted).get(name)}, lock says {version}"


def test_the_repository_as_committed_passes_the_pin_check() -> None:
    assert _load().pin_problems() == []


def test_a_lock_that_moved_without_the_skill_is_named_with_both_versions(sandbox: Any) -> None:
    lock = sandbox.PLUGIN_LOCK
    lock.write_text(
        lock.read_text(encoding="utf-8").replace(
            f'name = "pydantic"\nversion = "{sandbox.lock_pins()["pydantic"]}"',
            'name = "pydantic"\nversion = "99.0.1"',
        ),
        encoding="utf-8",
    )
    problems = sandbox.pin_problems()
    assert len(problems) == 2, problems
    for rel, problem in zip(PIN_FILES, problems, strict=True):
        assert rel in problem and "pydantic==99.0.1" in problem and "build_skill.py --write" in problem


def test_a_file_that_pins_nothing_is_a_problem_and_never_a_pass(sandbox: Any) -> None:
    """An absence must not read as agreement: a hint that names no version installs nothing."""
    target = sandbox.SKILL / "scripts" / "kn.py"
    target.write_text(
        re.sub(r"\b(pydantic|PyYAML|jsonschema)==[0-9][^\s`'\")]*", r"\1", target.read_text(encoding="utf-8")),
        encoding="utf-8",
    )
    problems = [p for p in sandbox.pin_problems() if "kn.py" in p]
    assert len(problems) == 3, problems
    assert all("pins nothing" in p for p in problems), problems


def test_a_lock_missing_one_of_the_three_is_refused_and_not_defaulted(sandbox: Any) -> None:
    lock = sandbox.PLUGIN_LOCK
    lock.write_text(
        lock.read_text(encoding="utf-8").replace('name = "jsonschema"', 'name = "jsonschema-other"'), encoding="utf-8"
    )
    with pytest.raises(ValueError, match="pins no version for jsonschema"):
        sandbox.lock_pins()
    assert sandbox.pin_problems() == ["plugin/kube-noob/uv.lock pins no version for jsonschema"]


def test_write_rewrites_both_files_from_the_lock_and_then_changes_nothing(sandbox: Any) -> None:
    lock = sandbox.PLUGIN_LOCK
    lock.write_text(
        lock.read_text(encoding="utf-8").replace(
            f'name = "pyyaml"\nversion = "{sandbox.lock_pins()["PyYAML"]}"', 'name = "pyyaml"\nversion = "99.0.2"'
        ),
        encoding="utf-8",
    )
    assert sorted(p.as_posix() for p in sandbox.rewrite_pins(sandbox.lock_pins())) == sorted(PIN_FILES)
    assert sandbox.pin_problems() == []
    for rel in PIN_FILES:
        assert ("PyYAML", "99.0.2") in _pins_in(sandbox.SKILL / rel)
    assert sandbox.rewrite_pins(sandbox.lock_pins()) == []


def test_rewriting_leaves_everything_but_the_version_alone(sandbox: Any) -> None:
    """The install hint is prose the model follows; a rewrite that reflowed it would change instructions."""
    before = {rel: (sandbox.SKILL / rel).read_text(encoding="utf-8") for rel in PIN_FILES}
    lock = sandbox.PLUGIN_LOCK
    lock.write_text(
        lock.read_text(encoding="utf-8").replace(
            f'name = "pydantic"\nversion = "{sandbox.lock_pins()["pydantic"]}"',
            'name = "pydantic"\nversion = "99.0.3"',
        ),
        encoding="utf-8",
    )
    sandbox.rewrite_pins(sandbox.lock_pins())
    for rel, old in before.items():
        new = (sandbox.SKILL / rel).read_text(encoding="utf-8")
        assert len(new.splitlines()) == len(old.splitlines())
        expected = re.sub(r"\bpydantic==[0-9][^\s`'\")]*", "pydantic==99.0.3", old)
        assert new == expected
