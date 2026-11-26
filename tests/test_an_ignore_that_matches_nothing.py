"""A Dependabot `ignore` entry that matches no dependency protects nothing, and reads as though it does (G412).

G398 pinned CodeQL back to v4.39.3 and added `ignore: github/codeql-action, versions: [4.39.4]` so Dependabot would
not propose the version again. The workflows use the sub-actions `github/codeql-action/init` and `/analyze`, and
Dependabot matches `dependency-name` against those exact names, so the entry matched nothing and #140 proposed
4.39.4 the next day. Every `ignore` entry for the github-actions ecosystem must now match at least one action the
workflows actually use.
"""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def _actions_used() -> set[str]:
    used: set[str] = set()
    for wf in sorted((ROOT / ".github" / "workflows").glob("*.y*ml")):
        for m in re.finditer(r"^\s*(?:-\s*)?uses:\s*([^@\s#]+)@", wf.read_text(encoding="utf-8"), flags=re.M):
            if not m.group(1).startswith("./"):
                used.add(m.group(1))
    return used


def _ignores() -> list[str]:
    cfg = yaml.safe_load((ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8"))
    names = []
    for update in cfg.get("updates") or ():
        if update.get("package-ecosystem") != "github-actions":
            continue
        for entry in update.get("ignore") or ():
            names.append(str(entry["dependency-name"]))
    return names


def test_the_workflows_use_actions_at_all() -> None:
    """The check below is vacuous if nothing is read; a broken regex would make every ignore 'match nothing'."""
    used = _actions_used()
    assert "github/codeql-action/init" in used and "actions/checkout" in used, sorted(used)


def test_every_actions_ignore_matches_an_action_the_workflows_use() -> None:
    used = _actions_used()
    names = _ignores()
    assert names, "no github-actions ignore entries were read; if that is now true, delete this test deliberately"
    dead = [n for n in names if not any(fnmatch.fnmatchcase(u, n) for u in used)]
    assert not dead, f"these ignore entries match no action any workflow uses, so they ignore nothing: {dead}"


def test_the_codeql_ignore_covers_both_pinned_sub_actions() -> None:
    names = _ignores()
    for sub in ("github/codeql-action/init", "github/codeql-action/analyze"):
        assert any(fnmatch.fnmatchcase(sub, n) for n in names), f"{sub} is pinned back but not ignored"
