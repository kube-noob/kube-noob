"""The two append-only documents merge by union, and nothing else does.

Every change in this repository appends a bullet to the top of `## Unreleased` in `CHANGELOG.md` and a row to the
end of `docs/guidance.md`. Two branches cut from the same `main` therefore insert at the same line in both files,
so every merge of `main` into an open branch conflicts in exactly those two places -- arithmetic, not bad luck, and
it has cost this repository whole rounds of conflict resolution that produced no code. `merge=union` keeps both
sides' lines, which is the right answer for a file that is only ever appended to.

It is the wrong answer for a file whose lines get rewritten: union keeps BOTH versions of a line both sides
changed, so a generated number would appear twice. The generated documents therefore keep the ordinary three-way
merge, and this file asserts that the union list is exactly the two append-only documents.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
APPEND_ONLY = ("CHANGELOG.md", "docs/guidance.md")
# Rewritten in place by scripts/doc_numbers.py or scripts/compliance_doc.py: union would duplicate a number.
GENERATED = ("docs/roadmap.md", "docs/limits.md", "docs/use-cases.md", "docs/compliance.md", "docs/safety-contract.md")


def _union_paths() -> set[str]:
    paths = set()
    for raw in (ROOT / ".gitattributes").read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        pattern, *attrs = line.split()
        if "merge=union" in attrs:
            paths.add(pattern)
    return paths


def test_the_append_only_documents_merge_by_union() -> None:
    assert _union_paths() >= set(APPEND_ONLY)


def test_no_generated_document_merges_by_union() -> None:
    """A document whose lines are rewritten must not keep both versions of a rewritten line."""
    assert _union_paths() & set(GENERATED) == set()


def test_union_is_declared_for_nothing_else() -> None:
    """The list is exhaustive on purpose: a file joins it only with a test that it is append-only."""
    assert _union_paths() == set(APPEND_ONLY)


def _git(repo: Path, *args: str) -> str:
    out = subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false", *args],  # noqa: S607
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )
    return out.stdout + out.stderr


def _repo_with(tmp_path: Path, name: str, base: str, ours: str, theirs: str) -> Path:
    """Two branches each change `name` the way a kube-noob branch does, then merge."""
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    repo = tmp_path / "r"
    (repo / Path(name).parent).mkdir(parents=True, exist_ok=True)
    _git(repo, "init", "-q", "-b", "main")
    (repo / ".gitattributes").write_text((ROOT / ".gitattributes").read_text(encoding="utf-8"), encoding="utf-8")
    (repo / name).write_text(base, encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "base")
    _git(repo, "checkout", "-q", "-b", "side")
    (repo / name).write_text(theirs, encoding="utf-8")
    _git(repo, "commit", "-qam", "theirs")
    _git(repo, "checkout", "-q", "main")
    (repo / name).write_text(ours, encoding="utf-8")
    _git(repo, "commit", "-qam", "ours")
    _git(repo, "merge", "side", "-m", "merge")
    return repo


def test_two_bullets_prepended_to_the_unreleased_section_both_survive(tmp_path: Path) -> None:
    base = "# Changelog\n\n## Unreleased\n\n- old entry\n"
    repo = _repo_with(
        tmp_path,
        "CHANGELOG.md",
        base,
        "# Changelog\n\n## Unreleased\n\n- ours new entry\n- old entry\n",
        "# Changelog\n\n## Unreleased\n\n- theirs new entry\n- old entry\n",
    )
    merged = (repo / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "<<<<<<<" not in merged and ">>>>>>>" not in merged
    assert "- ours new entry" in merged and "- theirs new entry" in merged
    assert merged.count("- old entry") == 1, merged


def test_two_rows_appended_to_guidance_both_survive(tmp_path: Path) -> None:
    base = "| ID | Rule | Enforced by |\n|---|---|---|\n| G01 | old | `tests/t.py::test_old` |\n"
    repo = _repo_with(
        tmp_path,
        "docs/guidance.md",
        base,
        base + "| G02 | ours | `tests/t.py::test_ours` |\n",
        base + "| G03 | theirs | `tests/t.py::test_theirs` |\n",
    )
    merged = (repo / "docs/guidance.md").read_text(encoding="utf-8")
    assert "<<<<<<<" not in merged and ">>>>>>>" not in merged
    rows = re.findall(r"^\| (G\d+) \|", merged, re.M)
    assert rows == ["G01", "G02", "G03"], merged
    assert len(rows) == len(set(rows))


def test_a_generated_number_both_sides_rewrote_still_conflicts(tmp_path: Path) -> None:
    """Why the union list stops at two files: a rewritten line would otherwise be kept twice."""
    base = "about 76,000 lines across 158 modules\n"
    repo = _repo_with(
        tmp_path,
        "docs/roadmap.md",
        base,
        "about 76,000 lines across 159 modules\n",
        "about 76,000 lines across 160 modules\n",
    )
    merged = (repo / "docs/roadmap.md").read_text(encoding="utf-8")
    assert "<<<<<<<" in merged, "a rewritten number must be resolved by hand, not kept twice"
