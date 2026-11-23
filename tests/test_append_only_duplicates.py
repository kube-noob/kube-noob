"""A line that union merge kept twice is found here, by name, because the merge will not report it.

`.gitattributes` merges `CHANGELOG.md` and `docs/guidance.md` by union (G297), which is what stops every open
branch conflicting in those two files each time another one lands. Union has a cost that an ordinary merge does
not: where it would have stopped, it keeps both sides' lines, and when both sides carry the SAME line it keeps
that line twice and says nothing. A branch stacked on one that has since merged is all it takes -- `main` holds
row X after someone else's row, the branch holds X followed by its own, the two hunks differ, and X is written
twice. It happened twice in one session: G335 once, then six rows at a time (G332, G334, G335, G336, G337, G339)
with three changelog bullets.

`tests/test_guidance.py` already refuses a duplicate id, and two things were left open (G347):

- it reads rows with a three-column expression, and six rows are written in two columns (G279, G319-G322, G325),
  so a duplicate of any of those was never seen at all -- an unrecognised shape reading as a pass;
- its failure says `duplicate guidance ids` and `assert 305 == 304`, which names no id, in a 320-line table whose
  rows run to twenty-nine thousand characters;

and nothing read `CHANGELOG.md` for a repeated bullet. So this file reads row ids by the loosest expression that
can find one -- the shell form is `grep -o '^| G[0-9]*' docs/guidance.md | sort | uniq -d` -- and names what it
finds.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from collections import Counter
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GUIDANCE = ROOT / "docs" / "guidance.md"
CHANGELOG = ROOT / "CHANGELOG.md"

# Deliberately not the row expression in tests/test_guidance.py: that one decides which rows have their citations
# resolved, and a row it does not match is a row it does not count. This one only has to find an id.
_ROW_ID = re.compile(r"^\| (G\d+)", re.M)


def _row_ids(text: str) -> list[str]:
    return _ROW_ID.findall(text)


def _sections(text: str) -> dict[str, list[str]]:
    """The first line of every bullet, per `## ` section, in file order.

    Every section is read, not only `## Unreleased`. The duplicate a union merge leaves lands in whichever
    section both branches were appending to, and on a release branch that is the version section: `bump_version`
    renames `## Unreleased` to `## <version>` and leaves an empty `## Unreleased` behind, so a check that reads
    only `## Unreleased` can read nothing exactly when a release is being cut -- which is when a silently
    duplicated bullet would actually ship. Scanning every section also catches the repeat across a section
    boundary that a release roll can produce.
    """
    lines = text.splitlines()
    heads = [i for i, line in enumerate(lines) if line.startswith("## ")]
    assert heads, "CHANGELOG.md has no `## ` heading, so this would be reading nothing"
    out: dict[str, list[str]] = {}
    for n, i in enumerate(heads):
        end = heads[n + 1] if n + 1 < len(heads) else len(lines)
        out[lines[i][3:].strip()] = [line for line in lines[i + 1 : end] if line.startswith("- ")]
    return out


def _twice(items: list[str]) -> list[str]:
    return sorted(item for item, n in Counter(items).items() if n > 1)


def _title(bullet: str) -> str:
    """Enough of a bullet to find it: its bold lead if it has one, else its first hundred characters."""
    lead = re.match(r"- \*\*(.+?)\*\*", bullet)
    return lead.group(1) if lead else bullet[:100]


def test_no_guidance_row_id_appears_twice() -> None:
    ids = _row_ids(GUIDANCE.read_text(encoding="utf-8"))
    assert len(ids) >= 300, f"only {len(ids)} rows found in docs/guidance.md; the expression has stopped matching"
    twice = _twice(ids)
    assert twice == [], (
        f"docs/guidance.md has more than one row for {', '.join(twice)}. A union merge keeps a row both sides "
        "carry and reports no conflict; delete the repeated row. If the two rows differ, two branches took the "
        "same number: the later change takes the next free one, in its tests, its changelog bullet and its row."
    )


def test_no_changelog_bullet_appears_twice_in_any_section() -> None:
    sections = _sections(CHANGELOG.read_text(encoding="utf-8"))
    assert sum(len(b) for b in sections.values()) >= 50, (
        f"only {sum(len(b) for b in sections.values())} bullets found across "
        f"{len(sections)} sections; the expression has stopped matching and this would be comparing nothing"
    )
    repeats = {name: [_title(b) for b in _twice(bullets)] for name, bullets in sections.items()}
    offenders = {name: titles for name, titles in repeats.items() if titles}
    assert offenders == {}, (
        "CHANGELOG.md has the same bullet more than once in one section: "
        + "; ".join(f"`## {name}`: " + ", ".join(repr(t) for t in titles) for name, titles in offenders.items())
        + ". A union merge keeps a line both sides carry and reports no conflict; delete the repeat."
    )


def test_distinct_rows_and_bullets_are_left_alone() -> None:
    """The control: the check must stay quiet on what every ordinary change produces."""
    table = "| ID | Rule | Enforced by |\n|---|---|---|\n| G01 | a | `t` |\n| G02 | a | `t` |\n| G100 | G01 again |\n"
    assert _twice(_row_ids(table)) == []
    log = "# Changelog\n\n## Unreleased\n\n- one (G02)\n\n- two (G02)\n  wrapped\n\n## 0.1.0\n\n- one (G02)\n"
    sections = _sections(log)
    assert sections == {"Unreleased": ["- one (G02)", "- two (G02)"], "0.1.0": ["- one (G02)"]}
    # The same bullet in two different sections is a release roll, not a duplicate: each section is its own list.
    assert all(_twice(bullets) == [] for bullets in sections.values())


def test_a_repeated_row_is_named_whatever_its_shape() -> None:
    """A three-column row and a two-column one, each repeated; and a number two different rows both claim."""
    table = (
        "| G01 | a | `t` |\n| G02 | b | `t` |\n| G02 | b | `t` |\n"
        "| G319 | two columns, citations inline `ci:x`. |\n| G319 | two columns, citations inline `ci:x`. |\n"
        "| G340 | one branch's | `t` |\n| G340 | another's | `t` |\n"
    )
    assert _twice(_row_ids(table)) == ["G02", "G319", "G340"]


def test_a_repeated_bullet_is_named_by_its_lead() -> None:
    log = "## Unreleased\n\n- **The gate passed (G1).** Why.\n- plain\n- **The gate passed (G1).** Why.\n- plain\n"
    assert [_title(b) for b in _twice(_sections(log)["Unreleased"])] == ["The gate passed (G1).", "- plain"]
    # And in a version section, which is where the duplicate lands while a release is being cut.
    rolled = "## Unreleased\n\n## 0.10.0 - 2026-01-01\n\n- **Twice (G2).** Why.\n- **Twice (G2).** Why.\n"
    assert _sections(rolled)["Unreleased"] == []
    assert [_title(b) for b in _twice(_sections(rolled)["0.10.0 - 2026-01-01"])] == ["Twice (G2)."]


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false", *args],  # noqa: S607
        cwd=repo,
        capture_output=True,
        text=True,
        check=True,
    )


def test_the_union_merge_that_repeats_a_row_is_silent_and_this_check_is_not(tmp_path: Path) -> None:
    """The mechanism, run rather than described: a stacked branch, this repository's own .gitattributes, no conflict.

    `main` took someone else's row and then the row this branch was stacked on; the branch carries that row
    followed by its own. If git ever stops repeating the line here, this test says so and the two above can go.
    """
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    repo = tmp_path / "r"
    (repo / "docs").mkdir(parents=True)
    table = repo / "docs" / "guidance.md"
    base = "| ID | Rule | Enforced by |\n|---|---|---|\n| G01 | old | `t` |\n"
    stacked_on, other, own = "| G02 | stacked on | `t` |\n", "| G04 | someone else's | `t` |\n", "| G03 | own | `t` |\n"
    _git(repo, "init", "-q", "-b", "main")
    (repo / ".gitattributes").write_text((ROOT / ".gitattributes").read_text(encoding="utf-8"), encoding="utf-8")
    table.write_text(base, encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "base")
    _git(repo, "checkout", "-q", "-b", "branch")
    table.write_text(base + stacked_on + own, encoding="utf-8")
    _git(repo, "commit", "-qam", "the branch")
    _git(repo, "checkout", "-q", "main")
    table.write_text(base + other + stacked_on, encoding="utf-8")
    _git(repo, "commit", "-qam", "main moved")
    _git(repo, "merge", "branch", "-m", "merge")  # check=True: the merge succeeds, which is the problem

    merged = table.read_text(encoding="utf-8")
    assert "<<<<<<<" not in merged
    assert merged.count(stacked_on) == 2, merged
    assert _twice(_row_ids(merged)) == ["G02"]
