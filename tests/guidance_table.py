"""One reader for the rows of `docs/guidance.md`, because a table has one shape and a check that reads another
shape reads nothing (G372).

`tests/test_guidance.py` resolved every citation in the table through a three-column expression,
`^\\| (G\\d{2,3}) \\| (.+?) \\| (.+) \\|$`. Two things in it decided which rows the citation check could see, and
both of them failed silently:

* six rows are written in two columns -- G279, G319, G320, G321, G322, G325 -- so the expression did not match
  them and they were dropped before any citation was resolved. 329 of 335 rows were read, and the six rows with
  the longest citation lists in the table (G279 alone names 68 tests) were the ones nothing checked. The hole was
  recorded in `tests/test_append_only_duplicates.py` under G347 and left open;
* `G\\d{2,3}` cannot match a four-digit id, so `G1000` and everything after it would have been skipped in the
  same silent way. The table ends at G372, so that one had not arrived yet.

This module reads a row by its id and takes its citations from everything after the id, whatever the row's column
shape is: a citation is a backticked `tests/<file>.py::<test>` or `ci:<step or job name>`, and which cell it sits
in is a question about markdown rendering, not about which checks enforce a rule. `tests/test_guidance.py` reads
the table through here and nothing else parses a guidance row, so there is one answer to "what does this row
cite" (review class 9).

`tests/test_append_only_duplicates.py` keeps its own looser id expression on purpose (G347): its job is to find a
row this reader might not, so sharing the expression would defeat it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GUIDANCE = ROOT / "docs" / "guidance.md"

#: A table row: a leading pipe, a G-id of any length, a pipe, and a body ending in the closing pipe. The id is
#: not bounded in length -- a bound is a silent skip waiting for the table to reach it.
ROW = re.compile(r"^\|\s*(G\d+)\s*\|(.*)\|[ \t]*$")
#: Anything the table wrote in backticks. The prefix decides whether it is a citation.
REF = re.compile(r"`([^`]+)`")
#: The two reference formats docs/guidance.md documents.
REF_PREFIXES = ("tests/", "ci:")


@dataclass(frozen=True)
class Row:
    """One row of the table: its id, everything the row says after the id, and the checks it cites."""

    id: str
    body: str
    refs: tuple[str, ...]


def parse(text: str) -> list[Row]:
    """Every row in `text`, in file order, however many columns the row is written in."""
    rows = []
    for line in text.splitlines():
        m = ROW.match(line)
        if m:
            body = m.group(2)
            refs = tuple(r for r in REF.findall(body) if r.startswith(REF_PREFIXES))
            rows.append(Row(m.group(1), body.strip(), refs))
    return rows


def rows(path: Path = GUIDANCE) -> list[Row]:
    """Every row of `docs/guidance.md`."""
    return parse(path.read_text(encoding="utf-8"))


def id_lines(text: str) -> list[str]:
    """Every line that opens with a G-id, by the loosest expression that can find one.

    `parse` must read all of these. The two counts differing is the defect this module exists to close: a row
    whose shape the reader does not recognise is a rule whose checks nobody resolved.
    """
    return [line for line in text.splitlines() if re.match(r"^\|\s*G\d+", line)]
