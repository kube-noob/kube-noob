"""`docs/review-classes.md` is the durable form of the brief the adversarial reviews worked from.

Two things keep it honest: the classes are numbered without gaps (append, never renumber), and `AGENTS.md`, which
tells the next author to read it, states the count the table actually has.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORDS = {
    20: "twenty",
    21: "twenty-one",
    22: "twenty-two",
    23: "twenty-three",
    24: "twenty-four",
    25: "twenty-five",
    26: "twenty-six",
    27: "twenty-seven",
    28: "twenty-eight",
    29: "twenty-nine",
    30: "thirty",
}


def _class_numbers() -> list[int]:
    text = (ROOT / "docs" / "review-classes.md").read_text(encoding="utf-8")
    return [int(m.group(1)) for m in re.finditer(r"^\| (\d+) \| ", text, re.M)]


def test_the_classes_are_numbered_without_a_gap() -> None:
    numbers = _class_numbers()
    assert numbers == list(range(1, len(numbers) + 1)), numbers


def test_agents_md_states_the_number_of_classes_the_table_has() -> None:
    count = len(_class_numbers())
    agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    assert "docs/review-classes.md" in agents
    assert f"the {WORDS[count]} defect classes" in agents, f"the table has {count} classes"


def test_every_class_names_a_test_shape() -> None:
    """A class without the test that holds it is a complaint, not a gate."""
    text = (ROOT / "docs" / "review-classes.md").read_text(encoding="utf-8")
    rows = [line for line in text.splitlines() if re.match(r"^\| \d+ \| ", line)]
    for row in rows:
        cells = [c.strip() for c in row.strip("|").split("|")]
        assert len(cells) == 4 and all(cells), row[:60]
