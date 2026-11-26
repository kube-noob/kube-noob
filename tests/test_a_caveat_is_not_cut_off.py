"""A hop's explanation was cut at 200 characters with no mark, and the cut fell on its caveat (G411).

The `why` of a hop that holds is the curriculum's own `holds` sentence, and its last clause is where the lesson
states what the rule does NOT read. `_line` bounded every value at 200 characters, so six of the RBAC lesson's
seven hops and one node-dark hop printed a hold stronger than the lesson wrote, with nothing to say a word was
missing. The text view now wraps instead of cutting; every word of every hop's explanation reaches the reader.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from kube_noob.audit.engine import analyze
from kube_noob.learn import mechanism as M

ROOT = Path(__file__).resolve().parents[1]


def _lesson(lesson_id: str) -> dict:
    data = yaml.safe_load((ROOT / "src" / "kube_noob" / "data" / "curriculum.yaml").read_text(encoding="utf-8"))
    return next(lsn for t in data["tracks"] for lsn in t.get("lessons") or () if lsn.get("id") == lesson_id)


def _walk(lesson_id: str, fixture: Path) -> dict:
    text = "---\n".join(p.read_text(encoding="utf-8") for p in sorted(fixture.glob("*.yaml")))
    report = analyze(text, "kubernetes", None, partial_bundle=False).as_dict()
    return M.walk(_lesson(lesson_id), report)


@pytest.mark.parametrize(
    ("lesson", "fixture"),
    [
        ("mech-sec-rbac-and-serviceaccounts", ROOT / "tests/fixtures/mechanism/rbac/complete"),
        ("mech-sec-rbac-and-serviceaccounts", ROOT / "tests/fixtures/mechanism/rbac/broken"),
        ("mech-cp-a-node-goes-dark", ROOT / "tests/fixtures/mechanism/complete"),
        ("mech-net-request-to-pod", ROOT / "tests/fixtures/mechanism/complete"),
    ],
)
def test_every_word_of_every_hop_reaches_the_text_view(lesson: str, fixture: Path) -> None:
    walked = _walk(lesson, fixture)
    flat = " ".join(M.render(walked).split())
    for step in walked["steps"]:
        why = " ".join(step["why"].split())
        assert why in flat, f"hop {step['step']} lost words in the text view: {why[-120:]!r}"
    assert len(" ".join(step["why"] for step in walked["steps"])) > 0


def test_the_wrapped_lines_never_reach_column_zero() -> None:
    walked = _walk("mech-sec-rbac-and-serviceaccounts", ROOT / "tests/fixtures/mechanism/rbac/complete")
    lines = M.render(walked).splitlines()
    body = lines[2:-2]
    for line in body:
        assert not line or line[0].isdigit() or line.startswith(" "), (
            f"an explanation line reached column zero: {line!r}"
        )


def test_an_overlong_value_says_it_was_cut() -> None:
    out = M._wrapped("x " * 5000)
    assert "[cut:" in out[-1], out[-1]
