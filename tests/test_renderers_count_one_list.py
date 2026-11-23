"""Every renderer names the same not-evaluated rules as the JSON, because there is one list of them.

`controlSummary` carried two lists of the same thing: `rulesNotEvaluated`, one row per rule with its reason, and
`notEvaluatedRules`, a bare list of ids that was a strict SUBSET of it -- a rule not evaluated because its kind
was absent from the input appeared in the first with its reason and in the second not at all. The caveat line
every renderer reads was built from the subset, so on a Deployment-and-ConfigMap input the JSON said 50 rules
reached no verdict and the text view, the SARIF notes and the HTML report said nothing had (G281, review class 9:
two sources of truth that can disagree, and this pair disagreed by 50 against 0).

The line is now built from `rulesNotEvaluated`. This test is the invariant rather than the instance: it asserts
the count the renderers state equals the count the JSON carries, so a renderer that is later pointed back at a
narrower list fails here instead of quietly under-reporting.
"""

from __future__ import annotations

import re

from kube_noob.audit.caveats import caveat_lines, not_evaluated_line
from kube_noob.audit.engine import analyze
from tests.test_absent_kinds import CONFIGMAP, DEPLOYMENT


def _summary() -> dict:
    return analyze(DEPLOYMENT + "---\n" + CONFIGMAP, "kubernetes", None).as_dict()["controlSummary"]


def _count_in(line: str) -> int:
    """How many rules a caveat line states, named ones plus the "and N more" it ends with."""
    head = line.split(" -- ", maxsplit=1)[0]
    body = head.split(": ", 1)[1]
    more = re.search(r" and (\d+) more$", body)
    if more:
        body = body[: more.start()]
    return len([x for x in body.split(", ") if x]) + (int(more.group(1)) if more else 0)


def test_the_not_evaluated_line_counts_every_rule_the_json_carries() -> None:
    summary = _summary()
    rows = [r for r in summary["rulesNotEvaluated"] if isinstance(r, dict) and r.get("ruleId")]
    assert rows, "the fixture must leave some rule unevaluated or this test asserts nothing"
    assert _count_in(not_evaluated_line(summary)) == len(rows)


def test_the_line_is_not_built_from_the_narrower_list() -> None:
    """The regression itself: the two lists differ on this input, so a renderer reading the wrong one shows it."""
    summary = _summary()
    rich = [r for r in summary["rulesNotEvaluated"] if isinstance(r, dict) and r.get("ruleId")]
    bare = summary.get("notEvaluatedRules") or []
    assert len(bare) != len(rich), (
        "this fixture no longer distinguishes the two lists, so it cannot catch a renderer reading the subset; "
        "pick an input where a rule is not evaluated for want of a subject kind"
    )
    assert _count_in(not_evaluated_line(summary)) == len(rich)


def test_every_renderer_reads_that_one_line() -> None:
    """`gate`'s SARIF notes and the HTML report both call `caveat_lines`, so the count travels with it."""
    summary = _summary()
    rows = [r for r in summary["rulesNotEvaluated"] if isinstance(r, dict) and r.get("ruleId")]
    lines = caveat_lines(summary)
    not_evaluated = [ln for ln in lines if ln.startswith("not evaluated: ")]
    assert len(not_evaluated) == 1, lines
    assert _count_in(not_evaluated[0]) == len(rows)
