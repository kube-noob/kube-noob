"""The webhook answered with more warning lines than it documents (G419).

`Config.max_warnings` caps the findings, and the response carries at most `max_warnings` + 1 lines: the unit tests
and the in-cluster load run both assert it. The two statements -- "rules that need other objects were not
evaluated" and "not fully audited, so this is not a clean result" -- were appended on top of the findings and the
"N more findings" line, so an object with ten findings and a rule that declined got twelve. The load run's fuzz
cases 27 and 81 failed on exactly that once G407 made a non-numeric `replicas` a decline.

These tests run the load run's own fuzz generator in-process, with its own seed, so the case that failed in the
cluster is the case that is asserted here. Statements are never dropped to make room: they take it from findings.
"""

from __future__ import annotations

import importlib.util
import json
import random
from pathlib import Path
from types import ModuleType

import pytest

from kube_noob import admission as adm

ROOT = Path(__file__).resolve().parents[1]


def _load_run() -> ModuleType:
    spec = importlib.util.spec_from_file_location("admission_kind_load", ROOT / "scripts" / "admission_kind_load.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize("max_warnings", [1, 2, 10])
def test_the_load_runs_fuzz_cases_stay_within_the_bound_and_keep_their_statements(max_warnings: int) -> None:
    load = _load_run()
    cfg = adm.Config(max_warnings=max_warnings)
    rng = random.Random(20261028)
    over, stated = [], 0
    for i in range(600):
        sent = load.review(load.mutate(rng), rng)
        warnings = adm.review_bytes(json.dumps(sent).encode(), cfg)["response"].get("warnings") or []
        if len(warnings) > max_warnings + 1:
            over.append((i, len(warnings)))
        stated += any("not fully audited" in w for w in warnings)
    assert not over, over
    assert stated > 0, "no fuzz case declined, so this test no longer exercises the statement lines"


def test_a_statement_is_never_dropped_to_make_room() -> None:
    """Fuzz case 27 itself: ten findings and a decline. Every line it returned before still has its meaning."""
    load = _load_run()
    rng = random.Random(20261028)
    for _ in range(27):
        load.review(load.mutate(rng), rng)
    sent = load.review(load.mutate(rng), rng)
    warnings = adm.review_bytes(json.dumps(sent).encode(), adm.Config())["response"]["warnings"]
    assert len(warnings) == adm.Config().max_warnings + 1, warnings
    assert any(w.startswith("kube-noob: not fully audited") for w in warnings)
    more = [w for w in warnings if w.startswith("kube-noob: ") and "more findings" in w]
    assert len(more) == 1
    shown = [w for w in warnings if w.startswith("[KN-")]
    assert shown, "findings are still shown beside the statement"
