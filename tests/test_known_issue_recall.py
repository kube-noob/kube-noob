"""Known-issue recall gate: the frozen eval in ``data/evals/known_issue_recall.yaml``.

Positives are symptoms as people write them, as alerts fire and as tools print events; each names the release-notes
issue it should find at the stated version. Negatives are everyday errors (and the etcd symptom on versions that
already carry the fix) that must never pull in a bug. The questions are frozen: the matcher is tuned, never the eval.
"""

from __future__ import annotations

import json
from importlib import resources
from typing import Any

import pytest
import yaml

from kube_noob import known_issues as ki
from kube_noob.cli import main
from tests import bounds

#: Measured: twenty corpus matches, corpus already loaded.
#: Re-measure with KUBE_NOOB_TEST_BOUNDS_REPORT=1 (tests/bounds.py).
HONEST_MATCH_20 = 0.05

MIN_RECALL = 0.8


def _eval() -> dict[str, Any]:
    text = resources.files("kube_noob").joinpath("data/evals/known_issue_recall.yaml").read_text(encoding="utf-8")
    doc = yaml.safe_load(text)
    assert isinstance(doc, dict)
    return doc


def _ids(text: str, version: str | None) -> list[str]:
    return [m["id"] for m in ki.match(text, "openshift", version, 3)["matches"]]


def test_the_eval_is_well_formed_and_big_enough() -> None:
    doc = _eval()
    pos, neg = doc["positives"], doc["negatives"]
    assert len(pos) >= 40 and len(neg) >= 30, (len(pos), len(neg))
    ids = [c["id"] for c in pos + neg]
    assert len(ids) == len(set(ids)), "duplicate case ids"
    assert {c["style"] for c in pos} == {"prose", "alert", "events"}
    issues = {i.id for i in ki.get_index().issues}
    for c in pos:
        assert set(c) <= {"id", "style", "version", "expect", "text"}, c["id"]
        assert c["expect"] in issues, f"{c['id']} expects {c['expect']}, which is not in the bundled index"
        assert 3 <= len(c["text"]) <= 400, c["id"]
    for c in neg:
        assert set(c) <= {"id", "version", "text"}, c["id"]


def test_recall_and_precision_gate() -> None:
    doc = _eval()
    misses = []
    for c in doc["positives"]:
        found = _ids(c["text"], c.get("version"))
        if c["expect"] not in found:
            misses.append(f"{c['id']} ({c['style']}) expected {c['expect']}, got {found or 'nothing'}")
    false = []
    for c in doc["negatives"]:
        found = _ids(c["text"], c.get("version"))
        if found:
            false.append(f"{c['id']} matched {found}: {c['text'][:80]}")
    total = len(doc["positives"])
    recall = (total - len(misses)) / total
    report = (
        f"recall {total - len(misses)}/{total} = {recall:.2f} (gate {MIN_RECALL}); "
        f"false matches {len(false)}/{len(doc['negatives'])} (gate 0)\n" + "\n".join(misses + false)
    )
    assert recall >= MIN_RECALL and not false, report


@pytest.mark.parametrize(
    ("version", "expect"),
    [("4.21.0", ["OCPBUGS-73881"]), ("4.20.5", ["OCPBUGS-73876"]), ("4.21.2", []), ("4.20.13", [])],
)
def test_the_measured_etcd_gap_is_closed(version: str, expect: list[str]) -> None:
    """The gap recorded in the program: missed before signal-keyed matching; no match once the fix is installed."""
    assert _ids("etcd leader changed frequently, apiserver timeouts after upgrade", version) == expect


def test_signal_terms_support_a_match_but_never_make_one_alone() -> None:
    text = "etcdHighNumberOfLeaderChanges firing on all masters after updating to 4.21.0"
    hit = ki.match(text, "openshift", "4.21.0")
    assert [m["id"] for m in hit["matches"]] == ["OCPBUGS-73881"]
    assert "alert:etcdHighNumberOfLeaderChanges" in hit["matches"][0]["signals"]
    for bare in ("etcdHighNumberOfLeaderChanges", "KubeAPIErrorBudgetBurn firing", "TargetDown"):
        assert _ids(bare, "4.21.0") == [], bare


def test_stems_meet_corpus_words_and_never_invent_them() -> None:
    assert set(ki.stems("draining restarted updated running").split()) >= {"drain", "restart", "update", "run"}
    known = {"drain", "restart", "update"}.__contains__
    assert ki.stems("exceeded limited draining restarted updated", known).split() == ["drain", "restart", "update"]
    assert ki.stems("x" * 300_000 + "ing") == ""
    assert ki.stems("") == ""


def test_matching_is_fast_and_deterministic() -> None:
    text = "etcd leader changed frequently, apiserver timeouts after upgrade"
    ki.match(text, "openshift", "4.21.0")  # the first call loads the corpus; the timer measures the matching
    with bounds.bounded(bounds.LINEAR, honest_seconds=HONEST_MATCH_20, guards="twenty matches against the corpus"):
        first = [ki.match(text, "openshift", "4.21.0") for _ in range(20)]
    assert all(json.dumps(r, sort_keys=True) == json.dumps(first[0], sort_keys=True) for r in first)


def test_hostile_text_is_bounded() -> None:
    for text in ("leader " * 200_000, "a" * 2_000_000, "\x00\x1b[2J" * 10_000, "etcd" + "-" * 500_000):
        out = ki.match(text, "openshift", "4.21.0")
        assert isinstance(out["matches"], list)


def test_cli_accept(capsys: pytest.CaptureFixture[str]) -> None:
    text = "etcd leader changed frequently, apiserver timeouts after upgrade"
    assert main(["known-issues", text, "--version", "4.21.0", "--format", "json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert [m["id"] for m in out["matches"]] == ["OCPBUGS-73881"]
    assert out["matches"][0]["url"] == "https://redhat.atlassian.net/browse/OCPBUGS-73881"
    assert main(["known-issues", text, "--version", "4.21.0"]) == 0
    assert "OCPBUGS-73881" in capsys.readouterr().out
