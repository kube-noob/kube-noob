"""An empty collection must not be the flattering answer.

`all([])` is `True` and `len([]) == 0`, so three scorers reported success for a spec that asserted nothing:

- `evals/reward.py` `_qa` set `coverage = 1.0 if not must else ...`, so a qa task with no `mustMention` scored
  perfect coverage for any prose at all;
- `evals/checks.py` `Evaluation.passed` is `self.parsed and all(o.passed for o in self.outcomes)`, so an
  evaluation with zero outcomes reported `passed: True` while `score()` returned `0.0`;
- `evals/selftest.py` built `missing = [r for r in case["expect"] if r not in fired]` and returned `not missing`,
  so a case with `expect: []` passed whatever the audit found.

None of the three is reachable from a shipped fixture today -- which is exactly why none was caught. They are the
same shape as the `corpus.py` `redistributable` bug (G154), which WAS reachable and did publish an empty corpus.

Two layers here: each scorer refuses an empty spec, and a sweep asserts no shipped fixture is empty, so a future
one is caught when it is added rather than when it scores.
"""

from __future__ import annotations

import json
import pathlib
from pathlib import Path
from typing import Any

import pytest
import yaml

from kube_noob.evals import checks, reward, selftest

ROOT = pathlib.Path(__file__).resolve().parent.parent
DATA = pathlib.Path(checks.__file__).resolve().parent.parent / "data" / "evals"


def test_a_qa_task_with_nothing_to_mention_says_it_checked_no_claims() -> None:
    """`coverage = 1.0 if not must else ...` is the right arithmetic -- a citation-only task is a legitimate
    shape, and `tests/test_reward_hardening.py` grades one deliberately. What was wrong is that the result did
    not say so: `missing: []` beside a full score reads as "covered every required claim" when none were
    required. My first attempt here refused the task outright and broke that legitimate case; the gate caught it.
    """
    score, details = reward._qa("any prose at all, saying nothing in particular", {"id": "t", "type": "qa"})
    assert details["claimsChecked"] == 0, "a reader must be able to see that no claim was checked"
    assert details["coverage"] == 1.0, "vacuously covered, and labelled as such rather than hidden"
    assert score > 0, "a citation-only task still scores on its other components"


def test_a_qa_task_that_lists_something_reports_what_it_checked() -> None:
    """The real case must be distinguishable from the vacuous one by the same field."""
    score, details = reward._qa("etcd leader elections and disk latency", {"id": "t", "mustMention": ["etcd"]})
    assert details["claimsChecked"] == 1
    assert score > 0


def test_a_qa_task_that_misses_its_claims_does_not_score_full() -> None:
    _, details = reward._qa("nothing relevant here", {"id": "t", "mustMention": ["etcd", "disk"]})
    assert details["claimsChecked"] == 2
    assert details["coverage"] == 0.0


def test_an_evaluation_with_no_outcomes_is_not_passed() -> None:
    """`all([])` is True, so this reported passed while the score was 0.0 -- two fields disagreeing about the
    same run. Unreachable through `evaluate`, which always seeds a parse outcome, so the guard is on the type."""
    empty = checks.Evaluation([], None, parsed=True)
    assert empty.passed is False
    assert empty.score == 0.0


def test_an_evaluation_with_outcomes_still_reports_them() -> None:
    ok = checks.Evaluation([checks.CheckOutcome("parsed", True, "ok")], None, parsed=True)
    assert ok.passed is True


def test_a_selftest_case_expecting_no_rules_is_refused() -> None:
    """`not missing` on an empty `expect` passed whatever the audit found, so the case asserted nothing."""
    with pytest.raises(selftest.SelfTestSpecError, match="expect"):
        selftest.validate_case({"id": "c", "kind": "audit", "expect": [], "manifests": "x"})


def test_a_selftest_case_with_expectations_is_accepted() -> None:
    selftest.validate_case({"id": "c", "kind": "audit", "expect": ["KN-S001"], "manifests": "x"})


@pytest.mark.parametrize(
    ("name", "key"),
    [
        ("tasks.yaml", "tasks"),
        ("selftest.yaml", "cases"),
        # `negatives` are the cases that must match nothing, so an empty `expect` is their whole point: excluded.
        ("known_issue_recall.yaml", "positives"),
    ],
)
def test_no_shipped_fixture_asserts_nothing(name: str, key: str) -> None:
    """The sweep. A scorer that refuses an empty spec only helps if nothing ships one, and the three holes above
    were latent precisely because no shipped fixture reached them -- so this is the test that keeps it that way."""
    spec = yaml.safe_load((DATA / name).read_text())
    items: list[dict[str, Any]] = spec.get(key) or []
    assert items, f"{name}: no {key} at all"
    empty: list[str] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        ident = str(item.get("id") or "?")
        # Whatever this item claims to check, it has to check something.
        claims = [
            item.get("expect"),
            (item.get("checks") or {}).get("assertions") if isinstance(item.get("checks"), dict) else None,
            (item.get("checks") or {}).get("kinds") if isinstance(item.get("checks"), dict) else None,
            item.get("mustMention"),
            item.get("mustNotMention"),
        ]
        if not any(c for c in claims if c):
            empty.append(f"{name}:{ident}")
    assert not empty, "fixture items that assert nothing: " + ", ".join(empty)


def test_the_protocol_does_not_call_a_run_ready_when_it_audited_nothing() -> None:
    """`status = "ready" if not blockers else "blocked"` asserts readiness from an absence of HIGH findings. With
    no documents, no rule ran, so there are no blockers and the run reported `ready` -- a far stronger claim than
    a control summary, and the same root cause as the coverage record still to be built."""
    from kube_noob.audit import protocol

    out = protocol.run_protocol("deploy this", manifests="")
    assert out["status"] != "ready", out["status"]
    assert out["status"] == "undetermined"


def test_db_check_refuses_a_bundle_manifest_that_declares_no_shards() -> None:
    """The guard against an empty corpus went into `build()`, which stops kube-noob publishing one. `db-check` is
    the command a USER runs against a bundle they downloaded, and it reported clean and exited 0 on a manifest
    declaring zero shards -- the one link of that chain still open, at the end people actually hold."""
    import json as _json
    import tempfile

    from kube_noob.sources import db_bundle

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "MANIFEST.json").write_text(
            _json.dumps(
                {
                    "bundle": {
                        "format": db_bundle.FORMAT,
                        "builtAt": "2026-11-03T00:00:00+00:00",
                        "kubeNoobVersion": "0.7.1",
                        "records": 0,
                        "licenses": {},
                        "files": [],
                    },
                    "shards": {},
                }
            )
        )
        (root / "ATTRIBUTION.md").write_text("none\n")
        problems = db_bundle.check(root)
    assert problems, "a bundle with no shards must not report clean"
    assert any("shard" in p for p in problems), problems


VERDICT_WORDS = (
    "pass",
    "ok",
    "clean",
    "ready",
    "valid",
    "redistributable",
    "coverage",
    "satisfied",
    "complete",
    "allowed",
    "safe",
    "healthy",
    "success",
    "missing",
    "problems",
    "blockers",
)
VERDICT_BASELINE = ROOT / "tests" / "fixtures" / "empty_verdict_baseline.json"


def _verdict_shaped_counts() -> dict[str, int]:
    """Per module: `all(...)`, `not any(...)` and `X if not Y else Z` within two lines of a verdict-shaped name.

    A pure AST sweep finds 85 of these and would be about 90% noise -- most are guarded by an earlier emptiness
    check, and a lint rule firing on all 85 would be silenced within a day. What the real bugs share is not a
    shape but a context: an empty collection reaching a name that means "this was fine". The name filter cuts 85
    to 13, which is small enough to review and freeze.
    """
    import ast

    src_root = ROOT / "src" / "kube_noob"
    out: dict[str, int] = {}
    for path in sorted(src_root.rglob("*.py")):
        src = path.read_text()
        try:
            tree = ast.parse(src)
        except SyntaxError:
            continue
        lines = src.split("\n")
        found = 0
        for node in ast.walk(tree):
            hit = (
                (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "all")
                or (
                    isinstance(node, ast.UnaryOp)
                    and isinstance(node.op, ast.Not)
                    and isinstance(node.operand, ast.Call)
                    and isinstance(node.operand.func, ast.Name)
                    and node.operand.func.id == "any"
                )
                or (
                    isinstance(node, ast.IfExp)
                    and isinstance(node.test, ast.UnaryOp)
                    and isinstance(node.test.op, ast.Not)
                )
            )
            if not hit:
                continue
            context = " ".join(lines[max(0, node.lineno - 2) : node.lineno + 1]).lower()
            if any(w in context for w in VERDICT_WORDS):
                found += 1
        if found:
            out[str(path.relative_to(src_root))] = found
    return out


def test_no_module_gains_an_empty_collection_verdict() -> None:
    """A frozen inventory of every place an empty collection could reach a verdict-shaped name.

    This does NOT claim the thirteen listed sites are correct. Three of them were the bugs fixed above and are
    now guarded or labelled; the rest were each read and found to be protected by an earlier emptiness check, but
    "I read it once" is not an invariant. What this test claims is only that the list may shrink and never grow,
    because `all([])` is `True` and `not []` is `True`, so each new one is a new place where nothing-checked can
    read as everything-fine -- and that has now happened seven times in this repository.

    A ruff or flake8 rule was considered and rejected: the four live instances shared no AST shape (two
    ternaries, one `all()`, one missing guard), so a rule precise enough to catch them would fire on all 85 raw
    sites and be silenced.
    """
    baseline = json.loads(VERDICT_BASELINE.read_text())
    now = _verdict_shaped_counts()
    grew = {f: (baseline.get(f, 0), n) for f, n in now.items() if n > baseline.get(f, 0)}
    assert not grew, (
        "an empty collection can now reach a verdict-shaped name here: "
        + ", ".join(f"{f} {was} -> {is_}" for f, (was, is_) in sorted(grew.items()))
        + ". Guard the empty case, or record it in tests/fixtures/empty_verdict_baseline.json deliberately."
    )
    shrank = {f: (baseline[f], now.get(f, 0)) for f in baseline if now.get(f, 0) < baseline[f]}
    assert not shrank, "sites were removed, which is the point -- lower the baseline to lock the gain in: " + ", ".join(
        f"{f} {was} -> {is_}" for f, (was, is_) in sorted(shrank.items())
    )


def test_all_matched_is_false_when_no_operator_was_looked_up() -> None:
    """The same shape in `operator_issues` (G278): `allMatched` was `complete and not_matched == 0`, and with nothing
    looked up `not_matched` is 0, so a cluster with no installed operator -- or no OLM at all -- read "every operator
    matched". It is true only for the `matched` verdict, which needs at least one operator looked up."""
    from kube_noob import operator_issues, operators

    empty_list = {"apiVersion": "operators.coreos.com/v1alpha1", "kind": "ClusterServiceVersionList", "items": []}
    subscribed = {
        "apiVersion": "operators.coreos.com/v1alpha1",
        "kind": "Subscription",
        "metadata": {"name": "ptp", "namespace": "p"},
        "spec": {"name": "ptp-operator", "source": "redhat-operators", "sourceNamespace": "openshift-marketplace"},
        "status": {"state": "UpgradePending"},
    }
    nothing = operator_issues.assess(
        operators.from_manifests(yaml.safe_dump_all([empty_list, subscribed])),
        release=operator_issues.Release(given="4.21.9"),
    )
    assert nothing["verdict"] == "nothing-to-match" and nothing["counts"]["assessable"] == 0
    assert nothing["allMatched"] is False
