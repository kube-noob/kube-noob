"""A walk that found a broken hop and then stopped said only that it stopped (G400).

Measured on the node-dark lesson against the shipped fixture directory: KN-C010 BROKEN at hop 2, KN-C009 unable to
judge hop 3, and the walk answered `stopped`, exit 5, with a reason naming only the stop. AGENTS.md (G272): 1 is
"a verdict was reached and it is not a pass", 5 is "no verdict was reached". A broken hop is a verdict about the
path -- no hop after it can make the path work -- so the walk had reached one, and the exit code and the sentence
a reader acts on both hid it.

The repair: a break wins over a later stop. The verdict is `broken` at 1, `stoppedAt` still names the hop that
could not be judged, the hops after it are still not walked, and the reason names both. A walk that stopped before
finding anything broken is unchanged: `stopped` at 5.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from kube_noob import toolkit as tk
from kube_noob.config import load_settings
from kube_noob.learn import mechanism as M

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "mechanism"
NODE_DARK = "mech-cp-a-node-goes-dark"
REQUEST = "mech-net-request-to-pod"


def _cli(lesson: str, path: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    return subprocess.run(
        [sys.executable, "-m", "kube_noob", "learn", "mechanism", lesson, "-f", str(path), *extra],
        capture_output=True,
        text=True,
        env=env,
        check=False,
        timeout=120,
    )


def _synthetic() -> dict:
    """Four hops: one holds, one is broken, one cannot be judged, one after it -- built from the walker's own
    inputs so the precedence is tested independently of what any rule happens to decide today."""
    return {
        "id": "mech-test-precedence",
        "title": "Precedence",
        "layer": "test",
        "steps": [
            {"id": "a", "title": "A", "kinds": ["Deployment"], "rules": ["KN-C001"], "holds": "a holds"},
            {"id": "b", "title": "B", "kinds": ["Deployment"], "rules": ["KN-C010"], "holds": "b holds"},
            {"id": "c", "title": "C", "kinds": ["PodDisruptionBudget"], "rules": ["KN-C009"], "holds": "c holds"},
            {"id": "d", "title": "D", "kinds": ["Deployment"], "rules": ["KN-C007"], "holds": "d holds"},
        ],
    }


def test_the_shipped_fixture_reproduces_it_and_now_answers_broken() -> None:
    """The case as it was measured: the directory fixture, the real CLI, every format agreeing on 1."""
    out = _cli(NODE_DARK, FIXTURES / "complete", "--format", "json")
    doc = json.loads(out.stdout)
    steps = {s["step"]: s["verdict"] for s in doc["steps"]}
    assert steps.get("replicas-can-land-apart") == M.FAILS, "the fixture no longer breaks hop 2; this test is stale"
    assert steps.get("the-budget-lets-one-go") == M.CANNOT_JUDGE, "the fixture no longer stops at hop 3; stale"
    assert doc["verdict"] == "broken" and doc["exitCode"] == out.returncode == 1, (doc["verdict"], out.returncode)
    assert doc["stoppedAt"] == "the-budget-lets-one-go", "the stop is still named"
    assert doc["counts"]["notReached"] == 1, "the hop after the stop is still not walked"
    assert "replicas-can-land-apart" in doc["verdictReason"], "the reason names the break"
    assert "the-budget-lets-one-go" in doc["verdictReason"], "and the stop"

    text = _cli(NODE_DARK, FIXTURES / "complete")
    assert text.returncode == 1
    last = text.stdout.strip().splitlines()[-1]
    assert last.startswith("these hops are broken: replicas-can-land-apart"), last
    assert "1 hop(s) after it were not walked" in text.stdout


def test_the_mcp_tool_answers_what_the_command_answers(tmp_path: Path) -> None:
    manifests = "---\n".join(p.read_text(encoding="utf-8") for p in sorted((FIXTURES / "complete").glob("*.yaml")))
    kit = tk.Toolkit(load_settings(overrides={"offline": True, "dataDir": str(tmp_path / "data")}))
    got = kit.mechanism(tk.MechanismIn(mechanism_id=NODE_DARK, manifests=manifests, partial_bundle=False))
    assert got["verdict"] == "broken" and got["exitCode"] == 1
    assert got["stoppedAt"] == "the-budget-lets-one-go"


def test_a_stop_with_nothing_broken_before_it_is_still_no_verdict() -> None:
    """The other half of the precedence, which must not move: only a break is a verdict."""
    out = _cli(REQUEST, FIXTURES / "complete" / "bundle.yaml", "--format", "json")
    doc = json.loads(out.stdout)
    assert not any(s["verdict"] == M.FAILS for s in doc["steps"]), "a hop broke; this control proves nothing"
    assert doc["stoppedAt"] is not None, "a single file is a fragment and must stop somewhere"
    assert doc["verdict"] == "stopped" and doc["exitCode"] == out.returncode == 5


def test_the_precedence_in_the_walker_itself() -> None:
    """Driven through `walk` with a report built by hand, so no rule's behaviour can make this pass by accident."""
    lesson = _synthetic()
    report = {
        "resources": [{"kind": "Deployment", "name": "web", "namespace": "shop"}],
        "findings": [
            {"ruleId": "KN-C010", "severity": "low", "resource": "Deployment/shop/web", "title": "not spread"}
        ],
        "notAudited": [],
        "notEvaluated": {"KN-C009": "no policy PodDisruptionBudget in the input"},
    }
    walked = M.walk(lesson, report)
    by = {s["step"]: s["verdict"] for s in walked["steps"]}
    assert by["b"] == M.FAILS and by["c"] == M.CANNOT_JUDGE and "d" not in by, by
    assert walked["verdict"] == "broken" and walked["exitCode"] == 1
    assert walked["stoppedAt"] == "c" and walked["counts"]["notReached"] == 1

    # Remove the break: the same stop is no verdict again.
    report["findings"] = []
    walked = M.walk(lesson, report)
    assert walked["verdict"] == "stopped" and walked["exitCode"] == 5 and walked["stoppedAt"] == "c"
