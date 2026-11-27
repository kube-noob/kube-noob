"""The fourth mechanism lesson: a Pod calls a Service (G420).

kubelearn's in-cluster call -- a pod asks DNS for a Service name, gets a ClusterIP, and the node sends it to a ready
endpoint -- walked against the user's own manifests. Two of its seven hops are not in any manifest (the DNS answer
and the ClusterIP translation) and are marked so; the five others are judged by rules that were measured, before
the lesson was written, with their object present and fine, present and violating, and absent:

Measured (G420):

- KN-N013 is silent and evaluated on an ingress-only policy and on an Egress policy allowing UDP and TCP 53; it
  fires on an Egress policy with no route to 53; with no NetworkPolicy it is "no networking.k8s.io NetworkPolicy
  in the input".
- KN-V023 is silent on a numeric targetPort the pods declare and fires on 9999; KN-V011, KN-V012 and KN-V023 all
  say "no pod spec in the input" without a workload, from a directory and from a single file alike.

With no pod spec at all, KN-N013 abstains too ("no pod spec in the input").

So the policy hop goes first: KN-N001 fires on a namespace with no policy, and the DNS hop then stops instead of
holding on nothing. These tests pin the table, so a rule that changes behaviour fails here first.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from kube_noob import toolkit as tk
from kube_noob.audit.engine import analyze
from kube_noob.config import load_settings
from kube_noob.learn import mechanism as M

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "mechanism" / "service"
LESSON = "mech-net-pod-calls-a-service"


def _cli(path: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    return subprocess.run(
        [sys.executable, "-m", "kube_noob", "learn", "mechanism", LESSON, "-f", str(path), *extra],
        capture_output=True,
        text=True,
        env=env,
        check=False,
        timeout=120,
    )


def _docs(fixture: str) -> list[dict]:
    return [d for d in yaml.safe_load_all((FIXTURES / fixture / "bundle.yaml").read_text(encoding="utf-8")) if d]


def _write(tmp_path: Path, name: str, docs: list[dict]) -> Path:
    d = tmp_path / name
    d.mkdir()
    (d / "bundle.yaml").write_text(yaml.safe_dump_all(docs, sort_keys=False), encoding="utf-8")
    return d


def _walk(path: Path) -> dict:
    out = _cli(path, "--format", "json")
    doc = json.loads(out.stdout)
    assert doc["exitCode"] == out.returncode, (doc["exitCode"], out.returncode)
    return doc


def _verdicts(doc: dict) -> dict[str, str]:
    return {s["step"]: s["verdict"] for s in doc["steps"]}


def test_the_healthy_bundle_walks_complete_and_the_two_unseen_hops_are_marked() -> None:
    doc = _walk(FIXTURES / "complete")
    assert doc["verdict"] == "complete" and doc["exitCode"] == 0, doc["verdictReason"]
    v = _verdicts(doc)
    assert v["name-resolves"] == v["clusterip-is-translated"] == M.NOT_OBSERVABLE
    assert doc["counts"] == {"declared": 7, "judged": 5, "notObservable": 2, "notReached": 0}


def test_the_broken_bundle_names_both_breaks() -> None:
    doc = _walk(FIXTURES / "broken")
    assert doc["verdict"] == "broken" and doc["exitCode"] == 1
    v = _verdicts(doc)
    assert v["egress-keeps-dns"] == M.FAILS and v["service-selects-pods"] == M.FAILS, v
    rules = {f["ruleId"] for s in doc["steps"] for f in s.get("findings", [])}
    assert {"KN-N013", "KN-V023"} <= rules
    assert "egress-keeps-dns" in doc["verdictReason"] and "service-selects-pods" in doc["verdictReason"]


def test_a_namespace_with_no_policy_breaks_at_the_policy_hop_and_does_not_pass_the_dns_hop(tmp_path: Path) -> None:
    """KN-N013 has nothing to judge without a NetworkPolicy. The hop before it is BROKEN on that absence (KN-N001),
    and the DNS hop stops rather than holding on nothing; G400 keeps the break as the answer."""
    docs = [d for d in _docs("complete") if d["kind"] != "NetworkPolicy"]
    doc = _walk(_write(tmp_path, "no-policy", docs))
    v = _verdicts(doc)
    assert v["namespace-has-a-policy"] == M.FAILS
    assert v["egress-keeps-dns"] == M.CANNOT_JUDGE, v
    assert doc["verdict"] == "broken" and doc["exitCode"] == 1 and doc["stoppedAt"] == "egress-keeps-dns"


def test_an_ingress_only_policy_leaves_egress_open_and_the_dns_hop_holds(tmp_path: Path) -> None:
    docs = [
        d
        for d in _docs("complete")
        if not (d["kind"] == "NetworkPolicy" and "Egress" in d["spec"].get("policyTypes", []))
    ]
    assert any(d["kind"] == "NetworkPolicy" for d in docs)
    doc = _walk(_write(tmp_path, "ingress-only", docs))
    assert _verdicts(doc)["egress-keeps-dns"] == M.HOLDS
    assert doc["verdict"] == "complete"


def test_a_bundle_with_no_pod_template_never_holds_a_hop_about_pods(tmp_path: Path) -> None:
    """Measured: with no pod spec every rule on the first two hops abstains ("no pod spec in the input"), so the
    walk stops at once -- and no hop about pods is ever reported as holding."""
    docs = [d for d in _docs("complete") if d["kind"] not in ("Deployment", "StatefulSet", "DaemonSet", "ReplicaSet")]
    for path in (_write(tmp_path, "svc-only", docs), _write(tmp_path, "svc-only-file", docs) / "bundle.yaml"):
        doc = _walk(path)
        v = _verdicts(doc)
        # The policy rules need pods to judge too (KN-N001 and KN-N012 abstain without them), so the walk stops at
        # its first hop: nothing after it is walked, and nothing about pods is reported as working.
        assert doc["stoppedAt"] == "namespace-has-a-policy", (path, v)
        assert doc["exitCode"] == 5 and doc["verdict"] == "stopped" and doc["counts"]["judged"] == 0
        for hop in ("service-selects-pods", "workload-selects-its-own-pods", "pod-reports-ready"):
            assert v.get(hop) != M.HOLDS, (hop, v)


@pytest.mark.parametrize(
    ("case", "expect_finding", "expect_reason"),
    [
        ("fine", set(), {}),
        ("no-policy", set(), {"KN-N013": "no networking.k8s.io NetworkPolicy in the input"}),
        ("no-dns", {"KN-N013"}, {}),
        ("port-9999", {"KN-V023"}, {}),
        (
            "no-workload",
            set(),
            {"KN-N013": "no pod spec", "KN-V011": "no pod spec", "KN-V012": "no pod spec", "KN-V023": "no pod spec"},
        ),
    ],
)
def test_the_measurement_table_still_holds(
    tmp_path: Path, case: str, expect_finding: set[str], expect_reason: dict[str, str]
) -> None:
    complete, broken = _docs("complete"), _docs("broken")
    shape = {
        "fine": complete,
        "no-policy": [d for d in complete if d["kind"] != "NetworkPolicy"],
        "no-dns": [d for d in broken if d["kind"] != "Service"] + [d for d in complete if d["kind"] == "Service"],
        "port-9999": [d for d in complete if d["kind"] != "Service"] + [d for d in broken if d["kind"] == "Service"],
        "no-workload": [d for d in complete if d["kind"] != "Deployment"],
    }[case]
    text = "---\n".join(yaml.safe_dump(d, sort_keys=False) for d in shape)
    report = analyze(text, "kubernetes", None, partial_bundle=False).as_dict()
    watched = {"KN-N013", "KN-V011", "KN-V012", "KN-V023"}
    found = {f["ruleId"] for f in report.get("findings", [])} & watched
    assert found == expect_finding, report.get("findings")
    reasons = report.get("notEvaluated") or {}
    for rule, words in expect_reason.items():
        assert words in reasons.get(rule, ""), (rule, reasons.get(rule))
    assert not ({r for r in reasons if r in watched} - set(expect_reason)), reasons


def test_the_mcp_tool_answers_what_the_command_answers(tmp_path: Path) -> None:
    kit = tk.Toolkit(load_settings(overrides={"offline": True, "dataDir": str(tmp_path / "data")}))
    for fixture, code in (("complete", 0), ("broken", 1)):
        text = (FIXTURES / fixture / "bundle.yaml").read_text(encoding="utf-8")
        got = kit.mechanism(tk.MechanismIn(mechanism_id=LESSON, manifests=text, partial_bundle=False))
        assert got["exitCode"] == code == _walk(FIXTURES / fixture)["exitCode"]


def test_the_watchable_page_draws_every_hop_of_this_lesson() -> None:
    out = _cli(FIXTURES / "broken", "--format", "html")
    assert out.returncode == 1
    for n in range(1, 8):
        assert f'id="step-{n}"' in out.stdout
    assert "https://" not in out.stdout and "http://" not in out.stdout
