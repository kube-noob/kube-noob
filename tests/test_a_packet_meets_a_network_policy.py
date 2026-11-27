"""The fifth mechanism lesson: NetworkPolicy, a packet admitted or dropped (G421).

kubelearn's NetworkPolicy walkthrough -- default allow, the policy is written, the CNI enforces it, the drop, the
allowed call -- walked against the user's own manifests. Two of its six hops are not in any manifest (which CNI
enforces the policy, and the per-packet decision) and are marked so; the four others are judged by rules that
were measured, before the lesson was written, with their object present and fine, present and violating, and
absent:

Measured (G421), a Deployment in one namespace beside each shape, as a whole namespace unless it says fragment:

- KN-N001 fires with no NetworkPolicy, and beside a CiliumNetworkPolicy alone; on a fragment it is "part of a
  namespace was passed"; with no workload it is "no apps DaemonSet, apps Deployment, ... in the input".
- KN-N012 fires on a policy whose podSelector matches no pod template here, on a fragment too; it is silent on a
  second workload that no policy selects; with no NetworkPolicy it is "no networking.k8s.io NetworkPolicy in the
  input", and with no workload "no pod spec in the input".
- KN-N007 fires on an ingress rule of `{}`, on `from: []`, on `namespaceSelector: {}` and on an ipBlock of
  0.0.0.0/0; it is silent on a rule that names ports and no `from`, and on `from: [{podSelector: {}}]`; with no
  NetworkPolicy it is "no networking.k8s.io NetworkPolicy in the input".
- KN-N013 fires on a default-deny over Ingress and Egress with no route to port 53, and is silent on an
  ingress-only policy and on an Egress policy allowing UDP and TCP 53.
- No rule compares a policy's ports with the ports the containers declare: a policy naming port 9999 against a
  container declaring 8080 is silent on every rule here.

So the namespace hop goes first (KN-N001 fires on the absence, and every later rule abstains on it, so the walk
is BROKEN and then stops instead of holding on nothing), the port comparison is in no hop's claim, and the two
limits measured above are written into the hops' own sentences. These tests pin the table, so a rule that changes
behaviour fails here first.
"""

from __future__ import annotations

import copy
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
FIXTURES = ROOT / "tests" / "fixtures" / "mechanism" / "networkpolicy"
LESSON = "mech-net-network-policy"
WATCHED = {"KN-N001", "KN-N007", "KN-N012", "KN-N013"}


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


def _policy(name: str) -> dict:
    return copy.deepcopy(next(d for d in _docs("complete") if d["metadata"]["name"] == name))


def _workload() -> dict:
    return copy.deepcopy(next(d for d in _docs("complete") if d["kind"] == "Deployment"))


def _allow(**ingress_rule: object) -> dict:
    """The fixture's allow policy with its one ingress rule replaced."""
    policy = _policy("api-allow-web")
    policy["spec"]["ingress"] = [dict(ingress_rule)]
    return policy


def test_the_healthy_bundle_walks_complete_and_the_two_unseen_hops_are_marked() -> None:
    doc = _walk(FIXTURES / "complete")
    assert doc["verdict"] == "complete" and doc["exitCode"] == 0, doc["verdictReason"]
    v = _verdicts(doc)
    assert v["cni-enforces-the-policy"] == v["packet-is-admitted-or-dropped"] == M.NOT_OBSERVABLE
    assert doc["counts"] == {"declared": 6, "judged": 4, "notObservable": 2, "notReached": 0}
    assert doc["namespaces"] == ["shop"]


def test_the_broken_bundle_names_both_breaks() -> None:
    doc = _walk(FIXTURES / "broken")
    assert doc["verdict"] == "broken" and doc["exitCode"] == 1
    v = _verdicts(doc)
    assert v["policy-selects-pods-here"] == M.FAILS and v["no-rule-admits-every-source"] == M.FAILS, v
    assert v["namespace-has-a-policy"] == v["egress-keeps-dns"] == M.HOLDS, v
    by_step = {s["step"]: {f["ruleId"] for f in s.get("findings", [])} for s in doc["steps"]}
    assert by_step["policy-selects-pods-here"] == {"KN-N012"}
    assert by_step["no-rule-admits-every-source"] == {"KN-N007"}
    assert "policy-selects-pods-here" in doc["verdictReason"] and "no-rule-admits-every-source" in doc["verdictReason"]


def test_a_namespace_with_no_policy_is_broken_at_the_first_hop_and_no_later_hop_holds(tmp_path: Path) -> None:
    """Every rule after the first reads a NetworkPolicy and abstains without one. KN-N001 fires on the absence, so
    the path is BROKEN; the next hop stops rather than holding on nothing, and G400 keeps the break as the answer."""
    doc = _walk(_write(tmp_path, "no-policy", [_workload()]))
    v = _verdicts(doc)
    assert v["namespace-has-a-policy"] == M.FAILS
    assert v["policy-selects-pods-here"] == M.CANNOT_JUDGE, v
    assert doc["verdict"] == "broken" and doc["exitCode"] == 1 and doc["stoppedAt"] == "policy-selects-pods-here"
    assert M.HOLDS not in v.values(), v
    assert doc["counts"]["notReached"] == 4


def test_a_policy_with_no_workload_never_holds_a_hop_about_pods(tmp_path: Path) -> None:
    """Measured: with no pod spec KN-N001 abstains ("no apps ... in the input"), so the walk stops at its first hop
    with nothing judged -- from a directory and from a single file alike."""
    docs = [d for d in _docs("complete") if d["kind"] == "NetworkPolicy"]
    for path in (_write(tmp_path, "policy-only", docs), _write(tmp_path, "policy-only-file", docs) / "bundle.yaml"):
        doc = _walk(path)
        assert doc["stoppedAt"] == "namespace-has-a-policy", (path, _verdicts(doc))
        assert doc["exitCode"] == 5 and doc["verdict"] == "stopped" and doc["counts"]["judged"] == 0
        assert M.HOLDS not in _verdicts(doc).values()


def test_a_single_file_is_a_fragment_and_the_first_hop_does_not_hold_on_it() -> None:
    """A file is part of a namespace: the namespace's other policies were not passed, KN-N001 says so, and the
    healthy fixture read as one file stops at exit 5 where the same bytes as a directory walk complete."""
    doc = _walk(FIXTURES / "complete" / "bundle.yaml")
    assert doc["verdict"] == "stopped" and doc["exitCode"] == 5 and doc["stoppedAt"] == "namespace-has-a-policy"
    assert doc["counts"]["judged"] == 0


def test_an_empty_input_judges_nothing(tmp_path: Path) -> None:
    d = tmp_path / "empty"
    d.mkdir()
    (d / "bundle.yaml").write_text("# nothing here\n", encoding="utf-8")
    out = _cli(d, "--format", "json")
    assert out.returncode != 0, out.stdout
    assert '"verdict": "complete"' not in out.stdout


def test_a_default_deny_holds_and_no_hop_says_a_packet_was_admitted(tmp_path: Path) -> None:
    """`podSelector: {}` with no ingress rule admits nothing, and every rule here is clean on it. The hops that
    hold must say what those rules decided -- a policy is here, it selects pods, no rule is empty -- and never
    that a packet gets in (the title-fidelity defect of G395, on the lesson where it would be easiest to make)."""
    deny = _policy("api-allow-web")
    deny["metadata"]["name"] = "default-deny"
    deny["spec"] = {"podSelector": {}, "policyTypes": ["Ingress"]}
    doc = _walk(_write(tmp_path, "deny", [_workload(), deny]))
    assert doc["verdict"] == "complete", doc["verdictReason"]
    for step in doc["steps"]:
        if step["verdict"] != M.HOLDS:
            continue
        claim = f"{step['title']} {step['why']}".lower()
        for words in ("lets the packet in", "admits the packet", "the call is allowed", "is admitted"):
            assert words not in claim, (step["step"], words)


def test_the_limits_the_rules_have_are_written_into_the_hops_that_hold(tmp_path: Path) -> None:
    """Three shapes the measurements found silent. Each walks `holds`, so each hop's own sentence must say that it
    did not read them: a workload no policy selects, a rule with ports and no `from`, and a port no container
    declares."""
    unselected = _workload()
    unselected["metadata"]["name"] = "web"
    unselected["spec"]["selector"]["matchLabels"] = {"app": "web"}
    unselected["spec"]["template"]["metadata"]["labels"] = {"app": "web"}
    ingress_only = [_workload(), unselected, _policy("api-allow-web")]
    doc = _walk(_write(tmp_path, "unselected", ingress_only))
    hop = next(s for s in doc["steps"] if s["step"] == "policy-selects-pods-here")
    assert hop["verdict"] == M.HOLDS and "a workload no policy selects" in hop["why"], hop

    ports_only = _allow(ports=[{"protocol": "TCP", "port": 8080}])
    doc = _walk(_write(tmp_path, "ports-only", [_workload(), ports_only]))
    hop = next(s for s in doc["steps"] if s["step"] == "no-rule-admits-every-source")
    assert hop["verdict"] == M.HOLDS and "names ports and no `from`" in hop["why"], hop

    lesson = M.lessons()[LESSON]
    packet = next(s for s in lesson["steps"] if s["id"] == "packet-is-admitted-or-dropped")
    assert "compares a policy's ports with the ports the containers declare" in " ".join(packet["holds"].split())


@pytest.mark.parametrize("partial", [False, True])
def test_a_policy_that_selects_nothing_is_not_called_broken_on_a_fragment(tmp_path: Path, partial: bool) -> None:
    """KN-N012 is the hop's `absent:` rule: the pod the policy selects may be in the file nobody passed (G408)."""
    typo = _policy("api-allow-web")
    typo["spec"]["podSelector"] = {"matchLabels": {"app": "apii"}}
    text = yaml.safe_dump_all([_workload(), typo], sort_keys=False)
    report = analyze(text, "kubernetes", None, partial_bundle=partial).as_dict()
    hop = M.Step.load(next(s for s in M.lessons()[LESSON]["steps"] if s["id"] == "policy-selects-pods-here"))
    walked = M.walk({"id": "x", "title": "t", "layer": "l", "steps": [_raw(hop)]}, report, partial_bundle=partial)
    assert walked["steps"][0]["verdict"] == (M.CANNOT_JUDGE if partial else M.FAILS), walked
    assert {f["ruleId"] for f in walked["steps"][0]["findings"]} == {"KN-N012"}


def _raw(step: M.Step) -> dict:
    return {
        "id": step.id,
        "title": step.title,
        "holds": step.holds,
        "needs": list(step.needs),
        "reads": list(step.reads),
        "rules": list(step.rules),
        "absent": list(step.absent),
    }


CASES: dict[str, tuple[set[str], dict[str, str], bool]] = {
    # case: (findings among WATCHED, notEvaluated reason fragments among WATCHED, fragment?)
    "fine": (set(), {}, False),
    "ingress-only": (set(), {}, False),
    "no-policy": (
        {"KN-N001"},
        dict.fromkeys(("KN-N007", "KN-N012", "KN-N013"), "no networking.k8s.io NetworkPolicy in the input"),
        False,
    ),
    "no-policy-fragment": (
        set(),
        {
            "KN-N001": "part of a namespace was passed",
            **dict.fromkeys(("KN-N007", "KN-N012", "KN-N013"), "no networking.k8s.io NetworkPolicy in the input"),
        },
        True,
    ),
    "cilium-policy-only": (
        {"KN-N001"},
        dict.fromkeys(("KN-N007", "KN-N012", "KN-N013"), "no networking.k8s.io NetworkPolicy in the input"),
        False,
    ),
    "no-workload": (
        set(),
        {"KN-N001": "no apps DaemonSet, apps Deployment", "KN-N012": "no pod spec", "KN-N013": "no pod spec"},
        False,
    ),
    "selector-typo": ({"KN-N012"}, {}, False),
    "selector-typo-fragment": (
        {"KN-N012"},
        {"KN-N001": "part of a namespace was passed", "KN-N013": "part of a namespace was passed"},
        True,
    ),
    "second-workload-unselected": (set(), {}, False),
    "rule-empty": ({"KN-N007"}, {}, False),
    "rule-from-empty-list": ({"KN-N007"}, {}, False),
    "rule-any-namespace": ({"KN-N007"}, {}, False),
    "rule-any-address": ({"KN-N007"}, {}, False),
    "rule-ports-and-no-from": (set(), {}, False),
    "rule-any-pod-here": (set(), {}, False),
    "port-9999": (set(), {}, False),
    "default-deny-both": ({"KN-N013"}, {}, False),
}


def _shape(case: str) -> list[dict]:
    work, allow, egress = _workload(), _policy("api-allow-web"), _policy("egress-dns-only")
    if case == "fine":
        return [work, allow, egress]
    if case == "ingress-only":
        return [work, allow]
    if case in ("no-policy", "no-policy-fragment"):
        return [work]
    if case == "cilium-policy-only":
        cilium = {
            "apiVersion": "cilium.io/v2",
            "kind": "CiliumNetworkPolicy",
            "metadata": {"name": "api", "namespace": "shop"},
            "spec": {"endpointSelector": {}},
        }
        return [work, cilium]
    if case == "no-workload":
        return [allow, egress]
    if case in ("selector-typo", "selector-typo-fragment"):
        allow["spec"]["podSelector"] = {"matchLabels": {"app": "apii"}}
        return [work, allow]
    if case == "second-workload-unselected":
        other = _workload()
        other["metadata"]["name"] = "web"
        other["spec"]["selector"]["matchLabels"] = {"app": "web"}
        other["spec"]["template"]["metadata"]["labels"] = {"app": "web"}
        return [work, other, allow]
    if case == "port-9999":
        allow["spec"]["ingress"][0]["ports"][0]["port"] = 9999
        return [work, allow]
    if case == "default-deny-both":
        allow["spec"] = {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}
        return [work, allow]
    rule: dict = {
        "rule-empty": {},
        "rule-from-empty-list": {"from": []},
        "rule-any-namespace": {"from": [{"namespaceSelector": {}}]},
        "rule-any-address": {"from": [{"ipBlock": {"cidr": "0.0.0.0/0"}}]},
        "rule-ports-and-no-from": {"ports": [{"protocol": "TCP", "port": 8080}]},
        "rule-any-pod-here": {"from": [{"podSelector": {}}]},
    }[case]
    return [work, _allow(**rule)]


@pytest.mark.parametrize("case", sorted(CASES))
def test_the_measurement_table_still_holds(case: str) -> None:
    expect_finding, expect_reason, fragment = CASES[case]
    text = "---\n".join(yaml.safe_dump(d, sort_keys=False) for d in _shape(case))
    report = analyze(text, "kubernetes", None, partial_bundle=fragment).as_dict()
    found = {f["ruleId"] for f in report.get("findings", [])} & WATCHED
    assert found == expect_finding, report.get("findings")
    reasons = report.get("notEvaluated") or {}
    for rule, words in expect_reason.items():
        assert words in reasons.get(rule, ""), (rule, reasons.get(rule))
    assert not ({r for r in reasons if r in WATCHED} - set(expect_reason)), reasons


def test_every_rule_a_hop_names_was_measured() -> None:
    """The table above is the lesson's evidence, so a rule added to a hop without a row in it fails here."""
    named = {r for s in M.lessons()[LESSON]["steps"] for r in s.get("rules") or ()}
    assert named == WATCHED


def test_the_mcp_tool_answers_what_the_command_answers(tmp_path: Path) -> None:
    kit = tk.Toolkit(load_settings(overrides={"offline": True, "dataDir": str(tmp_path / "data")}))
    for fixture, code in (("complete", 0), ("broken", 1)):
        text = (FIXTURES / fixture / "bundle.yaml").read_text(encoding="utf-8")
        got = kit.mechanism(tk.MechanismIn(mechanism_id=LESSON, manifests=text, partial_bundle=False))
        cli = _walk(FIXTURES / fixture)
        assert got["exitCode"] == code == cli["exitCode"]
        assert got["verdict"] == cli["verdict"]
        assert [(s["step"], s["verdict"]) for s in got["steps"]] == [(s["step"], s["verdict"]) for s in cli["steps"]]


def test_the_text_view_carries_every_word_of_every_hop() -> None:
    out = _cli(FIXTURES / "complete")
    assert out.returncode == 0
    flat = " ".join(out.stdout.split())
    for step in M.lessons()[LESSON]["steps"]:
        assert step["title"] in flat
        assert " ".join(str(step["holds"]).split()) in flat, step["id"]


def test_the_watchable_page_draws_every_hop_of_this_lesson() -> None:
    out = _cli(FIXTURES / "broken", "--format", "html")
    assert out.returncode == 1
    for n in range(1, 7):
        assert f'id="step-{n}"' in out.stdout
    assert 'id="step-7"' not in out.stdout
    assert "https://" not in out.stdout and "http://" not in out.stdout
