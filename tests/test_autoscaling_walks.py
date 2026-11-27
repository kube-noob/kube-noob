"""The seventh mechanism lesson: Autoscaling (G435).

How a HorizontalPodAutoscaler changes a replica count -- it finds its target, the metrics API serves usage, the
controller divides usage by the request, writes a new count, and the scheduler places the new pods -- walked
against the user's own manifests. Three of its seven hops belong to a running cluster (the metrics pipeline, the
controller's arithmetic, the scheduler) and are marked so; the four others are judged by rules that were measured,
before the lesson was written, with their object present and fine, present and violating, absent, present but
unrelated and present but contradictory.

Measured (G435): one Deployment `web` with no `spec.replicas` and CPU and memory requests, and one
`autoscaling/v2` HPA `web` at 2..6 on 70% CPU utilization, both in `shop`. Findings among the four rules a hop
names; "nE" is a `notEvaluated` reason. Whole namespace first, then where a fragment differs.

| case                                         | findings          | notEvaluated                              |
|----------------------------------------------|-------------------|-------------------------------------------|
| fine                                         | -                 | -                                         |
| HPA floor 8 above ceiling 6                  | KN-V025           | -                                         |
| Deployment only in namespace `other`         | KN-V025, KN-C007  | -                                         |
| target absent, another Deployment `api` here | KN-C007           | KN-V025: may be created outside the bundle|
| ref `extensions/v1beta1` (contradictory)     | -                 | KN-V025: names an API group other than    |
| HPA alone                                    | -                 | all four: no workload / outside the bundle|
| no HPA                                       | KN-C007           | KN-V025, KN-C012, KN-C014: no autoscaling HPA |
| no HPA, `replicas: 2`                        | -                 | the same three                            |
| no CPU request, CPU utilization target       | KN-C012           | -                                         |
| no CPU request, CPU AverageValue target      | -                 | -                                         |
| no requests, memory utilization target       | -                 | -   (a limit: KN-C012 reads CPU only)     |
| `replicas: 3` beside the HPA                 | KN-C014           | -                                         |
| `replicas: 0` beside the HPA                 | KN-C014           | -                                         |
| HPA floor 1, or no minReplicas               | KN-C007           | -                                         |
| HPA floor 1 and `replicas: 3`                | KN-C014           | -   (KN-C007 reads the declared count)    |
| StatefulSet target                           | -                 | -                                         |
| a second Deployment no HPA scales, 1 replica | KN-C007           | -                                         |
| a second Deployment no HPA scales, 2 replicas| -                 | -   (a limit: nothing asks for an HPA)    |
| fragment, target absent or in `other`        | KN-C007           | KN-V025: part of a namespace was passed   |

A walk judges one namespace (G404), so the third row never reaches a hop: with the Deployment in `other` and the
autoscaler in `shop` the walk names both namespaces and stops at exit 5, and KN-V025's finding is `audit`'s to
give. On the walk, the first hop is BROKEN by a floor above the ceiling and stopped by an absent target.

So the target hop goes first: with the target absent KN-C012 and KN-C014 are silent and EVALUATED (they found no
workload the autoscaler names, and said nothing), and only KN-V025 says no verdict was reached -- placed later,
the requests hop would have held on an autoscaler that scales nothing here. KN-C007 is the one `absent:` rule,
as on the node-dark lesson: on a fragment the autoscaler that excuses a workload may be in another file. The two
limits measured above are written into the hops' own sentences. These tests pin the table.
"""

from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest
import yaml

from kube_noob import toolkit as tk
from kube_noob.audit.engine import analyze
from kube_noob.config import load_settings
from kube_noob.learn import mechanism as M

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "mechanism" / "autoscaling"
LESSON = "mech-cp-autoscaling"
WATCHED = {"KN-V025", "KN-C012", "KN-C014", "KN-C007"}
TARGET, REQUESTS, COUNT, FLOOR = (
    "autoscaler-names-a-target-that-is-here",
    "target-declares-cpu-requests",
    "manifest-leaves-the-count-to-the-autoscaler",
    "floor-keeps-more-than-one-replica",
)
UNSEEN = ("metrics-are-served", "controller-computes-the-count", "scheduler-places-the-new-replicas")
NO_HPA = "no autoscaling HorizontalPodAutoscaler in the input"


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


def _docs(fixture: str = "complete") -> list[dict]:
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


def _with(change: Callable[[dict, dict], object]) -> list[dict]:
    """The healthy bundle with its Deployment and its autoscaler changed."""
    docs = copy.deepcopy(_docs())
    work = next(d for d in docs if d["kind"] == "Deployment")
    scaler = next(d for d in docs if d["kind"] == "HorizontalPodAutoscaler")
    extra = change(work, scaler)
    return [*docs, *extra] if isinstance(extra, list) else docs


def _requests(work: dict) -> dict:
    return work["spec"]["template"]["spec"]["containers"][0]["resources"]["requests"]


def _second(replicas: int | None) -> dict:
    other = copy.deepcopy(next(d for d in _docs() if d["kind"] == "Deployment"))
    other["metadata"]["name"] = "api"
    other["spec"]["selector"]["matchLabels"] = {"app": "api"}
    other["spec"]["template"]["metadata"]["labels"] = {"app": "api"}
    if replicas is not None:
        other["spec"]["replicas"] = replicas
    return other


def test_the_healthy_bundle_walks_complete_and_the_three_unseen_hops_are_marked() -> None:
    doc = _walk(FIXTURES / "complete")
    assert doc["verdict"] == "complete" and doc["exitCode"] == 0, doc["verdictReason"]
    v = _verdicts(doc)
    assert {v[h] for h in UNSEEN} == {M.NOT_OBSERVABLE}
    assert doc["counts"] == {"declared": 7, "judged": 4, "notObservable": 3, "notReached": 0}
    assert doc["namespaces"] == ["shop"]


def test_the_broken_bundle_names_its_three_breaks_each_on_its_own_hop() -> None:
    doc = _walk(FIXTURES / "broken")
    assert doc["verdict"] == "broken" and doc["exitCode"] == 1
    by_step = {s["step"]: {f["ruleId"] for f in s.get("findings", [])} for s in doc["steps"]}
    assert by_step[REQUESTS] == {"KN-C012"}
    assert by_step[COUNT] == {"KN-C014"}
    assert by_step[FLOOR] == {"KN-C007"}
    v = _verdicts(doc)
    assert v[TARGET] == M.HOLDS, v
    for hop in (REQUESTS, COUNT, FLOOR):
        assert v[hop] == M.FAILS and hop in doc["verdictReason"], (hop, v)


def test_a_target_in_another_namespace_is_the_audits_finding_and_the_walk_stops(tmp_path: Path) -> None:
    """Measured, and not what the hop's title alone would suggest: a walk judges ONE namespace (G404), and a
    Deployment in `other` beside an autoscaler in `shop` is two. So the walk names both and stops at the first hop
    at exit 5 -- it does not hold, and it does not call the hop BROKEN -- while `audit` on the same bytes reports
    KN-V025. The finding is the audit's to give; the walk's answer is that it was handed two namespaces."""
    moved = _with(lambda w, h: w["metadata"].update(namespace="other"))
    report = analyze(yaml.safe_dump_all(moved, sort_keys=False), "kubernetes", None).as_dict()
    assert "KN-V025" in {f["ruleId"] for f in report["findings"]}
    doc = _walk(_write(tmp_path, "other-namespace", moved))
    assert doc["namespaces"] == ["other", "shop"]
    assert _verdicts(doc)[TARGET] == M.CANNOT_JUDGE and doc["stoppedAt"] == TARGET
    assert doc["verdict"] == "stopped" and doc["exitCode"] == 5
    assert M.HOLDS not in _verdicts(doc).values()


def test_a_floor_above_the_ceiling_is_broken_at_the_first_hop_through_the_command(tmp_path: Path) -> None:
    doc = _walk(_write(tmp_path, "floor", _with(lambda w, h: h["spec"].update(minReplicas=8))))
    assert _verdicts(doc)[TARGET] == M.FAILS and doc["verdict"] == "broken" and doc["exitCode"] == 1
    assert _verdicts(doc)[FLOOR] == M.HOLDS, "a refused autoscaler still declares a floor of two or more to KN-C007"


def test_a_target_that_is_not_in_the_bundle_stops_the_walk_and_no_later_hop_holds(tmp_path: Path) -> None:
    """KN-C012 and KN-C014 are silent and evaluated when the autoscaler's target is not here. KN-V025 is what
    says no verdict was reached, so its hop is first and the walk stops before the hops that would have held."""
    absent = _with(lambda w, h: h["spec"]["scaleTargetRef"].update(name="checkout"))
    doc = _walk(_write(tmp_path, "absent", absent))
    v = _verdicts(doc)
    assert v[TARGET] == M.CANNOT_JUDGE and doc["stoppedAt"] == TARGET, v
    assert doc["verdict"] == "stopped" and doc["exitCode"] == 5
    assert REQUESTS not in v and COUNT not in v and FLOOR not in v
    assert M.HOLDS not in v.values()


def test_a_bundle_with_no_autoscaler_stops_at_the_first_hop(tmp_path: Path) -> None:
    alone = [d for d in _docs() if d["kind"] != "HorizontalPodAutoscaler"]
    doc = _walk(_write(tmp_path, "no-hpa", alone))
    assert doc["stoppedAt"] == TARGET and doc["exitCode"] == 5 and doc["counts"]["judged"] == 0
    assert M.HOLDS not in _verdicts(doc).values()


def test_a_single_file_does_not_call_a_floor_of_one_broken() -> None:
    """KN-C007 is the hop's `absent:` rule (G408): on a fragment the autoscaler that holds a workload at two may be
    in a file nobody passed. The broken file's other two breaks are about objects in front of the rules, so the
    walk is still BROKEN; the floor hop lists its finding and says `cannot judge`."""
    doc = _walk(FIXTURES / "broken" / "bundle.yaml")
    v = _verdicts(doc)
    assert v[REQUESTS] == v[COUNT] == M.FAILS and v[FLOOR] == M.CANNOT_JUDGE, v
    assert doc["verdict"] == "broken" and doc["exitCode"] == 1 and doc["stoppedAt"] == FLOOR
    complete = _walk(FIXTURES / "complete" / "bundle.yaml")
    assert complete["verdict"] == "complete", "both objects are in the one file, so nothing rests on an absence"


def test_the_limits_the_rules_have_are_written_into_the_hops_that_hold(tmp_path: Path) -> None:
    """Two shapes the measurements found silent. Each walks `holds`, so the hop's own sentence must say so."""

    def memory_target(work: dict, scaler: dict) -> None:
        _requests(work).pop("memory")
        scaler["spec"]["metrics"][0]["resource"]["name"] = "memory"

    doc = _walk(_write(tmp_path, "memory", _with(memory_target)))
    hop = next(s for s in doc["steps"] if s["step"] == REQUESTS)
    assert hop["verdict"] == M.HOLDS and "memory" in hop["why"] and "not read" in hop["why"], hop

    doc = _walk(_write(tmp_path, "unscaled", _with(lambda w, h: [_second(2)])))
    hop = next(s for s in doc["steps"] if s["step"] == FLOOR)
    assert hop["verdict"] == M.HOLDS and "no rule here asks that a workload have an autoscaler" in hop["why"], hop


def test_no_hop_that_holds_says_the_workload_scales(tmp_path: Path) -> None:
    """Title fidelity (G395): the rules read what the manifests declare. None can establish that metrics arrive,
    that the controller scaled anything, or that a new pod found a node."""
    doc = _walk(FIXTURES / "complete")
    for step in doc["steps"]:
        if step["verdict"] != M.HOLDS:
            continue
        claim = f"{step['title']} {step['why']}".lower()
        for words in ("scales up", "will scale", "is scaled to", "metrics are available", "is scheduled"):
            assert words not in claim, (step["step"], words)


CASES: dict[str, tuple[set[str], dict[str, str], bool]] = {
    # case: (findings among WATCHED, notEvaluated reason fragments among WATCHED, fragment?)
    "fine": (set(), {}, False),
    "fine-fragment": (set(), {}, True),
    "floor-above-ceiling": ({"KN-V025"}, {}, False),
    "target-in-another-namespace": ({"KN-V025", "KN-C007"}, {}, False),
    "target-in-another-namespace-fragment": ({"KN-C007"}, {"KN-V025": "part of a namespace was passed"}, True),
    "target-absent": ({"KN-C007"}, {"KN-V025": "may be created outside the bundle"}, False),
    "target-absent-fragment": ({"KN-C007"}, {"KN-V025": "part of a namespace was passed"}, True),
    "ref-group-mismatch": (set(), {"KN-V025": "names an API group other than"}, False),
    "hpa-alone": (
        set(),
        {
            "KN-V025": "may be created outside the bundle",
            "KN-C012": "no pod spec in the input",
            "KN-C014": "no apps Deployment",
            "KN-C007": "no apps Deployment",
        },
        False,
    ),
    "no-hpa": ({"KN-C007"}, dict.fromkeys(("KN-V025", "KN-C012", "KN-C014"), NO_HPA), False),
    "no-hpa-two-replicas": (set(), dict.fromkeys(("KN-V025", "KN-C012", "KN-C014"), NO_HPA), False),
    "no-cpu-request": ({"KN-C012"}, {}, False),
    "no-cpu-request-average-value": (set(), {}, False),
    "no-requests-memory-target": (set(), {}, False),
    "replicas-set": ({"KN-C014"}, {}, False),
    "replicas-zero": ({"KN-C014"}, {}, False),
    "floor-one": ({"KN-C007"}, {}, False),
    "floor-defaulted": ({"KN-C007"}, {}, False),
    "floor-one-fragment": ({"KN-C007"}, {}, True),
    "floor-one-replicas-set": ({"KN-C014"}, {}, False),
    "statefulset-target": (set(), {}, False),
    "second-workload-one-replica": ({"KN-C007"}, {}, False),
    "second-workload-two-replicas": (set(), {}, False),
}


def _statefulset(work: dict, scaler: dict) -> None:
    work["kind"] = "StatefulSet"
    work["spec"]["serviceName"] = "web"
    scaler["spec"]["scaleTargetRef"]["kind"] = "StatefulSet"


def _memory(work: dict, scaler: dict) -> None:
    work["spec"]["template"]["spec"]["containers"][0]["resources"].pop("requests")
    scaler["spec"]["metrics"][0]["resource"]["name"] = "memory"


def _average_value(work: dict, scaler: dict) -> None:
    _requests(work).pop("cpu")
    scaler["spec"]["metrics"][0]["resource"]["target"] = {"type": "AverageValue", "averageValue": "200m"}


CHANGES: dict[str, Callable[[dict, dict], object]] = {
    "fine": lambda w, h: None,
    "fine-fragment": lambda w, h: None,
    "floor-above-ceiling": lambda w, h: h["spec"].update(minReplicas=8),
    "target-in-another-namespace": lambda w, h: w["metadata"].update(namespace="other"),
    "target-in-another-namespace-fragment": lambda w, h: w["metadata"].update(namespace="other"),
    "target-absent": lambda w, h: w["metadata"].update(name="api"),
    "target-absent-fragment": lambda w, h: w["metadata"].update(name="api"),
    "ref-group-mismatch": lambda w, h: h["spec"]["scaleTargetRef"].update(apiVersion="extensions/v1beta1"),
    "no-cpu-request": lambda w, h: _requests(w).pop("cpu"),
    "no-cpu-request-average-value": _average_value,
    "no-requests-memory-target": _memory,
    "replicas-set": lambda w, h: w["spec"].update(replicas=3),
    "replicas-zero": lambda w, h: w["spec"].update(replicas=0),
    "floor-one": lambda w, h: h["spec"].update(minReplicas=1),
    "floor-defaulted": lambda w, h: h["spec"].pop("minReplicas"),
    "floor-one-fragment": lambda w, h: h["spec"].update(minReplicas=1),
    "floor-one-replicas-set": lambda w, h: (h["spec"].update(minReplicas=1), w["spec"].update(replicas=3)),
    "statefulset-target": _statefulset,
    "second-workload-one-replica": lambda w, h: [_second(None)],
    "second-workload-two-replicas": lambda w, h: [_second(2)],
}


def _shape(case: str) -> list[dict]:
    if case == "hpa-alone":
        return [d for d in _docs() if d["kind"] == "HorizontalPodAutoscaler"]
    if case in ("no-hpa", "no-hpa-two-replicas"):
        work = copy.deepcopy(next(d for d in _docs() if d["kind"] == "Deployment"))
        if case == "no-hpa-two-replicas":
            work["spec"]["replicas"] = 2
        return [work]
    return _with(CHANGES[case])


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
    fired = set().union(*(found for found, _, _ in CASES.values()))
    assert fired == WATCHED, "every rule a hop names has a row where it fires"


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
    for n in range(1, 8):
        assert f'id="step-{n}"' in out.stdout
    assert 'id="step-8"' not in out.stdout
    assert "https://" not in out.stdout and "http://" not in out.stdout
