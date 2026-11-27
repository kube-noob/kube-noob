"""The sixth mechanism lesson: Deploy an app (G422).

kubelearn's first walkthrough -- send the manifest, the API server's gatekeeping, saved to etcd, the controllers
react, scheduling, the kubelet starts it, ready for traffic -- walked against the user's own manifests. Four of its
nine hops here belong to a running cluster (the API server's admission and storage, the controllers, the scheduler
and the kubelet) and are marked so; the five others are judged by rules that were measured, before the lesson was
written, with their object present and fine, present and violating, and absent:

Measured (G422), one Deployment and one ConfigMap in a namespace, whole unless it says fragment:

- KN-V001 fires with no metadata.name, KN-V002 on `apps/v2`, KN-V005 on `apps/v1beta1`, KN-V009 on the name
  `Web_App`, KN-V010 on a selector that does not match the template, KN-C006 on a memory request above its limit.
  All six are silent and evaluated on the healthy Deployment.
- KN-C004 fires with no requests, on a fragment too.
- KN-C017 is silent when the pod names a ConfigMap that is here; it fires on a name that is missing beside
  another ConfigMap; it is "the bundle defines no Secret in namespace shop ..." when the pod names a Secret and
  the bundle has none, and "part of a namespace was passed" on a fragment.
- KN-S012 fires on `:latest`, on a version tag and on a container with no image.
- KN-C001 fires with no readiness probe.
- With no workload at all, KN-V010 and KN-C001 are "no apps DaemonSet, ..." and KN-C004, KN-C006, KN-C017 and
  KN-S012 are "no pod spec in the input". A Deployment with no pod template leaves those four with the same
  reason beside a schema finding, and the first hop stops.
- `containers: []` was silent on every rule here and on the schema stage when this lesson was written (G422),
  although the API server refuses it, and the row pinned that gap. G431 closed it in the schema stage: KN-V007 now
  reports a pod template with no regular container, the rules here still say nothing, and by G406 the first hop
  does not hold beside that finding (`tests/test_zero_regular_containers.py` walks it).

So KN-V010 sits on the first hop (a validation finding about the Deployment, beside which no hop that reads a
Deployment holds), the hop about what a pod names needs no `absent:` entry because KN-C017 declines on a fragment
by itself, and a single file therefore never walks complete. These tests pin the table.
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
FIXTURES = ROOT / "tests" / "fixtures" / "mechanism" / "deploy"
LESSON = "mech-cp-deploy-an-app"
WATCHED = {
    "KN-V001",
    "KN-V002",
    "KN-V005",
    "KN-V009",
    "KN-V010",
    "KN-C006",
    "KN-C004",
    "KN-C017",
    "KN-S012",
    "KN-C001",
}
NO_POD_SPEC = dict.fromkeys(("KN-C004", "KN-C006", "KN-C017", "KN-S012"), "no pod spec in the input")


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


def _with(change: Callable[[dict], object]) -> list[dict]:
    """The healthy bundle with its Deployment changed."""
    docs = copy.deepcopy(_docs())
    change(next(d for d in docs if d["kind"] == "Deployment"))
    return docs


def _pod(dep: dict) -> dict:
    return dep["spec"]["template"]["spec"]


def _container(dep: dict) -> dict:
    return _pod(dep)["containers"][0]


UNSEEN = (
    "api-server-admits-and-stores-it",
    "controllers-create-the-pods",
    "scheduler-binds-the-pod",
    "kubelet-starts-the-container",
)


def test_the_healthy_bundle_walks_complete_and_the_four_unseen_hops_are_marked() -> None:
    doc = _walk(FIXTURES / "complete")
    assert doc["verdict"] == "complete" and doc["exitCode"] == 0, doc["verdictReason"]
    v = _verdicts(doc)
    assert {v[h] for h in UNSEEN} == {M.NOT_OBSERVABLE}
    assert doc["counts"] == {"declared": 9, "judged": 5, "notObservable": 4, "notReached": 0}
    assert doc["namespaces"] == ["shop"]


def test_the_broken_bundle_names_its_three_breaks_each_on_its_own_hop() -> None:
    doc = _walk(FIXTURES / "broken")
    assert doc["verdict"] == "broken" and doc["exitCode"] == 1
    by_step = {s["step"]: {f["ruleId"] for f in s.get("findings", [])} for s in doc["steps"]}
    assert by_step["pod-names-objects-that-are-here"] == {"KN-C017"}
    assert by_step["image-is-named-by-digest"] == {"KN-S012"}
    assert by_step["containers-declare-readiness"] == {"KN-C001"}
    v = _verdicts(doc)
    assert v["manifest-is-not-refused"] == v["containers-declare-requests"] == M.HOLDS, v
    for hop in ("pod-names-objects-that-are-here", "image-is-named-by-digest", "containers-declare-readiness"):
        assert v[hop] == M.FAILS and hop in doc["verdictReason"], (hop, v)


@pytest.mark.parametrize(
    ("name", "change", "hop", "rule"),
    [
        ("api-removed", lambda d: d.update(apiVersion="apps/v1beta1"), "manifest-is-not-refused", "KN-V005"),
        ("bad-name", lambda d: d["metadata"].update(name="Web_App"), "manifest-is-not-refused", "KN-V009"),
        (
            "selector",
            lambda d: d["spec"]["selector"].update(matchLabels={"app": "wbe"}),
            "manifest-is-not-refused",
            "KN-V010",
        ),
        (
            "over-limit",
            lambda d: _container(d)["resources"]["requests"].update(memory="1Gi"),
            "manifest-is-not-refused",
            "KN-C006",
        ),
        (
            "no-requests",
            lambda d: _container(d)["resources"].pop("requests"),
            "containers-declare-requests",
            "KN-C004",
        ),
    ],
)
def test_each_remaining_rule_breaks_the_hop_that_names_it(
    tmp_path: Path, name: str, change: Callable[[dict], object], hop: str, rule: str
) -> None:
    """The broken fixture carries three breaks; these are the other links, one violation at a time."""
    doc = _walk(_write(tmp_path, name, _with(change)))
    step = next(s for s in doc["steps"] if s["step"] == hop)
    assert step["verdict"] == M.FAILS, doc
    assert rule in {f["ruleId"] for f in step["findings"]}
    assert doc["verdict"] == "broken" and doc["exitCode"] == 1


def test_a_bundle_with_no_deployment_stops_at_the_first_hop_and_holds_nothing(tmp_path: Path) -> None:
    """A StatefulSet is not what this lesson walks, and a ConfigMap alone is nothing to walk: `needs` stops it."""
    alone = [d for d in _docs() if d["kind"] != "Deployment"]
    other_kind = _with(lambda d: d.update(kind="StatefulSet"))
    for name, docs in (("configmap-only", alone), ("statefulset", other_kind)):
        doc = _walk(_write(tmp_path, name, docs))
        assert doc["stoppedAt"] == "manifest-is-not-refused", (name, doc)
        assert doc["verdict"] == "stopped" and doc["exitCode"] == 5 and doc["counts"]["judged"] == 0
        assert M.HOLDS not in _verdicts(doc).values()


def test_a_deployment_with_no_pod_template_holds_no_hop(tmp_path: Path) -> None:
    """Measured: the rules that read a pod spec say "no pod spec in the input", so the first hop has a rule behind
    it that reached no verdict and stops; nothing about containers is then reported as declared."""
    doc = _walk(_write(tmp_path, "no-template", _with(lambda d: d["spec"].pop("template"))))
    assert doc["stoppedAt"] == "manifest-is-not-refused" and doc["exitCode"] == 5, doc
    assert M.HOLDS not in _verdicts(doc).values()


def test_a_name_the_bundle_has_no_kind_for_stops_the_walk_and_is_not_found(tmp_path: Path) -> None:
    """The pod names a Secret and the bundle defines none. KN-C017 does not call that missing -- an operator may
    create it -- and it does not call it found either: the hop is `cannot judge`, and the image and readiness
    hops after it are not walked."""

    def env_from(dep: dict) -> None:
        _container(dep)["envFrom"] = [{"secretRef": {"name": "web-env"}}]

    doc = _walk(_write(tmp_path, "secret", _with(env_from)))
    v = _verdicts(doc)
    assert v["pod-names-objects-that-are-here"] == M.CANNOT_JUDGE, v
    assert doc["stoppedAt"] == "pod-names-objects-that-are-here"
    assert doc["verdict"] == "stopped" and doc["exitCode"] == 5
    assert "image-is-named-by-digest" not in v and "containers-declare-readiness" not in v
    assert doc["counts"]["notReached"] == 3


def test_a_single_file_is_a_fragment_and_never_walks_complete() -> None:
    """A file is part of a namespace, so a name it does not define is not a missing object: KN-C017 declines, and
    the same bytes that walk complete as a directory stop at exit 5 -- with the broken file too, whose ConfigMap
    typo cannot be called BROKEN on a fragment."""
    for fixture in ("complete", "broken"):
        doc = _walk(FIXTURES / fixture / "bundle.yaml")
        assert doc["stoppedAt"] == "pod-names-objects-that-are-here", (fixture, doc)
        assert doc["verdict"] == "stopped" and doc["exitCode"] == 5
        assert _verdicts(doc)["pod-names-objects-that-are-here"] == M.CANNOT_JUDGE


def test_a_break_before_the_stop_stays_the_answer(tmp_path: Path) -> None:
    """G400 on this lesson: no requests (BROKEN at the requests hop) and a Secret the bundle has no kind for (the
    names hop cannot judge) is `broken` at exit 1 with the stop named, not `stopped` at 5."""

    def both(dep: dict) -> None:
        _container(dep)["resources"].pop("requests")
        _container(dep)["envFrom"] = [{"secretRef": {"name": "web-env"}}]

    doc = _walk(_write(tmp_path, "both", _with(both)))
    assert doc["verdict"] == "broken" and doc["exitCode"] == 1
    assert doc["stoppedAt"] == "pod-names-objects-that-are-here"
    assert "containers-declare-requests" in doc["verdictReason"]


def test_no_hop_that_holds_says_the_pod_is_running_or_ready() -> None:
    """Title fidelity (G395): the rules read what a manifest declares. None of them can establish that the API
    server accepted it, that a pod was scheduled, that an image was pulled or that a pod is Ready."""
    doc = _walk(FIXTURES / "complete")
    for step in doc["steps"]:
        if step["verdict"] != M.HOLDS:
            continue
        claim = f"{step['title']} {step['why']}".lower()
        for words in (
            "the api server accepts",
            "is accepted",
            "is scheduled",
            "is pulled",
            "is running",
            "pod is ready",
            "pods are ready",
        ):
            assert words not in claim, (step["step"], words)


CASES: dict[str, tuple[set[str], dict[str, str], bool]] = {
    # case: (findings among WATCHED, notEvaluated reason fragments among WATCHED, fragment?)
    "fine": (set(), {}, False),
    "fine-fragment": (set(), {"KN-C017": "part of a namespace was passed"}, True),
    "no-name": ({"KN-V001"}, {}, False),
    "apps-v2": ({"KN-V002"}, {}, False),
    "apps-v1beta1": ({"KN-V005"}, {}, False),
    "bad-name": ({"KN-V009"}, {}, False),
    "selector-mismatch": ({"KN-V010"}, {}, False),
    "request-over-limit": ({"KN-C006"}, {}, False),
    "no-requests": ({"KN-C004"}, {}, False),
    "no-requests-fragment": ({"KN-C004"}, {"KN-C017": "part of a namespace was passed"}, True),
    "configmap-typo": ({"KN-C017"}, {}, False),
    "configmap-typo-fragment": (set(), {"KN-C017": "part of a namespace was passed"}, True),
    "secret-no-kind-here": (set(), {"KN-C017": "the bundle defines no Secret in namespace shop"}, False),
    "image-latest": ({"KN-S012"}, {}, False),
    "image-tag": ({"KN-S012"}, {}, False),
    "image-absent": ({"KN-S012"}, {}, False),
    "no-readiness": ({"KN-C001"}, {}, False),
    "no-workload": (
        set(),
        {"KN-V010": "no apps DaemonSet, Deployment", "KN-C001": "no apps DaemonSet, apps Deployment", **NO_POD_SPEC},
        False,
    ),
    "no-pod-template": (set(), NO_POD_SPEC, False),
    "containers-empty": (set(), {}, False),
}

CHANGES: dict[str, Callable[[dict], object]] = {
    "fine": lambda d: None,
    "fine-fragment": lambda d: None,
    "no-name": lambda d: d["metadata"].pop("name"),
    "apps-v2": lambda d: d.update(apiVersion="apps/v2"),
    "apps-v1beta1": lambda d: d.update(apiVersion="apps/v1beta1"),
    "bad-name": lambda d: d["metadata"].update(name="Web_App"),
    "selector-mismatch": lambda d: d["spec"]["selector"].update(matchLabels={"app": "wbe"}),
    "request-over-limit": lambda d: _container(d)["resources"]["requests"].update(memory="1Gi"),
    "no-requests": lambda d: _container(d)["resources"].pop("requests"),
    "no-requests-fragment": lambda d: _container(d)["resources"].pop("requests"),
    "configmap-typo": lambda d: _pod(d)["volumes"][0]["configMap"].update(name="web-confg"),
    "configmap-typo-fragment": lambda d: _pod(d)["volumes"][0]["configMap"].update(name="web-confg"),
    "secret-no-kind-here": lambda d: _container(d).update(envFrom=[{"secretRef": {"name": "web-env"}}]),
    "image-latest": lambda d: _container(d).update(image="registry.example.com/web:latest"),
    "image-tag": lambda d: _container(d).update(image="registry.example.com/web:1.4.2"),
    "image-absent": lambda d: _container(d).pop("image"),
    "no-readiness": lambda d: _container(d).pop("readinessProbe"),
    "no-pod-template": lambda d: d["spec"].pop("template"),
    "containers-empty": lambda d: _pod(d).update(containers=[]),
}


@pytest.mark.parametrize("case", sorted(CASES))
def test_the_measurement_table_still_holds(case: str) -> None:
    expect_finding, expect_reason, fragment = CASES[case]
    docs = [d for d in _docs() if d["kind"] != "Deployment"] if case == "no-workload" else _with(CHANGES[case])
    text = "---\n".join(yaml.safe_dump(d, sort_keys=False) for d in docs)
    report = analyze(text, "kubernetes", None, partial_bundle=fragment).as_dict()
    found = {f["ruleId"] for f in report.get("findings", [])} & WATCHED
    assert found == expect_finding, report.get("findings")
    reasons = report.get("notEvaluated") or {}
    for rule, words in expect_reason.items():
        assert words in reasons.get(rule, ""), (rule, reasons.get(rule))
    assert not ({r for r in reasons if r in WATCHED} - set(expect_reason)), reasons
    if case == "containers-empty":
        # No rule a hop names reads it; the schema stage does, since G431, and that is what stops the walk.
        said = [f["message"] for f in report["findings"] if f["ruleId"] == "KN-V007"]
        assert len(said) == 1 and "no regular container" in said[0], report["findings"]


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
    for n in range(1, 10):
        assert f'id="step-{n}"' in out.stdout
    assert 'id="step-10"' not in out.stdout
    assert "https://" not in out.stdout and "http://" not in out.stdout
