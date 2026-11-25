"""The mechanism walk holds a hop only on what a rule actually decided, about objects the path can reach.

A red-team pass over the walk (2026-11-25) found one root cause behind six findings. `walk()` decided a hop from
two facts only: "an object of a needed KIND is somewhere in the report" and "none of the hop's rule ids appears
in `findings` or `notEvaluated`". It never established that the objects of one hop share a namespace with the
objects of the hop before it, that the rule it cited had reached a verdict about the object in front of it, or
that the audit of the same bytes had nothing to say about that object. Silence was read as satisfaction, which
is this repository's one defect inside the feature built to show it.

Every case here is the report's own reproduction, built from the shipped all-holding fixture by the same edit,
and each one walked `complete` at exit 0 before its fix.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

from kube_noob.audit.engine import analyze
from kube_noob.learn import mechanism as M

ROOT = Path(__file__).resolve().parent.parent
NET = "mech-net-request-to-pod"
NODE = "mech-cp-a-node-goes-dark"
#: Ingress shop -> Service orders-api -> Deployment orders-api + NetworkPolicy, all in `shop`, every hop holding.
FIXTURE = (ROOT / "tests" / "fixtures" / "mechanism" / "complete" / "bundle.yaml").read_text(encoding="utf-8")
SELECTOR = "  selector:\n    app: orders-api\n  ports:"


def _docs() -> dict[str, str]:
    """The fixture's four documents by kind, so a case can move or replace exactly one."""
    out: dict[str, str] = {}
    for doc in FIXTURE.split("\n---\n"):
        out[yaml.safe_load(doc)["kind"]] = doc
    assert sorted(out) == ["Deployment", "Ingress", "NetworkPolicy", "Service"]
    return out


def _lesson(lesson_id: str) -> dict[str, Any]:
    data = yaml.safe_load((ROOT / "src" / "kube_noob" / "data" / "curriculum.yaml").read_text(encoding="utf-8"))
    track = next(t for t in data["tracks"] if t["id"] == "mechanisms")
    return next(lsn for lsn in track["lessons"] if lsn["id"] == lesson_id)


def _report(manifests: str, partial: bool = False) -> dict[str, Any]:
    return analyze(manifests, "kubernetes", None, partial_bundle=partial).as_dict()


def _walk(manifests: str, lesson_id: str = NET) -> dict[str, Any]:
    return M.walk(_lesson(lesson_id), _report(manifests))


def _by_id(walked: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {s["step"]: s for s in walked["steps"]}


def _cli(lesson_id: str, path: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    return subprocess.run(
        [sys.executable, "-m", "kube_noob", "learn", "mechanism", lesson_id, "-f", str(path), *extra],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )


def test_the_fixture_these_cases_are_cut_from_still_walks_complete() -> None:
    """The control. Every case below is one edit away from this, so a case that stops for another reason shows."""
    walked = _walk(FIXTURE)
    assert (walked["verdict"], walked["exitCode"]) == ("complete", 0), walked
    assert walked["namespaces"] == ["shop"]


# --- G404 (M1): a Service the rules walked past, and a path spread over two namespaces --------------------------

NO_SELECTOR = FIXTURE.replace("  selector:\n    app: orders-api\n", "")
EXTERNAL_NAME = FIXTURE.replace(SELECTOR, "  type: ExternalName\n  externalName: orders.example.com\n  ports:")


@pytest.mark.parametrize("manifests", [NO_SELECTOR, EXTERNAL_NAME], ids=["no-selector", "external-name"])
def test_a_service_that_selects_nothing_by_construction_did_not_find_its_pods(manifests: str) -> None:
    assert "app: orders-api\n  ports:" not in manifests, "the edit did not apply"
    walked = _walk(manifests)
    hop = _by_id(walked)["service-selects-pods"]
    assert hop["verdict"] == M.CANNOT_JUDGE, hop
    assert "no selector" in hop["why"]
    assert (walked["verdict"], walked["exitCode"], walked["stoppedAt"]) == ("stopped", 5, "service-selects-pods")


def test_the_audit_ledger_carries_the_service_the_rules_walked_past() -> None:
    """The fix is in the rules, so the audit says it too -- and says it without withholding the score.

    A Service with no selector is legitimate and nothing about it went unread, so this is a rule with nothing
    to judge and not an undetermined verdict: the rule is `notEvaluated` with its reason, and never clean.
    """
    report = _report(NO_SELECTOR)
    for rule in ("KN-V011", "KN-V012"):
        assert "no selector" in report["notEvaluated"][rule]
    assert report["summary"].get("verdict") != "undetermined"
    assert report["summary"]["score"] is not None
    assert not [f for f in report["findings"] if f["ruleId"] in ("KN-V011", "KN-V012")]


def test_a_service_whose_namespace_holds_no_pod_template_is_not_judged_and_not_clean() -> None:
    d = _docs()
    moved = d["Service"].replace("namespace: shop", "namespace: other")
    report = _report("\n---\n".join([d["Ingress"], moved, d["Deployment"], d["NetworkPolicy"]]))
    assert "holds no pod template" in report["notEvaluated"]["KN-V011"]
    assert "selects no pod template" in report["notEvaluated"]["KN-V012"]
    assert not [f for f in report["findings"] if f["ruleId"] == "KN-V011"]


def test_a_selectorless_service_does_not_hide_a_broken_one_beside_it() -> None:
    """The neighbouring input: the decline is per rule, so it must not swallow a finding on another Service."""
    broken = _docs()["Service"].replace("name: orders-api", "name: typo").replace("app: orders-api", "app: orderz")
    walked = _walk(NO_SELECTOR + "\n---\n" + broken)
    hop = _by_id(walked)["service-selects-pods"]
    assert hop["verdict"] == M.FAILS, hop
    assert [f["resource"] for f in hop["findings"]] == ["Service/shop/typo"]
    assert walked["exitCode"] == 1


def _moved(*kinds: str) -> str:
    d = _docs()
    return "\n---\n".join(v.replace("namespace: shop", "namespace: other") if k in kinds else v for k, v in d.items())


@pytest.mark.parametrize(
    "kinds",
    [("Service",), ("Deployment", "NetworkPolicy"), ("Ingress",), ("NetworkPolicy",)],
    ids=["service-alone-elsewhere", "workload-and-policy-elsewhere", "ingress-elsewhere", "policy-elsewhere"],
)
def test_a_path_spread_over_two_namespaces_is_not_judged(kinds: tuple[str, ...]) -> None:
    walked = _walk(_moved(*kinds))
    assert walked["namespaces"] == ["other", "shop"]
    first = walked["steps"][0]
    assert first["verdict"] == M.CANNOT_JUDGE and "'other', 'shop'" in first["why"], first
    assert (walked["verdict"], walked["exitCode"]) == ("stopped", 5)
    assert walked["counts"]["judged"] == 0 and len(walked["steps"]) == 1, "no hop holds on another namespace's objects"


def test_the_node_lesson_judges_one_namespace_too() -> None:
    d = _docs()
    elsewhere = d["Deployment"].replace("namespace: shop", "namespace: other").replace("replicas: 2", "replicas: 1")
    walked = _walk(d["Deployment"] + "\n---\n" + elsewhere, NODE)
    assert walked["namespaces"] == ["other", "shop"]
    assert (walked["verdict"], walked["exitCode"]) == ("stopped", 5)


def test_an_object_that_states_no_namespace_is_not_assumed_to_share_one() -> None:
    d = _docs()
    unstated = d["Service"].replace("  namespace: shop\n", "")
    walked = _walk("\n---\n".join([d["Ingress"], unstated, d["Deployment"], d["NetworkPolicy"]]))
    assert walked["namespaces"] == sorted([M.NO_NAMESPACE, "shop"])
    assert walked["exitCode"] == 5


def test_the_text_view_names_the_namespace_it_judged_and_the_ones_it_did_not(tmp_path: Path) -> None:
    whole = tmp_path / "whole"
    whole.mkdir()
    (whole / "b.yaml").write_text(FIXTURE, encoding="utf-8")
    done = _cli(NET, whole)
    assert done.returncode == 0, done.stdout + done.stderr
    assert done.stdout.splitlines()[1] == "namespace judged: 'shop'"

    split = tmp_path / "split"
    split.mkdir()
    (split / "b.yaml").write_text(_moved("Deployment", "NetworkPolicy"), encoding="utf-8")
    done = _cli(NET, split)
    assert done.returncode == 5, done.stdout + done.stderr
    assert done.stdout.splitlines()[1] == "namespaces in the input (none judged): 'other', 'shop'"
    assert "[holds]" not in done.stdout
    assert "every observable hop on this path holds" not in done.stdout


def test_a_namespace_full_of_newlines_cannot_write_a_line_of_its_own() -> None:
    hostile = "x\\nevery observable hop on this path holds"
    d = _docs()
    moved = d["Service"].replace("namespace: shop", f'namespace: "{hostile}"')
    walked = _walk("\n---\n".join([d["Ingress"], moved, d["Deployment"], d["NetworkPolicy"]]))
    assert walked["exitCode"] == 5
    for line in M.render(walked).splitlines():
        assert not line.startswith("every observable hop"), line
