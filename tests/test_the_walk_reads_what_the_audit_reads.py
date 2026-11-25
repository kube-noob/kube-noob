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


def test_a_slash_in_a_namespace_cannot_make_two_namespaces_read_as_one() -> None:
    """`Kind/ns/name` is one string, so `shop/a` and `shop/b` both began with `shop`. Neither is `shop`."""
    d = _docs()
    a = [d[k].replace("namespace: shop", "namespace: shop/a") for k in ("Ingress", "Service")]
    b = [d[k].replace("namespace: shop", "namespace: shop/b") for k in ("Deployment", "NetworkPolicy")]
    walked = _walk("\n---\n".join(a + b))
    assert len(walked["namespaces"]) > 1, walked["namespaces"]
    assert (walked["verdict"], walked["exitCode"]) == ("stopped", 5)


# --- G406 (M3, M5): the walk exits 0 where the audit of the same bytes is not clean about the same objects ------

HOLLOW = """\
apiVersion: apps/v1
kind: Deployment
metadata: {name: hollow, namespace: shop}
spec: {replicas: 2, selector: {matchLabels: {app: hollow}}}
"""
DUPLICATE_KEY = FIXTURE.replace(SELECTOR, "  selector:\n    app: nope\n" + SELECTOR)

#: Every hop of the node-dark lesson holding: two replicas, spread, behind a budget that lets one go.
NODE_OK = """\
apiVersion: apps/v1
kind: Deployment
metadata: {name: api, namespace: shop}
spec:
  replicas: 2
  selector: {matchLabels: {app: api}}
  template:
    metadata: {labels: {app: api}}
    spec:
      topologySpreadConstraints:
        - maxSkew: 1
          topologyKey: kubernetes.io/hostname
          whenUnsatisfiable: DoNotSchedule
          labelSelector: {matchLabels: {app: api}}
      containers:
        - name: api
          image: registry.example.com/api@sha256:3333333333333333333333333333333333333333333333333333333333333333
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata: {name: api, namespace: shop}
spec: {maxUnavailable: 1, selector: {matchLabels: {app: api}}}
"""
#: The workload a lost node takes down, in a kind no hop lists and no rule reads.
ROLLOUT = (
    NODE_OK.split("---", maxsplit=1)[0]
    .replace("apiVersion: apps/v1", "apiVersion: argoproj.io/v1alpha1")
    .replace("kind: Deployment", "kind: Rollout")
    .replace("name: api, namespace", "name: real-api, namespace")
    .replace("replicas: 2", "replicas: 1")
)
REFUSED_POLICY = """\
apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata: {name: np, namespace: shop}
spec: {selector: all()}
"""


def _audit_exit(tmp_path: Path, manifests: str) -> int:
    folder = tmp_path / "audit"
    folder.mkdir()
    (folder / "b.yaml").write_text(manifests, encoding="utf-8")
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    done = subprocess.run(
        [sys.executable, "-m", "kube_noob", "audit", "-f", str(folder)],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    return done.returncode


def test_a_hop_does_not_hold_on_a_workload_with_no_pod_template_beside_a_healthy_one(tmp_path: Path) -> None:
    """G389 fixed this where the hollow Deployment is the ONLY one. Beside a healthy one the rules ran, said
    nothing about it, and two hops listed it among the objects they held on."""
    manifests = FIXTURE + "\n---\n" + HOLLOW
    assert _audit_exit(tmp_path, manifests) == 1
    walked = _walk(manifests)
    hop = _by_id(walked)["workload-selects-its-own-pods"]
    assert hop["verdict"] == M.CANNOT_JUDGE and "KN-V007" in hop["why"], hop
    assert [(f["ruleId"], f["resource"]) for f in hop["findings"]] == [("KN-V007", "Deployment/shop/hollow")]
    assert (walked["verdict"], walked["exitCode"]) == ("stopped", 5)
    assert "pod-reports-ready" not in _by_id(walked), "the readiness hop was drawn over zero containers"


def test_a_hop_does_not_hold_on_an_object_with_a_duplicate_key(tmp_path: Path) -> None:
    assert DUPLICATE_KEY.count("  selector:") == 3, "the edit did not apply"
    assert _audit_exit(tmp_path, DUPLICATE_KEY) == 1
    walked = _walk(DUPLICATE_KEY)
    hop = _by_id(walked)["service-selects-pods"]
    assert hop["verdict"] == M.CANNOT_JUDGE and "KN-V018" in hop["why"], hop
    assert (walked["verdict"], walked["exitCode"]) == ("stopped", 5)


def test_a_schema_finding_from_the_hops_own_rule_is_still_a_verdict() -> None:
    """The neighbouring input: KN-V010 is a schema rule too, and on its own hop it is BROKEN, not a stop."""
    mismatched = FIXTURE.replace("      labels:\n        app: orders-api", "      labels:\n        app: other")
    walked = _walk(mismatched)
    assert _by_id(walked)["workload-selects-its-own-pods"]["verdict"] == M.FAILS
    assert walked["verdict"] == "broken" and walked["exitCode"] == 1


def test_a_finding_about_something_other_than_the_path_does_not_stop_it() -> None:
    """What the claim does NOT say: a security finding on the Deployment is the audit's, not this path's."""
    unprobed = FIXTURE.replace("        seccompProfile:\n          type: RuntimeDefault\n", "")
    report = _report(unprobed)
    assert report["findings"], "the control needs a finding outside every hop"
    walked = M.walk(_lesson(NET), report)
    assert (walked["verdict"], walked["exitCode"]) == ("complete", 0)


def test_a_workload_in_a_kind_nothing_reads_stops_the_hops_about_workloads(tmp_path: Path) -> None:
    manifests = NODE_OK + "---\n" + ROLLOUT
    assert _walk(NODE_OK, NODE)["exitCode"] == 0, "the control: without the Rollout every hop holds"
    assert _audit_exit(tmp_path, manifests) == 1
    assert _report(manifests)["summary"]["verdict"] == "undetermined"
    walked = _walk(manifests, NODE)
    first = walked["steps"][0]
    assert first["step"] == "more-than-one-replica" and first["verdict"] == M.CANNOT_JUDGE, first
    assert "'Rollout/shop/real-api'" in first["why"]
    assert (walked["verdict"], walked["exitCode"]) == ("stopped", 5)
    assert not [s for s in walked["steps"] if s["verdict"] == M.HOLDS]


def test_a_walk_is_never_complete_where_the_audit_of_the_same_input_is_undetermined() -> None:
    """The backstop, for what no hop names: a refused NetworkPolicy is in no hop of the node-dark lesson."""
    manifests = NODE_OK + "---\n" + REFUSED_POLICY
    assert _report(manifests)["summary"]["verdict"] == "undetermined"
    walked = _walk(manifests, NODE)
    assert (walked["verdict"], walked["exitCode"], walked["stoppedAt"]) == ("stopped", 5, None)
    assert "undetermined" in walked["verdictReason"] and "'NetworkPolicy/shop/np'" in walked["verdictReason"]
    assert "every observable hop on this path holds" not in M.render(walked)


def test_the_backstop_in_the_walker_itself_and_what_it_leaves_alone() -> None:
    """Over reports built by hand, so no rule's behaviour today can make these pass."""
    lesson = {
        "id": "x",
        "title": "t",
        "layer": "l",
        "steps": [
            {"id": "a", "title": "a", "needs": ["Deployment"], "rules": ["KN-C001"], "holds": "h"},
            {"id": "b", "title": "b", "needs": ["Service"], "rules": ["KN-V011"], "holds": "h"},
        ],
    }
    resources = ["Deployment/shop/web", "Service/shop/web"]
    clean = {"resources": resources, "summary": {}}
    assert M.walk(lesson, clean)["verdict"] == "complete"

    undetermined = {"resources": resources, "summary": {"verdict": "undetermined"}}
    walked = M.walk(lesson, undetermined)
    assert (walked["verdict"], walked["exitCode"]) == ("stopped", 5)
    assert "a rule declined" in walked["verdictReason"]

    # A broken hop is a verdict more evidence cannot reverse, so it stays 1 (G400).
    finding = {"ruleId": "KN-V011", "severity": "medium", "resource": "Service/shop/web", "title": "t"}
    broken = M.walk(lesson, {**undetermined, "findings": [finding]})
    assert (broken["verdict"], broken["exitCode"]) == ("broken", 1)

    # A malformed object under a hop that does not list the rule: the hop is not judged, and the finding shows.
    schema = {**finding, "ruleId": "KN-V018", "stage": "validate", "category": "schema"}
    odd = M.walk(lesson, {**clean, "findings": [schema]})
    assert _by_id(odd)["b"]["verdict"] == M.CANNOT_JUDGE and odd["exitCode"] == 5
    # The same finding on an object no hop reads says nothing about this path.
    elsewhere = M.walk(lesson, {**clean, "findings": [{**schema, "resource": "ConfigMap/shop/c"}]})
    assert elsewhere["verdict"] == "complete"
    # And a finding that is not about the object's shape is the audit's business, not a hop's.
    other = M.walk(lesson, {**clean, "findings": [{**schema, "category": "wiring", "ruleId": "KN-V023"}]})
    assert other["verdict"] == "complete"


# --- G407 (M4): a replica count that is not a number is not "two or more" ---------------------------------------

UNREADABLE_COUNTS = ['"1"', "'{{ .Values.replicas }}'", "true", "1.5"]


def _with_replicas(value: str) -> str:
    out = NODE_OK.replace("  replicas: 2\n", f"  replicas: {value}\n" if value else "")
    assert out != NODE_OK or value == "2", "the edit did not apply"
    return out


@pytest.mark.parametrize("value", UNREADABLE_COUNTS)
def test_a_replica_count_that_is_not_a_number_is_not_read_as_two_or_more(value: str) -> None:
    report = _report(_with_replicas(value))
    for rule in ("KN-C007", "KN-C009", "KN-C010"):
        assert "not an integer" in report["notEvaluated"][rule], (rule, report["notEvaluated"].get(rule))
        assert report["declined"][rule]["entries"][0]["resource"] == "Deployment/shop/api"
    assert not [f for f in report["findings"] if f["ruleId"] in ("KN-C007", "KN-C009", "KN-C010")]
    # The object is here and the rule could not read what it needs from it: that withholds the verdict (G272).
    assert report["summary"]["verdict"] == "undetermined"


@pytest.mark.parametrize("value", UNREADABLE_COUNTS)
def test_the_node_walk_cannot_judge_a_workload_whose_replica_count_it_cannot_read(value: str) -> None:
    walked = _walk(_with_replicas(value), NODE)
    first = walked["steps"][0]
    assert first["step"] == "more-than-one-replica" and first["verdict"] == M.CANNOT_JUDGE, first
    # Named by the rule the hop rests on, not only by the schema finding beside it (G406 would stop it too).
    assert first["why"].startswith("KN-C007 reached no verdict here: spec.replicas is not an integer"), first["why"]
    assert (walked["verdict"], walked["exitCode"]) == ("stopped", 5)


def test_one_unreadable_count_does_not_hide_a_single_replica_beside_it() -> None:
    """The neighbouring input: the decline is on one object, and the finding on the other still fires."""
    single = (
        NODE_OK.split("---", maxsplit=1)[0].replace("name: api,", "name: lone,").replace("replicas: 2", "replicas: 1")
    )
    report = _report(_with_replicas('"1"') + "---\n" + single)
    assert [f["resource"] for f in report["findings"] if f["ruleId"] == "KN-C007"] == ["Deployment/shop/lone"]
    walked = M.walk(_lesson(NODE), report)
    assert walked["steps"][0]["verdict"] == M.FAILS and walked["exitCode"] == 1


@pytest.mark.parametrize(("value", "fires"), [("1", True), ("", True), ("0", True), ("2", False), ("3", False)])
def test_a_count_that_is_a_number_is_judged_as_before(value: str, fires: bool) -> None:
    """An absent `replicas` is the API's default of one, which is a count; only a non-number is unknown."""
    report = _report(_with_replicas(value))
    assert "KN-C007" not in (report.get("notEvaluated") or {})
    assert bool([f for f in report["findings"] if f["ruleId"] == "KN-C007"]) is fires


def test_a_budget_is_not_measured_against_a_replica_count_nobody_could_read() -> None:
    """KN-C009 read the unknown count as one and reported "allows no disruptions ... (1 replicas)"."""
    strict = _with_replicas('"3"').replace("spec: {maxUnavailable: 1,", "spec: {minAvailable: 1,")
    report = _report(strict)
    assert not [f for f in report["findings"] if f["ruleId"] == "KN-C009"]
    assert "not an integer" in report["notEvaluated"]["KN-C009"]


# --- G408 (M6, and the hop that names nothing to read): a fragment cannot show that something is missing --------

SINGLE = NODE_OK.split("---", maxsplit=1)[0].replace("replicas: 2", "replicas: 1")
WRONG_SELECTOR = FIXTURE.replace(SELECTOR, "  selector:\n    app: someone-else\n  ports:")
INERT_POLICY = FIXTURE.replace(
    "  podSelector:\n    matchLabels:\n      app: orders-api",
    "  podSelector:\n    matchLabels:\n      app: someone-else",
)


def _kit(tmp_path: Path) -> Any:
    from kube_noob import toolkit as tk
    from kube_noob.config import load_settings

    return tk.Toolkit(load_settings(overrides={"offline": True, "dataDir": str(tmp_path / "data")}))


def _tool(tmp_path: Path, lesson_id: str, manifests: str, **kw: Any) -> dict[str, Any]:
    from kube_noob import toolkit as tk

    return _kit(tmp_path).mechanism(tk.MechanismIn(mechanism_id=lesson_id, manifests=manifests, **kw))


@pytest.mark.parametrize(
    ("lesson_id", "manifests", "step", "rule"),
    [
        (NODE, SINGLE, "more-than-one-replica", "KN-C007"),
        (NET, WRONG_SELECTOR, "service-selects-pods", "KN-V011"),
        (NET, INERT_POLICY, "policy-admits-the-packet", "KN-N012"),
    ],
    ids=["no-autoscaler-pasted", "no-matching-pod-pasted", "no-selected-pod-pasted"],
)
def test_a_fragment_is_not_called_broken_on_an_object_it_does_not_hold(
    lesson_id: str, manifests: str, step: str, rule: str, tmp_path: Path
) -> None:
    """`MechanismIn.partial_bundle` promised this and the walk did the opposite for three rules.

    The autoscaler that excuses one replica, and the pod a Service or a NetworkPolicy selects, may be in the
    file nobody pasted. The finding is still shown; it is not read as a verdict about the namespace.
    """
    assert manifests not in (FIXTURE, NODE_OK), "the edit did not apply"
    fragment = _tool(tmp_path, lesson_id, manifests)  # partial_bundle defaults to True
    hop = _by_id(fragment)[step]
    assert hop["verdict"] == M.CANNOT_JUDGE, hop
    assert rule in hop["why"] and "part of a namespace was passed" in hop["why"]
    assert rule in [f["ruleId"] for f in hop["findings"]], "the finding is withheld from the reader"
    assert (fragment["verdict"], fragment["exitCode"], fragment["stoppedAt"]) == ("stopped", 5, step)

    # The same bytes declared to be the whole namespace: now the absence is evidence, and the hop is BROKEN.
    whole = _tool(tmp_path, lesson_id, manifests, partial_bundle=False)
    assert _by_id(whole)[step]["verdict"] == M.FAILS
    assert (whole["verdict"], whole["exitCode"]) == ("broken", 1)


def test_one_file_through_the_command_is_a_fragment_too(tmp_path: Path) -> None:
    one = tmp_path / "deployment.yaml"
    one.write_text(SINGLE, encoding="utf-8")
    done = _cli(NODE, one)
    assert done.returncode == 5, done.stdout + done.stderr
    assert "1. [cannot judge]" in done.stdout and "KN-C007" in done.stdout
    assert "BROKEN" not in done.stdout

    folder = tmp_path / "ns"
    folder.mkdir()
    (folder / "deployment.yaml").write_text(SINGLE, encoding="utf-8")
    done = _cli(NODE, folder)
    assert done.returncode == 1 and "1. [BROKEN]" in done.stdout, done.stdout + done.stderr


def test_a_finding_that_rests_on_nothing_absent_is_broken_on_a_fragment_as_before() -> None:
    """Over a hand-built lesson and report: only a hop whose EVERY finding is from an `absent` rule declines."""
    lesson = {
        "id": "x",
        "title": "t",
        "layer": "l",
        "steps": [
            {"id": "a", "title": "a", "needs": ["Service"], "rules": ["R-1", "R-2"], "absent": ["R-1"], "holds": "h"}
        ],
    }

    def walked(rules: tuple[str, ...], partial: bool) -> str:
        findings = [{"ruleId": r, "severity": "low", "resource": "Service/shop/web", "title": "t"} for r in rules]
        report = {"resources": ["Service/shop/web"], "summary": {}, "findings": findings}
        return str(M.walk(lesson, report, partial_bundle=partial)["steps"][0]["verdict"])

    assert walked(("R-1",), True) == M.CANNOT_JUDGE
    assert walked(("R-1",), False) == M.FAILS
    assert walked(("R-2",), True) == M.FAILS
    assert walked(("R-1", "R-2"), True) == M.FAILS
    assert walked((), True) == M.HOLDS


def test_the_field_that_promises_this_says_what_the_walk_does() -> None:
    from kube_noob import toolkit as tk

    text = str(tk.MechanismIn.model_fields["partial_bundle"].description)
    assert "`cannot judge`" in text and "without reading it as a verdict" in text


def _step(**kw: Any) -> dict[str, Any]:
    return {"id": "s", "title": "t", "holds": "h", **kw}


def test_a_hop_that_names_nothing_to_read_is_refused_and_an_empty_report_holds_nothing() -> None:
    """`walk(lesson, {})` answered `complete`, exit 0, for a lesson whose only hop was `needs: []`."""
    bare = {"id": "x", "title": "t", "layer": "l", "steps": [_step(needs=[], rules=["KN-N001"])]}
    with pytest.raises(ValueError, match="names no kind"):
        M.walk(bare, {})

    reads = {
        "id": "x",
        "title": "t",
        "layer": "l",
        "steps": [_step(needs=[], reads=["NetworkPolicy"], rules=["KN-N001"])],
    }
    for empty in ({}, {"resources": []}, {"resources": None}):
        walked = M.walk(reads, empty)
        assert (walked["verdict"], walked["exitCode"]) == ("stopped", 5), empty
        assert walked["steps"][0]["verdict"] == M.CANNOT_JUDGE
    # With an object in the report the engine ran, its ledger is whole, and the hop is judged as before.
    assert M.walk(reads, {"resources": ["Deployment/shop/web"]})["verdict"] == "complete"

    stray = {"id": "x", "title": "t", "layer": "l", "steps": [_step(needs=["Service"], rules=["R-1"], absent=["R-9"])]}
    with pytest.raises(ValueError, match="R-9"):
        M.walk(stray, {})


def test_every_shipped_hop_names_what_it_reads_and_every_absent_rule_is_one_of_its_own() -> None:
    """The curriculum invariant: a third lesson cannot reintroduce the hop that holds on nothing."""
    data = yaml.safe_load((ROOT / "src" / "kube_noob" / "data" / "curriculum.yaml").read_text(encoding="utf-8"))
    lessons = [lsn for trk in data["tracks"] for lsn in trk.get("lessons") or () if lsn.get("steps")]
    assert len(lessons) >= 2
    from kube_noob.audit.rules import RULES

    for lesson in lessons:
        for raw in lesson["steps"]:
            step = M.Step.load(raw)  # raises on a hop that names no kind, or a stray `absent`
            if not step.observable:
                continue
            assert step.needs or step.reads, (lesson["id"], step.id)
            assert set(step.absent) <= set(step.rules) <= set(RULES), (lesson["id"], step.id)
    declared = {r for lesson in lessons for raw in lesson["steps"] for r in raw.get("absent") or ()}
    assert declared == {"KN-C007", "KN-V011", "KN-N012"}, "a new `absent` rule needs its own fragment case above"
