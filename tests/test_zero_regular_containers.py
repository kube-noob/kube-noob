"""A pod spec with zero regular containers is never clean (G431).

The API server refuses a pod with no regular container (`spec.containers: Required value`), and init and ephemeral
containers do not count toward it. The bundled OpenAPI schema says only that the `containers` key is required, so
`containers: []` satisfied it: every container rule then iterated nothing and was recorded evaluated and clean.

Measured (G431) with `kube_noob.audit.engine.analyze`, one object per row, `validate`-stage findings only.
"key" is KN-V007's `'containers' is a required property`; "zero" is KN-V007's `no regular container`:

| pod spec                                  | Pod .. CronJob, PodTemplate (9 kinds) | DeploymentConfig | RayCluster |
|-------------------------------------------|---------------------------------------|------------------|------------|
| one regular container                     | before: -      after: -               | - / -            | - / -      |
| `containers: []`                          | before: -      after: zero            | - / zero         | - / zero   |
| `containers: []` + one initContainer      | before: -      after: zero            | - / zero         | - / zero   |
| `containers: []` + one ephemeralContainer | before: -      after: zero            | - / zero         | - / zero   |
| no `containers` key                       | before: key    after: key             | - / zero         | - / zero   |
| `containers: null`                        | before: key    after: key             | - / zero         | - / zero   |
| no `containers` key + one initContainer   | before: key    after: key             | - / zero         | - / zero   |
| apiVersion of a group the kind is not in  | before: -      after: -  (KN-V002 and `notAudited` already say it) |

So the nine kinds with a bundled schema were silent on exactly the three empty-list rows, and DeploymentConfig and
RayCluster -- which have no bundled schema that requires the key -- were silent on all six. One fact gets one
finding: where the schema already reports the missing key, this check adds nothing. A KServe InferenceService
component is not in the table: its `containers` list is optional there (a predictor is written as `model:`), so an
empty one is not a refusal.

The mechanism walks, each lesson's `complete` example with every workload's `containers` emptied:

| lesson                            | before        | after                                                        |
|-----------------------------------|---------------|--------------------------------------------------------------|
| mech-cp-deploy-an-app             | complete, 0   | stopped, 5 at manifest-is-not-refused; no hop holds          |
| mech-net-request-to-pod           | complete, 0   | stopped, 5 at workload-selects-its-own-pods; readiness not drawn |
| mech-net-pod-calls-a-service      | complete, 0   | stopped, 5 at workload-selects-its-own-pods; readiness not drawn |
| mech-cp-a-node-goes-dark          | broken, 1; replicas hop holds | stopped, 5 at more-than-one-replica      |
| mech-sec-rbac-and-serviceaccounts | complete, 0   | stopped, 5 at no-pod-automounts-a-token                      |
| mech-net-network-policy           | complete, 0   | complete, 0: no hop of it reads a workload kind (see the test) |
| mech-cp-autoscaling (G435, later) | not written   | stopped, 5 at autoscaler-names-a-target-that-is-here         |
"""

from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

from kube_noob.audit.engine import analyze
from kube_noob.audit.podspec import POD_SPEC_PATHS
from kube_noob.learn import mechanism as M

ROOT = Path(__file__).resolve().parents[1]
C: dict[str, Any] = {"name": "c", "image": "registry.example.com/a@sha256:" + "a" * 64}
META = {"name": "w", "namespace": "shop"}
KEY = "'containers' is a required property"
ZERO = "no regular container"

SPECS: dict[str, dict[str, Any]] = {
    "one": {"containers": [C]},
    "empty": {"containers": []},
    "empty+init": {"containers": [], "initContainers": [C]},
    "empty+ephemeral": {"containers": [], "ephemeralContainers": [C]},
    "missing": {},
    "null": {"containers": None},
    "missing+init": {"initContainers": [C]},
}
SCHEMA_KINDS = (
    "Pod",
    "Deployment",
    "StatefulSet",
    "DaemonSet",
    "ReplicaSet",
    "ReplicationController",
    "Job",
    "CronJob",
    "PodTemplate",
)
NO_SCHEMA_KINDS = ("DeploymentConfig", "RayCluster")
#: spec -> what KN-V007 says for a kind WITH a bundled schema, and for one without.
EXPECT: dict[str, tuple[str | None, str | None]] = {
    "one": (None, None),
    "empty": (ZERO, ZERO),
    "empty+init": (ZERO, ZERO),
    "empty+ephemeral": (ZERO, ZERO),
    "missing": (KEY, ZERO),
    "null": (KEY, ZERO),
    "missing+init": (KEY, ZERO),
}


def _obj(kind: str, pod: dict[str, Any]) -> dict[str, Any]:
    pod = copy.deepcopy(pod)
    tpl = {"metadata": {"labels": {"app": "a"}}, "spec": pod}
    sel = {"matchLabels": {"app": "a"}}
    if kind == "Pod":
        return {"apiVersion": "v1", "kind": kind, "metadata": META, "spec": pod}
    if kind == "PodTemplate":
        return {"apiVersion": "v1", "kind": kind, "metadata": META, "template": tpl}
    if kind in ("Deployment", "ReplicaSet", "DaemonSet"):
        return {"apiVersion": "apps/v1", "kind": kind, "metadata": META, "spec": {"selector": sel, "template": tpl}}
    if kind == "StatefulSet":
        spec = {"serviceName": "w", "selector": sel, "template": tpl}
        return {"apiVersion": "apps/v1", "kind": kind, "metadata": META, "spec": spec}
    if kind == "ReplicationController":
        return {"apiVersion": "v1", "kind": kind, "metadata": META, "spec": {"selector": {"app": "a"}, "template": tpl}}
    if kind == "DeploymentConfig":
        spec = {"selector": {"app": "a"}, "template": tpl}
        return {"apiVersion": "apps.openshift.io/v1", "kind": kind, "metadata": META, "spec": spec}
    if kind == "RayCluster":
        spec = {"headGroupSpec": {"rayStartParams": {}, "template": tpl}}
        return {"apiVersion": "ray.io/v1", "kind": kind, "metadata": META, "spec": spec}
    pod["restartPolicy"] = "Never"
    job = {"template": {"spec": pod}}
    if kind == "Job":
        return {"apiVersion": "batch/v1", "kind": kind, "metadata": META, "spec": job}
    assert kind == "CronJob", kind
    spec = {"schedule": "* * * * *", "jobTemplate": {"spec": job}}
    return {"apiVersion": "batch/v1", "kind": kind, "metadata": META, "spec": spec}


def _v007(obj: dict[str, Any], platform: str = "kubernetes") -> list[dict[str, Any]]:
    report = analyze(yaml.safe_dump(obj, sort_keys=False), platform, None).as_dict()
    return [f for f in report["findings"] if f["ruleId"] == "KN-V007" and (KEY in f["message"] or ZERO in f["message"])]


@pytest.mark.parametrize("spec", sorted(SPECS))
@pytest.mark.parametrize("kind", [*SCHEMA_KINDS, *NO_SCHEMA_KINDS])
def test_the_measurement_table_still_holds(kind: str, spec: str) -> None:
    want = EXPECT[spec][0 if kind in SCHEMA_KINDS else 1]
    got = _v007(_obj(kind, SPECS[spec]), "openshift" if kind == "DeploymentConfig" else "kubernetes")
    if want is None:
        assert got == [], got
        return
    assert len(got) == 1, f"one fact, one finding: {got}"
    assert want in got[0]["message"], got
    assert got[0]["stage"] == "validate" and got[0]["category"] == "schema" and got[0]["severity"] == "high"


def test_the_finding_points_at_the_containers_field_and_says_what_does_not_count() -> None:
    (f,) = _v007(_obj("CronJob", SPECS["empty+init"]))
    assert f["path"] == "spec.jobTemplate.spec.template.spec.containers", f
    assert f["resource"] == "CronJob/shop/w"
    assert "Init and ephemeral containers do not count" in f["message"]
    (g,) = _v007(_obj("DeploymentConfig", SPECS["missing"]), "openshift")
    assert g["path"] == "spec.template.spec", "the key is absent, so the finding is on the pod spec that lacks it"


def test_every_pod_spec_of_an_object_that_holds_several_is_judged() -> None:
    obj = _obj("RayCluster", SPECS["one"])
    worker = {"metadata": {"labels": {"app": "a"}}, "spec": {"containers": [], "initContainers": [C]}}
    obj["spec"]["workerGroupSpecs"] = [{"groupName": "g", "template": copy.deepcopy(worker)}, {"template": worker}]
    paths = sorted(f["path"] for f in _v007(obj))
    assert paths == [
        "spec.workerGroupSpecs[0].template.spec.containers",
        "spec.workerGroupSpecs[1].template.spec.containers",
    ], paths


def test_a_kserve_component_may_have_no_containers_list() -> None:
    """`containers` is optional in a KServe component: the predictor is `model:`. An empty list is not a refusal."""
    isvc = {
        "apiVersion": "serving.kserve.io/v1beta1",
        "kind": "InferenceService",
        "metadata": META,
        "spec": {
            "predictor": {"containers": [], "model": {"modelFormat": {"name": "sklearn"}, "storageUri": "s3://b"}}
        },
    }
    assert _v007(isvc) == []


def test_an_object_the_rules_refused_is_not_judged_a_second_time() -> None:
    """`apps.example.com/v1 Deployment` is somebody else's kind: KN-V002 and `notAudited` already answer for it."""
    obj = _obj("Deployment", SPECS["empty"])
    obj["apiVersion"] = "apps.example.com/v1"
    report = analyze(yaml.safe_dump(obj), "kubernetes", None).as_dict()
    assert not [f for f in report["findings"] if f["ruleId"] == "KN-V007"], report["findings"]
    assert report["notAudited"], "and it is still named as not audited"


@pytest.mark.parametrize("bad", ["notalist", 7, {"a": 1}])
def test_a_containers_field_of_the_wrong_type_stays_the_schemas_to_report(bad: object) -> None:
    got = [
        f
        for f in analyze(yaml.safe_dump(_obj("Pod", {"containers": bad})), "kubernetes", None).as_dict()["findings"]
        if f["ruleId"] == "KN-V007"
    ]
    assert got and not [f for f in got if ZERO in f["message"]], got


def test_schema_off_is_the_callers_choice_and_says_nothing() -> None:
    report = analyze(yaml.safe_dump(_obj("Pod", SPECS["empty"])), "kubernetes", None, schema=False).as_dict()
    assert not [f for f in report["findings"] if f["ruleId"] == "KN-V007"]


# --- the mechanism walks ------------------------------------------------------------------------------------------


def _emptied(lesson: str, tmp_path: Path) -> Path:
    """The lesson's `complete` example with every workload's regular containers removed."""
    example = M.lessons()[lesson]["examples"][0]
    text = (ROOT / "tests" / "fixtures" / example / "bundle.yaml").read_text(encoding="utf-8")
    docs = [d for d in yaml.safe_load_all(text) if d]
    emptied = 0
    for d in docs:
        path = POD_SPEC_PATHS.get(d.get("kind"))
        if path is None:
            continue
        node = d
        for key in path:
            node = node[key]
        node["initContainers"] = node["containers"]  # they keep their probes and images, and do not count
        node["containers"] = []
        emptied += 1
    assert emptied, f"{lesson}: its example has no workload to empty"
    out = tmp_path / lesson
    out.mkdir()
    (out / "bundle.yaml").write_text(yaml.safe_dump_all(docs, sort_keys=False), encoding="utf-8")
    return out


def _walk(lesson: str, path: Path) -> dict[str, Any]:
    out = subprocess.run(
        [sys.executable, "-m", "kube_noob", "learn", "mechanism", lesson, "-f", str(path), "--format", "json"],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
        check=False,
        timeout=120,
    )
    doc: dict[str, Any] = json.loads(out.stdout)
    assert doc["exitCode"] == out.returncode
    return doc


#: lesson -> (the hop the walk stops at, hops about containers that must not hold)
WALKS: dict[str, tuple[str, tuple[str, ...]]] = {
    "mech-cp-deploy-an-app": (
        "manifest-is-not-refused",
        ("containers-declare-requests", "image-is-named-by-digest", "containers-declare-readiness"),
    ),
    "mech-cp-autoscaling": (
        "autoscaler-names-a-target-that-is-here",
        ("target-declares-cpu-requests", "floor-keeps-more-than-one-replica"),
    ),
    "mech-net-request-to-pod": ("workload-selects-its-own-pods", ("pod-reports-ready",)),
    "mech-net-pod-calls-a-service": ("workload-selects-its-own-pods", ("pod-reports-ready",)),
    "mech-cp-a-node-goes-dark": ("more-than-one-replica", ("replicas-can-land-apart",)),
    "mech-sec-rbac-and-serviceaccounts": ("no-pod-automounts-a-token", ()),
}


@pytest.mark.parametrize("lesson", sorted(WALKS))
def test_no_walk_holds_a_hop_about_containers_on_a_workload_that_has_none(lesson: str, tmp_path: Path) -> None:
    stop, must_not_hold = WALKS[lesson]
    doc = _walk(lesson, _emptied(lesson, tmp_path))
    verdicts = {s["step"]: s["verdict"] for s in doc["steps"]}
    assert doc["verdict"] == "stopped" and doc["exitCode"] == 5, (doc["verdict"], verdicts)
    assert doc["stoppedAt"] == stop and verdicts[stop] == M.CANNOT_JUDGE, verdicts
    for hop in (stop, *must_not_hold):
        assert verdicts.get(hop) != M.HOLDS, (hop, verdicts)


def test_every_walkable_lesson_with_a_hop_that_reads_a_workload_is_in_the_table() -> None:
    """A lesson added later with a readiness or image hop fails here until it has a row above."""
    reads_a_workload = {
        lid
        for lid, lesson in M.lessons().items()
        for s in lesson["steps"]
        if (set(s.get("needs") or ()) | set(s.get("reads") or ())) & set(POD_SPEC_PATHS)
    }
    assert reads_a_workload == set(WALKS)


def test_the_network_policy_lesson_reads_no_workload_and_still_walks(tmp_path: Path) -> None:
    """Its four judged hops read NetworkPolicy only -- which pods a policy selects is a matter of labels, and the
    template's labels are intact. Pinned so the day a hop of it reads a workload kind, the table above gains a row."""
    doc = _walk("mech-net-network-policy", _emptied("mech-net-network-policy", tmp_path))
    assert doc["verdict"] == "complete" and doc["exitCode"] == 0, doc["verdictReason"]
