"""A volume a container mounts and nobody declares, and a StatefulSet's governing Service (G434).

Two relationships no rule read. Both were measured silent on every shape below before the rules existed.

**KN-V026: a volumeMount naming no volume.** The API server refuses a pod whose container mounts a name the pod
does not declare (`volumeMounts[0].name: Not found`). The name resolves against the pod's own `volumes[]` and,
in a StatefulSet, against `volumeClaimTemplates[].metadata.name` -- both inside the one object, so no inventory
is needed and a fragment is judged like a namespace. Measured (G434) with `kube_noob.audit.engine.analyze`:

| pod                                                       | before  | KN-V026 after                    |
|-----------------------------------------------------------|---------|----------------------------------|
| StatefulSet, mount `data`, `volumes: [data]`              | -       | -                                |
| StatefulSet, mount `data`, `volumeClaimTemplates: [data]` | -       | -                                |
| StatefulSet, mount `data`, neither                        | -       | finding                          |
| StatefulSet, mount `dta`, `volumeClaimTemplates: [data]`  | -       | finding, names `data`            |
| StatefulSet, initContainer mount `data`, neither          | -       | finding, the initContainer       |
| StatefulSet, ephemeral container mount `data`, neither    | -       | finding, the ephemeral container |
| Deployment, mount `data`, no volumes                      | -       | finding                          |
| Deployment, mount `dta`, `volumes: [data]`                | -       | finding                          |
| Deployment, mount `data`, `volumeClaimTemplates: [data]`  | KN-V007 | finding too (1)                  |
| Pod, CronJob, DaemonSet, Job: mount `data`, no volumes    | -       | finding                          |
| any of them as a fragment                                 | -       | the same finding                 |
| container with no volumeMounts                            | -       | -                                |
| `volumes` not a list, or an entry with no name            | KN-V007 | declined: cannot be read         |
| KServe / KubeRay pod, mount naming no volume              | -       | nE: an operator may add volumes  |
| no pod spec in the input                                  | -       | nE: no pod spec in the input     |

(1) Only a StatefulSet has claim templates; on a Deployment the field is unknown (KN-V007) and declares nothing.

**KN-V027: a StatefulSet whose `serviceName` is not headless.** Each pod of a StatefulSet gets its stable DNS name
from the governing Service, and only a headless one (`clusterIP: None`) publishes per-pod records.

| StatefulSet `db` (serviceName `db`) in `shop`, beside      | before | KN-V027 after                    |
|------------------------------------------------------------|--------|----------------------------------|
| Service `db`, `clusterIP: None`                            | -      | -                                |
| Service `db`, no clusterIP (the cluster assigns one)       | -      | finding                          |
| Service `db`, `clusterIP: 10.0.0.1`, or `""`               | -      | finding                          |
| Service `db`, `type: ExternalName`                         | -      | finding                          |
| Service `db` with a clusterIP AND a headless `db-headless` | -      | finding (the other is unrelated) |
| only a healthy headless Service of another name            | -      | nE: outside the bundle           |
| Service `db` only in namespace `other`                     | -      | nE: outside the bundle           |
| no Service at all                                          | -      | nE: no Service in the input      |
| Service `db` absent, fragment                              | -      | nE: part of a namespace          |
| Service `db` not headless, fragment                        | -      | finding: both objects are here   |
| a `serving.knative.dev` Service `db` (refused)             | -      | declined: 1 Service not audited  |
| no serviceName, or `""`                                    | -      | nE: names no governing Service   |
| headless Service, no volumeClaimTemplates                  | -      | - (they are not required)        |
| no StatefulSet                                             | -      | nE: no apps StatefulSet          |

An absent Service is never a finding and never a pass: a chart, an operator or another repository may create it.
"""

from __future__ import annotations

import copy
from typing import Any

import pytest
import yaml

from kube_noob.audit.engine import analyze

IMAGE = "registry.example.com/db@sha256:" + "a" * 64
MOUNT, GOVERNS = "KN-V026", "KN-V027"
OUTSIDE = "may be created outside the bundle"


def _mounts(*names: str) -> list[dict[str, str]]:
    return [{"name": n, "mountPath": f"/{n}"} for n in names]


def _workload(
    kind: str = "StatefulSet",
    *,
    mounts: tuple[str, ...] | None = None,
    init_mounts: tuple[str, ...] | None = None,
    ephemeral_mounts: tuple[str, ...] | None = None,
    volumes: object = None,
    templates: tuple[str, ...] | None = None,
    service: object = "db",
    ns: str = "shop",
) -> dict[str, Any]:
    main: dict[str, Any] = {"name": "db", "image": IMAGE}
    if mounts is not None:
        main["volumeMounts"] = _mounts(*mounts)
    pod: dict[str, Any] = {"containers": [main]}
    if init_mounts is not None:
        pod["initContainers"] = [{"name": "init", "image": IMAGE, "volumeMounts": _mounts(*init_mounts)}]
    if ephemeral_mounts is not None:
        pod["ephemeralContainers"] = [{"name": "debug", "image": IMAGE, "volumeMounts": _mounts(*ephemeral_mounts)}]
    if volumes is not None:
        pod["volumes"] = [{"name": v, "emptyDir": {}} for v in volumes] if isinstance(volumes, tuple) else volumes
    meta = {"name": "db", "namespace": ns}
    template = {"metadata": {"labels": {"app": "db"}}, "spec": pod}
    if kind == "Pod":
        return {"apiVersion": "v1", "kind": kind, "metadata": meta, "spec": pod}
    if kind in ("Job", "CronJob"):
        pod["restartPolicy"] = "Never"
        job = {"template": {"spec": pod}}
        spec = job if kind == "Job" else {"schedule": "* * * * *", "jobTemplate": {"spec": job}}
        return {"apiVersion": "batch/v1", "kind": kind, "metadata": meta, "spec": spec}
    spec = {"selector": {"matchLabels": {"app": "db"}}, "template": template}
    if kind != "DaemonSet":
        spec["replicas"] = 2
    if kind == "StatefulSet" and service is not None:
        spec["serviceName"] = service
    if templates is not None:
        claim = {"accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": "1Gi"}}}
        spec["volumeClaimTemplates"] = [{"metadata": {"name": t}, "spec": copy.deepcopy(claim)} for t in templates]
    return {"apiVersion": "apps/v1", "kind": kind, "metadata": meta, "spec": spec}


def _service(name: str = "db", cluster_ip: object = "None", ns: str = "shop", **spec_more: object) -> dict[str, Any]:
    spec: dict[str, Any] = {"selector": {"app": "db"}, "ports": [{"port": 5432}], **spec_more}
    if cluster_ip is not None:
        spec["clusterIP"] = cluster_ip
    return {"apiVersion": "v1", "kind": "Service", "metadata": {"name": name, "namespace": ns}, "spec": spec}


def _report(docs: list[dict[str, Any]], fragment: bool = False) -> dict[str, Any]:
    text = "---\n".join(yaml.safe_dump(d, sort_keys=False) for d in docs)
    return analyze(text, "kubernetes", None, partial_bundle=fragment).as_dict()


def _why_not(report: dict[str, Any], rule: str) -> str:
    declined = (report.get("declined") or {}).get(rule) or {}
    words = [(report.get("notEvaluated") or {}).get(rule, ""), *(e["reason"] for e in declined.get("entries", []))]
    return " | ".join(w for w in words if w)


def _paths(report: dict[str, Any], rule: str) -> list[str]:
    return [f["path"] for f in report["findings"] if f["ruleId"] == rule]


# --- KN-V026 ------------------------------------------------------------------------------------------------------

C0 = "spec.template.spec.containers[0].volumeMounts[0].name"
#: case -> (documents, the paths KN-V026 reports, words in its notEvaluated/declined reason)
MOUNTS: dict[str, tuple[list[dict[str, Any]], list[str], str | None]] = {
    "volume-declared": ([_workload(mounts=("data",), volumes=("data",))], [], None),
    "claim-template-declared": ([_workload(mounts=("data",), templates=("data",))], [], None),
    "both-declared": ([_workload(mounts=("data", "tmp"), volumes=("tmp",), templates=("data",))], [], None),
    "neither": ([_workload(mounts=("data",))], [C0], None),
    "typo-against-a-claim-template": ([_workload(mounts=("dta",), templates=("data",))], [C0], None),
    "second-mount-only": (
        [_workload(mounts=("data", "cache"), templates=("data",))],
        ["spec.template.spec.containers[0].volumeMounts[1].name"],
        None,
    ),
    "init-container": (
        [_workload(init_mounts=("data",))],
        ["spec.template.spec.initContainers[0].volumeMounts[0].name"],
        None,
    ),
    "ephemeral-container": (
        [_workload(ephemeral_mounts=("data",))],
        ["spec.template.spec.ephemeralContainers[0].volumeMounts[0].name"],
        None,
    ),
    "deployment-no-volumes": ([_workload("Deployment", mounts=("data",))], [C0], None),
    "deployment-typo": ([_workload("Deployment", mounts=("dta",), volumes=("data",))], [C0], None),
    "deployment-with-claim-templates": ([_workload("Deployment", mounts=("data",), templates=("data",))], [C0], None),
    "daemonset": ([_workload("DaemonSet", mounts=("data",))], [C0], None),
    "pod": ([_workload("Pod", mounts=("data",))], ["spec.containers[0].volumeMounts[0].name"], None),
    "job": ([_workload("Job", mounts=("data",))], [C0], None),
    "cronjob": (
        [_workload("CronJob", mounts=("data",))],
        ["spec.jobTemplate.spec.template.spec.containers[0].volumeMounts[0].name"],
        None,
    ),
    "no-mounts": ([_workload()], [], None),
    "volumes-not-a-list": ([_workload(mounts=("data",), volumes="data")], [], "cannot be read"),
    "volume-without-a-name": ([_workload(mounts=("data",), volumes=[{"emptyDir": {}}])], [], "cannot be read"),
    "no-pod-spec": ([_service()], [], "no pod spec in the input"),
}


@pytest.mark.parametrize("fragment", [False, True], ids=["namespace", "fragment"])
@pytest.mark.parametrize("case", sorted(MOUNTS))
def test_the_mount_table_still_holds(case: str, fragment: bool) -> None:
    docs, paths, reason = MOUNTS[case]
    report = _report(docs, fragment)
    assert _paths(report, MOUNT) == paths, report["findings"]
    why = _why_not(report, MOUNT)
    if reason is None:
        assert why == "", why
    else:
        assert reason in why, why
    for f in report["findings"]:
        if f["ruleId"] == MOUNT:
            assert f["stage"] == "validate" and f["severity"] == "high"


def test_the_finding_names_the_container_the_volume_and_what_is_declared() -> None:
    report = _report([_workload(mounts=("dta",), volumes=("tmp",), templates=("data",))])
    (f,) = [f for f in report["findings"] if f["ruleId"] == MOUNT]
    assert f["resource"] == "StatefulSet/shop/db"
    assert "'db'" in f["message"] and "'dta'" in f["message"]
    assert "'data'" in f["message"] and "'tmp'" in f["message"]


def test_a_mount_in_a_pod_an_operator_builds_is_not_judged() -> None:
    """KServe and KubeRay add volumes to the pods they create (a storage initializer's, the Ray log directory), so a
    mount with no volume in the manifest is not a refusal there. Not judged, and said so: never clean."""
    isvc = {
        "apiVersion": "serving.kserve.io/v1beta1",
        "kind": "InferenceService",
        "metadata": {"name": "m", "namespace": "shop"},
        "spec": {"predictor": {"containers": [{"name": "c", "image": IMAGE, "volumeMounts": _mounts("model-dir")}]}},
    }
    report = _report([isvc])
    assert _paths(report, MOUNT) == []
    assert "an operator" in report["notEvaluated"][MOUNT]
    isvc["spec"]["predictor"]["volumes"] = [{"name": "model-dir", "emptyDir": {}}]
    assert MOUNT not in (_report([isvc]).get("notEvaluated") or {}), "a mount that does resolve is simply fine"


def test_a_mount_entry_that_cannot_be_read_declines_and_does_not_crash() -> None:
    for bad in ("data", [7], [{"mountPath": "/x"}], [{"name": 3, "mountPath": "/x"}]):
        workload = _workload(volumes=("data",))
        workload["spec"]["template"]["spec"]["containers"][0]["volumeMounts"] = bad
        report = _report([workload])
        assert _paths(report, MOUNT) == [], bad
        assert "cannot be read" in _why_not(report, MOUNT), (bad, "never evaluated and clean")


# --- KN-V027 ------------------------------------------------------------------------------------------------------

KNATIVE = {
    "apiVersion": "serving.knative.dev/v1",
    "kind": "Service",
    "metadata": {"name": "db", "namespace": "shop"},
    "spec": {"template": {"spec": {"containers": [{"image": IMAGE}]}}},
}
#: case -> (documents, fragment?, finding?, words in the notEvaluated/declined reason)
GOVERNING: dict[str, tuple[list[dict[str, Any]], bool, bool, str | None]] = {
    "headless": ([_workload(), _service()], False, False, None),
    "headless-and-no-claim-templates": ([_workload(mounts=("t",), volumes=("t",)), _service()], False, False, None),
    "no-cluster-ip": ([_workload(), _service(cluster_ip=None)], False, True, None),
    "cluster-ip-address": ([_workload(), _service(cluster_ip="10.0.0.1")], False, True, None),
    "cluster-ip-empty": ([_workload(), _service(cluster_ip="")], False, True, None),
    "external-name": (
        [_workload(), _service(cluster_ip=None, type="ExternalName", externalName="db.example.com")],
        False,
        True,
        None,
    ),
    "not-headless-beside-a-headless-one-of-another-name": (
        [_workload(), _service(cluster_ip=None), _service("db-headless")],
        False,
        True,
        None,
    ),
    "only-a-headless-service-of-another-name": ([_workload(), _service("db-headless")], False, False, OUTSIDE),
    "service-only-in-another-namespace": ([_workload(), _service(ns="other")], False, False, OUTSIDE),
    "no-service-at-all": ([_workload()], False, False, "no Service in the input"),
    "absent-on-a-fragment": ([_workload(), _service("web")], True, False, "part of a namespace was passed"),
    "not-headless-on-a-fragment": ([_workload(), _service(cluster_ip=None)], True, True, None),
    "refused-service-of-that-name": ([_workload(), KNATIVE, _service("web")], False, False, "1 Service not audited"),
    "no-service-name": ([_workload(service=None), _service()], False, False, "names no governing Service"),
    "empty-service-name": ([_workload(service=""), _service()], False, False, "names no governing Service"),
    "no-statefulset": ([_workload("Deployment"), _service()], False, False, "no apps StatefulSet in the input"),
}


@pytest.mark.parametrize("case", sorted(GOVERNING))
def test_the_governing_service_table_still_holds(case: str) -> None:
    docs, fragment, finding, reason = GOVERNING[case]
    report = _report(docs, fragment)
    assert _paths(report, GOVERNS) == (["spec.serviceName"] if finding else []), report["findings"]
    why = _why_not(report, GOVERNS)
    if reason is None:
        assert why == "", why
    else:
        assert reason in why, why


def test_an_absent_service_is_not_evaluated_and_the_reason_names_what_was_absent() -> None:
    report = _report([_workload(), _service("db-headless")])
    why = report["notEvaluated"][GOVERNS]
    assert "the Service a StatefulSet names as its serviceName is not in its namespace in this input" in why
    assert OUTSIDE in why
    assert GOVERNS not in (report.get("declined") or {}), "nothing went unread, so the score stands"


def test_the_finding_is_on_the_statefulset_and_says_what_the_service_has() -> None:
    cases: tuple[tuple[object, dict[str, object], str], ...] = (
        (None, {}, "sets no clusterIP, so the cluster assigns one"),
        ("", {}, "sets no clusterIP, so the cluster assigns one"),
        ("10.0.0.1", {}, "has clusterIP '10.0.0.1'"),
        (None, {"type": "ExternalName", "externalName": "db.example.com"}, "is an ExternalName Service"),
    )
    for cluster_ip, more, shown in cases:
        report = _report([_workload(), _service(cluster_ip=cluster_ip, **more)])
        (f,) = [f for f in report["findings"] if f["ruleId"] == GOVERNS]
        assert f["resource"] == "StatefulSet/shop/db" and "'db'" in f["message"], f
        assert shown in f["message"] and "clusterIP: None" in f["message"], f["message"]


def test_a_service_whose_spec_cannot_be_read_is_not_called_headless() -> None:
    service = _service()
    service["spec"] = "headless"
    report = _report([_workload(), service, _service("web")])
    assert _paths(report, GOVERNS) == []
    assert GOVERNS in (report.get("notEvaluated") or {}), "never evaluated and clean"
