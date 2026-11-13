"""An object collected twice with different content is a conflict, never a silent pick (G288).

The same Node (`worker-1`) under two gather directories -- Ready=True in `aaa-first/`, Ready=False in the image's
own directory -- read as `2/2 nodes Ready`: `_collect` kept the first file in path order and said nothing. Which
copy is the truth is not something a file order decides; the object is not determined, the headline counts it
apart, the analysis lists the conflict with both paths and the fields that differ, and `--require-complete` sees it.
An identical duplicate is a noted skip, not a conflict.
"""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

import pytest

from kube_noob.cli import main
from kube_noob.mustgather import analyse, completeness, ingest, sample
from kube_noob.mustgather import report as mg_report

IMAGE = sample.IMAGE
TOP = sample.TOP
NODE = f"{IMAGE}/cluster-scoped-resources/core/nodes/worker-1.yaml"
MASTER = f"{IMAGE}/cluster-scoped-resources/core/nodes/master-0.yaml"
CV = f"{IMAGE}/cluster-scoped-resources/config.openshift.io/clusterversions/version.yaml"
CO = f"{IMAGE}/cluster-scoped-resources/config.openshift.io/clusteroperators/etcd.yaml"
POD = f"{IMAGE}/namespaces/shop/pods/web-7d9f/web-7d9f.yaml"
SECOND = "aaa-first"  # sorts before the image directory, so file order would pick it


def _tar(path: Path, files: dict[str, str | bytes]) -> Path:
    with tarfile.open(path, "w:gz") as tf:
        for rel in sorted(files):
            data = files[rel].encode() if isinstance(files[rel], str) else files[rel]
            info = tarfile.TarInfo(f"{TOP}/{rel}")
            info.size = len(data)
            info.mtime = 1_793_181_600
            info.mode = 0o644
            tf.addfile(info, io.BytesIO(data))
    return path


def _files(**changes: str | bytes | None) -> dict[str, str | bytes]:
    out: dict[str, str | bytes] = {**sample.FILES, **sample.NESTED}
    for rel, data in changes.items():
        if data is None:
            out.pop(rel, None)
        else:
            out[rel] = data
    return out


def _under_second(rel: str) -> str:
    return SECOND + rel[len(IMAGE) :]


def _analyse(tmp_path: Path, files: dict[str, str | bytes], name: str = "c.tgz") -> analyse.Analysis:
    return analyse.analyse(ingest.open_bundle(_tar(tmp_path / name, files)))


READY_WORKER = sample.FILES[NODE].replace(
    'status: "False"\n    reason: KubeletNotReady', 'status: "True"\n    reason: KubeletReady'
)
assert sample.FILES[NODE] != READY_WORKER


def test_a_node_collected_twice_with_different_readiness_is_a_conflict_not_ready(tmp_path: Path) -> None:
    a = _analyse(tmp_path, _files(**{_under_second(NODE): READY_WORKER}))
    (conflict,) = a.conflicts
    assert conflict["kind"] == "Node" and conflict["name"] == "worker-1"
    assert len(conflict["paths"]) == 2 and any(SECOND in p for p in conflict["paths"])
    assert any(f.startswith("status.conditions") for f in conflict["differs"])
    nodes = a.cluster["nodes"]
    assert nodes == {"total": 2, "controlPlane": 1, "ready": 1, "readyNotDetermined": 1, "cordoned": 1}
    # neither copy's Ready is taken: no NotReady finding from the False copy, no Ready credit from the True one
    assert not any(f.analyser == "nodes" and "worker-1" in f.object and "Ready" in f.title for f in a.findings)
    head = analyse.render_text(a).splitlines()[0]
    assert "1/2 nodes Ready, 1 Ready not determined" in head


def test_the_text_view_names_the_conflict_and_its_paths(tmp_path: Path) -> None:
    a = _analyse(tmp_path, _files(**{_under_second(NODE): READY_WORKER}))
    text = analyse.render_text(a)
    line = next(x for x in text.splitlines() if x.startswith("conflicting:"))
    assert "Node/worker-1" in line and SECOND in line and "not determined" in line


def test_an_identical_duplicate_is_a_noted_skip_not_a_conflict(tmp_path: Path) -> None:
    a = _analyse(tmp_path, _files(**{_under_second(NODE): sample.FILES[NODE]}))
    assert a.conflicts == []
    assert [d["kind"] + "/" + d["name"] for d in a.duplicates] == ["Node/worker-1"]
    assert a.cluster["nodes"]["ready"] == 1 and a.cluster["nodes"]["total"] == 2
    assert "readyNotDetermined" not in a.cluster["nodes"]
    assert any(f.analyser == "nodes" and "worker-1" in f.object for f in a.findings)


def test_two_clusterversions_with_different_desired_versions_never_pick_one(tmp_path: Path) -> None:
    other = sample.FILES[CV].replace("version: 4.20.4", "version: 4.21.0")
    a = _analyse(tmp_path, _files(**{_under_second(CV): other}))
    assert a.cluster.get("version") in (None, "") and "desiredVersion" not in a.cluster
    assert "twice" in a.cluster["clusterVersionNote"] and "not determined" in a.cluster["clusterVersionNote"]
    assert analyse.has_clusterversion(a.cluster)
    (conflict,) = a.conflicts
    assert conflict["kind"] == "ClusterVersion"
    assert analyse.render_text(a).startswith("OpenShift, version not determined")


def test_a_cluster_operator_collected_twice_is_counted_apart(tmp_path: Path) -> None:
    other = sample.FILES[CO].replace('status: "True"', 'status: "False"', 1)
    assert other != sample.FILES[CO]
    a = _analyse(tmp_path, _files(**{_under_second(CO): other}))
    assert a.conflicts and a.conflicts[0]["kind"] == "ClusterOperator"
    ops = a.cluster["clusterOperators"]
    assert ops["availableNotDetermined"] == 1 and ops["total"] == 3 and ops["available"] == 1
    assert not any(f.analyser == "clusteroperators" and "etcd" in f.object for f in a.findings)
    assert "1 Available not determined" in analyse.render_text(a).splitlines()[0]


def test_a_pod_collected_twice_with_different_status_is_not_diagnosed_from_either(tmp_path: Path) -> None:
    other = sample.FILES[POD].replace("CrashLoopBackOff", "Running", 1)
    assert other != sample.FILES[POD]
    a = _analyse(tmp_path, _files(**{_under_second(POD): other}))
    assert any(c["kind"] == "Pod" and c["name"] == "web-7d9f" for c in a.conflicts)
    assert not any(f.analyser == "pods" and "web-7d9f" in f.object for f in a.findings)


def test_a_duplicate_inside_one_gather_directory_is_a_conflict_too(tmp_path: Path) -> None:
    sibling = f"{IMAGE}/cluster-scoped-resources/core/nodes/worker-1-copy.yaml"
    a = _analyse(tmp_path, _files(**{sibling: READY_WORKER}))
    (conflict,) = a.conflicts
    assert conflict["kind"] == "Node" and all(
        p.endswith(("worker-1.yaml", "worker-1-copy.yaml")) for p in conflict["paths"]
    )
    assert a.cluster["nodes"]["readyNotDetermined"] == 1


def test_require_complete_exits_5_on_a_conflict(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    tgz = _tar(tmp_path / "c.tgz", _files(**{_under_second(NODE): READY_WORKER}))
    assert main(["must-gather", "analyze", str(tgz), "--require-complete", "--fail-on", "never"]) == 5
    err = capsys.readouterr().err
    assert "objects" in err and "worker-1" in err
    rep = mg_report.build(ingest.open_bundle(tgz), analyse.analyse(ingest.open_bundle(tgz)))
    legs = {leg["leg"]: leg for leg in rep["completeness"]["legs"]}
    assert legs["objects"]["state"] == "partial" and "Node/worker-1" in legs["objects"]["why"]
    assert "objects" in completeness.LEGS
    assert rep["conflicts"][0]["kind"] == "Node"


def test_the_json_and_the_report_carry_the_conflicts(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    tgz = _tar(tmp_path / "c.tgz", _files(**{_under_second(NODE): READY_WORKER}))
    out_dir = tmp_path / "rep"
    assert main(["--format", "json", "must-gather", "analyze", str(tgz), "--report", str(out_dir)]) == 0
    shown = json.loads(capsys.readouterr().out)
    assert shown["conflicts"][0]["kind"] == "Node" and shown["cluster"]["nodes"]["readyNotDetermined"] == 1
    written = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
    assert written["conflicts"] == shown["conflicts"]
    md = (out_dir / "report.md").read_text(encoding="utf-8")
    assert "conflict" in md.lower() and "worker-1" in md
    assert "1 Ready" in md and "1 Ready not determined" in md


def test_identical_duplicates_are_noted_in_the_objects_leg_and_stay_complete(tmp_path: Path) -> None:
    tgz = _tar(tmp_path / "d.tgz", _files(**{_under_second(NODE): sample.FILES[NODE]}))
    rep = mg_report.build(ingest.open_bundle(tgz), analyse.analyse(ingest.open_bundle(tgz)))
    legs = {leg["leg"]: leg for leg in rep["completeness"]["legs"]}
    assert legs["objects"]["state"] == "complete" and "identical" in legs["objects"]["why"]
    assert rep["duplicates"][0]["kind"] == "Node"
    assert rep["completeness"]["partialLegs"] == ["operator inventory", "operator known issues", "release notes"]


def test_the_shipped_sample_has_no_conflict_and_no_duplicate(tmp_path: Path) -> None:
    a = analyse.analyse(ingest.open_bundle(sample.write(tmp_path)))
    assert a.conflicts == [] and a.duplicates == []
    assert "conflicting" not in a.cluster["nodes"]


# -- round 1 (1, 11, 13): volatile metadata is not a conflict; three copies; the case draft ----------------------

VOLATILE_WORKER = """apiVersion: v1
kind: Node
metadata:
  labels:
    node-role.kubernetes.io/worker: ''
  managedFields:
  - time: '2026-10-28T10:00:07Z'
  name: worker-1
  resourceVersion: '123457'
spec:
  unschedulable: true
status:
  conditions:
  - lastHeartbeatTime: '2026-10-28T10:00:07Z'
    message: container runtime network not ready
    reason: KubeletNotReady
    status: 'False'
    type: Ready
  - lastHeartbeatTime: '2026-10-28T10:00:07Z'
    reason: KubeletHasInsufficientMemory
    status: 'True'
    type: MemoryPressure
"""
VOLATILE_MASTER = sample.FILES[MASTER].replace("  name: master-0\n", "  name: master-0\n  resourceVersion: '9'\n")
ODF = "registry-redhat-io-odf4-odf-must-gather-rhel9-sha256-2a2a"


def _under_odf(rel: str) -> str:
    return ODF + rel[len(IMAGE) :]


def test_a_second_image_that_differs_only_in_volatile_metadata_is_read_once_and_the_findings_fire(
    tmp_path: Path,
) -> None:
    """Two gather images collect the same Nodes; the copies differ in resourceVersion, managedFields and
    lastHeartbeatTime only. That is one reading, and worker-1 is NotReady, cordoned and under memory pressure in
    both (round 1, 1)."""
    files = _files(**{_under_odf(NODE): VOLATILE_WORKER, _under_odf(MASTER): VOLATILE_MASTER})
    a = _analyse(tmp_path, files)
    assert a.conflicts == []
    assert sorted(d["name"] for d in a.duplicates) == ["master-0", "worker-1"]
    assert a.cluster["nodes"] == {"total": 2, "controlPlane": 1, "ready": 1, "cordoned": 1} or a.cluster["nodes"] >= {
        "total": 2,
        "controlPlane": 1,
        "ready": 1,
    }
    titles = [f.title for f in a.findings if f.analyser == "nodes" and "worker-1" in f.object]
    assert any("NotReady" in t for t in titles) and any("MemoryPressure" in t for t in titles)
    assert "conflicting" not in a.cluster["nodes"]
    assert analyse.render_text(a).splitlines()[0].count("1/2 nodes Ready") == 1


def test_the_volatile_paths_are_one_named_constant() -> None:
    paths = analyse.VOLATILE_PATHS
    assert ("metadata", "resourceVersion") in paths and ("metadata", "managedFields") in paths
    assert ("status", "conditions", "*", "lastHeartbeatTime") in paths
    assert ("status", "conditions", "*", "lastTransitionTime") in paths
    assert all(isinstance(why, str) and why for why in paths.values())


def test_a_real_conflict_is_not_determined_for_the_fields_that_differ_only(tmp_path: Path) -> None:
    """Ready differs; the labels, spec.unschedulable and MemoryPressure agree and are still read."""
    a = _analyse(tmp_path, _files(**{_under_second(NODE): READY_WORKER}))
    (conflict,) = a.conflicts
    assert conflict["differs"] == ["status.conditions[Ready]"]
    nodes = a.cluster["nodes"]
    assert nodes["total"] == 2 and nodes["controlPlane"] == 1 and nodes["ready"] == 1
    assert nodes["readyNotDetermined"] == 1
    titles = [f.title for f in a.findings if f.analyser == "nodes" and "worker-1" in f.object]
    assert any("MemoryPressure" in t for t in titles), "the condition both copies agree on is read"
    assert not any("NotReady" in t for t in titles), "the condition they disagree on is read from neither"
    head = analyse.render_text(a).splitlines()[0]
    assert "1/2 nodes Ready, 1 Ready not determined" in head


def test_a_label_conflict_leaves_the_control_plane_count_not_determined(tmp_path: Path) -> None:
    other = sample.FILES[MASTER].replace('node-role.kubernetes.io/master: ""', 'node-role.kubernetes.io/worker: ""')
    other = other.replace('    node-role.kubernetes.io/control-plane: ""\n', "")
    assert other != sample.FILES[MASTER]
    a = _analyse(tmp_path, _files(**{_under_second(MASTER): other}))
    nodes = a.cluster["nodes"]
    assert nodes["controlPlane"] == 0 and nodes["controlPlaneNotDetermined"] == 1
    assert "control plane not determined" in analyse.render_text(a).splitlines()[0]
    assert "not determined" in mg_report.markdown(
        mg_report.build(ingest.open_bundle(_tar(tmp_path / "m.tgz", _files(**{_under_second(MASTER): other}))), a)
    )


def test_three_copies_two_identical_one_different_is_one_conflict_naming_all_three(tmp_path: Path) -> None:
    files = _files(
        **{"aaa-first" + NODE[len(IMAGE) :]: READY_WORKER, "zzz-last" + NODE[len(IMAGE) :]: sample.FILES[NODE]}
    )
    a = _analyse(tmp_path, files)
    assert a.duplicates == [], "a key that is a conflict is not also a duplicate"
    (conflict,) = a.conflicts
    assert len(conflict["paths"]) == 3 and any("zzz-last" in p for p in conflict["paths"])
    assert a.cluster["nodes"]["readyNotDetermined"] == 1


def test_the_case_draft_carries_the_conflict_caveat(tmp_path: Path) -> None:
    tgz = _tar(tmp_path / "c.tgz", _files(**{_under_second(NODE): READY_WORKER}))
    rep = mg_report.build(ingest.open_bundle(tgz), analyse.analyse(ingest.open_bundle(tgz)))
    draft = mg_report.case_draft(rep)
    assert "Node/worker-1" in draft and "collected twice" in draft
    assert "Evidence is partial" in draft
