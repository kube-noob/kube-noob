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
    assert nodes == {"total": 2, "controlPlane": 1, "ready": 1, "conflicting": 1}
    # neither copy's verdict is taken: no NotReady finding from the False copy, no Ready credit from the True one
    assert not any(f.analyser == "nodes" and "worker-1" in f.object for f in a.findings)
    head = analyse.render_text(a).splitlines()[0]
    assert "1/2 nodes Ready, 1 conflicting" in head


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
    assert "conflicting" not in a.cluster["nodes"]
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
    assert ops["conflicting"] == 1 and ops["total"] == 3
    assert not any(f.analyser == "clusteroperators" and "etcd" in f.object for f in a.findings)


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
    assert conflict["kind"] == "Node" and sorted(
        p.endswith(("worker-1.yaml", "worker-1-copy.yaml")) for p in conflict["paths"]
    )
    assert a.cluster["nodes"]["conflicting"] == 1


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
    assert shown["conflicts"][0]["kind"] == "Node" and shown["cluster"]["nodes"]["conflicting"] == 1
    written = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
    assert written["conflicts"] == shown["conflicts"]
    md = (out_dir / "report.md").read_text(encoding="utf-8")
    assert "conflict" in md.lower() and "worker-1" in md
    assert "1 Ready" in md and "1 conflicting" in md


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
