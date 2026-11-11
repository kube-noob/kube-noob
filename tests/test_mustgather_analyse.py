"""G2: must-gather analysers. Each analyser on the synthetic fixture, ranking and determinism, signals, and hostile
content (deep or aliased YAML, names that would inject into commands, control characters, credentials)."""

from __future__ import annotations

import importlib.util
import io
import json
import sys
import tarfile
import time
from pathlib import Path
from typing import Any

import pytest

from kube_noob.cli import main
from kube_noob.mustgather import analyse, ingest

FIX = Path(__file__).resolve().parent / "fixtures" / "must-gather"
ROOT = "mg/img"


@pytest.fixture(scope="module")
def result(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, analyse.Analysis]:
    out = tmp_path_factory.mktemp("mga")
    spec = importlib.util.spec_from_file_location("mga_generate", FIX / "generate.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["mga_generate"] = mod
    spec.loader.exec_module(mod)
    mod.main(out)
    tgz = out / "must-gather.tar.gz"
    return tgz, analyse.analyse(ingest.open_bundle(tgz))


def _find(a: analyse.Analysis, analyser: str, needle: str) -> analyse.Finding:
    hits = [f for f in a.findings if f.analyser == analyser and needle in f.title]
    assert len(hits) == 1, [f.title for f in a.findings if f.analyser == analyser]
    return hits[0]


def _bundle(tmp_path: Path, files: dict[str, str | bytes], name: str = "t.tgz") -> ingest.Bundle:
    path = tmp_path / name
    with tarfile.open(path, "w:gz") as tf:
        for rel, data in files.items():
            raw = data.encode() if isinstance(data, str) else data
            info = tarfile.TarInfo(f"{ROOT}/{rel}")
            info.size, info.mode = len(raw), 0o644
            tf.addfile(info, io.BytesIO(raw))
    return ingest.open_bundle(path)


def _pod(name: str, ns: str = "shop", reason: str = "CrashLoopBackOff", message: str = "x") -> str:
    return json.dumps(
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": name, "namespace": ns},
            "status": {
                "phase": "Running",
                "containerStatuses": [
                    {"name": "c", "restartCount": 2, "state": {"waiting": {"reason": reason, "message": message}}}
                ],
            },
        }
    )


def test_cluster_version_and_platform(result: tuple[Path, analyse.Analysis]) -> None:
    _, a = result
    c = a.cluster
    assert (c["version"], c["desiredVersion"], c["channel"], c["platform"]) == (
        "4.20.3",
        "4.20.4",
        "stable-4.20",
        "AWS",
    )
    assert c["history"][0]["state"] == "Partial" and c["controlPlaneTopology"] == "HighlyAvailable"
    failing = _find(a, "clusterversion", "Failing")
    assert failing.severity == "critical" and failing.reason == "ClusterOperatorDegraded"
    blocked = _find(a, "clusterversion", "Upgradeable=False")
    assert blocked.severity == "medium" and "alert:ClusterNotUpgradeable" in blocked.as_dict()["signals"]
    assert _find(a, "clusterversion", "in progress").severity == "info"
    assert not [f for f in a.findings if "stopped partway" in f.title]  # Partial while Progressing: in progress


def test_operators_nodes_pools_olm(result: tuple[Path, analyse.Analysis]) -> None:
    _, a = result
    down = _find(a, "clusteroperators", "image-registry")
    assert down.severity == "critical" and down.detail == {"version": "4.20.3"}
    assert "alert:ClusterOperatorDown" in down.as_dict()["signals"]
    auth = _find(a, "clusteroperators", "authentication")
    assert auth.severity == "high" and "co_condition:authentication/Degraded=True:" in " ".join(
        auth.as_dict()["signals"]
    )
    assert a.cluster["clusterOperators"] == {"total": 3, "available": 2, "degraded": 1}
    notready = _find(a, "nodes", "NotReady")
    assert (notready.severity, notready.reason, notready.platform) == ("high", "KubeletNotReady", False)
    assert _find(a, "nodes", "MemoryPressure").reason == "KubeletHasInsufficientMemory"
    assert _find(a, "nodes", "cordoned").severity == "low"
    assert a.cluster["nodes"] == {"total": 2, "controlPlane": 1, "ready": 1, "cordoned": 1}
    degraded = _find(a, "machineconfigpools", "reports Degraded")
    assert degraded.severity == "high" and degraded.detail["degradedMachineCount"] == 1
    assert "unexpected on-disk state" in degraded.message
    assert _find(a, "machineconfigpools", "NodeDegraded").message == "1 nodes are reporting degraded status on sync"
    assert _find(a, "machineconfigpools", "updating").title.endswith("2 of 3 machines updated")
    csv = _find(a, "olm", "rhacs-operator")
    assert (csv.severity, csv.reason, csv.namespace) == ("high", "InstallCheckFailed", "rhacs-operator")
    assert a.cluster["operators"] == [
        {"name": "rhacs-operator.v4.6.0", "namespace": "rhacs-operator", "phase": "Failed"}
    ]


def test_pods_events_etcd(result: tuple[Path, analyse.Analysis]) -> None:
    _, a = result
    crash = _find(a, "pods", "CrashLoopBackOff")
    assert crash.count == 2 and "(2 pods), 14 restarts" in crash.title and crash.severity == "high"
    assert crash.detail["logHint"] == "Error: connect ECONNREFUSED 10.0.0.5:5432"
    assert crash.detail["lastTerminated"] == {"reason": "Error", "exitCode": 1}
    assert crash.next == ["oc describe pod -n shop web-7d9f", "oc logs -n shop web-7d9f -c web --previous"]
    assert any(e.endswith("previous.log") for e in crash.evidence)
    assert "alert:KubePodCrashLooping" in crash.as_dict()["signals"]
    pull = _find(a, "pods", "ImagePullBackOff")
    assert pull.next[1] == "oc get events -n shop --field-selector involvedObject.name=api-5c6d"
    assert _find(a, "pods", "Unschedulable").message == "0/3 nodes are available: 3 Insufficient memory."
    oom = _find(a, "pods", "OOMKilled")
    assert (oom.severity, oom.platform) == ("medium", True)
    backoff = _find(a, "events", "BackOff")
    assert (backoff.count, backoff.severity) == (37, "medium")
    assert _find(a, "events", "FailedScheduling").count == 12  # series.count
    assert _find(a, "events", "QuotaNearlyExhausted").severity == "low"  # a warning reason with no known meaning
    assert not [f for f in a.findings if f.reason == "Pulled"]  # Normal and routine
    leader = _find(a, "etcd", "leader changed")
    assert "terms 5 to 6" in leader.title and "1 'lost leader'" in leader.title
    for phrase, alert in (
        ("apply request took too long", "etcdGRPCRequestsSlow"),
        ("slow fdatasync", "etcdHighFsyncDurations"),
    ):
        assert f"alert:{alert}" in _find(a, "etcd", phrase).as_dict()["signals"]
    assert _find(a, "etcd", "heartbeat").severity == "medium"


def test_ranking_coverage_signals_and_determinism(result: tuple[Path, analyse.Analysis], tmp_path: Path) -> None:
    tgz, a = result
    keys = [analyse.SEVERITIES.index(f.severity) for f in a.findings]
    assert keys == sorted(keys) and a.findings[0].severity == "critical"
    assert a.counts() == {"critical": 2, "high": 8, "medium": 10, "low": 2, "info": 2}
    assert all(e["files"] for e in a.coverage.values()) and not a.unparsed
    names = {f"{s.kind}:{s.name}" for s in a.signals}
    assert {
        "alert:KubeNodeNotReady",
        "alert:KubeNodePressure",
        "alert:etcdHighNumberOfLeaderChanges",
        "event_reason:BackOff",
        "pod_reason:CrashLoopBackOff",
        "pod_reason:ImagePullBackOff",
        "component:machine-config",
        "component:olm",
    } <= names
    top = str(sys.modules["mga_generate"].TOP)
    directory = analyse.analyse(ingest.open_bundle(tgz.parent / top))
    assert json.dumps(directory.as_dict()).replace(top + "/", "") == json.dumps(a.as_dict()).replace(top + "/", "")


def test_cli(result: tuple[Path, analyse.Analysis], capsys: pytest.CaptureFixture[str]) -> None:
    tgz, _ = result
    assert main(["must-gather", "analyze", str(tgz), "--fail-on", "critical"]) == 1
    text = capsys.readouterr().out
    assert "OpenShift 4.20.3; updating to 4.20.4; platform AWS; 1/2 nodes Ready" in text
    assert "CRITICAL clusterversion: the cluster version operator reports Failing" in text
    assert main(["--format", "json", "must-gather", "analyze", str(tgz)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["kind"] == "tar" and out["cluster"]["version"] == "4.20.3"
    assert out["counts"]["critical"] == 2 and out["findings"][0]["evidence"]
    assert [c["analyser"] for c in out["coverage"]] == list(analyse.ANALYSERS)


def test_plain_inspect_output_without_openshift(tmp_path: Path) -> None:
    b = _bundle(tmp_path, {"namespaces/app/pods/p1/p1.yaml": _pod("p1", "app", "ErrImagePull")})
    a = analyse.analyse(b)
    assert a.cluster == {} and [f.reason for f in a.findings] == ["ErrImagePull"]
    assert a.coverage["clusterversion"]["note"].startswith("not in this must-gather")
    assert analyse.render_text(a).startswith("cluster version not in this must-gather")


def test_hostile_yaml_is_refused_not_crashed(tmp_path: Path) -> None:
    deep = "kind: Node\nmetadata: {name: n1}\nstatus: " + "[" * 200_000 + "]" * 200_000 + "\n"
    laughs = "a: &a [x, x, x, x, x, x, x, x, x]\n" + "".join(
        f"{c}: &{c} [{', '.join(['*' + p] * 9)}]\n" for p, c in zip("abcdefgh", "bcdefghi", strict=True)
    )
    many_docs = "---\nkind: Node\nmetadata: {name: n}\n" * 20
    b = _bundle(
        tmp_path,
        {
            "cluster-scoped-resources/core/nodes/deep.yaml": deep,
            "cluster-scoped-resources/core/nodes/laughs.yaml": laughs,
            "cluster-scoped-resources/core/nodes/docs.yaml": many_docs,
            "cluster-scoped-resources/core/nodes/bad.yaml": "kind: Node\nmetadata: {name: [\n",
            "cluster-scoped-resources/core/nodes/bin.yaml": b"\xff\xfe\x00kind: Node\x00",
        },
    )
    a = analyse.analyse(b)
    why = {u["path"].rsplit("/", 1)[-1]: u["reason"] for u in a.unparsed}
    assert why["deep.yaml"].startswith("nested deeper than 64")
    assert why["laughs.yaml"].startswith("uses YAML aliases")
    assert why["docs.yaml"].startswith("more than 10 YAML documents")
    assert why["bad.yaml"] == why["bin.yaml"] == "not valid YAML (not read)"
    assert a.findings == []


def test_a_file_only_one_yaml_parser_accepts_is_still_read(tmp_path: Path) -> None:
    """G121, on the operator's own evidence rather than our data. analyse prefers libyaml for its speed, and libyaml
    versions refuse documents PyYAML's scanner accepts -- an unspaced colon in a flow collection, which libyaml
    before 0.2 refuses outright. Recording such a file as unparsed loses a real finding quietly: `failing()` does not
    look at unparsed, so a --fail-on gate would still exit clean. A file either parser can read is read."""
    b = _bundle(
        tmp_path,
        {
            "cluster-scoped-resources/core/nodes/flow.yaml": "kind: Node\nmetadata: {name: n, labels: {app:}}\n",
            "cluster-scoped-resources/core/nodes/alias.yaml": "kind: Node\nmetadata: &m {name: n}\nspec: *m\n",
        },
    )
    a = analyse.analyse(b)
    why = {u["path"].rsplit("/", 1)[-1]: u["reason"] for u in a.unparsed}
    assert "flow.yaml" not in why, f"a readable file was dropped: {why}"
    # the retry walks the same events, so the refusals the caps exist for still stand
    assert why["alias.yaml"].startswith("uses YAML aliases")


def test_untrusted_names_and_text(tmp_path: Path) -> None:
    evil = "$(touch PWNED)"
    secret = "pass" + "word=" + "hunter2-" + "x" * 8
    msg = f"boom\n\x1b[2Jforged line\u202e {secret}"
    pods: dict[str, str | bytes] = {"namespaces/shop/pods/p0/p0.yaml": _pod("p0", message=msg)}
    pods["namespaces/shop/pods/evil/evil.yaml"] = _pod(evil)
    pods["namespaces/shop/core/events.yaml"] = json.dumps(
        {
            "kind": "EventList",
            "apiVersion": "v1",
            "items": [
                {
                    "kind": "Event",
                    "metadata": {"name": "e1", "namespace": "shop"},
                    "reason": "Failed; rm -rf /",
                    "type": "Warning",
                    "message": "x",
                },
                {
                    "kind": "Event",
                    "metadata": {"name": "e2", "namespace": "shop"},
                    "reason": "FailedMount",
                    "type": "Warning",
                    "involvedObject": {"kind": "Pod", "name": evil},
                    "message": msg,
                },
            ],
        }
    )
    a = analyse.analyse(_bundle(tmp_path, pods))
    blob = json.dumps(a.as_dict(), ensure_ascii=False) + analyse.render_text(a)
    assert "hunter2" not in blob and "\u202e" not in blob and "\nforged" not in blob and "\x1b" not in blob
    p0 = next(f for f in a.findings if f.object == "Pod/shop/p0")
    assert p0.message == "boom forged line pass" + "word=***"  # the whole escape sequence goes, not just ESC
    assert all(evil not in c for f in a.findings for c in f.next)
    evil_pod = next(f for f in a.findings if evil in f.object)
    assert evil_pod.next == []  # no command for a name that is not a Kubernetes name
    assert [f.reason for f in a.findings if f.analyser == "events"] == ["FailedMount"]  # not a reason: dropped


def test_a_name_with_a_trailing_newline_gets_no_command(tmp_path: Path) -> None:
    """Python's ``$`` matches before a trailing newline, so ``"shop\\n"`` once passed the name check and split a
    printed read-only step into two shell lines (the second one any no-argument command, such as ``env``)."""
    pods: dict[str, str | bytes] = {
        "namespaces/shop/pods/env/env.yaml": _pod("env", ns="shop\n"),
        "namespaces/shop/pods/web/web.yaml": _pod("web\n"),
        "namespaces/shop/pods/ok/ok.yaml": _pod("ok", reason="CrashLoopBackOff\n"),
        "namespaces/shop/pods/fine/fine.yaml": _pod("fine"),
    }
    a = analyse.analyse(_bundle(tmp_path, pods))
    steps = [c for f in a.findings for c in f.next]
    assert steps and all("\n" not in c and "\r" not in c for c in steps)
    assert steps == ["oc describe pod -n shop fine", "oc logs -n shop fine -c c --previous"]
    text = analyse.render_text(a)
    assert "\n env\n" not in text and not [line for line in text.splitlines() if line.strip() in {"env", "web"}]


def test_duplicates_across_gather_roots_and_copied_csvs(tmp_path: Path) -> None:
    node = "kind: Node\nmetadata: {name: n1}\nstatus:\n  conditions: [{type: Ready, status: 'False'}]\n"
    csv = (
        "kind: ClusterServiceVersion\nmetadata: {{name: op.v1, namespace: {ns}}}\n"
        "status: {{phase: Failed, reason: {r}}}\n"
    )
    b = _bundle(
        tmp_path,
        {
            "cluster-scoped-resources/core/nodes/n1.yaml": node,
            "img2/cluster-scoped-resources/core/nodes/n1.yaml": node,  # a second gather image
            "namespaces/a/operators.coreos.com/clusterserviceversions/op.v1.yaml": csv.format(ns="a", r="Copied"),
            "namespaces/b/operators.coreos.com/clusterserviceversions/op.v1.yaml": csv.format(
                ns="b", r="InstallCheckFailed"
            ),
        },
    )
    a = analyse.analyse(b)
    assert len([f for f in a.findings if f.analyser == "nodes"]) == 1
    (op,) = [f for f in a.findings if f.analyser == "olm"]
    assert (op.namespace, op.reason) == ("b", "InstallCheckFailed")


def test_one_leader_term_is_not_a_change(tmp_path: Path) -> None:
    log = '{"msg":"raft.node: 8e9e05c52164694d elected leader 91bc3c398fb3c146 at term 5"}\n' * 3
    b = _bundle(tmp_path, {"namespaces/openshift-etcd/pods/etcd-m0/etcd/etcd/logs/current.log": log})
    assert analyse.analyse(b).findings == []


def test_large_lists_are_fast_and_capped(tmp_path: Path) -> None:
    items: list[dict[str, Any]] = [
        {
            "kind": "Event",
            "metadata": {"name": f"e{i}", "namespace": "big"},
            "reason": f"Reason{i % 40}",
            "type": "Warning",
            "count": 2,
            "message": f"message {i}",
        }
        for i in range(20_000)
    ]
    pods = {f"namespaces/big/pods/p{i}/p{i}.yaml": _pod(f"p{i}", "big", message=f"m{i}") for i in range(400)}
    files: dict[str, str | bytes] = {"namespaces/big/core/events.yaml": json.dumps({"kind": "List", "items": items})}
    files.update(pods)
    start = time.monotonic()
    a = analyse.analyse(_bundle(tmp_path, files))
    assert time.monotonic() - start < 30
    events = [f for f in a.findings if f.analyser == "events"]
    assert len(events) == analyse.MAX_EVENT_REASONS and events[0].count == 1000
    pod_findings = [f for f in a.findings if f.analyser == "pods"]
    assert len(pod_findings) == analyse.MAX_PER_ANALYSER and a.coverage["pods"]["notShown"] == 400 - 150


def test_fail_on() -> None:
    a = analyse.Analysis(
        findings=[analyse.Finding("nodes", "info", "x", "y"), analyse.Finding("pods", "medium", "x", "y")]
    )
    assert [f.severity for f in analyse.failing(a, "medium")] == ["medium"]
    assert analyse.failing(a, "high") == [] and analyse.failing(a, "never") == []
    assert [f.severity for f in analyse.failing(a, "low")] == ["medium"]  # info never fails


def test_a_blind_run_is_not_reported_as_a_clean_one(tmp_path: Path) -> None:
    """ "No findings" means either nothing is wrong or nothing could be read, and the exit code used to say the same
    thing for both: failing() counts findings and never looks at unparsed, so a --fail-on gate passed over a
    must-gather whose evidence was truncated. The completeness block carries what was already recorded through to
    the verdict, and --require-complete exits 2 -- distinct from 1, which stays "findings at or above --fail-on"."""
    full = _bundle(
        tmp_path,
        {
            "cluster-scoped-resources/core/nodes/n.yaml": "kind: Node\nmetadata: {name: n}\n",
            "cluster-scoped-resources/core/nodes/bad.yaml": "kind: Node\nmetadata: {name: [\n",
        },
    )
    a = analyse.analyse(full)
    c = a.completeness()
    assert c["unreadableFiles"] >= 1
    assert c["complete"] is False
    assert c["analysersRead"] <= c["analysersExpected"]
    assert a.as_dict()["completeness"] == c
    # the text output has to say so where a reader will see it, not only in the JSON
    assert "evidence is partial" in analyse.render_text(a)
    # and it is still not a *finding*: --fail-on must not be the thing that catches this
    assert analyse.failing(a, "low") == []
