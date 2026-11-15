"""The incident watch: detection, explanation, memory across occurrences, and what it never stores."""

from __future__ import annotations

import copy
import json
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from kube_noob.cli import main
from kube_noob.config import Settings, load_settings
from kube_noob.errors import ClusterAccessError, ConfigError
from kube_noob.incidents import IncidentLedger, observe, what_changed
from kube_noob.toolkit import IncidentConfirmIn, IncidentIn, IncidentsIn, NamespaceCheckIn, Toolkit
from kube_noob.watch import Watcher, resolve_namespaces, start_background

NOW = datetime(2026, 10, 27, 12, 0, 0, tzinfo=UTC)


def ts(minutes_ago: float) -> str:
    return (NOW - timedelta(minutes=minutes_ago)).isoformat().replace("+00:00", "Z")


def rs(name: str, deploy: str, revision: int, image: str, memory: str, minutes_ago: float) -> dict[str, Any]:
    return {
        "metadata": {
            "name": name,
            "namespace": "shop",
            "creationTimestamp": ts(minutes_ago),
            "annotations": {"deployment.kubernetes.io/revision": str(revision)},
            "ownerReferences": [{"kind": "Deployment", "name": deploy}],
        },
        "spec": {
            "template": {
                "spec": {
                    "containers": [
                        {
                            "name": "api",
                            "image": image,
                            "env": [{"name": "DB_HOST"}] + ([{"name": "CACHE_URL"}] if revision > 1 else []),
                            "resources": {"limits": {"memory": memory}},
                        }
                    ]
                }
            }
        },
    }


def pod(
    name: str,
    owner_rs: str,
    *,
    waiting: dict[str, Any] | None = None,
    last: dict[str, Any] | None = None,
    phase: str = "Running",
    conditions: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    cs: dict[str, Any] = {"name": "api", "restartCount": 5 if last else 0, "state": {}, "lastState": {}}
    if waiting:
        cs["state"] = {"waiting": waiting}
    if last:
        cs["lastState"] = {"terminated": last}
    return {
        "metadata": {"name": name, "namespace": "shop", "ownerReferences": [{"kind": "ReplicaSet", "name": owner_rs}]},
        "status": {"phase": phase, "containerStatuses": [cs], "conditions": conditions or []},
    }


PSA_MSG = (
    'Error creating: pods "reports-6d9f7c-" is forbidden: violates PodSecurity "restricted:latest": '
    'allowPrivilegeEscalation != false (container "api" must set securityContext.allowPrivilegeEscalation=false)'
)


def snapshot() -> dict[str, list[dict[str, Any]]]:
    return {
        "replicasets": [
            rs("orders-api-5c8d9f6b7", "orders-api", 1, "registry.example.com/orders-api:2.7.0", "256Mi", 600),
            rs("orders-api-7d9f8c6b5", "orders-api", 2, "registry.example.com/orders-api:2.7.1", "128Mi", 4),
            rs("payments-6b5d4c3a2", "payments", 1, "registry.example.com/payments:3.1.0", "256Mi", 900),
            rs("reports-6d9f7c", "reports", 1, "registry.example.com/reports:1.0.0", "256Mi", 30),
        ],
        "pods": [
            pod(
                "orders-api-7d9f8c6b5-x2kq9",
                "orders-api-7d9f8c6b5",
                waiting={"reason": "CrashLoopBackOff"},
                last={"reason": "OOMKilled", "exitCode": 137, "finishedAt": ts(1)},
            ),
            pod(
                "payments-6b5d4c3a2-qq1zz",
                "payments-6b5d4c3a2",
                waiting={"reason": "ImagePullBackOff", "message": 'Back-off pulling image "payments:3.1.0"'},
            ),
            pod(
                "batch-7c6d5e4f3-pend1",
                "batch-7c6d5e4f3",
                phase="Pending",
                conditions=[
                    {
                        "type": "PodScheduled",
                        "status": "False",
                        "reason": "Unschedulable",
                        "message": "0/3 nodes are available: 3 Insufficient memory.",
                    }
                ],
            ),
        ],
        "events": [
            {
                "type": "Warning",
                "reason": "FailedCreate",
                "message": PSA_MSG,
                "lastTimestamp": ts(2),
                "metadata": {"name": "ev-1", "namespace": "shop"},
                "involvedObject": {"kind": "ReplicaSet", "name": "reports-6d9f7c"},
            },
            {
                "type": "Warning",
                "reason": "Unhealthy",
                "message": "Readiness probe failed: HTTP 500 password=hunter2",
                "lastTimestamp": ts(3),
                "metadata": {"name": "ev-2", "namespace": "shop"},
                "involvedObject": {"kind": "Pod", "name": "orders-api-7d9f8c6b5-x2kq9"},
            },
            {
                "type": "Warning",
                "reason": "BackOff",
                "message": "Back-off restarting failed container",
                "lastTimestamp": ts(180),
                "metadata": {"name": "ev-3", "namespace": "shop"},
                "involvedObject": {"kind": "Pod", "name": "old-pod-1234567-abcde"},
            },
            {
                "metadata": {"name": "ev-5", "namespace": "shop"},
                "type": "Normal",
                "reason": "Scheduled",
                "message": "ok",
                "lastTimestamp": ts(1),
            },
        ],
        "deployments": [],
    }


class FakeCluster:
    name = "fake"

    def __init__(self, snap: dict[str, list[dict[str, Any]]] | None = None, fail: bool = False) -> None:
        self.snap = snap if snap is not None else snapshot()
        self.fail = fail
        self.log_calls = 0
        self.resources: list[str] = []

    def get(self, resource: str, name: str | None = None, namespace: str | None = None, **_: Any) -> dict[str, Any]:
        self.resources.append(resource)
        if resource == "clusterversions" or self.fail:
            raise ClusterAccessError(f"{resource} not readable")
        return {"kind": "List", "items": copy.deepcopy(self.snap.get(resource, []))}

    def logs(self, namespace: str, pod: str, container: str | None, tail: int, previous: bool) -> str:
        self.log_calls += 1
        assert previous and tail == 50
        return "java.lang.OutOfMemoryError: Java heap space\nconnecting with token=sk-live-SECRET123456"

    def version(self) -> dict[str, Any]:
        return {"serverVersion": {"gitVersion": "v1.35.1"}}


def _settings(tmp_path: Path, **watch: Any) -> Settings:
    return load_settings(
        overrides={"dataDir": str(tmp_path), "cluster": {"enabled": True}, "watch": {"namespaces": ["shop"], **watch}}
    )


def test_observe_attributes_every_signal_to_its_workload() -> None:
    found = {(o.workload, o.signal): o for o in observe(snapshot(), "shop", NOW)}
    assert set(found) == {
        ("deployment/orders-api", "OOMKilled"),
        ("deployment/payments", "ImagePullBackOff"),
        ("deployment/batch", "Unschedulable"),
        ("deployment/reports", "FailedCreate"),
        ("deployment/orders-api", "ProbeFailed"),
    }
    oom = found[("deployment/orders-api", "OOMKilled")]
    assert oom.crashed == [("orders-api-7d9f8c6b5-x2kq9", "api")]
    assert "last exit 137 (OOMKilled)" in oom.evidence[0]
    probe = found[("deployment/orders-api", "ProbeFailed")]
    assert "hunter2" not in json.dumps(probe.evidence)  # redacted before it is kept anywhere


def test_what_changed_names_the_rollout_and_the_diff() -> None:
    changed = what_changed("deployment/orders-api", snapshot()["replicasets"], NOW)
    assert changed is not None
    assert changed["revision"] == 2 and changed["previousRevision"] == 1 and changed["minutesBeforeIncident"] == 4
    assert (
        "container api image registry.example.com/orders-api:2.7.0 -> registry.example.com/orders-api:2.7.1"
        in (changed["changes"])
    )
    assert "container api memory limit 256Mi -> 128Mi" in changed["changes"]
    assert "container api env added: CACHE_URL" in changed["changes"]
    assert changed["note"].startswith("Started 4 min after the rollout to revision 2")
    assert what_changed("statefulset/db", [], NOW) is None
    assert what_changed("deployment/reports", snapshot()["replicasets"], NOW)["changes"][0].startswith("first revision")


def test_poll_opens_explains_and_stores_nothing_sensitive(tmp_path: Path) -> None:
    cluster = FakeCluster()
    watcher = Watcher(_settings(tmp_path), cluster, ["shop"])
    result = watcher.poll(NOW)
    assert len(result["changes"]["opened"]) == 5 and result["errors"] == []
    led = IncidentLedger(tmp_path)
    by_signal = {i["signal"]: i for i in led.all()}
    oom = led.get(by_signal["OOMKilled"]["id"])
    assert oom["analysis"]["diagnosis"]["id"] == "DBG-OOM"
    assert "rollout to revision 2" in oom["headline"] and "128Mi" in oom["headline"]
    denied = by_signal["FailedCreate"]["analysis"]["policyDenials"][0]
    assert denied["engine"] == "pod-security" and "KN-S002" in denied["relatedRules"]
    assert by_signal["Unschedulable"]["analysis"]["diagnosis"]["id"] == "DBG-PENDING-RESOURCES"
    assert by_signal["ImagePullBackOff"]["analysis"]["diagnosis"]["id"] == "DBG-IMAGEPULL"
    assert cluster.log_calls == 1  # previous logs of the crashed container, once
    raw = (tmp_path / "incidents.json").read_text()
    for leaked in ("hunter2", "sk-live-SECRET123456", "OutOfMemoryError", "Java heap space"):
        assert leaked not in raw, leaked
    assert stat.S_IMODE((tmp_path / "incidents.json").stat().st_mode) == 0o600
    assert set(cluster.resources) <= {"pods", "events", "deployments", "replicasets", "clusterversions"}
    assert "secrets" not in cluster.resources


def test_recurrence_brings_back_the_confirmed_fix(tmp_path: Path) -> None:
    settings = _settings(tmp_path, resolveAfterPolls=2)
    healthy = FakeCluster({"pods": [], "events": [], "deployments": [], "replicasets": []})
    sick = FakeCluster()
    w_sick, w_ok = Watcher(settings, sick, ["shop"]), Watcher(settings, healthy, ["shop"])
    w_sick.poll(NOW)
    again = w_sick.poll(NOW + timedelta(minutes=1))
    assert again["changes"]["opened"] == [] and len(again["changes"]["updated"]) == 5
    assert sick.log_calls == 1  # an open incident is not re-diagnosed every poll
    led = IncidentLedger(settings.data_dir, resolve_after_polls=2)
    oom_id = next(i["id"] for i in led.all() if i["signal"] == "OOMKilled")
    kit = Toolkit(settings)
    with pytest.raises(ValueError, match="confirm"):
        kit.incident_confirm(IncidentConfirmIn(id=oom_id, cause="x" * 5, fix="y" * 5, confirmed_by_user=False))
    saved = kit.incident_confirm(
        IncidentConfirmIn(
            id=oom_id,
            cause="memory limit cut to 128Mi in revision 2",
            fix="restored the 256Mi memory limit",
            confirmed_by_user=True,
        )
    )
    assert saved["learningNote"].startswith("local-")
    assert w_ok.poll(NOW + timedelta(minutes=2))["changes"]["resolved"] == []
    assert len(w_ok.poll(NOW + timedelta(minutes=3))["changes"]["resolved"]) == 5
    back = w_sick.poll(NOW + timedelta(minutes=30))
    assert oom_id in back["changes"]["reopened"] and sick.log_calls == 2
    full = kit.incident(IncidentIn(id=oom_id))
    assert full["recurrence"]["occurrences"] == 2 and full["recurrence"]["resolvedOccurrenceMinutes"] == [3]
    assert full["recurrence"]["lastConfirmedFix"]["fix"] == "restored the 256Mi memory limit"
    assert "a fix was confirmed before: restored the 256Mi memory limit" in full["headline"]
    rows = kit.incidents(IncidentsIn(status="open"))["incidents"]
    assert next(r for r in rows if r["id"] == oom_id)["occurrences"] == 2
    search = kit.search(__import__("kube_noob.toolkit", fromlist=["SearchIn"]).SearchIn(query="256Mi memory limit"))
    assert any(r["chunkId"].startswith("kn:local-") for r in search["results"])


def test_failed_reads_never_resolve_and_old_incidents_age_out(tmp_path: Path) -> None:
    settings = _settings(tmp_path, resolveAfterPolls=1, retentionDays=1)
    Watcher(settings, FakeCluster(), ["shop"]).poll(NOW)
    broken = Watcher(settings, FakeCluster(fail=True), ["shop"]).poll(NOW + timedelta(minutes=5))
    assert broken["namespaces"] == [] and len(broken["errors"]) == 4
    assert broken["changes"]["resolved"] == [] and len(broken["open"]) == 5
    empty = FakeCluster({"pods": [], "events": [], "deployments": [], "replicasets": []})
    Watcher(settings, empty, ["shop"]).poll(NOW + timedelta(minutes=6))
    led = IncidentLedger(tmp_path, retention_days=1, resolve_after_polls=1)
    keep = led.all()[0]["id"]
    led.confirm(keep, "a cause that was confirmed", "a fix that was confirmed")
    Watcher(settings, empty, ["shop"]).poll(NOW + timedelta(days=3))
    assert [i["id"] for i in led.all()] == [keep]  # resolved and old: dropped, unless a fix was confirmed


def test_tools_cli_and_service_wiring(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    settings = _settings(tmp_path)

    class FrozenClock(datetime):
        @classmethod
        def now(cls, tz: Any = None) -> FrozenClock:  # type: ignore[override]
            return cls.fromtimestamp(NOW.timestamp(), tz or UTC)

    monkeypatch.setattr("kube_noob.watch.datetime", FrozenClock)
    monkeypatch.setattr("kube_noob.toolkit.get_backend", lambda _s: FakeCluster())
    monkeypatch.setattr("kube_noob.debug.cluster.get_backend", lambda _s: FakeCluster())
    kit = Toolkit(settings)
    names = {t.name for t in kit.specs()}
    assert {"incidents", "incident", "incident_confirm", "cluster_check_namespace"} <= names
    assert "incident_confirm" not in {t.name for t in Toolkit(settings, shared=True).specs()}
    assert "cluster_check_namespace" not in {t.name for t in Toolkit(load_settings()).specs()}
    checked = kit.cluster_check_namespace(NamespaceCheckIn(namespace="shop"))
    assert len(checked["open"]) == 5 and checked["openDetails"][0]["recurrence"]["occurrences"] == 1

    monkeypatch.setenv("KUBE_NOOB_DATA_DIR", str(tmp_path / "cli"))
    assert main(["--cluster-enabled", "watch", "-n", "shop", "--once"]) == 0
    out = capsys.readouterr().out
    assert "5 new, 0 back again, 0 resolved, 5 open" in out and "deployment/orders-api in shop" in out
    assert main(["--format", "json", "incidents", "list"]) == 0
    rows = json.loads(capsys.readouterr().out)["incidents"]
    oom = next(r for r in rows if r["signal"] == "OOMKilled")
    assert main(["incidents", "confirm", oom["id"], "--cause", "limit cut to 128Mi", "--fix", "restored 256Mi"]) == 0
    capsys.readouterr()
    assert main(["--format", "json", "incidents", "show", oom["id"]]) == 0
    assert json.loads(capsys.readouterr().out)["confirmedFixes"][0]["fix"] == "restored 256Mi"
    assert main(["incidents"]) == 0 and "x1" in capsys.readouterr().out
    assert main(["watch", "-n", "shop", "--once"]) == 2  # no cluster access: refused, not silently empty
    assert main(["--cluster-enabled", "watch", "-n", "shop", "--once", "--interval", "5"]) == 2

    stop = start_background(settings)
    stop.set()
    with pytest.raises(ConfigError, match=r"cluster\.enabled"):
        start_background(load_settings(overrides={"dataDir": str(tmp_path), "watch": {"enabled": True}}))
    with pytest.raises(ConfigError, match="namespace names"):
        load_settings(overrides={"watch": {"namespaces": ["Not A Namespace"]}})
    with pytest.raises(ConfigError, match="namespaces to watch"):
        resolve_namespaces(load_settings())
    with pytest.raises(KeyError):
        kit.incident(IncidentIn(id="inc-0000000000"))
