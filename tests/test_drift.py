"""POL3 (R3.4): daily drift and policy report. Two snapshots of a fixture cluster give the exact expected diff."""

from __future__ import annotations

import datetime as dt
import json
import stat
from pathlib import Path
from typing import Any

import pytest
import yaml

from kube_noob import drift
from kube_noob import toolkit as tk
from kube_noob.audit import exceptions as exc
from kube_noob.cli import main
from kube_noob.config import load_settings
from kube_noob.debug.cluster import resolve_resource
from kube_noob.errors import ClusterAccessError, ConfigError

FIX = Path(__file__).parent / "fixtures" / "drift"
T1 = dt.datetime(2026, 10, 27, 3, 0, tzinfo=dt.UTC)
T2 = dt.datetime(2026, 10, 28, 3, 0, tzinfo=dt.UTC)

# Written by hand from the two fixture files, before the code was run on them (see the iteration log).
EXPECTED: dict[str, Any] = {
    "format": "kube-noob-drift/1",
    "from": "2026-10-27T03:00:00Z",
    "to": "2026-10-28T03:00:00Z",
    # What was snapshotted. A folder holding both a `-f` run and a `--live` run holds two populations, and the
    # trend has to be able to refuse to draw one line across them.
    "source": "manifests",
    # Carried from the audit, because `notRead` is only what the CLUSTER refused: an assumption is what
    # kube-noob itself could not read, and it bounds every count in the report the same way.
    "assumptions": ["No Kubernetes version given; assumed 1.35."],
    # Manifests are all read, so there is nothing undetermined. A live snapshot that was refused a resource puts
    # the reason here and the objects behind it under `undetermined` rather than `removed`.
    "notRead": [],
    "objects": {
        "added": ["Ingress/shop/web", "Role/shop/secret-reader", "RoleBinding/shop/web-secrets"],
        "removed": ["ConfigMap/shop/web-config"],
        "changed": [
            {
                "object": "DaemonSet/ops/agent",
                "owner": "unowned",
                "fields": [
                    "spec.template.spec.containers[0].securityContext.allowPrivilegeEscalation",
                    "spec.template.spec.containers[0].securityContext.privileged",
                ],
            },
            {
                "object": "Deployment/shop/web",
                "owner": "web-team",
                "fields": [
                    "spec.template.spec.containers[0].image",
                    "spec.template.spec.containers[0].readinessProbe.httpGet.path",
                    "spec.template.spec.containers[0].readinessProbe.httpGet.port",
                ],
            },
        ],
        "undetermined": [],
        "unchanged": 8,
    },
    "findings": {
        "new": [
            {
                "ruleId": "KN-S001",
                "resource": "DaemonSet/ops/agent",
                "severity": "critical",
                "namespace": "ops",
                "owner": "unowned",
            },
            {
                "ruleId": "KN-S002",
                "resource": "DaemonSet/ops/agent",
                "severity": "medium",
                "namespace": "ops",
                "owner": "unowned",
            },
            {
                "ruleId": "KN-S017",
                "resource": "Role/shop/secret-reader",
                "severity": "low",
                "namespace": "shop",
                "owner": "team-shop",
            },
        ],
        "fixed": [
            {
                "ruleId": "KN-C001",
                "resource": "Deployment/shop/web",
                "severity": "medium",
                "namespace": "shop",
                "owner": "web-team",
            },
        ],
        "undetermined": [],
        "open": 5,
        "excepted": 0,
    },
    "violations": {
        "byNamespace": [
            {"namespace": "ops", "findings": 3, "critical": 1, "low": 1, "medium": 1},
            {"namespace": "shop", "findings": 2, "low": 2},
        ],
        "byOwner": [
            {"owner": "unowned", "findings": 3, "critical": 1, "low": 1, "medium": 1},
            {"owner": "team-shop", "findings": 2, "low": 2},
        ],
        "byRule": [
            {"ruleId": "KN-C016", "findings": 2, "low": 2},
            {"ruleId": "KN-S001", "findings": 1, "critical": 1},
            {"ruleId": "KN-S002", "findings": 1, "medium": 1},
            {"ruleId": "KN-S017", "findings": 1, "low": 1},
        ],
        # Hand-derived from the byRule rows above and the published rule-to-control map, the same way the rest of
        # this expectation was written. A finding counts once per control its rule names, so this column does not
        # sum to five: a rule that is evidence about three controls is evidence about three controls (N4).
        "byControl": [
            {
                "control": "AC-6",
                "title": "Least Privilege",
                "findings": 3,
                "critical": 1,
                "low": 1,
                "medium": 1,
                "namespaces": ["ops", "shop"],
            },
            {
                "control": "CM-7",
                "title": "Least Functionality",
                "findings": 2,
                "critical": 1,
                "medium": 1,
                "namespaces": ["ops"],
            },
            {
                "control": "SC-5",
                "title": "Denial-of-service Protection",
                "findings": 2,
                "low": 2,
                "namespaces": ["ops", "shop"],
            },
            {
                "control": "SC-6",
                "title": "Resource Availability",
                "findings": 2,
                "low": 2,
                "namespaces": ["ops", "shop"],
            },
            {"control": "AC-3", "title": "Access Enforcement", "findings": 1, "low": 1, "namespaces": ["shop"]},
            {"control": "AC-5", "title": "Separation of Duties", "findings": 1, "low": 1, "namespaces": ["shop"]},
            {
                "control": "AC-6(10)",
                "title": "Least Privilege | Prohibit Non-privileged Users from Executing Privileged Functions",
                "findings": 1,
                "medium": 1,
                "namespaces": ["ops"],
            },
            {"control": "SC-39", "title": "Process Isolation", "findings": 1, "critical": 1, "namespaces": ["ops"]},
        ],
    },
}


def _docs(name: str) -> list[dict[str, Any]]:
    return [d for d in yaml.safe_load_all((FIX / name).read_text(encoding="utf-8")) if d]


def _snap(name: str, when: dt.datetime, **kw: Any) -> dict[str, Any]:
    return drift.snapshot(_docs(name), source="manifests", taken_at=when, **kw)


def test_two_snapshots_give_the_exact_expected_report() -> None:
    report = drift.diff(_snap("day1.yaml", T1), _snap("day2.yaml", T2))
    # `controlStanding` is `kube_noob.audit.controls.summary` over the new snapshot's coverage record: 28 rows
    # whose buckets have their own tests (G191, G199, G202, and tests/test_control_standing.py). Pasting them
    # into an expectation whose entire value is that it was written BY HAND from the two fixtures would be
    # copying code output into the one test that must not contain any, so it is asserted there instead.
    standing = report.pop("controlStanding")
    assert standing["catalog"] == "NIST SP 800-53 Rev. 5" and standing["controls"]
    assert report == EXPECTED


def test_a_snapshot_holds_hashes_and_names_never_values() -> None:
    snap = _snap("day1.yaml", T1)
    text = json.dumps(snap)
    assert '"info"' not in text, "a ConfigMap value never reaches a snapshot"
    assert "sha256:aaaa" not in text and "quay.io" not in text and 'LOG_LEVEL": "info' not in text
    cm = snap["objects"]["ConfigMap/shop/web-config"]
    assert "data.LOG_LEVEL" in cm["fields"] and len(cm["fields"]["data.LOG_LEVEL"]) == 12
    assert all(len(h) == 12 for o in snap["objects"].values() for h in o["fields"].values())


def test_scaling_status_server_metadata_and_owned_objects_are_not_drift() -> None:
    base = _docs("day1.yaml")
    web = next(d for d in base if d["kind"] == "Deployment" and d["metadata"]["name"] == "worker")
    noisy = json.loads(json.dumps(web))
    noisy["spec"]["replicas"] = 9
    noisy["status"] = {"readyReplicas": 9}
    noisy["metadata"].update(
        {
            "uid": "x",
            "resourceVersion": "1",
            "generation": 4,
            "creationTimestamp": "t",
            "managedFields": [{"manager": "kubectl"}],
            "annotations": {"deployment.kubernetes.io/revision": "5"},
        }
    )
    noisy["spec"]["template"]["metadata"]["annotations"] = {"kubectl.kubernetes.io/restartedAt": "now"}
    rs = {
        "apiVersion": "apps/v1",
        "kind": "ReplicaSet",
        "metadata": {
            "name": "worker-1",
            "namespace": "shop",
            "ownerReferences": [{"kind": "Deployment", "name": "worker", "controller": True}],
        },
    }
    a = drift.snapshot(base, source="manifests", taken_at=T1)
    b = drift.snapshot([d for d in base if d is not web] + [noisy, rs], source="manifests", taken_at=T2)
    rep = drift.diff(a, b)
    assert rep["objects"]["changed"] == [] and rep["objects"]["added"] == []
    real = json.loads(json.dumps(web))
    real["spec"]["template"]["metadata"]["annotations"] = {"owner-note": "a real template change"}
    c = drift.snapshot([d for d in base if d is not web] + [real], source="manifests", taken_at=T2)
    assert drift.diff(a, c)["objects"]["changed"][0]["fields"] == ["spec.template.metadata.annotations.owner-note"]


def test_excepted_findings_are_not_counted_open() -> None:
    rev = exc.review(
        yaml.safe_dump(
            {
                "apiVersion": "kube-noob.io/v1",
                "kind": "ExceptionList",
                "exceptions": [
                    {
                        "id": "EXC-agent",
                        "rule": "KN-S001",
                        "owner": "ops",
                        "reason": "the agent reads host devices",
                        "expires": (dt.datetime.now(dt.UTC).date() + dt.timedelta(days=60)).isoformat(),
                        "scope": {"namespace": "ops", "kind": "DaemonSet", "name": "agent"},
                    }
                ],
            }
        )
    )
    rep = drift.diff(_snap("day1.yaml", T1), _snap("day2.yaml", T2, exceptions=rev))
    assert [f["ruleId"] for f in rep["findings"]["new"]] == ["KN-S002", "KN-S017"]
    # +2: KN-C016 reports `shop` and `ops` for a missing ResourceQuota on both days, so both stay open.
    assert rep["findings"]["open"] == 4 and rep["findings"]["excepted"] == 1


def test_the_daily_report_folder_keeps_the_newest_and_is_owner_only(tmp_path: Path) -> None:
    state = tmp_path / "posture"
    first, paths = drift.write_report(state, _snap("day1.yaml", T1), keep=2)
    assert first["from"] is None and len(first["objects"]["added"]) == 11
    second, paths = drift.write_report(state, _snap("day2.yaml", T2), keep=2)
    assert {k: v for k, v in second.items() if k not in {"from", "controlStanding", "history"}} == {
        k: v for k, v in EXPECTED.items() if k != "from"
    }
    # The trend is attached to what the caller renders and left out of the file written, so a report never
    # carries the history of the reports before it (which would nest, and grow the folder with keep squared).
    assert "history" not in json.loads(paths["report"].read_text(encoding="utf-8"))
    assert [(pt["open"], pt["complete"]) for pt in second["history"]["points"]] == [(3, True), (5, True)]
    assert second["history"]["unplaced"] == []
    for p in paths.values():
        assert stat.S_IMODE(p.stat().st_mode) == 0o600
    assert stat.S_IMODE(state.stat().st_mode) == 0o700
    md = paths["markdown"].read_text(encoding="utf-8")
    assert "| KN-S001 | DaemonSet/ops/agent | critical | unowned |" in md and "## Fixed findings" in md
    third, _ = drift.write_report(state, _snap("day2.yaml", T2 + dt.timedelta(days=1)), keep=2)
    assert third["objects"]["changed"] == [] and third["findings"]["new"] == []
    assert len(list(state.glob("snapshot-*.json"))) == 2 and len(list(state.glob("report-*.json"))) == 2
    assert drift.latest_report(state) == third
    with pytest.raises(drift.DriftError):
        drift.write_report(state, _snap("day2.yaml", T2), keep=0)


def test_bad_snapshots_are_refused(tmp_path: Path) -> None:
    f = tmp_path / "x.json"
    for text in ("{", json.dumps({"format": "other"}), json.dumps([1])):
        f.write_text(text, encoding="utf-8")
        with pytest.raises(drift.DriftError):
            drift.load(f)
    with pytest.raises(drift.DriftError):
        drift.diff({"format": "x"}, _snap("day1.yaml", T1))
    with pytest.MonkeyPatch.context() as m:
        m.setattr(drift, "MAX_OBJECTS", 3)
        with pytest.raises(drift.DriftError, match="more than 3"):
            drift.watched(_docs("day1.yaml"))


class FakeBackend:
    name = "fake"

    def __init__(self, docs: list[dict[str, Any]]) -> None:
        self.calls: list[tuple[str, str | None]] = []
        self.docs = docs

    def get(self, resource: str, name: str | None = None, namespace: str | None = None, **_: Any) -> dict[str, Any]:
        resolve_resource(resource)
        self.calls.append((resource, namespace))
        kind = {**drift.LIVE_RESOURCES, **drift.EXTRA_LIVE}[resource]
        if kind == "SecurityContextConstraints":
            raise ClusterAccessError("not served")
        items = [
            {k: v for k, v in d.items() if k != "kind"}
            for d in self.docs
            if d.get("kind") == kind and (namespace is None or d["metadata"].get("namespace") == namespace)
        ]
        return {"kind": "List", "items": items}


def test_live_snapshots_read_the_allowlist_only(tmp_path: Path) -> None:
    backend = FakeBackend(_docs("day2.yaml"))
    objects, not_read = drift.collect_live(backend, [])
    assert not any("secret" in r for r, _ in backend.calls)
    assert {r for r, _ in backend.calls} == set(drift.LIVE_RESOURCES) | set(drift.EXTRA_LIVE)
    assert any(n.startswith("securitycontextconstraints") for n in not_read)
    live = drift.snapshot(objects, source="live", taken_at=T2, not_read=not_read)
    assert set(live["objects"]) == set(_snap("day2.yaml", T2)["objects"])
    # The record has to arrive in the snapshot, not just be returned by the collector: asserting only that
    # `collect_live` produced it is what let a report call an unreadable object "removed" and its finding "fixed".
    assert live["notRead"] == sorted(not_read)[: drift.MAX_NOT_READ]
    assert "SecurityContextConstraints" in live["notReadKinds"]
    scoped = FakeBackend(_docs("day2.yaml"))
    objs, _ = drift.collect_live(scoped, ["shop"])
    assert ("namespaces", None) in scoped.calls and ("deployments", "shop") in scoped.calls
    assert {o["metadata"]["name"] for o in objs if o["kind"] == "Namespace"} == {"shop"}


def test_cli_snapshot_diff_and_report(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    s1, s2 = tmp_path / "1.json", tmp_path / "2.json"
    assert main(["posture", "snapshot", "-f", str(FIX / "day1.yaml"), "-o", str(s1)]) == 0
    assert main(["posture", "snapshot", "-f", str(FIX / "day2.yaml"), "-o", str(s2)]) == 0
    assert "11 objects, 3 findings" in capsys.readouterr().out
    md = tmp_path / "r.md"
    assert main(["--format", "json", "posture", "diff", str(s1), str(s2), "--markdown", str(md)]) == 0
    rep = json.loads(capsys.readouterr().out)
    assert {k: v for k, v in rep.items() if k not in {"from", "to", "controlStanding"}} == {
        k: v for k, v in EXPECTED.items() if k not in {"from", "to"}
    }
    assert rep["controlStanding"]["controls"], "the standing travels through the CLI too"
    assert md.read_text(encoding="utf-8").startswith("# Drift and policy report")
    state = tmp_path / "state"
    assert main(["posture", "report", "-f", str(FIX / "day1.yaml"), "--state-dir", str(state)]) == 0
    assert main(["posture", "report", "-f", str(FIX / "day2.yaml"), "--state-dir", str(state)]) == 0
    out = capsys.readouterr().out
    assert "3 new, 1 fixed, 5 open" in out
    for argv in (
        ["posture", "snapshot", "-o", str(s1)],
        ["posture", "report", "--live"],
        ["posture", "diff", str(s1), str(md)],
    ):
        assert main(argv) == 2
        capsys.readouterr()


def test_mcp_tool_and_serve_settings(tmp_path: Path) -> None:
    s = load_settings()
    kit = tk.Toolkit(s)
    assert kit.posture_report(tk.EmptyIn())["report"] is None
    drift.write_report(s.data_dir / "posture", _snap("day1.yaml", T1))
    drift.write_report(s.data_dir / "posture", _snap("day2.yaml", T2))
    got = kit.posture_report(tk.EmptyIn())["report"]
    assert got["findings"]["new"] == EXPECTED["findings"]["new"]
    with pytest.raises(ConfigError, match="namespace names"):
        load_settings(overrides={"posture": {"namespaces": ["Bad NS"]}})
    on = load_settings(overrides={"posture": {"reportEnabled": True, "keep": 7}})
    assert on.posture.report_enabled and on.posture.keep == 7
    from kube_noob.drift_schedule import start_background

    stop = start_background(on)
    try:
        assert 30 <= stop.first_delay <= 600
    finally:
        stop.set()


def test_a_kept_report_that_cannot_be_placed_is_named_rather_than_skipped(tmp_path: Path) -> None:
    """The trend is built by reading the reports still kept. A file that cannot be parsed, is not an object at
    all, or carries a count that is not a number, is a point nobody can place -- and a series quietly one point
    short is the defect this project keeps finding: the absence reads as continuity. None of them may crash
    either: `write_report` has already written three files by the time the trend is built, and `latest_report`
    is what the MCP tool and the daily job call."""
    state = tmp_path / "posture"
    for day, fixture in enumerate(("day1.yaml", "day2.yaml", "day1.yaml", "day2.yaml", "day1.yaml")):
        drift.write_report(state, _snap(fixture, T1 + dt.timedelta(days=day)), keep=14)
    kept = sorted(state.glob("report-*.json"))
    assert len(kept) == 5
    kept[1].write_text("{not json", encoding="utf-8")
    kept[2].write_text("null", encoding="utf-8")  # valid JSON, not an object
    kept[3].write_text(
        json.dumps({"format": "kube-noob-drift/1", "to": "x", "findings": {"open": "many", "excepted": None}}),
        encoding="utf-8",
    )
    series = drift.history(state)
    assert series["unplaced"] == [kept[1].name, kept[2].name]
    assert [(p["open"], p["excepted"]) for p in series["points"]] == [(3, 0), (None, None), (3, 0)]
    assert drift.latest_report(state) is not None, "the newest report is still readable"


def test_a_report_written_before_completeness_was_recorded_is_unknown_rather_than_complete(
    tmp_path: Path,
) -> None:
    """kube-noob 0.7.1 and earlier wrote reports under this same `format` string with no `notRead` key at all.
    Reading a missing key as "nothing was unread" would mark a two-week-old folder, inherited across an
    upgrade, as fourteen complete reads -- and draw a line through counts that may be floors."""
    state = tmp_path / "posture"
    drift.write_report(state, _snap("day1.yaml", T1), keep=14)
    old = sorted(state.glob("report-*.json"))[0]
    data = json.loads(old.read_text(encoding="utf-8"))
    del data["notRead"]
    old.write_text(json.dumps(data), encoding="utf-8")
    assert drift.history(state)["points"][0]["complete"] is None


def test_a_snapshot_whose_report_was_never_written_is_named(tmp_path: Path) -> None:
    """`write_report` writes the snapshot first. A kill between the two writes leaves a snapshot the next run
    diffs against and a point the trend cannot make, which has to be said rather than skipped."""
    state = tmp_path / "posture"
    for day in range(2):
        drift.write_report(state, _snap("day1.yaml", T1 + dt.timedelta(days=day)), keep=14)
    sorted(state.glob("report-*.json"))[0].unlink()
    series = drift.history(state)
    assert len(series["points"]) == 1
    assert series["unplaced"] == [sorted(state.glob("snapshot-*.json"))[0].name]


def test_a_kept_report_nested_past_the_limit_is_refused_rather_than_parsed(tmp_path: Path) -> None:
    """The trend reads files back off disk, so it goes through the bounded loader like every other reader:
    from Python 3.14 the depth at which `json.loads` gives up is whatever C stack the process has."""
    from kube_noob.sanitize import MAX_JSON_DEPTH_FILE

    state = tmp_path / "posture"
    drift.write_report(state, _snap("day1.yaml", T1), keep=14)
    bomb = sorted(state.glob("report-*.json"))[0]
    depth = MAX_JSON_DEPTH_FILE + 1
    bomb.write_text("[" * depth + "]" * depth, encoding="utf-8")
    series = drift.history(state)
    assert series["points"] == [] and series["unplaced"] == [bomb.name]
    assert drift.latest_report(state) is None, "and the same file is not returned as the latest report"


def test_a_folder_of_large_reports_spends_its_budget_on_the_newest(tmp_path: Path) -> None:
    """A trend is read from its right-hand end, so when the whole-series budget runs out the points that
    survive are the recent ones -- and every file it did not read is named."""
    state = tmp_path / "posture"
    for day in range(3):
        drift.write_report(state, _snap("day1.yaml", T1 + dt.timedelta(days=day)), keep=14)
    kept = sorted(state.glob("report-*.json"))
    big = drift.MAX_HISTORY_BYTES // 2 + 1
    for path in kept[:2]:
        data = json.loads(path.read_text(encoding="utf-8"))
        data["padding"] = "x" * big
        path.write_text(json.dumps(data), encoding="utf-8")
    series = drift.history(state)
    # Two files of half the budget each cannot both be read, so the newest alone survives and the two the
    # budget refused are named rather than dropped from the series.
    assert [p["at"] for p in series["points"]] == ["2026-10-29T03:00:00Z"]
    assert series["unplaced"] == [kept[0].name, kept[1].name]


def test_one_report_larger_than_the_per_file_limit_is_not_parsed(tmp_path: Path) -> None:
    state = tmp_path / "posture"
    drift.write_report(state, _snap("day1.yaml", T1), keep=14)
    big = sorted(state.glob("report-*.json"))[0]
    big.write_text(" " * (drift.MAX_REPORT_BYTES + 1), encoding="utf-8")
    series = drift.history(state)
    assert series["points"] == [] and series["unplaced"] == [big.name]


def test_a_snapshot_keeps_what_the_audit_had_to_assume(tmp_path: Path) -> None:
    """U4. `notRead` is only what the CLUSTER refused. An assumption is what kube-noob itself could not read
    -- above all a pod spec inside a kind it has no reader for -- and dropping it let a folder of snapshots
    report a complete read every day while a whole class of workload was never looked at."""
    rollout = {
        "apiVersion": "argoproj.io/v1alpha1",
        "kind": "Rollout",
        "metadata": {"name": "web", "namespace": "shop"},
        "spec": {"template": {"spec": {"containers": [{"name": "web", "image": "nginx:1.27"}]}}},
    }
    snap = drift.snapshot([rollout], source="manifests", taken_at=T1)
    assert any("no reader for" in a for a in snap["assumptions"]), snap["assumptions"]

    report = drift.first_report(snap)
    assert report["assumptions"] == snap["assumptions"], "a report carries them forward for the reviewer"
    assert any("no reader for" in line for line in drift.markdown(report).splitlines())


def test_the_assumptions_a_snapshot_keeps_are_bounded(tmp_path: Path) -> None:
    many = [
        {
            "apiVersion": "argoproj.io/v1alpha1",
            "kind": "Rollout",
            "metadata": {"name": f"w{i}", "namespace": "shop"},
            "spec": {"template": {"spec": {"containers": [{"name": "c", "image": "nginx:1.27"}]}}},
        }
        for i in range(drift.MAX_ASSUMPTIONS + 40)
    ]
    assert len(drift.snapshot(many, source="manifests", taken_at=T1)["assumptions"]) <= drift.MAX_ASSUMPTIONS
