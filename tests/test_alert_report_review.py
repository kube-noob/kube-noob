"""The adversarial review of I1 (G274): fifteen confirmed defects in the Alertmanager evidence report, each held here
by a test that reproduced it before it was fixed.

The first round passed its own tests and the full gate. Every defect below was a shape those tests did not try: a
long run of dashes that made one in-bounds post take a minute, a lone surrogate that sank a whole group, a size cap
that cut the most severe alert, annotation text that chose the namespace in a suggested command, a version that one
alert's label imposed on every other, and a store whose read paths wrote and whose retention a planted directory
could stop.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import stat
import threading
import time
from pathlib import Path
from typing import Any

import pytest
import yaml
from starlette.testclient import TestClient

from kube_noob import alert_report, alert_store
from kube_noob.config import AlertReportSettings, Settings, load_settings
from kube_noob.debug.cluster import redact_text
from kube_noob.server.http import http_app
from kube_noob.toolkit import AlertReportIn, DiagnoseIn, Toolkit

ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "deploy" / "helm" / "kube-noob"
SAMPLE = (ROOT / "examples" / "alertmanager-etcd.json").read_text(encoding="utf-8")
TOKEN = "review-" + "tok-" + "q" * 10
ROW = {"index": 0, "alertname": "A", "state": "firing", "verdict": "no-recognised-signal"}
AUTH = {"Authorization": f"Bearer {TOKEN}"}
DASHES = "-" * 2000


def _alert(name: str, state: str = "firing", ann: dict[str, str] | None = None, **labels: str) -> dict[str, Any]:
    return {
        "status": state,
        "labels": {"alertname": name, **labels},
        "annotations": ann if ann is not None else {"summary": f"{name} fired"},
    }


def _payload(*alerts: dict[str, Any], **top: Any) -> str:
    return json.dumps({"version": "4", "status": "firing", **top, "alerts": list(alerts)})


def _kit(tmp_path: Path, **extra: Any) -> Toolkit:
    return Toolkit(Settings.model_validate({"dataDir": str(tmp_path / "data"), **extra}), shared=True)


def _report(tmp_path: Path, text: str, **extra: Any) -> dict[str, Any]:
    out: dict[str, Any] = _kit(tmp_path, **extra).alert_report(AlertReportIn(payload=text))["report"]
    return out


def _server(tmp_path: Path, **extra: Any) -> Settings:
    return load_settings(
        overrides={
            "dataDir": str(tmp_path / "data"),
            "server": {"host": "0.0.0.0", "allowedHosts": ["testserver"]},  # noqa: S104
            **extra,
        }
    )


def _post(c: Any, text: str = SAMPLE) -> Any:
    return c.post("/v1/alert-reports", content=text, headers={**AUTH, "Content-Type": "application/json"})


def _worst_case() -> str:
    """The reviewer's in-bounds worst case: 150 alerts, five 2,000-dash fields each, just under the 1.5 MiB limit."""
    return json.dumps(
        {
            "alerts": [
                {
                    "status": "firing",
                    "labels": {"alertname": "KubePodCrashLooping", "namespace": DASHES, "pod": f"a{i}" + DASHES[:1900]},
                    "annotations": {"summary": DASHES, "description": DASHES, "message": DASHES},
                }
                for i in range(150)
            ]
        }
    )


# --- 1. cost, a time budget, and the event loop -----------------------------------------------------------------


#: Stated ceilings, absolute rather than relative. Measured on the 2-core build machine: before the fix one
#: 2,000-dash string took 19.7 ms to redact and the worst-case payload 40.4 s; after, 0.2 ms and the figure in
#: docs/operations.md. Each ceiling leaves about a tenfold margin for a slow CI runner.
REDACT_CEILING_SECONDS = 5.0  # 1,500 strings: the three annotations of 500 alerts
#: The worst case took 4.8 s on an idle build machine and 15 s with three other test suites on its two cores; the
#: ceiling is the north-star minute, with the time budget raised past it so the budget cannot hide a slow build.
WORST_CASE_CEILING_SECONDS = 60.0


def test_the_flag_rewrite_tries_only_the_dashes_near_a_keyword(monkeypatch: pytest.MonkeyPatch) -> None:
    """Counted, not timed: the costly pattern is tried only within 66 characters before a keyword that has a value."""
    from kube_noob.debug import cluster

    calls = []
    real = cluster._FLAG_SECRET

    class Counting:
        def match(self, text: str, pos: int = 0) -> Any:
            calls.append(pos)
            return real.match(text, pos)

    monkeypatch.setattr(cluster, "_FLAG_SECRET", Counting())
    redact_text(DASHES * 100)
    assert calls == [], "no keyword, no attempt"
    redact_text(DASHES + " --db-password hunter2")
    assert 1 <= len(calls) <= 67


def test_the_linear_flag_rewrite_rewrites_exactly_what_the_plain_substitution_did() -> None:
    import random

    from kube_noob.debug import cluster

    rng = random.Random(7)
    atoms = [
        "--",
        "-",
        " ",
        "\t",
        "=",
        ":",
        "password",
        "secret",
        "token",
        "api-key",
        "apikey",
        "db",
        "x",
        "hunter2",
        '"',
        ",",
        ";",
        "a.b",
        "PASSWORD",
        "Token",
        "--DB-PASSWORD",
        "-" * 70,
    ]
    for _ in range(4000):
        text = "".join(rng.choice(atoms) for _ in range(rng.randint(1, 14)))
        assert cluster._sub_flags(text) == cluster._FLAG_SECRET.sub(r"\1***", text), text


def test_redacting_a_long_run_of_dashes_stays_within_its_ceiling() -> None:
    started = time.perf_counter()
    for _ in range(1500):
        redact_text(DASHES)
    assert time.perf_counter() - started < REDACT_CEILING_SECONDS


def test_the_redactor_still_catches_every_flag_shape_after_the_pattern_change() -> None:
    for text, kept in (
        ("run --db-password=hunter2 now", "hunter2"),
        ("run --api-key abcdef123 now", "abcdef123"),
        ("cmd\t--client-secret s3cr3t-value", "s3cr3t-value"),
        ("x --token=t0k3nvalue y", "t0k3nvalue"),
        ("-password hunter2", "hunter2"),
        ("password: hunter2", "hunter2"),
    ):
        assert kept not in redact_text(text), text
    assert redact_text("--verbose --namespace=shop") == "--verbose --namespace=shop"


def test_the_reviewers_worst_case_payload_is_reported_in_full_within_its_ceiling(tmp_path: Path) -> None:
    started = time.perf_counter()
    body = _report(tmp_path, _worst_case(), alertReports={"budgetSeconds": 300})
    assert time.perf_counter() - started < WORST_CASE_CEILING_SECONDS
    assert body["summary"]["alerts"] == 150 and body["summary"]["byVerdict"]["not-evaluated"] == 0


def test_a_report_over_its_time_budget_returns_what_it_finished_and_counts_the_rest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ticks = iter(range(10_000))
    monkeypatch.setattr(alert_report, "_now", lambda: float(next(ticks)))
    alerts = [_alert("KubePodCrashLooping", namespace="shop", pod=f"web-{i}") for i in range(10)]
    body = alert_report.build(_payload(*alerts), _kit(tmp_path)._diagnose_alert, memory_configured=False, deadline=4.0)
    rows = body["alerts"]
    assert len(rows) == 10, "every alert keeps a row"
    cut = [a["index"] for a in rows if a["verdict"] == "not-evaluated"]
    assert cut and cut == list(range(cut[0], 10)) and cut[0] > 0
    assert body["summary"]["byVerdict"]["not-evaluated"] == len(cut)
    (gap,) = [n for n in body["notIncluded"] if n.get("what") == "alerts not evaluated"]
    assert gap["count"] == len(cut) and gap["indices"] == cut and "time budget" in gap["why"]
    text = alert_report.render_text(body)
    assert f"not included: {len(cut)} alerts not evaluated" in text and "time budget" in text


def test_the_time_budget_reaches_the_stored_record(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KUBE_NOOB_HTTP_TOKEN", TOKEN)
    ticks = iter(range(10_000))
    monkeypatch.setattr(alert_report, "_now", lambda: float(next(ticks)) * 10)
    with TestClient(http_app(_server(tmp_path, alertReports={"budgetSeconds": 5})), base_url="http://testserver") as c:
        out = _post(c).json()
        kept = c.get(f"/v1/alert-reports/{out['id']}", headers=AUTH).json()
    assert out["report"]["summary"]["byVerdict"]["not-evaluated"] >= 1
    assert kept["report"]["notIncluded"] == out["report"]["notIncluded"]


def test_reading_the_body_does_not_block_the_event_loop(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The JSON checks and the response rendering ran on the event loop, so one large post stalled /healthz."""
    from kube_noob import sanitize

    monkeypatch.setenv("KUBE_NOOB_HTTP_TOKEN", TOKEN)
    real = sanitize.json_nesting_ok

    def slow(text: Any, limit: int = sanitize.MAX_JSON_DEPTH) -> bool:
        time.sleep(1.5)
        return real(text, limit)

    monkeypatch.setattr(sanitize, "json_nesting_ok", slow)
    with TestClient(http_app(_server(tmp_path)), base_url="http://testserver") as c:
        worker = threading.Thread(target=lambda: _post(c))
        worker.start()
        time.sleep(0.3)
        started = time.perf_counter()
        assert c.get("/healthz").status_code == 200
        waited = time.perf_counter() - started
        worker.join()
    assert waited < 0.8, f"/healthz waited {waited:.2f}s behind a post"


def test_reports_are_built_a_bounded_number_at_a_time() -> None:
    from kube_noob.server import rest

    assert 1 <= rest.MAX_CONCURRENT_REPORTS <= 4


# --- 2. the chart: one store per pod -------------------------------------------------------------------------------


def test_the_chart_refuses_a_report_store_spread_over_several_pods() -> None:
    values = yaml.safe_load((CHART / "values.yaml").read_text(encoding="utf-8"))
    deployment = (CHART / "templates" / "deployment.yaml").read_text(encoding="utf-8")
    assert values["alertReports"]["store"] is False, "off by default, because the chart runs two replicas"
    assert values["replicaCount"] > 1
    block = deployment[deployment.index("{{- with .Values.alertReports }}") :]
    block = block[: block.index("{{- if .Values.rhacs.enabled }}")]
    assert "{{- if .store }}" in block and "{{- if gt (int $.Values.replicaCount) 1 }}" in block
    assert "alertReports.store keeps reports on one pod" in block


# --- 3. one unreadable alert does not sink the group ------------------------------------------------------------


def test_a_lone_surrogate_in_one_label_does_not_reject_the_group(tmp_path: Path) -> None:
    good = _alert("etcdHighNumberOfLeaderChanges", namespace="openshift-etcd")
    bad = '{"status":"firing","labels":{"alertname":"KubePodCrashLooping","pod":"\\ud800"}}'
    text = '{"alerts":[' + json.dumps(good) + "," + bad + "," + json.dumps(_alert("etcdMembersDown")) + "]}"
    body = _report(tmp_path, text)
    assert [a["alertname"] for a in body["alerts"]] == [
        "etcdHighNumberOfLeaderChanges",
        "KubePodCrashLooping",
        "etcdMembersDown",
    ]
    assert "\ud800" not in json.dumps(body, ensure_ascii=False)


def test_an_alert_whose_diagnosis_fails_is_counted_and_the_rest_are_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    kit = _kit(tmp_path)
    real = kit._diagnose_alert

    def flaky(text: str, version: str | None) -> dict[str, Any]:
        if "web-1" in text:
            raise ValueError("payload text that must not be echoed: SECRETISH")
        return real(text, version)

    monkeypatch.setattr(kit, "_diagnose_alert", flaky)
    alerts = [_alert("KubePodCrashLooping", namespace="shop", pod=f"web-{i}") for i in range(3)]
    body = kit.alert_report(AlertReportIn(payload=_payload(*alerts)))["report"]
    verdicts = [a["verdict"] for a in body["alerts"]]
    assert verdicts[1] == "not-evaluated" and verdicts[0] != "not-evaluated" and verdicts[2] != "not-evaluated"
    assert "SECRETISH" not in json.dumps(body)
    (gap,) = [n for n in body["notIncluded"] if n.get("what") == "alerts not evaluated"]
    assert gap["indices"] == [1] and "ValueError" in gap["why"]


# --- 4. truncation by severity and state, never by position -----------------------------------------------------


def test_the_size_cap_keeps_a_row_for_every_alert_and_the_most_severe_detail(tmp_path: Path) -> None:
    fill = dict.fromkeys(("namespace", "container", "service", "instance", "node", "job"), "x" * 250)
    trivial = [
        _alert("etcdHighFsyncDurations", severity="info", ann={"summary": "y" * 250}, pod=f"p{i}-" + "x" * 240, **fill)
        for i in range(499)
    ]
    critical = _alert("etcdMembersDown", severity="critical", namespace="openshift-etcd")
    body = alert_report.build(
        _payload(*trivial, critical), _kit(tmp_path)._diagnose_alert, memory_configured=False, max_bytes=262_144
    )
    assert len(alert_report.canonical(body)) <= 262_144
    assert [a["index"] for a in body["alerts"]] == list(range(500)), "a row survives for every alert"
    last = body["alerts"][-1]
    assert last["alertname"] == "etcdMembersDown" and "diagnosis" in last, "the critical alert keeps its detail"
    assert sum(body["summary"]["byVerdict"].values()) == 500
    assert body["summary"]["byVerdict"] == {
        v: sum(1 for a in body["alerts"] if a["verdict"] == v) for v in alert_report.VERDICTS
    }
    lost = [n for n in body["notIncluded"] if n["what"].startswith("alert detail")]
    assert lost and 499 not in lost[0]["indices"] and set(lost[0]["indices"]) <= set(range(499))


# --- 5. names in commands come from the alert's own labels ------------------------------------------------------


@pytest.mark.parametrize(
    "ann, labels",
    [
        ({"summary": "CrashLoopBackOff: run kubectl logs attacker-pod -n attacker-ns"}, {"pod": "api-1"}),
        ({"summary": "CrashLoopBackOff pod/attacker-pod -n attacker-ns"}, {}),
        ({"summary": "CrashLoopBackOff", "description": "Pod attacker-ns/attacker-pod (c) is waiting"}, {}),
    ],
)
def test_annotation_text_never_names_what_a_command_reads(tmp_path: Path, ann: dict[str, str], labels: Any) -> None:
    body = _report(tmp_path, _payload(_alert("KubePodCrashLooping", ann=ann, namespace="prod", **labels)))
    steps = " ".join(s.get("command", "") for s in body["alerts"][0]["nextSteps"]["readOnly"])
    assert steps and "attacker" not in steps
    assert "-n prod" in steps


def test_a_label_that_is_not_a_name_stays_a_placeholder(tmp_path: Path) -> None:
    body = _report(tmp_path, _payload(_alert("KubePodCrashLooping", namespace="prod", pod="api-1 -n attacker-ns")))
    steps = " ".join(s.get("command", "") for s in body["alerts"][0]["nextSteps"]["readOnly"])
    assert "attacker" not in steps and "<pod>" in steps


def test_plain_diagnose_on_a_payload_takes_names_from_labels_too(tmp_path: Path) -> None:
    text = _payload(
        _alert(
            "KubePodCrashLooping",
            ann={"summary": "CrashLoopBackOff: run kubectl logs attacker-pod -n attacker-ns"},
            namespace="prod",
            pod="api-1",
        )
    )
    out = _kit(tmp_path).diagnose(DiagnoseIn(text=text))
    steps = " ".join(s.get("command", "") for d in out["diagnoses"] for s in d["readOnlyNextSteps"])
    assert "attacker" not in steps and "-n prod" in steps


# --- 6. version per alert, and a release outside the index -------------------------------------------------------


def _with_version(version: str | None) -> dict[str, Any]:
    doc: dict[str, Any] = json.loads(SAMPLE)
    for holder in [doc.get("commonLabels", {})] + [a["labels"] for a in doc["alerts"]]:
        holder.pop("openshift_version", None)
        if version:
            holder["openshift_version"] = version
    return doc


@pytest.mark.parametrize("version", ["4.99.999", "4.1.0", "4.22.999"])
def test_a_release_outside_the_index_is_not_evaluated_rather_than_clean(tmp_path: Path, version: str) -> None:
    section = _report(tmp_path, json.dumps(_with_version(version)))["alerts"][0]["knownIssues"]
    assert section["status"] == "not-evaluated" and section["matches"] == []
    assert version in section["note"] and "4.20" in section["note"]


def test_each_alert_is_narrowed_to_its_own_version(tmp_path: Path) -> None:
    doc = _with_version(None)
    doc.pop("commonLabels", None)
    doc["alerts"][0]["labels"]["openshift_version"] = "4.99.0"
    doc["alerts"][1]["labels"]["openshift_version"] = "4.21.0"
    for order in (doc["alerts"], list(reversed(doc["alerts"]))):
        body = _report(tmp_path, json.dumps({**doc, "alerts": order}))
        by_name = {a["alertname"]: a["knownIssues"] for a in body["alerts"]}
        assert by_name["etcdHighNumberOfLeaderChanges"]["status"] == "not-evaluated"
        assert [m["id"] for m in by_name["etcdHighFsyncDurations"]["matches"]] == ["OCPBUGS-73881"]


def test_an_alerts_own_label_beats_common_labels(tmp_path: Path) -> None:
    """Alertmanager's commonLabels are the labels every alert of the group shares, so they cannot disagree with an
    alert -- a hand-made payload can. The alert's own label is the more specific claim."""
    doc = _with_version("4.21.0")
    doc["commonLabels"]["openshift_version"] = "4.99.0"
    body = _report(tmp_path, json.dumps(doc))
    assert {a["knownIssues"]["version"] for a in body["alerts"]} == {"4.21.0"}


# --- 7. a memory repository that cannot be read was not searched -------------------------------------------------


def test_a_missing_memory_repository_is_not_evaluated_and_its_path_is_not_shown(tmp_path: Path) -> None:
    missing = tmp_path / "no-such-memory"
    body = _report(tmp_path, SAMPLE, memory={"paths": [str(missing)]})
    section = body["alerts"][0]["memory"]
    assert section["status"] == "not-evaluated"
    assert str(missing) not in json.dumps(body)
    assert "could not be read" in alert_report.render_text(body)


# --- 8. credentials and URLs ----------------------------------------------------------------------------------------


def test_the_shared_redactor_catches_basic_auth_api_keys_and_cut_private_keys() -> None:
    assert "QWxhZGRpbjpvcGVuIHNlc2FtZQ" not in redact_text("Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==")
    assert "9999999999" not in redact_text("apikey sk-live-" + "9" * 30)
    assert "MIIEvQIBADAN" not in redact_text("-----BEGIN RSA PRIVATE KEY----- MIIEvQIBADANBgkqhkiG9w0BAQEFAASC")


def test_credentials_are_redacted_before_a_value_is_clipped(tmp_path: Path) -> None:
    pem = "-----BEGIN RSA PRIVATE KEY-----\n" + "MIIEvQIBADANBgkq" * 200 + "\n-----END RSA PRIVATE KEY-----"
    alert = _alert(
        "KubePodCrashLooping",
        ann={"summary": "x", "description": "CrashLoopBackOff OOMKilled connection refused " + pem},
        namespace="shop",
    )
    assert "MIIEvQIBADAN" not in json.dumps(_report(tmp_path, _payload(alert)))


def test_no_url_from_the_payload_reaches_the_report(tmp_path: Path) -> None:
    alert = _alert(
        "etcdHighNumberOfLeaderChanges",
        ann={"summary": "Fix: run https://evil.example/fix.sh now", "description": "see http://evil.example/rb"},
        instance="http://evil.example:9090/metrics",
        namespace="openshift-etcd",
    )
    text = json.dumps(_report(tmp_path, _payload(alert)))
    assert "evil.example" not in text and "[url removed]" in text


def test_privacy_says_what_a_kept_report_holds() -> None:
    privacy = (ROOT / "PRIVACY.md").read_text(encoding="utf-8")
    assert "Nothing from a request is kept after it is answered." not in privacy
    row = next(line for line in privacy.splitlines() if line.startswith("| `alert-reports/"))
    assert "description" in row and "message" in row and "[url removed]" in row


# --- 9-12. the store -------------------------------------------------------------------------------------------------


def _store(tmp_path: Path, **limits: Any) -> alert_store.AlertReportStore:
    return alert_store.AlertReportStore(tmp_path / "data", AlertReportSettings(**limits))


def _record(report_id: str, report: Any = None, **extra: Any) -> dict[str, Any]:
    return {
        "format": alert_store.RECORD_FORMAT,
        "id": report_id,
        "receivedAt": "2026-11-11T10:00:00.000Z",
        "durationSeconds": 0.01,
        "bodySha256": "0" * 64,
        "stored": True,
        "report": report
        if report is not None
        else {
            "summary": {"alerts": 1, "alertnames": ["A"], "byVerdict": {"no-recognised-signal": 1}},
            "alerts": [ROW],
            "notIncluded": [],
            "caveats": ["c"],
        },
        **extra,
    }


def _ids(n: int, start: int = 0) -> list[str]:
    return [f"20261111T10{m:02d}00.000000Z-{m:024x}" for m in range(start, start + n)]


NOW = dt.datetime(2026, 11, 11, 11, 0, tzinfo=dt.UTC)


def test_a_directory_with_a_reports_name_does_not_stop_retention(tmp_path: Path) -> None:
    store = _store(tmp_path, max_reports=3)
    root = tmp_path / "data" / "alert-reports"
    root.mkdir(parents=True, mode=0o700)
    (root / "20200101T000000.000000Z-000000000000000000000000.json").mkdir()
    results = [store.save(_record(rid), NOW) for rid in _ids(5)]
    # Second review: the planted directory is no report, so retention neither counts it nor tries to remove it.
    assert all(r.not_removed == 0 for r in results)
    reports = [n for n in os.listdir(root) if n.endswith(".summary.json")]
    assert len(reports) == 3
    assert store.newest(10)["total"] == 3


def test_a_temporary_file_left_by_a_killed_write_is_collected(tmp_path: Path) -> None:
    store = _store(tmp_path)
    (first,) = _ids(1)
    store.save(_record(first), NOW)
    stale = tmp_path / "data" / "alert-reports" / f".{first}-deadbeef.tmp"
    stale.write_bytes(b"x")
    os.utime(stale, (time.time() - 10 * 86400,) * 2)
    assert alert_store._TEMP.match(stale.name)
    store.save(_record(_ids(1, 1)[0]), NOW)
    assert not stale.exists()


def test_the_report_just_written_is_never_the_one_retention_removes(tmp_path: Path) -> None:
    store = _store(tmp_path, max_reports=2)
    for k in range(2):
        store.save(_record(f"20990101T00000{k}.000000Z-" + "a" * 24), NOW)
    (now_id,) = _ids(1)
    result = store.save(_record(now_id), NOW)
    assert store.get(now_id)["id"] == now_id and result.evicted == 1


@pytest.mark.parametrize(
    "tamper",
    [
        {"durationSeconds": "x"},
        {"report": "a string"},
        {"report": {"alerts": ["str", 5], "summary": [1], "caveats": 7, "notIncluded": "zz"}},
        {"receivedAt": 5},
        {"stored": "yes"},
        {
            "report": {
                "summary": {"alerts": 1, "alertnames": ["A"], "byVerdict": {"diagnosed": 1}},
                "alerts": [],
                "notIncluded": [],
                "caveats": ["c"],
            }
        },
    ],
)
def test_a_stored_record_of_the_wrong_shape_is_refused_not_passed_through(
    tmp_path: Path, tamper: dict[str, Any], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from kube_noob.cli import main

    store = _store(tmp_path)
    (rid,) = _ids(1)
    store.save(_record(rid, _report(tmp_path, SAMPLE)), NOW)
    path = tmp_path / "data" / "alert-reports" / f"{rid}.json"
    path.write_text(json.dumps({**json.loads(path.read_text(encoding="utf-8")), **tamper}), encoding="utf-8")
    with pytest.raises(alert_store.StoreUnavailable):
        store.get(rid)
    monkeypatch.setenv("KUBE_NOOB_DATA_DIR", str(tmp_path / "data"))
    assert main(["alerts", "show", rid]) == 4
    assert "Traceback" not in capsys.readouterr().err


@pytest.mark.parametrize("summary", [{"alertnames": 5}, {"alerts": "5\x1b[2J"}, {"receivedAt": ["x"]}])
def test_a_summary_of_the_wrong_shape_is_listed_as_unreadable(
    tmp_path: Path, summary: dict[str, Any], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from kube_noob.cli import main

    store = _store(tmp_path)
    (rid,) = _ids(1)
    store.save(_record(rid), NOW)
    (tmp_path / "data" / "alert-reports" / f"{rid}.summary.json").write_text(
        json.dumps({"id": rid, **summary}), encoding="utf-8"
    )
    (row,) = store.newest(5)["reports"]
    assert row == {"id": rid, "unreadable": row["unreadable"]}
    monkeypatch.setenv("KUBE_NOOB_DATA_DIR", str(tmp_path / "data"))
    assert main(["alerts", "list"]) == 0
    assert "unreadable" in capsys.readouterr().out


def test_a_damaged_stored_report_is_a_server_error_not_refused_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("KUBE_NOOB_HTTP_TOKEN", TOKEN)
    store = _store(tmp_path)
    (rid,) = _ids(1)
    store.save(_record(rid, report="a string"), NOW)
    with TestClient(http_app(_server(tmp_path)), base_url="http://testserver") as c:
        got = c.get(f"/v1/alert-reports/{rid}", headers=AUTH)
    assert got.status_code == 500 and "not an alert report" in got.json()["error"]


# --- 13. read paths do not write -------------------------------------------------------------------------------------


def test_listing_and_reading_do_not_change_the_directory(tmp_path: Path) -> None:
    store = _store(tmp_path)
    (rid,) = _ids(1)
    store.save(_record(rid), NOW)
    root = tmp_path / "data" / "alert-reports"
    os.chmod(root, 0o750)  # noqa: S103 - looser than the store sets, to see that reading keeps it
    store.newest(5)
    store.get(rid)
    assert stat.S_IMODE(root.stat().st_mode) == 0o750


def test_the_contract_says_which_tools_write_the_learning_file() -> None:
    import importlib.util
    import sys

    spec = importlib.util.spec_from_file_location("safety_contract", ROOT / "scripts" / "safety_contract.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["safety_contract"] = mod
    spec.loader.exec_module(mod)
    why = mod.LOCAL_STATE_SWITCHES["learningEnabled"]
    assert "not read-only" not in why or "read-only tools" in why
    assert "counter" in why


# --- 14. every default-on setting is reviewed --------------------------------------------------------------------


def test_an_unreviewed_default_on_setting_fails_the_contract() -> None:
    import importlib.util
    import sys

    spec = importlib.util.spec_from_file_location("safety_contract", ROOT / "scripts" / "safety_contract.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["safety_contract"] = mod
    spec.loader.exec_module(mod)
    assert mod.default_violations() == []
    reviewed = dict(mod.DEFAULT_ON)
    reviewed.pop("mustGather.enabled")
    assert any("mustGather.enabled" in p for p in mod.default_violations(reviewed=reviewed))
    stale = {**mod.DEFAULT_ON, "noSuch.setting": ("local state", "gone")}
    assert any("noSuch.setting" in p for p in mod.default_violations(reviewed=stale))
    groups = {d.key: d.group for d in mod.defaults()}
    assert groups["mustGather.enabled"] != "opt-in feature"


# --- 15. the smaller mismatches ------------------------------------------------------------------------------------


def test_the_refusal_states_the_limits_that_actually_apply(tmp_path: Path) -> None:
    with pytest.raises(ValueError) as exc:
        _report(tmp_path, '{"hello": "world"}')
    assert "2,000,000 characters" in str(exc.value) and "1.5 MiB" in str(exc.value)


def test_the_receivers_answer_and_every_guard_status_are_documented() -> None:
    from kube_noob.server import rest

    doc = rest.full_document()
    post = doc["paths"]["/v1/alert-reports"]["post"]
    assert "receivedAt" in post["responses"]["200"]["description"]
    for path, ops in doc["paths"].items():
        for op in ops.values():
            assert {"403", "405", "421"} <= set(op["responses"]), path


def test_a_method_not_served_names_every_method_that_is(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KUBE_NOOB_HTTP_TOKEN", TOKEN)
    with TestClient(http_app(_server(tmp_path)), base_url="http://testserver") as c:
        r = c.put("/v1/alert-reports", headers=AUTH)
    assert r.status_code == 405
    assert {m.strip() for m in r.headers["allow"].split(",")} >= {"GET", "POST"}


@pytest.mark.parametrize("bad", ["2٠261111T100000.000000Z-" + "a" * 24, "20261111T100000.00000٠Z-" + "a" * 24])
def test_an_id_with_non_ascii_digits_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad: str) -> None:
    assert not alert_store.valid_id(bad)
    monkeypatch.setenv("KUBE_NOOB_HTTP_TOKEN", TOKEN)
    with TestClient(http_app(_server(tmp_path)), base_url="http://testserver") as c:
        assert c.get(f"/v1/alert-reports/{bad}", headers=AUTH).status_code == 400


def test_the_chart_counts_the_whole_record_and_checks_the_volume_it_writes_to() -> None:
    deployment = (CHART / "templates" / "deployment.yaml").read_text(encoding="utf-8")
    schema = json.loads((CHART / "values.schema.json").read_text(encoding="utf-8"))["properties"]["alertReports"]
    assert set(schema["required"]) == {"store", "maxReports", "maxAgeDays", "maxReportBytes", "budgetSeconds"}
    assert "32768" in deployment, "each report is its body plus the receipt allowance and its summary"
    assert "persistence.size" in deployment


def test_operations_states_alertmanagers_retry_rule_as_its_source_does() -> None:
    ops = (ROOT / "docs" / "operations.md").read_text(encoding="utf-8")
    assert "413 and Alertmanager retries it" not in ops
    assert "4xx" in ops and "notify/util.go" in ops


# --- neighbours of the reviewed shapes (class 21) --------------------------------------------------------------------


def test_a_fifo_at_a_reports_name_is_refused_without_blocking(tmp_path: Path) -> None:
    store = _store(tmp_path)
    (rid,) = _ids(1)
    store.save(_record(rid), NOW)
    root = tmp_path / "data" / "alert-reports"
    for name in (f"{rid}.json", f"{rid}.summary.json"):
        (root / name).unlink()
        os.mkfifo(root / name)
    done: list[Any] = []

    def read() -> None:
        try:
            store.get(rid)
        except alert_store.StoreUnavailable as exc:
            done.append(exc)
        done.append(store.newest(5))

    worker = threading.Thread(target=read, daemon=True)
    worker.start()
    worker.join(5)
    assert not worker.is_alive(), "opening a FIFO for reading blocked until a writer came"
    # Second review: a FIFO is not a report, so the list counts it as ignored instead of showing it unreadable forever.
    assert isinstance(done[0], alert_store.StoreUnavailable)
    assert done[1]["reports"] == [] and done[1]["ignored"] == 2


@pytest.mark.parametrize(
    "row",
    [
        {"index": "0", "alertname": "A", "state": "firing", "verdict": "diagnosed"},
        {"index": 0, "alertname": 5, "state": "firing", "verdict": "diagnosed"},
        {"index": 0, "alertname": "A", "state": "firing", "verdict": "healthy"},
    ],
)
def test_a_row_of_the_wrong_shape_inside_a_stored_record_is_refused(tmp_path: Path, row: dict[str, Any]) -> None:
    store = _store(tmp_path)
    (rid,) = _ids(1)
    report = {
        "summary": {"alerts": 1, "alertnames": ["A"], "byVerdict": {"diagnosed": 1}},
        "alerts": [row],
        "notIncluded": [],
        "caveats": ["c"],
    }
    store.save(_record(rid, report), NOW)
    with pytest.raises(alert_store.StoreUnavailable):
        store.get(rid)


def test_odd_section_types_in_a_row_never_crash_the_text_view() -> None:
    body = {
        "summary": {"alerts": 1, "byVerdict": {"diagnosed": 1}, "versions": "4.21"},
        "notIncluded": [{"count": 1, "indices": "zz"}, "x"],
        "caveats": "c",
        "alerts": [
            {
                "index": 0,
                "alertname": "A",
                "state": "firing",
                "verdict": "diagnosed",
                "labels": ["x"],
                "signals": 5,
                "diagnosis": {"playbooks": "x", "note": 3},
                "knownIssues": {"matches": [5, "y"]},
                "memory": {"matches": None, "notes": "n"},
                "nextSteps": {"readOnly": [5, {"command": 7}]},
            },
            "not a row",
        ],
    }
    text = alert_report.render_text(body, {"stored": "yes", "durationSeconds": "x"})
    assert "[0] A firing" in text


@pytest.mark.parametrize("where", ["summary", "alertname", "commonLabels"])
def test_a_lone_surrogate_anywhere_in_an_alert_is_dropped(tmp_path: Path, where: str) -> None:
    alert = {"status": "firing", "labels": {"alertname": "KubePodCrashLooping"}, "annotations": {"summary": "s"}}
    text = json.dumps({"alerts": [alert], "commonLabels": {"namespace": "prod"}})
    marker = {"summary": '"summary": "s"', "alertname": '"KubePodCrashLooping"', "commonLabels": '"prod"'}[where]
    text = text.replace(marker, marker[:-1] + '\\ud800"')
    # A second, ordinary alert: with only the damaged one, an alertname that is not a name leaves no payload at all.
    doc = json.loads(text)
    doc["alerts"].append(_alert("etcdMembersDown"))
    body = _report(tmp_path, json.dumps(doc))
    assert body["summary"]["alerts"] == 2
    assert "\ud800" not in json.dumps(body, ensure_ascii=False)


@pytest.mark.parametrize(
    "url",
    ["HTTPS://evil.example/x", "ftp://evil.example/x", "s3://bucket-x/key", "http://[::1]:9/x"],
)
def test_every_scheme_url_shape_is_removed(tmp_path: Path, url: str) -> None:
    alert = _alert("KubePodCrashLooping", ann={"summary": f"see {url} now"}, namespace="shop")
    text = json.dumps(_report(tmp_path, _payload(alert)))
    assert url not in text and "[url removed]" in text
