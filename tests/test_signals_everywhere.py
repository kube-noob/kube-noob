"""Signals everywhere: diagnose, debug, bundle and policy explain show the signals they read and use them to rank
playbooks; diagnose takes an Alertmanager webhook payload as it is; MCP offers `extract_signals` (read-only)."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from kube_noob import toolkit as tk
from kube_noob.cli import main
from kube_noob.config import load_settings
from kube_noob.debug.diagnose import bundle_markdown, debug_workload, diagnose
from kube_noob.debug.playbooks import PLAYBOOKS
from kube_noob.debug.policy import explain
from kube_noob.signals import Signal, alertmanager
from kube_noob.signals.catalogue import entries

FIXTURES = Path(__file__).parent / "fixtures"
PAYLOAD = (FIXTURES / "alertmanager-etcd.json").read_text(encoding="utf-8")
KYVERNO = """Error from server: error when creating "deploy.yaml": admission webhook "validate.kyverno.svc-fail" \
denied the request:

resource Deployment/shop/orders-api was blocked due to the following policies

require-labels:
  check-team: 'validation error: The label `team` is required. rule check-team failed at path /metadata/labels/team/'
"""


def _kit(tmp_path: Path) -> tk.Toolkit:
    return tk.Toolkit(load_settings(overrides={"dataDir": str(tmp_path)}))


def _payload(**changes: Any) -> dict[str, Any]:
    doc: dict[str, Any] = json.loads(PAYLOAD)
    doc.update(changes)
    return doc


# ----------------------------------------------------------------------------- the accept test


def test_an_etcd_alert_payload_ranks_the_etcd_playbook_first_with_known_issues_for_its_version(
    tmp_path: Path,
) -> None:
    out = _kit(tmp_path).diagnose(tk.DiagnoseIn(text=PAYLOAD))
    assert out["diagnoses"][0]["id"] == "DBG-ETCD"
    assert "signal alert etcdHighNumberOfLeaderChanges" in out["diagnoses"][0]["evidence"]
    assert out["input"] == {
        "kind": "alertmanager",
        "alerts": 2,
        "firing": 2,
        "alertnames": ["etcdHighFsyncDurations", "etcdHighNumberOfLeaderChanges"],
        "version": "4.21.0",
        "versionFrom": "label openshift_version",
    }
    assert [m["id"] for m in out["knownIssues"]][:1] == ["OCPBUGS-73881"]
    names = {(s["kind"], s["name"]) for s in out["signals"]}
    assert {("alert", "etcdHighNumberOfLeaderChanges"), ("alert", "etcdHighFsyncDurations"), ("component", "etcd")} <= (
        names
    )
    assert out["diagnoses"][0]["readOnlyNextSteps"][0]["command"].startswith("oc get co etcd")


def test_an_explicit_version_wins_over_the_label_and_a_fixed_version_has_no_known_issue(tmp_path: Path) -> None:
    kit = _kit(tmp_path)
    fixed = kit.diagnose(tk.DiagnoseIn(text=PAYLOAD, version="4.21.2"))
    assert fixed["input"]["version"] == "4.21.2" and fixed["input"]["versionFrom"] == "argument"
    assert fixed["knownIssues"] == [] and fixed["diagnoses"][0]["id"] == "DBG-ETCD"
    no_label = json.loads(PAYLOAD)
    for alert in no_label["alerts"]:
        alert["labels"].pop("openshift_version")
    no_label["commonLabels"].pop("openshift_version")
    out = kit.diagnose(tk.DiagnoseIn(text=json.dumps(no_label)))
    assert out["input"]["version"] is None and "versionFrom" not in out["input"]


def test_the_cli_diagnoses_a_payload_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    f = tmp_path / "alert.json"
    f.write_text(PAYLOAD, encoding="utf-8")
    assert main(["diagnose", "-f", str(f), "--format", "json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["diagnoses"][0]["id"] == "DBG-ETCD" and out["input"]["kind"] == "alertmanager"
    assert main(["signals", "-f", str(f)]) == 0
    text = capsys.readouterr().out
    assert "alert           etcdHighNumberOfLeaderChanges" in text


# ----------------------------------------------------------------------------- the payload reader


def test_payload_reader_reads_webhook_and_api_shapes() -> None:
    p = alertmanager.parse(PAYLOAD)
    assert p is not None and p.alerts == 2 and p.firing == 2 and p.version == "4.21.0"
    assert "alert etcdHighNumberOfLeaderChanges firing, severity warning, namespace openshift-etcd" in p.text
    assert "pod/etcd-master-0.example.test" in p.text
    assert "summary: etcd cluster has high number of leader changes." in p.text
    api = [
        {
            "labels": {"alertname": "KubePodCrashLooping", "namespace": "shop", "pod": "web-1"},
            "annotations": {"description": "Pod shop/web-1 (web) is in waiting state (reason: CrashLoopBackOff)."},
            "status": {"state": "active"},
        }
    ]
    q = alertmanager.parse(json.dumps(api))
    assert q is not None and q.alerts == 1 and q.firing == 1 and "alert KubePodCrashLooping firing" in q.text
    resolved = _payload(alerts=[{**_payload()["alerts"][0], "status": "resolved"}])
    r = alertmanager.parse(json.dumps(resolved))
    assert r is not None and r.firing == 0 and "alert etcdHighNumberOfLeaderChanges resolved" in r.text


@pytest.mark.parametrize(
    "text",
    [
        "etcd leader changed frequently",
        '{"alerts": "nope"}',
        '{"items": []}',
        "[1, 2, 3]",
        PAYLOAD[: len(PAYLOAD) // 2],
        "[" * 100_000 + "]" * 100_000,
        '{"alerts": [' + ",".join(['{"labels": {"alertname": 1}}'] * 10) + "]}",
    ],
)
def test_payload_reader_returns_none_for_anything_else(text: str) -> None:
    assert alertmanager.parse(text) is None


def test_payload_reader_is_bounded_and_strips_control_characters() -> None:
    alert = {
        "status": "firing",
        "labels": {
            "alertname": "TargetDown",
            "namespace": "shop\x1b[2J",
            "x" * 300: "y",
            **{f"l{i}": "v" for i in range(70)},
        },
        "annotations": {"description": "boom \x00\x07 " + "d" * 2_050},
    }
    raw = json.dumps({"alerts": [alert] * 560})
    assert len(raw) < alertmanager.MAX_PAYLOAD
    p = alertmanager.parse(raw)
    assert p is not None and p.alerts == alertmanager.MAX_ALERTS
    assert alertmanager.parse(" " + "x" * alertmanager.MAX_PAYLOAD) is None
    small = alertmanager.compact(raw, limit=50_000)
    assert small is not None and len(small) <= 50_000
    again = alertmanager.parse(small)
    assert again is not None and 1 <= again.alerts < 500 and "alert TargetDown firing" in again.text
    assert "\x1b" not in p.text and "\x00" not in p.text
    assert max(len(line) for line in p.text.splitlines()) <= alertmanager.MAX_VALUE + 40
    assert len(p.text) <= alertmanager.MAX_TEXT


@pytest.mark.parametrize(
    ("labels", "version", "source"),
    [
        ({"openshift_version": "4.20.5", "version": "4.21.0"}, "4.20.5", "label openshift_version"),
        ({"version": "4.21.0"}, "4.21.0", "label version"),
        ({"version": "1.2.3"}, None, None),
        ({"version": "4.21.0; rm -rf /"}, None, None),
        ({"openshift_version": "v4.21.0"}, None, None),
        ({}, None, None),
    ],
)
def test_only_an_openshift_release_label_sets_the_version(
    labels: dict[str, str], version: str | None, source: str | None
) -> None:
    doc = {"alerts": [{"labels": {"alertname": "etcdNoLeader", **labels}, "status": "firing"}]}
    p = alertmanager.parse(json.dumps(doc))
    assert p is not None and p.version == version and p.version_from == source


# ----------------------------------------------------------------------------- ranking and display


def test_a_signal_alone_puts_its_playbook_on_the_list() -> None:
    out = diagnose("something is wrong with the control plane", signals=[Signal("alert", "etcdNoLeader", "", "test")])
    assert [d.playbook.pid for d in out.diagnoses] == ["DBG-ETCD"]
    assert out.diagnoses[0].evidence == ["signal alert etcdNoLeader"]
    assert diagnose("something is wrong with the control plane").diagnoses == []


def test_signals_break_ties_between_playbooks_with_the_same_text_evidence() -> None:
    text = "Back-off restarting failed container web\nLast State: Terminated Reason: OOMKilled Exit Code: 137"
    plain = {d.playbook.pid: d.score for d in diagnose(text, signals=[]).diagnoses}
    boosted = diagnose(text)
    scores = {d.playbook.pid: d.score for d in boosted.diagnoses}
    assert boosted.diagnoses[0].playbook.pid == "DBG-OOM"
    assert scores["DBG-OOM"] > plain["DBG-OOM"]
    assert ("pod_reason", "OOMKilled") in {(s.kind, s.name) for s in boosted.signals}


def test_diagnose_lists_its_signals_and_stays_fast_on_hostile_text(tmp_path: Path) -> None:
    out = _kit(tmp_path).diagnose(tk.DiagnoseIn(text="etcdserver: leader changed\nmvcc: database space exceeded"))
    assert out["diagnoses"][0]["id"] == "DBG-ETCD"
    alerts = [s["name"] for s in out["signals"] if s["kind"] == "alert"]
    assert alerts == ["etcdDatabaseQuotaLowSpace", "etcdHighNumberOfLeaderChanges"]
    assert out["signals"][0]["kind"] == "alert"
    assert "input" not in out
    t = time.perf_counter()
    for text in ("leader changed " * 25_000, "a-" * 199_000, "{" * 399_000, "\x1b[2J" * 99_000):
        _kit(tmp_path).diagnose(tk.DiagnoseIn(text=text))
    assert time.perf_counter() - t < 30  # linear work on 4 x 400 KB; CI runs it under coverage on slower CPUs


def test_every_catalogued_playbook_exists_and_etcd_alerts_point_at_the_etcd_playbook() -> None:
    pids = {p.pid for p in PLAYBOOKS}
    for e in entries():
        assert set(e.playbooks) <= pids, e.id
        if e.kind == "alert" and e.name.startswith("etcd"):
            assert "DBG-ETCD" in e.playbooks, e.id


def test_the_etcd_playbook_is_read_only_first_and_kubernetes_gets_kubectl() -> None:
    ocp = diagnose("etcdserver: request timed out\netcdHighFsyncDurations", platform="openshift").as_dict()
    d = ocp["diagnoses"][0]
    assert d["id"] == "DBG-ETCD" and len(d["readOnlyNextSteps"]) >= 3
    assert any("etcdctl endpoint status" in c["command"] for c in d["diagnosticCommands"])
    assert all(c["requiresApproval"] for c in d["diagnosticCommands"])
    k8s = diagnose("etcdserver: request timed out", platform="kubernetes").as_dict()["diagnoses"][0]
    commands = [s["command"] for s in k8s["readOnlyNextSteps"] if "command" in s]
    assert commands and all(c.startswith("kubectl ") for c in commands)
    assert not any("openshift-etcd" in c for c in commands)
    assert any("component=etcd" in c for c in commands)
    assert diagnose("etcdNoLeader", platform="rosa-hcp").diagnoses == []


def test_policy_explain_shows_admission_signals(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    out = explain(KYVERNO)
    assert out["signals"] == [{"kind": "admission", "name": "kyverno:require-labels/check-team", "source": "denial[0]"}]
    assert explain("all good")["signals"] == []
    f = tmp_path / "denied.txt"
    f.write_text(KYVERNO, encoding="utf-8")
    assert main(["policy", "explain", "-f", str(f)]) == 0
    assert "signals: admission kyverno:require-labels/check-team" in capsys.readouterr().out


class _Cluster:
    name = "fake"

    def version(self) -> dict[str, Any]:
        return {"serverVersion": {"gitVersion": "v1.34.2"}}

    def get(self, resource: str, name: str | None = None, **_: Any) -> dict[str, Any]:
        if resource == "deployments":
            return {"metadata": {"name": "api"}, "spec": {"selector": {"matchLabels": {"app": "api"}}}, "status": {}}
        if resource == "pods":
            pod = {
                "metadata": {"name": "api-1", "namespace": "shop"},  # the API server always sends it (D9)
                "spec": {"nodeName": "w1"},
                "status": {
                    "phase": "Running",
                    "containerStatuses": [
                        {
                            "name": "api",
                            "restartCount": 3,
                            "state": {"waiting": {"reason": "CrashLoopBackOff"}},
                            "lastState": {"terminated": {"reason": "OOMKilled", "exitCode": 137}},
                        }
                    ],
                },
            }
            return {"items": [pod]}
        if resource == "events":
            return {"items": []}
        from kube_noob.errors import ClusterAccessError

        raise ClusterAccessError(f"no {resource}")

    def logs(self, *_: Any, **__: Any) -> str:
        return "starting"


def test_debug_and_bundle_show_signals() -> None:
    out = debug_workload(_Cluster(), "shop", "deployment", "api")
    assert out["diagnoses"][0]["id"] == "DBG-OOM"
    assert ("pod_reason", "OOMKilled") in {(s["kind"], s["name"]) for s in out["signals"]}
    md = bundle_markdown(out)
    assert "## Signals" in md and "- pod_reason OOMKilled" in md
    assert md.index("## Signals") < md.index("## DBG-OOM")


# ----------------------------------------------------------------------------- MCP


def test_extract_signals_tool_is_read_only_strict_and_explains_what_it_found(tmp_path: Path) -> None:
    kit = _kit(tmp_path)
    spec = next(s for s in kit.specs() if s.name == "extract_signals")
    assert spec.read_only and spec.tier is None
    with pytest.raises(ValidationError):
        tk.SignalsIn.model_validate({"text": "x", "extra": 1})
    with pytest.raises(ValidationError):
        tk.SignalsIn.model_validate({"text": "x" * 400_001})
    out = kit.extract_signals(tk.SignalsIn(text=PAYLOAD))
    assert out["input"]["kind"] == "alertmanager" and out["input"]["version"] == "4.21.0"
    assert ("alert", "etcdHighNumberOfLeaderChanges") in {(s["kind"], s["name"]) for s in out["signals"]}
    cat = {c["id"]: c for c in out["catalogue"]}
    assert cat["alert:etcdHighNumberOfLeaderChanges"]["playbooks"] == ["DBG-ETCD"]
    assert all(src.startswith("https://") for c in out["catalogue"] for src in c["sources"])
    prose = kit.extract_signals(tk.SignalsIn(text="etcd leader changed frequently after the update"))
    assert prose["signals"] == [] or all(s["kind"] != "alert" for s in prose["signals"])
    assert [s["name"] for s in prose["implied"]] == ["etcdHighNumberOfLeaderChanges"]
    assert prose["implied"][0]["detail"] == "leader changed"
    assert out["playbooks"][0] == "DBG-ETCD"
