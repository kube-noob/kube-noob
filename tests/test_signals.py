"""Signal extraction: canonical names from alerts, events, ClusterOperators, pod status and free text."""

from __future__ import annotations

import dataclasses
import json
import random

import pytest

from kube_noob.signals import Signal, extract, normalise_error
from kube_noob.signals import core as ex
from tests import bounds

#: Measured: one hostile 300 KB paste through extract. Re-measure with KUBE_NOOB_TEST_BOUNDS_REPORT=1 (tests/bounds.py).
HONEST_HOSTILE_EXTRACT = 0.28


def names(signals: list[Signal], kind: str) -> list[str]:
    return [s.name for s in signals if s.kind == kind]


# Shape from the Alertmanager webhook documentation (version 4).
ALERTMANAGER = {
    "version": "4",
    "groupKey": '{}:{alertname="etcdHighNumberOfLeaderChanges"}',
    "truncatedAlerts": 0,
    "status": "firing",
    "receiver": "kube-noob",
    "groupLabels": {"alertname": "etcdHighNumberOfLeaderChanges"},
    "commonLabels": {"alertname": "etcdHighNumberOfLeaderChanges", "job": "etcd", "severity": "warning"},
    "commonAnnotations": {},
    "externalURL": "https://alertmanager.example",
    "alerts": [
        {
            "status": "firing",
            "labels": {"alertname": "etcdHighNumberOfLeaderChanges", "job": "etcd", "pod": "etcd-master-0"},
            "annotations": {
                "description": 'etcd cluster "etcd": 4 leader changes within the last 15 minutes.',
                "summary": "etcd cluster has high number of leader changes.",
            },
            "startsAt": "2026-10-28T10:00:00Z",
            "endsAt": "0001-01-01T00:00:00Z",
            "generatorURL": "https://prometheus.example/graph",
            "fingerprint": "6f0c1a2b3c4d5e6f",
        },
        {
            "status": "firing",
            "labels": {"alertname": "KubeAPIErrorBudgetBurn", "job": "apiserver"},
            "annotations": {"description": "The API server is burning too much error budget."},
            "startsAt": "2026-10-28T10:01:00Z",
            "endsAt": "0001-01-01T00:00:00Z",
            "generatorURL": "https://prometheus.example/graph",
            "fingerprint": "7a8b9c0d1e2f3a4b",
        },
    ],
}

EVENTS_JSON = {
    "apiVersion": "v1",
    "kind": "List",
    "items": [
        {
            "apiVersion": "v1",
            "kind": "Event",
            "type": "Warning",
            "reason": "FailedScheduling",
            "message": "0/6 nodes are available: 3 Insufficient memory, 3 node(s) had untolerated taint.",
            "involvedObject": {"kind": "Pod", "name": "web-7d4b9c8f6d-x2k9p", "namespace": "shop"},
        },
        {
            "apiVersion": "v1",
            "kind": "Event",
            "type": "Warning",
            "reason": "BackOff",
            "message": "Back-off restarting failed container web in pod web-7d4b9c8f6d-x2k9p_shop(1f2e)",
            "involvedObject": {"kind": "Pod", "name": "web-7d4b9c8f6d-x2k9p", "namespace": "shop"},
        },
        {
            "apiVersion": "v1",
            "kind": "Event",
            "type": "Normal",
            "reason": "Pulled",
            "message": "Successfully pulled image",
            "involvedObject": {"kind": "Pod", "name": "web-7d4b9c8f6d-x2k9p", "namespace": "shop"},
        },
    ],
}

EVENTS_V1 = {
    "apiVersion": "events.k8s.io/v1",
    "kind": "Event",
    "type": "Warning",
    "reason": "FailedMount",
    "note": 'MountVolume.SetUp failed for volume "data" : secret "db-creds" not found',
    "regarding": {"kind": "Pod", "name": "db-0", "namespace": "shop"},
}

CLUSTER_OPERATOR_YAML = """
apiVersion: config.openshift.io/v1
kind: ClusterOperator
metadata:
  name: authentication
status:
  conditions:
  - type: Degraded
    status: "True"
    reason: OAuthServerRouteEndpointAccessibleController_SyncError
    message: 'OAuthServerRouteEndpointAccessibleControllerDegraded: Get "https://oauth-openshift.apps.example/healthz":
      dial tcp 10.0.12.4:443: connect: connection refused'
  - type: Available
    status: "False"
    reason: OAuthServerRouteEndpointAccessibleController_EndpointUnavailable
  - type: Progressing
    status: "False"
  - type: Upgradeable
    status: "True"
"""

POD = {
    "apiVersion": "v1",
    "kind": "Pod",
    "metadata": {"name": "api-5c9d7b6f4-abcde", "namespace": "shop"},
    "status": {
        "phase": "Running",
        "containerStatuses": [
            {
                "name": "api",
                "state": {"waiting": {"reason": "CrashLoopBackOff", "message": "back-off 5m0s restarting failed"}},
                "lastState": {"terminated": {"reason": "OOMKilled", "exitCode": 137}},
            }
        ],
    },
}
EVICTED = {
    "kind": "Pod",
    "metadata": {"name": "batch-x"},
    "status": {"phase": "Failed", "reason": "Evicted", "message": "The node was low on resource: memory."},
}

OC_GET_EVENTS = """LAST SEEN   TYPE      REASON             OBJECT                        MESSAGE
2m          Warning   FailedScheduling   pod/web-7d4b9c8f6d-x2k9p      0/6 nodes are available
5m          Normal    Pulled             pod/web-7d4b9c8f6d-x2k9p      Successfully pulled image
1m          Warning   Unhealthy          pod/web-7d4b9c8f6d-x2k9p      Readiness probe failed: HTTP probe failed
"""

OC_GET_CO = (
    "NAME             VERSION   AVAILABLE   PROGRESSING   DEGRADED   SINCE   MESSAGE\n"
    "authentication   4.21.1    False       False         True       12m     "
    "OAuthServerRouteEndpointAccessibleControllerAvailable: failed\n"
    "dns              4.21.1    True        False         False      3d\n"
    "etcd             4.21.1    True        True          False      5m      NodeInstallerProgressing: 1 node at 7\n"
)

KYVERNO = (
    (
        'Error from server: error when creating "pod.yaml": admission webhook "validate.kyverno.svc-fail" denied the '
        "request:\n"
    )
    + """
resource Pod/shop/web was blocked due to the following policies

require-labels:
  check-team: 'validation error: label team is required. rule check-team failed at path /metadata/labels/team/'
"""
)


def test_alertmanager_payload() -> None:
    s = extract(json.dumps(ALERTMANAGER))
    assert names(s, "alert") == ["KubeAPIErrorBudgetBurn", "etcdHighNumberOfLeaderChanges"]
    assert "etcd" in names(s, "component") and "kube-apiserver" in names(s, "component")
    assert s == extract(ALERTMANAGER)  # parsed payloads give the same answer as text


def test_events_list_keeps_warnings_and_known_reasons() -> None:
    s = extract(json.dumps(EVENTS_JSON))
    assert names(s, "event_reason") == ["BackOff", "FailedScheduling"]
    templates = [x.detail for x in s if x.kind == "error_template"]
    assert any(t.startswith("Back-off restarting failed container web in pod web-<pod>") for t in templates)


def test_events_k8s_io_v1_shape() -> None:
    s = extract(EVENTS_V1)
    assert names(s, "event_reason") == ["FailedMount"]
    assert any('secret "db-creds" not found' in x.detail for x in s if x.kind == "error_template")


def test_cluster_operator_conditions() -> None:
    s = extract(CLUSTER_OPERATOR_YAML)
    assert names(s, "co_condition") == [
        "authentication/Available=False:OAuthServerRouteEndpointAccessibleController_EndpointUnavailable",
        "authentication/Degraded=True:OAuthServerRouteEndpointAccessibleController_SyncError",
    ]
    assert "authentication" in names(s, "component")
    templates = [x.detail for x in s if x.kind == "error_template"]
    assert any("dial tcp <ip>: connect: connection refused" in t for t in templates)


def test_pod_status_reasons() -> None:
    assert names(extract(POD), "pod_reason") == ["CrashLoopBackOff", "OOMKilled"]
    assert names(extract(EVICTED), "pod_reason") == ["Evicted"]


def test_cli_tables_and_free_text() -> None:
    s = extract(OC_GET_EVENTS)
    assert names(s, "event_reason") == ["FailedScheduling", "Unhealthy"]
    co = extract(OC_GET_CO)
    assert names(co, "co_condition") == [
        "authentication/Available=False:OAuthServerRouteEndpointAccessibleControllerAvailable",
        "authentication/Degraded=True:OAuthServerRouteEndpointAccessibleControllerAvailable",
    ]
    text = extract(
        "[FIRING:2] KubePodCrashLooping shop\nalertname=etcdNoLeader\nLast State: Terminated Reason: OOMKilled"
    )
    assert names(text, "alert") == ["KubePodCrashLooping", "etcdNoLeader"]
    assert names(text, "pod_reason") == ["OOMKilled"]
    assert "etcd" not in names(extract("my etcetera text"), "component")
    assert names(extract("openshift-apiserver pods restarted"), "component") == ["openshift-apiserver"]


def test_admission_denials_become_signals() -> None:
    assert names(extract(KYVERNO), "admission") == ["kyverno:require-labels/check-team"]


def test_error_templates_are_stable_across_variable_parts() -> None:
    tail = 'failed to list *v1.Pod: Get "https://{ip}:6443/api": dial tcp {ip}:6443: i/o timeout after {t}'
    a = "I1028 10:21:33.123456   12345 reflector.go:561] " + tail.format(ip="10.0.0.1", t="30s")
    b = "I1028 11:02:07.900001   99999 reflector.go:561] " + tail.format(ip="10.0.9.7", t="45s")
    ta, da = normalise_error(a)
    tb, db = normalise_error(b)
    assert ta == tb and da == db and len(da) == 12
    assert ta == 'failed to list *v1.Pod: Get "https://<ip>/api": dial tcp <ip>: i/o timeout after <duration>'
    t, _ = normalise_error(
        "2026-10-28T10:00:00.123Z pod web-7d4b9c8f6d-x2k9p uid 1b4e28ba-2fa1-11d2-883f-0016d3cca427 failed with "
        "image sha 3f786850e387550fdab836ed7e6dc881de23001b on [fd00::1]:8080 code 404"
    )
    assert t == "<time> pod web-<pod> uid <uuid> failed with image sha <hex> on <ip> code 404"


def test_output_is_deterministic_and_sorted() -> None:
    lines = [*OC_GET_EVENTS.splitlines()[1:], "alertname=etcdNoLeader", "[FIRING:1] KubeNodeNotReady"]
    first = extract("\n".join(lines) + "\n" + KYVERNO)
    for seed in range(5):
        shuffled = list(lines)
        random.Random(seed).shuffle(shuffled)
        again = extract("\n".join(shuffled) + "\n" + KYVERNO)
        assert {(x.kind, x.name) for x in again} == {(x.kind, x.name) for x in first}
        assert extract("\n".join(lines) + "\n" + KYVERNO) == first
    kinds = [x.kind for x in first]
    assert kinds == sorted(kinds, key=ex.KINDS.index)


def test_inputs_are_bounded_and_hostile_input_is_cheap() -> None:
    many = {"alerts": [{"labels": {"alertname": f"Alert{i}"}} for i in range(ex.MAX_ITEMS + 50)]}
    assert len(extract(many)) <= ex.MAX_SIGNALS
    deep = "[" * 5000 + "]" * 5000
    assert extract(deep) == [] or isinstance(extract(deep), list)
    hostile = ("error " + "a-" * 40_000 + "\n") * 3 + "1" * 100_000 + "\n" + "::" * 50_000
    with bounds.bounded(bounds.LINEAR, honest_seconds=HONEST_HOSTILE_EXTRACT, guards="hostile signal text"):
        extract(hostile)
    assert (
        len(
            [
                x
                for x in extract("\n".join(f"error number {i} in widget{i}x" for i in range(500)))
                if x.kind == "error_template"
            ]
        )
        <= ex.MAX_TEMPLATES
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        Signal("alert", "x").__setattr__("name", "y")


def test_cli_prints_signals(capsys: pytest.CaptureFixture[str]) -> None:
    from kube_noob.cli import main

    row = 'Warning  FailedMount  pod/db-0  MountVolume.SetUp failed for volume "data" : secret "db-creds" not found'
    assert main(["signals", row]) == 0
    out = capsys.readouterr().out
    assert "event_reason    FailedMount" in out
    assert 'MountVolume.SetUp failed for volume "data" : secret "db-creds" not found' in out
    assert "pod/db-0" not in out
    assert main(["signals", "--format", "json", json.dumps(ALERTMANAGER)]) == 0
    assert json.loads(capsys.readouterr().out)["signals"][0] == {
        "kind": "alert",
        "name": "KubeAPIErrorBudgetBurn",
        "source": "doc[0].alerts[1].labels",
    }
