"""The second adversarial review of I1 (G274): what the fixes for the first fifteen defects broke or left open.

Two of these were shared regressions that reached every tool that redacts text (diagnose, insight, must-gather,
build logs, incidents, the learning-note filter): a lone ``-----BEGIN ... PRIVATE KEY-----`` line deleted everything
after it, and the new api-key pattern redacted plain English. The rest are the receiver's: a post waiting for its
turn held its body in memory with no bound on the wait, the MCP route did not share the two-at-a-time limit, the
exporter's ``service`` label named the service in commands, label names replaced every name read from the text, and
the two version readers disagreed about precedence. Each test reproduced its defect before the fix.
"""

from __future__ import annotations

import datetime as dt
import importlib.util
import json
import os
import random
import re
import sys
import threading
import time
from pathlib import Path
from types import ModuleType
from typing import Any, Literal

import anyio
import pytest
from pydantic import BaseModel, Field

from kube_noob import alert_report, alert_store
from kube_noob.config import AlertReportSettings, Settings, load_settings
from kube_noob.debug import cluster
from kube_noob.debug.cluster import redact_text
from kube_noob.errors import ServerBusy
from kube_noob.learn.memory import contains_credential
from kube_noob.server import metrics
from kube_noob.server.http import http_app
from kube_noob.signals import alertmanager
from kube_noob.toolkit import AlertReportIn, DiagnoseIn, Toolkit

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = (ROOT / "examples" / "alertmanager-etcd.json").read_text(encoding="utf-8")
TOKEN = "review2-" + "tok-" + "q" * 10


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


def _server(tmp_path: Path, **extra: Any) -> Settings:
    return load_settings(
        overrides={
            "dataDir": str(tmp_path / "data"),
            "server": {"host": "0.0.0.0", "allowedHosts": ["testserver"]},  # noqa: S104
            **extra,
        }
    )


def _steps(out: dict[str, Any]) -> list[str]:
    return [s.get("command", "") for d in out["diagnoses"] for s in d.get("readOnlyNextSteps") or []]


# --- an ASGI client that sees exactly what the app reads ------------------------------------------------------------


class _Exchange:
    def __init__(self) -> None:
        self.chunks_read = 0
        self.status: int | None = None
        self.headers: dict[str, str] = {}
        self.body = b""


def _call(
    app: Any, path: str, body: bytes, *, disconnect: bool = False, chunks: int = 4, method: str = "POST"
) -> _Exchange:
    """One request through the whole ASGI stack. The body arrives in ``chunks`` pieces and the exchange counts how
    many the app asked for, so a test can see that a refused post was never read. ``disconnect`` makes the client go
    away as soon as its body is sent."""
    ex = _Exchange()
    size = max(1, -(-len(body) // chunks))
    pieces = [body[i : i + size] for i in range(0, len(body), size)] or [b""]

    async def receive() -> dict[str, Any]:
        if ex.chunks_read < len(pieces):
            ex.chunks_read += 1
            return {
                "type": "http.request",
                "body": pieces[ex.chunks_read - 1],
                "more_body": ex.chunks_read < len(pieces),
            }
        if disconnect:
            return {"type": "http.disconnect"}
        await anyio.sleep_forever()
        return {}  # pragma: no cover

    async def send(message: dict[str, Any]) -> None:
        if message["type"] == "http.response.start":
            ex.status = message["status"]
            ex.headers = {k.decode().lower(): v.decode() for k, v in message.get("headers", [])}
        elif message["type"] == "http.response.body":
            ex.body += message.get("body", b"")

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": [
            (b"host", b"testserver"),
            (b"authorization", f"Bearer {TOKEN}".encode()),
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
        ],
        "client": ("127.0.0.1", 50000),
        "server": ("testserver", 80),
    }
    anyio.run(app, scope, receive, send)
    return ex


def _stored(tmp_path: Path) -> list[str]:
    root = tmp_path / "data" / "alert-reports"
    return sorted(n for n in os.listdir(root) if n.endswith(".summary.json")) if root.exists() else []


# --- N1. the wait for a slot is bounded, holds no body, and abandoned posts are dropped -----------------------------


def test_a_post_that_cannot_get_a_slot_is_refused_with_503_within_the_wait(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("KUBE_NOOB_HTTP_TOKEN", TOKEN)
    monkeypatch.setattr(alert_report, "SLOT_WAIT_SECONDS", 0.3)
    monkeypatch.setattr(alert_report.Slots, "try_acquire", lambda self: False)
    started = time.monotonic()
    ex = _call(http_app(_server(tmp_path)), "/v1/alert-reports", SAMPLE.encode())
    waited = time.monotonic() - started
    assert ex.status == 503
    assert int(ex.headers["retry-after"]) >= 1
    assert "busy" in json.loads(ex.body)["error"]
    # Third review: the body is read first (bounded by size, a read deadline and the large-body tickets), because a
    # slot taken before the body let a sender that trickled hold it (test_alert_report_review3.py).
    assert waited < 3, f"the wait for a slot is bounded; it took {waited:.1f}s"
    assert _stored(tmp_path) == []


def test_a_post_whose_client_went_away_is_neither_built_nor_stored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("KUBE_NOOB_HTTP_TOKEN", TOKEN)
    ran: list[int] = []
    real = Toolkit.alert_report

    def counting(self: Toolkit, p: AlertReportIn) -> dict[str, Any]:
        ran.append(1)
        return real(self, p)

    monkeypatch.setattr(Toolkit, "alert_report", counting)
    _call(http_app(_server(tmp_path)), "/v1/alert-reports", SAMPLE.encode(), disconnect=True)
    assert ran == [], "the tool ran for a client that had already gone"
    assert _stored(tmp_path) == []
    # The neighbour: the same post with the client still there is built and stored.
    ex = _call(http_app(_server(tmp_path)), "/v1/alert-reports", SAMPLE.encode())
    assert ex.status == 200 and ran == [1] and len(_stored(tmp_path)) == 1


def test_a_body_over_the_limit_on_the_receiver_route_is_still_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The receiver's body is no longer buffered up front (so a waiting post holds none); the 1.5 MiB limit holds."""
    from kube_noob.server.http import MAX_BODY_BYTES

    monkeypatch.setenv("KUBE_NOOB_HTTP_TOKEN", TOKEN)
    big = b'{"alerts":[' + b" " * (MAX_BODY_BYTES + 10) + b"]}"
    ex = _call(http_app(_server(tmp_path)), "/v1/alert-reports", big, chunks=40)
    assert ex.status == 413


def test_the_report_deadline_counts_from_receipt_not_from_the_start_of_the_tool(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A post that waited its whole budget for a slot used to get the full budget again on top."""
    clock = [1000.0]
    monkeypatch.setattr(alert_report, "_now", lambda: clock[0])
    real = alert_report.Slots.acquire

    def slow_acquire(self: alert_report.Slots, timeout: float) -> bool:
        clock[0] += 100  # waited 100 s for the slot, past the 30 s budget
        return real(self, timeout)

    monkeypatch.setattr(alert_report.Slots, "acquire", slow_acquire)
    body = _kit(tmp_path).alert_report(AlertReportIn(payload=SAMPLE))["report"]
    assert body["summary"]["byVerdict"]["not-evaluated"] == body["summary"]["alerts"]
    # The neighbour: the REST route, where the receipt time is taken before the wait for a slot.
    monkeypatch.setenv("KUBE_NOOB_HTTP_TOKEN", TOKEN)

    def slow_try(self: alert_report.Slots) -> bool:
        clock[0] += 100
        return bool(self._sem.acquire(blocking=False))

    monkeypatch.setattr(alert_report.Slots, "try_acquire", slow_try)
    ex = _call(http_app(_server(tmp_path)), "/v1/alert-reports", SAMPLE.encode())
    out = json.loads(ex.body)
    assert ex.status == 200
    assert out["report"]["summary"]["byVerdict"]["not-evaluated"] == out["report"]["summary"]["alerts"]


def test_the_report_duration_histogram_reaches_past_the_longest_possible_answer() -> None:
    longest = AlertReportSettings.model_fields["budget_seconds"].metadata
    ceiling = max(m.le for m in longest if hasattr(m, "le"))
    assert metrics.REPORT_BUCKETS[-1] > ceiling + alert_report.SLOT_WAIT_SECONDS
    assert list(metrics.REPORT_BUCKETS) == sorted(metrics.REPORT_BUCKETS)
    text = metrics.render(registry=metrics.Metrics())
    assert 'kube_noob_alert_report_duration_seconds_bucket{le="300"}' in text
    assert 'kube_noob_alert_reports_dropped_total{outcome="busy"} 0' in text


# --- N2. one limiter for every transport ----------------------------------------------------------------------------


def test_the_mcp_tool_shares_the_receivers_limit_and_says_it_is_busy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from kube_noob.server.mcp_app import CallFailed, run_tool

    monkeypatch.setattr(alert_report, "SLOT_WAIT_SECONDS", 0.2)
    kit = _kit(tmp_path)
    taken = [kit.report_slots.try_acquire() for _ in range(alert_report.MAX_CONCURRENT_REPORTS)]
    assert all(taken) and not kit.report_slots.try_acquire()
    spec = next(s for s in kit.specs() if s.name == "alert_report")
    with pytest.raises(ServerBusy):
        kit.alert_report(AlertReportIn(payload=SAMPLE))
    with pytest.raises(CallFailed) as exc:
        run_tool(spec, {"payload": SAMPLE}, "2026-01-01")
    assert exc.value.status == 503 and "busy" in exc.value.message and "retry" in exc.value.message
    kit.report_slots.release()
    assert kit.alert_report(AlertReportIn(payload=SAMPLE))["report"]["summary"]["alerts"] == 2


def test_the_rest_route_and_the_mcp_tool_draw_on_the_same_slots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Holding the toolkit's slots (as two MCP calls would) makes the REST route answer 503."""
    from kube_noob.server import mcp_app

    monkeypatch.setenv("KUBE_NOOB_HTTP_TOKEN", TOKEN)
    monkeypatch.setattr(alert_report, "SLOT_WAIT_SECONDS", 0.2)
    kits: list[Toolkit] = []
    real = mcp_app.Toolkit

    def keep(*args: Any, **kwargs: Any) -> Toolkit:
        kits.append(real(*args, **kwargs))
        return kits[-1]

    monkeypatch.setattr(mcp_app, "Toolkit", keep)
    app = http_app(_server(tmp_path))
    (kit,) = kits
    for _ in range(alert_report.MAX_CONCURRENT_REPORTS):
        assert kit.report_slots.try_acquire()
    assert _call(app, "/v1/alert-reports", SAMPLE.encode()).status == 503
    kit.report_slots.release()
    assert _call(app, "/v1/alert-reports", SAMPLE.encode()).status == 200


# --- N3. a lone BEGIN line no longer deletes the rest of the text -------------------------------------------------


PEM_BODY = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7" * 2


def test_a_lone_private_key_header_in_prose_keeps_the_rest_of_the_text() -> None:
    text = (
        "2026-11-11T10:00:00Z ERROR tls: expected -----BEGIN RSA PRIVATE KEY----- in /etc/tls/key.pem, got garbage\n"
        "Warning  BackOff  pod/api-1  Back-off restarting failed container api in pod api-1_prod\n"
    )
    assert redact_text(text) == text
    doc = "Docs example: -----BEGIN PRIVATE KEY----- header must be on its own line\nthen restart the router pod"
    assert redact_text(doc) == doc


def test_diagnose_reads_past_a_lone_private_key_header(tmp_path: Path) -> None:
    text = (
        "2026-11-11T10:00:00Z ERROR tls: expected -----BEGIN RSA PRIVATE KEY----- in /etc/tls/key.pem, got garbage\n"
        "Warning  BackOff  pod/api-1  Back-off restarting failed container api in pod api-1_prod\n"
        "Last State: Terminated, Reason: OOMKilled, Exit Code: 137\n"
    )
    out = _kit(tmp_path, learningEnabled=False).diagnose(DiagnoseIn(text=text))
    assert out["context"].get("pod") == "api-1"
    assert any("api-1" in s for s in _steps(out))


@pytest.mark.parametrize(
    "cut",
    [
        "-----BEGIN RSA PRIVATE KEY-----\n" + PEM_BODY[:64] + "\n" + PEM_BODY[64:],
        "-----BEGIN RSA PRIVATE KEY----- " + PEM_BODY,
        "-----BEGIN PRIVATE KEY-----\r\n" + PEM_BODY[:64] + "\r\n" + PEM_BODY[64:80] + "==",
        "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0A1B2C3D\n\n" + PEM_BODY,
        "-----BEGIN OPENSSH PRIVATE KEY-----\n" + PEM_BODY + "\n" + "AAAA",
    ],
)
def test_a_cut_private_key_loses_its_body_and_only_its_body(cut: str) -> None:
    out = redact_text("before " + cut + "\nthen restart the router pod")
    assert "MIIEvQIBADAN" not in out and "BKcwggSj" not in out and "AAAA" not in out.split("PRIVATE KEY")[-1]
    assert out.startswith("before ") and out.endswith("then restart the router pod")


def test_a_complete_private_key_is_replaced_exactly_as_before() -> None:
    old = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----")
    rng = random.Random(11)
    atoms = [
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----END RSA PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----",
        "-----END PRIVATE KEY-----",
        "-----BEGIN A PRIVATE KEY",
        "-----END ",
        "-----",
        "\n",
        " ",
        "x",
        "prose words",
    ]
    for _ in range(3000):
        text = "".join(rng.choice(atoms) for _ in range(rng.randint(1, 10)))
        if "-----END" not in text or "PRIVATE KEY-----" not in text:
            continue
        expected = old.sub("***PRIVATE KEY***", text)
        got = cluster._sub_private_keys(text)
        # Where the old pattern found a complete key, the new code replaces the same span; a BEGIN left over has no
        # END after it and keeps its header unless a base64 body follows.
        if "-----BEGIN" not in expected:
            assert got == expected, text


# --- N4. prose is not a credential --------------------------------------------------------------------------------


PROSE = [
    "Fix: rotate the apikey whenever a teammate leaves, then restart the pod",
    "Set the apikey environment variable in the Deployment before rollout",
    "The access_key rotation runbook lives in the wiki",
    "access_key management is described in the runbook",
    "api_key handling: see documentation",
    "Authorization: Basic realm missing",
    "APIKEY rotation needed",
    "The Apikey   environment",
    "sha256:sk_live_ is not a key: image sk_test_examplevalue1",
    "sk-live-1234567890 is a placeholder",
    "Use basic authentication for the registry; this is a basic setup with token based auth",
    "Bearer authentication is required for this route",
]


@pytest.mark.parametrize("text", PROSE)
def test_prose_about_keys_is_not_redacted(text: str) -> None:
    assert redact_text(text) == text


@pytest.mark.parametrize("text", PROSE[:3])
def test_the_learning_note_filter_accepts_prose_about_keys(text: str) -> None:
    assert not contains_credential(text)


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("apikey sk-live-" + "9" * 30, "9999999999"),
        ("access_key AKIAIOSFODNN7EXAMPLE1234", "IOSFODNN7"),
        ("Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==", "QWxhZGRpbjpvcGVuIHNlc2FtZQ"),
        ("Authorization: Basic s3cr3t-Value_9", "Value_9"),
        ("authorization: basic dXNlcjpwYXNz", "dXNlcjpwYXNz"),
        ("sk_live_" + "a1B2c3D4e5" * 3, "a1B2c3D4e5"),
    ],
)
def test_real_keys_are_still_redacted_whole(text: str, secret: str) -> None:
    assert secret not in redact_text(text)


# --- N5. the exporter's service label is not the service the alert is about -------------------------------------


KSM = {"job": "kube-state-metrics", "service": "kube-state-metrics", "endpoint": "https-main"}


@pytest.mark.parametrize(
    "labels",
    [
        KSM,
        {"service": "kube-state-metrics"},
        {"job": "orders-api", "service": "orders-api"},
        {"service": "node-exporter"},
        {"service": "metrics", "endpoint": "web"},
    ],
)
def test_a_scrape_targets_service_label_does_not_name_the_service_in_commands(
    tmp_path: Path, labels: dict[str, str]
) -> None:
    a = _alert(
        "KubePodCrashLooping",
        ann={"description": "CrashLoopBackOff. dial tcp 172.30.12.4:6379: connect: connection refused"},
        namespace="shop",
        pod="cart-1",
        **labels,
    )
    out = _kit(tmp_path, learningEnabled=False).diagnose(DiagnoseIn(text=_payload(a)))
    svc = [s for s in _steps(out) if " svc " in s or "service-name=" in s]
    assert svc and all("<service>" in s for s in svc), svc
    assert "svc" not in alertmanager.label_context([a["labels"]])


def test_an_alert_about_a_service_still_names_it(tmp_path: Path) -> None:
    a = _alert(
        "KubeServiceNoEndpoints", ann={"description": "Service has no endpoints"}, namespace="shop", service="cart"
    )
    assert alertmanager.label_context([a["labels"]])["svc"] == "cart"
    out = _kit(tmp_path, learningEnabled=False).diagnose(DiagnoseIn(text=_payload(a)))
    assert any("describe svc cart -n shop" in s for s in _steps(out))


# --- N6. labels override the names they carry, and only those -------------------------------------------------------


def test_names_from_the_text_that_labels_do_not_carry_are_kept(tmp_path: Path) -> None:
    kit = _kit(tmp_path, learningEnabled=False)
    forbidden = _alert(
        "KubePodCrashLooping",
        ann={
            "description": 'pods is forbidden: User "system:serviceaccount:team-a:operator" cannot list resource '
            '"pods" in API group "" at the cluster scope'
        },
        namespace="team-a",
        pod="operator-7b9-xyz12",
        **KSM,
    )
    steps = " ".join(_steps(kit.diagnose(DiagnoseIn(text=_payload(forbidden)))))
    assert "kubectl auth can-i list pods -n team-a --as=system:serviceaccount:team-a:operator" in steps
    pull = _alert(
        "KubePodNotReady",
        ann={"description": "Pod ci/runner-1: Unable to retrieve some image pull secrets (regcred); attempting"},
        namespace="ci",
        pod="runner-1",
    )
    assert "metadata.name=regcred" in " ".join(_steps(kit.diagnose(DiagnoseIn(text=_payload(pull)))))
    mounts = _alert(
        "KubePodNotReady",
        ann={"description": 'pod db/postgres-0: persistentvolumeclaim "data-postgres-0" not found; MountVolume'},
        namespace="db",
        pod="postgres-0",
    )
    out = kit.diagnose(DiagnoseIn(text=_payload(mounts)))
    assert out["context"].get("pvc") == "data-postgres-0" and out["context"]["ns"] == "db"


def test_the_report_keeps_the_text_names_too(tmp_path: Path) -> None:
    forbidden = _alert(
        "KubePodCrashLooping",
        ann={
            "description": 'pods is forbidden: User "system:serviceaccount:team-a:operator" cannot list resource '
            '"pods" in API group "" at the cluster scope'
        },
        namespace="team-a",
        pod="operator-7b9-xyz12",
    )
    body = _kit(tmp_path).alert_report(AlertReportIn(payload=_payload(forbidden)))["report"]
    steps = " ".join(s.get("command", "") for s in body["alerts"][0]["nextSteps"]["readOnly"])
    assert "--as=system:serviceaccount:team-a:operator" in steps


# --- N7. one version precedence for diagnose and the report ------------------------------------------------------


@pytest.mark.parametrize(
    ("own", "common", "expected"),
    [
        ({"openshift_version": "4.21.0"}, {"openshift_version": "4.20.1"}, "4.21.0"),
        ({"version": "4.21.0"}, {"openshift_version": "4.20.1"}, "4.20.1"),
        ({"version": "4.21.0"}, {"version": "4.20.1"}, "4.21.0"),
        ({}, {"version": "4.20.1"}, "4.20.1"),
        ({"version": "4.21.0", "openshift_version": "4.20.1"}, {}, "4.20.1"),
        ({"version": "2.3.1"}, {"version": "4.20.1"}, "4.20.1"),
    ],
)
def test_diagnose_and_the_report_read_the_same_version(
    tmp_path: Path, own: dict[str, str], common: dict[str, str], expected: str
) -> None:
    kit = _kit(tmp_path)
    for order in (False, True):
        # Both from the platform (an openshift-* namespace): since the third review a `version` label counts only there.
        alerts = [
            _alert("etcdHighFsyncDurations", namespace="openshift-etcd", **own),
            _alert("etcdMembersDown", namespace="openshift-etcd", **own),
        ]
        if order:
            alerts.reverse()
        text = _payload(*alerts, commonLabels=common)
        assert alertmanager.parse(text).version == expected  # type: ignore[union-attr]
        assert {a.version for a in alertmanager.split(text).alerts} == {expected}  # type: ignore[union-attr]
        assert kit.diagnose(DiagnoseIn(text=text))["input"]["version"] == expected
        report = kit.alert_report(AlertReportIn(payload=text))["report"]
        assert report["summary"]["version"] == expected


# --- N8. the redactor is linear, counted ----------------------------------------------------------------------------


class _Counting:
    """A compiled pattern that records how many characters each call could examine: a match counts what it consumed
    (plus one for the character that stopped it), a search or a scan counts everything from its start to the end."""

    def __init__(self, real: re.Pattern[str], seen: list[int]) -> None:
        self.real, self.seen = real, seen

    def match(self, text: str, pos: int = 0, endpos: int | None = None) -> Any:
        m = self.real.match(text, pos) if endpos is None else self.real.match(text, pos, endpos)
        self.seen.append((m.end() - pos if m else 0) + 1)
        return m

    def search(self, text: str, pos: int = 0, endpos: int | None = None) -> Any:
        self.seen.append(len(text) - pos)
        return self.real.search(text, pos) if endpos is None else self.real.search(text, pos, endpos)

    def finditer(self, text: str, pos: int = 0, endpos: int | None = None) -> Any:
        self.seen.append(len(text) - pos)
        return self.real.finditer(text, pos) if endpos is None else self.real.finditer(text, pos, endpos)

    def sub(self, repl: Any, text: str, count: int = 0) -> str:
        self.seen.append(len(text))
        return self.real.sub(repl, text, count)

    def __getattr__(self, name: str) -> Any:
        return getattr(self.real, name)


@pytest.mark.parametrize(
    "flood",
    [
        "eyJ",
        "-----BEGIN A PRIVATE KEY-----",
        "-----BEGIN A PRIVATE KEY----- " + "QUJDREVGR0hJSktMTU5PUA" + " ",
        "eyJhbGciOiJIUzI1NiJ9.",
        "-----END A PRIVATE KEY-----",
    ],
)
def test_the_key_and_token_scans_examine_each_character_a_bounded_number_of_times(
    monkeypatch: pytest.MonkeyPatch, flood: str
) -> None:
    seen: list[int] = []
    for name in ("_PEM_BEGIN", "_PEM_END", "_PEM_BODY", "_JWT_RUN"):
        monkeypatch.setattr(cluster, name, _Counting(getattr(cluster, name), seen))
    for size in (8_000, 64_000):
        seen.clear()
        text = (flood * (size // len(flood) + 1))[:size]
        cluster._sub_private_keys(text)
        cluster._sub_jwts(text)
        assert sum(seen) <= 8 * size + 64, f"{flood[:12]!r} x {size}: {sum(seen)} characters examined"


def test_the_jwt_scan_replaces_exactly_what_the_plain_pattern_did() -> None:
    old = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
    rng = random.Random(5)
    atoms = ["eyJ", "eyJhbGciOi", "abcdefgh", "ABCD1234", ".", "..", "-", "_", " ", "x", "=", "eyJeyJ", "/"]
    for _ in range(6000):
        text = "".join(rng.choice(atoms) for _ in range(rng.randint(1, 16)))
        assert cluster._sub_jwts(text) == old.sub("***JWT***", text), text


# --- N10. a report evicted while the list was being read is gone, not unreadable ----------------------------------


def _record(report_id: str) -> dict[str, Any]:
    return {
        "format": alert_store.RECORD_FORMAT,
        "id": report_id,
        "receivedAt": "2026-11-11T10:00:00.000Z",
        "durationSeconds": 0.01,
        "bodySha256": "0" * 64,
        "stored": True,
        "report": {
            "summary": {"alerts": 1, "alertnames": ["A"], "byVerdict": {"no-recognised-signal": 1}},
            "alerts": [{"index": 0, "alertname": "A", "state": "firing", "verdict": "no-recognised-signal"}],
            "notIncluded": [],
            "caveats": ["c"],
        },
    }


def _ids(n: int, start: int = 0) -> list[str]:
    return [f"20261111T10{m:02d}00.000000Z-{m:024x}" for m in range(start, start + n)]


NOW = dt.datetime(2026, 11, 11, 11, 0, tzinfo=dt.UTC)


def _store(tmp_path: Path, **limits: Any) -> alert_store.AlertReportStore:
    return alert_store.AlertReportStore(tmp_path / "data", AlertReportSettings(**limits))


def test_a_report_removed_while_the_list_is_read_is_left_out_not_unreadable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path)
    ids = _ids(3)
    for rid in ids:
        store.save(_record(rid), NOW)
    root = tmp_path / "data" / "alert-reports"
    real = store._read

    def evicting(dfd: int, name: str, cap: int) -> Any:
        if name.startswith(ids[1]):  # retention removed this one between the directory listing and the read
            for suffix in (".json", ".summary.json"):
                (root / f"{ids[1]}{suffix}").unlink(missing_ok=True)
        return real(dfd, name, cap)

    monkeypatch.setattr(store, "_read", evicting)
    out = store.newest(10)
    assert [r["id"] for r in out["reports"]] == [ids[2], ids[0]]
    assert not any("unreadable" in r for r in out["reports"]) and out["total"] == 2
    # The neighbour: a summary missing while its report is still there is unreadable, as before.
    (root / f"{ids[0]}.summary.json").unlink()
    rows = {r["id"]: r for r in store.newest(10)["reports"]}
    assert "unreadable" in rows[ids[0]]


# --- the store: planted entries, hard links ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", ["directory", "fifo", "symlink"])
def test_an_entry_that_is_not_a_file_is_not_listed_and_takes_no_place_under_the_cap(tmp_path: Path, kind: str) -> None:
    store = _store(tmp_path, max_reports=3)
    root = tmp_path / "data" / "alert-reports"
    root.mkdir(parents=True, mode=0o700)
    planted = root / "20991231T000000.000000Z-ffffffffffffffffffffffff.json"
    if kind == "directory":
        planted.mkdir()
    elif kind == "fifo":
        os.mkfifo(planted)
    else:
        planted.symlink_to(tmp_path)
    results = [store.save(_record(rid), NOW) for rid in _ids(5)]
    assert all(r.not_removed == 0 for r in results)
    out = store.newest(10)
    assert [r["id"] for r in out["reports"]] == list(reversed(_ids(5)))[:3], "the cap counts what is shown"
    assert out["total"] == 3 and out["ignored"] == 1 and "not a regular file" in out["note"]


def test_a_hard_link_to_a_file_outside_the_store_is_not_served(tmp_path: Path) -> None:
    store = _store(tmp_path)
    (rid,) = _ids(1)
    store.save(_record(rid), NOW)
    root = tmp_path / "data" / "alert-reports"
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps(_record(rid)), encoding="utf-8")
    (root / f"{rid}.json").unlink()
    os.link(outside, root / f"{rid}.json")
    with pytest.raises(alert_store.StoreUnavailable):
        store.get(rid)
    # The neighbour: the summary file hard-linked is unreadable in the list, not shown.
    (root / f"{rid}.summary.json").unlink()
    os.link(outside, root / f"{rid}.summary.json")
    (row,) = store.newest(5)["reports"]
    assert "unreadable" in row


# --- the safety contract catches the defaults it used to pass ----------------------------------------------------


def _contract() -> ModuleType:
    spec = importlib.util.spec_from_file_location("safety_contract", ROOT / "scripts" / "safety_contract.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["safety_contract"] = mod
    spec.loader.exec_module(mod)
    return mod


class _Beacon(BaseModel):
    enabled: bool = True


class _LiteralOn(Settings):
    telemetry: Literal["off", "on"] = "on"


class _UrlDefault(Settings):
    phone_home: str = "https://collector.example.com/v1"


class _ListOfModels(Settings):
    beacons: list[_Beacon] = Field(default_factory=list)


class _ListDefault(Settings):
    upload_targets: list[str] = Field(default_factory=lambda: ["s3://bucket"])


@pytest.mark.parametrize(
    ("model", "key"),
    [
        (_LiteralOn, "telemetry"),
        (_UrlDefault, "phoneHome"),
        (_ListOfModels, "beacons[].enabled"),
        (_ListDefault, "uploadTargets"),
    ],
)
def test_the_contract_fails_a_default_that_is_on_in_any_shape(model: type[Settings], key: str) -> None:
    sc = _contract()
    problems = sc.default_violations(model.model_validate({"dataDir": "/nonexistent"}))
    assert any(key in p for p in problems), problems
    assert sc.default_violations() == []


# --- the severity docstring and the code agree --------------------------------------------------------------------


@pytest.mark.parametrize("severity", ["", "P1", "disaster", "CRIT"])
def test_an_unrecognised_severity_ranks_with_critical(severity: str) -> None:
    def row(sev: str, index: int) -> dict[str, Any]:
        return {"index": index, "state": "firing", "labels": {"severity": sev} if sev else {}}

    assert alert_report._keep_rank(row(severity, 0))[0] == alert_report._keep_rank(row("critical", 0))[0]
    assert alert_report._keep_rank(row(severity, 1)) > alert_report._keep_rank(row("warning", 0))


# --- N11. the redactor's reach is what PRIVACY.md says ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("client_secret=Zq8w4Lx1VbN0", "Zq8w4Lx1VbN0"),
        ("aws_secret_access_key=wJalrXUtnFEMI/K7MDENG", "wJalrXUtnFEMI"),
        ("export DB_PASSWORD=hunter2", "hunter2"),
        ("CLIENT_SECRET: s3cr3tvalue", "s3cr3tvalue"),
        ("curl -H 'X: y' Bearer 9f86d081884c7d659a2feaa0c55ad015", "9f86d081884c"),
        ('{"type": "service_account", "private_key": "-----BEGIN PRIVATE KEY-----\\nMIIEvQ\\n"}', "MIIEvQ"),
        ("mysql --pwd hunter2 shop", "hunter2"),
        ("tool --pwd=hunter2", "hunter2"),
    ],
)
def test_the_cheap_remaining_credential_shapes_are_redacted(text: str, secret: str) -> None:
    assert secret not in redact_text(text)


def test_privacy_names_what_the_redactor_does_not_catch() -> None:
    privacy = (ROOT / "PRIVACY.md").read_text(encoding="utf-8")
    section = privacy[privacy.index("## What the redactor removes") :]
    section = section[: section.index("\n## ", 4)]
    for gap in ("`token <value>`", "`-p<password>`", "`password%3D`", "split across"):
        assert gap in section, gap
    for caught in ("client_secret", "aws_secret_access_key", "DB_PASSWORD", "Bearer", "private_key", "--pwd"):
        assert caught in section, caught
    # What the section calls a gap really is one: the document never claims more than the code does.
    assert "hunter2" in redact_text("mysql -phunter2 shop")
    assert "hunter2" in redact_text("token hunter2xyz")


def test_operations_states_the_measured_answer_time() -> None:
    ops = (ROOT / "docs" / "operations.md").read_text(encoding="utf-8")
    assert "one post ends within the budget plus the one alert in progress" not in ops
    assert "503" in ops and "Retry-After" in ops


def test_a_thread_waiting_for_a_slot_gives_up_after_the_bound(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(alert_report, "SLOT_WAIT_SECONDS", 0.2)
    kit = _kit(tmp_path)
    for _ in range(alert_report.MAX_CONCURRENT_REPORTS):
        kit.report_slots.try_acquire()
    errors: list[BaseException] = []

    def call() -> None:
        try:
            kit.alert_report(AlertReportIn(payload=SAMPLE))
        except BaseException as exc:  # noqa: BLE001 - collected for the assertion
            errors.append(exc)

    workers = [threading.Thread(target=call) for _ in range(6)]
    started = time.monotonic()
    for w in workers:
        w.start()
    for w in workers:
        w.join(10)
    assert time.monotonic() - started < 5
    assert len(errors) == 6 and all(isinstance(e, ServerBusy) for e in errors)


def test_large_mcp_bodies_waiting_in_memory_are_bounded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The MCP SDK parses a call's body before the tool can wait for a report slot, so each waiting MCP call held its
    whole body (about 10 MB parsed); twenty took the server to 311 MB. Large bodies in memory are capped instead (the
    third review made the cap count bytes in memory, wait for room and release when the tool takes the body)."""
    from kube_noob.server import admission

    monkeypatch.setenv("KUBE_NOOB_HTTP_TOKEN", TOKEN)
    monkeypatch.setattr(admission, "MAX_LARGE_BODIES", 0)
    monkeypatch.setattr(admission, "READ_SECONDS", 0.5)
    big = (
        b'{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{},"pad":"' + b"x" * admission.LARGE_BODY_BYTES + b'"}'
    )
    ex = _call(http_app(_server(tmp_path)), "/mcp", big)
    assert ex.status == 503 and int(ex.headers["retry-after"]) >= 1
    # The neighbours: a small body is not counted, and a large one is admitted again once the earlier one finished.
    from starlette.testclient import TestClient

    headers = {
        "Authorization": f"Bearer {TOKEN}",
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }
    with TestClient(http_app(_server(tmp_path)), base_url="http://testserver") as c:
        assert c.post("/mcp", content=b'{"jsonrpc":"2.0","id":1,"method":"ping"}', headers=headers).status_code != 503
    monkeypatch.setattr(admission, "MAX_LARGE_BODIES", 1)
    with TestClient(http_app(_server(tmp_path)), base_url="http://testserver") as c:
        assert c.post("/mcp", content=big, headers=headers).status_code != 503
        assert c.post("/mcp", content=big, headers=headers).status_code != 503
