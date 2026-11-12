"""The third adversarial review of I1 (G274): availability regressions in the server-wide limits the second added.

A report slot was taken before the body was read, with no read deadline, so two senders that trickled a byte at a
time held both slots and every real alert post was refused as "busy" for as long as they kept trickling. The
large-body cap counted declared lengths, so eight trickling posts refused every large post on every route; it also
refused, rather than queued, the tenth of ten ordinary parallel audits. Its 503 on ``/mcp`` was a plain JSON body the
MCP SDK turned into a generic error. And an MCP report waiting for its slot blocked an anyio worker thread for up to
5 s, so sixty of them starved every other tool. Each test below reproduced its defect before the fix.
"""

from __future__ import annotations

import json
import socket
import threading
import time
from pathlib import Path
from typing import Any

import anyio
import pytest

from kube_noob import alert_report
from kube_noob.config import Settings, load_settings
from kube_noob.server import admission
from kube_noob.server.http import http_app
from kube_noob.toolkit import Toolkit

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = (ROOT / "examples" / "alertmanager-etcd.json").read_text(encoding="utf-8")
TOKEN = "review3-" + "tok-" + "q" * 10
MCP_ACCEPT = "application/json, text/event-stream"


def _server(tmp_path: Path, **extra: Any) -> Settings:
    return load_settings(
        overrides={
            "dataDir": str(tmp_path / "data"),
            "learningEnabled": False,
            "server": {"host": "0.0.0.0", "allowedHosts": ["testserver"]},  # noqa: S104
            **extra,
        }
    )


class _Exchange:
    def __init__(self) -> None:
        self.chunks_read = 0
        self.status: int | None = None
        self.headers: dict[str, str] = {}
        self.body = b""
        self.done_at: float | None = None

    def json(self) -> Any:
        return json.loads(self.body)


def _request(
    app: Any,
    path: str,
    body: bytes,
    *,
    declared: int | None = None,
    stall_after: int | None = None,
    chunks: int = 4,
) -> tuple[Any, _Exchange]:
    """An ASGI exchange to run inside an event loop. ``stall_after`` chunks are sent and then the sender goes quiet
    without closing, as a slowloris does; ``declared`` is the Content-Length it claims."""
    ex = _Exchange()
    size = max(1, -(-len(body) // chunks))
    pieces = [body[i : i + size] for i in range(0, len(body), size)] or [b""]
    limit = len(pieces) if stall_after is None else stall_after

    async def receive() -> dict[str, Any]:
        if ex.chunks_read < limit:
            ex.chunks_read += 1
            more = ex.chunks_read < len(pieces)
            return {"type": "http.request", "body": pieces[ex.chunks_read - 1], "more_body": more}
        await anyio.sleep_forever()
        return {}  # pragma: no cover

    async def send(message: dict[str, Any]) -> None:
        if message["type"] == "http.response.start":
            ex.status = message["status"]
            ex.headers = {k.decode().lower(): v.decode() for k, v in message.get("headers", [])}
        elif message["type"] == "http.response.body":
            ex.body += message.get("body", b"")
            if not message.get("more_body"):
                ex.done_at = time.monotonic()

    headers = [
        (b"host", b"testserver"),
        (b"authorization", f"Bearer {TOKEN}".encode()),
        (b"content-type", b"application/json"),
        (b"accept", MCP_ACCEPT.encode()),
        (b"content-length", str(declared if declared is not None else len(body)).encode()),
    ]
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": headers,
        "client": ("127.0.0.1", 50000),
        "server": ("testserver", 80),
    }

    async def run() -> None:
        await app(scope, receive, send)

    return run, ex


def _together(*runs: Any, limit: float = 30) -> None:
    async def main() -> None:
        with anyio.fail_after(limit):
            async with anyio.create_task_group() as tg:
                for run in runs:
                    tg.start_soon(run)

    anyio.run(main)


def _diagnose_body(size: int) -> bytes:
    return json.dumps({"text": "CrashLoopBackOff " + "x" * size}).encode()


# --- 1. a slow sender holds no slot and no ticket ---------------------------------------------------------------------


def test_a_trickling_alert_post_is_dropped_with_408_and_holds_no_report_slot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("KUBE_NOOB_HTTP_TOKEN", TOKEN)
    monkeypatch.setattr(admission, "READ_SECONDS", 1.0)
    app = http_app(_server(tmp_path))
    slow = [_request(app, "/v1/alert-reports", SAMPLE.encode(), stall_after=1) for _ in range(3)]
    real = _request(app, "/v1/alert-reports", SAMPLE.encode())
    started = time.monotonic()
    _together(*(r for r, _ in slow), real[0])
    assert real[1].status == 200, real[1].body[:200]
    assert real[1].done_at is not None and real[1].done_at - started < 0.9, "the real post waited for the slow ones"
    for _, ex in slow:
        assert ex.status == 408 and "did not arrive" in ex.json()["error"]


def test_a_trickling_large_post_holds_no_large_body_ticket(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Eight senders that declared 300 KiB and sent ten bytes used to refuse every large post on every route."""
    monkeypatch.setenv("KUBE_NOOB_HTTP_TOKEN", TOKEN)
    monkeypatch.setattr(admission, "READ_SECONDS", 1.5)
    monkeypatch.setattr(admission, "MAX_LARGE_BODIES", 1)
    app = http_app(_server(tmp_path))
    big = _diagnose_body(300_000)
    slow = [_request(app, path, big, stall_after=1, chunks=30_000) for path in ("/v1/audit", "/v1/diagnose", "/mcp")]
    real = _request(app, "/v1/diagnose", big)
    _together(*(r for r, _ in slow), real[0])
    assert real[1].status == 200, real[1].body[:200]
    assert all(ex.status == 408 for _, ex in slow), [ex.status for _, ex in slow]


def test_a_large_post_over_the_cap_waits_for_a_ticket_instead_of_being_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ten parallel audits of a 320 KB bundle: eight answered and two refused in 0.02 s. They queue now."""
    monkeypatch.setenv("KUBE_NOOB_HTTP_TOKEN", TOKEN)
    monkeypatch.setattr(admission, "MAX_LARGE_BODIES", 1)
    app = http_app(_server(tmp_path))
    runs = [_request(app, "/v1/diagnose", _diagnose_body(300_000)) for _ in range(4)]
    _together(*(r for r, _ in runs))
    assert [ex.status for _, ex in runs] == [200] * 4


def test_a_large_body_frees_its_ticket_when_its_tool_takes_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The cap bounds bodies waiting in memory, not tools running: with room for one, two slow large diagnoses run at
    the same time."""
    monkeypatch.setenv("KUBE_NOOB_HTTP_TOKEN", TOKEN)
    monkeypatch.setattr(admission, "MAX_LARGE_BODIES", 1)
    both = threading.Barrier(2, timeout=5)
    real = Toolkit.diagnose

    def slow(self: Toolkit, p: Any) -> dict[str, Any]:
        both.wait()  # breaks (and the call fails) unless the second large body reached its tool while this one ran
        return real(self, p)

    monkeypatch.setattr(Toolkit, "diagnose", slow)
    app = http_app(_server(tmp_path))
    runs = [_request(app, "/v1/diagnose", _diagnose_body(300_000)) for _ in range(2)]
    _together(*(r for r, _ in runs))
    assert [ex.status for _, ex in runs] == [200, 200]


def test_the_busy_answer_says_what_holds_the_slots() -> None:
    message = alert_report.busy_message(5.0)
    assert "report slots" in message and "in use" in message and "retry" in message


# --- 3. /mcp refusals are JSON-RPC errors --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "patch", "declared", "stall", "words"),
    [
        (503, {"MAX_LARGE_BODIES": 0, "READ_SECONDS": 1.0}, None, None, "busy"),
        (413, {}, 2_000_000, None, "too large"),
        (408, {"READ_SECONDS": 0.5}, None, 1, "did not arrive"),
    ],
)
def test_a_refusal_on_mcp_is_a_json_rpc_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    status: int,
    patch: dict[str, Any],
    declared: int | None,
    stall: int | None,
    words: str,
) -> None:
    monkeypatch.setenv("KUBE_NOOB_HTTP_TOKEN", TOKEN)
    for name, value in patch.items():
        monkeypatch.setattr(admission, name, value)
    body = (
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 9,
                "method": "tools/call",
                "params": {"name": "kubenoob_diagnose", "arguments": {}},
            }
        ).encode()[:-1]
        + b',"pad":"'
        + b"x" * 300_000
        + b'"}'
    )
    run, ex = _request(http_app(_server(tmp_path)), "/mcp", body, declared=declared, stall_after=stall)
    _together(run)
    assert ex.status == status
    assert ex.headers["content-type"].startswith("application/json")
    doc = ex.json()
    assert doc["jsonrpc"] == "2.0" and doc["id"] is None and doc["error"]["code"] == -32000
    assert words in doc["error"]["message"]


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port: int = s.getsockname()[1]
        return port


def test_the_mcp_sdk_client_shows_the_refusal_message(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The plain JSON 503 reached an MCP client as "Server returned an error response", the reason lost."""
    import uvicorn

    httpx2 = pytest.importorskip("httpx2")
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    monkeypatch.setenv("KUBE_NOOB_HTTP_TOKEN", TOKEN)
    monkeypatch.setattr(admission, "MAX_LARGE_BODIES", 0)
    monkeypatch.setattr(admission, "READ_SECONDS", 1.0)
    settings = load_settings(
        overrides={"dataDir": str(tmp_path / "data"), "learningEnabled": False, "server": {"host": "127.0.0.1"}}
    )
    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(http_app(settings), host="127.0.0.1", port=port, log_level="critical"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 20
        while not server.started and time.monotonic() < deadline:
            time.sleep(0.05)
        seen: list[str] = []

        async def main() -> None:
            url = f"http://127.0.0.1:{port}/mcp"
            async with (
                httpx2.AsyncClient(headers={"Authorization": f"Bearer {TOKEN}"}, timeout=30) as http,
                streamable_http_client(url, http_client=http) as (r, w, *_),
                ClientSession(r, w) as session,
            ):
                await session.initialize()
                try:
                    await session.call_tool("kubenoob_diagnose", {"text": "x" * 300_000})
                except Exception as exc:  # noqa: BLE001 - the message is what is checked
                    seen.append(str(exc))
                small = await session.call_tool("kubenoob_diagnose", {"text": "CrashLoopBackOff"})
                seen.append("small ok" if not small.is_error else "small failed")

        anyio.run(main)
    finally:
        server.should_exit = True
        thread.join(10)
    assert seen and "busy" in seen[0] and "retry" in seen[0], seen
    assert seen[-1] == "small ok"


# --- 4. waiting for a report slot never blocks a worker thread ---------------------------------------------------


def test_mcp_reports_waiting_for_a_slot_do_not_starve_other_tools(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from starlette.testclient import TestClient

    monkeypatch.setenv("KUBE_NOOB_HTTP_TOKEN", TOKEN)
    monkeypatch.setattr(alert_report, "SLOT_WAIT_SECONDS", 3.0)
    monkeypatch.setattr(alert_report.Slots, "try_acquire", lambda self: False)
    monkeypatch.setattr(alert_report.Slots, "acquire", lambda self, timeout: (time.sleep(timeout), False)[1])
    headers = {"Authorization": f"Bearer {TOKEN}", "Accept": MCP_ACCEPT, "Content-Type": "application/json"}
    call = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "kubenoob_alert_report", "arguments": {"payload": SAMPLE}},
    }
    with TestClient(http_app(_server(tmp_path)), base_url="http://testserver") as c:
        answers: list[Any] = []
        workers = [
            threading.Thread(target=lambda: answers.append(c.post("/mcp", json=call, headers=headers)))
            for _ in range(50)
        ]
        for w in workers:
            w.start()
        time.sleep(0.5)
        started = time.monotonic()
        small = c.post("/v1/diagnose", json={"text": "CrashLoopBackOff"}, headers=headers)
        took = time.monotonic() - started
        for w in workers:
            w.join(30)
    assert small.status_code == 200 and took < 1.5, f"a small diagnose waited {took:.1f}s behind report waits"
    assert len(answers) == 50 and all("busy" in a.text for a in answers)


# --- the documented answers ------------------------------------------------------------------------------------------


def test_every_post_route_documents_its_refusals() -> None:
    from kube_noob.server import rest

    doc = rest.full_document()
    for path, ops in doc["paths"].items():
        if "post" in ops:
            assert {"408", "413", "499", "503"} <= set(ops["post"]["responses"]), path


# --- 5. the scrape target is not the subject -----------------------------------------------------------------------
# Upstream (kube-prometheus kubeStateMetrics-serviceMonitor.yaml: honorLabels true, labeldrop pod|service|endpoint|
# namespace; OpenShift cluster-monitoring-operator kube-state-metrics service-monitor.yaml: honorLabels true, no
# labeldrop; nodeExporter-serviceMonitor.yaml: no honorLabels), so a metric without a namespace keeps the exporter's on
# OpenShift, node-exporter series carry the exporter's own pod and namespace, and a scrape without honorLabels moves
# the subject's labels to exported_*.


def _ctx(**labels: str) -> dict[str, str]:
    from kube_noob.signals import alertmanager

    return alertmanager.label_context([labels])


def test_exported_labels_name_the_subject_when_the_plain_ones_name_the_exporter() -> None:
    ctx = _ctx(
        alertname="KubePodCrashLooping",
        job="kube-state-metrics",
        namespace="monitoring",
        pod="kube-state-metrics-6d8f9b7c5-xk2lp",
        service="kube-state-metrics",
        exported_namespace="shop",
        exported_pod="cart-7d9c8b6f5d-2xkqp",
    )
    assert ctx.get("ns") == "shop" and ctx.get("pod") == "cart-7d9c8b6f5d-2xkqp"
    # The neighbour: with honorLabels the plain labels are the subject's, and exported_* (absent) changes nothing.
    assert _ctx(alertname="KubePodCrashLooping", job="kube-state-metrics", namespace="shop", pod="cart-1") == {
        "ns": "shop",
        "pod": "cart-1",
        "name": "cart-1",
    }


@pytest.mark.parametrize(
    "labels",
    [
        {
            "alertname": "NodeFilesystemSpaceFillingUp",
            "job": "node-exporter",
            "namespace": "openshift-monitoring",
            "pod": "node-exporter-q8r4n",
            "service": "node-exporter",
            "endpoint": "https",
            "instance": "worker-1",
        },
        {
            "alertname": "NodeClockNotSynchronising",
            "job": "node-exporter",
            "namespace": "monitoring",
            "pod": "node-exporter-7xk2p",
            "instance": "worker-1",
        },
        {
            "alertname": "KubeNodeNotReady",
            "job": "kube-state-metrics",
            "service": "kube-state-metrics",
            "endpoint": "https-main",
            "namespace": "openshift-monitoring",
            "node": "worker-4",
            "condition": "Ready",
        },
    ],
)
def test_the_exporters_namespace_and_pod_are_not_the_subject_of_a_node_alert(labels: dict[str, str]) -> None:
    ctx = _ctx(**labels)
    assert "ns" not in ctx and "pod" not in ctx, ctx


def test_a_pvc_alert_from_the_kubelet_keeps_its_namespace() -> None:
    """The neighbour of the node rule: kubelet volume stats carry the claim's own namespace (honorLabels)."""
    ctx = _ctx(
        alertname="KubePersistentVolumeFillingUp",
        job="kubelet",
        service="kubelet",
        endpoint="https-metrics",
        node="worker-3",
        namespace="openshift-monitoring",
        persistentvolumeclaim="prometheus-data-prometheus-k8s-0",
    )
    assert ctx["ns"] == "openshift-monitoring" and ctx["pvc"] == "prometheus-data-prometheus-k8s-0"


def test_target_down_names_the_target_service() -> None:
    ctx = _ctx(alertname="TargetDown", job="orders-api", namespace="shop", service="orders-api")
    assert ctx.get("svc") == "orders-api" and ctx.get("ns") == "shop"
    # The neighbour: the same labels on a pod alert are the scrape target, not its subject.
    assert "svc" not in _ctx(alertname="KubePodCrashLooping", job="orders-api", namespace="shop", service="orders-api")


# --- 6. a reference to a secret is not a secret ------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "    Environment:\n      DB_PASSWORD:  <set to the key 'password' in secret 'orders-db'>  Optional: false\n",
        "  DB_PASSWORD: orders-db/password",
        "  API_TOKEN: <set to the key 'token' of config map 'cfg'>",
    ],
)
def test_a_secret_reference_is_not_redacted_and_is_not_a_credential(text: str) -> None:
    from kube_noob.debug.cluster import redact_text
    from kube_noob.learn.memory import contains_credential

    assert redact_text(text) == text
    assert not contains_credential(text.strip())


def test_a_value_that_merely_contains_a_slash_is_still_redacted() -> None:
    from kube_noob.debug.cluster import redact_text

    for text in ("DB_PASSWORD: Xk9/q2Lm", "DB_PASSWORD: orders-db/Xk9q2Lm7", "password=a/b"):
        assert "***" in redact_text(text), text


# --- 7. access-key flags -------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    ["aws configure --access-key s3cr3tValue9 --x", "tool -access_key s3cr3tValue9", "--access-key=s3cr3tValue9"],
)
def test_an_access_key_flag_is_redacted(text: str) -> None:
    from kube_noob.debug.cluster import redact_text

    assert "s3cr3tValue9" not in redact_text(text)


# --- 8. cut private keys in log and escaped shapes -------------------------------------------------------------------

B64 = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj"


@pytest.mark.parametrize(
    "text",
    [
        'msg="loaded key" tls.key="-----BEGIN RSA PRIVATE KEY-----\\n' + B64 + "\\n" + B64 + "\\n" + B64[:30],
        "KEY=-----BEGIN PRIVATE KEY-----" + B64 + B64 + B64[:20],
        "2024-05-13T10:20:41.135Z -----BEGIN RSA PRIVATE KEY-----\n2024-05-13T10:20:41.135Z "
        + B64
        + "\n2024-05-13T10:20:41.136Z "
        + B64
        + "\n",
        "2024-05-13T10:20:41.135Z stdout F -----BEGIN EC PRIVATE KEY-----\n2024-05-13T10:20:41.135Z stdout F "
        + B64
        + "\n",
        "[pod/web-1/app] -----BEGIN PRIVATE KEY-----\n[pod/web-1/app] " + B64 + "\n[pod/web-1/app] " + B64 + "\n",
        '{"type":"service_account","private_key":"-----BEGIN PRIVATE KEY-----\\n' + B64,
    ],
)
def test_a_cut_private_key_with_a_log_prefix_or_escaped_newlines_loses_its_body(text: str) -> None:
    from kube_noob.debug.cluster import redact_text

    out = redact_text(text + "\nthen restart the router pod")
    assert "MIIEvQIBADAN" not in out and "BKcwggSj" not in out, out
    assert out.endswith("then restart the router pod")


# --- 9. the safety contract cannot be evaded by shape -------------------------------------------------------------


def _contract() -> Any:
    import importlib.util
    import sys

    spec = importlib.util.spec_from_file_location("safety_contract", ROOT / "scripts" / "safety_contract.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["safety_contract"] = mod
    spec.loader.exec_module(mod)
    return mod


def _evasions() -> list[tuple[type, str]]:
    from typing import Literal

    from pydantic import BaseModel, Field, model_validator

    class Sub(BaseModel):
        enabled: bool = True
        endpoint: str = "https://telemetry.example.com"

    class Item(BaseModel):
        enabled: bool = False

        @model_validator(mode="after")
        def _on(self) -> Any:
            object.__setattr__(self, "enabled", True)
            return self

    class Mode(BaseModel):
        mode: Literal["audit", "enforce"] = "enforce"
        host: str = "telemetry.example.com"

    class DictOf(Settings):
        extras: dict[str, Sub] = Field(default_factory=dict)

    class ListOf(Settings):
        items: list[Item] = Field(default_factory=list)

    class Nested(Settings):
        m: Mode = Field(default_factory=Mode)

    class Optional_(Settings):
        opt: Sub | None = None

    return [
        (DictOf, "extras{}.enabled"),
        (DictOf, "extras{}.endpoint"),
        (ListOf, "items[].enabled"),
        (Nested, "m.mode"),
        (Nested, "m.host"),
        (Optional_, "opt.enabled"),
    ]


@pytest.mark.parametrize("index", range(6))
def test_the_contract_sees_through_dicts_optionals_validators_literals_and_bare_hosts(index: int) -> None:
    model, key = _evasions()[index]
    sc = _contract()
    problems = sc.default_violations(model.model_validate({"dataDir": "/nonexistent"}))
    assert any(key in p for p in problems), (key, problems)
    assert sc.default_violations() == []


def test_the_contract_says_what_web_allowed_domains_also_governs() -> None:
    sc = _contract()
    why = sc.REVIEWED_VALUES["web.allowedDomains"]
    assert "jira" in why.lower()
    assert (
        "jira"
        in (ROOT / "docs" / "safety-contract.md")
        .read_text(encoding="utf-8")
        .split("web.allowedDomains")[1][:400]
        .lower()
    )


# --- 11. an application's version label is not an OpenShift release ------------------------------------------------


@pytest.mark.parametrize(
    ("labels", "expected"),
    [
        ({"alertname": "OrdersApiErrors", "namespace": "shop", "service": "orders-api", "version": "4.2"}, None),
        ({"alertname": "OrdersApiErrors", "namespace": "shop", "openshift_version": "4.21.3"}, "4.21.3"),
        (
            {"alertname": "ClusterOperatorDegraded", "namespace": "openshift-cluster-version", "version": "4.21.3"},
            "4.21.3",
        ),
        ({"alertname": "X", "job": "cluster-version-operator", "version": "4.20.1"}, "4.20.1"),
        ({"alertname": "X", "version": "4.20.1"}, None),
    ],
)
def test_a_version_label_counts_only_from_the_platform(
    tmp_path: Path, labels: dict[str, str], expected: str | None
) -> None:
    from kube_noob.signals import alertmanager
    from kube_noob.toolkit import AlertReportIn, DiagnoseIn

    text = json.dumps({"alerts": [{"status": "firing", "labels": labels, "annotations": {"summary": "x"}}]})
    assert alertmanager.parse(text).version == expected  # type: ignore[union-attr]
    kit = Toolkit(Settings.model_validate({"dataDir": str(tmp_path / "d"), "learningEnabled": False}))
    assert kit.diagnose(DiagnoseIn(text=text))["input"]["version"] == expected
    assert kit.alert_report(AlertReportIn(payload=text))["report"]["summary"]["version"] == expected


def test_operations_documents_499_and_hard_link_refusal() -> None:
    ops = (ROOT / "docs" / "operations.md").read_text(encoding="utf-8")
    assert "499" in ops and "408" in ops and "hard link" in ops


def test_an_alert_about_a_prometheus_pod_keeps_its_pod() -> None:
    """The neighbour of the exporter rule: prometheus-k8s and alertmanager pods are subjects, not exporters."""
    ctx = _ctx(alertname="KubePodNotReady", namespace="openshift-monitoring", pod="prometheus-k8s-1")
    assert ctx == {"ns": "openshift-monitoring", "pod": "prometheus-k8s-1", "name": "prometheus-k8s-1"}
