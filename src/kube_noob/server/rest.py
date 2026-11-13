"""REST routes on the HTTP server (backlog I6): plain JSON in and out for callers that do not speak MCP (CI jobs,
scripts, chat bots, a console plugin). Each route runs the same toolkit tool as MCP, with the same validation,
sanitising, ``knowledgeAsOf`` and content-free audit line; the routes exist only for the tools this server offers
(a shared server offers no tool that writes).

Security: behind the HTTP server's bearer token and body limit (``kube_noob.server.http``); every request passes the
MCP transport's Host and Origin checks (DNS rebinding) and a POST must be ``application/json`` (a cross-site form or
``text/plain`` post never reaches a tool). ``GET /v1/openapi.json`` describes the routes; the document is generated
from the tools' models, and ``docs/api/openapi.json`` is kept equal to it by a test.
"""

from __future__ import annotations

import datetime as dt
import json
import re
import time
from dataclasses import dataclass
from typing import Any

import anyio
from mcp.server.transport_security import TransportSecurityMiddleware, TransportSecuritySettings
from pydantic.json_schema import models_json_schema
from starlette.requests import ClientDisconnect, Request
from starlette.responses import JSONResponse, Response

from kube_noob import alert_report, sanitize
from kube_noob.toolkit import ToolSpec

API_VERSION = "1.1.0"  # the contract's version, not the package's: it changes only when a route or a body changes


@dataclass(frozen=True)
class Route:
    path: str
    tool: str
    methods: tuple[str, ...] = ("POST",)
    summary: str = ""
    #: When set, the whole request body becomes this ONE argument rather than being read as the argument map.
    #: Needed for a route that receives somebody else's payload shape: Alertmanager posts
    #: `{"receiver": ..., "status": ..., "alerts": [...]}`, which is not a kube-noob argument map and would be
    #: refused by the tool's `extra=forbid` model. The payload IS the text to analyse, so it is passed as one
    #: (N11): that is what makes this an Alertmanager receiver rather than a documented shape to reformat by hand.
    body_as: str | None = None
    #: Query parameters a GET passes to the tool as arguments. Only these: an existing GET route ignores its query
    #: string, and turning that into a 400 for callers that send one would be a contract change.
    query: tuple[str, ...] = ()
    #: The Alertmanager receiver: after the tool has built the report, the server stamps the receipt (id, times,
    #: the receipt-to-report duration) and keeps the record (``kube_noob.alert_store.Receiver``).
    receiver: bool = False


_PATH_PARAM = re.compile(r"\{([a-z_]+)\}")


ROUTES: tuple[Route, ...] = (
    Route("/v1/insight", "insight", summary="Paste anything: recognised, routed to every analyser, one answer"),
    Route("/v1/diagnose", "diagnose", summary="Diagnose an error, events or logs: cause and read-only steps first"),
    Route("/v1/audit", "audit_manifests", summary="Audit manifests against the rules for a platform and version"),
    Route("/v1/known-issues", "known_issues", summary="Reported OpenShift bugs that match a text, with fix versions"),
    Route("/v1/upgrade-risks", "upgrade_risks", summary="Risks Red Hat declares for an OpenShift update, offline"),
    Route("/v1/policy/reach", "check_network_policy", summary="Can pod A reach pod B under these NetworkPolicies?"),
    Route(
        "/v1/policy/migrate-check",
        "policy_migrate_check",
        summary="Lint legacy Kyverno policies for the CEL types: drafts and kyverno test skeletons, never applied",
    ),
    Route("/v1/memory/match", "memory_match", summary="Your team's approved memory entries for an error"),
    Route("/v1/reports", "posture_report", ("GET", "POST"), summary="The newest daily drift and policy report"),
    Route("/v1/must-gather", "analyze_must_gather", summary="What is wrong in a must-gather on the server's volume"),
    Route(
        "/v1/alerts",
        "extract_signals",
        summary="Alertmanager webhook receiver: post the payload, get the signals it carries",
        body_as="text",
    ),
    # A path of its own rather than /v1/reports/<id>: /v1/reports is the daily posture report (GET returns the newest
    # one), and a list under it would make one public path answer two unrelated questions.
    Route(
        "/v1/alert-reports",
        "alert_report",
        summary="Alertmanager webhook receiver: post the payload, get (and keep) an evidence report per alert",
        body_as="payload",
        receiver=True,
    ),
    Route(
        "/v1/alert-reports",
        "alert_report_list",
        ("GET",),
        summary="The newest stored alert reports: ids, times, alert names and verdicts",
        query=("limit",),
    ),
    Route("/v1/alert-reports/{id}", "alert_report_get", ("GET",), summary="One stored alert report by its id"),
)
PAYLOAD_SCHEMA = {
    "description": "An Alertmanager webhook body (version 4: receiver, status, commonLabels, alerts[] with status, "
    "labels and annotations), the Alertmanager API v2 alert list, or Prometheus's /api/v1/alerts, as JSON. Read "
    "bounded: 500 alerts, 64 labels, 2,000 characters a value, control characters dropped; the server's body limit "
    "is 1.5 MiB. Sources: https://prometheus.io/docs/alerting/latest/configuration/#webhook_config and "
    "https://github.com/prometheus/alertmanager/blob/main/api/v2/openapi.yaml",
    "type": ["object", "array"],
}
ERROR_SCHEMA = {
    "type": "object",
    "properties": {"error": {"type": "string"}, "outcome": {"type": "string"}},
    "required": ["error"],
}


def offered(specs: list[ToolSpec]) -> list[tuple[Route, ToolSpec]]:
    by_name = {s.name: s for s in specs}
    return [(r, by_name[r.tool]) for r in ROUTES if r.tool in by_name]


def full_document() -> dict[str, Any]:
    """The document with every route offered (memory and must-gather configured): ``docs/api/openapi.json``."""
    from kube_noob.config import Settings
    from kube_noob.toolkit import Toolkit

    # Settings from these values alone (no config file, no environment): the document does not depend on the machine
    settings = Settings.model_validate(
        {"memory": {"paths": ["/srv/kube-noob/memory"]}, "mustGather": {"allowedDir": "/srv/kube-noob/must-gather"}}
    )
    return openapi(Toolkit(settings, shared=True).specs())


def _decode_json_text(raw: bytes) -> str:
    """The body as the one string both the nesting guard and the parser see.

    ``json.loads`` accepts bytes and sniffs the encoding (RFC 8259 allows UTF-8, UTF-16 and UTF-32, and CPython
    detects a BOM or the NUL pattern of a wide encoding). A caller sending UTF-16 is legitimate, so the body is
    decoded with the same rule rather than refused -- and then only the decoded text is used.
    """
    if raw[:3] == b"\xef\xbb\xbf":
        return raw[3:].decode("utf-8")
    if raw[:4] in (b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff"):
        return raw.decode("utf-32")
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16")
    # No BOM: CPython's own detection reads the NUL pattern of the first four bytes.
    if len(raw) >= 4 and raw[0] == 0 and raw[1] == 0 and raw[2] == 0:
        return raw.decode("utf-32-be")
    if len(raw) >= 4 and raw[1] == 0 and raw[2] == 0 and raw[3] == 0:
        return raw.decode("utf-32-le")
    if len(raw) >= 2 and raw[0] == 0:
        return raw.decode("utf-16-be")
    if len(raw) >= 2 and raw[1] == 0:
        return raw.decode("utf-16-le")
    return raw.decode("utf-8")


def openapi(specs: list[ToolSpec]) -> dict[str, Any]:
    """OpenAPI 3.1 for the routes these specs offer; request bodies are the tools' own JSON Schemas."""
    pairs = offered(specs)
    keys, defs = models_json_schema(
        [(spec.model, "validation") for _, spec in pairs], ref_template="#/components/schemas/{model}"
    )
    schemas: dict[str, Any] = dict(defs.get("$defs", {}))
    schemas["Error"] = ERROR_SCHEMA
    paths: dict[str, Any] = {}
    for route, spec in pairs:
        body = keys[(spec.model, "validation")]
        responses = {
            "200": {
                "description": (
                    "The receiver's record: id, receivedAt, durationSeconds (receipt to report), bodySha256, stored "
                    "and, when it was not kept, notStoredReason; the report itself under report; knowledgeAsOf"
                    if route.receiver
                    else "The tool's result (always carries knowledgeAsOf)"
                ),
                "content": {"application/json": {"schema": {"type": "object", "additionalProperties": True}}},
            },
            **{
                code: {
                    "description": why,
                    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}},
                }
                for code, why in (
                    ("400", "Invalid arguments, or the tool refused the input"),
                    ("401", "No or wrong bearer token"),
                    ("404", "Unknown id"),
                    ("403", "Origin not allowed (the transport's DNS-rebinding check)"),
                    ("405", "Method not allowed; the Allow header names the ones served on this path"),
                    ("413", "Request body too large"),
                    ("421", "Host not allowed (server.allowedHosts)"),
                    ("500", "Internal error, or kube-noob's own stored data is damaged (the message says which)"),
                )
            },
        }
        error = {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}
        busy = (
            "Busy: all report slots were in use by reports being built and none came free within the wait (at most "
            "5 s), or too many large bodies were already waiting in memory; nothing was kept. Retry after the "
            "Retry-After header"
            if route.receiver
            else "Busy: too many large request bodies (over 256 KiB) were already waiting in memory and none was taken "
            "within the read deadline; nothing was run. Retry after the Retry-After header"
        )
        post_only = {
            "408": {"description": "The request body did not arrive within the read deadline (10 s)", "content": error},
            "499": {"description": "The sender went away before the answer; no body is sent and nothing was kept"},
            "503": {"description": busy, "content": error},
        }
        ops: dict[str, Any] = {}
        for method in route.methods:
            op: dict[str, Any] = {
                "operationId": f"{method.lower()}_{spec.name}",
                "summary": route.summary or spec.title,
                "description": spec.description,
                "responses": {**responses, **post_only} if method == "POST" else responses,
            }
            if method == "POST" and route.body_as is not None:
                # The body is Alertmanager's own payload, passed whole as one argument: describing it as the tool's
                # argument map (`{"text": ...}`) told a client to send a shape the route does not take.
                schemas["AlertmanagerPayload"] = PAYLOAD_SCHEMA
                ref = {"$ref": "#/components/schemas/AlertmanagerPayload"}
                op["requestBody"] = {"required": True, "content": {"application/json": {"schema": ref}}}
            elif method == "POST":
                op["requestBody"] = {"required": True, "content": {"application/json": {"schema": body}}}
            elif _PATH_PARAM.search(route.path) or route.query:
                op["parameters"] = _parameters(spec, route)
            ops[method.lower()] = op
        # Two routes can share a path with different methods (POST and GET /v1/alert-reports).
        paths.setdefault(route.path, {}).update(ops)
    return {
        "openapi": "3.1.0",
        "info": {
            "title": "kube-noob REST API",
            "version": API_VERSION,
            "description": "The kube-noob tools as JSON over HTTP, beside MCP. Bearer token as for MCP.",
        },
        "components": {
            "schemas": schemas,
            "securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}},
        },
        "security": [{"bearer": []}],
        "paths": paths,
    }


def _parameters(spec: ToolSpec, route: Route) -> list[dict[str, Any]]:
    props = spec.model.model_json_schema().get("properties", {})
    out = [
        {"name": name, "in": "path", "required": True, "schema": props[name]}
        for name in _PATH_PARAM.findall(route.path)
    ]
    out += [{"name": name, "in": "query", "required": False, "schema": props[name]} for name in route.query]
    return out


#: Alert reports built at once, by the receiver and the MCP tool together (``alert_report.Slots``, G274).
MAX_CONCURRENT_REPORTS = alert_report.MAX_CONCURRENT_REPORTS
#: Paths whose POST body the HTTP layer does not buffer up front (``kube_noob.server.http.BodyLimit``): the receiver
#: reads it itself, under the same limit, read deadline and large-body tickets, so that it can take a report slot
#: between reading the body and building the report -- never before reading it: a slot taken first and held while a
#: sender trickled let two slow senders refuse every alert for as long as they trickled (G274).
STREAMED_PATHS = frozenset(r.path for r in ROUTES if r.receiver)


class _Refused(Exception):
    """A request body that never reaches a tool: the message is safe to show the caller."""

    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.message, self.status = message, status


def _arguments_from_body(raw: bytes, route: Route) -> Any:
    """The tool's arguments from a POST body. Runs in a worker thread: decoding, the nesting scan (pure Python) and
    the parse of a 1.5 MiB body took the event loop long enough to stall /healthz behind one post (G274)."""
    if not raw.strip():
        return {}
    # Decode once and parse the text, never the bytes. json.loads auto-detects UTF-16 and UTF-32 from a BOM or NUL
    # pattern, so counting brackets on a UTF-8 decoding of the same bytes checked a different string from the one the
    # parser read -- a bypass of the guard that exists because deep nesting overflows the C stack on CPython 3.14 as
    # a fatal error, not a RecursionError.
    try:
        text = _decode_json_text(raw)
    except UnicodeDecodeError:
        raise _Refused("the body is not JSON") from None
    if not sanitize.json_nesting_ok(text):
        raise _Refused("the body is not JSON")
    try:
        arguments = json.loads(text)
    except (ValueError, RecursionError):
        raise _Refused("the body is not JSON") from None
    if route.body_as is not None:
        # Somebody else's payload shape: the body is the input, not the argument map.
        return {route.body_as: text}
    if not isinstance(arguments, dict):
        raise _Refused("the body must be a JSON object")
    return arguments


def _failed(exc: Any) -> Response:
    headers = {"Retry-After": str(alert_report.RETRY_AFTER_SECONDS)} if exc.status == 503 else None
    return JSONResponse({"error": exc.message, "outcome": exc.outcome}, status_code=exc.status, headers=headers)


def _render(result: Any) -> bytes:
    """What JSONResponse renders, made in a worker thread: a report is up to a megabyte of JSON."""
    return json.dumps(result, ensure_ascii=False, allow_nan=False, indent=None, separators=(",", ":")).encode("utf-8")


def register(
    mcp: Any,
    specs: list[ToolSpec],
    call: Any,
    security: TransportSecuritySettings,
    receiver: Any = None,
    reports: Any = None,
    gate: Any = None,
) -> list[str]:
    """Add the routes to an MCPServer (``mcp.custom_route``). ``call(spec, arguments)`` runs a tool synchronously and
    returns its result or raises ``CallFailed``. ``receiver(result, started, received_at)`` finishes a receiver
    route's answer (``kube_noob.alert_store.Receiver``). ``reports`` is the Toolkit whose ``report_slots`` the receiver
    shares with the MCP tool: a post's body is read first (within ``admission.READ_SECONDS``, else 408, holding a
    large-body ticket from ``gate`` while it is large), then it takes a slot, is refused with 503 and ``Retry-After``
    when none comes free within ``report_wait_seconds()``, and is dropped unbuilt and unstored if its client has gone
    by the time it would start or be kept. Returns the paths added.

    Routes that share a path are served by one handler, so a method that is not served gets 405 with an ``Allow``
    header naming every method that is (two handlers each answered for their own method only). Everything that costs
    time -- reading the body, the tool, rendering the answer -- runs in worker threads, never on the event loop."""
    from kube_noob.server import admission, metrics
    from kube_noob.server.http import MAX_BODY_BYTES, read_limited, refusal
    from kube_noob.server.mcp_app import CallFailed

    large = gate if gate is not None else admission.LargeBodies()

    guard = TransportSecurityMiddleware(security)
    pairs = offered(specs)
    document = openapi(specs)
    by_path: dict[str, dict[str, tuple[Route, ToolSpec]]] = {}
    for route, spec in pairs:
        for method in route.methods:
            by_path.setdefault(route.path, {})[method] = (route, spec)

    def endpoint(methods: dict[str, tuple[Route, ToolSpec]]) -> Any:
        async def handle(request: Request) -> Response:
            # The receipt clocks start here, before the body is read: the duration a receiver reports, and the time
            # budget of the report, both count from receiving the payload.
            started, received_at = time.monotonic(), dt.datetime.now(dt.UTC)
            received = admission.RECEIVED.get()
            received = received if received is not None else alert_report._now()
            route, spec = methods["GET" if request.method == "HEAD" else request.method]
            is_post = request.method == "POST"
            refused = await guard.validate_request(request, is_post=is_post)
            if refused is not None:
                return refused
            if route.receiver and is_post and reports is not None:
                return await report(request, route, spec, started, received_at, received)
            return await answer(request, route, spec, started, received_at)

        return handle

    async def gone(request: Request) -> Response | None:
        """The answer for a post whose sender has gone, or None. Alertmanager gives up on a slow receiver and
        resends; building and storing the abandoned copy would spend a slot on nobody and keep a duplicate."""
        if await request.is_disconnected():
            metrics.REGISTRY.alert_report_dropped("client-gone")
            return Response(status_code=499)
        return None

    async def report(
        request: Request, route: Route, spec: ToolSpec, started: float, received_at: dt.datetime, received: float
    ) -> Response:
        """The Alertmanager receiver: read the body (bounded in size and time), then take a report slot, then
        build -- so a slot is only ever held by a report being built."""
        budget = float(reports.settings.alert_reports.budget_seconds)
        deadline = time.monotonic() + min(admission.READ_SECONDS, budget)
        got = await read_limited(request.receive, MAX_BODY_BYTES, large, deadline)
        if isinstance(got[0], int):
            status, message = int(got[0]), str(got[1])
            if status == 499:
                metrics.REGISTRY.alert_report_dropped("client-gone")
                return Response(status_code=499)
            if status == 503:
                metrics.REGISTRY.alert_report_dropped("busy")
            extra = {"limitBytes": MAX_BODY_BYTES} if status == 413 else {}
            return refusal(request.url.path, None, status, message, **extra)
        raw, ticket = got
        try:
            try:
                arguments = await anyio.to_thread.run_sync(_arguments_from_body, raw, route)
            except _Refused as exc:
                return JSONResponse({"error": exc.message}, status_code=exc.status)
            del raw
            wait = reports.report_wait_seconds()
            if not await admission.take_slot(reports.report_slots, wait):
                metrics.REGISTRY.alert_report_dropped("busy")
                return JSONResponse(
                    {"error": alert_report.busy_message(wait), "outcome": "busy"},
                    status_code=503,
                    headers={"Retry-After": str(alert_report.RETRY_AFTER_SECONDS)},
                )
        finally:
            # Held while the body waited for its slot; a report being built is bounded by the slots themselves.
            if ticket is not None:
                ticket.release()
        try:
            if (left := await gone(request)) is not None:
                return left

            def run() -> Any:
                with reports.report_admission(received):
                    return call(spec, arguments)

            try:
                result = await anyio.to_thread.run_sync(run)
                if receiver is not None:
                    if (left := await gone(request)) is not None:
                        return left
                    result = await anyio.to_thread.run_sync(receiver, result, started, received_at)
            except CallFailed as exc:
                return _failed(exc)
            body = await anyio.to_thread.run_sync(_render, result)
            return Response(content=body, media_type="application/json")
        finally:
            reports.report_slots.release()

    async def answer(
        request: Request, route: Route, spec: ToolSpec, started: float, received_at: dt.datetime
    ) -> Response:
        arguments: Any = {}
        if request.method == "POST":
            try:
                raw = await request.body()
                arguments = await anyio.to_thread.run_sync(_arguments_from_body, raw, route)
            except _Refused as exc:
                return JSONResponse({"error": exc.message}, status_code=exc.status)
            except ClientDisconnect:
                return Response(status_code=499)
            del raw
            admission.release_current()  # the tool has the body now: its large-body ticket is free for the next one
        else:
            # Path parameters are the route's own ({id}); query parameters only those the route names.
            arguments = {k: v for k, v in request.query_params.items() if k in route.query}
            arguments.update(request.path_params)
        try:
            result = await anyio.to_thread.run_sync(call, spec, arguments)
            if route.receiver and request.method == "POST" and receiver is not None:
                result = await anyio.to_thread.run_sync(receiver, result, started, received_at)
        except CallFailed as exc:
            return _failed(exc)
        body = await anyio.to_thread.run_sync(_render, result)
        return Response(content=body, media_type="application/json")

    for path, methods in by_path.items():
        mcp.custom_route(path, methods=sorted(methods))(endpoint(methods))

    async def describe(request: Request) -> Response:
        refused = await guard.validate_request(request)
        if refused is not None:
            return JSONResponse({"error": bytes(refused.body).decode()}, status_code=refused.status_code)
        if request.url.path.endswith("openapi.json"):
            return JSONResponse(document)
        return JSONResponse(
            {"routes": [{"path": r.path, "methods": list(r.methods), "tool": s.name} for r, s in pairs]}
        )

    mcp.custom_route("/v1", methods=["GET"])(describe)
    mcp.custom_route("/v1/openapi.json", methods=["GET"])(describe)
    return ["/v1", "/v1/openapi.json", *by_path]
