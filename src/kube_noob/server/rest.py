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
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from kube_noob import sanitize
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
                "description": "The tool's result (always carries knowledgeAsOf)",
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
                    ("413", "Request body too large"),
                    ("500", "Internal error (details in the server log only)"),
                )
            },
        }
        ops: dict[str, Any] = {}
        for method in route.methods:
            op: dict[str, Any] = {
                "operationId": f"{method.lower()}_{spec.name}",
                "summary": route.summary or spec.title,
                "description": spec.description,
                "responses": responses,
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


def register(
    mcp: Any,
    specs: list[ToolSpec],
    call: Any,
    security: TransportSecuritySettings,
    receiver: Any = None,
) -> list[str]:
    """Add the routes to an MCPServer (``mcp.custom_route``). ``call(spec, arguments)`` runs a tool synchronously and
    returns its result or raises ``CallFailed``. ``receiver(result, started, received_at)`` finishes a receiver
    route's answer (``kube_noob.alert_store.Receiver``). Returns the paths added."""
    from kube_noob.server.mcp_app import CallFailed

    guard = TransportSecurityMiddleware(security)
    pairs = offered(specs)
    document = openapi(specs)

    def endpoint(spec: ToolSpec, route: Route) -> Any:
        async def handle(request: Request) -> Response:
            # The receipt clock starts here, before the body is read: the duration a receiver reports is the time
            # this process took from receiving the payload to having its report.
            started, received_at = time.monotonic(), dt.datetime.now(dt.UTC)
            is_post = request.method == "POST"
            refused = await guard.validate_request(request, is_post=is_post)
            if refused is not None:
                return JSONResponse({"error": bytes(refused.body).decode()}, status_code=refused.status_code)
            arguments: Any = {}
            if is_post:
                raw = await request.body()
                if raw.strip():
                    # Decode once and parse the text, never the bytes. json.loads auto-detects UTF-16 and UTF-32
                    # from a BOM or NUL pattern, so counting brackets on a UTF-8 decoding of the same bytes checked
                    # a different string from the one the parser read -- a bypass of the guard that exists because
                    # deep nesting overflows the C stack on CPython 3.14 as a fatal error, not a RecursionError.
                    try:
                        text = _decode_json_text(raw)
                    except UnicodeDecodeError:
                        return JSONResponse({"error": "the body is not JSON"}, status_code=400)
                    if not sanitize.json_nesting_ok(text):
                        return JSONResponse({"error": "the body is not JSON"}, status_code=400)
                    try:
                        arguments = json.loads(text)
                    except (ValueError, RecursionError):
                        return JSONResponse({"error": "the body is not JSON"}, status_code=400)
                    if route.body_as is not None:
                        # Somebody else's payload shape: the body is the input, not the argument map.
                        arguments = {route.body_as: text}
                    elif not isinstance(arguments, dict):
                        return JSONResponse({"error": "the body must be a JSON object"}, status_code=400)
            else:
                # Path parameters are the route's own ({id}); query parameters only those the route names.
                arguments = {k: v for k, v in request.query_params.items() if k in route.query}
                arguments.update(request.path_params)
            try:
                result = await anyio.to_thread.run_sync(call, spec, arguments)
                if route.receiver and is_post and receiver is not None:
                    result = await anyio.to_thread.run_sync(receiver, result, started, received_at)
            except CallFailed as exc:
                return JSONResponse({"error": exc.message, "outcome": exc.outcome}, status_code=exc.status)
            return JSONResponse(result)

        return handle

    for route, spec in pairs:
        mcp.custom_route(route.path, methods=list(route.methods))(endpoint(spec, route))

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
    return ["/v1", "/v1/openapi.json", *(r.path for r, _ in pairs)]
