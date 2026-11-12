"""Serve the MCP server over streamable HTTP: the OpenShift sidecar and the in-cluster service.

Kept apart from ``mcp_app`` because it reads the bearer token from the environment; the Claude plugin serves over stdio
only and ships without this module.
"""

from __future__ import annotations

import hmac
import os
import time
from typing import Any

import anyio
from mcp.server.transport_security import TransportSecuritySettings
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from kube_noob.config import Settings
from kube_noob.server import admission
from kube_noob.server.mcp_app import build_server

PUBLIC_PATHS = frozenset({"/healthz", "/readyz"})
METRICS_PATH = "/metrics"
DEFAULT_TOKEN_ENV = "KUBE_NOOB_HTTP_TOKEN"  # noqa: S105 - the variable's name, not a secret
# Every tool argument is capped at 1,000,000 characters (``toolkit.MAX_*``), so a body much above that can never be
# a valid request. The limit used to be 8 MiB, which bought nothing and cost a lot: each buffered body is copied
# again by ``request.body()`` and by ``raw.decode``, and the bracket scan over it is pure Python, which stalls the
# event loop past the kubelet's 3s probe timeout. 1.5 MiB leaves room for JSON-RPC framing and escaping around a
# maximum-length argument.
MAX_BODY_BYTES = 1536 * 1024


def _streamed_paths() -> frozenset[str]:
    from kube_noob.server.rest import STREAMED_PATHS

    return STREAMED_PATHS


def refusal(path: str, mcp_path: str | None, status: int, message: str, **extra: Any) -> JSONResponse:
    """A refusal before any tool ran. On the MCP endpoint it is a JSON-RPC error (``id`` null: the request was never
    parsed), which the MCP SDK client surfaces with its message; a plain ``{"error": ...}`` became a generic "Server
    returned an error response" there (G274). Elsewhere it is the REST error shape."""
    headers = {"Retry-After": str(admission.RETRY_AFTER_SECONDS)} if status == 503 else None
    if mcp_path is not None and path == mcp_path:
        doc = {"jsonrpc": "2.0", "id": None, "error": {"code": -32000, "message": message}}
        return JSONResponse(doc, status_code=status, headers=headers)
    return JSONResponse({"error": message, **extra}, status_code=status, headers=headers)


def too_slow_message() -> str:
    return f"the request body did not arrive within {admission.READ_SECONDS:g} s; nothing was run"


def busy_bodies_message() -> str:
    return (
        f"busy: {admission.MAX_LARGE_BODIES} large request bodies are already in memory waiting for their tools and "
        f"none was taken within {admission.READ_SECONDS:g} s; nothing was run, retry after "
        f"{admission.RETRY_AFTER_SECONDS} s"
    )


async def read_limited(
    receive: Receive, limit: int, gate: admission.LargeBodies | None, deadline: float
) -> tuple[bytes, admission.Ticket | None] | tuple[int, str]:
    """The whole body, and its large-body ticket when it is large; or ``(status, message)``: 413 past ``limit``,
    408 when the body has not arrived by ``deadline`` (``time.monotonic()``), 503 when no ticket came free by then,
    499 when the sender went away. A body becomes large only once that many bytes are in memory: a declared length
    holds nothing, so a sender that trickles holds nothing until it has sent it."""
    body = bytearray()
    ticket: admission.Ticket | None = None
    done = False
    try:
        while True:
            message: Any = {}
            with anyio.move_on_after(max(deadline - time.monotonic(), 0.0)):
                message = await receive()
            if not message:
                return 408, too_slow_message()
            if message["type"] == "http.disconnect":
                return 499, "the sender went away"
            body.extend(message.get("body", b""))
            if len(body) > limit:
                return 413, "request body too large"
            if gate is not None and ticket is None and len(body) > admission.LARGE_BODY_BYTES:
                ticket = await gate.take(deadline - time.monotonic())
                if ticket is None:
                    return 503, busy_bodies_message()
            if not message.get("more_body", False):
                done = True
                return bytes(body), ticket
    finally:
        if ticket is not None and not done:
            ticket.release()


class BodyLimit:
    """Reject request bodies above ``limit`` bytes with 413 before the MCP app sees them, refuse a body that has not
    arrived within ``admission.READ_SECONDS`` with 408, and hold a large body's ticket (``admission``) until its tool
    takes it.

    Bodies are read up front (JSON-RPC requests are small and the server answers with plain JSON), so a declared
    Content-Length or a chunked upload that exceeds the limit never reaches the application. The Alertmanager receiver
    reads its own body (``rest.STREAMED_PATHS``) under the same rules.
    """

    def __init__(
        self,
        app: ASGIApp,
        limit: int = MAX_BODY_BYTES,
        gate: admission.LargeBodies | None = None,
        mcp_path: str | None = None,
    ) -> None:
        self.app = app
        self.limit = limit
        self.gate = gate if gate is not None else admission.LargeBodies()
        self.mcp_path = mcp_path

    async def _refuse(self, scope: Scope, receive: Receive, send: Send, status: int, message: str) -> None:
        extra = {"limitBytes": self.limit} if status == 413 else {}
        await refusal(scope.get("path", ""), self.mcp_path, status, message, **extra)(scope, receive, send)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("method") not in {"POST", "PUT", "PATCH"}:
            await self.app(scope, receive, send)
            return
        # A kubelet probe sends no body, and these are the only paths an unauthenticated caller can reach. Buffering
        # one here let anything that could open the port take the pod to its memory limit: 50 connections each
        # declaring the old 8 MiB limit took the process from 96 MiB to 522 MiB, and the kernel killed it at the
        # chart's 512Mi. Refuse the body instead of reading it.
        if scope.get("path") in PUBLIC_PATHS:
            await JSONResponse({"error": "method not allowed"}, status_code=405)(scope, receive, send)
            return
        received = admission.RECEIVED.set(_report_clock())
        try:
            declared = dict(scope.get("headers") or []).get(b"content-length")
            if declared is not None and declared.isdigit() and int(declared) > self.limit:
                await self._refuse(scope, receive, send, 413, "request body too large")
                return
            if scope.get("path") in _streamed_paths():
                # The Alertmanager receiver reads its own body under the same limit, deadline and tickets
                # (``rest``), so it can take a report slot between reading and building.
                await self.app(scope, receive, send)
                return
            got = await read_limited(receive, self.limit, self.gate, time.monotonic() + admission.READ_SECONDS)
            if isinstance(got[0], int):
                status, message = got
                if status != 499:
                    await self._refuse(scope, receive, send, int(status), str(message))
                return
            body, ticket = got
            replayed = False

            async def replay() -> Any:
                nonlocal replayed
                if not replayed:
                    replayed = True
                    return {"type": "http.request", "body": body, "more_body": False}
                return await receive()

            current = admission.CURRENT.set(ticket)
            try:
                await self.app(scope, replay, send)
            finally:
                admission.CURRENT.reset(current)
                if ticket is not None:
                    ticket.release()
        finally:
            admission.RECEIVED.reset(received)


def _report_clock() -> float:
    from kube_noob.alert_report import _now

    return _now()


class MetricsEndpoint:
    """Serve `/metrics` and pass everything else through.

    Mounted INSIDE `BearerAuth`, so by default the scrape needs the same token as every other call: an
    unauthenticated endpoint on a non-loopback bind publishes which tools a team runs and how often, and the
    refusal in `http_app` exists to stop exactly that. `server.metrics.allowUnauthenticated` opts out for a mesh
    that authenticates upstream, and the chart's ServiceMonitor carries the token from the existing secret.
    """

    def __init__(self, app: ASGIApp, settings: Settings) -> None:
        self.app = app
        self.settings = settings

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("path") != METRICS_PATH:
            await self.app(scope, receive, send)
            return
        if scope.get("method") not in {"GET", "HEAD"}:
            await JSONResponse({"error": "method not allowed"}, status_code=405)(scope, receive, send)
            return
        from kube_noob.server.metrics import render

        body = render(self.settings).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [
                    (b"content-type", b"text/plain; version=0.0.4; charset=utf-8"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": b"" if scope.get("method") == "HEAD" else body})


class BearerAuth:
    """Constant-time static bearer token check for HTTP mode (health endpoints stay public for probes)."""

    def __init__(self, app: ASGIApp, token: str | None) -> None:
        self.app = app
        self.token = token.encode() if token else None

    def _refuses(self, scope: Scope) -> bool:
        if scope["type"] != "http" or self.token is None or scope.get("path") in PUBLIC_PATHS:
            return False
        # Read the header list, not a dict of it: a dict keeps the last value while a proxy in front that checks the
        # header reads the first, so "wrong, right" authenticated here and "right, wrong" did not. Two Authorization
        # headers are never a legitimate request, so neither resolution is the right one -- refuse.
        sent = [v for k, v in (scope.get("headers") or []) if k == b"authorization"]
        if len(sent) != 1:
            return True
        return not hmac.compare_digest(sent[0], b"Bearer " + self.token)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if self._refuses(scope):
            resp = JSONResponse({"error": "unauthorized"}, status_code=401, headers={"WWW-Authenticate": "Bearer"})
            await resp(scope, receive, send)
            return
        await self.app(scope, receive, send)


def http_app(settings: Settings, *, allow_unauthenticated: bool = False) -> ASGIApp:
    srv = settings.server
    token_env = srv.auth_token_env or DEFAULT_TOKEN_ENV
    token = os.environ.get(token_env) or None
    loopback = srv.host in {"127.0.0.1", "::1", "localhost"}
    if token is None and not loopback and not allow_unauthenticated:
        raise RuntimeError(
            f"Refusing to serve MCP over HTTP on {srv.host} without authentication. Set {token_env}, bind "
            "to 127.0.0.1 (sidecar mode), or pass --allow-unauthenticated if a mesh/proxy authenticates callers."
        )
    if token is not None and not loopback and not srv.allowed_hosts:
        # Remote service with bearer auth and no Host allowlist configured (e.g. `docker run` with the image's default
        # command): a DNS-rebinding page cannot attach the bearer token, so Host/Origin checks would only turn every
        # request addressed by a DNS name into a 421. Configure server.allowedHosts to re-enable them.
        security = TransportSecuritySettings(enable_dns_rebinding_protection=False)
    else:
        allowed_hosts = srv.allowed_hosts or ["127.0.0.1", "localhost", "127.0.0.1:*", "localhost:*", "[::1]:*"]
        security = TransportSecuritySettings(
            enable_dns_rebinding_protection=True, allowed_hosts=allowed_hosts, allowed_origins=srv.allowed_origins
        )
    # Over HTTP many callers share one learning file, so the tools that write it are not offered (add team notes
    # with `kube-noob learning note` in the pod instead).
    gate = admission.LargeBodies()
    mcp = build_server(settings, shared=True, rest=security, gate=gate)
    app = mcp.streamable_http_app(
        streamable_http_path=srv.path,
        transport_security=security,
        host=srv.host,
        stateless_http=True,
        json_response=True,
    )
    # Authenticate before reading any body, so a caller without the token cannot make the server buffer requests.
    # `/metrics` sits inside the authentication wrapper unless it is explicitly opened: a scrape endpoint on a
    # non-loopback bind publishes which tools a team runs and how often (N11).
    # Inside BearerAuth by default (the token is checked first, then the path), outside it only when the operator
    # has asked for that -- the order of the two wrappers IS the policy, so it is written once, here.
    if srv.metrics.allow_unauthenticated:
        return MetricsEndpoint(BearerAuth(BodyLimit(app, gate=gate, mcp_path=srv.path), token), settings)
    return BearerAuth(MetricsEndpoint(BodyLimit(app, gate=gate, mcp_path=srv.path), settings), token)
