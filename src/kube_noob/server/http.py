"""Serve the MCP server over streamable HTTP: the OpenShift sidecar and the in-cluster service.

Kept apart from ``mcp_app`` because it reads the bearer token from the environment; the Claude plugin serves over stdio
only and ships without this module.
"""

from __future__ import annotations

import hmac
import os
from typing import Any

from mcp.server.transport_security import TransportSecuritySettings
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from kube_noob.config import Settings
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


#: A body this large is counted while it is in flight. The MCP SDK parses a call's whole body before the tool runs, so
#: an `alert_report` call waiting for one of the two report slots held its body, parsed, for up to the slot wait --
#: about 10 MB for a 1.5 MiB payload, 311 MB for twenty at once, and past the chart's 512Mi at the concurrency limit
#: of 64 (G274). Small calls, which are nearly all of them, are never counted.
LARGE_BODY_BYTES = 256 * 1024
#: Large bodies admitted at once; one more is answered 503 with Retry-After before it is read. Two report slots plus
#: the posts waiting for them, with room for a large `diagnose` or `insight` text alongside.
MAX_LARGE_BODIES = 8
BUSY_RETRY_AFTER_SECONDS = 5


def _streamed_paths() -> frozenset[str]:
    from kube_noob.server.rest import STREAMED_PATHS

    return STREAMED_PATHS


class BodyLimit:
    """Reject request bodies above ``limit`` bytes with 413 before the MCP app sees them.

    Bodies are read up front (JSON-RPC requests are small and the server answers with plain JSON), so a declared
    Content-Length or a chunked upload that exceeds the limit never reaches the application.
    """

    def __init__(self, app: ASGIApp, limit: int = MAX_BODY_BYTES) -> None:
        self.app = app
        self.limit = limit
        self._large = 0  # large bodies in flight; one event loop, so no lock

    async def _busy(self, scope: Scope, receive: Receive, send: Send) -> None:
        await JSONResponse(
            {"error": "busy: too many large requests are in progress; nothing was read, retry later"},
            status_code=503,
            headers={"Retry-After": str(BUSY_RETRY_AFTER_SECONDS)},
        )(scope, receive, send)

    async def _reject(self, scope: Scope, receive: Receive, send: Send) -> None:
        await JSONResponse({"error": "request body too large", "limitBytes": self.limit}, status_code=413)(
            scope, receive, send
        )

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
        declared = dict(scope.get("headers") or []).get(b"content-length")
        if declared is not None and declared.isdigit() and int(declared) > self.limit:
            await self._reject(scope, receive, send)
            return
        if scope.get("path") in _streamed_paths():
            # The Alertmanager receiver reads its own body, under the same limit, and only once it holds a report
            # slot: buffered here, every post waiting for its turn held up to 1.5 MiB (G274).
            await self.app(scope, receive, send)
            return
        counted = False
        if declared is not None and declared.isdigit() and int(declared) > LARGE_BODY_BYTES:
            if self._large >= MAX_LARGE_BODIES:
                await self._busy(scope, receive, send)
                return
            self._large += 1
            counted = True
        try:
            body = bytearray()
            while True:
                message = await receive()
                if message["type"] == "http.disconnect":
                    return
                body.extend(message.get("body", b""))
                if len(body) > self.limit:
                    await self._reject(scope, receive, send)
                    return
                if not counted and len(body) > LARGE_BODY_BYTES:  # a chunked upload that declared no length
                    if self._large >= MAX_LARGE_BODIES:
                        await self._busy(scope, receive, send)
                        return
                    self._large += 1
                    counted = True
                if not message.get("more_body", False):
                    break
            replayed = False

            async def replay() -> Any:
                nonlocal replayed
                if not replayed:
                    replayed = True
                    return {"type": "http.request", "body": bytes(body), "more_body": False}
                return await receive()

            await self.app(scope, replay, send)
        finally:
            if counted:
                self._large -= 1


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
    mcp = build_server(settings, shared=True, rest=security)
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
        return MetricsEndpoint(BearerAuth(BodyLimit(app), token), settings)
    return BearerAuth(MetricsEndpoint(BodyLimit(app), settings), token)
