"""Single choke point for outbound HTTP.

* ``Purpose.WEB``     - answering questions from the web. Requires ``webEnabled: true`` and every request
                        (including redirects) must target an allowlisted domain.
* ``Purpose.SOURCES`` - maintainer-run corpus builds (git/Jira ingestion). Requires ``webEnabled: true`` or an
                        explicit ``allow_sources=True`` from a CLI command the operator ran on purpose.
* ``Purpose.LLM``     - the configured model provider endpoint. Not web browsing; always permitted when an
                        LLM provider is configured. Under the offline lock every request (and no redirect, no proxy
                        from the environment) must target loopback or an in-cluster ``*.svc`` host.
* ``Purpose.CI``      - the GitHub Actions API for CI run history. Requires ``ci.githubEnabled``; GET only, https only,
                        to the configured API host only, no redirects. Under the offline lock only a loopback or
                        in-cluster ``*.svc`` host.
* ``Purpose.RHACS``   - RHACS Central's policy API. Requires ``rhacs.enabled``; GET only, https only, to the configured
                        endpoint's host and port only, no redirects. Under the offline lock only a loopback or
                        in-cluster ``*.svc`` Central, with no proxy from the environment.

No other module may construct an ``httpx`` client directly, except the in-cluster API client in
``kube_noob.debug.backends`` (ServiceAccount token, cluster CA, no redirects, no proxy), which is used only when cluster
access is enabled.
"""

from __future__ import annotations

import enum
import ssl
from urllib.parse import urlsplit

import httpx

from kube_noob import __version__
from kube_noob.config import Settings, is_local_url
from kube_noob.errors import ConfigError, DomainNotAllowedError, WebDisabledError

USER_AGENT = f"kube-noob/{__version__} (+https://github.com/kube-noob/kube-noob)"


class Purpose(enum.Enum):
    WEB = "web"
    SOURCES = "sources"
    LLM = "llm"
    RHACS = "rhacs"
    CI = "ci"


def host_allowed(host: str, allowed: list[str]) -> bool:
    host = host.lower().rstrip(".")
    return any(host == d or host.endswith("." + d) for d in allowed)


def http_client(
    settings: Settings,
    purpose: Purpose,
    *,
    allow_sources: bool = False,
    timeout: float | None = None,
    extra_headers: dict[str, str] | None = None,
    transport: httpx.BaseTransport | None = None,
) -> httpx.Client:
    if settings.offline and purpose in (Purpose.WEB, Purpose.SOURCES):
        raise WebDisabledError(
            purpose.value,
            f"Outbound access for '{purpose.value}' is blocked by the offline lock (offline: true / "
            "KUBE_NOOB_OFFLINE). kube-noob answers from local knowledge only.",
        )
    if purpose is Purpose.WEB and not settings.web_enabled:
        raise WebDisabledError("web lookup")
    if purpose is Purpose.SOURCES and not (settings.web_enabled or allow_sources):
        raise WebDisabledError("source ingestion")

    hooks: dict[str, list] = {"request": []}  # type: ignore[type-arg]
    if purpose is Purpose.WEB:
        allowed = list(settings.web.allowed_domains)

        def _guard(request: httpx.Request) -> None:
            if request.method != "GET":
                raise WebDisabledError("web lookup", f"Web access is read-only: {request.method} is not allowed (GET).")
            if request.url.scheme != "https":
                raise DomainNotAllowedError(f"{request.url.host} (non-https scheme {request.url.scheme})")
            if not host_allowed(request.url.host, allowed):
                raise DomainNotAllowedError(request.url.host)

        hooks["request"].append(_guard)

    verify: bool | ssl.SSLContext = True
    if purpose is Purpose.RHACS:
        rh = settings.rhacs
        if not (rh.enabled and rh.endpoint):
            raise WebDisabledError(
                "rhacs",
                "Reading RHACS Central is off (rhacs.enabled: false). Set rhacs.enabled: true and rhacs.endpoint, or "
                "compare an exported policy file instead.",
            )
        if settings.offline and not is_local_url(rh.endpoint):
            raise WebDisabledError(
                "rhacs",
                "The offline lock only allows a loopback or in-cluster (*.svc) RHACS Central; refused "
                f"{urlsplit(rh.endpoint).hostname}.",
            )
        central = urlsplit(rh.endpoint)
        want = (central.hostname or "").lower(), central.port or 443
        if rh.ca_file is not None:
            try:
                verify = ssl.create_default_context(cafile=str(rh.ca_file))
            except (OSError, ssl.SSLError) as exc:
                raise ConfigError(f"rhacs.caFile {rh.ca_file} is not a readable PEM bundle: {exc}") from exc

        def _central_only(request: httpx.Request) -> None:
            if request.method != "GET":
                raise WebDisabledError("rhacs", f"RHACS access is read-only: {request.method} is not allowed (GET).")
            got = request.url.host.lower(), request.url.port or 443
            if request.url.scheme != "https" or got != want:
                raise DomainNotAllowedError(f"{request.url.host} (only rhacs.endpoint {want[0]} is allowed)")

        hooks["request"].append(_central_only)

    if purpose is Purpose.CI:
        ci = settings.ci
        if not ci.github_enabled:
            raise WebDisabledError(
                "ci",
                "Reading CI history from GitHub is off (ci.githubEnabled: false). Set ci.githubEnabled: true, or "
                "analyse run folders on disk with kube-noob build analytics --history <dir>.",
            )
        if settings.offline and not is_local_url(ci.github_api_url):
            raise WebDisabledError(
                "ci",
                "The offline lock only allows a loopback or in-cluster (*.svc) GitHub API; refused "
                f"{urlsplit(ci.github_api_url).hostname}.",
            )
        api = urlsplit(ci.github_api_url)
        api_host = (api.hostname or "").lower(), api.port or 443

        def _api_only(request: httpx.Request) -> None:
            if request.method != "GET":
                raise WebDisabledError("ci", f"CI history is read-only: {request.method} is not allowed (GET).")
            got = request.url.host.lower(), request.url.port or 443
            if request.url.scheme != "https" or got != api_host:
                raise DomainNotAllowedError(f"{request.url.host} (only ci.githubApiUrl {api_host[0]} is allowed)")

        hooks["request"].append(_api_only)

    locked_llm = settings.offline and purpose is Purpose.LLM
    no_redirects = locked_llm or purpose in (Purpose.RHACS, Purpose.CI)
    no_env_proxy = settings.offline and purpose in (Purpose.LLM, Purpose.RHACS, Purpose.CI)
    if locked_llm:

        def _local_only(request: httpx.Request) -> None:
            if not is_local_url(str(request.url)):
                raise WebDisabledError(
                    "llm",
                    f"The offline lock only allows model endpoints on loopback or inside the cluster (*.svc); "
                    f"refused {request.url.host}.",
                )

        hooks["request"].append(_local_only)

    headers = {"User-Agent": USER_AGENT}
    if extra_headers:
        headers.update(extra_headers)
    return httpx.Client(
        timeout=timeout if timeout is not None else settings.web.timeout_seconds,
        follow_redirects=not no_redirects,
        max_redirects=5,
        headers=headers,
        event_hooks=hooks,
        transport=transport,
        trust_env=not no_env_proxy,
        verify=verify,
    )
