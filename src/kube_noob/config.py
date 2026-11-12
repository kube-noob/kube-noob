"""Configuration.

Precedence (lowest -> highest): built-in defaults < config file < environment variables < explicit
overrides passed by the CLI.

Config file lookup order: ``--config``, ``$KUBE_NOOB_CONFIG``, ``$XDG_CONFIG_HOME/kube-noob/config.yaml``
(``~/.config/kube-noob/config.yaml``), ``/etc/kube-noob/config.yaml`` (the path the Helm chart mounts).

The current directory is deliberately NOT searched: a ``kube-noob.yaml`` inside a cloned repository could otherwise
enable web/cluster access or point the agent's API key at an attacker's endpoint. Pass ``--config ./kube-noob.yaml``
to use a project file explicitly.

Keys are camelCase in YAML (``webEnabled: true``) and snake_case in Python.

``offline: true`` (or ``KUBE_NOOB_OFFLINE=1``) is an admin lock, not a default: it overrides ``webEnabled``, blocks
corpus downloads and allows only local model endpoints, and no later source in the chain can lift it.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
from pathlib import Path
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator
from pydantic.alias_generators import to_camel

from kube_noob.errors import ConfigError

_log = logging.getLogger("kube_noob.config")

DEFAULT_ALLOWED_DOMAINS: tuple[str, ...] = (
    "kubernetes.io",
    "helm.sh",
    "docs.redhat.com",
    "docs.openshift.com",
    "access.redhat.com",
    "cloud.redhat.com",
    "developers.redhat.com",
    "redhat.atlassian.net",
    "docs.aws.amazon.com",
    "github.com",
    "raw.githubusercontent.com",
    "stackrox.io",
    "www.stackrox.io",
    "gateway-api.sigs.k8s.io",
    "kind.sigs.k8s.io",
)

DEFAULT_MODEL = "claude-fable-5-1"


class _Base(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, extra="forbid")


class WebSettings(_Base):
    allowed_domains: list[str] = Field(default_factory=lambda: list(DEFAULT_ALLOWED_DOMAINS))
    timeout_seconds: float = Field(default=20.0, gt=0, le=120)
    max_bytes: int = Field(default=2_000_000, gt=0, le=20_000_000)

    @field_validator("allowed_domains")
    @classmethod
    def _lower(cls, v: list[str]) -> list[str]:
        cleaned = []
        for raw in v:
            d = raw.strip().lower()
            if not d:
                continue
            # Entries already match their subdomains, so '*.example.com' means 'example.com'.
            d = d.removeprefix("*.").lstrip(".")
            if "/" in d or ":" in d or " " in d or "*" in d or "." not in d:
                raise ValueError(f"allowedDomains entries must be bare host names like 'docs.redhat.com', got {raw!r}")
            cleaned.append(d)
        return cleaned


class ClusterSettings(_Base):
    enabled: bool = False
    backend: Literal["auto", "in-cluster", "kubectl", "oc"] = "auto"
    context: str | None = None
    timeout_seconds: float = Field(default=20.0, gt=0, le=120)
    max_log_lines: int = Field(default=200, ge=1, le=5000)


# apiKeyEnv may only name a model provider's key variable (ending in _API_KEY), so a configuration file cannot point
# the model client at an unrelated variable - above all not at the HTTP service's own bearer token (server.authTokenEnv
# and its default), which the same process holds and which a model endpoint has no business receiving. The default per
# provider is set in kube_noob.agent.providers, which is the only code that reads it, and there is no default for an
# endpoint kube-noob did not choose.
_KEY_VAR = re.compile(r"^[A-Z][A-Z0-9_]*_API_KEY\Z")
_CLUSTER_LOCAL_SUFFIXES = (".svc", ".svc.cluster.local", ".local", ".internal")


_LOCK_LOCAL_SUFFIXES = (".svc", ".svc.cluster.local")


def is_local_url(url: str | None) -> bool:
    """Endpoints the offline lock allows: loopback, ``localhost`` or an in-cluster Service (``*.svc``,
    ``*.svc.cluster.local``). Deliberately narrower than ``_CLUSTER_LOCAL_SUFFIXES``: ``*.internal`` and ``*.local``
    can resolve to corporate or cloud-metadata hosts outside the cluster."""
    if not url:
        return False
    host = (urlsplit(url).hostname or "").lower().rstrip(".")
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host == "localhost" or host.endswith(_LOCK_LOCAL_SUFFIXES)


def check_endpoint(base_url: str | None, allow_insecure: bool, what: str) -> None:
    """Reject an endpoint that would carry the API key in clear text or embed credentials in the URL. Public so the
    providers can hold a base URL that arrived from the environment to the same rule as one from the config file."""
    if base_url is None:
        return
    parts = urlsplit(base_url)
    if parts.scheme not in {"https", "http"} or not parts.hostname:
        raise ValueError(f"{what}.baseUrl must be an http(s) URL with a host, got {base_url!r}")
    if parts.username or parts.password:
        raise ValueError(f"{what}.baseUrl must not embed credentials; use apiKeyEnv")
    if parts.scheme == "http" and not allow_insecure:
        host = parts.hostname.lower()
        try:
            local = ipaddress.ip_address(host).is_loopback
        except ValueError:
            local = host == "localhost" or host.endswith(_CLUSTER_LOCAL_SUFFIXES)
        if not local:
            raise ValueError(
                f"{what}.baseUrl {base_url!r} uses plain http to a non-local host: the API key would travel in "
                "clear text. Use https, a loopback / cluster-local (*.svc) endpoint, or set "
                f"{what}.allowInsecureBaseUrl: true."
            )


class _LLMEndpoint(_Base):
    base_url: str | None = None
    api_key_env: str | None = None
    allow_insecure_base_url: bool = False

    @field_validator("api_key_env")
    @classmethod
    def _key_env(cls, v: str | None) -> str | None:
        if v is not None and not _KEY_VAR.match(v):
            raise ValueError(f"apiKeyEnv {v!r} must name a model provider key variable (*_API_KEY)")
        return v


class LLMSettings(_LLMEndpoint):
    # Only `kube-noob ask`, `train bench` and the eval judge use a model; nothing does until you choose one.
    provider: Literal["anthropic", "openai-compatible", "none"] = "none"
    model: str = DEFAULT_MODEL
    max_tokens: int = Field(default=4096, ge=256, le=64000)
    max_tool_rounds: int = Field(default=12, ge=1, le=50)
    timeout_seconds: float = Field(default=120.0, gt=0, le=900)

    @model_validator(mode="after")
    def _endpoint(self) -> LLMSettings:
        check_endpoint(self.base_url, self.allow_insecure_base_url, "llm")
        return self


class JudgeSettings(_LLMEndpoint):
    """Optional LLM judge. Eval-only: judge outputs are never exported as training labels by default."""

    provider: Literal["none", "anthropic", "openai-compatible"] = "none"
    model: str = DEFAULT_MODEL

    @model_validator(mode="after")
    def _endpoint(self) -> JudgeSettings:
        check_endpoint(self.base_url, self.allow_insecure_base_url, "judge")
        return self


class WatchSettings(_Base):
    """Always-on incident watch (``kube-noob watch``, ``kube-noob serve`` with ``enabled``). Read-only."""

    enabled: bool = False
    interval_seconds: int = Field(default=60, ge=15, le=3600)
    namespaces: list[str] = Field(default_factory=list, max_length=50)  # empty: the pod's own namespace
    resolve_after_polls: int = Field(default=3, ge=1, le=100)
    retention_days: int = Field(default=30, ge=1, le=365)

    @field_validator("namespaces")
    @classmethod
    def _dns_names(cls, v: list[str]) -> list[str]:
        bad = [n for n in v if not re.fullmatch(r"[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?", n)]
        if bad:
            raise ValueError(f"watch.namespaces must be namespace names: {bad}")
        return v


class AlertReportSettings(_Base):
    """Evidence reports the HTTP server keeps for the Alertmanager payloads posted to ``POST /v1/alert-reports``.

    Written by ``kube-noob serve`` only (never by a tool, the CLI or the stdio server) into ``<dataDir>/alert-reports``,
    owner-only and atomically, never through a symbolic link. Retention is bounded twice: the newest ``maxReports``
    are kept and anything older than ``maxAgeDays`` goes, oldest first. A report larger than ``maxReportBytes`` keeps
    every alert's row (name, state, verdict) and drops detail from resolved and low-severity alerts first, naming them.
    A payload gets ``budgetSeconds`` at most; alerts not reached are kept as ``not-evaluated``. ``store: false``
    keeps nothing: the POST still answers with the report and ``stored: false``."""

    store: bool = True
    max_reports: int = Field(default=200, ge=1, le=5000)
    max_age_days: int = Field(default=14, ge=1, le=365)
    max_report_bytes: int = Field(default=1_048_576, ge=262_144, le=8_388_608)
    #: Seconds one payload may spend being reported. Alerts not reached by then keep a `not-evaluated` row and are
    #: counted, so a sender cannot hold the server for longer than this with one post (G274).
    budget_seconds: int = Field(default=30, ge=1, le=300)


class PostureSettings(_Base):
    """Daily drift and policy report (``kube-noob serve`` with ``report_enabled``; ``kube-noob posture report``).

    Read-only: one live snapshot a day (a random first delay, then every 24 h +/- 10%), diffed against the previous one
    in ``<dataDir>/posture``; the newest ``keep`` snapshots and their reports are kept."""

    report_enabled: bool = False
    namespaces: list[str] = Field(default_factory=list, max_length=50)  # empty: every namespace the account can list
    keep: int = Field(default=14, ge=1, le=365)

    @field_validator("namespaces")
    @classmethod
    def _dns_names(cls, v: list[str]) -> list[str]:
        bad = [n for n in v if not re.fullmatch(r"[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?", n)]
        if bad:
            raise ValueError(f"posture.namespaces must be namespace names: {bad}")
        return v


# rhacs.tokenEnv may only name a KUBE_NOOB_* variable (unset: the variable the RHACS CLI reads), so a configuration
# file cannot make kube-noob send an unrelated variable to Central.
_RHACS_TOKEN_VAR = re.compile(r"^KUBE_NOOB_[A-Z0-9_]+\Z")


class RhacsSettings(_Base):
    """Read RHACS Central's policies for ``kube-noob rhacs compare --live`` and the ``rhacs_compare_live`` tool.

    Off by default. GET only, to ``endpoint``'s host only, no redirects; the token comes from ``tokenEnv`` (unset: the
    RHACS CLI's API token variable) and is sent only to that host. Under the offline lock only a loopback or
    in-cluster ``*.svc`` Central is allowed."""

    enabled: bool = False
    endpoint: str | None = None  # https://central.stackrox.svc or https://central-stackrox.apps.example.com
    token_env: str | None = None
    ca_file: Path | None = None  # PEM bundle for Central's certificate (default: the system trust store)
    max_policies: int = Field(default=500, ge=1, le=2000)

    @field_validator("endpoint")
    @classmethod
    def _https_root(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip().rstrip("/")
        parts = urlsplit(v)
        if parts.scheme != "https" or not parts.hostname:
            raise ValueError(f"rhacs.endpoint must be an https:// URL with a host, got {v!r}")
        if parts.username or parts.password or parts.path or parts.query or parts.fragment:
            raise ValueError("rhacs.endpoint must be Central's root (https://host[:port]) without credentials or path")
        return v

    @field_validator("token_env")
    @classmethod
    def _token_var(cls, v: str | None) -> str | None:
        if v is not None and not _RHACS_TOKEN_VAR.match(v):
            raise ValueError(
                f"rhacs.tokenEnv {v!r} must be a KUBE_NOOB_* variable; leave it unset to use the RHACS CLI's token "
                "variable"
            )
        return v

    @field_validator("ca_file")
    @classmethod
    def _expand_ca(cls, v: Path | None) -> Path | None:
        return v.expanduser() if v is not None else None

    @model_validator(mode="after")
    def _endpoint_when_enabled(self) -> RhacsSettings:
        if self.enabled and not self.endpoint:
            raise ValueError("rhacs.enabled needs rhacs.endpoint (Central's https:// root)")
        return self


class CiSettings(_Base):
    """Read CI run history from the GitHub Actions API for ``kube-noob build history`` (R4.4). Off by default.

    GET only, to ``githubApiUrl``'s host only, no redirects, a random pause between requests; the token comes from
    ``githubTokenEnv`` (a KUBE_NOOB_* variable; unset: the variable the GitHub CLI reads). Under the offline lock only
    a loopback or in-cluster ``*.svc`` API (GitHub Enterprise Server behind a Service) is allowed."""

    github_enabled: bool = False
    github_api_url: str = "https://api.github.com"
    github_token_env: str | None = None
    max_runs: int = Field(default=200, ge=1, le=2000)

    @field_validator("github_api_url")
    @classmethod
    def _api_root(cls, v: str) -> str:
        v = v.strip().rstrip("/")
        parts = urlsplit(v)
        if parts.scheme != "https" or not parts.hostname or parts.username or parts.password or parts.query:
            raise ValueError(f"ci.githubApiUrl must be an https:// URL without credentials or query, got {v!r}")
        if parts.path not in {"", "/api/v3"}:
            raise ValueError(
                "ci.githubApiUrl must be https://api.github.com or a GitHub Enterprise https://<host>/api/v3"
            )
        return v

    @field_validator("github_token_env")
    @classmethod
    def _gh_token_var(cls, v: str | None) -> str | None:
        if v is not None and not _RHACS_TOKEN_VAR.match(v):
            raise ValueError(f"ci.githubTokenEnv {v!r} must be a KUBE_NOOB_* variable; leave it unset for the default")
        return v


_RULE_ID = r"^KN-[A-Z]{1,2}\d{3}$"
_NAMESPACE = r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$"


class AdmissionSettings(_Base):
    """The ``kube-noob admission serve`` webhook (R3.3, tier A). Warnings only unless a rule is listed in
    ``enforce``; the system namespaces are always excluded; rules that need other objects run only with ``lookups``
    (which needs ``cluster.enabled``) and are never enforced."""

    enforce: list[Annotated[str, Field(pattern=_RULE_ID)]] = Field(default_factory=list, max_length=100)
    excluded_namespaces: list[Annotated[str, Field(pattern=_NAMESPACE)]] = Field(default_factory=list, max_length=200)
    exceptions_file: Path | None = None
    lookups: bool = False
    max_warnings: int = Field(default=10, ge=1, le=50)
    version: str | None = Field(default=None, pattern=r"^\d+\.\d+(\.\d+)?$")


class ProbeSettings(_Base):
    """Tier P: ephemeral debug containers or probe Jobs. Off by default; every probe needs an approval."""

    enabled: bool = False


class DryRunSettings(_Base):
    """Tier D: server-side dry-run of manifests (``?dryRun=All``). Off by default; every request needs an approval."""

    enabled: bool = False


class ItsmSettings(_Base):
    """Tier W: attach evidence to tickets in an external ITSM system. Off by default."""

    write_enabled: bool = False


class NotifySettings(_Base):
    """Tier W: forward reports to chat or webhooks. Off by default."""

    enabled: bool = False


class GateSettings(_Base):
    """Tier G: forward approved tool calls to an upstream MCP server. Off by default."""

    enabled: bool = False


class MemorySettings(_Base):
    """Team memory repositories (``kube-noob memory init``) read where kube-noob runs: the CLI, the stdio MCP server
    and the HTTP server. Read-only; kube-noob never uploads, bundles or exports them. ``$KUBE_NOOB_MEMORY_PATHS``
    (paths separated by ``:``) overrides the list."""

    paths: list[Path] = Field(default_factory=list, max_length=10)

    @field_validator("paths")
    @classmethod
    def _expand(cls, v: list[Path]) -> list[Path]:
        return [p.expanduser() for p in v]


class MustGatherSettings(_Base):
    """Where the ``analyze_must_gather`` MCP tool may read must-gathers. The local stdio server reads any path the
    user names (it runs as the user) unless this is set; the HTTP server offers the tool only when it is set, and
    then only for paths that resolve inside it (links resolved first). ``$KUBE_NOOB_MUST_GATHER_DIR`` overrides it.

    ``enabled: false`` (``$KUBE_NOOB_MUST_GATHER_ENABLED=false``) withdraws the tool entirely. It is the only tool
    that opens a path on the machine rather than reading text it was handed, so a deployment that must not touch the
    user's files turns it off here and says so: the Claude plugin does. Until this existed the plugin relied on
    `scripts/sync_plugin_server.py` leaving the module out of its copy, which is a packaging accident rather than a
    stated policy -- and it stopped holding the moment the plugin installed the published package instead."""

    enabled: bool = True
    allowed_dir: Path | None = None

    @field_validator("allowed_dir")
    @classmethod
    def _absolute(cls, v: Path | None) -> Path | None:
        if v is None:
            return None
        v = v.expanduser()
        if not v.is_absolute():
            raise ValueError("mustGather.allowedDir must be an absolute path")
        return v


class JiraSettings(_Base):
    """Local copy of Red Hat's public Jira (``kube-noob corpus jira``) for "has Red Hat seen this error?" answers.

    ``sync_enabled`` makes ``kube-noob serve`` keep the copy current in the background: at most one request per
    second, ``max_requests`` per run, every ``interval_hours``. Blocked by the offline lock like any download."""

    base_url: str = "https://redhat.atlassian.net"
    projects: str = "default"  # default | all | comma-separated project keys
    sync_enabled: bool = False
    interval_hours: int = Field(default=24, ge=6, le=168)
    max_requests: int = Field(default=600, ge=10, le=20_000)

    @field_validator("base_url")
    @classmethod
    def _https_site(cls, v: str) -> str:
        if not re.fullmatch(r"https://[A-Za-z0-9.-]+\.[A-Za-z]{2,}", v.rstrip("/")):
            raise ValueError("jira.baseUrl must be an https:// site root such as https://redhat.atlassian.net")
        return v.rstrip("/")

    @field_validator("projects")
    @classmethod
    def _project_spec(cls, v: str) -> str:
        v = v.strip()
        key = r"[A-Za-z][A-Za-z0-9_]{1,29}"
        if v in {"default", "all"} or re.fullmatch(rf"{key}(\s*,\s*{key})*", v):
            return v
        raise ValueError("jira.projects must be default, all, or comma-separated project keys such as OCPBUGS,ROX")


#: At most this many registry entries, and the shape each one has to have. The same grammar the policy
#: generator compiles (kube_noob.generate.policies._REGISTRY_ENTRY): a lower-case host, an optional port, and
#: optional path segments.
MAX_ALLOWED_REGISTRIES = 64
_REGISTRY_ENTRY = re.compile(r"[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?(/[a-z0-9]([a-z0-9._-]*[a-z0-9])?)*")


class AuditSettings(_Base):
    #: Registries an image may come from. A POLICY, not a fact about a manifest: no document states which
    #: registries an organisation has approved, so KN-S036 declines to decide when this is empty rather than
    #: reporting every image as fine. It lives in the configuration file and not on the command line because it
    #: is an organisational decision that should be the same for every caller of a deployment, which is also why
    #: the MCP tools do not take it as an argument.
    #:
    #: Each entry is a registry host, optionally with a port, and optionally with a leading path segment to
    #: narrow it to one organisation: `quay.io`, `registry.example.com:5000`, `quay.io/my-org`.
    allowed_registries: list[str] = Field(default_factory=list)

    @field_validator("allowed_registries")
    @classmethod
    def _registries(cls, v: list[str]) -> list[str]:
        """Refuse an entry that could never match, loudly, at load (G243).

        An image reference is lower-case and its first component is the registry only when it looks like a host
        -- a dot, a port, or exactly `localhost`. So `MyRegistry` and `myregistry` match no image a runtime can
        pull from that registry: left in, they would report every image in the cluster as unapproved while
        looking like a configured allowlist. A typo is a startup error instead.
        """
        cleaned = [e.strip() for e in v if e.strip()]
        if len(cleaned) > MAX_ALLOWED_REGISTRIES:
            raise ValueError(f"audit.allowedRegistries takes at most {MAX_ALLOWED_REGISTRIES} entries")
        for entry in cleaned:
            if not _REGISTRY_ENTRY.fullmatch(entry):
                raise ValueError(
                    f"audit.allowedRegistries {entry!r} is not a registry: write a lower-case host with an "
                    "optional port and optional path, such as quay.io, registry.example.com:5000 or quay.io/my-org"
                )
            host = entry.split("/", 1)[0]
            if not ("." in host or ":" in host or host == "localhost"):
                raise ValueError(
                    f"audit.allowedRegistries {entry!r} names no registry: a reference whose first component has "
                    "no dot, port or 'localhost' comes from docker.io, so this entry would match no image"
                )
        return cleaned


class MetricsSettings(_Base):
    #: `/metrics` sits behind the same bearer token as everything else by default. Opening it is a deliberate
    #: choice for a mesh that authenticates upstream: the document names every tool this deployment serves and
    #: how often each is called, which is operational intelligence about the team running it (N11).
    allow_unauthenticated: bool = False


class ServerSettings(_Base):
    host: str = "127.0.0.1"
    port: int = Field(default=8080, ge=1, le=65535)
    path: str = "/mcp"
    auth_token_env: str | None = None  # default set in kube_noob.server.http, the only code that reads it
    allowed_hosts: list[str] = Field(default_factory=list)
    allowed_origins: list[str] = Field(default_factory=list)
    metrics: MetricsSettings = Field(default_factory=MetricsSettings)


def _default_data_dir() -> Path:
    env = os.environ.get("KUBE_NOOB_DATA_DIR")
    if env:
        return Path(env)
    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "share"
    return base / "kube-noob"


class Settings(_Base):
    offline: bool = False  # admin lock: no web, no corpus downloads, only local model endpoints
    learning_enabled: bool = True  # local learning.json: confirmed notes, profile, pattern counters
    web_enabled: bool = False
    web: WebSettings = Field(default_factory=WebSettings)
    audit: AuditSettings = Field(default_factory=AuditSettings)
    cluster: ClusterSettings = Field(default_factory=ClusterSettings)
    llm: LLMSettings = Field(default_factory=LLMSettings)
    judge: JudgeSettings = Field(default_factory=JudgeSettings)
    server: ServerSettings = Field(default_factory=ServerSettings)
    watch: WatchSettings = Field(default_factory=WatchSettings)
    posture: PostureSettings = Field(default_factory=PostureSettings)
    alert_reports: AlertReportSettings = Field(default_factory=AlertReportSettings)
    rhacs: RhacsSettings = Field(default_factory=RhacsSettings)
    ci: CiSettings = Field(default_factory=CiSettings)
    admission: AdmissionSettings = Field(default_factory=AdmissionSettings)
    jira: JiraSettings = Field(default_factory=JiraSettings)
    memory: MemorySettings = Field(default_factory=MemorySettings)
    must_gather: MustGatherSettings = Field(default_factory=MustGatherSettings)
    probe: ProbeSettings = Field(default_factory=ProbeSettings)
    dry_run: DryRunSettings = Field(default_factory=DryRunSettings)
    itsm: ItsmSettings = Field(default_factory=ItsmSettings)
    notify: NotifySettings = Field(default_factory=NotifySettings)
    gate: GateSettings = Field(default_factory=GateSettings)
    data_dir: Path = Field(default_factory=_default_data_dir)
    default_platform: Literal["kubernetes", "openshift", "rosa-classic", "rosa-hcp"] = "kubernetes"
    source_path: Path | None = Field(default=None, exclude=True)
    web_locked: bool = Field(default=False, exclude=True)

    @field_validator("offline", "web_enabled", "learning_enabled", mode="before")
    @classmethod
    def _null_is_default(cls, v: Any, info: Any) -> Any:
        # `offline:` with no value (for example a Helm value missing after `upgrade --reuse-values`) means unset.
        if v is None:
            return info.field_name == "learning_enabled"
        return v

    @model_validator(mode="after")
    def _offline_lock(self) -> Settings:
        if self.offline and self.web_enabled:
            self.web_enabled = False
            self.web_locked = True
        return self

    def public_view(self) -> dict[str, Any]:
        """Config safe to display (no secrets are ever stored in Settings, only env var names)."""
        out = self.model_dump(by_alias=True, mode="json")
        out["configFile"] = str(self.source_path) if self.source_path else None
        return out


SYSTEM_CONFIG = Path("/etc/kube-noob/config.yaml")


def _system_lock() -> bool:
    """``offline`` in the system config is an admin lock that applies even when a user config file wins. It fails
    closed: a system config that exists but cannot be read or parsed counts as locked."""
    if not SYSTEM_CONFIG.exists():
        return False
    try:
        raw = yaml.safe_load(SYSTEM_CONFIG.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError, UnicodeDecodeError) as exc:
        _log.warning("system config %s is unreadable (%s); applying the offline lock", SYSTEM_CONFIG, exc)
        return True
    return isinstance(raw, dict) and _truthy(raw.get("offline"))


def _candidate_files() -> list[Path]:
    env = os.environ.get("KUBE_NOOB_CONFIG")
    if env:
        return [Path(env)]
    xdg = os.environ.get("XDG_CONFIG_HOME")
    cfg_home = Path(xdg) if xdg else Path.home() / ".config"
    return [cfg_home / "kube-noob" / "config.yaml", SYSTEM_CONFIG]


_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}


def _truthy(value: Any) -> bool:
    """The lock reads every spelling pydantic would coerce to True (true, 1, "yes", "on", ...)."""
    if isinstance(value, bool):
        return value
    if isinstance(value, int | float):
        return value == 1
    return isinstance(value, str) and value.strip().lower() in _TRUE


def _env_bool(name: str) -> bool | None:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return None
    v = raw.strip().lower()
    if v in _TRUE:
        return True
    if v in _FALSE:
        return False
    raise ConfigError(f"{name} must be one of true/false/1/0/yes/no/on/off, got {raw!r}")


def _env(name: str) -> str | None:
    """An environment override, or None when it is absent or blank.

    A variable set to the empty string, or to whitespace, is an unset variable rather than a setting of "": a shell
    that exports one unconditionally should not make the server refuse to start, which is what an empty
    ``mustGather.allowedDir`` did (it has to be an absolute path).
    """
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return None
    return raw


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def _env_overrides() -> dict[str, Any]:
    o: dict[str, Any] = {}
    web = _env_bool("KUBE_NOOB_WEB_ENABLED")
    if web is not None:
        o["webEnabled"] = web
    offline = _env_bool("KUBE_NOOB_OFFLINE")
    if offline is not None:
        o["offline"] = offline
    learning = _env_bool("KUBE_NOOB_LEARNING_ENABLED")
    if learning is not None:
        o["learningEnabled"] = learning
    cluster = _env_bool("KUBE_NOOB_CLUSTER_ENABLED")
    if cluster is not None:
        o.setdefault("cluster", {})["enabled"] = cluster
    for env, path in (
        ("KUBE_NOOB_LLM_PROVIDER", ("llm", "provider")),
        ("KUBE_NOOB_LLM_MODEL", ("llm", "model")),
        ("KUBE_NOOB_LLM_BASE_URL", ("llm", "baseUrl")),
        ("KUBE_NOOB_CLUSTER_BACKEND", ("cluster", "backend")),
        ("KUBE_NOOB_DEFAULT_PLATFORM", ("defaultPlatform",)),
        ("KUBE_NOOB_SERVER_HOST", ("server", "host")),
    ):
        val = _env(env)
        if val:
            cur = o
            for part in path[:-1]:
                cur = cur.setdefault(part, {})
            cur[path[-1]] = val
    must_gather = _env("KUBE_NOOB_MUST_GATHER_DIR")
    if must_gather:
        o["mustGather"] = {"allowedDir": must_gather}
    mg_enabled = _env_bool("KUBE_NOOB_MUST_GATHER_ENABLED")
    if mg_enabled is not None:
        o.setdefault("mustGather", {})["enabled"] = mg_enabled
    # an explicit empty value still clears the configured paths, so this one keeps reading the variable directly
    memory = os.environ.get("KUBE_NOOB_MEMORY_PATHS")
    if memory is not None:
        o["memory"] = {"paths": [p for p in memory.split(os.pathsep) if p.strip()]}
    port = os.environ.get("KUBE_NOOB_SERVER_PORT")
    if port:
        try:
            o.setdefault("server", {})["port"] = int(port)
        except ValueError as exc:
            raise ConfigError(f"KUBE_NOOB_SERVER_PORT must be an integer, got {port!r}") from exc
    return o


def load_settings(path: str | Path | None = None, overrides: dict[str, Any] | None = None) -> Settings:
    """Load settings. ``overrides`` use the camelCase keys of the YAML file."""
    data: dict[str, Any] = {}
    source: Path | None = None
    candidates = [Path(path)] if path else _candidate_files()
    for cand in candidates:
        if cand.is_file():
            try:
                raw = yaml.safe_load(cand.read_text(encoding="utf-8")) or {}
            except yaml.YAMLError as exc:
                raise ConfigError(f"Config file {cand} is not valid YAML: {exc}") from exc
            if not isinstance(raw, dict):
                raise ConfigError(f"Config file {cand} must contain a mapping at the top level")
            data = raw
            source = cand
            break
        if path:  # an explicit path that does not exist is an error, not a silent fallback
            raise ConfigError(f"Config file {cand} does not exist")
    # The offline lock only ever tightens: any of the system config, the chosen config file or KUBE_NOOB_OFFLINE can
    # switch it on, and nothing later in the chain (environment "0", CLI flags, tool overrides) can switch it off.
    locked = _truthy(data.get("offline")) or _system_lock()
    data = _deep_merge(data, _env_overrides())
    locked = locked or _truthy(data.get("offline"))
    if overrides:
        data = _deep_merge(data, overrides)
    if locked:
        data["offline"] = True
    try:
        settings = Settings.model_validate(data)
    except ValidationError as exc:
        raise ConfigError(f"Invalid kube-noob configuration: {exc}") from exc
    settings.source_path = source
    return settings
