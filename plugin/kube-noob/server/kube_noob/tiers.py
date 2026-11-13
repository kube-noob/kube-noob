"""Capability tiers: what kube-noob may do beyond reading, each off by default and approved action by action.

| Tier | Switch | Allows | What it needs |
|---|---|---|---|
| R | ``cluster.enabled`` | get, list and logs on the allowlisted resources | get/list/watch RBAC |
| P | ``probe.enabled`` | an ephemeral debug container or a probe Job | patch ``pods/ephemeralcontainers``; Jobs |
| D | ``dryRun.enabled`` | server-side dry-run (``?dryRun=All``) of a manifest | create/patch on the named resources |
| W | ``itsm.writeEnabled``, ``notify.enabled`` | attach evidence to a ticket; forward a report | the system's token |
| G | ``gate.enabled`` | forward an approved tool call to an upstream MCP server | the upstream's own access |
| A | ``admission.enforce`` | ``kube-noob admission serve`` denies requests for the listed rules (else warns) | none |

Tier A is configuration, not an action: the operator who lists a rule in ``admission.enforce`` is the person who
approved every denial of that rule, so it needs no per-action approval; without it the webhook only warns.

The read-only backends (``kube_noob.debug.backends``) have no method that writes. Anything that changes something is
a ``Writer`` subclass: it cannot be constructed while its tier is off, and each call is checked against an
``Approval`` for exactly that action, unexpired and used once. kube-noob never approves its own actions: an approval
comes from a person (a CLI flag they typed, or an approval they gave through the gate).
"""

from __future__ import annotations

import re
import secrets
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, ClassVar

from kube_noob.config import Settings
from kube_noob.errors import ApprovalError, TierDisabledError

MAX_TTL = timedelta(hours=24)
DEFAULT_TTL = timedelta(minutes=15)
_PRINTABLE = re.compile(r"^[^\x00-\x1f\x7f]+\Z")


@dataclass(frozen=True)
class Tier:
    code: str
    name: str
    switches: tuple[str, ...]
    allows: str
    rbac: str
    writes: bool
    external: bool  # reaches a system outside the cluster: refused under the offline lock
    sources: tuple[str, ...] = field(default=())


TIERS: tuple[Tier, ...] = (
    Tier(
        "R",
        "read-only cluster",
        ("cluster.enabled",),
        "get, list and logs on the allowlisted resources; Secrets never",
        "get, list, watch on the allowlist (chart: templates/rbac.yaml)",
        writes=False,
        external=False,
        sources=(
            "https://github.com/kubernetes/website/blob/main/content/en/docs/reference/access-authn-authz/rbac.md",
        ),
    ),
    Tier(
        "P",
        "probe",
        ("probe.enabled",),
        "an ephemeral debug container in a pod, or a short-lived probe Job",
        "patch on pods/ephemeralcontainers (kubectl debug patches that subresource); create and delete on Jobs",
        writes=True,
        external=False,
        sources=("https://github.com/kubernetes/kubectl/blob/master/pkg/cmd/debug/debug.go",),
    ),
    Tier(
        "D",
        "server-side dry-run",
        ("dryRun.enabled",),
        "create or patch with ?dryRun=All: admission runs, nothing is stored",
        "create and patch on the named resources: dry-run is authorized exactly like the real request",
        writes=True,
        external=False,
        sources=(  # "Authorization for dry-run and non-dry-run requests is identical" (checked 2026-10-28)
            "https://github.com/kubernetes/website/blob/main/content/en/docs/reference/using-api/api-concepts.md",
        ),
    ),
    Tier(
        "W",
        "external writes",
        ("itsm.writeEnabled", "notify.enabled"),
        "attach a report to a ticket; forward a report to a chat or webhook",
        "none in the cluster; the external system's token",
        writes=True,
        external=True,
        sources=("https://github.com/kube-noob/kube-noob/blob/main/PRIVACY.md",),  # every destination listed there
    ),
    Tier(
        "G",
        "gate forwarding",
        ("gate.enabled",),
        "forward a tool call a person approved to an upstream MCP server",
        "none in kube-noob; the upstream server keeps its own access",
        writes=True,
        external=False,
        sources=(
            "https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2025-06-18/"
            "server/tools.mdx",
        ),
    ),
    Tier(
        "A",
        "admission enforcement",
        ("admission.enforce",),
        "kube-noob admission serve denies a create or update for a rule listed in admission.enforce (only a finding "
        "the old object did not have); without it the webhook only warns, and it never mutates",
        "none for the webhook; admission.lookups adds get and list on PodDisruptionBudgets, NetworkPolicies, "
        "PersistentVolumeClaims, HorizontalPodAutoscalers and StorageClasses (chart: templates/admission.yaml)",
        writes=False,
        external=False,
        sources=(  # failurePolicy Ignore, timeoutSeconds 1-30, warnings in AdmissionResponse (checked 2026-10-28)
            "https://github.com/kubernetes/api/blob/master/admissionregistration/v1/types.go",
            "https://github.com/kubernetes/api/blob/master/admission/v1/types.go",
        ),
    ),
)
_BY_CODE = {t.code: t for t in TIERS}


def _switch(settings: Settings, path: str) -> bool:
    section, key = path.split(".")
    attr = {"dryRun": "dry_run"}.get(section, section)
    field_name = {"writeEnabled": "write_enabled"}.get(key, key)
    return bool(getattr(getattr(settings, attr), field_name))


def enabled(settings: Settings, code: str) -> bool:
    tier = _BY_CODE.get(code)
    return tier is not None and any(_switch(settings, sw) for sw in tier.switches)


def describe(settings: Settings) -> list[dict[str, Any]]:
    return [
        {
            "tier": t.code,
            "name": t.name,
            "enabled": enabled(settings, t.code),
            "switch": " or ".join(t.switches),
            "allows": t.allows,
            "rbac": t.rbac,
            "approvalPerAction": t.writes,
        }
        for t in TIERS
    ]


def conflicts(settings: Settings) -> list[str]:
    """Settings that contradict each other; the safer reading always wins at runtime."""
    out: list[str] = []
    for sw in ("probe.enabled", "dryRun.enabled"):
        if _switch(settings, sw) and not settings.cluster.enabled:
            out.append(f"{sw} needs cluster.enabled (tiers P and D act on the cluster); it stays unusable until then")
    if settings.admission.lookups and not settings.cluster.enabled:
        out.append(
            "admission.lookups reads the namespace's other objects and needs cluster.enabled (read-only); "
            "kube-noob admission serve refuses to start until then"
        )
    if settings.offline:
        for sw in ("itsm.writeEnabled", "notify.enabled"):
            if _switch(settings, sw):
                out.append(
                    f"{sw} sends to a system outside the cluster, which the offline lock forbids; it stays off. "
                    "Remove it or the lock so the configuration states what actually happens."
                )
    return out


def offered(spec: Any, settings: Settings) -> bool:
    """Whether a tool (``ToolSpec``) is offered: tools without a tier always are; tier tools only when it is on."""
    tier = getattr(spec, "tier", None)
    return tier is None or enabled(settings, tier)


_used: set[str] = set()
_used_lock = threading.Lock()


@dataclass(frozen=True)
class Approval:
    """A person's approval of one action in one tier, valid until ``expires_at`` and usable once."""

    id: str
    tier: str
    action: str
    approver: str
    reason: str
    expires_at: datetime

    @classmethod
    def create(
        cls,
        tier: str,
        action: str,
        approver: str,
        reason: str,
        ttl: timedelta = DEFAULT_TTL,
        now: datetime | None = None,
    ) -> Approval:
        t = _BY_CODE.get(tier)
        if t is None:
            raise ApprovalError(f"unknown tier {tier!r}; tiers are {', '.join(_BY_CODE)}")
        if not t.writes:
            raise ApprovalError(f"tier {tier} is read-only and needs no approval")
        for label, value, limit in (("approver", approver, 120), ("reason", reason, 500), ("action", action, 2000)):
            if not value or not value.strip() or len(value) > limit or not _PRINTABLE.match(value):
                raise ApprovalError(f"an approval needs a {label}: printable text, at most {limit} characters")
        if ttl <= timedelta(0) or ttl > MAX_TTL:
            raise ApprovalError("an approval lasts between a second and 24 hours")
        start = now or datetime.now(UTC)
        return cls(secrets.token_hex(8), tier, action, approver.strip(), reason.strip(), start + ttl)


class Writer:
    """Base for anything that changes a cluster or an external system. Subclasses set ``tier``."""

    tier: ClassVar[str] = ""

    def __init__(self, settings: Settings) -> None:
        if not enabled(settings, self.tier):
            t = _BY_CODE.get(self.tier)
            switch = " or ".join(t.switches) if t else "?"
            raise TierDisabledError(f"tier {self.tier} ({t.name if t else 'unknown'}) is off: set {switch}: true")
        self.settings = settings

    def authorize(self, approval: Approval, action: str, now: datetime | None = None) -> Approval:
        """Check that ``approval`` covers exactly ``action`` in this tier, is unexpired and unused; then spend it."""
        if not isinstance(approval, Approval):
            raise ApprovalError("this action needs an approval from a person (kube_noob.tiers.Approval)")
        if approval.tier != self.tier:
            raise ApprovalError(f"the approval is for tier {approval.tier}, this action is tier {self.tier}")
        if approval.action != action:
            raise ApprovalError("the approval was given for a different action; ask for one for this action")
        if (now or datetime.now(UTC)) >= approval.expires_at:
            raise ApprovalError("the approval expired; ask for a new one")
        with _used_lock:
            if approval.id in _used:
                raise ApprovalError("the approval was already used; each approval covers one action once")
            _used.add(approval.id)
        return approval
