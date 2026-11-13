"""Exceptions as code (requirements R3.5): a reviewed, owned, expiring decision to accept one rule on named objects.

File (YAML, kept in Git next to the manifests and reviewed by pull request)::

    apiVersion: kube-noob.io/v1
    kind: ExceptionList
    exceptions:
    - id: EXC-001                      # optional; defaults to <rule>#<position>
      rule: KN-S009
      scope: {namespace: monitoring, kind: DaemonSet, name: node-exporter}
      owner: team-observability
      reason: Node metrics need the host network namespace
      expires: 2026-12-31
      ticket: OPS-1234                 # optional

An entry can instead accept one object the rules did not read (the audit's ``notAudited``), with the same owner,
reason and expiry::

    - id: EXC-KNATIVE
      notAudited: {namespace: prod, kind: Service, name: hello, apiGroup: serving.knative.dev}
      owner: team-web
      reason: Knative Services are audited by the serving team's own pipeline
      expires: 2027-06-30

The row stays listed, marked ``acceptedBy``, and no longer makes the verdict undetermined.

Every entry is checked on its own; one bad entry never hides the others. An entry is refused, with the reason, when
its rule is unknown, it has no owner or no reason (10 characters at least), its expiry is missing, not a date, or more
than ``MAX_DAYS`` ahead, its scope is too broad (no namespace, a namespace that is only a wildcard; a cluster-scoped
kind needs its kind and exact name instead), or it has fields this format does not know. An entry past its expiry
date is ``expired``. Refused and expired entries fail the gate: ``kube-noob audit --exceptions`` exits 1 and says why,
whatever the findings.

An active exception hides a finding only when the rule matches and the finding's object is inside the scope; a finding
of the same rule on any other object stays. Findings an exception hides are listed as ``excepted`` with the
exception's id, owner and expiry, and active exceptions that matched nothing are reported as ``unused`` (a stale
exception to delete). Objects without a namespace in a bundle count as namespace ``default``.
"""

from __future__ import annotations

import datetime as dt
import fnmatch
import re
from dataclasses import dataclass, field
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from kube_noob import sanitize
from kube_noob.audit.rules import RULES

MAX_DAYS = 400
MAX_EXCEPTIONS = 500
MAX_BYTES = 1_000_000
CLUSTER_SCOPED_KINDS = frozenset(
    {
        "Namespace",
        "Project",
        "Node",
        "PersistentVolume",
        "StorageClass",
        "ClusterRole",
        "ClusterRoleBinding",
        "SecurityContextConstraints",
        "MachineConfig",
        "MachineConfigPool",
        "CustomResourceDefinition",
        "ValidatingWebhookConfiguration",
        "MutatingWebhookConfiguration",
        "ValidatingAdmissionPolicy",
        "ValidatingAdmissionPolicyBinding",
        "PriorityClass",
        "IngressClass",
        "CSIDriver",
        "ClusterIssuer",
    }
)
_DNS_LABEL = re.compile(r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?\Z")
_NS_PREFIX = re.compile(r"^[a-z0-9][-a-z0-9]{1,60}\*\Z")
_NAME_PATTERN = re.compile(r"^[a-z0-9*]([-a-z0-9.*]{0,251}[a-z0-9*])?\Z")
_KIND_PATTERN = re.compile(r"^[A-Z][A-Za-z0-9]{0,62}\Z")
_GROUP_PATTERN = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*\Z")


class ExceptionsError(ValueError):
    """The file is not an exception list at all (not YAML, wrong apiVersion or kind, too large)."""


class _Scope(BaseModel):
    model_config = ConfigDict(extra="forbid")
    namespace: str | None = Field(None, max_length=63)
    kind: str | None = Field(None, max_length=63)
    name: str | None = Field(None, max_length=253)


class _NotAuditedScope(BaseModel):
    """What a `notAudited:` entry accepts: one object the rules did not read, by kind, API group, namespace and
    name (a name pattern is allowed, as in `scope`). A Helm render with an Istio Gateway or a Knative Service had
    an undetermined verdict forever, and a `rule:` entry could not name it (review 5, item 4)."""

    model_config = ConfigDict(extra="forbid")
    namespace: str | None = Field(None, max_length=63)
    kind: str = Field(..., max_length=63)
    name: str = Field(..., max_length=253)
    apiGroup: str = Field(..., max_length=253)


class _Entry(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    id: str | None = Field(None, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9._#-]{0,63}$")
    rule: str | None = Field(None, max_length=10)
    scope: _Scope | None = None
    notAudited: _NotAuditedScope | None = None
    owner: str = Field(..., max_length=200)
    reason: str = Field(..., max_length=2000)
    expires: dt.date
    ticket: str | None = Field(None, max_length=100)

    @model_validator(mode="after")
    def _one_kind_of_entry(self) -> _Entry:
        if self.notAudited is not None:
            if self.rule is not None or self.scope is not None:
                raise ValueError("an entry accepts either a rule on a scope or one notAudited object, not both")
        elif self.rule is None or self.scope is None:
            raise ValueError("an entry needs rule and scope, or notAudited")
        return self


@dataclass(frozen=True)
class Checked:
    id: str
    rule: str
    status: Literal["active", "expired", "refused"]
    reason: str
    owner: str = ""
    expires: str = ""
    scope: dict[str, str] = field(default_factory=dict)
    #: For a `notAudited:` entry: the object it accepts (kind, apiGroup, name, optional namespace). `rule` is "".
    not_audited: dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"id": self.id, "status": self.status, "reason": self.reason}
        if self.not_audited:
            out["notAudited"] = self.not_audited
        else:
            out["rule"] = self.rule
        if self.owner:
            out["owner"] = self.owner
        if self.expires:
            out["expires"] = self.expires
        if self.scope:
            out["scope"] = self.scope
        return out

    def accepts_object(self, kind: str, api_group: str, namespace: str | None, name: str) -> bool:
        """Whether this active `notAudited:` entry accepts the object (exact kind and group; name as a pattern)."""
        sc = self.not_audited
        if self.status != "active" or not sc or sc["kind"] != kind or sc["apiGroup"] != api_group:
            return False
        if "namespace" in sc:
            if namespace is None or not fnmatch.fnmatchcase(namespace, sc["namespace"]):
                return False
        elif kind not in CLUSTER_SCOPED_KINDS and namespace is not None:
            return False
        return fnmatch.fnmatchcase(name, sc["name"])

    def covers(self, rule_id: str, kind: str, namespace: str | None, name: str) -> bool:
        if self.status != "active" or rule_id != self.rule:
            return False
        sc = self.scope
        if sc.get("kind") and sc["kind"] != kind:
            return False
        if "namespace" in sc:
            if namespace is None or not fnmatch.fnmatchcase(namespace, sc["namespace"]):
                return False
        elif kind not in CLUSTER_SCOPED_KINDS:
            return False
        return not (sc.get("name") and not fnmatch.fnmatchcase(name, sc["name"]))


@dataclass
class Review:
    entries: list[Checked]

    @property
    def gate_failures(self) -> list[Checked]:
        return [e for e in self.entries if e.status != "active"]

    @property
    def active(self) -> list[Checked]:
        return [e for e in self.entries if e.status == "active"]

    def summary(self) -> dict[str, Any]:
        counts = {s: sum(1 for e in self.entries if e.status == s) for s in ("active", "expired", "refused")}
        return {"counts": counts, "entries": [e.as_dict() for e in self.entries], "gate": not self.gate_failures}


def _readable(exc: ValidationError) -> str:
    parts = []
    for err in exc.errors()[:3]:
        loc = ".".join(str(x) for x in err.get("loc", ()))
        msg = "unknown field" if err.get("type") == "extra_forbidden" else err.get("msg", "invalid")
        parts.append(f"{loc}: {msg}" if loc else str(msg))
    return "; ".join(parts)


def _scope_problem(scope: _Scope) -> str | None:
    if scope.kind is not None and not _KIND_PATTERN.match(scope.kind):
        return f"scope.kind {scope.kind!r} is not a kind"
    if scope.name is not None and not _NAME_PATTERN.match(scope.name):
        return f"scope.name {scope.name!r} is not a name or a name pattern"
    if scope.namespace is None:
        if scope.kind in CLUSTER_SCOPED_KINDS and scope.name and "*" not in scope.name:
            return None
        return (
            "scope too broad: name a namespace, or for a cluster-scoped kind (ClusterRole, SCC, StorageClass...) its "
            "kind and exact name"
        )
    ns = scope.namespace
    if not (_DNS_LABEL.match(ns) or _NS_PREFIX.match(ns)):
        return f"scope.namespace {ns!r} is too broad or not a namespace: an exact name or a prefix such as team-*"
    return None


def _check(eid: str, e: _Entry, today: dt.date, duplicate: bool) -> Checked:
    if e.notAudited is not None:
        return _check_not_audited(eid, e, today, duplicate)
    if e.rule is None or e.scope is None:  # the model validator holds this; said here for the type checker
        return Checked(eid, "", "refused", "an entry needs rule and scope, or notAudited")
    scope = {k: v for k, v in e.scope.model_dump().items() if v is not None}
    rid = e.rule.upper()
    status: Literal["active", "expired", "refused"]
    problem: str | None = None
    if rid not in RULES:
        problem = f"unknown rule {e.rule!r} (kube-noob rules lists them)"
    elif not e.owner.strip():
        problem = "no owner: name the team or person who answers for this exception"
    elif len(e.reason.strip()) < 10:
        problem = "no reason: say why the risk is accepted (10 characters at least)"
    elif (e.expires - today).days > MAX_DAYS:
        problem = f"expires {e.expires.isoformat()}, more than {MAX_DAYS} days ahead: review it at least yearly"
    elif duplicate:
        problem = f"duplicate id {eid}"
    else:
        problem = _scope_problem(e.scope)
    if problem:
        status, why = "refused", problem
    elif e.expires < today:
        status, why = "expired", f"expired on {e.expires.isoformat()}"
    else:
        status, why = "active", f"accepted until {e.expires.isoformat()}"
    return Checked(eid, rid, status, why, owner=e.owner, expires=e.expires.isoformat(), scope=scope)


def _check_not_audited(eid: str, e: _Entry, today: dt.date, duplicate: bool) -> Checked:
    """A `notAudited:` entry: the same owner, reason, expiry and scope discipline as a rule entry, on one object."""
    na = e.notAudited
    if na is None:
        return Checked(eid, "", "refused", "an entry needs rule and scope, or notAudited")
    target = {k: v for k, v in na.model_dump().items() if v is not None}
    problem: str | None = None
    if not e.owner.strip():
        problem = "no owner: name the team or person who answers for this exception"
    elif len(e.reason.strip()) < 10:
        problem = "no reason: say why the object is accepted unaudited (10 characters at least)"
    elif (e.expires - today).days > MAX_DAYS:
        problem = f"expires {e.expires.isoformat()}, more than {MAX_DAYS} days ahead: review it at least yearly"
    elif duplicate:
        problem = f"duplicate id {eid}"
    elif not _KIND_PATTERN.match(na.kind):
        problem = f"notAudited.kind {na.kind!r} is not a kind"
    elif na.apiGroup and not _GROUP_PATTERN.match(na.apiGroup):
        problem = f"notAudited.apiGroup {na.apiGroup!r} is not an API group"
    else:
        problem = _scope_problem(_Scope(namespace=na.namespace, kind=na.kind, name=na.name))
        problem = problem.replace("scope.", "notAudited.") if problem else None
    status: Literal["active", "expired", "refused"]
    if problem:
        status, why = "refused", problem
    elif e.expires < today:
        status, why = "expired", f"expired on {e.expires.isoformat()}"
    else:
        status, why = "active", f"accepted until {e.expires.isoformat()}"
    return Checked(eid, "", status, why, owner=e.owner, expires=e.expires.isoformat(), not_audited=target)


def accept_not_audited(rev: Review, rows: list[dict[str, Any]]) -> set[str]:
    """Mark every `notAudited` row an active entry accepts with `acceptedBy`, in place; the ids used.

    An accepted row stays listed -- the object was still not audited -- but no longer stops the verdict being
    determined (`undetermined_reason` skips it). Matched on the row's own cleaned `object` and `apiGroup`."""
    used: set[str] = set()
    for row in rows:
        if not isinstance(row, dict) or row.get("acceptedBy"):
            continue
        kind, ns, name = _parts(str(row.get("object", "")))
        hit = next((e for e in rev.active if e.accepts_object(kind, str(row.get("apiGroup", "")), ns, name)), None)
        if hit is not None:
            row["acceptedBy"] = hit.id
            used.add(hit.id)
    return used


def review(text: str, today: dt.date | None = None) -> Review:
    """Check every entry of an exception list. Raises ExceptionsError only when the file itself is not one."""
    if len(text.encode("utf-8")) > MAX_BYTES:
        raise ExceptionsError(f"exception list larger than {MAX_BYTES} bytes")
    try:
        doc = sanitize.safe_load_bounded(text)
    except sanitize.YamlTooDeep as exc:
        raise ExceptionsError(str(exc)) from exc
    except (yaml.YAMLError, RecursionError) as exc:
        raise ExceptionsError(f"not YAML: {str(exc)[:200]}") from exc
    if not isinstance(doc, dict) or doc.get("apiVersion") != "kube-noob.io/v1" or doc.get("kind") != "ExceptionList":
        raise ExceptionsError("expected apiVersion: kube-noob.io/v1 and kind: ExceptionList")
    unknown = sorted(set(doc) - {"apiVersion", "kind", "exceptions", "metadata"})
    if unknown:
        raise ExceptionsError(f"unknown top-level field(s): {unknown}")
    raw = doc.get("exceptions") or []
    if not isinstance(raw, list):
        raise ExceptionsError("exceptions must be a list")
    if len(raw) > MAX_EXCEPTIONS:
        raise ExceptionsError(f"more than {MAX_EXCEPTIONS} exceptions")
    today = today or dt.datetime.now(dt.UTC).date()
    out: list[Checked] = []
    seen: set[str] = set()
    for i, item in enumerate(raw):
        rule = str(item.get("rule", "")) if isinstance(item, dict) else ""
        default_id = f"{rule or ('notAudited' if isinstance(item, dict) and 'notAudited' in item else 'entry')}#{i + 1}"
        eid = str(item.get("id") or default_id) if isinstance(item, dict) else default_id
        if not isinstance(item, dict):
            out.append(Checked(eid, rule, "refused", "an exception must be a mapping"))
            continue
        try:
            e = _Entry.model_validate(item)
        except ValidationError as exc:
            out.append(Checked(eid, rule, "refused", _readable(exc)))
            continue
        out.append(_check(eid, e, today, eid in seen))
        seen.add(eid)
    return Review(out)


def _parts(resource: str) -> tuple[str, str | None, str]:
    bits = resource.split("/")
    if len(bits) >= 3:
        return bits[0], bits[1], "/".join(bits[2:])
    if len(bits) == 2:
        kind = bits[0]
        return kind, (None if kind in CLUSTER_SCOPED_KINDS else "default"), bits[1]
    return resource, None, ""


def match(rev: Review, rule_id: str, resource: str) -> Checked | None:
    """The active exception that hides a finding of ``rule_id`` on ``resource`` (Kind/namespace/name), if any."""
    kind, ns, name = _parts(resource)
    return next((e for e in rev.active if e.covers(rule_id, kind, ns, name)), None)


def apply(findings: list[dict[str, Any]], rev: Review) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    """(findings kept, findings excepted with the exception that hides each, ids of active exceptions unused)."""
    kept: list[dict[str, Any]] = []
    excepted: list[dict[str, Any]] = []
    used: set[str] = set()
    for f in findings:
        hit = match(rev, str(f.get("ruleId")), str(f.get("resource", "")))
        if hit is None:
            kept.append(f)
        else:
            used.add(hit.id)
            excepted.append({**f, "exception": {"id": hit.id, "owner": hit.owner, "expires": hit.expires}})
    return kept, excepted, [e.id for e in rev.active if e.id not in used]
