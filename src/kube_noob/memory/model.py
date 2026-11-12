"""The memory entry: what a team learned about one problem, as a validated value.

Shape (YAML keys in camelCase): ``id`` (MEM-<n>), ``status`` (proposed, approved, retired), ``kind`` (fix, negative:
tried and did not work, runbook), ``signals`` (kube_noob.signals kinds and names; error templates by their 12-digit
hash), ``symptom``, ``platform``, ``versions`` (``introduced``, ``fixedIn``), ``operators`` (name and version
range), ``cause``, ``fix`` (``text``, optional ``patch`` manifest, optional ``commands`` labelled ``read-only`` or
``needs-approval``), ``evidence`` (references only), ``outcomes`` (date, result, opaque ticket ref, cluster label),
``owners``, ``sources``, ``created``, ``updated``, optional ``reviewBy`` and ``riskAccepted`` (owner, reason,
optional expiry; required by ``memory validate`` for any fix the verifier flags HIGH).

Content rules enforced here, beyond shape: prose fields are summaries (``kube_noob.learn.memory.check_text``: no
credentials, raw logs, event rows, stack traces, pipelines or manifests); a command's label is the one the playbook
classifier (``kube_noob.debug.steps.classify_step``) gives it, and a command is one line with no shell comment (zsh
passes ``#`` on as arguments) that never prints a Secret; a patch is Kubernetes manifests without Secrets or
credentials; evidence is a URL, a ticket key, a ``kn:``/``mem:`` citation or a path inside a bundle, never pasted
output.
"""

from __future__ import annotations

import re
from datetime import date
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from kube_noob.catalog import PLATFORMS, Platform

MAX_SYMPTOM = 500
MAX_CAUSE = 2_000
MAX_FIX_TEXT = 2_000
MAX_PATCH = 20_000
MAX_NOTE = 300
MAX_SIGNALS = 20
MAX_COMMANDS = 20
MAX_EVIDENCE = 30
MAX_OUTCOMES = 1_000
MAX_LIST = 20

_VERSION = re.compile(r"^\d{1,3}\.\d{1,4}(\.\d{1,6})?\Z")
_SIGNAL_NAMES: dict[str, re.Pattern[str]] = {
    "alert": re.compile(r"^[A-Za-z][A-Za-z0-9_:.-]{0,127}$"),
    "co_condition": re.compile(
        r"^[a-z0-9][a-z0-9-]{0,62}/[A-Za-z]{1,40}=(True|False|Unknown)(:[A-Za-z][A-Za-z0-9_]{0,127})?$"
    ),
    "event_reason": re.compile(r"^[A-Za-z][A-Za-z0-9]{0,63}$"),
    "pod_reason": re.compile(r"^[A-Za-z][A-Za-z0-9]{0,63}$"),
    "admission": re.compile(r"^[a-z][a-z-]{1,30}(:[A-Za-z0-9._-]{1,253}(/[A-Za-z0-9._-]{1,253})?)?$"),
    "component": re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$"),
    "error_template": re.compile(r"^[0-9a-f]{12}$"),
}
_RANGE_PART = re.compile(r"^(>=|<=|>|<|=)v?(\d{1,6}(?:\.\d{1,6}){0,2})\Z")
_DNS_SUBDOMAIN = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?\Z")
_TICKET_KEY = re.compile(r"^[A-Z][A-Z0-9_]{0,29}-\d{1,9}\Z")
_CITATION = re.compile(r"^\[?(kn|mem):[A-Za-z0-9._:-]{1,200}(#\d{1,6})?\]?\Z")
_BUNDLE = re.compile(r"^bundle:(?!.*\.\.)[A-Za-z0-9._-]{1,100}(/[A-Za-z0-9._-]{1,100}){0,5}\Z")
_URL = re.compile(r"^https://[A-Za-z0-9.-]{1,253}(:\d{1,5})?(/[^\s<>\"'`]{0,800})?\Z")
_OPAQUE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/#-]{0,99}\Z")
_CLUSTER = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}\Z")
_OWNER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._@/+-]{0,99}\Z")
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_PRINTS_SECRET = re.compile(
    r"\b(get|describe|edit)\s+(secrets?|secret/\S+)\b.*(-o|--output)[ =]?(yaml|json|jsonpath|go-template|template)"
    r"|\bextract\s+(secrets?/|secret\s)"
    r"|\bget\s+(secrets?|secret/\S+)\b.*--template",
    re.IGNORECASE,
)


def _whole(pattern: re.Pattern[str]) -> str:
    """The pattern for a pydantic ``Field``: its Rust engine has no ``\\Z``, and its ``$`` already means the end of
    the text (Python's ``$`` also matches before a final newline, so the compiled patterns here end with ``\\Z``)."""
    return pattern.pattern.removesuffix("\\Z") + "$"


def vkey(version: str) -> tuple[int, ...]:
    """Numeric parts of a version, ignoring a build suffix ("4.16.0-202410011135" -> (4, 16, 0))."""
    return tuple(int(p[:9]) for p in re.findall(r"\d+", version[:200].split("-", 1)[0].lstrip("v"))[:3])


def _prose(field: str, value: str, limit: int) -> str:
    from kube_noob.learn.memory import check_text

    try:
        return check_text(field, value, limit, what="memory entries")
    except ValueError as exc:  # re-raised so pydantic reports it on the field
        raise ValueError(str(exc)) from None


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True, str_strip_whitespace=True)


class SignalRef(_Model):
    kind: Literal["alert", "co_condition", "event_reason", "pod_reason", "admission", "component", "error_template"]
    name: str = Field(..., min_length=1, max_length=260)

    @model_validator(mode="after")
    def _name_fits_kind(self) -> SignalRef:
        if not _SIGNAL_NAMES[self.kind].match(self.name):
            hint = " (the 12-digit hash from `kube-noob signals`)" if self.kind == "error_template" else ""
            raise ValueError(f"signal name {self.name!r} is not a valid {self.kind} name{hint}")
        return self


class Versions(_Model):
    introduced: str | None = None
    fixed_in: str | None = Field(None, alias="fixedIn")

    @field_validator("introduced", "fixed_in", mode="before")
    @classmethod
    def _quoted(cls, v: Any) -> Any:
        if isinstance(v, int | float) and not isinstance(v, bool):
            raise ValueError(f'quote versions in YAML ({v} reads as a number): write "{v}"')
        if v is not None and (not isinstance(v, str) or not _VERSION.match(v.strip())):
            raise ValueError(f"version {v!r} must look like 4.21 or 4.21.3")
        return v

    @model_validator(mode="after")
    def _order(self) -> Versions:
        if self.introduced and self.fixed_in and vkey(self.introduced) > vkey(self.fixed_in):
            raise ValueError(f"introduced {self.introduced} is after fixedIn {self.fixed_in}")
        return self


class OperatorRange(_Model):
    name: str = Field(..., min_length=1, max_length=253, pattern=_whole(_DNS_SUBDOMAIN))
    range: str | None = Field(None, max_length=60, description="One or two comparators: '>=0.28.0 <0.29.0', '=4.16.2'.")

    @field_validator("range")
    @classmethod
    def _range(cls, v: str | None) -> str | None:
        if v is None:
            return None
        parts = v.replace(",", " ").split()
        if not 1 <= len(parts) <= 2 or not all(_RANGE_PART.match(p) for p in parts):
            raise ValueError(f"operator range {v!r}: use one or two comparators such as '>=0.28.0 <0.29.0'")
        return " ".join(parts)

    def contains(self, version: str) -> bool:
        if not self.range:
            return True
        have = vkey(version)
        for part in self.range.split():
            m = _RANGE_PART.match(part)
            if m is None:  # cannot happen: the range was validated
                return False
            op, want = m.group(1), vkey(m.group(2))
            n = max(len(have), len(want))
            a, b = have + (0,) * (n - len(have)), want + (0,) * (n - len(want))
            ok = {">=": a >= b, "<=": a <= b, ">": a > b, "<": a < b, "=": a == b}[op]
            if not ok:
                return False
        return True


class Command(_Model):
    command: str = Field(..., max_length=500)
    label: Literal["read-only", "needs-approval"]

    @field_validator("command", mode="before")
    @classmethod
    def _one_clean_line(cls, v: Any) -> Any:
        if not isinstance(v, str) or not v.strip():
            raise ValueError("command is empty")
        if "\n" in v.strip() or "\r" in v:
            raise ValueError("a command is one line; list each command separately")
        if _CONTROL.search(v):
            raise ValueError("command contains control characters")
        return v

    @model_validator(mode="after")
    def _label_and_content(self) -> Command:
        from kube_noob.debug.steps import classify_step, split_comment
        from kube_noob.learn.memory import contains_credential

        if split_comment(self.command)[1] is not None:
            raise ValueError("command carries a shell comment ('# ...'): zsh passes it on as arguments; drop it")
        if contains_credential(self.command):
            raise ValueError("command looks like it contains a credential; memory entries never store secrets")
        if _PRINTS_SECRET.search(self.command):
            raise ValueError("command prints a Secret's contents; kube-noob never shows Secret values")
        want = "read-only" if classify_step(self.command) == "read" else "needs-approval"
        if self.label != want:
            raise ValueError(f"command {self.command!r} must be labelled {want} (the playbook classifier's verdict)")
        return self


class Fix(_Model):
    text: str = Field(..., min_length=3)
    patch: str | None = Field(None, description="Kubernetes manifests (YAML) that apply the fix; never a Secret.")
    commands: Annotated[list[Command], Field(max_length=MAX_COMMANDS)] = []

    @field_validator("text")
    @classmethod
    def _text(cls, v: str) -> str:
        return _prose("fix.text", v, MAX_FIX_TEXT)

    @field_validator("patch")
    @classmethod
    def _patch(cls, v: str | None) -> str | None:
        if v is None:
            return None
        from kube_noob.errors import ManifestError
        from kube_noob.learn.memory import contains_credential
        from kube_noob.yamlio import load_documents

        if len(v) > MAX_PATCH:
            raise ValueError(f"fix.patch is longer than {MAX_PATCH} characters; keep large manifests in Git")
        try:
            docs = [d.data for d in load_documents(v)]
        except ManifestError as exc:
            raise ValueError(f"fix.patch is not valid YAML: {exc}") from None
        if not docs or not all(isinstance(d, dict) and d.get("apiVersion") and d.get("kind") for d in docs):
            raise ValueError("fix.patch must be Kubernetes manifests, each with apiVersion and kind")
        if any(str(d.get("kind")) == "Secret" for d in docs):
            raise ValueError("fix.patch contains a Secret; memory entries never store Secrets")
        if contains_credential(v):
            raise ValueError("fix.patch looks like it contains a credential; memory entries never store secrets")
        return v


class Evidence(_Model):
    kind: Literal["url", "ticket", "citation", "bundle"]
    ref: str = Field(..., min_length=1, max_length=900)
    note: str | None = None

    @model_validator(mode="after")
    def _reference_only(self) -> Evidence:
        pattern = {"url": _URL, "ticket": _TICKET_KEY, "citation": _CITATION, "bundle": _BUNDLE}[self.kind]
        if not pattern.match(self.ref):
            raise ValueError(
                f"evidence {self.kind} {self.ref[:60]!r} is not a reference: give an https URL, a ticket key "
                "(OCPBUGS-123), a citation (kn:doc#0, mem:MEM-4) or a bundle path (bundle:<dir>/<file>), never output"
            )
        if self.note is not None:
            _prose("evidence.note", self.note, MAX_NOTE)
        return self


class Outcome(_Model):
    date: date
    result: Literal["resolved", "not-resolved", "partial"]
    ticket: str | None = Field(None, max_length=100, pattern=_whole(_OPAQUE))
    cluster: str | None = Field(None, max_length=63, pattern=_whole(_CLUSTER))

    @field_validator("ticket", "cluster", mode="before")
    @classmethod
    def _named(cls, v: Any, info: Any) -> Any:
        pattern = _OPAQUE if info.field_name == "ticket" else _CLUSTER
        if v is not None and (not isinstance(v, str) or not pattern.match(v)):
            what = "an opaque ticket ref such as INC-4211" if info.field_name == "ticket" else "a cluster label"
            raise ValueError(f"{info.field_name} {v!r} is not {what} ({pattern.pattern})")
        return v


class RiskAccepted(_Model):
    owner: str = Field(..., max_length=100, pattern=_whole(_OWNER))
    reason: str
    expires: date | None = None

    @field_validator("reason")
    @classmethod
    def _reason(cls, v: str) -> str:
        return _prose("riskAccepted.reason", v, MAX_NOTE * 2)


_OwnerName = Annotated[str, Field(max_length=100, pattern=_whole(_OWNER))]
_SourceUrl = Annotated[str, Field(max_length=900, pattern=_whole(_URL))]


class MemoryEntry(_Model):
    id: str = Field(..., pattern=r"^MEM-[1-9]\d{0,6}$")
    status: Literal["proposed", "approved", "retired"]
    kind: Literal["fix", "negative", "runbook"]
    signals: Annotated[list[SignalRef], Field(max_length=MAX_SIGNALS)] = []
    symptom: str
    platform: Platform
    versions: Versions = Versions()
    operators: Annotated[list[OperatorRange], Field(max_length=MAX_LIST)] = []
    cause: str
    fix: Fix
    evidence: Annotated[list[Evidence], Field(max_length=MAX_EVIDENCE)] = []
    outcomes: Annotated[list[Outcome], Field(max_length=MAX_OUTCOMES)] = []
    owners: Annotated[
        list[Annotated[str, Field(max_length=100, pattern=_whole(_OWNER))]], Field(min_length=1, max_length=MAX_LIST)
    ]
    sources: Annotated[
        list[Annotated[str, Field(max_length=900, pattern=_whole(_URL))]], Field(max_length=MAX_LIST)
    ] = []
    created: date
    updated: date
    review_by: date | None = Field(None, alias="reviewBy")
    risk_accepted: RiskAccepted | None = Field(None, alias="riskAccepted")

    @field_validator("id", "status", "kind", "platform", mode="before")
    @classmethod
    def _plain(cls, v: Any, info: Any) -> Any:
        allowed = {
            "status": "proposed, approved or retired",
            "kind": "fix, negative or runbook",
            "platform": ", ".join(PLATFORMS),
            "id": "MEM-<n> with n from 1",
        }[info.field_name]
        if not isinstance(v, str):
            raise ValueError(f"{info.field_name} must be {allowed}")
        return v

    @field_validator("symptom")
    @classmethod
    def _symptom(cls, v: str) -> str:
        return _prose("symptom", v, MAX_SYMPTOM)

    @field_validator("cause")
    @classmethod
    def _cause(cls, v: str) -> str:
        return _prose("cause", v, MAX_CAUSE)

    @field_validator("sources", mode="before")
    @classmethod
    def _https(cls, v: Any) -> Any:
        if isinstance(v, list):
            for url in v:
                if not isinstance(url, str) or not _URL.match(url):
                    raise ValueError(f"source {url!r} must be an https URL")
        return v

    @model_validator(mode="after")
    def _dates(self) -> MemoryEntry:
        if self.updated < self.created:
            raise ValueError(f"updated {self.updated} is before created {self.created}")
        return self

    @property
    def number(self) -> int:
        return int(self.id.split("-", 1)[1])

    def fixed_for(self, version: str | None) -> bool:
        """True when ``version`` already carries the fix (``fixedIn`` at or below it): the entry is history there."""
        if not version or not self.versions.fixed_in or not _VERSION.match(version):
            return False
        have, want = vkey(version), vkey(self.versions.fixed_in)
        n = max(len(have), len(want))
        return have + (0,) * (n - len(have)) >= want + (0,) * (n - len(want))
