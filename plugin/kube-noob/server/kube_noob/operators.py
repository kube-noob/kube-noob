"""Installed-operator inventory (E2): which OLM operators are installed, at what version, from which catalog and
channel, with what approval mode, in which namespaces and in what phase -- and, as part of the same answer, what
could not be read. An inventory that could not see the OLM objects says "not determined"; it never says "no
operators", because that is the absence-reads-as-a-pass this project exists to refuse.

Three inputs feed one builder: manifest files (``from_manifests``), a must-gather (``kube_noob.mustgather.operators``,
which the Claude plugin does not ship) and the live cluster through the read-only allowlisted backend
(``collect_live``: ClusterServiceVersions and Subscriptions only, never Secrets).

Every field, label and annotation below was read in the source that defines it (the commit is the citation):

- operator-framework/api e1a542ceb01262523627440bde3a0b3387bdeb16
  - ``pkg/operators/v1alpha1/clusterserviceversion_types.go``: ``spec.version`` (an OperatorVersion, semver),
    ``status.phase`` (Pending, InstallReady, Installing, Succeeded, Failed, Unknown, Replacing, Deleting),
    ``status.reason`` Copied (CSVReasonCopied), ``status.message``.
  - ``pkg/operators/v1alpha1/clusterserviceversion.go``: ``CopiedLabelKey = "olm.copiedFrom"``; ``IsCopied`` is
    true for reason Copied, for that label, or for an ``olm.operatorNamespace`` annotation naming another namespace.
  - ``pkg/operators/v1alpha1/subscription_types.go``: ``spec.name`` (the package), ``spec.source``,
    ``spec.sourceNamespace``, ``spec.channel``, ``spec.installPlanApproval`` (Automatic or Manual; absent means
    Automatic, ``GetInstallPlanApproval``), ``status.installedCSV``, ``status.currentCSV``, ``status.state``,
    ``status.installPlanRef``, conditions InstallPlanPending, InstallPlanFailed, InstallPlanMissing,
    ResolutionFailed, BundleUnpackFailed, CatalogSourcesUnhealthy.
  - ``pkg/operators/v1alpha1/installplan_types.go``: ``spec.clusterServiceVersionNames``, ``spec.approval``,
    ``spec.approved``, ``status.phase`` (Planning, RequiresApproval, Installing, Complete, Failed).
  - ``pkg/operators/v1/operatorgroup_types.go``: annotations ``olm.targetNamespaces`` (``BuildTargetNamespaces``:
    ``status.namespaces`` sorted and joined with commas; the empty namespace means all of them) and
    ``olm.operatorNamespace``; ``spec.targetNamespaces``, ``status.namespaces``.
  - ``crds/operators.coreos.com_{clusterserviceversions,subscriptions}.yaml``: group operators.coreos.com, version
    v1alpha1 (served, storage), scope Namespaced, category ``olm``.
- operator-framework/operator-lifecycle-manager f4ec58f8678b04ca27d953db4eb08ed918ed3b18
  - ``pkg/controller/operators/olm/operatorgroup.go`` ``csvCopyPrototype``: a copy carries the label
    ``olm.copiedFrom=<the source namespace>``, ``status.reason`` Copied, the source's spec and status, and no
    ``olm.targetNamespaces`` annotation.
  - ``pkg/controller/operators/olm/operator.go``: OLM itself lists the originals with the selector
    ``!olm.copiedFrom``, which is what a cluster-wide live read here uses.
  - ``pkg/controller/operators/catalog/subscription/state.go``: an InstallPlan in RequiresApproval shows on its
    Subscription as condition InstallPlanPending with reason RequiresApproval, so a live read that has no
    InstallPlans still sees a Manual approval waiting.
  - ``pkg/controller/registry/resolver/projection/properties.go`` and ``steps.go``: the annotation
    ``operatorframework.io/properties``, JSON ``{"properties": [{"type": ..., "value": ...}]}``.
- operator-framework/operator-registry 3f41ded86df8e755d6a51d70f10cd50a489ef4b9 ``alpha/property/property.go``:
  property type ``olm.package`` with value ``{"packageName", "version"}``.

What reads as an answer, and what does not (G270). The verdict is ``listed`` only when every object the answer
needs was read and nothing was skipped. Any of these makes it ``partial`` (or ``not-determined`` when no
ClusterServiceVersion was read at all), and each is named in ``caveats``: a file that could not be read or was
skipped by the reader; a file in an OLM path that held no usable object of that kind; an item in a typed list that is
not an object of that kind; objects past ``MAX_ITEMS``; an object named like an OLM kind from another API group
(ignored, and a caveat); two objects with one name and different content; a Subscription with no status; a namespace
whose Subscriptions were not read. ``no-olm`` needs a 404 on ``operators.coreos.com`` for both live reads, in the
exact words the backends write for a missing resource type, never just "not found".

Joining: a Subscription names its installed CSV in ``status.installedCSV`` and is joined on that alone, to a CSV
that is an original in its own namespace; a copy never stands in for one. ``currentCSV`` is only ever the upgrade
(or install) in flight. One entry per CSV, however many Subscriptions name it.

Safety: Secret objects in the input are dropped unread; only named fields are read (a Subscription's
``spec.config``, which can carry environment values, never is); every string shown is made printable by
``sanitize.visible`` and redacted; names and versions that are not valid are not shown as names or versions. The
output is bounded and sorted, and evidence names an object and its file rather than a document position, so the
same objects in any order give the same bytes; duplicates that disagree are resolved by content and flagged.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel

from kube_noob.debug.cluster import redact_text
from kube_noob.sanitize import visible

GROUP = "operators.coreos.com"
RESOURCES = ("clusterserviceversions", "subscriptions", "installplans", "operatorgroups")
KIND_TO_RESOURCE = {
    "ClusterServiceVersion": "clusterserviceversions",
    "Subscription": "subscriptions",
    "InstallPlan": "installplans",
    "OperatorGroup": "operatorgroups",
}
RESOURCE_TO_KIND = {r: k for k, r in KIND_TO_RESOURCE.items()}
#: Read live. InstallPlans and OperatorGroups are not on the read-only allowlist: what they add here (a waiting
#: approval, the target namespaces) the Subscription's conditions and the CSV's annotation already carry.
LIVE_RESOURCES = ("clusterserviceversions", "subscriptions")
#: What the answer needs. InstallPlans and OperatorGroups only add detail, so their absence is not a gap.
REQUIRED = ("clusterserviceversions", "subscriptions")
#: status.phase values OLM defines (clusterserviceversion_types.go). Anything else is shown as unknown.
PHASES = frozenset({"Pending", "InstallReady", "Installing", "Succeeded", "Failed", "Unknown", "Replacing", "Deleting"})

MAX_OPERATORS = 500
MAX_NAMESPACES = 100
MAX_ITEMS = 50_000  # objects of one resource read from one source
MAX_PROPERTIES_BYTES = 64 * 1024
MAX_PROBLEMS = 5
MAX_UNREADABLE = 50
TEXT_LIMIT = 300

COPIED_LABEL = "olm.copiedFrom"
OPERATOR_NAMESPACE = "olm.operatorNamespace"
TARGET_NAMESPACES = "olm.targetNamespaces"
PROPERTIES = "operatorframework.io/properties"
#: Subscription conditions that say why nothing is (or will be) installed, when their status is True.
_PROBLEM_CONDITIONS = (
    "ResolutionFailed",
    "InstallPlanFailed",
    "InstallPlanMissing",
    "BundleUnpackFailed",
    "CatalogSourcesUnhealthy",
)
NOT_COVERED = (
    "Operators installed without OLM (Helm charts, plain manifests, OLM v1 ClusterExtensions) are outside this "
    "inventory: it reads operators.coreos.com objects only."
)
#: Kinds kube-noob never reads, wherever they appear: counted and dropped.
_NEVER_READ = frozenset({"Secret", "SecretList"})

_NAME = re.compile(r"^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?\Z")
_REASON = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,127}\Z")
# a channel is free text in the CRD; this is what is shown as written, anything else is flattened and marked
_CHANNEL = re.compile(r"^[a-z0-9]([-a-z0-9._/]{0,126}[a-z0-9])?\Z")
_CORE = r"(?:0|[1-9]\d{0,8})\.(?:0|[1-9]\d{0,8})\.(?:0|[1-9]\d{0,8})"
_SUFFIX = r"(?:-[0-9A-Za-z.-]{1,64})?(?:\+[0-9A-Za-z.-]{1,64})?"
_SEMVER = re.compile(rf"^{_CORE}{_SUFFIX}\Z")
# `<package>.v<semver>`, the naming convention OLM bundles follow; used only when no field states the version
_NAMED_VERSION = re.compile(rf"\.v({_CORE}{_SUFFIX})\Z")
_NOT_SERVED = re.compile(
    r"the server (?:doesn't|does not) have a resource type \"(?P<r>[a-z]+)(?:\.operators\.coreos\.com)?\""
)
_IN_CLUSTER_404 = re.compile(
    r"^Not found: GET /apis/operators\.coreos\.com/v1alpha1/(?:namespaces/[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?/)?"
    r"(?P<r>[a-z]+)\Z"
)

State = Literal[
    "installed",
    "upgrade-pending",
    "not-installed",
    "csv-missing",
    "csv-not-read",
    "status-not-read",
    "no-subscription",
    "subscription-not-read",
]
#: States whose answer was not read rather than read: any of them makes the verdict partial.
UNDETERMINED_STATES = frozenset({"csv-not-read", "status-not-read", "subscription-not-read"})
ReadState = Literal["read", "partial", "not-read", "not-served"]
Verdict = Literal["listed", "partial", "not-determined", "no-olm"]


class _Out(BaseModel):
    model_config = ConfigDict(extra="forbid", alias_generator=to_camel, populate_by_name=True)


class SourceRead(_Out):
    """What one input could see of one resource."""

    resource: str
    state: ReadState
    objects: int = 0
    reason: str = ""


class Operator(_Out):
    """One installed (or subscribed-to) operator. ``package`` and ``version`` are the stable keys a later match
    against known issues needs; each says where it came from, because a version read off a name is a guess."""

    state: State
    namespace: str
    package: str | None = None
    package_from: Literal["subscription", "csv-properties"] | None = None
    csv: str | None = None
    version: str | None = None
    version_from: Literal["spec.version", "csv-properties", "derived-from-name"] | None = None
    phase: str | None = None
    reason: str | None = None
    message: str | None = None
    subscription: str | None = None
    catalog: str | None = None
    catalog_namespace: str | None = None
    channel: str | None = None
    approval: Literal["Automatic", "Manual"] | None = None
    approval_defaulted: bool | None = None
    installed_csv: str | None = Field(None, alias="installedCSV")  # upstream's own spelling
    upgrade_to: str | None = None
    awaiting_approval: bool = False
    all_namespaces: bool | None = None
    target_namespaces: list[str] | None = None
    target_namespaces_total: int | None = None
    target_namespaces_from: Literal["csv-annotation", "operatorgroup"] | None = None
    copied_into: list[str] = Field(default_factory=list)
    copied_into_total: int | None = None
    problems: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)


@dataclass
class Obj:
    doc: dict[str, Any]
    where: str
    namespace: str
    name: str
    notes: list[str] = field(default_factory=list)
    wheres: list[str] = field(default_factory=list)


@dataclass
class Collected:
    """The OLM objects one input held, and what it could and could not read. ``namespaces`` is None when every
    namespace was read, else the namespaces that were."""

    source: Literal["manifests", "must-gather", "live"]
    objects: dict[str, list[Obj]] = field(default_factory=lambda: {r: [] for r in RESOURCES})
    reads: dict[str, SourceRead] = field(default_factory=dict)
    namespaces: frozenset[str] | None = None
    caveats: list[str] = field(default_factory=list)
    unreadable: list[dict[str, str]] = field(default_factory=list)
    dropped_unread: int = 0  # objects of a kind never read (Secrets): counted, never parsed further
    dropped: Counter[str] = field(default_factory=Counter)  # objects past MAX_ITEMS, per resource: never silent
    rejected: Counter[str] = field(default_factory=Counter)  # items in an OLM context that were not usable objects
    foreign: Counter[str] = field(default_factory=Counter)  # "<resource> <apiVersion>" named like OLM, other group
    subscription_namespaces: set[str] = field(default_factory=set)  # where a file set held a Subscription

    def add(self, doc: Any, where: str, default_ns: str = "", expect: str = "") -> bool:
        """Keep an OLM object; returns whether it was kept. ``expect`` is the kind the context promises (a typed
        list, a must-gather path, a live read): there, anything that is not a usable object of that kind is counted
        as rejected, which makes the answer partial. Without it, other kinds are simply not OLM objects."""
        expected = KIND_TO_RESOURCE.get(expect)
        if not isinstance(doc, dict):
            if expected:
                self.rejected[expected] += 1
            return False
        stated = doc.get("kind")
        kind = stated if isinstance(stated, str) and stated else expect
        if kind in _NEVER_READ:
            self.dropped_unread += 1
            return False
        resource = KIND_TO_RESOURCE.get(kind)
        if resource is None or (expected and resource != expected):
            if expected:
                self.rejected[expected] += 1
            return False
        api = doc.get("apiVersion")
        if api not in (None, "") and not (isinstance(api, str) and api.startswith(GROUP + "/")):
            self.foreign[f"{RESOURCE_TO_KIND[resource]} {_text(api, 80) or '<not a string>'}"] += 1
            if expected:
                self.rejected[expected] += 1
            return False
        meta = _d(doc.get("metadata"))
        name, ns = meta.get("name"), meta.get("namespace")
        if not isinstance(name, str) or not name:
            self.rejected[resource] += 1
            return False
        notes: list[str] = []
        if isinstance(ns, str) and ns:
            if default_ns and ns != default_ns:
                notes.append(
                    f"its metadata.namespace {_shown(ns)} differs from the namespace in its path "
                    f"{_shown(default_ns)}: it is attributed to {_shown(ns)}"
                )
        else:
            ns = default_ns
        if resource == "subscriptions":
            self.subscription_namespaces.add(ns)
        if len(self.objects[resource]) < MAX_ITEMS:
            self.objects[resource].append(Obj(doc, where, ns, name, notes))
        else:
            self.dropped[resource] += 1
        return True

    def overflow(self, resource: str, n: int) -> None:
        """``n`` more objects of ``resource`` than were looked at: a list sliced at MAX_ITEMS."""
        if n > 0:
            self.dropped[resource] += n


# ------------------------------------------------------------------------------------------------- helpers ----


def _d(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _l(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _text(value: Any, limit: int = TEXT_LIMIT) -> str:
    """One safe line: every non-printing character removed (``sanitize.visible``), whitespace collapsed,
    credentials redacted, length capped."""
    if not isinstance(value, str):
        return ""
    s = " ".join(visible(value[: limit * 4]).split())
    s = redact_text(s)
    return s if len(s) <= limit else s[: limit - 3] + "..."


def _shown(value: str) -> str:
    """A name as it may be shown: a valid name as is, anything else flattened and marked with <> so it is not
    mistaken for a name."""
    return value if _NAME.match(value) else f"<{_text(value, 120) or 'unnamed'}>"


def _valid(value: Any, rx: re.Pattern[str] = _NAME) -> str | None:
    return value if isinstance(value, str) and rx.match(value) else None


def _field(value: Any, rx: re.Pattern[str], what: str, notes: list[str]) -> str | None:
    """A field as it may be shown: valid as is; a string that is not valid flattened and marked with <> (it is
    present, so it is never shown as unknown); anything else absent, with a note when it was there."""
    if value is None or value == "":
        return None
    if isinstance(value, str):
        if rx.match(value):
            return value
        notes.append(f"{what} is not in the form this reads, shown flattened")
        return f"<{_text(value, 120) or '?'}>"
    notes.append(f"{what} is present but not a string ({type(value).__name__}), so it is not shown")
    return None


def _true(cond: dict[str, Any] | None) -> bool:
    """A condition's status is the string "True"; YAML written by hand may carry the boolean."""
    return bool(cond) and (cond or {}).get("status") in ("True", True)


def _copied_label(obj: Obj) -> str | None:
    value = _d(_d(obj.doc.get("metadata")).get("labels")).get(COPIED_LABEL)
    return value if isinstance(value, str) else None


def is_copy(obj: Obj) -> bool:
    """operator-framework/api ``IsCopied``: reason Copied, the copiedFrom label, or an operator namespace that is
    not this one. A copiedFrom label naming the object's own namespace -- something OLM never writes -- is not taken
    as a copy, so it cannot fold a second install into a first."""
    meta = _d(obj.doc.get("metadata"))
    label = _copied_label(obj)
    if label is not None and label != obj.namespace:
        return True
    if _d(obj.doc.get("status")).get("reason") == "Copied" and label is None:
        return True
    operator_ns = _d(meta.get("annotations")).get(OPERATOR_NAMESPACE)
    return isinstance(operator_ns, str) and bool(operator_ns) and operator_ns != obj.namespace


def _origin(obj: Obj) -> str | None:
    meta = _d(obj.doc.get("metadata"))
    for candidate in (_copied_label(obj), _d(meta.get("annotations")).get(OPERATOR_NAMESPACE)):
        if _valid(candidate) and candidate != obj.namespace:
            return str(candidate)
    return None


def _package_property(doc: dict[str, Any], notes: list[str]) -> dict[str, Any]:
    """The ``olm.package`` property of a CSV, or {} with a note saying why it could not be used."""
    raw = _d(_d(doc.get("metadata")).get("annotations")).get(PROPERTIES)
    if raw is None:
        return {}
    if not isinstance(raw, str) or len(raw) > MAX_PROPERTIES_BYTES:
        notes.append(f"the {PROPERTIES} annotation could not be read (not a string, or over 64 KiB)")
        return {}
    from kube_noob import sanitize

    try:
        parsed = sanitize.loads_bounded(raw)  # depth counted first: a nesting bomb is refused the same everywhere
    except ValueError:
        notes.append(f"the {PROPERTIES} annotation could not be read (not JSON, or nested too deeply)")
        return {}
    found = [
        _d(p.get("value"))
        for p in _l(_d(parsed).get("properties"))
        if isinstance(p, dict) and p.get("type") == "olm.package"
    ]
    distinct = {json.dumps(v, sort_keys=True, default=str) for v in found}
    if len(distinct) > 1:
        notes.append(
            f"the {PROPERTIES} annotation holds {len(distinct)} olm.package properties that disagree: none used"
        )
        return {}
    return found[0] if found else {}


def _version(doc: dict[str, Any], name: str, notes: list[str]) -> tuple[str | None, Any]:
    stated = _d(doc.get("spec")).get("version")
    if _valid(stated, _SEMVER):
        return str(stated), "spec.version"
    if stated not in (None, ""):
        notes.append("spec.version is not a semantic version, so it is not used")
    prop = _valid(_package_property(doc, []).get("version"), _SEMVER)
    if prop:
        return prop, "csv-properties"
    m = _NAMED_VERSION.search(name)
    if m:
        return m.group(1), "derived-from-name"
    return None, None


def _targets(original: Obj | None, groups: list[Obj]) -> tuple[list[str] | None, Any]:
    if original is not None:
        raw = _d(_d(original.doc.get("metadata")).get("annotations")).get(TARGET_NAMESPACES)
        if isinstance(raw, str):
            return sorted({p.strip() for p in raw[:200_000].split(",")}), "csv-annotation"
    if len(groups) == 1:  # OLM refuses to install with more than one OperatorGroup in a namespace
        g = groups[0].doc
        status_ns = _d(g.get("status")).get("namespaces")
        spec_ns = _d(g.get("spec")).get("targetNamespaces")
        chosen = status_ns if isinstance(status_ns, list) else spec_ns
        if isinstance(chosen, list):
            return sorted({str(n) for n in chosen[:200_000] if isinstance(n, str)}), "operatorgroup"
        if not _d(g.get("spec")).get("selector"):
            return [""], "operatorgroup"  # no targets and no selector: an AllNamespaces group
    return None, None


def _names(values: Iterable[str]) -> tuple[list[str], int]:
    shown = sorted({_shown(v) for v in values})
    return shown[:MAX_NAMESPACES], len(shown)


def _conditions(status: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for c in _l(status.get("conditions"))[:64]:
        if isinstance(c, dict) and isinstance(c.get("type"), str) and c["type"] not in out:
            out[c["type"]] = c
    return out


def _fingerprint(doc: dict[str, Any]) -> str:
    return json.dumps(doc, sort_keys=True, default=str)


# ------------------------------------------------------------------------------------------------- inputs ----


def _finish_file_set(c: Collected) -> Collected:
    for resource in RESOURCES:
        kept = len(c.objects[resource])
        gaps = c.rejected[resource] + c.dropped[resource]
        if kept or resource in c.reads:
            state: ReadState = "partial" if gaps else "read"
            reason = f"{gaps} object(s) of this kind were not usable or not read" if gaps else ""
            c.reads[resource] = SourceRead(resource=resource, state=state, objects=kept, reason=reason)
        elif c.rejected[resource]:
            c.reads[resource] = SourceRead(
                resource=resource,
                state="not-read",
                reason=f"{c.rejected[resource]} item(s) in the input were not usable "
                f"{RESOURCE_TO_KIND[resource]} objects",
            )
        else:
            c.reads[resource] = SourceRead(
                resource=resource,
                state="not-read",
                reason=f"no {RESOURCE_TO_KIND[resource]} in the input, so it was not read",
            )
    return c


def _add_document(c: Collected, doc: Any, label: str) -> None:
    if not isinstance(doc, dict):
        return
    kind = str(doc.get("kind") or "")
    items = doc.get("items")
    if kind.endswith("List") and kind not in _NEVER_READ:
        element = kind[: -len("List")]
        typed = element in KIND_TO_RESOURCE
        if not isinstance(items, list):
            if typed:
                c.rejected[KIND_TO_RESOURCE[element]] += 1
            return
        if typed:
            # an empty list of this kind is still a read of it
            c.reads.setdefault(KIND_TO_RESOURCE[element], SourceRead(resource=KIND_TO_RESOURCE[element], state="read"))
        for item in items[:MAX_ITEMS]:
            c.add(item, label, expect=element if typed else "")
        if typed:
            c.overflow(KIND_TO_RESOURCE[element], len(items) - MAX_ITEMS)
        elif len(items) > MAX_ITEMS:
            c.caveats.append(f"a List in {label} held {len(items)} items; only the first {MAX_ITEMS} were read")
            c.overflow("clusterserviceversions", len(items) - MAX_ITEMS)  # unknown kinds: counted where it matters
        return
    c.add(doc, label)


def from_sources(sources: Iterable[tuple[str, list[Any]]], unreadable: list[dict[str, str]] | None = None) -> Collected:
    """Collect OLM objects from parsed documents, grouped by the file (or label) they came from. A ``List`` or
    ``<Kind>List`` is opened; Secrets are counted and dropped unread; ``unreadable`` are files the caller could not
    parse, which make the answer partial."""
    c = Collected("manifests")
    c.unreadable = [dict(u) for u in (unreadable or [])]
    for label, docs in sources:
        for doc in docs:
            _add_document(c, doc, label)
    return _finish_file_set(c)


def from_documents(docs: Iterable[Any], label: str = "manifest") -> Collected:
    return from_sources([(label, list(docs))])


def from_manifests(text: str, label: str = "manifest") -> Collected:
    """Collect from YAML text (the ``yamlio`` caps on size, documents, depth and aliases apply)."""
    from kube_noob.yamlio import load_documents

    # yamlio flattens a plain `List` into its items, so its documents are added one by one
    return from_sources([(label, [d.data for d in load_documents(text)])])


def _not_served(resource: str, message: str) -> bool:
    """A 404 because the API group is not served, recognised only in the exact words the two backends write for
    it: kubectl's "the server doesn't have a resource type" for this resource, or the in-cluster backend's "Not
    found" for this group's path. Anything else -- an auth plugin "not found", a proxy's 404, a namespace that does
    not exist -- is a read that failed, which is not determined. (``debug.netpol._tier_absent`` is a looser
    substring match; this inventory does not use it.)"""
    if "forbidden" in message.lower():
        return False
    m = _NOT_SERVED.search(message) or _IN_CLUSTER_404.match(message.strip())
    return m is not None and m.group("r") == resource


def collect_live(backend: Any, namespaces: list[str]) -> Collected:
    """Read ClusterServiceVersions and Subscriptions through the read-only backend (never Secrets: not on its
    allowlist). Cluster-wide, copies are left out with the selector OLM itself uses (``!olm.copiedFrom``) and the
    namespaces an operator serves come from its ``olm.targetNamespaces`` annotation; per namespace, copies are read,
    because a copy is how a namespace shows which operators manage it. A response without an ``items`` list is a
    failed read, not zero objects."""
    from kube_noob.debug.cluster import stamp_api_version
    from kube_noob.errors import KubeNoobError

    c = Collected("live", namespaces=frozenset(namespaces) if namespaces else None)
    scopes: list[str | None] = list(namespaces) if namespaces else [None]
    for resource in LIVE_RESOURCES:
        failures: list[str] = []
        not_served = 0
        for ns in scopes:
            selector = "!olm.copiedFrom" if resource == "clusterserviceversions" and ns is None else None
            try:
                data = backend.get(resource, namespace=ns, selector=selector)
            except KubeNoobError as exc:
                if _not_served(resource, str(exc)):
                    not_served += 1
                failures.append(f"{ns + ': ' if ns else ''}{_text(str(exc), 240)}")
                continue
            items = data.get("items") if isinstance(data, dict) else None
            if not isinstance(items, list):
                failures.append(f"{ns + ': ' if ns else ''}the response held no items list")
                continue
            for item in items[:MAX_ITEMS]:
                stamped = stamp_api_version(resource, item) if isinstance(item, dict) else item
                c.add(stamped, f"live {resource}", ns or "", expect=RESOURCE_TO_KIND[resource])
            c.overflow(resource, len(items) - MAX_ITEMS)
        read_any = len(failures) < len(scopes)
        kept = len(c.objects[resource])
        gaps = c.rejected[resource] + c.dropped[resource]
        if not failures and not gaps:
            state: ReadState = "read"
            reason = "" if c.namespaces is None else "only the namespaces asked for"
        elif not_served == len(scopes):
            state, reason = "not-served", f"{GROUP}/v1alpha1 {resource} is not served (404)"
        elif read_any:
            parts = failures[:5] + ([f"{gaps} object(s) not usable or past the read cap"] if gaps else [])
            state, reason = "partial", "; ".join(parts)
        else:
            state, reason = "not-read", "; ".join(failures[:5])
        c.reads[resource] = SourceRead(resource=resource, state=state, objects=kept, reason=reason)
    # A 404 is "no OLM" only when both reads say it: one resource served and the other not is a contradiction.
    states = {r: c.reads[r].state for r in LIVE_RESOURCES}
    if "not-served" in states.values() and set(states.values()) != {"not-served"}:
        for r, st in states.items():
            if st == "not-served":
                c.reads[r] = SourceRead(
                    resource=r,
                    state="not-read",
                    reason=f"{GROUP} answered 404 for {r} while the other OLM read succeeded: not determined",
                )
    for resource in RESOURCES:
        if resource not in c.reads:
            c.reads[resource] = SourceRead(
                resource=resource, state="not-read", reason="not read live (not on the read-only allowlist)"
            )
    if namespaces:
        c.caveats.append(
            f"only namespaces {', '.join(sorted(namespaces))} were read: an operator installed in any other namespace "
            "is not in this answer, and for one copied into these the Subscription in its own namespace was not read"
        )
    else:
        c.caveats.append(
            "copied ClusterServiceVersions were not read cluster-wide (selector !olm.copiedFrom, as OLM lists them); "
            "the namespaces an operator serves come from its olm.targetNamespaces annotation"
        )
    return c


# ------------------------------------------------------------------------------------------------- builder ----


def _dedupe(objs: list[Obj], conflicts: list[str]) -> list[Obj]:
    """One object per namespace and name. Identical duplicates (two gather images) merge; duplicates that differ
    keep the one that sorts first by content -- not by position, so input order never decides -- and are flagged."""
    by_key: dict[tuple[str, str], list[Obj]] = {}
    for o in objs:
        by_key.setdefault((o.namespace, o.name), []).append(o)
    out: list[Obj] = []
    for (ns, name), group in sorted(by_key.items()):
        wheres = sorted({w for o in group for w in [o.where, *o.wheres]})
        notes = sorted({n for o in group for n in o.notes})
        if len(group) == 1:
            keep = group[0]
        else:
            prints = sorted(((_fingerprint(o.doc), i) for i, o in enumerate(group)))
            keep = group[prints[0][1]]
            if len({p for p, _ in prints}) > 1:
                kind = str(keep.doc.get("kind") or "object")
                conflicts.append(f"{kind} {_shown(ns)}/{_shown(name)}")
                notes.append(
                    f"{len({p for p, _ in prints})} different objects of this name were in the input; the one shown "
                    "was chosen by content, not by position"
                )
        out.append(Obj(keep.doc, keep.where, ns, name, notes, wheres))
    return out


@dataclass
class _Group:
    namespace: str
    name: str
    original: Obj | None = None
    copies: dict[str, Obj] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def representative(self) -> Obj:
        return self.original or self.copies[min(self.copies)]


def _same_install(a: Obj, b: Obj) -> bool:
    """A copy carries its source's spec and status, so a copy whose version or phase differs is not that install."""
    return _d(a.doc.get("spec")).get("version") == _d(b.doc.get("spec")).get("version") and _d(a.doc.get("status")).get(
        "phase"
    ) == _d(b.doc.get("status")).get("phase")


def _groups(csvs: list[Obj]) -> dict[tuple[str, str], _Group]:
    """One group per installed CSV: the original in the operator's namespace and its copies folded into it.

    A copy names its source namespace in the olm.copiedFrom label (or the olm.operatorNamespace annotation). One that
    names neither -- marked only by status.reason Copied -- is folded into the single original of that name when
    there is exactly one. A copy whose version or phase differs from the original it names is not folded: it is
    shown on its own, because folding it would hide a second install's state.
    """
    groups: dict[tuple[str, str], _Group] = {}
    copies: list[Obj] = []
    for obj in csvs:
        if is_copy(obj):
            copies.append(obj)
        else:
            g = groups.setdefault((obj.namespace, obj.name), _Group(obj.namespace, obj.name))
            g.original = obj
            label = _copied_label(obj)
            if label is not None:
                g.notes.append("labelled olm.copiedFrom its own namespace, which OLM never writes: read as an install")
    originals_by_name: dict[str, list[tuple[str, str]]] = {}
    for key in groups:
        originals_by_name.setdefault(key[1], []).append(key)

    def alone(obj: Obj, why: str) -> None:
        g = groups.setdefault((obj.namespace, obj.name), _Group(obj.namespace, obj.name))
        g.original = g.original or obj
        g.notes.append(why)

    for obj in copies:
        origin = _origin(obj)
        if origin is None:
            same = originals_by_name.get(obj.name, [])
            if len(same) == 1 and _same_install(groups[same[0]].original or obj, obj):
                groups[same[0]].copies.setdefault(obj.namespace, obj)
            else:
                alone(
                    obj,
                    "marked as a copy (status.reason Copied) without naming its source, and no single original of "
                    "that name matches it: shown as its own install",
                )
            continue
        target = groups.get((origin, obj.name))
        if target is not None and target.original is not None and not _same_install(target.original, obj):
            alone(
                obj,
                f"marked as a copy from {_shown(origin)}, but its version or phase differs from the original there: "
                "shown as its own install",
            )
            continue
        groups.setdefault((origin, obj.name), _Group(origin, obj.name)).copies.setdefault(obj.namespace, obj)
    return groups


def _plan_index(plans: list[Obj]) -> tuple[dict[str, list[Obj]], dict[str, list[Obj]]]:
    by_name: dict[str, list[Obj]] = {}
    by_csv: dict[str, list[Obj]] = {}
    for p in plans:
        by_name.setdefault(p.name, []).append(p)
        for n in _l(_d(p.doc.get("spec")).get("clusterServiceVersionNames"))[:1000]:
            if isinstance(n, str):
                by_csv.setdefault(n, []).append(p)
    return by_name, by_csv


def _awaiting(status: dict[str, Any], index: tuple[dict[str, list[Obj]], dict[str, list[Obj]]], csvs: set[str]) -> bool:
    cond = _conditions(status).get("InstallPlanPending")
    if _true(cond) and (cond or {}).get("reason") == "RequiresApproval":
        return True
    by_name, by_csv = index
    ref = _d(status.get("installPlanRef")).get("name")
    candidates = list(by_name.get(ref, [])) if isinstance(ref, str) else []
    for n in csvs:
        candidates += by_csv.get(n, [])
    return any(_d(p.doc.get("status")).get("phase") == "RequiresApproval" for p in candidates)


def _csv_fields(op: dict[str, Any], g: _Group, groups_in_ns: list[Obj]) -> None:
    rep = g.representative()
    status = _d(rep.doc.get("status"))
    notes: list[str] = op["notes"]
    notes += g.notes
    for o in [*([g.original] if g.original else []), *g.copies.values()]:
        notes += o.notes
    op["csv"] = _shown(g.name)
    op["version"], op["version_from"] = _version(rep.doc, g.name, notes)
    phase = status.get("phase")
    if phase in PHASES:
        op["phase"] = phase
    elif phase in (None, ""):
        notes.append("status.phase is not in the input: the phase is unknown")
    else:
        notes.append(f"status.phase {_text(str(phase), 60)!r} is not one OLM defines: the phase is unknown")
    reason = _valid(status.get("reason"), _REASON)
    op["reason"] = reason if reason != "Copied" else None
    if op.get("phase") != "Succeeded":
        op["message"] = _text(status.get("message")) or None
    prop = _package_property(rep.doc, notes)
    pkg = _valid(prop.get("packageName"))
    if op.get("package") is None:
        if pkg:
            op["package"], op["package_from"] = pkg, "csv-properties"
    elif pkg and pkg != op["package"]:
        notes.append(f"the CSV's olm.package property names package {pkg}, the Subscription {op['package']}")
    targets, source = _targets(g.original, groups_in_ns)
    if targets is not None:
        op["all_namespaces"] = "" in targets
        shown, total = _names(t for t in targets if t)
        op["target_namespaces"] = shown
        if total > len(shown):
            op["target_namespaces_total"] = total
        op["target_namespaces_from"] = source
    copies, total = _names(g.copies)
    op["copied_into"] = copies
    if total > len(copies):
        op["copied_into_total"] = total
    if g.original is None:
        notes.append(f"the original in {_shown(g.namespace)} was not in the input: known from its copies")
    sources = [*([g.original] if g.original else []), *g.copies.values()]
    op["evidence"] = sorted({*op["evidence"], *(_text(w, 300) for o in sources for w in [o.where, *o.wheres])})[:5]


def _subscription_fields(op: dict[str, Any], sub: Obj) -> None:
    spec, status = _d(sub.doc.get("spec")), _d(sub.doc.get("status"))
    notes: list[str] = op["notes"]
    notes += sub.notes
    op["subscription"] = _shown(sub.name)
    pkg = _valid(spec.get("name"))
    if pkg:
        op["package"], op["package_from"] = pkg, "subscription"
    elif spec.get("name") not in (None, ""):
        notes.append("spec.name (the package) is not a valid name, so it is not used as one")
    op["catalog"] = _field(spec.get("source"), _NAME, "spec.source (the catalog)", notes)
    op["catalog_namespace"] = _field(spec.get("sourceNamespace"), _NAME, "spec.sourceNamespace", notes)
    op["channel"] = _field(spec.get("channel"), _CHANNEL, "spec.channel", notes)
    approval = spec.get("installPlanApproval")
    op["approval"] = "Manual" if approval == "Manual" else "Automatic"
    op["approval_defaulted"] = approval in (None, "")
    if approval not in (None, "", "Manual", "Automatic"):
        notes.append(
            f"spec.installPlanApproval is {_text(str(approval), 40)!r}, which is neither Manual nor Automatic; "
            "OLM treats anything but Manual as Automatic"
        )
    op["installed_csv"] = _valid(status.get("installedCSV"))
    conditions = _conditions(status)
    problems: list[str] = []
    for t in _PROBLEM_CONDITIONS:
        cond = conditions.get(t)
        if cond is not None and _true(cond):
            problems.append(f"{t}: {_text(cond.get('message'), 200) or _valid(cond.get('reason'), _REASON) or 'True'}")
    op["problems"] = problems[:MAX_PROBLEMS]
    if status.get("state") == "UpgradeFailed":
        op["problems"].append("state UpgradeFailed")
    op["evidence"] = sorted({*op["evidence"], *(_text(w, 300) for w in [sub.where, *sub.wheres])})[:5]


def _sort_key(op: Operator) -> tuple[str, str, str, str]:
    return (op.namespace, op.package or "", op.csv or "", op.subscription or "")


def _subscription_read_for(c: Collected, ns: str) -> bool:
    """Whether the Subscriptions of a namespace were read, so a CSV there with none is truly without one. A file
    set can only show it for a namespace it holds a Subscription in."""
    read = c.reads.get("subscriptions")
    if read is None or read.state != "read":
        return False
    if c.source == "manifests":
        return ns in c.subscription_namespaces
    return c.namespaces is None or ns in c.namespaces


def inventory(c: Collected, *, top: int = MAX_OPERATORS) -> dict[str, Any]:
    """The inventory of what ``c`` holds. Deterministic: the same objects in any order give the same bytes."""
    conflicts: list[str] = []
    objects = {r: _dedupe(c.objects[r], conflicts) for r in RESOURCES}
    groups = _groups(objects["clusterserviceversions"])
    by_ns: dict[str, dict[str, list[Obj]]] = {r: {} for r in RESOURCES}
    for resource in ("subscriptions", "installplans", "operatorgroups"):
        for obj in objects[resource]:
            by_ns[resource].setdefault(obj.namespace, []).append(obj)
    plan_index = {ns: _plan_index(plans) for ns, plans in by_ns["installplans"].items()}
    no_plans: tuple[dict[str, list[Obj]], dict[str, list[Obj]]] = ({}, {})
    csv_read = c.reads["clusterserviceversions"].state in ("read", "partial")

    def has_original(key: tuple[str, str]) -> bool:
        g = groups.get(key)
        return g is not None and g.original is not None

    entries: list[Operator] = []
    joined: dict[tuple[str, str], dict[str, Any]] = {}
    used: set[tuple[str, str]] = set()
    unclear_ns: set[str] = set()  # a Subscription there carries no usable status: its CSVs' state is not known
    pending: list[dict[str, Any]] = []
    for ns, subs in sorted(by_ns["subscriptions"].items()):
        for sub in subs:
            raw_status = sub.doc.get("status")
            status = _d(raw_status)
            op: dict[str, Any] = {"namespace": _shown(ns), "notes": [], "evidence": []}
            _subscription_fields(op, sub)
            installed_raw = status.get("installedCSV")
            installed = _valid(installed_raw)
            current = _valid(status.get("currentCSV"))
            op["awaiting_approval"] = _awaiting(
                status, plan_index.get(ns, no_plans), {n for n in (current, installed) if n}
            )
            if not status:
                op["state"] = "status-not-read"
                op["notes"].append("the Subscription has no status in the input: what it installed is not known")
                unclear_ns.add(ns)
                pending.append(op)
                continue
            if installed_raw not in (None, "") and installed is None:
                op["state"] = "status-not-read"
                op["notes"].append("status.installedCSV is not a valid name: what it installed is not known")
                unclear_ns.add(ns)
                pending.append(op)
                continue
            if current and current != installed and has_original((ns, current)):
                used.add((ns, current))
                cur = groups[(ns, current)].representative()
                phase = _d(cur.doc.get("status")).get("phase")
                op["notes"].append(
                    f"the incoming CSV {_shown(current)} is present, phase {phase if phase in PHASES else 'unknown'}"
                )
            if not csv_read:
                op["state"] = "csv-not-read"
                op["notes"].append("ClusterServiceVersions were not read, so whether this is installed is not known")
            elif installed:
                key = (ns, installed)
                if key in joined:  # one entry per CSV, however many Subscriptions name it
                    joined[key]["notes"].append(f"Subscription {_shown(sub.name)} also names it as installed")
                    continue
                if has_original(key):
                    used.add(key)
                    _csv_fields(op, groups[key], by_ns["operatorgroups"].get(ns, []))
                    if current and current != installed:
                        op["state"], op["upgrade_to"] = "upgrade-pending", current
                    else:
                        op["state"] = "installed"
                    joined[key] = op
                else:
                    op["state"] = "csv-missing"
                    op["notes"].append(
                        f"the Subscription names {_shown(installed)} as installed, and no ClusterServiceVersion "
                        "of that name was read in its namespace"
                    )
                    if key in groups:  # only copies of it were read: they do not stand in for the install
                        used.add(key)
                        where = ", ".join(sorted(_shown(n) for n in groups[key].copies)[:10])
                        op["notes"].append(f"copies of it were read in {where}, which do not show it installed")
                    if current and current != installed:
                        op["upgrade_to"] = current
            else:
                op["state"] = "not-installed"
                if current:
                    op["upgrade_to"] = current
            pending.append(op)
    entries += [Operator.model_validate(op) for op in pending]
    for key, g in sorted(groups.items()):
        if key in used:
            continue
        ns = g.namespace
        op = {"namespace": _shown(ns), "notes": [], "evidence": []}
        _csv_fields(op, g, by_ns["operatorgroups"].get(ns, []))
        if ns in unclear_ns:
            op["state"] = "subscription-not-read"
            op["notes"].append(
                "a Subscription in its namespace has no usable status, so whether it installed this is not known"
            )
        elif _subscription_read_for(c, ns):
            op["state"] = "no-subscription"
            op["notes"].append(
                "no Subscription in its namespace names it: installed by hand or by the platform itself, so its "
                "catalog, channel and approval are unknown"
                if c.source != "manifests"
                else "no Subscription in the input names it, though the input holds Subscriptions in its namespace: "
                "installed by hand, or its Subscription is not in these files, so its catalog, channel and approval "
                "are unknown"
            )
        else:
            op["state"] = "subscription-not-read"
            op["notes"].append(
                "Subscriptions were not read for its namespace: catalog, channel and approval are not determined"
            )
        entries.append(Operator.model_validate(op))

    for e in entries:
        e.notes = list(dict.fromkeys(e.notes))[:20]
    entries.sort(key=_sort_key)
    return _assemble(c, objects, entries, conflicts, top)


def _verdict(c: Collected, entries: list[Operator], conflicts: list[str]) -> Verdict:
    csv = c.reads["clusterserviceversions"]
    if csv.state == "not-served" and c.reads["subscriptions"].state == "not-served":
        return "no-olm"
    if csv.state in ("not-read", "not-served"):
        return "not-determined"
    gaps = (
        any(c.reads[r].state != "read" for r in REQUIRED)
        or c.unreadable
        or c.namespaces is not None
        or c.dropped
        or c.rejected
        or conflicts
        or any(e.state in UNDETERMINED_STATES for e in entries)
    )
    return "partial" if gaps else "listed"


def _assemble(
    c: Collected, objects: dict[str, list[Obj]], entries: list[Operator], conflicts: list[str], top: int
) -> dict[str, Any]:
    verdict = _verdict(c, entries, conflicts)
    states = Counter(e.state for e in entries)
    counts = {
        "operators": len(entries),
        "installed": states["installed"]
        + states["upgrade-pending"]
        + states["no-subscription"]
        + states["subscription-not-read"],
        "upgradePending": states["upgrade-pending"],
        "awaitingApproval": sum(1 for e in entries if e.awaiting_approval),
        "notInstalled": states["not-installed"] + states["csv-missing"],
        "noSubscription": states["no-subscription"],
        "notDetermined": sum(n for s, n in states.items() if s in UNDETERMINED_STATES),
        "notSucceeded": sum(1 for e in entries if e.csv and e.phase != "Succeeded"),
    }
    caveats = list(c.caveats)
    for r in REQUIRED:
        read = c.reads[r]
        what = "ClusterServiceVersions" if r == "clusterserviceversions" else "Subscriptions"
        if read.state in ("partial", "not-read", "not-served"):
            how = {"partial": "were only partly read", "not-read": "were not read", "not-served": "are not served"}
            caveats.append(f"{what} {how[read.state]}: {read.reason}")
    if c.unreadable:
        caveats.append(f"{len(c.unreadable)} file(s) could not be read; operators in them are not in this answer")
    for r, n in sorted(c.dropped.items()):
        caveats.append(f"{n} {r} past the first {MAX_ITEMS} were not read; operators among them are not in this answer")
    for r, n in sorted(c.rejected.items()):
        caveats.append(f"{n} item(s) where a {RESOURCE_TO_KIND[r]} was expected were not usable objects of that kind")
    for what, n in sorted(c.foreign.items()):
        caveats.append(f"{n} {what} object(s) of another API group were ignored: not OLM's ({GROUP})")
    if conflicts:
        caveats.append(
            f"{len(conflicts)} object(s) appeared more than once with different content: "
            + ", ".join(conflicts[:5])
            + ("" if len(conflicts) <= 5 else f" and {len(conflicts) - 5} more")
        )
    undetermined = sum(1 for e in entries if e.state in UNDETERMINED_STATES)
    if undetermined:
        caveats.append(f"{undetermined} operator(s) have a state that could not be determined from the input")
    shown = entries[:top]
    out: dict[str, Any] = {
        "source": c.source,
        "verdict": verdict,
        "complete": verdict in ("listed", "no-olm"),
        "summary": _summary(c, verdict, counts, caveats),
        "counts": counts,
        "operators": [e.model_dump(by_alias=True, exclude_none=True) for e in shown],
        "operatorsTotal": len(entries),
    }
    if len(entries) > len(shown):
        out["notShown"] = len(entries) - len(shown)
    reads = []
    for r in RESOURCES:
        read = c.reads[r].model_copy()
        if read.state in ("read", "partial"):
            read.objects = len(objects[r])
        reads.append(read.model_dump(by_alias=True))
    out["sources"] = reads
    out["caveats"] = caveats
    out["unreadable"] = c.unreadable[:MAX_UNREADABLE]
    out["unreadableTotal"] = len(c.unreadable)
    out["droppedUnread"] = c.dropped_unread
    out["notCovered"] = NOT_COVERED
    return out


def _summary(c: Collected, verdict: Verdict, counts: dict[str, int], caveats: list[str]) -> str:
    csv = c.reads["clusterserviceversions"]
    if verdict == "no-olm":
        return (
            "not an OLM cluster: operators.coreos.com is not served (404), so there are no OLM-installed operators to "
            "list and nothing here was evaluated. " + NOT_COVERED
        )
    if verdict == "not-determined":
        return (
            "installed operators not determined: ClusterServiceVersions could not be read "
            f"({csv.reason or csv.state}). That does not mean none are installed."
        )
    n = counts["operators"]
    head = f"{n} operator{'s' if n != 1 else ''} from OLM data"
    if verdict == "listed":
        return f"{head}, every OLM object this needs was read"
    sub = c.reads["subscriptions"]
    parts = []
    if sub.state != "read":
        how = "only partly read" if sub.state == "partial" else "not read"
        parts.append(
            f"Subscriptions were {how}, so catalog, channel and approval are not determined for every operator"
        )
    if csv.state == "partial":
        parts.append("ClusterServiceVersions were only partly read, so an operator may be missing")
    if c.unreadable:
        parts.append(f"{len(c.unreadable)} file(s) could not be read")
    if c.namespaces is not None:
        parts.append("only some namespaces were read")
    if counts["notDetermined"]:
        parts.append(f"{counts['notDetermined']} operator state(s) not determined")
    if not parts:
        parts.append(f"{len(caveats)} caveat(s) below")
    return f"{head}; " + "; ".join(parts)


# ------------------------------------------------------------------------------------------------- text ----


def render_text(inv: dict[str, Any]) -> str:
    """The text view. It carries every caveat the JSON does (G221): a reader of the text acts on the list too."""
    c = inv["counts"]
    lines = [
        f"operator inventory ({inv['source']}): {inv['verdict']} -- {inv['summary']}",
        f"counts: {c['operators']} operator(s), {c['installed']} installed, {c['upgradePending']} upgrade pending, "
        f"{c['awaitingApproval']} awaiting approval, {c['notInstalled']} not installed, {c['noSubscription']} without "
        f"a Subscription, {c['notDetermined']} not determined, {c['notSucceeded']} not Succeeded",
    ]
    for op in inv["operators"]:
        name = op.get("csv") or f"subscription {op.get('subscription')}"
        version = op.get("version")
        label = {
            "derived-from-name": " (derived from the name)",
            "csv-properties": " (from the CSV's olm.package property)",
        }.get(op.get("versionFrom") or "", "")
        version_text = f"{version}{label}" if version else "unknown"
        package = op.get("package") or "unknown"
        if op.get("package"):
            package += " (from the Subscription)" if op.get("packageFrom") == "subscription" else " (from the CSV)"
        head = f"  {name}  package {package}  version {version_text}  state {op['state']}"
        if op.get("csv"):
            head += f"  phase {op.get('phase') or 'unknown'}"
        if op.get("reason"):
            head += f" [{op['reason']}]"
        lines.append(head)
        where = f"namespace {op['namespace']}"
        source = " (from the OperatorGroup)" if op.get("targetNamespacesFrom") == "operatorgroup" else ""
        if op.get("allNamespaces"):
            where += f"; serves all namespaces{source}"
        elif op.get("targetNamespaces") is not None:
            total = op.get("targetNamespacesTotal") or len(op["targetNamespaces"])
            where += f"; serves {total} namespace(s){source}: " + ", ".join(op["targetNamespaces"][:10])
        if op.get("copiedInto"):
            total = op.get("copiedIntoTotal") or len(op["copiedInto"])
            where += f"; copied into {total}: " + ", ".join(op["copiedInto"][:10])
        lines.append(f"      {where}")
        if op.get("subscription"):
            approval = op["approval"] + (" (default)" if op.get("approvalDefaulted") else "")
            catalog = op.get("catalog") or "unknown"
            if op.get("catalogNamespace"):
                catalog += f" in {op['catalogNamespace']}"
            lines.append(
                f"      subscription {op['subscription']}: catalog {catalog}, "
                f"channel {op.get('channel') or 'unknown'}, approval {approval}"
            )
            if op.get("installedCSV") and op.get("installedCSV") != op.get("csv"):
                lines.append(f"      installedCSV {op['installedCSV']}")
        else:
            why = "no Subscription" if op["state"] == "no-subscription" else "not determined"
            lines.append(f"      catalog unknown, channel unknown, approval unknown ({why})")
        if op.get("upgradeTo"):
            lines.append(f"      upgrade to {op['upgradeTo']} pending")
        if op.get("awaitingApproval"):
            lines.append("      an InstallPlan is waiting for manual approval")
        if op.get("message"):
            lines.append(f"      {op['message']}")
        for p in op.get("problems", []):
            lines.append(f"      problem: {p}")
        for note in op.get("notes", []):
            lines.append(f"      note: {note}")
        if op.get("evidence"):
            lines.append("      evidence: " + "; ".join(op["evidence"]))
    if inv.get("notShown"):
        lines.append(f"  and {inv['notShown']} more (see --format json)")
    for s in inv["sources"]:
        if s["state"] != "read":
            optional = "" if s["resource"] in REQUIRED else ", optional: it only adds detail"
            lines.append(f"not read: {s['resource']} ({s['state']}{optional}) {s['reason']}".rstrip())
    for u in inv["unreadable"]:
        lines.append(f"not read: {u['path']} ({u['reason']})")
    if inv["unreadableTotal"] > len(inv["unreadable"]):
        lines.append(f"not read: and {inv['unreadableTotal'] - len(inv['unreadable'])} more file(s)")
    for caveat in inv["caveats"]:
        lines.append(f"caveat: {caveat}")
    if inv["droppedUnread"]:
        lines.append(f"{inv['droppedUnread']} object(s) of a kind kube-noob never reads (Secret) were dropped unread.")
    lines.append(f"not covered: {inv['notCovered']}")
    return "\n".join(lines)
