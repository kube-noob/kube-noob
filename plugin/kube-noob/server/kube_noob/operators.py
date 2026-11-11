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

Safety: Secret objects in the input are dropped unread; only named fields are read (a Subscription's
``spec.config``, which can carry environment values, never is); every string shown is flattened and redacted; names
and versions that are not valid are not shown as names or versions; the output is bounded and sorted, so the same
input gives the same bytes.
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

RESOURCES = ("clusterserviceversions", "subscriptions", "installplans", "operatorgroups")
KIND_TO_RESOURCE = {
    "ClusterServiceVersion": "clusterserviceversions",
    "Subscription": "subscriptions",
    "InstallPlan": "installplans",
    "OperatorGroup": "operatorgroups",
}
#: Read live. InstallPlans and OperatorGroups are not on the read-only allowlist: what they add here (a waiting
#: approval, the target namespaces) the Subscription's conditions and the CSV's annotation already carry.
LIVE_RESOURCES = ("clusterserviceversions", "subscriptions")
#: What the answer needs. InstallPlans and OperatorGroups only add detail, so their absence is not a gap.
REQUIRED = ("clusterserviceversions", "subscriptions")

MAX_OPERATORS = 500
MAX_NAMESPACES = 100
MAX_ITEMS = 50_000  # objects of one resource read from one source
MAX_PROPERTIES_BYTES = 64 * 1024
MAX_PROBLEMS = 5
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

_NAME = re.compile(r"^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?\Z")
_REASON = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,127}\Z")
_PHASE = re.compile(r"^[A-Za-z]{1,32}\Z")
_SEMVER = re.compile(r"^\d{1,9}\.\d{1,9}\.\d{1,9}(?:-[0-9A-Za-z.-]{1,64})?(?:\+[0-9A-Za-z.-]{1,64})?\Z")
# `<package>.v<semver>`, the naming convention OLM bundles follow; used only when no field states the version
_NAMED_VERSION = re.compile(r"\.v(\d{1,9}\.\d{1,9}\.\d{1,9}(?:-[0-9A-Za-z.-]{1,64})?(?:\+[0-9A-Za-z.-]{1,64})?)\Z")
_HIDDEN = re.compile(r"[\x00-\x1f\x7f-\x9f\u200b-\u200f\u2028\u2029\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]")
_ANSI = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]{0,256}(?:\x07|\x1b\\)?)")

State = Literal[
    "installed",
    "upgrade-pending",
    "not-installed",
    "csv-missing",
    "csv-not-read",
    "no-subscription",
    "subscription-not-read",
]
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
    secrets_ignored: int = 0
    dropped: Counter[str] = field(default_factory=Counter)  # objects past MAX_ITEMS, per resource: never silent

    def add(self, doc: Any, where: str, default_ns: str = "", kind: str = "") -> bool:
        """Keep an OLM object of a known kind; anything else is left alone. ``kind`` is used when the object does not
        state one (the items of an API server's ``<Kind>List`` omit it). Returns whether it was kept."""
        if not isinstance(doc, dict):
            return False
        resource = KIND_TO_RESOURCE.get(str(doc.get("kind") or kind))
        if resource is None:
            return False
        meta = _d(doc.get("metadata"))
        name, ns = meta.get("name"), meta.get("namespace")
        if not isinstance(name, str) or not name:
            return False
        ns = ns if isinstance(ns, str) and ns else default_ns
        if len(self.objects[resource]) < MAX_ITEMS:
            self.objects[resource].append(Obj(doc, where, ns, name))
        else:
            self.dropped[resource] += 1
        return True


# ------------------------------------------------------------------------------------------------- helpers ----


def _d(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _l(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _text(value: Any, limit: int = TEXT_LIMIT) -> str:
    """One safe line: terminal escapes and invisible characters removed, whitespace collapsed, credentials
    redacted, length capped."""
    if not isinstance(value, str):
        return ""
    s = _ANSI.sub(" ", value[: limit * 4])
    s = " ".join(_HIDDEN.sub(" ", s).split())
    s = redact_text(s)
    return s if len(s) <= limit else s[: limit - 3] + "..."


def _shown(value: str) -> str:
    """A name as it may be shown: a valid name as is, anything else flattened (and marked so it is not mistaken
    for a name)."""
    return value if _NAME.match(value) else f"<{_text(value, 120) or 'unnamed'}>"


def _valid(value: Any, rx: re.Pattern[str] = _NAME) -> str | None:
    return value if isinstance(value, str) and rx.match(value) else None


def is_copy(obj: Obj) -> bool:
    """operator-framework/api ``IsCopied``: reason Copied, the copiedFrom label, or an operator namespace that is
    not this one."""
    meta = _d(obj.doc.get("metadata"))
    if _d(obj.doc.get("status")).get("reason") == "Copied" or COPIED_LABEL in _d(meta.get("labels")):
        return True
    operator_ns = _d(meta.get("annotations")).get(OPERATOR_NAMESPACE)
    return isinstance(operator_ns, str) and bool(operator_ns) and operator_ns != obj.namespace


def _origin(obj: Obj) -> str | None:
    meta = _d(obj.doc.get("metadata"))
    for candidate in (_d(meta.get("labels")).get(COPIED_LABEL), _d(meta.get("annotations")).get(OPERATOR_NAMESPACE)):
        if _valid(candidate) and candidate != obj.namespace:
            return str(candidate)
    return None


def _package_property(doc: dict[str, Any]) -> dict[str, Any]:
    raw = _d(_d(doc.get("metadata")).get("annotations")).get(PROPERTIES)
    if not isinstance(raw, str) or len(raw) > MAX_PROPERTIES_BYTES:
        return {}
    try:
        parsed = json.loads(raw)
    except ValueError:
        return {}
    for prop in _l(_d(parsed).get("properties"))[:500]:
        if isinstance(prop, dict) and prop.get("type") == "olm.package":
            return _d(prop.get("value"))
    return {}


def _version(doc: dict[str, Any], name: str, notes: list[str]) -> tuple[str | None, Any]:
    stated = _d(doc.get("spec")).get("version")
    if _valid(stated, _SEMVER):
        return str(stated), "spec.version"
    if stated not in (None, ""):
        notes.append("spec.version is not a semantic version, so it is not used")
    prop = _valid(_package_property(doc).get("version"), _SEMVER)
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


# ------------------------------------------------------------------------------------------------- inputs ----


def from_documents(docs: Iterable[Any], label: str = "manifest") -> Collected:
    """Collect OLM objects from parsed documents (a ``List`` or ``<Kind>List`` is opened). Secrets are counted and
    dropped unread."""
    c = Collected("manifests")
    seen: Counter[str] = Counter()
    for i, doc in enumerate(docs):
        if not isinstance(doc, dict):
            continue
        kind = str(doc.get("kind") or "")
        items = doc.get("items")
        if kind.endswith("List") and isinstance(items, list):
            element = kind[: -len("List")]
            for j, item in enumerate(items[:MAX_ITEMS]):
                item_kind = str(_d(item).get("kind") or element)
                if item_kind == "Secret":
                    c.secrets_ignored += 1
                elif c.add(item, f"{label} document {i + 1} item {j + 1}", kind=element):
                    seen[KIND_TO_RESOURCE[item_kind]] += 1
            if element in KIND_TO_RESOURCE:
                seen[KIND_TO_RESOURCE[element]] += 0  # an empty list of this kind is still a read of it
            continue
        if kind == "Secret":
            c.secrets_ignored += 1
        elif c.add(doc, f"{label} document {i + 1}"):
            seen[KIND_TO_RESOURCE[kind]] += 1
    for resource in RESOURCES:
        if resource in seen:
            c.reads[resource] = SourceRead(resource=resource, state="read", objects=len(c.objects[resource]))
        else:
            kind = next(k for k, r in KIND_TO_RESOURCE.items() if r == resource)
            c.reads[resource] = SourceRead(
                resource=resource, state="not-read", reason=f"no {kind} in the input, so it was not read"
            )
    return c


def from_manifests(text: str) -> Collected:
    """Collect from YAML text (the ``yamlio`` caps on size, documents, depth and aliases apply)."""
    from kube_noob.yamlio import load_documents

    return from_documents(d.data for d in load_documents(text))


def _absent(message: str) -> bool:
    """A 404 -- the API group is not served -- as opposed to a 403 or any other failed read."""
    from kube_noob.debug.netpol import _tier_absent

    return _tier_absent(message)


def collect_live(backend: Any, namespaces: list[str]) -> Collected:
    """Read ClusterServiceVersions and Subscriptions through the read-only backend (never Secrets: not on its
    allowlist). Cluster-wide, copies are left out with the selector OLM itself uses (``!olm.copiedFrom``) and the
    namespaces an operator serves come from its ``olm.targetNamespaces`` annotation; per namespace, copies are read,
    because a copy is how a namespace shows which operators manage it."""
    from kube_noob.errors import KubeNoobError

    c = Collected("live", namespaces=frozenset(namespaces) if namespaces else None)
    scopes: list[str | None] = list(namespaces) if namespaces else [None]
    for resource in LIVE_RESOURCES:
        failures: list[str] = []
        not_served = False
        read_any = False
        for ns in scopes:
            selector = "!olm.copiedFrom" if resource == "clusterserviceversions" and ns is None else None
            try:
                data = backend.get(resource, namespace=ns, selector=selector)
            except KubeNoobError as exc:
                message = _text(str(exc), 240)
                if _absent(str(exc)):
                    not_served = True
                failures.append(f"{ns + ': ' if ns else ''}{message}")
                continue
            read_any = True
            kind = next(k for k, r in KIND_TO_RESOURCE.items() if r == resource)
            for item in _l(_d(data).get("items"))[:MAX_ITEMS]:
                if _d(item).get("kind") in (None, "", kind):  # never another kind under this resource's name
                    c.add(item, f"live {resource}", ns or "", kind=kind)
        if not failures:
            state: ReadState = "read"
            reason = "" if c.namespaces is None else "only the namespaces asked for"
        elif not_served and not read_any:
            state, reason = "not-served", "operators.coreos.com/v1alpha1 is not served (404): no OLM on this cluster"
        elif read_any:
            state, reason = "partial", "; ".join(failures[:5])
        else:
            state, reason = "not-read", "; ".join(failures[:5])
        c.reads[resource] = SourceRead(resource=resource, state=state, objects=len(c.objects[resource]), reason=reason)
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


@dataclass
class _Group:
    namespace: str
    name: str
    original: Obj | None = None
    copies: dict[str, Obj] = field(default_factory=dict)
    origin_unknown: bool = False

    def representative(self) -> Obj:
        return self.original or self.copies[min(self.copies)]


def _groups(csvs: list[Obj]) -> dict[tuple[str, str], _Group]:
    """One group per installed CSV: the original in the operator's namespace and its copies folded into it.

    A copy names its source namespace in the olm.copiedFrom label (or the olm.operatorNamespace annotation). One that
    names neither -- marked only by status.reason Copied -- is folded into the single original of that name when
    there is exactly one; otherwise it stays on its own and says its source is unknown, rather than being guessed
    onto one of several.
    """
    ordered = sorted(csvs, key=lambda o: (o.namespace, o.name, o.where))
    groups: dict[tuple[str, str], _Group] = {}
    for obj in ordered:
        if not is_copy(obj):
            g = groups.setdefault((obj.namespace, obj.name), _Group(obj.namespace, obj.name))
            if g.original is None:
                g.original = obj
    unplaced: list[Obj] = []
    for obj in ordered:
        if not is_copy(obj):
            continue
        origin = _origin(obj)
        if origin is None:
            unplaced.append(obj)
            continue
        groups.setdefault((origin, obj.name), _Group(origin, obj.name)).copies.setdefault(obj.namespace, obj)
    with_original: dict[str, list[tuple[str, str]]] = {}
    for key, g in groups.items():
        if g.original is not None:
            with_original.setdefault(key[1], []).append(key)
    for obj in unplaced:
        same = with_original.get(obj.name, [])
        if len(same) == 1:
            groups[same[0]].copies.setdefault(obj.namespace, obj)
        else:
            g = groups.setdefault((obj.namespace, obj.name), _Group(obj.namespace, obj.name, origin_unknown=True))
            g.copies.setdefault(obj.namespace, obj)
    return groups


def _subscription_read_for(c: Collected, ns: str) -> bool:
    read = c.reads.get("subscriptions")
    if read is None or read.state != "read":
        return False
    return c.namespaces is None or ns in c.namespaces


def _awaiting(sub: dict[str, Any], plans: list[Obj], csvs: set[str]) -> bool:
    cond = _conditions(_d(sub.get("status"))).get("InstallPlanPending")
    if cond and cond.get("status") == "True" and cond.get("reason") == "RequiresApproval":
        return True
    ref = _d(_d(sub.get("status")).get("installPlanRef")).get("name")
    for p in plans:
        names = {n for n in _l(_d(p.doc.get("spec")).get("clusterServiceVersionNames")) if isinstance(n, str)}
        if (p.name == ref or names & csvs) and _d(p.doc.get("status")).get("phase") == "RequiresApproval":
            return True
    return False


def _csv_fields(op: dict[str, Any], g: _Group, groups_in_ns: list[Obj]) -> None:
    rep = g.representative()
    status = _d(rep.doc.get("status"))
    notes: list[str] = op["notes"]
    op["csv"] = _shown(g.name)
    op["version"], op["version_from"] = _version(rep.doc, g.name, notes)
    phase = _valid(status.get("phase"), _PHASE)
    op["phase"] = phase
    reason = _valid(status.get("reason"), _REASON)
    op["reason"] = reason if reason != "Copied" else None
    if phase and phase != "Succeeded":
        op["message"] = _text(status.get("message")) or None
    if op.get("package") is None:
        pkg = _valid(_package_property(rep.doc).get("packageName"))
        if pkg:
            op["package"], op["package_from"] = pkg, "csv-properties"
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
    if g.origin_unknown:
        notes.append(
            "a copy (status.reason Copied) that does not record its source namespace, and no single original "
            "of that name was read: the operator's own namespace is unknown"
        )
    elif g.original is None:
        notes.append(f"the original in {_shown(g.namespace)} was not in the input: known from its copies")
    op["evidence"] = sorted({_text(o.where, 300) for o in [*([g.original] if g.original else []), *g.copies.values()]})[
        :5
    ]


def _subscription_fields(op: dict[str, Any], sub: Obj) -> None:
    spec, status = _d(sub.doc.get("spec")), _d(sub.doc.get("status"))
    op["subscription"] = _shown(sub.name)
    pkg = _valid(spec.get("name"))
    if pkg:
        op["package"], op["package_from"] = pkg, "subscription"
    op["catalog"] = _valid(spec.get("source"))
    op["catalog_namespace"] = _valid(spec.get("sourceNamespace"))
    op["channel"] = _valid(spec.get("channel"))
    approval = spec.get("installPlanApproval")
    op["approval"] = "Manual" if approval == "Manual" else "Automatic"
    op["approval_defaulted"] = approval not in ("Manual", "Automatic")
    op["installed_csv"] = _valid(status.get("installedCSV"))
    conditions = _conditions(status)
    op["problems"] = [
        f"{t}: {_text(c.get('message'), 200) or _valid(c.get('reason'), _REASON) or 'True'}"
        for t in _PROBLEM_CONDITIONS
        if (c := conditions.get(t)) and c.get("status") == "True"
    ][:MAX_PROBLEMS]
    if status.get("state") == "UpgradeFailed":
        op["problems"].append("state UpgradeFailed")
    op["evidence"] = sorted({*op.get("evidence", []), _text(sub.where, 300)})[:5]


def _sort_key(op: Operator) -> tuple[str, str, str, str]:
    return (op.namespace, op.package or "", op.csv or "", op.subscription or "")


def inventory(c: Collected, *, top: int = MAX_OPERATORS) -> dict[str, Any]:
    """The inventory of what ``c`` holds. Deterministic: the same objects in any order give the same bytes."""
    groups = _groups(c.objects["clusterserviceversions"])
    by_ns: dict[str, dict[str, list[Obj]]] = {r: {} for r in RESOURCES}
    for resource in ("subscriptions", "installplans", "operatorgroups"):
        for obj in sorted(c.objects[resource], key=lambda o: (o.namespace, o.name, o.where)):
            by_ns[resource].setdefault(obj.namespace, []).append(obj)
    csv_read = c.reads["clusterserviceversions"].state in ("read", "partial")

    entries: list[Operator] = []
    used: set[tuple[str, str]] = set()
    seen_subs: set[tuple[str, str]] = set()
    for ns, subs in sorted(by_ns["subscriptions"].items()):
        for sub in subs:
            if (ns, sub.name) in seen_subs:
                continue  # one object collected twice (two gather images): the first file wins
            seen_subs.add((ns, sub.name))
            status = _d(sub.doc.get("status"))
            installed = _valid(status.get("installedCSV"))
            current = _valid(status.get("currentCSV"))
            op: dict[str, Any] = {"namespace": _shown(ns), "notes": [], "evidence": []}
            _subscription_fields(op, sub)
            key = next(((ns, n) for n in (installed, current) if n and (ns, n) in groups), None)
            op["awaiting_approval"] = _awaiting(
                sub.doc, by_ns["installplans"].get(ns, []), {current or "", installed or ""} - {""}
            )
            if key is not None:
                used.add(key)
                _csv_fields(op, groups[key], by_ns["operatorgroups"].get(ns, []))
                if installed and current and installed != current:
                    op["state"], op["upgrade_to"] = "upgrade-pending", current
                else:
                    op["state"] = "installed"
            elif not csv_read:
                op["state"] = "csv-not-read"
                op["notes"].append("ClusterServiceVersions were not read, so whether this is installed is not known")
            elif installed:
                op["state"] = "csv-missing"
                op["notes"].append(
                    f"the Subscription names {_shown(installed)} as installed, and no ClusterServiceVersion of that "
                    "name was read in its namespace"
                )
            else:
                op["state"] = "not-installed"
                if current:
                    op["upgrade_to"] = current
            entries.append(Operator.model_validate(op))
    for key, g in sorted(groups.items()):
        if key in used:
            continue
        ns = g.namespace
        op = {"namespace": _shown(ns), "notes": [], "evidence": []}
        _csv_fields(op, g, by_ns["operatorgroups"].get(ns, []))
        if _subscription_read_for(c, ns):
            op["state"] = "no-subscription"
            op["notes"].append(
                "no Subscription in its namespace names it: installed by hand or by the platform itself, so its "
                "catalog, channel and approval are unknown"
                if c.source != "manifests"
                else "no Subscription in the input names it: installed by hand, or its Subscription is not in these "
                "files, so its catalog, channel and approval are unknown"
            )
        else:
            op["state"] = "subscription-not-read"
            op["notes"].append(
                "Subscriptions were not read for its namespace: catalog, channel and approval are not determined"
            )
        entries.append(Operator.model_validate(op))

    entries.sort(key=_sort_key)
    return _assemble(c, entries, top)


def _verdict(c: Collected) -> Verdict:
    csv = c.reads["clusterserviceversions"]
    if csv.state == "not-served":
        return "no-olm"
    if csv.state == "not-read":
        return "not-determined"
    gaps = any(c.reads[r].state != "read" for r in REQUIRED) or c.unreadable or c.namespaces is not None or c.dropped
    return "partial" if gaps else "listed"


def _assemble(c: Collected, entries: list[Operator], top: int) -> dict[str, Any]:
    verdict = _verdict(c)
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
        "notSucceeded": sum(1 for e in entries if e.phase and e.phase != "Succeeded"),
    }
    caveats = list(c.caveats)
    for r in REQUIRED:
        read = c.reads[r]
        if read.state in ("partial", "not-read"):
            what = "ClusterServiceVersions" if r == "clusterserviceversions" else "Subscriptions"
            how = "were only partly read" if read.state == "partial" else "were not read"
            caveats.append(f"{what} {how}: {read.reason}")
    if c.unreadable:
        caveats.append(f"{len(c.unreadable)} file(s) could not be read; operators in them are not in this answer")
    for r, n in sorted(c.dropped.items()):
        caveats.append(f"{n} {r} past the first {MAX_ITEMS} were not read; operators among them are not in this answer")
    summary = _summary(c, verdict, counts)
    shown = entries[:top]
    out: dict[str, Any] = {
        "source": c.source,
        "verdict": verdict,
        "complete": verdict in ("listed", "no-olm"),
        "summary": summary,
        "counts": counts,
        "operators": [e.model_dump(by_alias=True, exclude_none=True) for e in shown],
        "operatorsTotal": len(entries),
    }
    if len(entries) > len(shown):
        out["notShown"] = len(entries) - len(shown)
    out["sources"] = [c.reads[r].model_dump(by_alias=True) for r in RESOURCES]
    out["caveats"] = caveats
    out["unreadable"] = c.unreadable[:50]
    out["secretsIgnored"] = c.secrets_ignored
    out["notCovered"] = NOT_COVERED
    return out


def _summary(c: Collected, verdict: Verdict, counts: dict[str, int]) -> str:
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
    missing = [r for r in REQUIRED if c.reads[r].state != "read"]
    parts = []
    if "subscriptions" in missing:
        how = "only partly read" if c.reads["subscriptions"].state == "partial" else "not read"
        parts.append(
            f"Subscriptions were {how}, so catalog, channel and approval are not determined for every operator"
        )
    if "clusterserviceversions" in missing:
        parts.append("ClusterServiceVersions were only partly read, so an operator may be missing")
    if c.unreadable:
        parts.append(f"{len(c.unreadable)} file(s) could not be read")
    if c.namespaces is not None:
        parts.append("only some namespaces were read")
    if c.dropped:
        parts.append(f"more objects than the {MAX_ITEMS} read per resource")
    return f"{head}; " + "; ".join(parts)


# ------------------------------------------------------------------------------------------------- text ----


def render_text(inv: dict[str, Any]) -> str:
    """The text view. It carries every caveat the JSON does (G221): a reader of the text acts on the list too."""
    lines = [f"operator inventory ({inv['source']}): {inv['verdict']} -- {inv['summary']}"]
    for op in inv["operators"]:
        name = op.get("csv") or f"subscription {op.get('subscription')}"
        version = op.get("version")
        if version and op.get("versionFrom") == "derived-from-name":
            version_text = f"{version} (derived from the name)"
        elif version:
            version_text = version
        else:
            version_text = "unknown"
        head = f"  {name}  package {op.get('package') or 'unknown'}  version {version_text}  state {op['state']}"
        if op.get("phase"):
            head += f"  phase {op['phase']}" + (f" [{op['reason']}]" if op.get("reason") else "")
        lines.append(head)
        where = f"namespace {op['namespace']}"
        if op.get("allNamespaces"):
            where += "; serves all namespaces"
        elif op.get("targetNamespaces") is not None:
            total = op.get("targetNamespacesTotal") or len(op["targetNamespaces"])
            where += f"; serves {total} namespace(s): " + ", ".join(op["targetNamespaces"][:10])
        if op.get("copiedInto"):
            total = op.get("copiedIntoTotal") or len(op["copiedInto"])
            where += f"; copied into {total}: " + ", ".join(op["copiedInto"][:10])
        lines.append(f"      {where}")
        if op.get("subscription"):
            approval = op["approval"] + (" (default)" if op.get("approvalDefaulted") else "")
            lines.append(
                f"      catalog {op.get('catalog') or 'unknown'}, channel {op.get('channel') or 'unknown'}, "
                f"approval {approval}"
            )
        else:
            why = "not read" if op["state"] == "subscription-not-read" else "no Subscription"
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
    if inv.get("notShown"):
        lines.append(f"  and {inv['notShown']} more (see --format json)")
    for s in inv["sources"]:
        if s["state"] != "read":
            optional = "" if s["resource"] in REQUIRED else ", optional: it only adds detail"
            lines.append(f"not read: {s['resource']} ({s['state']}{optional}) {s['reason']}".rstrip())
    for u in inv["unreadable"][:5]:
        lines.append(f"not read: {u['path']} ({u['reason']})")
    for caveat in inv["caveats"]:
        lines.append(f"caveat: {caveat}")
    if inv["secretsIgnored"]:
        lines.append(f"{inv['secretsIgnored']} Secret object(s) in the input were ignored, unread.")
    lines.append(f"not covered: {inv['notCovered']}")
    return "\n".join(lines)
