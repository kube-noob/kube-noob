"""Must-gather analysers (backlog G2): what is wrong in a must-gather, ranked, each finding with the files it came
from, the signals it carries (``kube_noob.signals``) and read-only next steps.

Field and value names, checked on 2026-10-28 in the sources that define them (the URL is the citation):

- Node conditions Ready, MemoryPressure, DiskPressure, PIDPressure, NetworkUnavailable and ``spec.unschedulable``;
  pod phases; the PodScheduled reasons Unschedulable and SchedulingGated; container ``state`` and ``lastState`` with
  ``waiting`` and ``terminated``, ``restartCount``; Event ``involvedObject``, ``count``, ``series.count``,
  ``lastTimestamp``, ``eventTime``: https://github.com/kubernetes/api/blob/master/core/v1/types.go
- Event field selectors (``reason``, ``involvedObject.name``):
  https://github.com/kubernetes/kubernetes/blob/master/pkg/apis/core/v1/conversion.go
- kubelet node condition reasons (KubeletNotReady and the pressure reasons):
  https://github.com/kubernetes/kubernetes/blob/master/pkg/kubelet/nodestatus/setters.go
- container reasons: ``kube_noob.signals.vocab`` (kubelet images/types.go, container/sync_result.go, cri-o)
- the control-plane node role label: https://github.com/kubernetes/kubernetes/blob/master/cmd/kubeadm/app/constants/constants.go
- ClusterVersion ``spec.channel``, ``status.desired.version``, ``status.history[].state`` (Completed, Partial):
  https://github.com/openshift/api/blob/master/config/v1/types_cluster_version.go; its conditions Available,
  Failing, Progressing, RetrievedUpdates, Upgradeable, ReleaseAccepted, Invalid: openshift/api and
  openshift/cluster-version-operator
- ClusterOperator conditions: https://github.com/openshift/api/blob/master/config/v1/types_cluster_operator.go
- Infrastructure ``status.platformStatus.type`` and ``status.controlPlaneTopology``:
  https://github.com/openshift/api/blob/master/config/v1/types_infrastructure.go
- MachineConfigPool ``spec.paused``, the machine counts and the conditions Updated, Updating, Degraded,
  NodeDegraded, RenderDegraded (and the newer *Degraded types):
  https://github.com/openshift/api/blob/master/machineconfiguration/v1/types.go
- ClusterServiceVersion phases and reasons (Copied marks the copies OLM writes into every target namespace):
  https://github.com/operator-framework/api/blob/master/pkg/operators/v1alpha1/clusterserviceversion_types.go
- etcd log messages "apply request took too long", "slow fdatasync" and "leader failed to send out heartbeat on
  time" (etcd-io/etcd server and WAL), and raft's "elected leader", "changed leader from" and "lost leader" lines
  (etcd-io/raft node logging, "... at term N").

Severities are kube-noob's (docs/guidance.md): an unavailable cluster version or operator and a NotReady
control-plane node are critical; a Degraded operator or pool, a NotReady worker, node pressure, failed operators and
pods that cannot start are high; slow etcd, leader changes, OOM kills, unschedulable pods and warning events on
known failure reasons are medium.

Safety: only the files ``ingest`` kept are read (Secrets never are). YAML is parsed with libyaml when available,
after an event pre-scan that refuses aliases and nesting deeper than ``MAX_YAML_DEPTH`` (the C composer recurses
without a guard and crashes the process on very deep input). Every string shown is flattened and passed through
``redact_text``; names in next-step commands must be valid Kubernetes names, otherwise the command is left out.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

import yaml

from kube_noob.debug.cluster import redact_text
from kube_noob.mustgather.ingest import Bundle, classify, root_of
from kube_noob.sanitize import visible
from kube_noob.signals import KINDS, Signal, for_text
from kube_noob.signals.catalogue import get as catalogue_get
from kube_noob.signals.core import extract
from kube_noob.signals.vocab import EVENT_REASONS, POD_REASONS, ROUTINE_REASONS

SEVERITIES = ("critical", "high", "medium", "low", "info")
ANALYSERS = ("clusterversion", "clusteroperators", "nodes", "machineconfigpools", "olm", "pods", "events", "etcd")
_SEV = {s: i for i, s in enumerate(SEVERITIES)}
_AN = {a: i for i, a in enumerate(ANALYSERS)}

MAX_YAML_DEPTH = 64
MAX_DOCUMENTS = 10  # per file; oc writes one
MAX_PARSED_BYTES = 768 * 2**20
MAX_ITEMS = 100_000  # objects read from one list file
MAX_PER_ANALYSER = 150
MAX_FINDINGS = 500
MAX_UNPARSED = 50
MAX_EVENT_REASONS = 25
MAX_EXAMPLES = 5
TEXT_LIMIT = 400

_LOADER: Any = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
_OPEN = (yaml.MappingStartEvent, yaml.SequenceStartEvent)
_CLOSE = (yaml.MappingEndEvent, yaml.SequenceEndEvent)
# everything a parser can raise on a file that is not readable YAML; _Refused (a ValueError) is always caught first
_BAD_YAML = (yaml.YAMLError, RecursionError, ValueError, TypeError, OverflowError)
_NAME = re.compile(r"^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?\Z")
_LABEL = re.compile(r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?\Z")
_REASON = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,127}\Z")
_VERSION = re.compile(r"^\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.-]{1,64})?\Z")
_SUFFIX = re.compile(r"\.(?:ya?ml|json)$")
_ERRORISH = re.compile(
    r"(?i)\b(error|failed|failure|denied|forbidden|panic|fatal|unable|cannot|timeout|timed out|refused|invalid|"
    r"x509|exceeded|unauthorized|rejected|deadline|not found|no such|killed)\b"
)
_ETCD_HINTS: tuple[tuple[str, str | None], ...] = (
    ("apply request took too long", "etcdGRPCRequestsSlow"),
    ("slow fdatasync", "etcdHighFsyncDurations"),
    ("leader failed to send out heartbeat on time", None),
)
_RAFT = re.compile(
    r"\b(elected leader [0-9a-f]{1,16}|changed leader from [0-9a-f]{1,16} to [0-9a-f]{1,16}|lost leader [0-9a-f]{1,16})"
    r" at term (\d{1,15})\b"
)
_POD_HIGH = frozenset(
    {
        "CrashLoopBackOff",
        "ImagePullBackOff",
        "ErrImagePull",
        "ErrImageNeverPull",
        "InvalidImageName",
        "CreateContainerConfigError",
        "CreateContainerError",
        "RunContainerError",
        "CreatePodSandboxError",
    }
)
_IMAGE_REASONS = frozenset({"ImagePullBackOff", "ErrImagePull", "ErrImageNeverPull", "InvalidImageName"})
_ROUTES_CLUSTER = {
    ("config.openshift.io", "clusterversions"): ("ClusterVersion", "clusterversion"),
    ("config.openshift.io", "clusteroperators"): ("ClusterOperator", "clusteroperators"),
    ("config.openshift.io", "infrastructures"): ("Infrastructure", "infrastructure"),
    ("core", "nodes"): ("Node", "nodes"),
    ("machineconfiguration.openshift.io", "machineconfigpools"): ("MachineConfigPool", "machineconfigpools"),
}
_ROUTES_NAMESPACED = {
    ("core", "pods"): ("Pod", "pods"),
    ("core", "events"): ("Event", "events"),
    ("operators.coreos.com", "clusterserviceversions"): ("ClusterServiceVersion", "olm"),
}
_COLLECTED_BY = {
    "clusterversion": "cluster-scoped-resources/config.openshift.io/clusterversions",
    "clusteroperators": "cluster-scoped-resources/config.openshift.io/clusteroperators",
    "nodes": "cluster-scoped-resources/core/nodes",
    "machineconfigpools": "cluster-scoped-resources/machineconfiguration.openshift.io/machineconfigpools",
    "olm": "namespaces/<ns>/operators.coreos.com/clusterserviceversions",
    "pods": "namespaces/<ns>/pods/<pod>/<pod>.yaml",
    "events": "namespaces/<ns>/core/events.yaml",
    "etcd": "namespaces/openshift-etcd/pods/<pod>/etcd/etcd/logs",
}


class _Refused(ValueError):
    pass


@dataclass
class Finding:
    analyser: str
    severity: str
    object: str
    title: str
    reason: str = ""
    message: str = ""
    namespace: str = ""
    platform: bool = False
    count: int = 1
    evidence: list[str] = field(default_factory=list)
    signals: list[Signal] = field(default_factory=list)
    next: list[str] = field(default_factory=list)
    detail: dict[str, Any] = field(default_factory=dict)

    def key(self) -> tuple[int, int, int, str, str]:
        return (_SEV[self.severity], 0 if self.platform else 1, _AN[self.analyser], self.object, self.title)

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "analyser": self.analyser,
            "severity": self.severity,
            "object": self.object,
            "title": self.title,
        }
        for k, v in (("reason", self.reason), ("message", self.message), ("namespace", self.namespace)):
            if v:
                out[k] = v
        if self.platform:
            out["platform"] = True
        if self.count != 1:
            out["count"] = self.count
        out["evidence"] = self.evidence[:MAX_EXAMPLES]
        out["signals"] = [f"{s.kind}:{s.name}" for s in self.signals]
        out["next"] = self.next
        if self.detail:
            out["detail"] = self.detail
        return out


@dataclass
class Analysis:
    cluster: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    coverage: dict[str, dict[str, Any]] = field(default_factory=dict)
    unparsed: list[dict[str, str]] = field(default_factory=list)
    signals: list[Signal] = field(default_factory=list)
    #: Objects collected more than once with different content (G288): neither copy is read by any analyser, the
    #: object is not determined, and the headline counts it apart. Identical duplicates are `duplicates`, a note.
    conflicts: list[dict[str, Any]] = field(default_factory=list)
    duplicates: list[dict[str, Any]] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        c = Counter(f.severity for f in self.findings)
        return {s: c.get(s, 0) for s in SEVERITIES}

    def completeness(self) -> dict[str, Any]:
        """What this analysis could actually see, so a clean verdict can be told from a blind one.

        "No findings" means two very different things: nothing is wrong, or nothing could be read. The second is the
        dangerous one, because the exit code was the same -- `failing()` counts findings and never looks at
        `unparsed`, so a `--fail-on` gate passed over a must-gather whose ClusterOperator, Node and ClusterVersion
        files were all truncated. Everything needed to tell them apart was already recorded; nothing carried it to
        the verdict.
        """
        missing = [a for a in ANALYSERS if self.coverage.get(a, {}).get("note")]
        read = [a for a in ANALYSERS if a in self.coverage and not self.coverage[a].get("note")]
        return {
            "analysersRead": len(read),
            "analysersExpected": len(ANALYSERS),
            "notCollected": missing,
            "unreadableFiles": len(self.unparsed),
            "complete": not missing and not self.unparsed,
        }

    def as_dict(self) -> dict[str, Any]:
        return {
            "cluster": self.cluster,
            "counts": self.counts(),
            "completeness": self.completeness(),
            "findings": [f.as_dict() for f in self.findings],
            "coverage": [{"analyser": a, **self.coverage[a]} for a in ANALYSERS if a in self.coverage],
            "unparsed": self.unparsed,
            "conflicts": self.conflicts,
            "duplicates": self.duplicates,
            "signals": [s.as_dict() for s in self.signals],
        }


@dataclass
class _Obj:
    path: str
    doc: dict[str, Any]


# ---------------------------------------------------------------------------------------------------- helpers ----


def _text(value: Any, limit: int = TEXT_LIMIT) -> str:
    """A value as one safe line: control and invisible characters removed, whitespace collapsed, credentials
    redacted, length capped."""
    if value is None or isinstance(value, dict | list):
        return ""
    s = value if isinstance(value, str) else str(value)
    s = " ".join(visible(s[: limit * 4]).split())
    s = redact_text(s)
    return s if len(s) <= limit else s[: limit - 3] + "..."


def _d(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _l(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _int(value: Any) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return max(0, min(value, 10**9))
    if isinstance(value, str) and value.isdigit() and len(value) <= 10:
        return min(int(value), 10**9)
    return 0


def _conditions(status: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for c in _l(status.get("conditions"))[:64]:
        if isinstance(c, dict) and isinstance(c.get("type"), str) and c["type"] not in out:
            out[c["type"]] = c
    return out


def _status(cond: dict[str, Any] | None) -> str:
    return str(cond.get("status")) if cond else ""


def _reason(value: Any) -> str:
    return value if isinstance(value, str) and _REASON.match(value) else ""


def _name(doc: dict[str, Any]) -> str:
    name = _d(doc.get("metadata")).get("name")
    return name if isinstance(name, str) else ""


def _shown(name: str) -> str:
    return _text(name, 253) or "<unnamed>"


def _cmd(template: str, **names: str) -> str | None:
    """A read-only command with object names filled in, or None when a name is not a valid Kubernetes name (a
    must-gather is untrusted input: ``$(...)`` in a name must never reach a command line)."""
    for key, value in names.items():
        rx = _LABEL if key in {"container", "ns"} else _REASON if key == "reason" else _NAME
        if not rx.match(value or ""):
            return None
    return template.format(**names)


def _cmds(*pairs: tuple[str, dict[str, str]]) -> list[str]:
    return [c for c in (_cmd(t, **n) for t, n in pairs) if c]


def _implied(name: str, why: str) -> list[Signal]:
    """A catalogued alert the state implies (the alert's expression watches this condition)."""
    return [Signal("alert", name, why, "must-gather")] if catalogue_get("alert", name) else []


def _merge(*groups: list[Signal]) -> list[Signal]:
    seen: set[tuple[str, str]] = set()
    out: list[Signal] = []
    for group in groups:
        for s in group:
            if (s.kind, s.name) not in seen:
                seen.add((s.kind, s.name))
                out.append(s)
    return sorted(out, key=lambda s: KINDS.index(s.kind))[:20]


def _platform(ns: str) -> bool:
    return ns in {"default", "openshift"} or ns.startswith(("openshift-", "kube-"))


# ---------------------------------------------------------------------------------------------------- loading ----


class _Loader:
    def __init__(self, bundle: Bundle) -> None:
        self.bundle = bundle
        self.parsed = 0
        self.unparsed: list[dict[str, str]] = []

    def _fail(self, path: str, why: str) -> None:
        if len(self.unparsed) < MAX_UNPARSED:
            self.unparsed.append({"path": _text(path, 300), "reason": why})

    def load(self, path: str) -> list[Any]:
        data = self.bundle.files.get(path)
        if not data:
            return []
        if self.parsed + len(data) > MAX_PARSED_BYTES:
            self._fail(path, f"over the {MAX_PARSED_BYTES // 2**20} MiB parse budget (not read)")
            return []
        self.parsed += len(data)
        text = data.decode("utf-8", "replace")
        try:
            return self._documents(text, _LOADER)
        except _Refused as exc:
            self._fail(path, str(exc))
            return []
        except _BAD_YAML:
            pass
        # libyaml and PyYAML's own scanner do not accept the same documents: libyaml before 0.2 refuses a flow
        # collection holding an unspaced colon, such as `{image: reg/app:v1}`, which the scanner reads without
        # complaint. This is the operator's own must-gather, not our data, so a parser disagreement must not lose
        # their evidence: a file that only one of the two can read is read by that one. The caps above still apply,
        # because the retry walks the same events. Only a file neither can read is recorded as unparsed.
        if _LOADER is not yaml.SafeLoader:
            try:
                return self._documents(text, yaml.SafeLoader)
            except _Refused as exc:
                self._fail(path, str(exc))
                return []
            except _BAD_YAML:
                pass
        self._fail(path, "not valid YAML (not read)")
        return []

    def _documents(self, text: str, loader: Any) -> list[Any]:
        depth = docs = 0
        for event in yaml.parse(text, Loader=loader):
            if isinstance(event, _OPEN):
                depth += 1
                if depth > MAX_YAML_DEPTH:
                    raise _Refused(f"nested deeper than {MAX_YAML_DEPTH} levels (not read)")
            elif isinstance(event, _CLOSE):
                depth -= 1
            elif isinstance(event, yaml.AliasEvent):
                raise _Refused("uses YAML aliases, which oc never writes (not read)")
            elif isinstance(event, yaml.DocumentStartEvent):
                docs += 1
                if docs > MAX_DOCUMENTS:
                    raise _Refused(f"more than {MAX_DOCUMENTS} YAML documents (not read)")
        return list(yaml.load_all(text, Loader=loader))


def _items(doc: Any, kind: str) -> Iterator[dict[str, Any]]:
    if not isinstance(doc, dict):
        return
    items = doc.get("items")
    if isinstance(items, list) and str(doc.get("kind") or "").endswith("List"):
        for item in items[:MAX_ITEMS]:
            if isinstance(item, dict) and item.get("kind") in (kind, None, ""):
                yield item
    elif doc.get("kind") == kind:
        yield doc


def _route(path: str) -> tuple[str, str, str] | None:
    """(kind, analyser bucket, namespace from the path) for a resource file an analyser reads."""
    found = root_of(path)
    if found is None or classify(path) != "resource":
        return None
    rest = found[1]
    if rest[0] == "cluster-scoped-resources":
        if len(rest) == 4:
            hit = _ROUTES_CLUSTER.get((rest[1], rest[2]))
        elif len(rest) == 3:
            hit = _ROUTES_CLUSTER.get((rest[1], _SUFFIX.sub("", rest[2])))
        else:
            hit = None
        return (*hit, "") if hit else None
    if rest[0] != "namespaces" or len(rest) < 4:
        return None
    ns = rest[1]
    if rest[2] == "pods":
        ok = len(rest) == 5 and _SUFFIX.sub("", rest[4]) == rest[3]
        return ("Pod", "pods", ns) if ok else None
    if len(rest) == 4:
        hit = _ROUTES_NAMESPACED.get((rest[2], _SUFFIX.sub("", rest[3])))
    elif len(rest) == 5:
        hit = _ROUTES_NAMESPACED.get((rest[2], rest[3]))
    else:
        hit = None
    return (*hit, ns) if hit else None


MAX_CONFLICTS = 200
MAX_DIFFERING_FIELDS = 12


@dataclass
class _Collected:
    objects: dict[str, dict[tuple[str, str], _Obj]]
    files: Counter[str]
    #: bucket -> the keys collected more than once with different content; no analyser reads them (G288)
    conflicting: dict[str, set[tuple[str, str]]]
    conflicts: list[dict[str, Any]]
    duplicates: list[dict[str, Any]]


def _differing_fields(a: Any, b: Any, prefix: str = "", depth: int = 0, out: list[str] | None = None) -> list[str]:
    """Dotted paths (two levels deep at most) where two readings of one object differ, so a reader knows whether
    it is `status.conditions` or a label that disagrees."""
    out = [] if out is None else out
    if len(out) >= MAX_DIFFERING_FIELDS:
        return out
    if isinstance(a, dict) and isinstance(b, dict) and depth < 2:
        for key in sorted(set(a) | set(b), key=str):
            if a.get(key) != b.get(key):
                _differing_fields(a.get(key), b.get(key), f"{prefix}{_text(key, 64)}.", depth + 1, out)
        return out
    out.append(prefix.rstrip(".") or "(document)")
    return out


def _collect(bundle: Bundle, loader: _Loader) -> _Collected:
    """Objects per analyser bucket, keyed (namespace, name). An object several files hold with the same content is a
    duplicate, noted; one they hold with different content is a conflict: it is taken out of its bucket, so no
    analyser answers from either copy, and reported with both paths and the fields that differ. The first file in
    path order used to win silently, so a Node Ready in one gather directory and NotReady in another read as Ready
    (G288)."""
    objects: dict[str, dict[tuple[str, str], _Obj]] = {}
    files: Counter[str] = Counter()
    seen: dict[tuple[str, tuple[str, str]], _Obj] = {}
    conflicting: dict[str, set[tuple[str, str]]] = {}
    conflicts: list[dict[str, Any]] = []
    duplicates: list[dict[str, Any]] = []
    for path in sorted(bundle.files):
        routed = _route(path)
        if routed is None:
            continue
        kind, bucket, path_ns = routed
        files[bucket] += 1
        store = objects.setdefault(bucket, {})
        for doc in loader.load(path):
            for obj in _items(doc, kind):
                name = _name(obj)
                if not name:
                    continue
                ns = _d(obj.get("metadata")).get("namespace")
                key = (ns if isinstance(ns, str) else path_ns, name)
                first = seen.get((bucket, key))
                if first is None:
                    seen[(bucket, key)] = store[key] = _Obj(path, obj)
                    continue
                if first.path == path:
                    continue  # the same file listing one object twice is one reading, not two
                entry = _conflict_or_duplicate(conflicts, duplicates, kind, key, first, path, obj)
                if entry == "conflict":
                    store.pop(key, None)
                    conflicting.setdefault(bucket, set()).add(key)
    return _Collected(objects, files, conflicting, conflicts, duplicates)


def _conflict_or_duplicate(
    conflicts: list[dict[str, Any]],
    duplicates: list[dict[str, Any]],
    kind: str,
    key: tuple[str, str],
    first: _Obj,
    path: str,
    obj: dict[str, Any],
) -> str:
    ns, name = key
    shown_ns = _text(ns, 63)
    shown = f"{kind}/{shown_ns + '/' if shown_ns else ''}{_shown(name)}"
    rows = conflicts if first.doc != obj else duplicates
    existing = next((r for r in rows if r["object"] == shown), None)
    if existing is not None:
        if path not in existing["paths"] and len(existing["paths"]) < 8:
            existing["paths"].append(path)
        if rows is conflicts:
            for f in _differing_fields(first.doc, obj):
                if f not in existing["differs"] and len(existing["differs"]) < MAX_DIFFERING_FIELDS:
                    existing["differs"].append(f)
        return "conflict" if rows is conflicts else "duplicate"
    if len(rows) >= MAX_CONFLICTS:
        return "conflict" if rows is conflicts else "duplicate"
    row: dict[str, Any] = {"kind": kind, "name": _shown(name), "object": shown, "paths": [first.path, path]}
    if shown_ns:
        row["namespace"] = shown_ns
    if rows is conflicts:
        row["differs"] = _differing_fields(first.doc, obj)
        row["why"] = "collected twice with different content: not determined"
    else:
        row["why"] = "collected twice with identical content: read once"
    rows.append(row)
    return "conflict" if rows is conflicts else "duplicate"


def _logs(bundle: Bundle) -> dict[tuple[str, str, str], list[str]]:
    """(namespace, pod, container) -> log paths, previous.log first."""
    out: dict[tuple[str, str, str], list[str]] = {}
    for path in sorted(bundle.files):
        found = root_of(path)
        if found is None or classify(path) != "log":
            continue
        rest = found[1]
        if (
            len(rest) == 8
            and rest[0] == "namespaces"
            and rest[2] == "pods"
            and rest[4] == rest[5]
            and rest[6] == "logs"
        ):
            out.setdefault((rest[1], rest[3], rest[4]), []).append(path)
    for paths in out.values():
        paths.sort(key=lambda p: (0 if p.rsplit("/", 1)[-1].startswith("previous") else 1, p))
    return out


# -------------------------------------------------------------------------------------------------- analysers ----


def _clusterversion(objs: dict[tuple[str, str], _Obj], out: list[Finding], cluster: dict[str, Any]) -> bool:
    """Findings for the ClusterVersion; True while an update is in progress."""
    if not objs:
        return False
    obj = objs.get(("", "version"))
    if obj is None:
        # The cluster's ClusterVersion is the singleton named "version"; any other is not it, and picking the first
        # of several by file order would make the version an accident of naming. It is still a ClusterVersion, so the
        # cluster is OpenShift (``has_clusterversion``) and each object's conditions are still findings, named for
        # the object they came from. None of them says an update is in progress for the cluster.
        names = sorted(_text(name, 64) for _, name in objs)
        shown = ", ".join(names[:5]) + (f" and {len(names) - 5} more" if len(names) > 5 else "")
        cluster["version"] = ""
        cluster["clusterVersionNote"] = (
            f"ClusterVersion present but none named version ({len(objs)} object(s): {shown}): the cluster version is "
            "not determined"
        )
        for key in sorted(objs):
            other = objs[key]
            o_status = _d(other.doc.get("status"))
            o_history = [h for h in _l(o_status.get("history"))[:200] if isinstance(h, dict)]
            _clusterversion_findings(f"ClusterVersion/{_text(key[1], 64)}", o_status, o_history, other.path, out)
        return False
    doc, path = obj.doc, obj.path
    status, spec = _d(doc.get("status")), _d(doc.get("spec"))
    desired = _text(_d(status.get("desired")).get("version"), 64)
    history = [h for h in _l(status.get("history"))[:200] if isinstance(h, dict)]
    current = next((_text(h.get("version"), 64) for h in history if h.get("state") == "Completed"), "")
    cluster["version"] = current if _VERSION.match(current) else desired if _VERSION.match(desired) else ""
    cluster["desiredVersion"] = desired
    # the newest Completed entry as written (it may not be a version), None when no update completed: for readers
    # that must not fall back to status.desired when a completed entry is unreadable
    completed = next((h for h in history if h.get("state") == "Completed"), None)
    cluster["completedVersion"] = None if completed is None else _text(completed.get("version"), 64)
    cluster["channel"] = _text(spec.get("channel"), 64)
    cluster["history"] = [
        {k: _text(h.get(k), 64) for k in ("version", "state", "startedTime", "completionTime")} for h in history[:5]
    ]
    return _clusterversion_findings("ClusterVersion/version", status, history, path, out)


def has_clusterversion(cluster: dict[str, Any]) -> bool:
    """Whether the must-gather holds a ClusterVersion at all -- the one named ``version`` (which sets
    ``desiredVersion``, even when it holds no readable version) or only others (``clusterVersionNote``). Either way the
    cluster is OpenShift; only the version may be unknown."""
    return "desiredVersion" in cluster or bool(cluster.get("clusterVersionNote"))


def _clusterversion_findings(
    name: str, status: dict[str, Any], history: list[dict[str, Any]], path: str, out: list[Finding]
) -> bool:
    """The findings one ClusterVersion's conditions and history raise, for the object ``name``; True when it is
    Progressing."""
    conds = _conditions(status)
    progressing = _status(conds.get("Progressing")) == "True"
    nxt = ["oc adm upgrade", "oc get clusterversion version -o yaml"]
    rules: tuple[tuple[str, str, str, str, str | None], ...] = (
        ("Failing", "True", "critical", "the cluster version operator reports Failing", None),
        ("Available", "False", "critical", "the cluster version is not Available", None),
        ("Invalid", "True", "high", "the ClusterVersion spec is Invalid", None),
        ("ReleaseAccepted", "False", "high", "the target release was not accepted", None),
        (
            "Upgradeable",
            "False",
            "medium",
            "minor version updates are blocked (Upgradeable=False)",
            "ClusterNotUpgradeable",
        ),
        ("RetrievedUpdates", "False", "low", "available updates could not be retrieved", None),
        ("Progressing", "True", "info", "an update is in progress", None),
    )
    for ctype, bad, sev, title, alert in rules:
        cond = conds.get(ctype)
        if _status(cond) != bad or cond is None:
            continue
        message = _text(cond.get("message"))
        out.append(
            Finding(
                "clusterversion",
                sev,
                name,
                title,
                reason=_reason(cond.get("reason")),
                message=message,
                platform=True,
                evidence=[path],
                signals=_merge(
                    _implied(alert, f"ClusterVersion {ctype}={bad}") if alert else [],
                    [Signal("component", "cluster-version", "", "must-gather")],
                    for_text(message) if message else [],
                ),
                next=nxt,
            )
        )
    if history and history[0].get("state") == "Partial" and not progressing:
        target = _text(history[0].get("version"), 64)
        out.append(
            Finding(
                "clusterversion",
                "high",
                name,
                f"the update to {target or 'the desired version'} stopped partway (history state Partial) "
                "and is not progressing",
                platform=True,
                evidence=[path],
                signals=[Signal("component", "cluster-version", "", "must-gather")],
                next=nxt,
            )
        )
    return progressing


def _infrastructure(objs: dict[tuple[str, str], _Obj], cluster: dict[str, Any]) -> None:
    obj = objs.get(("", "cluster")) or next(iter(objs.values()), None)
    if obj is None:
        return
    status = _d(obj.doc.get("status"))
    platform = _d(status.get("platformStatus")).get("type") or status.get("platform")
    cluster["platform"] = _text(platform, 64)
    cluster["controlPlaneTopology"] = _text(status.get("controlPlaneTopology"), 64)


def _clusteroperators(
    objs: dict[tuple[str, str], _Obj], out: list[Finding], cluster: dict[str, Any], updating: bool
) -> None:
    rules: tuple[tuple[str, str, str, str, str | None], ...] = (
        ("Available", "False", "critical", "is not Available", "ClusterOperatorDown"),
        ("Degraded", "True", "high", "is Degraded", "ClusterOperatorDegraded"),
        ("Upgradeable", "False", "low", "blocks minor updates (Upgradeable=False)", "ClusterNotUpgradeable"),
        ("Progressing", "True", "info" if updating else "low", "is Progressing", None),
    )
    summary = Counter[str]()
    for (_, name), obj in sorted(objs.items()):
        status = _d(obj.doc.get("status"))
        conds = _conditions(status)
        summary["total"] += 1
        summary["available"] += _status(conds.get("Available")) == "True"
        summary["degraded"] += _status(conds.get("Degraded")) == "True"
        version = next(
            (_text(v.get("version"), 64) for v in _l(status.get("versions")) if _d(v).get("name") == "operator"), ""
        )
        base: list[Signal] | None = None
        for ctype, bad, sev, title, alert in rules:
            cond = conds.get(ctype)
            if cond is None or _status(cond) != bad:
                continue
            if base is None:
                base = extract(obj.doc)
            out.append(
                Finding(
                    "clusteroperators",
                    sev,
                    f"ClusterOperator/{_shown(name)}",
                    f"cluster operator {_shown(name)} {title}",
                    reason=_reason(cond.get("reason")),
                    message=_text(cond.get("message")),
                    platform=True,
                    evidence=[obj.path],
                    signals=_merge(_implied(alert, f"ClusterOperator {ctype}={bad}") if alert else [], base),
                    next=_cmds(
                        ("oc get clusteroperator {name} -o yaml", {"name": name}),
                        ("oc describe clusteroperator {name}", {"name": name}),
                    ),
                    detail={"version": version} if version else {},
                )
            )
    if summary["total"]:
        cluster["clusterOperators"] = dict(summary)


def _nodes(objs: dict[tuple[str, str], _Obj], out: list[Finding], cluster: dict[str, Any]) -> None:
    summary = Counter[str]()
    for (_, name), obj in sorted(objs.items()):
        doc = obj.doc
        labels = _d(_d(doc.get("metadata")).get("labels"))
        # node-role.kubernetes.io/<role> label keys: the prefix is a label domain, compared whole
        roles = sorted(
            role
            for prefix, sep, role in (k.partition("/") for k in labels if isinstance(k, str))
            if sep and prefix == "node-role.kubernetes.io"
        )
        control = "control-plane" in roles or "master" in roles
        conds = _conditions(_d(doc.get("status")))
        ready = conds.get("Ready")
        summary["total"] += 1
        summary["controlPlane"] += control
        summary["ready"] += _status(ready) == "True"
        node = _shown(name)
        nxt = _cmds(
            ("oc describe node {name}", {"name": name}),
            ("oc adm node-logs {name} -u kubelet", {"name": name}),
        )
        role = "control-plane" if control else "worker"
        detail = {"roles": [_text(r, 63) for r in roles[:8]]}
        kubelet = [Signal("component", "kubelet", "", "must-gather")]
        if ready is not None and _status(ready) != "True":
            state = _status(ready)
            title = (
                f"{role} node {node} is NotReady"
                if state == "False"
                else f"{role} node {node}: Ready is {_text(state, 16) or 'missing'} (the kubelet stopped reporting)"
            )
            out.append(
                Finding(
                    "nodes",
                    "critical" if control else "high",
                    f"Node/{node}",
                    title,
                    reason=_reason(ready.get("reason")),
                    message=_text(ready.get("message")),
                    platform=control,
                    evidence=[obj.path],
                    signals=_merge(_implied("KubeNodeNotReady", f"Node Ready={state}"), kubelet),
                    next=nxt,
                    detail=detail,
                )
            )
        for ctype in ("MemoryPressure", "DiskPressure", "PIDPressure", "NetworkUnavailable"):
            cond = conds.get(ctype)
            if cond is None or _status(cond) != "True":
                continue
            pressure = ctype != "NetworkUnavailable"
            out.append(
                Finding(
                    "nodes",
                    "high",
                    f"Node/{node}",
                    f"{role} node {node} reports {ctype}",
                    reason=_reason(cond.get("reason")),
                    message=_text(cond.get("message")),
                    platform=control,
                    evidence=[obj.path],
                    signals=_merge(_implied("KubeNodePressure", f"Node {ctype}=True") if pressure else [], kubelet),
                    next=nxt,
                    detail=detail,
                )
            )
        if _d(doc.get("spec")).get("unschedulable") is True:
            summary["cordoned"] += 1
            out.append(
                Finding(
                    "nodes",
                    "low",
                    f"Node/{node}",
                    f"{role} node {node} is cordoned (spec.unschedulable)",
                    platform=control,
                    evidence=[obj.path],
                    next=nxt,
                    detail=detail,
                )
            )
    if summary["total"]:
        cluster["nodes"] = dict(summary)


def _machineconfigpools(objs: dict[tuple[str, str], _Obj], out: list[Finding]) -> None:
    for (_, name), obj in sorted(objs.items()):
        doc = obj.doc
        status = _d(doc.get("status"))
        conds = _conditions(status)
        counts = {
            k: _int(status.get(k))
            for k in (
                "machineCount",
                "updatedMachineCount",
                "readyMachineCount",
                "unavailableMachineCount",
                "degradedMachineCount",
            )
        }
        pool = _shown(name)
        nxt = _cmds(("oc describe machineconfigpool {name}", {"name": name}), ("oc get machineconfigpool", {}))
        mco = [Signal("component", "machine-config", "", "must-gather")]
        degraded = False
        for ctype in sorted(conds):
            cond = conds[ctype]
            if not ctype.endswith("Degraded") or _status(cond) != "True":
                continue
            degraded = True
            # The MCO writes a sentence as the reason of NodeDegraded ("1 nodes are reporting degraded status on
            # sync"): shown as the message when there is no message.
            message = _text(cond.get("message")) or _text(cond.get("reason"))
            out.append(
                Finding(
                    "machineconfigpools",
                    "high" if ctype in {"Degraded", "NodeDegraded", "RenderDegraded"} else "medium",
                    f"MachineConfigPool/{pool}",
                    f"machine config pool {pool} reports {_text(ctype, 64)}",
                    reason=_reason(cond.get("reason")),
                    message=message,
                    platform=True,
                    evidence=[obj.path],
                    signals=_merge(mco, for_text(message) if message else []),
                    next=nxt,
                    detail=counts,
                )
            )
        if counts["degradedMachineCount"] and not degraded:
            out.append(
                Finding(
                    "machineconfigpools",
                    "high",
                    f"MachineConfigPool/{pool}",
                    f"machine config pool {pool} has {counts['degradedMachineCount']} degraded machine(s)",
                    platform=True,
                    evidence=[obj.path],
                    signals=mco,
                    next=nxt,
                    detail=counts,
                )
            )
        if _status(conds.get("Updating")) == "True":
            out.append(
                Finding(
                    "machineconfigpools",
                    "info",
                    f"MachineConfigPool/{pool}",
                    f"machine config pool {pool} is updating: {counts['updatedMachineCount']} of "
                    f"{counts['machineCount']} machines updated",
                    platform=True,
                    evidence=[obj.path],
                    signals=mco,
                    next=nxt,
                    detail=counts,
                )
            )
        if _d(doc.get("spec")).get("paused") is True:
            out.append(
                Finding(
                    "machineconfigpools",
                    "low",
                    f"MachineConfigPool/{pool}",
                    f"machine config pool {pool} is paused: machine config changes are not rolled out",
                    platform=True,
                    evidence=[obj.path],
                    signals=mco,
                    next=nxt,
                    detail=counts,
                )
            )


def _olm(objs: dict[tuple[str, str], _Obj], out: list[Finding], cluster: dict[str, Any]) -> None:
    by_name: dict[str, tuple[str, _Obj]] = {}
    for (ns, name), obj in sorted(objs.items()):
        copied = _d(obj.doc.get("status")).get("reason") == "Copied"
        held = by_name.get(name)
        if held is None or (_d(held[1].doc.get("status")).get("reason") == "Copied" and not copied):
            by_name[name] = (ns, obj)
    inventory = []
    for name, (ns, obj) in sorted(by_name.items()):
        status = _d(obj.doc.get("status"))
        phase = _text(status.get("phase"), 32)
        inventory.append({"name": _shown(name), "namespace": _shown(ns), "phase": phase})
        sev = {"Failed": "high", "Pending": "medium", "Unknown": "medium"}.get(phase)
        if sev is None:
            continue
        message = _text(status.get("message"))
        out.append(
            Finding(
                "olm",
                sev,
                f"ClusterServiceVersion/{_shown(ns)}/{_shown(name)}",
                f"operator {_shown(name)} is {phase}",
                reason=_reason(status.get("reason")),
                message=message,
                namespace=_shown(ns),
                platform=_platform(ns),
                evidence=[obj.path],
                signals=_merge([Signal("component", "olm", "", "must-gather")], for_text(message) if message else []),
                next=_cmds(
                    ("oc describe csv -n {ns} {name}", {"ns": ns, "name": name}),
                    ("oc get subscription,installplan -n {ns}", {"ns": ns}),
                ),
            )
        )
    if inventory:
        cluster["operators"] = inventory[:300]


def _log_hint(bundle: Bundle, paths: list[str]) -> tuple[str, str]:
    """The last error-like line in a container's logs (previous run first) and its file."""
    for path in paths[:4]:
        lines = bundle.files[path][-65536:].decode("utf-8", "replace").splitlines()
        for line in reversed(lines[-400:]):
            if _ERRORISH.search(line):
                return _text(line, 300), path
    return "", ""


def _pods(
    objs: dict[tuple[str, str], _Obj], out: list[Finding], bundle: Bundle, logs: dict[tuple[str, str, str], list[str]]
) -> None:
    groups: dict[tuple[str, str, str, str], dict[str, Any]] = {}

    def add(
        ns: str, pod: str, owner: str, container: str, reason: str, sev: str, title: str, obj: _Obj, **extra: Any
    ) -> None:
        key = (ns, owner or pod, container, reason)
        g = groups.get(key)
        if g is None:
            groups[key] = g = {
                "ns": ns,
                "pods": [],
                "sev": sev,
                "title": title,
                "obj": obj,
                "container": container,
                "reason": reason,
                "restarts": 0,
                **extra,
            }
        g["pods"].append(pod)
        g["restarts"] = max(g["restarts"], extra.get("restarts", 0))
        if _SEV[sev] < _SEV[g["sev"]]:
            g["sev"] = sev

    for (ns, pod), obj in sorted(objs.items()):
        doc = obj.doc
        meta, status = _d(doc.get("metadata")), _d(doc.get("status"))
        owner_ref = next((_d(r) for r in _l(meta.get("ownerReferences")) if isinstance(_d(r).get("name"), str)), {})
        owner = f"{_text(owner_ref.get('kind'), 64)}/{_shown(owner_ref['name'])}" if owner_ref else ""
        phase = status.get("phase")
        for group in ("initContainerStatuses", "containerStatuses", "ephemeralContainerStatuses"):
            for raw_cs in _l(status.get(group))[:64]:
                cs = _d(raw_cs)
                cname: str = cs["name"] if isinstance(cs.get("name"), str) else ""
                restarts = _int(cs.get("restartCount"))
                state, last = _d(cs.get("state")), _d(cs.get("lastState"))
                waiting, term, last_term = (
                    _d(state.get("waiting")),
                    _d(state.get("terminated")),
                    _d(last.get("terminated")),
                )
                wreason = waiting.get("reason")
                kind = "init container" if group.startswith("init") else "container"
                if isinstance(wreason, str) and wreason in POD_REASONS:
                    add(
                        ns,
                        pod,
                        owner,
                        cname,
                        wreason,
                        "high" if wreason in _POD_HIGH else "medium",
                        f"{kind} {_shown(cname)}: {wreason}",
                        obj,
                        restarts=restarts,
                        message=_text(waiting.get("message")),
                        lastExit=_reason(last_term.get("reason")),
                        exitCode=_int(last_term.get("exitCode")),
                    )
                elif term.get("reason") == "OOMKilled":
                    add(
                        ns,
                        pod,
                        owner,
                        cname,
                        "OOMKilled",
                        "high",
                        f"{kind} {_shown(cname)} was OOMKilled",
                        obj,
                        restarts=restarts,
                    )
                elif last_term.get("reason") == "OOMKilled":
                    add(
                        ns,
                        pod,
                        owner,
                        cname,
                        "OOMKilled",
                        "medium",
                        f"{kind} {_shown(cname)} was OOMKilled before its last restart",
                        obj,
                        restarts=restarts,
                    )
        sched = _conditions(status).get("PodScheduled")
        if phase == "Pending" and sched and _status(sched) == "False" and sched.get("reason") == "Unschedulable":
            add(
                ns,
                pod,
                owner,
                "",
                "Unschedulable",
                "medium",
                "cannot be scheduled (PodScheduled=False, Unschedulable)",
                obj,
                message=_text(sched.get("message")),
            )
        if phase == "Failed" and status.get("reason") == "Evicted":
            add(ns, pod, owner, "", "Evicted", "low", "was evicted", obj, message=_text(status.get("message")))

    for (ns, workload, container, reason), g in sorted(groups.items(), key=lambda kv: kv[0]):
        pods = sorted(set(g["pods"]))
        first, obj = pods[0], g["obj"]
        hint, hint_path = _log_hint(bundle, logs.get((ns, first, container), [])) if container else ("", "")
        sigs = _merge(
            _implied("KubePodCrashLooping", "container waiting in CrashLoopBackOff")
            if reason == "CrashLoopBackOff"
            else [],
            [s for s in extract(obj.doc) if s.kind == "component"],
            [Signal("pod_reason", reason, "", "must-gather")] if reason in POD_REASONS else [],
            for_text(hint) if hint else [],
        )
        who = workload if workload != first else f"pod {_shown(first)}"
        title = f"{_shown(ns)}/{_shown(who)}: {g['title']}"
        if len(pods) > 1:
            title += f" ({len(pods)} pods)"
        if g["restarts"]:
            title += f", {g['restarts']} restarts"
        if reason in {"Unschedulable", "Evicted"} or reason in _IMAGE_REASONS:
            nxt = _cmds(
                ("oc describe pod -n {ns} {name}", {"ns": ns, "name": first}),
                ("oc get events -n {ns} --field-selector involvedObject.name={name}", {"ns": ns, "name": first}),
            )
        else:
            logs_cmd = "oc logs -n {ns} {name} -c {container}" + (" --previous" if g["restarts"] else "")
            nxt = _cmds(
                ("oc describe pod -n {ns} {name}", {"ns": ns, "name": first}),
                (logs_cmd, {"ns": ns, "name": first, "container": container}),
            )
        detail: dict[str, Any] = {"pods": [_shown(p) for p in pods[:MAX_EXAMPLES]]}
        if container:
            detail["container"] = _shown(container)
        if g.get("lastExit"):
            detail["lastTerminated"] = {"reason": g["lastExit"], "exitCode": g.get("exitCode", 0)}
        if hint:
            detail["logHint"] = hint
        out.append(
            Finding(
                "pods",
                g["sev"],
                f"Pod/{_shown(ns)}/{_shown(first)}",
                title,
                reason=reason,
                message=g.get("message", ""),
                namespace=_shown(ns),
                platform=_platform(ns),
                count=len(pods),
                evidence=[obj.path, *([hint_path] if hint_path else [])],
                signals=sigs,
                next=nxt,
                detail=detail,
            )
        )


def _events(objs: dict[tuple[str, str], _Obj], out: list[Finding]) -> None:
    agg: dict[str, dict[str, Any]] = {}
    for (ns, _), obj in sorted(objs.items()):
        doc = obj.doc
        reason, etype = doc.get("reason"), doc.get("type")
        if not isinstance(reason, str) or not _REASON.match(reason):
            continue
        if not (etype == "Warning" or reason in EVENT_REASONS) or (reason in ROUTINE_REASONS and etype != "Warning"):
            continue
        n = _int(_d(doc.get("series")).get("count")) or _int(doc.get("count")) or 1
        when = str(
            doc.get("lastTimestamp") or doc.get("eventTime") or _d(doc.get("metadata")).get("creationTimestamp") or ""
        )
        inv = _d(doc.get("involvedObject"))
        g = agg.setdefault(
            reason, {"count": 0, "ns": set(), "objects": Counter(), "last": ("", "", ""), "paths": set()}
        )
        g["count"] += n
        g["ns"].add(ns)
        g["objects"][f"{_text(inv.get('kind'), 64)}/{_shown(ns)}/{_shown(str(inv.get('name') or ''))}"] += n
        g["paths"].add(obj.path)
        if when >= g["last"][0]:
            g["last"] = (when, _text(doc.get("message")), _shown(ns))
    ranked = sorted(agg.items(), key=lambda kv: (-kv[1]["count"], kv[0]))[:MAX_EVENT_REASONS]
    for reason, g in ranked:
        message = g["last"][1]
        known = reason in EVENT_REASONS
        platform = any(_platform(ns) for ns in g["ns"])
        out.append(
            Finding(
                "events",
                "medium" if known else "low",
                f"Event/{reason}",
                f"{reason}: {g['count']} warning event(s) on {len(g['objects'])} object(s) "
                f"in {len(g['ns'])} namespace(s)",
                reason=reason,
                message=message,
                platform=platform,
                count=g["count"],
                evidence=sorted(g["paths"])[:MAX_EXAMPLES],
                signals=_merge(
                    [Signal("event_reason", reason, "", "must-gather")], for_text(message) if message else []
                ),
                next=_cmds(("oc get events -A --field-selector reason={reason}", {"reason": reason})),
                detail={
                    "namespaces": sorted(g["ns"])[:MAX_EXAMPLES],
                    "objects": [o for o, _ in g["objects"].most_common(MAX_EXAMPLES)],
                    "lastSeen": _text(g["last"][0], 40),
                },
            )
        )


def _etcd(bundle: Bundle, logs: dict[tuple[str, str, str], list[str]], out: list[Finding]) -> int:
    files = {
        (pod, path) for (ns, pod, c), paths in logs.items() if ns == "openshift-etcd" and c == "etcd" for path in paths
    }
    hits: dict[str, dict[str, Any]] = {}
    terms: set[int] = set()
    lost = 0
    lost_example = ""
    tail_only = False
    paths_seen: set[str] = set()
    pods: set[str] = set()
    for pod, path in sorted(files):
        tail_only = tail_only or path in bundle.truncated
        for line in bundle.files[path].decode("utf-8", "replace").splitlines():
            if "leader" in line:
                m = _RAFT.search(line)
                if m:
                    pods.add(pod)
                    paths_seen.add(path)
                    if m.group(1).startswith("lost"):
                        lost += 1
                        lost_example = _text(line, 300)
                    else:
                        terms.add(int(m.group(2)))
            for phrase, _alert in _ETCD_HINTS:
                if phrase in line:
                    h = hits.setdefault(phrase, {"count": 0, "pods": Counter(), "example": "", "paths": set()})
                    h["count"] += 1
                    h["pods"][pod] += 1
                    h["example"] = _text(line, 300)
                    h["paths"].add(path)
    note = {"logTailOnly": True} if tail_only else {}
    etcd = [Signal("component", "etcd", "", "must-gather")]
    for phrase, alert in _ETCD_HINTS:
        if phrase not in hits:
            continue
        h = hits[phrase]
        first = sorted(h["pods"])[0]
        out.append(
            Finding(
                "etcd",
                "medium",
                "etcd",
                f'etcd logged "{phrase}" {h["count"]} time(s) on {len(h["pods"])} member(s)',
                message=h["example"],
                namespace="openshift-etcd",
                platform=True,
                count=h["count"],
                evidence=sorted(h["paths"])[:MAX_EXAMPLES],
                signals=_merge(_implied(alert, f'etcd log "{phrase}"') if alert else [], etcd),
                next=_cmds(
                    ("oc get pods -n openshift-etcd -o wide", {}),
                    ("oc logs -n openshift-etcd {name} -c etcd", {"name": first}),
                    ("oc get clusteroperator etcd -o yaml", {}),
                ),
                detail={"perMember": {_shown(p): n for p, n in sorted(h["pods"].items())}, **note},
            )
        )
    if len(terms) >= 2 or lost:
        span = f", terms {min(terms)} to {max(terms)}" if terms else ""
        out.append(
            Finding(
                "etcd",
                "medium",
                "etcd",
                f"etcd leader changed: {len(terms)} election term(s) seen{span}, {lost} 'lost leader' line(s)",
                message=lost_example,
                namespace="openshift-etcd",
                platform=True,
                count=max(len(terms) - 1, 0) + lost,
                evidence=sorted(paths_seen)[:MAX_EXAMPLES],
                signals=_merge(_implied("etcdHighNumberOfLeaderChanges", "raft leader election lines"), etcd),
                next=_cmds(("oc get pods -n openshift-etcd -o wide", {}), ("oc get clusteroperator etcd -o yaml", {})),
                detail={"members": sorted(_shown(p) for p in pods)[:MAX_EXAMPLES], **note},
            )
        )
    return len(files)


# ------------------------------------------------------------------------------------------------------- main ----


def analyse(bundle: Bundle) -> Analysis:
    """Run every analyser over a bundle opened by ``ingest.open_bundle``. Deterministic: the same bundle gives the
    same findings in the same order."""
    loader = _Loader(bundle)
    collected = _collect(bundle, loader)
    objects, files = collected.objects, collected.files
    logs = _logs(bundle)
    cluster: dict[str, Any] = {}
    raw: list[Finding] = []
    _infrastructure(objects.get("infrastructure", {}), cluster)
    updating = _clusterversion(objects.get("clusterversion", {}), raw, cluster)
    if ("", "version") in collected.conflicting.get("clusterversion", set()):
        # Two readings of the singleton with different content: picking either would make the version an accident
        # of file order (G288). The cluster is still OpenShift; only the version is not determined.
        paths = next(
            c["paths"] for c in collected.conflicts if c["kind"] == "ClusterVersion" and c["name"] == "version"
        )
        cluster.pop("version", None)
        cluster.pop("desiredVersion", None)
        cluster["clusterVersionNote"] = (
            f"the ClusterVersion named version was collected twice with different content ({', '.join(paths[:2])}): "
            "the version is not determined"
        )
    _clusteroperators(objects.get("clusteroperators", {}), raw, cluster, updating)
    _nodes(objects.get("nodes", {}), raw, cluster)
    for bucket, field_name in (("nodes", "nodes"), ("clusteroperators", "clusterOperators")):
        n = len(collected.conflicting.get(bucket, set()))
        if n:
            summary = cluster.setdefault(field_name, {"total": 0})
            summary["total"] = int(summary.get("total", 0)) + n
            summary["conflicting"] = n
    _machineconfigpools(objects.get("machineconfigpools", {}), raw)
    _olm(objects.get("olm", {}), raw, cluster)
    _pods(objects.get("pods", {}), raw, bundle, logs)
    _events(objects.get("events", {}), raw)
    etcd_logs = _etcd(bundle, logs, raw)
    files["etcd"] = etcd_logs

    analysis = Analysis(
        cluster=cluster, unparsed=loader.unparsed, conflicts=collected.conflicts, duplicates=collected.duplicates
    )
    per: Counter[str] = Counter()
    dropped: Counter[str] = Counter()
    for f in sorted(raw, key=Finding.key):
        if per[f.analyser] >= MAX_PER_ANALYSER or len(analysis.findings) >= MAX_FINDINGS:
            dropped[f.analyser] += 1
            continue
        per[f.analyser] += 1
        analysis.findings.append(f)
    for a in ANALYSERS:
        objs = etcd_logs if a == "etcd" else len(objects.get(a, {}))
        entry: dict[str, Any] = {"files": files.get(a, 0), "objects": objs, "findings": per[a]}
        if collected.conflicting.get(a):
            entry["conflicting"] = len(collected.conflicting[a])
        if dropped[a]:
            entry["notShown"] = dropped[a]
        if not files.get(a):
            skipped_here = [
                (p, r) for p, r in bundle.skipped_paths if (routed := _route(p)) is not None and routed[1] == a
            ]
            if skipped_here:
                # Present and not opened is not absent: a link or a device where the file would be (round 1, 8).
                shown = "; ".join(f"{_text(p, 200)} ({r})" for p, r in skipped_here[:3])
                entry["note"] = f"present but skipped ({shown}): not read"
            else:
                entry["note"] = f"not in this must-gather ({_COLLECTED_BY[a]})"
        analysis.coverage[a] = entry
    analysis.signals = _merge_all(analysis.findings)
    return analysis


def _merge_all(findings: list[Finding]) -> list[Signal]:
    seen: dict[tuple[str, str], Signal] = {}
    for f in findings:
        for s in f.signals:
            seen.setdefault((s.kind, s.name), s)
    return sorted(seen.values(), key=lambda s: (KINDS.index(s.kind), s.name))[:200]


def failing(analysis: Analysis, fail_on: str) -> list[Finding]:
    if fail_on == "never":
        return []
    return [f for f in analysis.findings if f.severity != "info" and _SEV[f.severity] <= _SEV[fail_on]]


def _conflicting(summary: dict[str, Any]) -> str:
    n = summary.get("conflicting")
    return f", {n} conflicting" if n else ""


def render_text(analysis: Analysis, completeness: dict[str, Any] | None = None) -> str:
    """``completeness``: the fold of every leg (``mustgather.completeness.fold``) when the caller has it; without it
    the line says what the analysers alone can say."""
    c = analysis.cluster
    head = []
    if c.get("version"):
        from kube_noob.mustgather.report import okd_of

        head.append(f"OKD {c['version']}" if okd_of(c) else f"OpenShift {c['version']}")
        if c.get("desiredVersion") and c["desiredVersion"] != c["version"]:
            head.append(f"updating to {c['desiredVersion']}")
    if c.get("platform"):
        head.append(f"platform {c['platform']}")
    nodes = c.get("nodes")
    if nodes:
        head.append(f"{nodes.get('ready', 0)}/{nodes['total']} nodes Ready" + _conflicting(nodes))
    ops = c.get("clusterOperators")
    if ops:
        head.append(
            f"{ops.get('available', 0)}/{ops['total']} cluster operators Available, {ops.get('degraded', 0)} Degraded"
            + _conflicting(ops)
        )
    counts = analysis.counts()
    if c.get("clusterVersionNote"):
        head.insert(0, f"OpenShift, version not determined: {c['clusterVersionNote']}")
    elif not c.get("version") and has_clusterversion(c):
        head.insert(0, "OpenShift, version not determined: the ClusterVersion named version holds no version")
    lines = ["; ".join(head) or "cluster version not in this must-gather"]
    lines.append("findings: " + ", ".join(f"{counts[s]} {s}" for s in SEVERITIES))
    for f in analysis.findings:
        reason = f" [{f.reason}]" if f.reason and f.reason not in f.title else ""
        lines.append(f"  {f.severity.upper():8} {f.analyser}: {f.title}{reason}")
        if f.message:
            lines.append(f"           {f.message}")
        hint = f.detail.get("logHint")
        if hint:
            lines.append(f"           log: {hint}")
        if f.next:
            lines.append(f"           next: {f.next[0]}")
    for conflict in analysis.conflicts[:20]:
        lines.append(
            f"conflicting: {conflict['object']} collected twice with different content "
            f"({', '.join(conflict['paths'][:2])}; differs: {', '.join(conflict['differs'][:4]) or 'content'}): "
            "not determined, read from neither copy"
        )
    if len(analysis.conflicts) > 20:
        lines.append(f"conflicting: and {len(analysis.conflicts) - 20} more")
    if analysis.duplicates:
        lines.append(
            f"duplicates: {len(analysis.duplicates)} object(s) collected twice with identical content, read once"
        )
    missing = [a for a, e in analysis.coverage.items() if e.get("note")]
    if missing:
        lines.append("not collected: " + ", ".join(missing))
    for u in analysis.unparsed[:5]:
        lines.append(f"not read: {u['path']} ({u['reason']})")
    if len(analysis.unparsed) > 5:
        lines.append(f"not read: and {len(analysis.unparsed) - 5} more")
    if completeness is not None:
        from kube_noob.mustgather.completeness import render_line

        line = render_line(completeness)
        if line:
            lines.append(line)
    else:
        c = analysis.completeness()
        if not c["complete"]:
            lines.append(
                f"evidence is partial: {c['analysersRead']} of {c['analysersExpected']} analysers had data, "
                f"{c['unreadableFiles']} file(s) could not be read. A verdict from this is not a clean bill of health; "
                "--require-complete exits 5 on it."
            )
    if analysis.signals:
        lines.append("signals: " + ", ".join(f"{s.kind}:{s.name}" for s in analysis.signals[:20]))
    return "\n".join(lines)
