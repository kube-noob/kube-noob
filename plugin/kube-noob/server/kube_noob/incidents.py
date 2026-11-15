"""Incident watch: detect problems from read-only snapshots, explain each once, and remember them.

A poll reads pods, events, deployments and replicasets in the watched namespaces (get and list only; Secrets are never
read). Problems are grouped into incidents by fingerprint: namespace, workload and signal (CrashLoopBackOff, OOMKilled,
ImagePullBackOff, FailedCreate ...). A new or recurring incident is diagnosed once with the playbooks, the policy
explainer and the reported-issue index, and gets a "what changed" note from the workload's rollout history.

The ledger is the memory: how often each incident came back, how long it lasted, and the fixes a person confirmed, so
the next occurrence arrives with "seen before, and this fixed it". It stores signals, redacted event messages and
diagnosis ids, never log lines, object specs or Secret values, and it never leaves the machine or the pod.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import tempfile
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None  # type: ignore[assignment]

from kube_noob.debug.cluster import redact_text

FILE_NAME = "incidents.json"
SCHEMA_VERSION = 1
MAX_INCIDENTS = 500
MAX_EVIDENCE = 8
MAX_LINE = 300
MAX_FIXES = 5

SIGNAL_TITLES = {
    "CrashLoopBackOff": "container keeps crashing",
    "OOMKilled": "container killed for memory",
    "ImagePullBackOff": "image cannot be pulled",
    "ContainerConfigError": "container cannot start (configuration)",
    "FailedCreate": "pods cannot be created",
    "Unschedulable": "pods cannot be scheduled",
    "FailedMount": "volume cannot be mounted",
    "ProbeFailed": "health probe failing",
    "RolloutStuck": "rollout stuck",
    "Evicted": "pods evicted",
}
_CONFIG_REASONS = {"CreateContainerConfigError", "CreateContainerError", "RunContainerError"}
_PULL_REASONS = {"ImagePullBackOff", "ErrImagePull", "InvalidImageName", "ErrImageNeverPull"}
_lock = threading.Lock()


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(t: datetime) -> str:
    return t.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _line(text: str) -> str:
    one = " ".join(redact_text(str(text)).split())
    return one if len(one) <= MAX_LINE else one[: MAX_LINE - 3] + "..."


# --- who owns what ---------------------------------------------------------------------------------------------


def _meta(obj: dict[str, Any]) -> dict[str, Any]:
    m = obj.get("metadata")
    return m if isinstance(m, dict) else {}


def _rs_owners(replicasets: list[dict[str, Any]]) -> dict[str, str]:
    out: dict[str, str] = {}
    for rs in replicasets:
        name = str(_meta(rs).get("name", ""))
        owner = next((o for o in _meta(rs).get("ownerReferences") or [] if o.get("kind") == "Deployment"), None)
        out[name] = f"deployment/{owner['name']}" if owner else f"replicaset/{name}"
    return out


def _strip_hash(name: str, parts: int) -> str:
    bits = name.split("-")
    return "-".join(bits[:-parts]) if len(bits) > parts else name


def workload_of_pod(pod: dict[str, Any], rs_owner: dict[str, str]) -> str:
    meta = _meta(pod)
    for o in meta.get("ownerReferences") or []:
        kind, name = o.get("kind"), str(o.get("name", ""))
        if kind == "ReplicaSet":
            return rs_owner.get(name) or f"deployment/{_strip_hash(name, 1)}"
        if kind in {"StatefulSet", "DaemonSet", "Job"}:
            return f"{kind.lower()}/{name}"
    return f"pod/{meta.get('name', '')}"


def _workload_of_event(ev: dict[str, Any], pods: dict[str, dict[str, Any]], rs_owner: dict[str, str]) -> str:
    io = ev.get("involvedObject") or ev.get("regarding") or {}
    kind, name = io.get("kind"), str(io.get("name", ""))
    if kind == "Pod":
        pod = pods.get(name)
        return workload_of_pod(pod, rs_owner) if pod else f"deployment/{_strip_hash(name, 2)}"
    if kind == "ReplicaSet":
        return rs_owner.get(name) or f"deployment/{_strip_hash(name, 1)}"
    if kind in {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"}:
        return f"{str(kind).lower()}/{name}"
    return f"{str(kind or 'object').lower()}/{name}"


# --- what the snapshot shows -------------------------------------------------------------------------------------


@dataclass
class Observation:
    namespace: str
    workload: str
    signal: str
    evidence: list[str] = field(default_factory=list)
    pods: list[str] = field(default_factory=list)
    crashed: list[tuple[str, str]] = field(default_factory=list)  # (pod, container) whose previous logs explain it

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(f"{self.namespace}|{self.workload}|{self.signal}".encode()).hexdigest()[:16]

    def merge(self, other: Observation) -> None:
        for e in other.evidence:
            if e not in self.evidence and len(self.evidence) < MAX_EVIDENCE:
                self.evidence.append(e)
        for p in other.pods:
            if p not in self.pods and len(self.pods) < 5:
                self.pods.append(p)
        for c in other.crashed:
            if c not in self.crashed and len(self.crashed) < 3:
                self.crashed.append(c)


def _recent(t: datetime | None, now: datetime, window: timedelta) -> bool:
    return t is not None and now - t <= window


def _pod_observations(
    pod: dict[str, Any], workload: str, ns: str, now: datetime, window: timedelta
) -> list[Observation]:
    out: list[Observation] = []
    name = str(_meta(pod).get("name", ""))
    status = pod.get("status") or {}
    statuses = (status.get("initContainerStatuses") or []) + (status.get("containerStatuses") or [])
    for cs in statuses:
        c = str(cs.get("name", ""))
        waiting = (cs.get("state") or {}).get("waiting") or {}
        last = (cs.get("lastState") or {}).get("terminated") or {}
        reason = str(waiting.get("reason") or "")
        restarts = cs.get("restartCount", 0)
        oom = last.get("reason") == "OOMKilled"
        if reason == "CrashLoopBackOff" or (oom and _recent(_parse_time(last.get("finishedAt")), now, window)):
            signal = "OOMKilled" if oom else "CrashLoopBackOff"
            detail = f"pod {name} container {c}: {reason or 'restarted'}, restartCount {restarts}"
            if last:
                detail += f", last exit {last.get('exitCode')} ({last.get('reason') or 'Error'})"
            out.append(Observation(ns, workload, signal, [_line(detail)], [name], [(name, c)]))
        elif reason in _PULL_REASONS:
            msg = f"{reason}: {waiting['message']}" if waiting.get("message") else reason
            out.append(
                Observation(ns, workload, "ImagePullBackOff", [_line(f"pod {name} container {c}: {msg}")], [name])
            )
        elif reason in _CONFIG_REASONS:
            msg = f"{reason}: {waiting['message']}" if waiting.get("message") else reason
            out.append(
                Observation(ns, workload, "ContainerConfigError", [_line(f"pod {name} container {c}: {msg}")], [name])
            )
    if status.get("reason") == "Evicted":
        out.append(
            Observation(ns, workload, "Evicted", [_line(f"pod {name}: {status.get('message', 'Evicted')}")], [name])
        )
    if status.get("phase") == "Pending":
        for cond in status.get("conditions") or []:
            if cond.get("type") == "PodScheduled" and cond.get("status") == "False":
                msg = cond.get("message") or cond.get("reason") or "Unschedulable"
                out.append(Observation(ns, workload, "Unschedulable", [_line(f"pod {name}: {msg}")], [name]))
    return out


def _event_signal(ev: dict[str, Any]) -> str | None:
    reason = str(ev.get("reason", ""))
    msg = str(ev.get("message") or ev.get("note") or "")
    if reason == "FailedCreate":
        return "FailedCreate"
    if reason == "FailedScheduling":
        return "Unschedulable"
    if reason in {"FailedMount", "FailedAttachVolume"}:
        return "FailedMount"
    if reason == "Unhealthy":
        return "ProbeFailed"
    if reason == "Evicted":
        return "Evicted"
    if reason in {"BackOff", "Failed"}:
        if re.search(r"pull|image", msg, re.IGNORECASE):
            return "ImagePullBackOff"
        if reason == "BackOff":
            return "CrashLoopBackOff"
    return None


def observe(
    snapshot: dict[str, list[dict[str, Any]]], namespace: str, now: datetime | None = None, window_seconds: int = 600
) -> list[Observation]:
    """Problems in one namespace's snapshot (``pods``, ``events``, ``deployments``, ``replicasets``)."""
    now = now or _now()
    window = timedelta(seconds=window_seconds)
    rs_owner = _rs_owners(snapshot.get("replicasets", []))
    pods = {str(_meta(p).get("name", "")): p for p in snapshot.get("pods", [])}
    found: dict[tuple[str, str], Observation] = {}

    def add(o: Observation) -> None:
        key = (o.workload, o.signal)
        if key in found:
            found[key].merge(o)
        else:
            found[key] = o

    for pod in pods.values():
        for o in _pod_observations(pod, workload_of_pod(pod, rs_owner), namespace, now, window):
            add(o)
    for ev in snapshot.get("events", []):
        if ev.get("type") != "Warning":
            continue
        when = _parse_time(ev.get("lastTimestamp") or ev.get("eventTime") or _meta(ev).get("creationTimestamp"))
        if not _recent(when, now, window):
            continue
        signal = _event_signal(ev)
        if signal is None:
            continue
        workload = _workload_of_event(ev, pods, rs_owner)
        msg = ev.get("message") or ev.get("note") or ""
        add(Observation(namespace, workload, signal, [_line(f"event {ev.get('reason')}: {msg}")]))
    for d in snapshot.get("deployments", []):
        name = str(_meta(d).get("name", ""))
        for cond in (d.get("status") or {}).get("conditions") or []:
            if cond.get("type") == "Progressing" and cond.get("reason") == "ProgressDeadlineExceeded":
                add(Observation(namespace, f"deployment/{name}", "RolloutStuck", [_line(cond.get("message", ""))]))
            if cond.get("type") == "ReplicaFailure" and cond.get("status") == "True":
                add(Observation(namespace, f"deployment/{name}", "FailedCreate", [_line(cond.get("message", ""))]))
    return list(found.values())


# --- what changed ----------------------------------------------------------------------------------------------


def _revision(rs: dict[str, Any]) -> int:
    try:
        return int((_meta(rs).get("annotations") or {}).get("deployment.kubernetes.io/revision", "0"))
    except ValueError:
        return 0


def _containers(rs: dict[str, Any]) -> dict[str, dict[str, Any]]:
    spec = ((rs.get("spec") or {}).get("template") or {}).get("spec") or {}
    return {str(c.get("name")): c for c in spec.get("containers") or [] if isinstance(c, dict)}


def _diff(old: dict[str, dict[str, Any]], new: dict[str, dict[str, Any]]) -> list[str]:
    changes: list[str] = []
    for name in sorted(set(old) | set(new)):
        a, b = old.get(name), new.get(name)
        if a is None:
            changes.append(f"container {name} added")
            continue
        if b is None:
            changes.append(f"container {name} removed")
            continue
        if a.get("image") != b.get("image"):
            changes.append(f"container {name} image {a.get('image')} -> {b.get('image')}")
        env_a = {e.get("name") for e in a.get("env") or [] if isinstance(e, dict)}
        env_b = {e.get("name") for e in b.get("env") or [] if isinstance(e, dict)}
        if env_b - env_a:
            changes.append(f"container {name} env added: {', '.join(sorted(map(str, env_b - env_a)))[:120]}")
        if env_a - env_b:
            changes.append(f"container {name} env removed: {', '.join(sorted(map(str, env_a - env_b)))[:120]}")
        for kind in ("limits", "requests"):
            ra, rb = (a.get("resources") or {}).get(kind) or {}, (b.get("resources") or {}).get(kind) or {}
            for res in sorted(set(ra) | set(rb)):
                if ra.get(res) != rb.get(res):
                    changes.append(f"container {name} {res} {kind[:-1]} {ra.get(res, 'none')} -> {rb.get(res, 'none')}")
        if a.get("command") != b.get("command") or a.get("args") != b.get("args"):
            changes.append(f"container {name} command or args changed")
    return changes


def what_changed(workload: str, replicasets: list[dict[str, Any]], opened: datetime) -> dict[str, Any] | None:
    """The latest rollout of a Deployment and how its pod template differs from the previous revision."""
    if not workload.startswith("deployment/"):
        return None
    name = workload.split("/", 1)[1]
    owned = [
        rs
        for rs in replicasets
        if any(o.get("kind") == "Deployment" and o.get("name") == name for o in _meta(rs).get("ownerReferences") or [])
    ]
    if not owned:
        return None
    owned.sort(key=_revision)
    newest = owned[-1]
    rolled = _parse_time(_meta(newest).get("creationTimestamp"))
    out: dict[str, Any] = {"revision": _revision(newest)}
    if rolled:
        out["rolledOutAt"] = _iso(rolled)
        minutes = int((opened - rolled).total_seconds() // 60)
        out["minutesBeforeIncident"] = minutes
    if len(owned) > 1:
        out["changes"] = _diff(_containers(owned[-2]), _containers(newest)) or ["pod template unchanged in containers"]
        out["previousRevision"] = _revision(owned[-2])
    else:
        out["changes"] = ["first revision: nothing earlier to compare"]
    if rolled and 0 <= out["minutesBeforeIncident"] <= 60 and len(owned) > 1:
        out["note"] = (
            f"Started {out['minutesBeforeIncident']} min after the rollout to revision {out['revision']}: "
            + "; ".join(out["changes"][:3])
        )
    return out


# --- the ledger --------------------------------------------------------------------------------------------------


class IncidentLedger:
    """``<dataDir>/incidents.json``: incidents, their occurrences and confirmed fixes. One writer at a time."""

    def __init__(self, data_dir: Path, retention_days: int = 30, resolve_after_polls: int = 3) -> None:
        self.path = data_dir / FILE_NAME
        self.retention = timedelta(days=retention_days)
        self.resolve_after = resolve_after_polls

    def _load(self) -> dict[str, Any]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {"schemaVersion": SCHEMA_VERSION, "incidents": []}
        except (OSError, ValueError) as exc:
            raise ValueError(f"{self.path} cannot be read ({exc}); move it aside to start a new ledger") from exc
        if not isinstance(data, dict) or not isinstance(data.get("incidents"), list):
            raise ValueError(f"{self.path} is not an incident ledger; move it aside to start a new one")
        if data.get("schemaVersion", 0) > SCHEMA_VERSION:
            raise ValueError(f"{self.path} was written by a newer kube-noob; upgrade to change it")
        return data

    @contextlib.contextmanager
    def _mutate(self) -> Iterator[dict[str, Any]]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with _lock, open(self.path.with_name(FILE_NAME + ".lock"), "a", encoding="utf-8") as fh:
            if fcntl is not None:
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            try:
                data = self._load()
                yield data
                data["updated"] = _iso(_now())
                fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".incidents.", suffix=".tmp")
                try:
                    os.fchmod(fd, 0o600)
                    with os.fdopen(fd, "w", encoding="utf-8") as out:
                        json.dump(data, out, indent=2, sort_keys=True)
                    os.replace(tmp, self.path)
                except BaseException:
                    Path(tmp).unlink(missing_ok=True)
                    raise
            finally:
                if fcntl is not None:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)

    # -- reading -------------------------------------------------------------------------------------------------
    def all(self) -> list[dict[str, Any]]:
        return list(self._load()["incidents"])

    def get(self, incident_id: str) -> dict[str, Any]:
        for inc in self.all():
            if inc["id"] == incident_id:
                return with_context(inc, self.all())
        raise KeyError(f"no incident {incident_id}; see `kube-noob incidents`")

    def needs_analysis(self, obs: Observation) -> bool:
        current = next((i for i in self.all() if i["fingerprint"] == obs.fingerprint), None)
        return current is None or current["status"] == "resolved" or not current.get("analysis")

    def listing(self, status: str = "open", namespace: str | None = None, limit: int = 20) -> list[dict[str, Any]]:
        everything = self.all()
        rows = [
            i
            for i in everything
            if (status == "all" or i["status"] == status) and (namespace is None or i["namespace"] == namespace)
        ]
        rows.sort(key=lambda i: i["lastSeen"], reverse=True)
        return [summary_row(i) for i in rows[:limit]]

    # -- writing -------------------------------------------------------------------------------------------------
    def record(
        self,
        observations: list[Observation],
        analyses: dict[str, dict[str, Any]],
        polled_namespaces: list[str],
        now: datetime | None = None,
    ) -> dict[str, list[str]]:
        now = now or _now()
        stamp = _iso(now)
        changes: dict[str, list[str]] = {"opened": [], "reopened": [], "updated": [], "resolved": []}
        with self._mutate() as data:
            incidents: list[dict[str, Any]] = data["incidents"]
            by_fp = {i["fingerprint"]: i for i in incidents}
            seen: set[str] = set()
            for obs in observations:
                fp = obs.fingerprint
                seen.add(fp)
                inc = by_fp.get(fp)
                if inc is None:
                    inc = {
                        "id": f"inc-{fp[:10]}",
                        "fingerprint": fp,
                        "namespace": obs.namespace,
                        "workload": obs.workload,
                        "signal": obs.signal,
                        "status": "open",
                        "firstSeen": stamp,
                        "occurrences": [{"opened": stamp, "resolved": None}],
                        "confirmedFixes": [],
                    }
                    incidents.append(inc)
                    by_fp[fp] = inc
                    changes["opened"].append(inc["id"])
                elif inc["status"] == "resolved":
                    inc["status"] = "open"
                    inc["occurrences"] = (inc.get("occurrences") or [])[-19:] + [{"opened": stamp, "resolved": None}]
                    changes["reopened"].append(inc["id"])
                else:
                    changes["updated"].append(inc["id"])
                inc["lastSeen"] = stamp
                inc["missedPolls"] = 0
                inc["evidence"] = obs.evidence[:MAX_EVIDENCE]
                inc["pods"] = obs.pods[:5]
                if fp in analyses:
                    inc["analysis"] = analyses[fp]
            for inc in incidents:
                if inc["status"] != "open" or inc["fingerprint"] in seen or inc["namespace"] not in polled_namespaces:
                    continue
                inc["missedPolls"] = int(inc.get("missedPolls", 0)) + 1
                if inc["missedPolls"] >= self.resolve_after:
                    inc["status"] = "resolved"
                    if inc.get("occurrences"):
                        inc["occurrences"][-1]["resolved"] = stamp
                    changes["resolved"].append(inc["id"])
            cutoff = now - self.retention
            kept = [
                i
                for i in incidents
                if i["status"] == "open" or (_parse_time(i.get("lastSeen")) or now) >= cutoff or i.get("confirmedFixes")
            ]
            if len(kept) > MAX_INCIDENTS:
                kept.sort(key=lambda i: (i["status"] == "open", i.get("lastSeen", "")))
                kept = kept[-MAX_INCIDENTS:]
            data["incidents"] = kept
        return changes

    def confirm(self, incident_id: str, cause: str, fix: str) -> dict[str, Any]:
        from kube_noob.learn.memory import check_text

        entry = {
            "at": _iso(_now()),
            "cause": check_text("cause", cause, 600),
            "fix": check_text("fix", fix, 1200),
        }
        with self._mutate() as data:
            inc = next((i for i in data["incidents"] if i["id"] == incident_id), None)
            if inc is None:
                raise KeyError(f"no incident {incident_id}; see `kube-noob incidents`")
            inc["confirmedFixes"] = (inc.get("confirmedFixes") or [])[-(MAX_FIXES - 1) :] + [entry]
            return dict(inc)


# --- presentation ------------------------------------------------------------------------------------------------


def _headline(inc: dict[str, Any]) -> str:
    title = SIGNAL_TITLES.get(inc["signal"], inc["signal"])
    parts = [f"{inc['workload']} in {inc['namespace']}: {title}"]
    analysis = inc.get("analysis") or {}
    dx = analysis.get("diagnosis")
    if dx:
        parts.append(f"likely {dx['title']} ({dx['id']})")
    for d in analysis.get("policyDenials") or []:
        parts.append(f"denied by {d['engineName']}" + (f" {d['policy']}" if d.get("policy") else ""))
        break
    for k in analysis.get("knownIssues") or []:
        verdict = str(k.get("verdict") or ("fixed" if k.get("kind") == "fixed" else "known issue")).replace("-", " ")
        fixed = f", fixed in {k['fixedIn']}" if k.get("fixedIn") and verdict == "fixed" else ""
        parts.append(f"reported as {k['id']} ({verdict}{fixed})")
        break
    coverage = analysis.get("knownIssuesCoverage") or {}
    if coverage.get("status") == "not-determined":  # no "reported as" here is not "not a known bug" (G277)
        parts.append(f"known issues not determined for OpenShift {coverage.get('version')} (outside the index)")
    changed = analysis.get("whatChanged") or {}
    if changed.get("note"):
        parts.append(changed["note"])
    n = len(inc.get("occurrences") or [])
    if n > 1:
        parts.append(f"occurrence {n}")
    if inc.get("confirmedFixes"):
        parts.append(f"a fix was confirmed before: {inc['confirmedFixes'][-1]['fix'][:120]}")
    return "; ".join(parts)


def summary_row(inc: dict[str, Any]) -> dict[str, Any]:
    dx = (inc.get("analysis") or {}).get("diagnosis") or {}
    return {
        "id": inc["id"],
        "status": inc["status"],
        "namespace": inc["namespace"],
        "workload": inc["workload"],
        "signal": inc["signal"],
        "occurrences": len(inc.get("occurrences") or []),
        "firstSeen": inc.get("firstSeen"),
        "lastSeen": inc.get("lastSeen"),
        "diagnosis": dx.get("id"),
        "headline": _headline(inc),
    }


def with_context(inc: dict[str, Any], everything: list[dict[str, Any]]) -> dict[str, Any]:
    """An incident plus what the ledger knows around it: earlier fixes for the same problem elsewhere."""
    out = {**inc, "headline": _headline(inc)}
    dx = ((inc.get("analysis") or {}).get("diagnosis") or {}).get("id")
    related = [
        {"id": i["id"], "namespace": i["namespace"], "workload": i["workload"], "fix": i["confirmedFixes"][-1]["fix"]}
        for i in everything
        if i["id"] != inc["id"]
        and i.get("confirmedFixes")
        and i["signal"] == inc["signal"]
        and (dx is None or ((i.get("analysis") or {}).get("diagnosis") or {}).get("id") == dx)
    ]
    if related:
        out["relatedConfirmedFixes"] = related[:3]
    occ = inc.get("occurrences") or []
    durations = []
    for o in occ:
        a, b = _parse_time(o.get("opened")), _parse_time(o.get("resolved"))
        if a and b:
            durations.append(int((b - a).total_seconds() // 60))
    out["recurrence"] = {
        "occurrences": len(occ),
        "resolvedOccurrenceMinutes": durations,
        "lastConfirmedFix": (inc.get("confirmedFixes") or [None])[-1],
    }
    return out
