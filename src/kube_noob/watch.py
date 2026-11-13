"""The always-on watch loop: poll the watched namespaces read-only, open and close incidents, explain new ones.

Runs as ``kube-noob watch`` (a terminal, or ``--once`` in CI) or inside ``kube-noob serve`` when ``watch.enabled`` is
set, so the sidecar or the in-cluster service keeps the incident ledger current between questions. It calls only
get, list and logs on the Kubernetes API through the configured backend; no model, no other network.
"""

from __future__ import annotations

import contextlib
import logging
import threading
from datetime import UTC, datetime
from typing import Any

from kube_noob.config import Settings
from kube_noob.debug.cluster import list_items
from kube_noob.errors import ClusterAccessError, ConfigError
from kube_noob.incidents import IncidentLedger, Observation, observe, what_changed

_log = logging.getLogger("kube_noob.watch")
RESOURCES = ("pods", "events", "deployments", "replicasets")


def _pod_namespace() -> str | None:
    """The namespace this pod runs in, from the in-cluster backend's mount (absent outside a pod)."""
    try:
        from kube_noob.debug.backends import SA_DIR
    except ImportError:  # the Claude plugin build ships without cluster access
        return None
    try:
        return (SA_DIR / "namespace").read_text(encoding="ascii").strip() or None
    except OSError:
        return None


def resolve_namespaces(settings: Settings, requested: list[str] | None = None) -> list[str]:
    """Namespaces to watch: the ones asked for, else ``watch.namespaces``, else the pod's own namespace."""
    names = list(requested or settings.watch.namespaces)
    if not names:
        own = _pod_namespace()
        names = [own] if own else []
    if not names:
        raise ConfigError("name the namespaces to watch: -n NAMESPACE (repeat for several) or watch.namespaces")
    return list(dict.fromkeys(names))


class Watcher:
    def __init__(self, settings: Settings, backend: Any, namespaces: list[str], platform: str | None = None) -> None:
        self.settings = settings
        self.backend = backend
        self.namespaces = namespaces
        w = settings.watch
        self.ledger = IncidentLedger(settings.data_dir, w.retention_days, w.resolve_after_polls)
        # Recent enough to count: three poll intervals, at least ten minutes (events are updated, not re-sent).
        self.window_seconds = max(600, 3 * w.interval_seconds)
        self.platform = platform
        self.version: str | None = None
        self._info_read = False
        self.cluster_not_read: str | None = None  # named in every poll's errors (G293, review)

    def _cluster_info(self) -> None:
        if self._info_read:
            return
        self._info_read = True
        from kube_noob.debug.cluster import cluster_info

        try:
            info = cluster_info(self.backend)
        except Exception as exc:  # noqa: BLE001 - the version only sharpens known-issue matches, but say so
            self.cluster_not_read = f"clusterversions: not read ({str(exc)[:300]}); no platform for known-issue matches"
            return
        self.version = info.get("openshift")
        if info.get("platformNotRead"):
            # A ServiceAccount that may not read ClusterVersion is the usual shape on OpenShift: the diagnosis still
            # runs, without a platform, and the poll says so instead of a silent None (G293, review).
            self.cluster_not_read = f"clusterversions: not read ({info['platformNotRead']})"
        if self.platform is None:
            self.platform = info.get("platform")  # None when ClusterVersion could not be read (G279)

    def snapshot(self, namespace: str) -> tuple[dict[str, list[dict[str, Any]]], list[str]]:
        snap: dict[str, list[dict[str, Any]]] = {}
        errors: list[str] = []
        for resource in RESOURCES:
            try:
                snap[resource] = list(list_items(self.backend.get(resource, namespace=namespace), resource, namespace))
            except ClusterAccessError as exc:
                snap[resource] = []
                errors.append(f"{namespace}/{resource}: {exc}")
        return snap, errors

    def analyse(self, obs: Observation, snap: dict[str, list[dict[str, Any]]], now: datetime) -> dict[str, Any]:
        """Diagnose a new or recurring incident once. Logs are read for the diagnosis and never stored."""
        from kube_noob.debug.diagnose import diagnose
        from kube_noob.debug.policy import explain as explain_denials
        from kube_noob.known_issues import match as known_issue_match

        logs = ""
        not_read: list[str] = []
        for pod, container in obs.crashed[:1]:
            try:
                logs = self.backend.logs(obs.namespace, pod, container, 50, True)
            except ClusterAccessError as exc:
                # The diagnosis runs on the events alone; the reader is told the log was not part of it (G293).
                not_read.append(f"{obs.namespace}/pods/log {pod}/{container}: not read ({str(exc)[:300]})")
        text = "\n".join(obs.evidence) + "\n" + logs + f"\nNamespace: {obs.namespace}\n"
        dx = diagnose(text, platform=self.platform, limit=1).as_dict()
        out: dict[str, Any] = {"analyzedAt": now.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")}
        if not_read:
            out["notRead"] = not_read
        if dx["diagnoses"]:
            top = dx["diagnoses"][0]
            out["diagnosis"] = {
                "id": top["id"],
                "title": top["title"],
                "confidence": top["confidence"],
                "readOnlyNextSteps": top["readOnlyNextSteps"][:4],
                "proposedChanges": [c["change"] for c in top["proposedChanges"][:3]],
            }
        denials = explain_denials(text, self.platform)["denials"]
        if denials:
            out["policyDenials"] = [
                {
                    k: d[k]
                    for k in ("engine", "engineName", "policy", "rule", "meaning", "readOnlyNextSteps", "relatedRules")
                    if k in d
                }
                for d in denials[:3]
            ]
        known = known_issue_match(text, self.platform, self.version, 2, self.settings.data_dir, require_context=True)[
            "matches"
        ]
        if known:
            keep = ("id", "url", "status", "kind", "verdict", "fixedIn", "workaround")  # kind: known, fixed or ticket
            out["knownIssues"] = [{k: m[k] for k in keep if m.get(k) is not None} for m in known]
        changed = what_changed(obs.workload, snap.get("replicasets", []), now)
        if changed:
            out["whatChanged"] = changed
        return out

    def poll(self, now: datetime | None = None) -> dict[str, Any]:
        now = now or datetime.now(UTC)
        self._cluster_info()
        observations: list[Observation] = []
        analyses: dict[str, dict[str, Any]] = {}
        polled: list[str] = []
        errors: list[str] = [self.cluster_not_read] if self.cluster_not_read else []
        for ns in self.namespaces:
            snap, errs = self.snapshot(ns)
            errors += errs
            if len(errs) == len(RESOURCES):
                continue  # nothing readable: do not resolve this namespace's incidents on a failed read
            polled.append(ns)
            for obs in observe(snap, ns, now, self.window_seconds):
                observations.append(obs)
                if self.ledger.needs_analysis(obs):
                    analyses[obs.fingerprint] = self.analyse(obs, snap, now)
                    errors += analyses[obs.fingerprint].get("notRead", [])
        changes = self.ledger.record(observations, analyses, polled, now)
        if self.settings.learning_enabled and (changes["opened"] or changes["reopened"]):
            from kube_noob.learn.memory import LearningStore

            keys = [f"incident:{o.signal.lower()}" for o in observations if o.fingerprint in analyses]
            with contextlib.suppress(Exception):  # counting is best effort
                LearningStore(self.settings.data_dir).bump(keys)
        return {
            "polledAt": now.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "namespaces": polled,
            "changes": changes,
            "open": self.ledger.listing("open"),
            "errors": errors,
        }

    def run(self, stop: threading.Event) -> None:
        interval = self.settings.watch.interval_seconds
        _log.info("watching %s every %ss (read-only)", ", ".join(self.namespaces), interval)
        while not stop.is_set():
            try:
                result = self.poll()
                for kind in ("opened", "reopened", "resolved"):
                    for incident_id in result["changes"][kind]:
                        _log.info("incident %s %s", incident_id, kind)
                for err in result["errors"]:
                    _log.warning("watch read failed: %s", err)
            except Exception:  # noqa: BLE001 - one failed poll must not stop the watch
                _log.exception("watch poll failed")
            stop.wait(interval)


def start_background(settings: Settings, namespaces: list[str] | None = None) -> threading.Event:
    """Start the watch in a daemon thread (``kube-noob serve``); returns the event that stops it."""
    from kube_noob.debug.cluster import get_backend

    if not settings.cluster.enabled:
        raise ConfigError("watch.enabled needs read-only cluster access: set cluster.enabled: true")
    watcher = Watcher(settings, get_backend(settings), resolve_namespaces(settings, namespaces))
    stop = threading.Event()
    threading.Thread(target=watcher.run, args=(stop,), name="kube-noob-watch", daemon=True).start()
    return stop
