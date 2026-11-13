"""Alertmanager payloads as input: the webhook body (version 4) or the API's list of alerts, read as text.

``diagnose -f alert.json`` hands the payload here first. Each alert becomes a short block (name, state, severity,
namespace, pod, then its summary and description) that playbooks, known-issue matching and policy explanations read
like any pasted error; the signals come from the structured payload itself (``kube_noob.signals.extract``).
Known-issue matching reads ``symptoms``: each alert's line and its summary only. A description is the rule's own
explanation, the same on every cluster ("Frequent elections may be a sign of insufficient resources, high network
latency, or disruptions by other components"), and its words are no evidence of a particular bug.

The version of the cluster comes from an ``openshift_version`` or ``version`` label on the payload or its alerts, and
only when the value is an OpenShift 4 release (``4.21`` or ``4.21.3``): a ``version`` label can name an app release.

Formats: webhook body https://prometheus.io/docs/alerting/latest/configuration/#webhook_config (``version``,
``status``, ``commonLabels``, ``alerts[]`` with ``status``, ``labels``, ``annotations``) and the API v2 alert list
https://github.com/prometheus/alertmanager/blob/main/api/v2/openapi.yaml (``status.state``: active, suppressed or
unprocessed).
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from kube_noob import sanitize

MAX_PAYLOAD = 2_000_000  # bytes of JSON read; anything longer is treated as text
MAX_ALERTS = 500
MAX_LABELS = 64
MAX_VALUE = 2_000  # characters kept from one label or annotation value
MAX_TEXT = 400_000  # characters of readable text, the diagnose input limit
VERSION_LABELS = ("openshift_version", "version")

_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_:]{0,127}\Z")
_OCP_RELEASE = re.compile(r"^4\.[0-9]{1,2}(\.[0-9]{1,3})?\Z")
#: Names a suggested command may use: a namespace is a DNS-1123 label, a pod, service or claim a DNS-1123 subdomain.
_NAMESPACE = re.compile(r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?\Z")
_OBJECT = re.compile(r"^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?\Z")
#: Label -> the name a playbook step fills in (kube_noob.debug.diagnose._fill), and the shape it must have.
CONTEXT_LABELS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("namespace", "ns", _NAMESPACE),
    ("pod", "pod", _OBJECT),
    ("service", "svc", _OBJECT),
    ("persistentvolumeclaim", "pvc", _OBJECT),
)


@dataclass(frozen=True)
class Payload:
    text: str
    symptoms: str
    alerts: int
    firing: int
    alertnames: tuple[str, ...]
    version: str | None
    version_from: str | None
    #: The names a suggested command may use, read from the alerts' own labels and nothing else (G274): annotation text
    #: is whatever the alert's author wrote, and "run kubectl logs x -n other" in a summary must not choose the
    #: namespace a step reads. A name is kept only when every alert that carries the label agrees on it.
    context: dict[str, str] = field(default_factory=dict)

    def summary(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "kind": "alertmanager",
            "alerts": self.alerts,
            "firing": self.firing,
            "alertnames": list(self.alertnames),
            "version": self.version,
        }
        if self.version_from:
            out["versionFrom"] = self.version_from
        return out


#: What a ``transform`` may read of one value: enough that a credential cut by the clip is still seen whole.
MAX_TRANSFORMED = MAX_VALUE * 4


def _clean(value: Any, transform: Callable[[str], str] | None = None) -> str:
    """One value with control characters and surrogates gone and whitespace collapsed, at most ``MAX_VALUE``
    characters. ``transform`` (a redactor) runs before the clip, so a value is never cut through a credential and
    then redacted, which left a private key without its END line looking like no key at all."""
    text = value if isinstance(value, str) else ""
    text = sanitize.visible(text[: MAX_TRANSFORMED if transform else MAX_VALUE * 2])
    if transform is not None:
        text = transform(text)
    return " ".join(text.split())[:MAX_VALUE]


def _labels(value: Any, transform: Callable[[str], str] | None = None) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    out: dict[str, str] = {}
    for k, v in list(value.items())[:MAX_LABELS]:
        if isinstance(k, str) and _NAME.match(k) and isinstance(v, str):
            out[k] = _clean(v, transform)
    return out


def _platform(labels: dict[str, str]) -> bool:
    """Whether an alert comes from an OpenShift platform component, whose ``version`` label is the cluster's release:
    an ``openshift-*`` namespace or the cluster-version-operator. Any other alert's ``version`` is its application's,
    and ``version="4.2"`` on an orders API is not OpenShift 4.2 (G274)."""
    return labels.get("namespace", "").startswith("openshift-") or "cluster-version-operator" in (
        labels.get("job"),
        labels.get("service"),
        labels.get("container"),
    )


def release(labels: dict[str, str], common: dict[str, str] | None = None) -> tuple[str, str] | None:
    """The OpenShift release an alert names, and where it came from. One order for every reader (``parse`` for
    diagnose, ``split`` for the report), so the two never name different releases for the same alert (G274):

    1. the alert's own ``openshift_version``, 2. the payload's common ``openshift_version``, 3. the alert's own
    ``version``, 4. the payload's common ``version``.

    ``openshift_version`` says what it is. ``version`` often names an application's release, so it counts only on an
    alert from an OpenShift platform component (``_platform``), and an explicit ``openshift_version`` anywhere beats
    it. Between two of the same name the alert's own is the more specific claim. Only an OpenShift 4 release (``4.21``
    or ``4.21.3``) counts."""
    common = common or {}
    for key in VERSION_LABELS:
        if key == "version" and not _platform({**common, **labels}):
            continue
        for source, where in ((labels, "label"), (common, "commonLabels")):
            value = source.get(key, "")
            if _OCP_RELEASE.match(value):
                return value, f"{where} {key}"
    return None


#: Scrape targets whose ``service`` label names the exporter that reported a metric, not the service an alert is
#: about: kube-state-metrics reports every pod's CrashLoopBackOff with service="kube-state-metrics" (G274).
EXPORTER_SERVICES = frozenset(
    {
        "kube-state-metrics",
        "node-exporter",
        "prometheus-node-exporter",
        "kubelet",
        "cadvisor",
        "openshift-state-metrics",
        "telemeter-client",
        "blackbox-exporter",
        "prometheus-k8s",
        "alertmanager-main",
    }
)


def _service_is_the_alerts(labels: dict[str, str]) -> bool:
    """Whether a ``service`` label names the service the alert is about rather than the scrape target that reported
    it. Prometheus's Kubernetes service discovery stamps ``service``, ``job`` (the service's name by default) and
    ``endpoint`` (the port) on every series a target exports, so any of these marks the label as the target's."""
    service = labels.get("service", "")
    return bool(service) and not (
        service in EXPORTER_SERVICES or labels.get("job") == service or bool(labels.get("endpoint"))
    )


#: Namespaces the monitoring stack itself runs in (kube-prometheus and OpenShift).
MONITORING_NAMESPACES = frozenset({"monitoring", "openshift-monitoring", "openshift-user-workload-monitoring"})
#: Pod-name prefixes of exporters, which report metrics about other objects: a pod label like these is the exporter's
#: own pod, not the alert's subject. Prometheus and Alertmanager pods are not here: an alert about them is about them.
EXPORTER_POD_PREFIXES = (
    "blackbox-exporter-",
    "kube-state-metrics-",
    "node-exporter-",
    "openshift-state-metrics-",
    "prometheus-node-exporter-",
)
#: Labels naming a namespaced object an alert is about; with none of them, a node alert has no subject namespace.
OBJECT_LABELS = (
    "pod",
    "persistentvolumeclaim",
    "deployment",
    "statefulset",
    "daemonset",
    "replicaset",
    "job_name",
    "cronjob",
    "horizontalpodautoscaler",
    "poddisruptionbudget",
    "resourcequota",
    "service",
)


def _from_exporter(labels: dict[str, str]) -> bool:
    return (
        labels.get("job", "") in EXPORTER_SERVICES
        or labels.get("service", "") in EXPORTER_SERVICES
        or labels.get("pod", "").startswith(EXPORTER_POD_PREFIXES)
    )


def subject_labels(labels: dict[str, str]) -> dict[str, str]:
    """The labels that name what an alert is about, with the scrape target's own taken out (G274).

    Upstream decides which is which: kube-prometheus scrapes kube-state-metrics with ``honorLabels: true`` and drops
    the target's ``pod``, ``service``, ``endpoint`` and ``namespace``; OpenShift's cluster-monitoring-operator scrapes
    it with ``honorLabels: true`` and no such drop, so a metric without a namespace of its own (``kube_node_*``) keeps
    ``namespace="openshift-monitoring"``; node-exporter is scraped without ``honorLabels``, so its series carry the
    exporter pod's ``pod`` and ``namespace``; and a scrape without ``honorLabels`` moves the subject's labels to
    ``exported_namespace`` and ``exported_pod``. So: when ``exported_*`` exist they are the subject, whatever the
    exporter is called; an exporter pod is never the subject; a node alert from an exporter in a monitoring
    namespace has no subject namespace; and ``service`` names the subject only when it is not the scrape target --
    except for TargetDown, whose subject IS the target."""
    out = dict(labels)
    pod, namespace = labels.get("pod", ""), labels.get("namespace", "")
    exporter_pod = pod.startswith(EXPORTER_POD_PREFIXES)
    if labels.get("exported_namespace") or labels.get("exported_pod"):
        # An `exported_` label exists only because a scrape without honorLabels found the target's own label in the
        # way, whatever the exporter is called (fourth review): the exported one is the subject's.
        for label in ("namespace", "pod"):
            out.pop(label, None)
            if labels.get(f"exported_{label}"):
                out[label] = labels[f"exported_{label}"]
    elif exporter_pod:
        out.pop("pod", None)
        out.pop("namespace", None)
    elif (
        _from_exporter(labels)
        and namespace in MONITORING_NAMESPACES
        and labels.get("node")
        and not any(labels.get(k) for k in OBJECT_LABELS if k != "service")
    ):
        out.pop("namespace", None)
    target_down = labels.get("alertname") == "TargetDown" and labels.get("job") == labels.get("service")
    if not target_down and not _service_is_the_alerts(labels):
        out.pop("service", None)
    return out


def label_context(labelsets: list[dict[str, str]]) -> dict[str, str]:
    """The names the labels agree on, each of the shape a command may hold; a disagreement leaves the placeholder.
    Each alert's labels are read for its subject first (``subject_labels``)."""
    subjects = [subject_labels(ls) for ls in labelsets]
    out: dict[str, str] = {}
    for label, key, shape in CONTEXT_LABELS:
        values = {ls[label] for ls in subjects if ls.get(label)}
        if len(values) == 1:
            (value,) = values
            if shape.match(value):
                out[key] = value
    if "pod" in out:
        out["name"] = out["pod"]
    return out


def _state(alert: dict[str, Any]) -> str:
    status = alert.get("status")
    if isinstance(status, dict):  # API v2: {"state": "active" | "suppressed" | "unprocessed"}
        state = status.get("state")
        return "firing" if state == "active" else (state if state in {"suppressed", "unprocessed"} else "unknown")
    if status in {"firing", "resolved"}:
        return str(status)
    state = alert.get("state")  # Prometheus /api/v1/alerts: "firing" | "pending" | "inactive"
    return "firing" if state == "firing" else (str(state) if state in {"pending", "inactive"} else "unknown")


def _alerts(doc: Any) -> list[dict[str, Any]] | None:
    if isinstance(doc, dict) and isinstance(doc.get("alerts"), list):
        items = doc["alerts"]
    elif isinstance(doc, dict) and isinstance(doc.get("data"), dict) and isinstance(doc["data"].get("alerts"), list):
        items = doc["data"]["alerts"]  # Prometheus /api/v1/alerts
    elif isinstance(doc, list):
        items = doc
    else:
        return None
    alerts = [a for a in items[:MAX_ALERTS] if isinstance(a, dict) and isinstance(a.get("labels"), dict)]
    named = [
        a for a in alerts if isinstance(a["labels"].get("alertname"), str) and _NAME.match(a["labels"]["alertname"])
    ]
    return named or None


def _load(text: str) -> tuple[Any, list[dict[str, Any]]] | None:
    head = text.lstrip()[:1]
    if head not in {"{", "["} or len(text) > MAX_PAYLOAD:
        return None
    if not sanitize.json_nesting_ok(text):
        return None
    try:
        doc = json.loads(text)
    except (ValueError, RecursionError):
        return None
    alerts = _alerts(doc)
    return (doc, alerts) if alerts is not None else None


_STARTS_AT = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?(Z|[+-][0-9]{2}:[0-9]{2})\Z"
)
_FINGERPRINT = re.compile(r"^[0-9a-f]{1,32}\Z")
#: The annotations a report reads. ``runbook_url`` and every other annotation are left out on purpose: a URL in a
#: payload is somebody else's text, and nothing kube-noob writes should hand a reader a link it never checked.
READ_ANNOTATIONS = ("summary", "description", "message")


@dataclass(frozen=True)
class Alert:
    """One alert of a payload, cleaned: labels and the readable annotations as ``_labels`` keeps them (64 labels,
    2,000 characters a value, control characters dropped), its state, and its start time and fingerprint only when
    they have the shape Alertmanager writes."""

    index: int  # position in the payload's alert list
    name: str
    state: str
    labels: dict[str, str]
    annotations: dict[str, str]
    starts_at: str | None
    fingerprint: str | None
    #: The OpenShift release this alert names, by ``release``: an ``openshift_version`` (the alert's, then the
    #: payload's commonLabels) before a ``version`` (likewise). Alertmanager's commonLabels are the labels every alert
    #: of the group shares, so the two agree on a real payload; a hand-made one can disagree.
    version: str | None = None
    version_from: str | None = None

    def payload(self) -> str:
        """This alert alone as a payload ``parse`` reads back to the same alert: what the per-alert diagnosis gets."""
        alert: dict[str, Any] = {"labels": self.labels, "annotations": self.annotations}
        if self.state in {"firing", "resolved"}:
            alert["status"] = self.state
        elif self.state in {"suppressed", "unprocessed"}:
            alert["status"] = {"state": self.state}
        elif self.state in {"pending", "inactive"}:
            alert["state"] = self.state
        # ensure_ascii=False: escaped, a 2,000-character value of non-ASCII text grows sixfold and one alert with 64
        # such labels would pass the diagnose tool's input limit.
        return json.dumps({"alerts": [alert]}, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@dataclass(frozen=True)
class Split:
    payload: Payload
    alerts: tuple[Alert, ...]
    #: Items of the payload's alert list that are not alerts kube-noob can read, by reason, and alerts past MAX_ALERTS.
    not_read: dict[str, int]
    #: Alerts Alertmanager left out of this webhook message: the payload's ``truncatedAlerts``, "how many alerts have
    #: been truncated due to max_alerts" (prometheus/alertmanager docs/configuration.md, webhook_config, retrieved
    #: 2026-11-13). 0 when the field is absent or 0; None when it is present but not a non-negative integer, with
    #: ``truncated_unreadable`` saying why -- an unreadable count is not a zero (G289).
    truncated: int | None = 0
    truncated_unreadable: str | None = None
    #: Every item of the payload's alert list, read or not: the group Alertmanager sent is this plus `truncated`.
    items: int = 0


def split(text: str, transform: Callable[[str], str] | None = None) -> Split | None:
    """The payload alert by alert, with what was not read counted rather than dropped. None when ``text`` is not an
    Alertmanager payload (the same test ``parse`` applies). ``transform`` runs on every label and annotation value
    before it is clipped (the report passes the redactor and the URL filter)."""
    payload = parse(text)
    loaded = _load(text) if payload is not None else None
    if payload is None or loaded is None:
        return None
    doc, _ = loaded
    if isinstance(doc, dict) and isinstance(doc.get("alerts"), list):
        items: list[Any] = doc["alerts"]
    elif isinstance(doc, dict) and isinstance(doc.get("data"), dict):
        items = doc["data"]["alerts"]
    else:
        items = doc
    common = _labels(doc.get("commonLabels")) if isinstance(doc, dict) else {}
    not_read: dict[str, int] = {}
    if len(items) > MAX_ALERTS:
        not_read["over the limit of 500 alerts"] = len(items) - MAX_ALERTS
    out: list[Alert] = []
    for i, item in enumerate(items[:MAX_ALERTS]):
        if not isinstance(item, dict) or not isinstance(item.get("labels"), dict):
            not_read["not an alert object with labels"] = not_read.get("not an alert object with labels", 0) + 1
            continue
        labels = _labels(item["labels"], transform)
        name = labels.get("alertname", "")
        if not _NAME.match(name):
            key = "no valid alertname label"
            not_read[key] = not_read.get(key, 0) + 1
            continue
        notes = {k: v for k, v in _labels(item.get("annotations"), transform).items() if k in READ_ANNOTATIONS and v}
        found = release(labels, common)
        starts = item.get("startsAt") if isinstance(item.get("startsAt"), str) else None
        fingerprint = item.get("fingerprint") if isinstance(item.get("fingerprint"), str) else None
        out.append(
            Alert(
                index=i,
                name=name,
                state=_state(item),
                labels=labels,
                annotations=notes,
                starts_at=starts if starts and _STARTS_AT.match(starts) else None,
                fingerprint=fingerprint if fingerprint and _FINGERPRINT.match(fingerprint) else None,
                version=found[0] if found else None,
                version_from=found[1] if found else None,
            )
        )
    truncated, unreadable = _truncated(doc)
    return Split(payload, tuple(out), not_read, truncated, unreadable, len(items))


MAX_TRUNCATED = 1_000_000


def _truncated(doc: Any) -> tuple[int | None, str | None]:
    """The payload's ``truncatedAlerts``: a non-negative integer, or None with the reason it could not be read."""
    if not isinstance(doc, dict) or "truncatedAlerts" not in doc:
        return 0, None
    value = doc["truncatedAlerts"]
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        shown = (
            json.dumps(value, ensure_ascii=False)[:40] if not isinstance(value, dict | list) else type(value).__name__
        )
        return None, f"truncatedAlerts is not a non-negative integer ({shown})"
    if value > MAX_TRUNCATED:
        # an integer, and one no receiver can have truncated: said apart from a type error (round 1, 12)
        return None, f"truncatedAlerts ({value:,}) exceeds the cap ({MAX_TRUNCATED:,}) this reads"
    return value, None


def compact(text: str, limit: int = MAX_TEXT) -> str | None:
    """The same payload as smaller JSON (labels, the three readable annotations and the state of each alert, values
    cut to ``MAX_VALUE``), for payloads longer than the diagnose input limit. None when ``text`` is not a payload."""
    loaded = _load(text)
    if loaded is None:
        return None
    doc, alerts = loaded
    common = _labels(doc.get("commonLabels")) if isinstance(doc, dict) else {}
    kept = [
        {
            "status": _state(a),
            "labels": _labels(a["labels"]),
            "annotations": {
                k: v for k, v in _labels(a.get("annotations")).items() if k in {"summary", "description", "message"}
            },
        }
        for a in alerts
    ]
    while kept:
        out = json.dumps({"commonLabels": common, "alerts": kept}, separators=(",", ":"))
        if len(out) <= limit:
            return out
        kept = kept[: max(1, len(kept) * 3 // 4)] if len(kept) > 1 else []
    return None


def parse(text: str) -> Payload | None:
    """The payload in ``text``, or None when ``text`` is not an Alertmanager payload (it is then read as text)."""
    loaded = _load(text)
    if loaded is None:
        return None
    doc, alerts = loaded
    common = _labels(doc.get("commonLabels")) if isinstance(doc, dict) else {}
    lines: list[str] = []
    symptoms: list[str] = []
    names: set[str] = set()
    firing = 0
    labelsets = [_labels(a["labels"]) for a in alerts]
    # The first alert that names a release, by the one precedence `split` uses too; a payload whose alerts name
    # different releases is reported per alert by the evidence report.
    version = next((v for v in (release(ls, common) for ls in labelsets) if v), None)
    for alert, labels in zip(alerts, labelsets, strict=True):
        name = labels["alertname"]
        names.add(name)
        state = _state(alert)
        firing += state == "firing"
        parts = [f"alert {name} {state}"]
        for key, word in (("severity", "severity"), ("namespace", "namespace")):
            if labels.get(key):
                parts.append(f"{word} {labels[key]}")
        if labels.get("pod"):
            parts.append(f"pod/{labels['pod']}")
        for key in ("container", "service", "instance", "node"):
            if labels.get(key):
                parts.append(f"{key} {labels[key]}")
        lines.append(", ".join(parts))
        symptoms.append(lines[-1])
        notes = _labels(alert.get("annotations"))
        for key in ("summary", "description", "message"):
            if notes.get(key):
                lines.append(f"  {key}: {notes[key]}")
        short = notes.get("summary") or notes.get("message") or notes.get("description")
        if short:
            symptoms.append(f"  {short}")
    return Payload(
        text="\n".join(lines)[:MAX_TEXT],
        symptoms="\n".join(symptoms)[:MAX_TEXT],
        alerts=len(alerts),
        firing=firing,
        alertnames=tuple(sorted(names)),
        version=version[0] if version else None,
        version_from=version[1] if version else None,
        context=label_context(labelsets),
    )
