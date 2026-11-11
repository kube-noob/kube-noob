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
from dataclasses import dataclass
from typing import Any

from kube_noob import sanitize

MAX_PAYLOAD = 2_000_000  # bytes of JSON read; anything longer is treated as text
MAX_ALERTS = 500
MAX_LABELS = 64
MAX_VALUE = 2_000  # characters kept from one label or annotation value
MAX_TEXT = 400_000  # characters of readable text, the diagnose input limit
VERSION_LABELS = ("openshift_version", "version")

_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_:]{0,127}\Z")
_OCP_RELEASE = re.compile(r"^4\.\d{1,2}(\.\d{1,3})?\Z")
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


@dataclass(frozen=True)
class Payload:
    text: str
    symptoms: str
    alerts: int
    firing: int
    alertnames: tuple[str, ...]
    version: str | None
    version_from: str | None

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


def _clean(value: Any) -> str:
    text = value if isinstance(value, str) else ""
    return " ".join(_CONTROL.sub(" ", text[: MAX_VALUE * 2]).split())[:MAX_VALUE]


def _labels(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    out: dict[str, str] = {}
    for k, v in list(value.items())[:MAX_LABELS]:
        if isinstance(k, str) and _NAME.match(k) and isinstance(v, str):
            out[k] = _clean(v)
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


_STARTS_AT = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})\Z")
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


def split(text: str) -> Split | None:
    """The payload alert by alert, with what was not read counted rather than dropped. None when ``text`` is not an
    Alertmanager payload (the same test ``parse`` applies)."""
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
    not_read: dict[str, int] = {}
    if len(items) > MAX_ALERTS:
        not_read["over the limit of 500 alerts"] = len(items) - MAX_ALERTS
    out: list[Alert] = []
    for i, item in enumerate(items[:MAX_ALERTS]):
        if not isinstance(item, dict) or not isinstance(item.get("labels"), dict):
            not_read["not an alert object with labels"] = not_read.get("not an alert object with labels", 0) + 1
            continue
        labels = _labels(item["labels"])
        name = labels.get("alertname", "")
        if not _NAME.match(name):
            key = "no valid alertname label"
            not_read[key] = not_read.get(key, 0) + 1
            continue
        notes = {k: v for k, v in _labels(item.get("annotations")).items() if k in READ_ANNOTATIONS and v}
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
            )
        )
    return Split(payload, tuple(out), not_read)


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
    version: tuple[str, str] | None = None
    for source in [common, *(_labels(a["labels"]) for a in alerts)]:
        for key in VERSION_LABELS:
            value = source.get(key, "")
            if version is None and _OCP_RELEASE.match(value):
                version = (value, f"label {key}")
    for alert in alerts:
        labels = _labels(alert["labels"])
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
    )
