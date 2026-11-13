"""Extract signals from free text, an Alertmanager webhook payload, events, ClusterOperators or pod status, and Ceph
health output (``ceph health detail``, ``ceph status``, their JSON, a Rook CephCluster's status).

Every name comes from a vocabulary checked against its upstream source (``kube_noob.signals.vocab``,
``kube_noob.signals.ceph``) or from the structured field that carries it (``labels.alertname``, ``reason``,
``status.conditions``, Ceph's ``checks``). Output is deterministic: the same input gives the same signals in the same
order. Input is bounded in size, lines, items and signals.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any

from kube_noob import sanitize
from kube_noob.errors import ManifestError
from kube_noob.signals.vocab import (
    CO_BAD,
    COMPONENTS,
    EVENT_REASONS,
    POD_REASONS,
    ROUTINE_REASONS,
    STRUCTURED_ONLY,
)

KINDS = (
    "alert",
    "ceph_health",
    "co_condition",
    "event_reason",
    "pod_reason",
    "admission",
    "component",
    "error_template",
)
MAX_INPUT = 2_000_000  # characters
MAX_LINES = 20_000
MAX_LINE = 4_000
MAX_ITEMS = 5_000
MAX_SIGNALS = 200
MAX_TEMPLATES = 20
MIN_TEMPLATE_WORDS = 3

_ORDER = {k: i for i, k in enumerate(KINDS)}
_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_:.-]{0,127}\Z")
_REASON = re.compile(r"^[A-Z][A-Za-z0-9]{1,63}\Z")
_ALERTNAME_TEXT = re.compile(r"""alertname\s*[=:]\s*["']?([A-Za-z_][A-Za-z0-9_:]{0,127})""")
_FIRING = re.compile(r"^\s*\[(?:FIRING|RESOLVED)(?::\d+)?\]\s+([A-Za-z_][A-Za-z0-9_:]{0,127})")
_EVENT_ROW = re.compile(r"^\s*(?:\S+\s+)?(Warning|Normal)\s+([A-Z][A-Za-z0-9]{1,63})\s")
_REASON_FIELD = re.compile(r"\b[Rr]eason:\s*([A-Z][A-Za-z0-9]{1,63})\b")
_CO_ROW = re.compile(
    r"^\s*(?:clusteroperator(?:\.config\.openshift\.io)?/)?([a-z0-9][a-z0-9-]{0,62})\s+(?:\S+\s+)?"
    r"(True|False|Unknown)\s+(True|False|Unknown)\s+(True|False|Unknown)\b(.*)$"
)
_CAMEL_PREFIX = re.compile(r"^\s*(?:\S+\s+){0,2}?([A-Z][A-Za-z0-9_]{3,127}):\s")
_WORD = re.compile(r"[A-Za-z][A-Za-z0-9]*")
_TOKEN = re.compile(r"[a-z0-9][a-z0-9.-]*[a-z0-9]|[a-z0-9]")
_ERRORISH = re.compile(
    r"(?i)\b(error|failed|failure|denied|forbidden|panic|unable|cannot|timeout|timed out|refused|invalid|"
    r"x509|exceeded|unauthorized|rejected|conflict|deadline|not found|no such|crash)\b"
)

# Normalisation: each pattern is bounded and anchored on simple character classes (no nested quantifiers).
_NORMALISE: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^[IWEF]\d{4} \d{2}:\d{2}:\d{2}\.\d{1,9}\s+\d{1,10}\s+[\w./-]{1,200}:\d{1,6}\]\s*"), ""),  # klog
    (re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?"), "<time>"),
    (re.compile(r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) {1,2}\d{1,2} \d{2}:\d{2}:\d{2}\b"), "<time>"),
    (re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"), "<uuid>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b"), "<ip>"),
    (
        re.compile(
            r"(?<![\w:])\[?(?=[0-9a-fA-F:]{0,39}\d)(?:[0-9a-fA-F]{1,4}:|:){2,8}[0-9a-fA-F]{0,4}\]?(?::\d{1,5})?"
        ),
        "<ip>",
    ),
    (re.compile(r"\b([a-z0-9](?:[-a-z0-9]{0,200}[a-z0-9])?)-[a-z0-9]{8,10}-[a-z0-9]{5}(?![a-z0-9])"), r"\1-<pod>"),
    (
        re.compile(
            r"\b([a-z](?:[-a-z0-9]{0,200}[a-z0-9])?)-(?=[a-z0-9]{5}(?![a-z0-9]))(?=[a-z]{0,4}\d)[a-z0-9]{5}(?![a-z0-9])"
        ),
        r"\1-<pod>",
    ),
    (
        re.compile(r"\b(?:\d{1,6}h)?(?:\d{1,6}m)?\d{1,6}(?:\.\d{1,9})?(?:ns|us|µs|ms|s)\b|\b\d{1,6}(?:h|m)\b"),
        "<duration>",
    ),
    (re.compile(r"\b(?=[0-9a-fA-F]{0,63}[0-9])(?=[0-9a-fA-F]{0,63}[a-fA-F])[0-9a-fA-F]{8,64}\b"), "<hex>"),
    (re.compile(r"\b\d+\.\d+\b|\b\d{4,}\b"), "<n>"),
)


@dataclass(frozen=True)
class Signal:
    kind: str
    name: str
    detail: str = ""
    source: str = ""

    def as_dict(self) -> dict[str, str]:
        out = {"kind": self.kind, "name": self.name, "source": self.source}
        if self.detail:
            out["detail"] = self.detail
        return out


def normalise_error(line: str) -> tuple[str, str]:
    """A stable template for an error line (names, addresses, times and ids replaced) and its short sha256."""
    text = line[:MAX_LINE].strip()
    for rx, repl in _NORMALISE:
        text = rx.sub(repl, text)
    text = re.sub(r"\s+", " ", text).strip(" .;,")
    return text, hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()[:12]


class _Collector:
    def __init__(self) -> None:
        self.found: dict[tuple[str, str], Signal] = {}
        self.templates = 0

    def add(self, kind: str, name: str, source: str, detail: str = "") -> None:
        if len(self.found) >= MAX_SIGNALS or not name:
            return
        key = (kind, name)
        if key not in self.found:
            self.found[key] = Signal(kind, name, detail[:300], source[:120])

    def result(self) -> list[Signal]:
        return sorted(self.found.values(), key=lambda s: (_ORDER[s.kind], s.name, s.source))


def extract(data: Any) -> list[Signal]:
    """Signals in ``data``: text (free text, JSON or YAML) or an already parsed payload (dict or list)."""
    out = _Collector()
    if isinstance(data, str):
        text = data[:MAX_INPUT]
        parsed = _parse(text)
        if parsed is not None:
            for i, doc in enumerate(parsed[:MAX_ITEMS]):
                _structured(doc, out, f"doc[{i}]")
        else:
            _text(text, out, "text")
    elif isinstance(data, dict | list):
        for i, doc in enumerate((data if isinstance(data, list) else [data])[:MAX_ITEMS]):
            _structured(doc, out, f"doc[{i}]")
    return out.result()


def _parse(text: str) -> list[Any] | None:
    """Structured input: JSON or YAML that parses to objects with a known shape. Prose that happens to be valid YAML
    (a plain scalar) is treated as text."""
    head = text.lstrip()[:200]
    if head.startswith(("{", "[")):  # JSON (kubectl -o json, Alertmanager): parsed as JSON only, fast to refuse
        try:
            doc = sanitize.loads_bounded(text)
        except (ValueError, RecursionError):
            return None
        docs = doc if isinstance(doc, list) and doc and all(isinstance(d, dict) for d in doc) else [doc]
        return [d for d in docs if isinstance(d, dict)] or None
    if not re.match(r"(?m)^(apiVersion|kind|items|alerts|status|metadata):", head):
        return None
    from kube_noob.yamlio import load_documents

    try:
        docs = [d.data for d in load_documents(text)]
    except (ManifestError, ValueError, RecursionError):
        return None
    return [d for d in docs if isinstance(d, dict)] or None


def _structured(doc: Any, out: _Collector, where: str) -> None:
    if not isinstance(doc, dict):
        return
    from kube_noob.signals.ceph import json_checks

    checks = json_checks(doc)  # ceph health detail / ceph status -f json, or a CephCluster's status
    if checks is not None:
        for code, detail, path in checks:
            out.add("ceph_health", code, f"{where}.{path}", detail)
        if doc.get("kind") != "CephCluster":
            return
    if isinstance(doc.get("alerts"), list):  # Alertmanager webhook payload (version 4)
        for i, alert in enumerate(doc["alerts"][:MAX_ITEMS]):
            _alert(alert, out, f"{where}.alerts[{i}]")
        common = _dict(doc.get("commonLabels"))
        _alertname(common.get("alertname"), out, f"{where}.commonLabels")
        return
    if isinstance(doc.get("labels"), dict) and "alertname" in doc["labels"]:
        _alert(doc, out, where)
        return
    items = doc.get("items")
    if isinstance(items, list):  # a List that load_documents did not flatten (JSON parsed as one mapping)
        for i, item in enumerate(items[:MAX_ITEMS]):
            _structured(item, out, f"{where}.items[{i}]")
        return
    kind = str(doc.get("kind") or "")
    if kind == "Event" or ("reason" in doc and ("involvedObject" in doc or "regarding" in doc)):
        _event(doc, out, where)
    elif kind == "ClusterOperator":
        _cluster_operator(doc, out, where)
    elif kind == "Pod" or isinstance(_dict(doc.get("status")).get("containerStatuses"), list):
        _pod(doc, out, where)
    else:
        _text(_strings(doc), out, where)


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _alertname(value: Any, out: _Collector, where: str) -> None:
    if isinstance(value, str) and _NAME.match(value):
        out.add("alert", value, where)


def _alert(alert: Any, out: _Collector, where: str) -> None:
    if not isinstance(alert, dict):
        return
    labels = _dict(alert.get("labels"))
    _alertname(labels.get("alertname"), out, f"{where}.labels")
    for label in ("container", "pod", "job", "service", "namespace"):
        value = labels.get(label)
        if isinstance(value, str):
            _components(value, out, f"{where}.labels.{label}")
    notes = _dict(alert.get("annotations"))
    text = "\n".join(str(notes[k]) for k in ("summary", "description", "message") if isinstance(notes.get(k), str))
    if text:
        _text(text, out, f"{where}.annotations")


def _event(doc: dict[str, Any], out: _Collector, where: str) -> None:
    reason = doc.get("reason")
    etype = doc.get("type")
    if (
        isinstance(reason, str)
        and _REASON.match(reason)
        and (reason in EVENT_REASONS or (etype == "Warning" and reason not in ROUTINE_REASONS))
    ):
        out.add("event_reason", reason, where)
    message = doc.get("message") or doc.get("note")
    if isinstance(message, str) and (etype == "Warning" or reason in EVENT_REASONS):
        _text(message, out, f"{where}.message")
    obj = doc.get("involvedObject") or doc.get("regarding")
    if isinstance(obj, dict) and isinstance(obj.get("name"), str):
        _components(obj["name"], out, f"{where}.object")


def _cluster_operator(doc: dict[str, Any], out: _Collector, where: str) -> None:
    name = str(_dict(doc.get("metadata")).get("name") or "")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", name):
        return
    out.add("component", name, where)
    for cond in _dict(doc.get("status")).get("conditions") or []:
        if not isinstance(cond, dict):
            continue
        ctype, status, reason = cond.get("type"), str(cond.get("status")), cond.get("reason")
        if ctype in CO_BAD and CO_BAD[ctype] == status:
            suffix = f":{reason}" if isinstance(reason, str) and _REASON.match(reason.replace("_", "")) else ""
            out.add("co_condition", f"{name}/{ctype}={status}{suffix}", where)
            if isinstance(cond.get("message"), str):
                _text(cond["message"], out, f"{where}.{ctype}")


def _pod(doc: dict[str, Any], out: _Collector, where: str) -> None:
    status = _dict(doc.get("status"))
    if isinstance(status.get("reason"), str) and status["reason"] in POD_REASONS:
        out.add("pod_reason", status["reason"], f"{where}.status")
    for group in ("initContainerStatuses", "containerStatuses", "ephemeralContainerStatuses"):
        for i, cs in enumerate(status.get(group) or []):
            if not isinstance(cs, dict):
                continue
            for state_key in ("state", "lastState"):
                state = cs.get(state_key) or {}
                for phase in ("waiting", "terminated"):
                    detail = state.get(phase) if isinstance(state, dict) else None
                    reason = detail.get("reason") if isinstance(detail, dict) else None
                    if isinstance(reason, str) and (reason in POD_REASONS or reason == "Error"):
                        out.add("pod_reason", reason, f"{where}.{group}[{i}].{state_key}.{phase}")
                    if isinstance(detail, dict) and isinstance(detail.get("message"), str):
                        _text(detail["message"], out, f"{where}.{group}[{i}].{state_key}.{phase}")
    name = _dict(doc.get("metadata")).get("name")
    if isinstance(name, str):
        _components(name, out, f"{where}.metadata")


def _strings(value: Any, depth: int = 0) -> str:
    """Every string in a parsed document, for documents of no known shape (bounded)."""
    if depth > 20:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return "\n".join(_strings(v, depth + 1) for v in list(value.values())[:MAX_ITEMS])
    if isinstance(value, list):
        return "\n".join(_strings(v, depth + 1) for v in value[:MAX_ITEMS])
    return ""


def _components(text: str, out: _Collector, where: str) -> None:
    tokens = set(_TOKEN.findall(text.lower()[:MAX_LINE]))
    for canonical, aliases in COMPONENTS.items():
        if any(t == a or t.startswith(a + "-") for a in aliases for t in tokens):
            out.add("component", canonical, where)


def _text(text: str, out: _Collector, where: str) -> None:
    text = text[:MAX_INPUT]
    from kube_noob.debug.policy import admission_signal
    from kube_noob.debug.policy import explain as explain_denials

    for d in explain_denials(text[:200_000])["denials"]:
        out.add("admission", admission_signal(d), where)
    from kube_noob.signals.ceph import text_signals

    for code, detail, n in text_signals(text, MAX_LINES, MAX_LINE):
        out.add("ceph_health", code, f"{where} line {n}", detail)
    from kube_noob.signals.catalogue import _alert_names

    known_alerts = _alert_names()
    lines = text.splitlines()[:MAX_LINES]
    for n, raw in enumerate(lines, 1):
        line = raw[:MAX_LINE]
        src = f"{where} line {n}"
        for rx in (_ALERTNAME_TEXT, _FIRING):
            m = rx.search(line)
            if m:
                out.add("alert", m.group(1), src)
        m = _EVENT_ROW.match(line)
        if m and (m.group(2) in EVENT_REASONS or (m.group(1) == "Warning" and m.group(2) not in ROUTINE_REASONS)):
            out.add("event_reason", m.group(2), src)
        if m:  # an `oc get events` row: the template is the message, after the object column
            rest = line[m.end() :].split(None, 1)
            if len(rest) == 2:
                line = rest[1]
        m = _CO_ROW.match(line)
        if m:
            _co_row(m, out, src)
        for rm in _REASON_FIELD.finditer(line):
            reason = rm.group(1)
            if reason in POD_REASONS:
                out.add("pod_reason", reason, src)
            elif reason in EVENT_REASONS:
                out.add("event_reason", reason, src)
        for word in _WORD.findall(line):
            if word in POD_REASONS and word not in STRUCTURED_ONLY:
                out.add("pod_reason", word, src)
            elif word in known_alerts:  # a catalogued alert name written in prose ("etcdNoLeader is firing")
                out.add("alert", word, src)
        _components(line, out, src)
        if out.templates < MAX_TEMPLATES and _ERRORISH.search(line):
            template, digest = normalise_error(line)
            if len(template.split()) >= MIN_TEMPLATE_WORDS:
                before = len(out.found)
                out.add("error_template", digest, src, template)
                out.templates += len(out.found) - before


def _co_row(m: re.Match[str], out: _Collector, src: str) -> None:
    """A row of ``oc get clusteroperators``: NAME VERSION AVAILABLE PROGRESSING DEGRADED SINCE MESSAGE."""
    name, available, _progressing, degraded, rest = m.groups()
    reason_match = _CAMEL_PREFIX.match(rest)
    suffix = f":{reason_match.group(1)}" if reason_match else ""
    if available == "False":
        out.add("co_condition", f"{name}/Available=False{suffix}", src)
    if degraded == "True":
        out.add("co_condition", f"{name}/Degraded=True{suffix}", src)
    if available == "False" or degraded == "True":
        out.add("component", name, src)
