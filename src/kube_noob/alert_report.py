"""An evidence report for an Alertmanager payload, alert by alert (moat item I1).

For every alert a payload carries: the signals it carries, the diagnosis the deterministic playbooks give, the
reported issues that match for the version the payload names, approved team memory when a memory repository is
configured, and read-only next steps. Each of those comes from the ``diagnose`` tool itself, called once per alert
with that alert alone (``kube_noob.toolkit.Toolkit.diagnose``), so the report is what the tools already answer and
not a second implementation of them.

Every section says what it could not determine and why. An alert kube-noob recognises nothing in is reported as
exactly that and kept, never dropped and never shown as healthy; a resolved alert is recorded as resolved and not
diagnosed as if it were firing; alerts and list items that could not be read are counted with the reason.

The body is deterministic: the same payload gives the same bytes (``canonical``). Ids, times and durations belong to
the receipt the HTTP receiver adds (``kube_noob.alert_store``), never to the body. The body is built from
third-party text -- an Alertmanager payload is whatever its senders put in labels and annotations -- so every string
in it is redacted for credential shapes and then cleaned by ``kube_noob.sanitize`` before it is returned or kept, and
it carries no URL, file name or command from the payload: next steps come from kube-noob's playbooks, with names
from the alert filled in only where they are shell-safe (``kube_noob.debug.diagnose``).

Nothing here reads a cluster, a file or the network, and nothing here writes: storing a report is the HTTP
receiver's job.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from kube_noob import sanitize
from kube_noob.debug.cluster import redact_text
from kube_noob.signals import alertmanager

FORMAT = "kube-noob/alert-report/v1"
VERDICTS = ("diagnosed", "no-playbook", "no-recognised-signal", "resolved")
#: States that mean the condition is over. ``inactive`` is Prometheus's word for it, ``resolved`` Alertmanager's.
NOT_FIRING = frozenset({"resolved", "inactive"})
SHOWN_LABELS = ("severity", "namespace", "pod", "container", "service", "instance", "node", "job")
MAX_SHOWN = 256  # characters of one label or summary kept in an alert's heading
MAX_STEPS = 8
MAX_PLAYBOOKS = 3
MAX_CAUSES = 3
DEFAULT_MAX_BYTES = 1_048_576
DETAIL_KEYS = ("signals", "diagnosis", "knownIssues", "memory", "nextSteps")

#: ``diagnose(text, version)`` -> the diagnose tool's result for one alert's payload.
Diagnose = Callable[[str, str | None], dict[str, Any]]

CAVEATS = (
    "Built from the payload and kube-noob's local knowledge only: no cluster, file or network was read, so the "
    "report says what the alert names point at, not what is true in the cluster now.",
    "Labels and annotations are text from whoever sent the payload: they are shown redacted and cleaned, and "
    "kube-noob acts on none of them.",
    "Next steps are read-only checks from kube-noob's playbooks. Commands that execute in a container or change the "
    "cluster are left out; `kube-noob diagnose` lists them, each needing approval.",
)


def _clip(value: str) -> str:
    return value if len(value) <= MAX_SHOWN else value[: MAX_SHOWN - 3] + "..."


def _recognised(signals: list[dict[str, Any]]) -> list[str]:
    """Catalogued ids among the signals: the names kube-noob has playbooks, phrases and sources for."""
    from kube_noob.signals.catalogue import get

    out: list[str] = []
    for s in signals:
        entry = get(str(s.get("kind", "")), str(s.get("name", "")))
        if entry is not None and entry.id not in out:
            out.append(entry.id)
    return out


def _heading(alert: alertmanager.Alert) -> dict[str, Any]:
    head: dict[str, Any] = {"index": alert.index, "alertname": alert.name, "state": alert.state}
    shown = {k: _clip(redact_text(alert.labels[k])) for k in SHOWN_LABELS if alert.labels.get(k)}
    if shown:
        head["labels"] = shown
    short = alert.annotations.get("summary") or alert.annotations.get("message")
    if short:
        head["summary"] = _clip(redact_text(short))
    if alert.starts_at:
        head["startsAt"] = alert.starts_at
    if alert.fingerprint:
        head["fingerprint"] = alert.fingerprint
    return head


def _not_evaluated(why: str) -> dict[str, Any]:
    return {"status": "not-evaluated", "note": why}


def _resolved(alert: alertmanager.Alert) -> dict[str, Any]:
    why = f"The alert is {alert.state}: recorded, not diagnosed, because a cleared condition is not a symptom."
    return {
        **_heading(alert),
        "verdict": "resolved",
        "verdictReason": why,
        **{k: _not_evaluated(why) for k in DETAIL_KEYS},
    }


def _signals_section(found: list[dict[str, Any]], recognised: list[str]) -> dict[str, Any]:
    items = [{"kind": s.get("kind"), "name": s.get("name")} for s in found]
    if not items:
        return {"status": "none", "items": [], "note": "No signal was read from this alert."}
    out: dict[str, Any] = {"status": "found", "items": items, "recognised": recognised}
    if not recognised:
        out["note"] = (
            "None of these names is in kube-noob's signal catalogue, so no playbook, reported issue or memory entry is "
            "keyed to them; matching falls back to the alert's words."
        )
    return out


def _diagnosis_section(out: dict[str, Any], recognised: list[str]) -> dict[str, Any]:
    playbooks = []
    for d in (out.get("diagnoses") or [])[:MAX_PLAYBOOKS]:
        entry: dict[str, Any] = {
            "id": d.get("id"),
            "title": d.get("title"),
            "confidence": d.get("confidence"),
            "evidence": list(d.get("evidence") or [])[:5],
        }
        if d.get("likelyCause"):
            entry["likelyCause"] = d["likelyCause"]
        entry["rootCauses"] = list(d.get("rootCauses") or [])[:MAX_CAUSES]
        playbooks.append(entry)
    section: dict[str, Any] = {"status": "found" if playbooks or out.get("cephHealth") else "none"}
    section["playbooks"] = playbooks
    if out.get("cephHealth"):
        section["cephHealth"] = out["cephHealth"]
    if section["status"] == "none":
        if recognised:
            section["note"] = (
                f"kube-noob recognises {', '.join(recognised)} but has no playbook for it, and no playbook pattern "
                "matched the alert's text. No diagnosis is not a sign the alert is benign."
            )
        else:
            section["note"] = (
                "No catalogued signal and no playbook pattern matched: kube-noob has no deterministic diagnosis for "
                "this alert. No diagnosis is not a sign the alert is benign."
            )
    return section


def _known_issues_section(out: dict[str, Any], version: str | None, version_from: str | None) -> dict[str, Any]:
    matches = list(out.get("knownIssues") or [])
    section: dict[str, Any] = {"status": "found" if matches else "none", "matches": matches, "version": version}
    if version:
        section["note"] = f"Narrowed to OpenShift {version} ({version_from}): issues fixed before it are left out."
    else:
        section["note"] = (
            "No OpenShift release label (openshift_version or version) on the alert or the payload: matches are not "
            "narrowed to a version, so an issue already fixed in your release can be listed and its status cannot "
            "say whether you have the fix."
        )
    if not matches:
        section["note"] += " No reported issue in kube-noob's local copy matched this alert's name and summary."
    return section


def _memory_section(out: dict[str, Any], memory_configured: bool) -> dict[str, Any]:
    if not memory_configured:
        return _not_evaluated("No team memory repository is configured (memory.paths): no past fix was searched.")
    matches = list(out.get("memory") or [])
    section: dict[str, Any] = {"status": "found" if matches else "none", "matches": matches}
    if out.get("memoryNotes"):
        section["notes"] = list(out["memoryNotes"])
    if not matches:
        section["note"] = "No approved entry in the configured memory matched this alert."
    return section


def _steps_section(out: dict[str, Any]) -> dict[str, Any]:
    steps: list[dict[str, Any]] = []
    seen: set[str] = set()
    for d in out.get("diagnoses") or []:
        for step in d.get("readOnlyNextSteps") or []:
            key = str(step.get("command") or step.get("instruction") or "")
            if key and key not in seen:
                seen.add(key)
                steps.append(step)
    steps = steps[:MAX_STEPS]
    if steps:
        return {"status": "found", "readOnly": steps}
    return {
        "status": "none",
        "readOnly": [],
        "note": "No playbook matched, so kube-noob has no read-only step to offer for this alert.",
    }


def _diagnosed(alert: alertmanager.Alert, out: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
    found = [s for s in out.get("signals") or [] if isinstance(s, dict)]
    recognised = _recognised(found)
    diagnosis = _diagnosis_section(out, recognised)
    if diagnosis["status"] == "found":
        verdict, why = "diagnosed", "A playbook matched the alert's signals or text."
    elif recognised:
        verdict, why = "no-playbook", "kube-noob recognises the alert but has no playbook that applies."
    else:
        verdict, why = (
            "no-recognised-signal",
            "kube-noob recognises nothing in this alert. It is kept in the report, and it is not a sign of health.",
        )
    return {
        **_heading(alert),
        "verdict": verdict,
        "verdictReason": why,
        "signals": _signals_section(found, recognised),
        "diagnosis": diagnosis,
        "knownIssues": _known_issues_section(out, ctx["version"], ctx["versionFrom"]),
        "memory": _memory_section(out, ctx["memory"]),
        "nextSteps": _steps_section(out),
    }


def canonical(body: dict[str, Any]) -> bytes:
    """The bytes a body is compared, hashed and stored as: sorted keys, no whitespace."""
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _bound(body: dict[str, Any], max_bytes: int) -> dict[str, Any]:
    """Keep the body under ``max_bytes``: detail goes from the last alerts first, then (only if the headings alone
    are too large) the last headings, and either is counted in ``notIncluded``. Nothing goes without being said."""
    if len(canonical(body)) <= max_bytes:
        return body
    alerts = body["alerts"]
    stripped = 0
    for i in range(len(alerts) - 1, -1, -1):
        alerts[i] = {
            **{k: v for k, v in alerts[i].items() if k not in DETAIL_KEYS},
            "detail": "omitted: the report reached its size limit (alertReports.maxReportBytes)",
        }
        stripped += 1
        if len(canonical(body)) <= max_bytes:
            break
    body["notIncluded"].append(
        {"what": "alert detail (sections)", "count": stripped, "why": "the report reached its size limit"}
    )
    dropped = 0
    while alerts and len(canonical(body)) > max_bytes:
        alerts.pop()
        dropped += 1
    if dropped:
        body["notIncluded"].append(
            {"what": "alerts (heading too)", "count": dropped, "why": "the report reached its size limit"}
        )
    return body


def build(
    text: str, diagnose: Diagnose, *, memory_configured: bool, max_bytes: int = DEFAULT_MAX_BYTES
) -> dict[str, Any]:
    """The report body for an Alertmanager payload. Raises ValueError when ``text`` is not one."""
    split = alertmanager.split(text)
    if split is None:
        raise ValueError(
            "not an Alertmanager payload: expected the webhook body (alerts[] with labels.alertname), the API's alert "
            "list, or Prometheus's /api/v1/alerts, as JSON of at most 2 MB"
        )
    payload = split.payload
    ctx = {"version": payload.version, "versionFrom": payload.version_from, "memory": memory_configured}
    memo: dict[str, dict[str, Any]] = {}
    alerts: list[dict[str, Any]] = []
    for alert in split.alerts:
        if alert.state in NOT_FIRING:
            alerts.append(_resolved(alert))
            continue
        one = alert.payload()
        # Two alerts with the same labels and annotations get the same diagnosis: computed once.
        if one not in memo:
            memo[one] = diagnose(one, payload.version)
        alerts.append(_diagnosed(alert, memo[one], ctx))
    by_verdict = {v: sum(1 for a in alerts if a["verdict"] == v) for v in VERDICTS}
    by_state: dict[str, int] = {}
    for a in alerts:
        by_state[a["state"]] = by_state.get(a["state"], 0) + 1
    caveats = list(CAVEATS)
    if not payload.version:
        caveats.append(
            "The payload names no OpenShift release (an openshift_version or version label such as 4.21.3), so no "
            "known-issue match is narrowed to a version."
        )
    if not memory_configured:
        caveats.append("No team memory repository is configured, so no team fix was searched.")
    body: dict[str, Any] = {
        "format": FORMAT,
        "summary": {
            "alerts": len(alerts),
            "byVerdict": by_verdict,
            "byState": dict(sorted(by_state.items())),
            "alertnames": sorted({a["alertname"] for a in alerts}),
            "version": payload.version,
            "versionFrom": payload.version_from,
        },
        "notIncluded": [
            {"what": "items of the alert list", "count": n, "why": why} for why, n in sorted(split.not_read.items())
        ],
        "caveats": caveats,
        "alerts": alerts,
    }
    # Third-party text: redacted above where it is copied, and cleaned here as a whole, so a stored report is already
    # what a caller may see. Cleaning first and bounding second means the size is the size of what is kept.
    cleaned: dict[str, Any] = sanitize.result(body)
    return _bound(cleaned, max_bytes)


def render_text(body: dict[str, Any], receipt: dict[str, Any] | None = None) -> str:
    """The report for a terminal: the summary, what was not read, the caveats, then each alert."""
    s = body.get("summary") or {}
    lines = [f"Alert evidence report: {s.get('alerts', 0)} alert(s)"]
    if receipt:
        stored = "stored" if receipt.get("stored") else f"not stored ({receipt.get('notStoredReason', '')})"
        lines.append(f"id {receipt.get('id', '-')}, received {receipt.get('receivedAt', '-')}, {stored}")
        if "durationSeconds" in receipt:
            lines.append(f"receipt to report: {receipt['durationSeconds']:.3f}s")
    counts = ", ".join(f"{k} {v}" for k, v in (s.get("byVerdict") or {}).items())
    lines.append(f"verdicts: {counts}")
    version = s.get("version")
    lines.append(f"version: {version} ({s.get('versionFrom')})" if version else "version: not named by the payload")
    for item in body.get("notIncluded") or []:
        lines.append(f"not included: {item['count']} {item['what']} ({item['why']})")
    if body.get("untrusted"):
        lines.append(f"untrusted text neutralised: {len(body.get('injectionSignals') or [])} signal(s)")
    lines.append("caveats:")
    lines += [f"  - {c}" for c in body.get("caveats") or []]
    for a in body.get("alerts") or []:
        lines.append("")
        labels = a.get("labels") or {}
        where = ", ".join(f"{k} {v}" for k, v in labels.items())
        lines.append(f"[{a.get('index')}] {a.get('alertname')} {a.get('state')}" + (f" ({where})" if where else ""))
        if a.get("summary"):
            lines.append(f"    {a['summary']}")
        lines.append(f"    verdict: {a.get('verdict')}: {a.get('verdictReason')}")
        if a.get("detail"):
            lines.append(f"    {a['detail']}")
            continue
        if a.get("verdict") == "resolved":
            continue
        sig = a.get("signals") or {}
        names = ", ".join(f"{x['kind']}:{x['name']}" for x in sig.get("items") or [])
        lines.append(f"    signals: {names or 'none'}")
        for name in DETAIL_KEYS:
            section = a.get(name) or {}
            if section.get("note"):
                lines.append(f"    {name}: {section.get('status')}: {section['note']}")
        for p in (a.get("diagnosis") or {}).get("playbooks") or []:
            lines.append(f"    playbook {p['id']} ({p['confidence']}): {p['title']}")
            if p.get("likelyCause"):
                lines.append(f"      likely cause: {p['likelyCause']}")
        for m in (a.get("knownIssues") or {}).get("matches") or []:
            lines.append(f"    known issue {m.get('id')}: {m.get('status') or m.get('summary') or ''}")
        for m in (a.get("memory") or {}).get("matches") or []:
            lines.append(f"    memory {m.get('citation') or m.get('id')}: {m.get('symptom') or ''}")
        for st in (a.get("nextSteps") or {}).get("readOnly") or []:
            lines.append(f"    read-only: {st.get('command') or st.get('instruction')}")
    return "\n".join(lines)
