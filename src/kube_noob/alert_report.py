"""An evidence report for an Alertmanager payload, alert by alert (moat item I1).

For every alert a payload carries: the signals it carries, the diagnosis the deterministic playbooks give, the
reported issues that match for the release that alert's labels name, approved team memory when a memory repository
is configured, and read-only next steps. Each of those comes from the ``diagnose`` tool itself, called once per alert
with that alert alone (``kube_noob.toolkit.Toolkit.diagnose``), so the report is what the tools already answer and
not a second implementation of them.

Every section says what it could not determine and why. An alert kube-noob recognises nothing in is reported as
exactly that and kept, never dropped and never shown as healthy; a resolved alert is recorded as resolved and not
diagnosed as if it were firing; an alert whose diagnosis failed, or that the time budget did not reach, keeps its row
as ``not-evaluated``; list items that could not be read are counted with the reason.

The body is deterministic for a payload reported within its time budget: the same payload gives the same bytes
(``canonical``). Ids, times and durations belong to the receipt the HTTP receiver adds (``kube_noob.alert_store``),
never to the body. The body is built from third-party text -- an Alertmanager payload is whatever its senders put in
labels and annotations -- so every label and annotation value is redacted for credential shapes before it is
clipped, has its URLs (``scheme://...``) replaced by ``[url removed]``, and the whole body is then cleaned by
``kube_noob.sanitize``. Next steps come from kube-noob's playbooks, with names filled in only from the alert's own
labels and only where they are valid Kubernetes names (``alertmanager.label_context``).

Nothing here reads a cluster, a file or the network, and nothing here writes: storing a report is the HTTP
receiver's job.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable
from typing import Any

from kube_noob import sanitize
from kube_noob.debug.cluster import redact_text
from kube_noob.signals import alertmanager

FORMAT = "kube-noob/alert-report/v1"
VERDICTS = ("diagnosed", "no-playbook", "no-recognised-signal", "resolved", "not-evaluated")
#: States that mean the condition is over. ``inactive`` is Prometheus's word for it, ``resolved`` Alertmanager's.
NOT_FIRING = frozenset({"resolved", "inactive"})
SHOWN_LABELS = ("severity", "namespace", "pod", "container", "service", "instance", "node", "job")
MAX_SHOWN = 256  # characters of one label or summary kept in an alert's heading
MAX_ROW_NAME = 128  # an alertname is at most 128 characters (alertmanager._NAME)
MAX_STEPS = 8
MAX_PLAYBOOKS = 3
MAX_CAUSES = 3
DEFAULT_MAX_BYTES = 1_048_576
DETAIL_KEYS = ("signals", "diagnosis", "knownIssues", "memory", "nextSteps")
#: What a row keeps when the size cap takes its detail: enough to see that the alert exists and what became of it.
MINIMAL_KEYS = ("index", "alertname", "state", "severity", "verdict")
URL = re.compile(r"(?i)\b[a-z][a-z0-9+.-]{1,15}://[^\s\"'<>]+")
URL_REMOVED = "[url removed]"

#: ``diagnose(text, version)`` -> the diagnose tool's result for one alert's payload.
Diagnose = Callable[[str, str | None], dict[str, Any]]
#: Monotonic seconds; a module attribute so a test can drive the time budget deterministically.
_now: Callable[[], float] = time.monotonic

CAVEATS = (
    "Built from the payload and kube-noob's local knowledge only: no cluster, file or network was read, so the "
    "report says what the alert names point at, not what is true in the cluster now.",
    "Labels and annotations are text from whoever sent the payload: they are shown redacted, with URLs removed and "
    "cleaned, and kube-noob acts on none of them. Names in next steps come only from the alert's own labels.",
    "Next steps are read-only checks from kube-noob's playbooks. Commands that execute in a container or change the "
    "cluster are left out; `kube-noob diagnose` lists them, each needing approval.",
)


def scrub(value: str) -> str:
    """A label or annotation value as a report may keep it: credential shapes redacted, then URLs removed."""
    return URL.sub(URL_REMOVED, redact_text(value))


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
    # Values were redacted and stripped of URLs by `scrub` before they were clipped (alertmanager.split).
    head: dict[str, Any] = {"index": alert.index, "alertname": alert.name, "state": alert.state}
    shown = {k: _clip(alert.labels[k]) for k in SHOWN_LABELS if alert.labels.get(k)}
    if shown:
        head["labels"] = shown
    short = alert.annotations.get("summary") or alert.annotations.get("message")
    if short:
        head["summary"] = _clip(short)
    if alert.starts_at:
        head["startsAt"] = alert.starts_at
    if alert.fingerprint:
        head["fingerprint"] = alert.fingerprint
    return head


def _not_evaluated(why: str) -> dict[str, Any]:
    return {"status": "not-evaluated", "note": why}


def _unevaluated_row(alert: alertmanager.Alert, verdict: str, why: str) -> dict[str, Any]:
    return {
        **_heading(alert),
        "verdict": verdict,
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


def _vkey(version: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"[0-9]+", version)[:3])


def _minor(version: str) -> str:
    return ".".join(version.split(".")[:2])


def _known_issues_section(
    out: dict[str, Any], alert: alertmanager.Alert, coverage: dict[str, str] | None
) -> dict[str, Any]:
    version, version_from = alert.version, alert.version_from
    matches = list(out.get("knownIssues") or [])
    section: dict[str, Any] = {"status": "found" if matches else "none", "matches": matches, "version": version}
    covered = ", ".join(sorted(coverage or {}, key=_vkey)) or "none"
    if version and coverage is not None and _minor(version) not in coverage:
        # The local issues are for the releases the index holds; for another one an empty list proves nothing.
        return {
            "status": "not-evaluated",
            "matches": [],
            "version": version,
            "note": f"OpenShift {version} ({version_from}) is outside the releases kube-noob's local reported issues "
            f"cover ({covered}), so no match was looked for and none is implied.",
        }
    if version and coverage is not None and _vkey(version) > _vkey(coverage[_minor(version)]):
        newest = coverage[_minor(version)]
        note = (
            f"OpenShift {version} ({version_from}) is newer than the newest {_minor(version)} release kube-noob's "
            f"local reported issues cover ({newest}; releases covered: {covered}): issues reported after it are "
            "unknown here."
        )
        if not matches:
            return {"status": "not-evaluated", "matches": [], "version": version, "note": note}
        section["note"] = note
        return section
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
    unreadable = len(out.get("memoryNotes") or [])
    section: dict[str, Any] = {"status": "found" if matches else "none", "matches": matches}
    if unreadable:
        # The notes name the server's own paths; the count and the setting are what a reader of a report needs.
        why = (
            f"{unreadable} configured memory repository(ies) could not be read (see memory.paths and "
            "`kube-noob memory validate` on the server)"
        )
        if not matches:
            return _not_evaluated(why + ": nothing was searched there, so no match is implied.")
        section["note"] = why + "."
        return section
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


def _diagnosed(
    alert: alertmanager.Alert,
    out: dict[str, Any],
    memory_configured: bool,
    coverage: dict[str, str] | None,
) -> dict[str, Any]:
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
        "knownIssues": _known_issues_section(out, alert, coverage),
        "memory": _memory_section(out, memory_configured),
        "nextSteps": _steps_section(out),
    }


def canonical(body: dict[str, Any]) -> bytes:
    """The bytes a body is compared, hashed and stored as: sorted keys, no whitespace."""
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


_SEVERITY_RANK = {
    "critical": 4,
    "error": 4,
    "high": 4,
    "page": 4,
    "warning": 2,
    "warn": 2,
    "medium": 2,
    "info": 1,
    "informational": 1,
    "low": 1,
    "none": 1,
}


def _keep_rank(row: dict[str, Any]) -> tuple[int, int]:
    """How much a row's detail is worth keeping: a resolved alert least, then by severity. An unrecognised or missing
    severity ranks with critical, because an unknown is not a reason to drop something first. Ties keep the earlier
    alert, so the order is deterministic and never position alone."""
    if row.get("state") in NOT_FIRING:
        return (0, -int(row.get("index", 0)))
    severity = str((row.get("labels") or {}).get("severity", "")).lower()
    return (_SEVERITY_RANK.get(severity, 3), -int(row.get("index", 0)))


def _minimal(row: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {k: row[k] for k in ("index", "alertname", "state", "verdict") if k in row}
    severity = (row.get("labels") or {}).get("severity")
    if severity:
        out["severity"] = str(severity)[:32]
    out["detail"] = "omitted: the report reached its size limit (alertReports.maxReportBytes)"
    return out


def _bound(body: dict[str, Any], max_bytes: int) -> dict[str, Any]:
    """Keep the body under ``max_bytes`` without losing an alert: the least important rows (resolved, then the lowest
    severity, then the later alert) lose their sections first, keeping their heading; if that is not enough, the
    same order loses the heading down to ``{index, alertname, state, severity, verdict}``. Every alert keeps a row,
    the summary is computed before any of this, and the indices that lost detail are named in ``notIncluded``."""
    if len(canonical(body)) <= max_bytes:
        return body
    alerts: list[dict[str, Any]] = body["alerts"]
    order = sorted(range(len(alerts)), key=lambda i: _keep_rank(alerts[i]))
    # Tier by tier, least important first: a tier's rows lose their sections, then their headings, before any row of
    # a more important tier loses anything -- so a critical alert keeps its detail while an info alert has a heading.
    tiers: dict[int, list[int]] = {}
    for i in order:
        tiers.setdefault(_keep_rank(alerts[i])[0], []).append(i)
    ops = [(step, i) for rank in sorted(tiers) for step in ("sections", "heading") for i in tiers[rank]]
    size = len(canonical(body))
    # Room for the two notIncluded entries that name the indices: up to six characters an index, twice, and words.
    target = max_bytes - (14 * len(alerts) + 600)
    stripped: list[int] = []
    minimal: list[int] = []
    for step, i in ops:
        if size <= target:
            break
        before = len(canonical(alerts[i]))
        if step == "sections":
            alerts[i] = {
                **{k: v for k, v in alerts[i].items() if k not in DETAIL_KEYS},
                "detail": "omitted: the report reached its size limit (alertReports.maxReportBytes)",
            }
            stripped.append(alerts[i]["index"])
        else:
            alerts[i] = _minimal(alerts[i])
            minimal.append(alerts[i]["index"])
        size += len(canonical(alerts[i])) - before
    if stripped:
        body["notIncluded"].append(
            {
                "what": "alert detail (sections)",
                "count": len(stripped),
                "why": "the report reached its size limit; resolved and lower-severity alerts lost detail first",
                "indices": sorted(stripped),
            }
        )
    if minimal:
        body["notIncluded"].append(
            {
                "what": "alert detail (labels and summary too)",
                "count": len(minimal),
                "why": "the report reached its size limit; each of these keeps its name, state and verdict",
                "indices": sorted(minimal),
            }
        )
    return body


def build(
    text: str,
    diagnose: Diagnose,
    *,
    memory_configured: bool,
    max_bytes: int = DEFAULT_MAX_BYTES,
    deadline: float | None = None,
    coverage: dict[str, str] | None = None,
) -> dict[str, Any]:
    """The report body for an Alertmanager payload. Raises ValueError when ``text`` is not one.

    ``deadline`` is a ``_now()`` value: alerts not started by then are kept as ``not-evaluated`` rows and counted,
    so one payload cannot hold the server for longer than its budget. ``coverage`` maps each OpenShift minor the
    local reported issues cover to the newest release in it; a version outside it is reported as not evaluated."""
    split = alertmanager.split(text, scrub)
    if split is None:
        raise ValueError(
            "not an Alertmanager payload: expected the webhook body (alerts[] with labels.alertname), the API's alert "
            "list, or Prometheus's /api/v1/alerts, as JSON of at most 2,000,000 characters (the HTTP server takes "
            "at most 1.5 MiB)"
        )
    memo: dict[tuple[str, str | None], dict[str, Any]] = {}
    alerts: list[dict[str, Any]] = []
    out_of_time: list[int] = []
    failed: dict[str, list[int]] = {}
    for alert in split.alerts:
        if alert.state in NOT_FIRING:
            why = f"The alert is {alert.state}: recorded, not diagnosed, because a cleared condition is not a symptom."
            alerts.append(_unevaluated_row(alert, "resolved", why))
            continue
        if deadline is not None and _now() >= deadline:
            out_of_time.append(alert.index)
            why = "Not evaluated: the report's time budget (alertReports.budgetSeconds) ran out before this alert."
            alerts.append(_unevaluated_row(alert, "not-evaluated", why))
            continue
        key = (alert.payload(), alert.version)
        try:
            # Two alerts with the same labels and annotations get the same diagnosis: computed once.
            if key not in memo:
                memo[key] = diagnose(*key)
        except Exception as exc:  # noqa: BLE001 - one alert that cannot be diagnosed must not sink the group
            # The class name only: a message can quote the payload, and the payload is somebody else's text.
            failed.setdefault(type(exc).__name__, []).append(alert.index)
            why = f"Not evaluated: its diagnosis failed ({type(exc).__name__})."
            alerts.append(_unevaluated_row(alert, "not-evaluated", why))
            continue
        alerts.append(_diagnosed(alert, memo[key], memory_configured, coverage))
    by_verdict = {v: sum(1 for a in alerts if a["verdict"] == v) for v in VERDICTS}
    by_state: dict[str, int] = {}
    for a in alerts:
        by_state[a["state"]] = by_state.get(a["state"], 0) + 1
    not_included: list[dict[str, Any]] = [
        {"what": "items of the alert list", "count": n, "why": why} for why, n in sorted(split.not_read.items())
    ]
    if out_of_time:
        not_included.append(
            {
                "what": "alerts not evaluated",
                "count": len(out_of_time),
                "why": "the report's time budget (alertReports.budgetSeconds) ran out; each keeps its row",
                "indices": out_of_time,
            }
        )
    for name, indices in sorted(failed.items()):
        not_included.append(
            {
                "what": "alerts not evaluated",
                "count": len(indices),
                "why": f"their diagnosis failed ({name}); each keeps its row",
                "indices": indices,
            }
        )
    versions = sorted({a.version for a in split.alerts if a.version}, key=_vkey)
    caveats = list(CAVEATS)
    if not versions:
        caveats.append(
            "The payload names no OpenShift release (an openshift_version or version label such as 4.21.3), so no "
            "known-issue match is narrowed to a version."
        )
    elif len(versions) > 1:
        caveats.append(
            f"The alerts name different OpenShift releases ({', '.join(versions)}): each is read for its own."
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
            "versions": versions,
            # One release for the whole payload when every alert that names one names the same; otherwise None and
            # each alert's knownIssues.version says which release it was read for.
            "version": versions[0] if len(versions) == 1 else None,
            "versionFrom": next((a.version_from for a in split.alerts if a.version), None)
            if len(versions) == 1
            else None,
        },
        "notIncluded": not_included,
        "caveats": caveats,
        "alerts": alerts,
    }
    # Third-party text: redacted and stripped of URLs where it was read, and cleaned here as a whole, so a stored
    # report is already what a caller may see. Cleaning first and bounding second means the size is what is kept.
    cleaned: dict[str, Any] = sanitize.result(body)
    return _bound(cleaned, max_bytes)


def _str(value: Any) -> str:
    """A value from a body for a terminal: one line, visible characters only."""
    return " ".join(sanitize.clean(str(value))[0].split()) if value is not None else ""


def _d(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _l(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def render_text(body: dict[str, Any], receipt: dict[str, Any] | None = None) -> str:
    """The report for a terminal: the summary, what was not included, the caveats, then each alert. Every field is
    read with its type checked, so a body read back from disk in an unexpected shape prints what it can rather than
    raising (the CLI's only other outcome would be a traceback and exit 1)."""
    s = _d(body.get("summary"))
    lines = [f"Alert evidence report: {_str(s.get('alerts', 0))} alert(s)"]
    if receipt:
        if receipt.get("stored") is True:
            stored = "stored"
        else:
            stored = f"not stored ({_str(receipt.get('notStoredReason', ''))})"
        lines.append(f"id {_str(receipt.get('id', '-'))}, received {_str(receipt.get('receivedAt', '-'))}, {stored}")
        seconds = receipt.get("durationSeconds")
        if isinstance(seconds, int | float) and not isinstance(seconds, bool):
            lines.append(f"receipt to report: {seconds:.3f}s")
    counts = ", ".join(f"{_str(k)} {_str(v)}" for k, v in _d(s.get("byVerdict")).items())
    lines.append(f"verdicts: {counts}")
    versions = _l(s.get("versions"))
    lines.append(
        f"versions: {', '.join(_str(v) for v in versions)}" if versions else "version: not named by the payload"
    )
    for item in map(_d, _l(body.get("notIncluded"))):
        indices = _l(item.get("indices"))
        where = f" [alerts {', '.join(_str(i) for i in indices)}]" if indices else ""
        lines.append(
            f"not included: {_str(item.get('count'))} {_str(item.get('what'))} ({_str(item.get('why'))}){where}"
        )
    if body.get("untrusted"):
        lines.append(f"untrusted text neutralised: {len(_l(body.get('injectionSignals')))} signal(s)")
    lines.append("caveats:")
    lines += [f"  - {_str(c)}" for c in _l(body.get("caveats"))]
    for a in map(_d, _l(body.get("alerts"))):
        lines.append("")
        where = ", ".join(f"{_str(k)} {_str(v)}" for k, v in _d(a.get("labels")).items())
        head = f"[{_str(a.get('index'))}] {_str(a.get('alertname'))} {_str(a.get('state'))}"
        lines.append(head + (f" ({where})" if where else ""))
        if a.get("summary"):
            lines.append(f"    {_str(a['summary'])}")
        lines.append(f"    verdict: {_str(a.get('verdict'))}: {_str(a.get('verdictReason'))}")
        if a.get("detail"):
            lines.append(f"    {_str(a['detail'])}")
            continue
        if a.get("verdict") in {"resolved", "not-evaluated"}:
            continue
        names = ", ".join(
            f"{_str(_d(x).get('kind'))}:{_str(_d(x).get('name'))}" for x in _l(_d(a.get("signals")).get("items"))
        )
        lines.append(f"    signals: {names or 'none'}")
        for name in DETAIL_KEYS:
            section = _d(a.get(name))
            if section.get("note"):
                lines.append(f"    {name}: {_str(section.get('status'))}: {_str(section['note'])}")
            for note in _l(section.get("notes")):
                lines.append(f"    {name} note: {_str(note)}")
        for p in map(_d, _l(_d(a.get("diagnosis")).get("playbooks"))):
            lines.append(f"    playbook {_str(p.get('id'))} ({_str(p.get('confidence'))}): {_str(p.get('title'))}")
            if p.get("likelyCause"):
                lines.append(f"      likely cause: {_str(p['likelyCause'])}")
        for m in map(_d, _l(_d(a.get("knownIssues")).get("matches"))):
            lines.append(f"    known issue {_str(m.get('id'))}: {_str(m.get('status') or m.get('summary') or '')}")
        for m in map(_d, _l(_d(a.get("memory")).get("matches"))):
            lines.append(f"    memory {_str(m.get('citation') or m.get('id'))}: {_str(m.get('symptom') or '')}")
        for st in map(_d, _l(_d(a.get("nextSteps")).get("readOnly"))):
            lines.append(f"    read-only: {_str(st.get('command') or st.get('instruction'))}")
    return "\n".join(lines)
