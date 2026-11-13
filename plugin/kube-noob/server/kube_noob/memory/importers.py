"""``kube-noob memory import``: resolved tickets exported from ServiceNow or Jira become proposed memory entries.

Formats and the fields read (checked 2026-10-28):

- ``servicenow-json``: a Table API response (``{"result": [...]}``, or a bare list) of incident records. Values are
  strings, or ``{"value": ..., "display_value": ...}`` objects (``sysparm_display_value=all``) and reference objects
  with ``link``/``value``. Fields: ``number``, ``short_description``, ``description``, ``state``, ``close_code``,
  ``close_notes``, ``resolved_at``, ``closed_at``, ``work_notes``, ``comments``. States: 1 New, 2 In Progress,
  3 On Hold, 6 Resolved, 7 Closed, 8 Canceled (servicenow.itsm ``module_utils/incident.py``; display names accepted).
  Close codes differ between ServiceNow releases, so they are read by meaning: "Not Solved", "No resolution",
  "Duplicate", "User error" and "by caller" mean no fix; "Work Around"/"Workaround" means a partial fix.
  https://github.com/ansible-collections/servicenow.itsm/blob/main/plugins/module_utils/incident.py
- ``servicenow-csv``: a list export whose columns are those field names or their labels (Number, Short description,
  Description, State, Resolution code, Resolution notes, Resolved, Closed, Work notes, Additional comments).
- ``jira-json``: a REST search response (``{"issues": [{"key": ..., "fields": {...}}]}``, v2 strings or v3 ADF):
  ``summary``, ``description``, ``resolution.name``, ``resolutiondate``, ``status``, ``comment.comments[].body``.
  https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issue-search/
- ``jira-csv``: the issue navigator CSV export: Issue key, Summary, Description, Status, Resolution, Resolved, and one
  ``Comment`` column per comment, oldest first; a comment cell is ``date;author;body``.
  https://support.atlassian.com/jira/kb/how-to-export-issues-from-jira-cloud-in-csv-format/

Never kept: who was involved. Assignee, reporter, caller and "opened/resolved/closed by" fields are not read; emails,
account ids, @mentions, phone numbers and lines that name a person ("Assigned to: ...") are removed from the text;
credential-looking values are masked. A ticket is skipped, with the reason, when it has no resolution, was canceled
or closed without a fix, has no resolution notes, or its text still fails the entry's content rules.
"""

from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any

from kube_noob import sanitize

FORMATS = ("servicenow-json", "servicenow-csv", "jira-json", "jira-csv")
MAX_EXPORT = 50_000_000  # bytes
MAX_TICKETS = 20_000
MAX_FIELD = 50_000  # characters kept from one field
MAX_COMMENTS = 50

_PERSON_LINE = re.compile(
    r"(?im)^[ \t]*(assigned to|assignee|assignment group|caller|opened by|resolved by|closed by|reported by|reporter|"
    r"requested by|requested for|contact|on behalf of|watch list|created by|updated by)\b[ \t]*[:=].*$"
)
_JOURNAL = re.compile(
    r"(?m)^\d{4}-\d{2}-\d{2} \d{2}:\d{2}(:\d{2})? - .*\((Work notes|Additional comments|Comments)\)\s*$"
)
_BY_PERSON = re.compile(
    r"\b((?:[Rr]eported|[Oo]pened|[Rr]esolved|[Cc]losed|[Aa]ssigned|[Rr]equested|[Rr]aised|[Ee]scalated|[Ss]ubmitted"
    r"|[Cc]hecked|[Cc]onfirmed|[Ff]ixed) (?:by|with))\s+[A-Z][a-z]+(?:[ -][A-Z][a-z'-]+){0,2}"
)
_PHONE = re.compile(r"(?<![\w.])\+?\(?\d{1,4}\)?[ -]\d{2,4}[ -]\d{3,4}(?:[ -]\d{2,4})?(?!\w|\.\d)")
_SENTENCE = re.compile(r"(?<=[.!?;])\s+|\n+")
_MENTION = re.compile(r"(?<![\w@])@[A-Za-z][\w.-]{1,60}")
_ROOT_CAUSE = re.compile(r"(?i)\b(?:root cause|cause)\s*(?:was|is|:|-)\s*([^.\n]{8,400})")
_NO_FIX = re.compile(
    r"(?i)not solved|no resolution|duplicate|user error|by caller|cancel|won'?t|cannot reproduce|"
    r"not a bug|incomplete|declined|obsolete|rejected"
)
_WORKAROUND = re.compile(r"(?i)work ?around")
_SN_STATES = {"1": "open", "2": "open", "3": "open", "6": "resolved", "7": "closed", "8": "canceled"}
_SN_NAMES = {
    "new": "1",
    "in progress": "2",
    "on hold": "3",
    "resolved": "6",
    "closed": "7",
    "canceled": "8",
    "cancelled": "8",
}
_SN_COLUMNS = {
    "number": ("number",),
    "short_description": ("short_description", "short description"),
    "description": ("description",),
    "state": ("state", "incident state", "incident_state"),
    "close_code": ("close_code", "resolution code", "close code"),
    "close_notes": ("close_notes", "resolution notes", "close notes"),
    "resolved_at": ("resolved_at", "resolved"),
    "closed_at": ("closed_at", "closed"),
    "work_notes": ("work_notes", "work notes"),
    "comments": ("comments", "additional comments"),
    "opened_at": ("opened_at", "opened", "sys_created_on", "created"),
}
_JIRA_COLUMNS = {
    "key": ("issue key", "key"),
    "summary": ("summary",),
    "description": ("description",),
    "status": ("status",),
    "resolution": ("resolution",),
    "resolved": ("resolved", "resolution date", "resolutiondate"),
    "created": ("created",),
}


@dataclass(frozen=True)
class Ticket:
    ref: str
    title: str
    body: str
    notes: str
    resolution: str  # what was done, in the ticket's words
    outcome: str  # resolved | partial | none
    reason: str  # why there is no fix, when outcome is none
    resolved: date | None
    opened: date | None = None


class TicketImportError(ValueError):
    """The export cannot be read."""


def _value(v: Any) -> str:
    if isinstance(v, dict):
        v = v.get("display_value") if v.get("display_value") not in (None, "") else v.get("value")
    return str(v)[:MAX_FIELD] if isinstance(v, str | int | float) and not isinstance(v, bool) else ""


def _date(text: str) -> date | None:
    """ServiceNow ``2026-10-28 09:12:41``, Jira ``2026-10-28T09:12:41.000+0000`` or ``28/Oct/26 9:12 AM``."""
    text = text.strip()
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})", text)
    if m:
        try:
            return date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
        except ValueError:
            return None
    for fmt in (
        "%d/%b/%y %I:%M %p",
        "%d/%b/%y %H:%M",
        "%d/%b/%y",
        "%m/%d/%Y %I:%M:%S %p",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y",
    ):
        try:
            return datetime.strptime(text, fmt).date()
        except ValueError:
            continue
    return None


def _sn_ticket(rec: dict[str, Any]) -> Ticket:
    get = {k: _value(rec.get(k)) for k in _SN_COLUMNS}
    state_raw = get["state"].strip()
    state = _SN_STATES.get(state_raw) or _SN_STATES.get(_SN_NAMES.get(state_raw.lower(), ""), "open")
    code = get["close_code"]
    outcome, reason = "none", ""
    if state == "canceled":
        reason = "canceled"
    elif state == "open":
        reason = "no resolution (still open)"
    elif _NO_FIX.search(code):
        reason = f"closed without a fix ({code.strip()})"
    elif not get["close_notes"].strip():
        reason = "no resolution notes"
    else:
        outcome = "partial" if _WORKAROUND.search(code) else "resolved"
    when = _date(get["resolved_at"]) or _date(get["closed_at"])
    notes = "\n".join(x for x in (get["work_notes"], get["comments"]) if x)
    return Ticket(
        get["number"],
        get["short_description"],
        get["description"],
        notes,
        get["close_notes"],
        outcome,
        reason,
        when,
        _date(get["opened_at"]),
    )


def _jira_ticket(key: str, f: dict[str, Any]) -> Ticket:
    from kube_noob.sources.jira import adf_to_text

    resolution = (f.get("resolution") or {}).get("name", "") if isinstance(f.get("resolution"), dict) else ""
    comments = [c for c in ((f.get("comment") or {}).get("comments") or [])[-MAX_COMMENTS:] if isinstance(c, dict)]
    bodies = [adf_to_text(c.get("body"))[:MAX_FIELD] for c in comments]
    status = f.get("status") or {}
    done = isinstance(status, dict) and (status.get("statusCategory") or {}).get("key") == "done"
    return _jira_from(
        key,
        str(f.get("summary") or ""),
        adf_to_text(f.get("description"))[:MAX_FIELD],
        bodies,
        resolution,
        str(f.get("resolutiondate") or ""),
        done,
        str(f.get("created") or ""),
    )


def _jira_from(
    key: str,
    title: str,
    body: str,
    comments: list[str],
    resolution: str,
    resolved: str,
    done: bool,
    created: str = "",
) -> Ticket:
    outcome, reason = "none", ""
    if not resolution or resolution.lower() in {"unresolved", "none"}:
        reason = "no resolution (still open)" if not done else "no resolution"
    elif _NO_FIX.search(resolution):
        reason = f"closed without a fix ({resolution})"
    elif not comments:
        reason = "no resolution notes"
    else:
        outcome = "partial" if _WORKAROUND.search(resolution) else "resolved"
    last = comments[-1] if comments else ""
    return Ticket(key, title, body, "\n".join(comments[:-1]), last, outcome, reason, _date(resolved), _date(created))


def _columns(header: list[str], wanted: dict[str, tuple[str, ...]]) -> dict[str, int]:
    norm = [h.strip().lower() for h in header]
    out: dict[str, int] = {}
    for key, names in wanted.items():
        for name in names:
            if name in norm:
                out[key] = norm.index(name)
                break
    return out


def _csv_rows(text: str) -> tuple[list[str], list[list[str]]]:
    csv.field_size_limit(MAX_FIELD * 4)
    try:
        reader = csv.reader(io.StringIO(text))
        header = next(reader, [])
        rows: list[list[str]] = []
        for row in reader:
            if len(rows) >= MAX_TICKETS:
                break
            rows.append([c[:MAX_FIELD] for c in row])
    except csv.Error as exc:
        raise TicketImportError(f"the CSV cannot be read: {exc}") from None
    if not header:
        raise TicketImportError("the CSV is empty")
    return header, rows


def parse(fmt: str, text: str) -> list[Ticket]:
    """Tickets from an export. Raises ``TicketImportError`` when the export cannot be read."""
    if fmt not in FORMATS:
        raise TicketImportError(f"unknown format {fmt!r}; use one of {', '.join(FORMATS)}")
    if len(text.encode("utf-8", errors="replace")) > MAX_EXPORT:
        raise TicketImportError(
            f"the export is larger than {MAX_EXPORT // 1_000_000} MB; export fewer tickets at a time"
        )
    if fmt.endswith("json"):
        try:
            doc = sanitize.loads_bounded(text, sanitize.MAX_JSON_DEPTH_FILE)
        except sanitize.JsonTooDeep as exc:
            raise TicketImportError(f"the JSON cannot be read: it is {exc}") from None
        except (ValueError, RecursionError) as exc:
            raise TicketImportError(f"the JSON cannot be read: {str(exc)[:120]}") from None
        if fmt == "servicenow-json":
            records = doc.get("result") if isinstance(doc, dict) else doc
            if not isinstance(records, list):
                raise TicketImportError('a ServiceNow export is {"result": [...]} or a list of incident records')
            return [_sn_ticket(r) for r in records[:MAX_TICKETS] if isinstance(r, dict) and _value(r.get("number"))]
        issues = doc.get("issues") if isinstance(doc, dict) else doc
        if not isinstance(issues, list):
            raise TicketImportError('a Jira export is {"issues": [...]} from the search API')
        return [
            _jira_ticket(str(i["key"]), i.get("fields") or {})
            for i in issues[:MAX_TICKETS]
            if isinstance(i, dict) and isinstance(i.get("key"), str) and isinstance(i.get("fields") or {}, dict)
        ]
    header, rows = _csv_rows(text)
    if fmt == "servicenow-csv":
        cols = _columns(header, _SN_COLUMNS)
        if "number" not in cols or "short_description" not in cols:
            raise TicketImportError(
                "a ServiceNow CSV needs the number and short_description (or Short description) columns"
            )
        out = []
        for row in rows:
            rec = {k: row[i] for k, i in cols.items() if i < len(row)}
            if rec.get("number"):
                out.append(_sn_ticket(rec))
        return out
    cols = _columns(header, _JIRA_COLUMNS)
    if "key" not in cols or "summary" not in cols:
        raise TicketImportError("a Jira CSV needs the Issue key and Summary columns")
    comment_cols = [i for i, h in enumerate(header) if h.strip().lower() in {"comment", "comments"}][:MAX_COMMENTS]
    out = []
    for row in rows:

        def cell(name: str, row: list[str] = row) -> str:
            i = cols.get(name)
            return row[i] if i is not None and i < len(row) else ""

        comments = [_comment_body(row[i]) for i in comment_cols if i < len(row) and row[i].strip()]
        if cell("key"):
            out.append(
                _jira_from(
                    cell("key"),
                    cell("summary"),
                    cell("description"),
                    comments,
                    cell("resolution"),
                    cell("resolved"),
                    cell("status").lower() in {"done", "closed", "resolved"},
                    cell("created"),
                )
            )
    return out


def _comment_body(cell: str) -> str:
    parts = cell.split(";", 2)
    if len(parts) == 3 and (_date(parts[0]) or _date(parts[1])):
        return parts[2]
    return cell


# --------------------------------------------------------------------------------------------------- text


def clean(text: str) -> str:
    """The ticket's words without people, contact details, credentials, journal headers, logs or manifests."""
    from kube_noob.learn.memory import (
        _EVENT_ROW,
        _LOG_LINE,
        _MANIFEST_KEYS,
        _STACK,
        contains_credential,
        mask_credentials,
    )
    from kube_noob.sources.jira import scrub

    # A sentence that carries a credential is dropped whole: masking one pattern can hide the key word and leave the
    # value ("token: password is X" masks "password" and keeps X).
    text = "\n".join(part for part in _SENTENCE.split(text[:MAX_FIELD]) if part and not contains_credential(part))
    text = _PERSON_LINE.sub("", text)
    text = _JOURNAL.sub("", text)
    text = _BY_PERSON.sub(r"\1 someone", text)
    text = scrub(text)
    text = _MENTION.sub("someone", text)
    text = _PHONE.sub("<phone>", text)
    text, _ = mask_credentials(text)
    kept = []
    for line in text.splitlines():
        if _LOG_LINE.search(line) or _EVENT_ROW.search(line) or _STACK.search(line) or _MANIFEST_KEYS.search(line):
            continue
        kept.append(line.strip())
    return " ".join(" ".join(kept).replace("|", "/").split())


def _summary(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    cut = text[:limit]
    end = max(cut.rfind(". "), cut.rfind("; "))
    return (cut[: end + 1] if end > limit // 2 else cut.rsplit(" ", 1)[0]).strip()


# --------------------------------------------------------------------------------------------------- import


def import_tickets(
    root: Path,
    fmt: str,
    text: str,
    platform: str,
    owner: str,
    cluster: str | None = None,
    dry_run: bool = False,
    today: date | None = None,
) -> dict[str, Any]:
    """Proposed entries for the resolved tickets in an export; every other ticket is listed with the reason."""
    from pydantic import ValidationError

    from kube_noob.memory.model import MemoryEntry
    from kube_noob.memory.repo import _reason, add_entry, load_repo, next_number, require_repo
    from kube_noob.signals import for_text

    require_repo(root)
    seen: dict[str, str] = {}
    for item in load_repo(root):
        if item.entry:
            for o in item.entry.outcomes:
                if o.ticket:
                    seen[o.ticket] = item.entry.id
    created: list[dict[str, str]] = []
    skipped: list[dict[str, str]] = []
    day = today or date.today()
    preview_number = next_number(root)
    for t in parse(fmt, text):
        ref = re.sub(r"[^A-Za-z0-9._:/#-]", "-", t.ref.strip())[:100].strip("-") or "ticket"
        if t.outcome == "none":
            skipped.append({"ticket": ref, "reason": t.reason})
            continue
        if ref in seen:
            skipped.append({"ticket": ref, "reason": f"already imported as {seen[ref]}"})
            continue
        title, body, notes, resolution = clean(t.title), clean(t.body), clean(t.notes), clean(t.resolution)
        if not resolution:
            skipped.append({"ticket": ref, "reason": "no resolution notes left after removing logs and names"})
            continue
        cause_match = _ROOT_CAUSE.search(f"{resolution} {notes} {body}")
        found = for_text("\n".join((t.title, t.body, t.notes, t.resolution)))
        ranked = sorted(found, key=lambda s: (s.kind in {"component", "error_template"}, s.kind, s.name))
        fields: dict[str, Any] = {
            "kind": "fix",
            "signals": [{"kind": s.kind, "name": s.name} for s in ranked[:20]],
            "symptom": _summary(title or body or ref, 480),
            "platform": platform,
            "cause": _summary(
                cause_match.group(1).strip() if cause_match else f"Not stated in {ref}; see the fix.", 1900
            ),
            "fix": {"text": _summary(resolution, 1900)},
            "outcomes": [
                {
                    "date": t.resolved or day,
                    "result": t.outcome,
                    "ticket": ref,
                    **({"cluster": cluster} if cluster else {}),
                }
            ],
            "owners": [owner],
        }
        try:
            if dry_run:
                entry = MemoryEntry.model_validate(
                    {
                        **fields,
                        "id": f"MEM-{preview_number}",
                        "status": "proposed",
                        "created": min(t.resolved or day, day),
                        "updated": day,
                    }
                )
                preview_number += 1
            else:
                _, entry = add_entry(root, fields, day, created=t.resolved)
        except (ValidationError, ValueError) as exc:
            reason = _reason(exc) if isinstance(exc, ValidationError) else str(exc)
            skipped.append({"ticket": ref, "reason": f"text fails the entry rules: {reason}"[:300]})
            continue
        seen[ref] = entry.id
        created.append({"ticket": ref, "entry": entry.id, "outcome": t.outcome})
    return {"repository": str(root), "format": fmt, "dryRun": dry_run, "created": created, "skipped": skipped}
