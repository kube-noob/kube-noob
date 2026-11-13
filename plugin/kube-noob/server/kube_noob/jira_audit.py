"""``kube-noob corpus jira-audit``: what the local Red Hat Jira copy holds, and whether it keeps any people.

Per project: tickets, verdicts and status categories, how many tickets carry comments, how many comments are kept
against the totals Jira reported (and which tickets miss some), tickets cut at the size cap, tickets still in the
older text format that the next syncs refetch, the oldest and newest update, the key range and its coverage, the
shard's size, and the sync state. Then what the anonymiser replaced (emails, phone numbers, account ids, mentions,
commenter labels) and a self-check that looks for anything person-shaped left in the text. Local and offline:
it reads the shards and the sync state only.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

MAX_LINE = 2_000_000  # bytes: a record line longer than this is counted as malformed, not parsed
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
# The bare forms, with no `[~...]` or `accountId:` in front of them. Shared with `sources.jira`'s scrubber, which
# must be at least as strong as this audit: this one gates the weekly refresh, so anything it flags and the
# scrubber misses fails the run every week instead of being redacted.
BARE_ACCOUNT_ID = r"\b(?:5[0-9a-f]{23}|[0-9]{6}:[0-9a-f-]{36}|712020:[0-9a-f-]{20,})\b"
_ACCOUNT_ID = re.compile(BARE_ACCOUNT_ID)
_PROFILE = re.compile(r"https?://[^\s/]+/(?:jira/)?people/|ViewProfile\.jspa\?name=", re.IGNORECASE)
_COMMENTER = re.compile(r"\bby (Commenter [A-Z]{1,3})\b")
PLACEHOLDERS = ("<email>", "<phone>", "<account>", "@user")


def redacted_shape(matched: str) -> str:
    """The form of a match with none of its content: ``A9 at A9.A9`` for ``alice1 at example1.com``.

    The gate refuses a copy and names the ticket and the kind, which is not enough to tell a real leak from a
    false positive -- a 24-character hex digest fragment and an Atlassian account id match the same pattern.
    Printing the match itself would write personal data into a public CI log, which is worse than an unactionable
    failure. So each run of letters becomes ``A``, each run of digits ``9``, and the separators that carry the
    structure (``at``, ``dot``, punctuation) are kept. Capped so a report stays readable.
    """
    out: list[str] = []
    for token in re.split(r"(\s+)", matched.strip()):
        if not token or token.isspace():
            out.append(" ")
            continue
        if token.lower() in {"at", "dot"}:  # the words that make a spelled-out email what it is
            out.append(token.lower())
            continue
        piece = re.sub(r"[0-9]+", "9", re.sub(r"[A-Za-z]+", "A", token))
        out.append(piece)
    shape = "".join(out).strip()
    return shape if len(shape) <= 80 else shape[:77] + "..."


def _person_shapes(body: str) -> list[str]:
    """Kinds of person-shaped text left in a stored record: the anonymiser's own patterns, run again, plus account
    ids and Jira profile paths. Anything the anonymiser would still change is a leak.

    Each kind is returned as ``"<kind> <shape>"``, the shape being :func:`redacted_shape` of what matched, so a
    reviewer can act on a failure without decrypting the copy and without the log carrying anyone's details.
    """
    from kube_noob.sources import jira

    kinds: list[str] = []
    shapes: dict[str, str] = {}
    for rx, kind in (
        (_EMAIL, "email"),
        (jira._EMAIL_LOCAL, "email"),
        (jira._EMAIL_SPELLED, "spelled-out email"),
        (_ACCOUNT_ID, "account id"),
        (_PROFILE, "profile link"),
        (jira._PROFILE_URL, "profile link"),
        (jira._PHONE_INTL, "phone"),
        (jira._HANDLE, "handle"),
        (jira._QUOTE_HEADER, "quoted reply name"),
    ):
        m = rx.search(body)
        if m and not (kind == "phone" and sum(c.isdigit() for c in m.group(0)) < 8) and kind not in kinds:
            if kind == "quoted reply name" and " someone wrote:" in m.group(0):
                continue
            kinds.append(kind)
            shapes[kind] = redacted_shape(m.group(0))
    return [f"{k} {shapes[k]}" for k in kinds]


def _key_number(record_id: str) -> int:
    m = re.fullmatch(r"jira-[A-Z][A-Z0-9_]{1,29}-(\d{1,9})", record_id)
    return int(m.group(1)) if m else -1


def _project_report(path: Path) -> tuple[dict[str, Any], Counter[str], list[str]]:
    verdicts: Counter[str] = Counter()
    categories: Counter[str] = Counter()
    scrub: Counter[str] = Counter()
    leaks: list[str] = []
    tickets = with_comments = kept = reported = cut = old_format = malformed = 0
    missing: list[tuple[int, str]] = []
    keys: list[int] = []
    updated: list[str] = []
    from kube_noob.tickets import verdict

    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if len(line) > MAX_LINE:
                malformed += 1
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                malformed += 1
                continue
            if not isinstance(rec, dict) or not str(rec.get("sourceId", "")).startswith("jira:"):
                continue
            tickets += 1
            rid = str(rec.get("id", ""))
            if (n := _key_number(rid)) >= 0:
                keys.append(n)
            verdicts[verdict(rec.get("issueType"), rec.get("status"), rec.get("resolution"))] += 1
            categories[str(rec.get("statusCategory") or "unknown")] += 1
            if rec.get("updated"):
                updated.append(str(rec["updated"]))
            text = str(rec.get("text") or "")
            if "\n## Comments\n" in text:
                with_comments += 1
            if "commentsTotal" not in rec:
                old_format += 1
            else:
                k, t = int(rec.get("comments") or 0), int(rec.get("commentsTotal") or 0)
                kept += k
                reported += t
                if k < t:
                    missing.append((t - k, rid.removeprefix("jira-")))
            if rec.get("textCut"):
                cut += 1
            for p in PLACEHOLDERS:
                scrub[p] += text.count(p)
            scrub["commenter labels"] += len(set(_COMMENTER.findall(text)))
            for field, body in (("text", text), ("title", str(rec.get("title") or ""))):
                for kind in _person_shapes(body):
                    if len(leaks) < 50:
                        leaks.append(f"{rid.removeprefix('jira-')} {field}: {kind}")
    span = (max(keys) - min(keys) + 1) if keys else 0
    report = {
        "tickets": tickets,
        "byVerdict": dict(sorted(verdicts.items())),
        "byStatusCategory": dict(sorted(categories.items())),
        "withComments": with_comments,
        "commentsKept": kept,
        "commentsReported": reported,
        "ticketsMissingComments": len(missing),
        "mostMissing": [f"{key} ({n} missing)" for n, key in sorted(missing, reverse=True)[:5]],
        "textCut": cut,
        "olderFormat": old_format,
        "oldestUpdate": min(updated) if updated else None,
        "newestUpdate": max(updated) if updated else None,
        "keyRange": [min(keys), max(keys)] if keys else None,
        "keyCoverage": round(tickets / span, 3) if span else None,
        "bytes": path.stat().st_size,
        **({"malformedLines": malformed} if malformed else {}),
    }
    return report, scrub, leaks


def audit(data_dir: Path, project: str | None = None) -> dict[str, Any]:
    """The copy's audit report; ``project`` limits it to one project key."""
    from kube_noob.ticket_changes import sync_state

    corpus = data_dir / "corpus"
    shards = sorted(corpus.glob("jira-*.jsonl")) if corpus.is_dir() else []
    shards = [p for p in shards if p.stem != "jira-insights"]
    if project:
        shards = [p for p in shards if p.stem == f"jira-{project.lower()}"]
    if not shards:
        return {
            "available": False,
            "note": "No local Jira copy: kube-noob corpus jira --online, or kube-noob corpus import <snapshot>.",
        }
    state = sync_state(data_dir)
    projects: dict[str, Any] = {}
    scrub_total: Counter[str] = Counter()
    leaks: list[str] = []
    for path in shards:
        key = path.stem.removeprefix("jira-").upper()
        rep, scrub, found = _project_report(path)
        st = (state.get("projects") or {}).get(key) or {}
        rep["sync"] = {
            k: st.get(k) for k in ("lastSyncAt", "complete", "lowestKey", "openDone", "textVersion") if k in st
        }
        projects[key] = rep
        scrub_total.update(scrub)
        leaks.extend(found)
    total = sum(p["tickets"] for p in projects.values())
    reported = sum(p["commentsReported"] for p in projects.values())
    kept = sum(p["commentsKept"] for p in projects.values())
    return {
        "available": True,
        "baseUrl": state.get("baseUrl"),
        "tickets": total,
        "bytes": sum(p["bytes"] for p in projects.values()),
        "commentCompleteness": round(kept / reported, 4) if reported else None,
        "projects": projects,
        "anonymiser": dict(sorted(scrub_total.items())),
        "selfCheck": {"personShapedFindings": len(leaks), "examples": leaks[:10]},
    }


def text_report(rep: dict[str, Any]) -> list[str]:
    if not rep.get("available"):
        return [str(rep.get("note"))]
    mb = rep["bytes"] / 1_000_000
    complete = rep["commentCompleteness"]
    lines = [
        f"Jira copy: {rep['tickets']} tickets, {mb:.1f} MB, comments kept "
        + ("n/a" if complete is None else f"{complete:.1%}")
        + f" (from {rep.get('baseUrl') or 'unknown'})"
    ]
    for key, p in rep["projects"].items():
        sync = p["sync"]
        state = "complete" if sync.get("complete") else f"backfilling below {sync.get('lowestKey', 'the top')}"
        lines.append(
            f"  {key:10} {p['tickets']:>7} tickets  {p['withComments']} with comments  "
            f"{p['ticketsMissingComments']} missing comments  {p['textCut']} cut  {p['olderFormat']} older format  "
            f"keys {p['keyRange'][0] if p['keyRange'] else '-'}-{p['keyRange'][1] if p['keyRange'] else '-'} "
            f"({p['keyCoverage']} covered)  {state}, last sync {sync.get('lastSyncAt', 'never')}"
        )
        lines.append("             " + ", ".join(f"{n} {v}" for v, n in p["byVerdict"].items()))
    lines.append("anonymiser: " + ", ".join(f"{n} {k}" for k, n in rep["anonymiser"].items()))
    check = rep["selfCheck"]
    lines.append(
        "self-check: no person-shaped text found"
        if not check["personShapedFindings"]
        else f"self-check: {check['personShapedFindings']} person-shaped findings, e.g. {', '.join(check['examples'])}"
    )
    return lines
