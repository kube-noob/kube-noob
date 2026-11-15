"""Has Red Hat seen this before? Match an error against the local copy of Red Hat's public Jira tickets.

``kube-noob corpus jira`` keeps a copy of every ticket in the chosen projects, whatever became of it. This module
indexes that copy with SQLite FTS5 and answers two questions about an error: which tickets describe it, and what
became of each one - fixed (in which release, and whether the cluster's version already has it), still open (with any
workaround posted in the comments), or closed as not a bug, won't fix, duplicate, cannot reproduce or obsolete.

A ticket counts as a match only when it shares several words with the error that are rare among tickets and in general
Kubernetes writing, or when a distinctive line of the error appears in it word for word, so a generic CrashLoopBackOff
never pulls in an unrelated bug. The copy and its index stay in the data folder of the install that pulled them
(``<dataDir>/corpus/jira-*.jsonl`` and ``<dataDir>/jira/tickets.db``); nothing here is shipped or sent anywhere.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import sqlite3
import tempfile
import threading
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from kube_noob import sanitize
from kube_noob.catalog import OPENSHIFT_FAMILY
from kube_noob.errors import KubeNoobError
from kube_noob.jira_catalog import DEFAULT_BASE_URL, DEFAULT_PROJECTS, ISSUE_KEY, OPENSHIFT_VERSIONED, parse_version

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None  # type: ignore[assignment]

MIN_RARE_TERMS = 3  # rare words the error and the ticket must share
RARE_SHARE = 0.03  # a word in at most 3% of tickets is rare
GENERAL_MAX_CHUNKS = 2  # and in at most 2 sections of the bundled docs (see known_issues.GENERAL_MAX_CHUNKS)
PHRASE_MAX_HITS = 25  # a line found word for word in more tickets than this is too common to identify one,
PHRASE_MAX_SHARE = 0.005  # and in more than 0.5% of a smaller copy
PHRASE_MIN_WORDS = 5
PHRASE_MIN_DISTINCT = 2  # words in the phrase that are neither everyday English nor Kubernetes status vocabulary
MAX_QUERY_TERMS = 24
CANDIDATES = 40
MAX_BODY = 20_000
INDEX_VERSION = "1"
OPENSHIFT_ONLY = tuple(sorted(k for k, v in DEFAULT_PROJECTS.items() if v == "openshift"))
BUG_TYPES = {"bug", "vulnerability", "weakness", "defect"}

_lock = threading.Lock()
_failed: dict[str, str] = {}  # index path -> fingerprint whose build failed


def _sync_running(data_dir: Path) -> bool:
    """A sync holds ``jira/.sync.lock`` (see sources.jira.sync_lock) while it rewrites shards."""
    lock = data_dir / "jira" / ".sync.lock"
    if fcntl is None or not lock.is_file():
        return False
    try:
        with open(lock, "a", encoding="utf-8") as fh:
            try:
                fcntl.flock(fh.fileno(), fcntl.LOCK_SH | fcntl.LOCK_NB)
            except BlockingIOError:
                return True
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
    except OSError:
        return False
    return False


_WORD = re.compile(r"[a-z0-9]+")
_ERRORISH = re.compile(
    r"(?i)\b(error|errors|failed|failure|fails|denied|forbidden|panic|unable|cannot|timeout|timed out|refused|"
    r"invalid|x509|oomkilled|backoff|back-off|not found|exceeded|unauthorized|rejected|conflict|deadline|crash)\b"
)
_CLAUSE = re.compile(r"[:;,\"'()\[\]{}|=/\\<>]")
_COMMENT_HEAD = re.compile(
    r"^Comment \((\d{4}-\d{2}-\d{2})?\)(?: by (?:Commenter [A-Z]{1,3}|a commenter))?: ?", re.MULTILINE
)
_SENTENCE = re.compile(r"(?<=[.!?])\s+|\n{2,}")
_URL = re.compile(r"^https://[A-Za-z0-9.-]+/browse/([A-Z][A-Z0-9_]{1,29}-\d{1,9})\Z")
REMARKS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("workaround", re.compile(r"(?i)\bwork[- ]?around\b|\bto work around\b|\bmitigat(e|ion)\b")),
    (
        "expected",
        re.compile(
            r"(?i)\bexpected behaviou?r\b|\bworking as (designed|intended|expected)\b|\bby design\b|\bnot a bug\b|"
            r"\bmisconfigur|\bconfiguration (issue|problem|error)\b|\bunsupported configuration\b"
        ),
    ),
    ("cause", re.compile(r"(?i)\broot cause\b|\bcaused by\b|\bthe cause\b|\b(happens|occurs) because\b")),
    (
        "fix",
        re.compile(r"(?i)\bfixed in\b|\bfix (is|was|has been) (merged|released|available|backported)\b|\bbackport"),
    ),
)
_RESOLUTION_VERDICTS: tuple[tuple[str, str], ...] = (
    ("duplicate", "duplicate"),
    ("not a bug", "not-a-bug"),
    ("notabug", "not-a-bug"),
    ("works as", "not-a-bug"),
    ("as designed", "not-a-bug"),
    ("explained", "not-a-bug"),
    ("cannot reproduce", "cannot-reproduce"),
    ("can't reproduce", "cannot-reproduce"),
    ("unable to reproduce", "cannot-reproduce"),
    ("insufficient", "cannot-reproduce"),
    ("incomplete", "cannot-reproduce"),
    ("won't", "wont-fix"),
    ("wont", "wont-fix"),
    ("can't do", "wont-fix"),
    ("cannot do", "wont-fix"),
    ("declined", "wont-fix"),
    ("rejected", "wont-fix"),
    ("out of scope", "wont-fix"),
    ("obsolete", "obsolete"),
    ("out of date", "obsolete"),
    ("end of life", "obsolete"),
    ("migrated", "obsolete"),
    ("done", "fixed"),
    ("fixed", "fixed"),
    ("errata", "fixed"),
    ("release", "fixed"),
    ("resolved", "fixed"),
    ("complete", "fixed"),
)
_IN_PROGRESS = {"modified", "on_qa", "on qa", "verified", "release pending", "ready for release"}


# Words that never identify a ticket on their own: Kubernetes reasons, events and status vocabulary, and everyday
# English. A copy where a few tickets paste `oc describe` output would otherwise make them look rare.
GENERIC_WORDS = frozenset(
    """
    the and for with from that this was were are not but has have had been will can could should would into onto
    when then than there their they them its also any all one two use used using via per out off back after before
    while still again only just more most some such each other our your you yes may might must does did done
    error errors failed failure fails failing fail unable cannot timeout timed refused invalid denied forbidden
    unauthorized rejected conflict deadline exceeded panic crash crashed crashing warning warn normal info debug
    reason message status code exit exited killed kill signal restart restarts restarting restarted started start
    starting created create creating pulling pulled pull pulls image images container containers pod pods node
    nodes deployment deployments replicaset statefulset daemonset job jobs service services namespace namespaces
    backoff crashloopbackoff oomkilled imagepullbackoff errimagepull containercreating pending running succeeded
    evicted unschedulable failedmount failedscheduling failedcreate unhealthy probe readiness liveness startup
    event events kubelet scheduled scheduling ready true false none null nil value values object objects resource
    resources request requests response cluster clusters openshift kubernetes version versions issue bug ticket
    rpc grpc desc notfound unpack terminated last state context canceled cancelled eof dial tcp udp http https
    connection connect lookup host port address get post put read write file files directory path permission
    unknown exists already found available unavailable internal server client api default system kube
    """.split()  # noqa: SIM905 - a word list reads better as text
)


class TicketIndexError(KubeNoobError):
    pass


# --------------------------------------------------------------------------------------------------------------------
# Verdicts and remarks


def verdict(issue_type: str | None, status: str | None, resolution: str | None) -> str:
    """What became of a ticket: fixed, done, fix-in-progress, fix-proposed, open, not-a-bug, wont-fix, duplicate,
    cannot-reproduce, obsolete or closed."""
    res = (resolution or "").strip().lower()
    st = (status or "").strip().lower()
    if res and res not in {"unresolved", "none"}:
        for needle, code in _RESOLUTION_VERDICTS:
            if needle in res:
                if code == "fixed" and (issue_type or "").strip().lower() not in BUG_TYPES:
                    return "done"
                return code
        return "closed"
    if st in _IN_PROGRESS:
        return "fix-in-progress"
    if st == "post":
        return "fix-proposed"
    if st in {"closed", "done", "resolved"}:
        return "closed"
    return "open"


def _clip(text: str, limit: int = 280) -> str:
    text = re.sub(r"\s+", " ", sanitize.visible(text)).strip()
    return text if len(text) <= limit else text[: limit - 3].rsplit(" ", 1)[0] + "..."


def split_body(body: str) -> tuple[str, list[tuple[str | None, str]]]:
    """The record text as (description, [(comment date, comment text), ...]) in posting order."""
    desc, _, comments = body.partition("\n## Comments\n")
    desc = desc.split("\n## Description\n", 1)[-1]
    heads = list(_COMMENT_HEAD.finditer(comments))
    out: list[tuple[str | None, str]] = []
    for i, m in enumerate(heads):
        end = heads[i + 1].start() if i + 1 < len(heads) else len(comments)
        out.append((m.group(1), comments[m.end() : end].strip()))
    return desc.strip(), out


def remarks(body: str, limit: int = 3) -> list[dict[str, str]]:
    """Workarounds, causes, "expected behaviour" verdicts and fix notes, latest comment first, one per kind."""
    desc, comments = split_body(body)
    found: list[dict[str, str]] = []
    kinds: set[str] = set()
    sources: list[tuple[str | None, str, str]] = [(d, t, "comment") for d, t in reversed(comments)]
    sources.append((None, desc, "description"))
    for date, text, where in sources:
        for sentence in _SENTENCE.split(text):
            for kind, rx in REMARKS:
                if kind in kinds or not rx.search(sentence) or len(sentence.strip()) < 20:
                    continue
                kinds.add(kind)
                item = {"kind": kind, "from": where, "text": _clip(sentence)}
                if date:
                    item["date"] = date
                found.append(item)
                if len(found) >= limit:
                    return found
    return found


def _versions(names: list[str]) -> list[tuple[str, tuple[int, int, int]]]:
    return [(n, v) for n in names if (v := parse_version(n)) is not None]


def _exact(name: str) -> bool:
    return bool(re.search(r"\d+\.\d+\.\d+", name)) and not name.lower().endswith(".z")


def fix_assessment(fix_names: list[str], running: str | None) -> tuple[str | None, bool | None, str]:
    """(fixed-in name, applies to the running version?, sentence) for a fixed bug. ``applies`` is None when unknown."""
    parsed = _versions(fix_names)
    if not parsed:
        return None, None, ""
    if not running or (r := parse_version(running)) is None:
        name = min(parsed, key=lambda p: p[1])[0]
        return name, None, ""
    parsed = [p for p in parsed if p[1][0] == r[0]]  # "OADP 1.4.2" or "Logging 5.9" say nothing about OpenShift 4.x
    if not parsed:
        return None, None, ""
    same = [p for p in parsed if p[1][:2] == r[:2]]
    if same:
        name, v = min(same, key=lambda p: p[1])
        if not _exact(name):
            return name, None, f" The fix is in a {r[0]}.{r[1]} update; the ticket does not name the exact release."
        if r >= v:
            return name, False, f" You run {running}, which already includes it, so this is probably not the cause."
        return name, True, f" You run {running}: updating to {name} or later fixes it."
    later = [p for p in parsed if p[1][:2] > r[:2]]
    if later:
        name = min(later, key=lambda p: p[1])[0]
        return (
            name,
            True,
            f" You run {running}; the fix shipped in {name}. Check the linked tickets for a backport to {r[0]}.{r[1]}.",
        )
    name = max(parsed, key=lambda p: p[1])[0]
    return name, False, f" The fix shipped in {name}, before your {running}, so this is probably not the cause."


def describe(t: dict[str, Any], running: str | None) -> tuple[str, bool | None, str | None]:
    """A sentence on what became of the ticket, whether it can apply to the running version, and the fix release."""
    v = t["verdict"]
    resolved = (t.get("resolved") or t.get("updated") or "")[:10]
    when = f" on {resolved}" if resolved else ""
    kind = "bug" if (t.get("type") or "").lower() in BUG_TYPES else (t.get("type") or "ticket").lower()
    fix = t.get("fix") or []
    if v == "fixed":
        name, applies, note = fix_assessment(fix, running)
        versions = f" Fix version{'s' if len(fix) > 1 else ''}: {', '.join(fix)}." if fix else ""
        return f"Known {kind}, fixed{when}.{versions}{note}", applies, name
    if v == "done":
        name = min(_versions(fix), key=lambda p: p[1])[0] if _versions(fix) else None
        return f"{t.get('type') or 'Ticket'} completed{when}{f' in {name}' if name else ''}.", None, name
    if v == "fix-in-progress":
        target = f" Target: {', '.join(fix)}." if fix else ""
        return f"Known {kind}; a fix is merged and waiting for release (status {t.get('status')}).{target}", None, None
    if v == "fix-proposed":
        return f"Known {kind}; a fix is proposed but not merged yet (status {t.get('status')}).", None, None
    if v == "open":
        if (t.get("type") or "").lower() in BUG_TYPES:
            return f"Known bug, still open (status {t.get('status')}); no fix released yet.", None, None
        return f"Open {kind} (status {t.get('status')}): not available yet.", None, None
    if v == "not-a-bug":
        return (
            f"Reported and closed as {t.get('resolution')}{when}: Red Hat treats this as expected behaviour or a "
            "configuration issue, not a defect.",
            None,
            None,
        )
    if v == "wont-fix":
        return f"Reported and closed as {t.get('resolution')}{when}: no fix is planned.", None, None
    if v == "cannot-reproduce":
        return (
            f"Reported and closed as {t.get('resolution')}{when}: Red Hat could not reproduce it. If you can, the "
            "ticket's details help a support case.",
            None,
            None,
        )
    if v == "obsolete":
        return (
            f"Closed as {t.get('resolution')}{when}: the affected version or component is no longer maintained.",
            None,
            None,
        )
    if v == "duplicate":
        dup = t.get("duplicateOf")
        return f"Closed as a duplicate{f' of {dup}' if dup else ''}{when}.", None, None
    return f"Closed ({t.get('resolution') or t.get('status')}){when}.", None, None


# --------------------------------------------------------------------------------------------------------------------
# Index


def index_path(data_dir: Path) -> Path:
    return data_dir / "jira" / "tickets.db"


def _ticket_shards(data_dir: Path) -> list[tuple[str, dict[str, Any]]]:
    manifest = data_dir / "corpus" / "MANIFEST.json"
    try:
        doc = (
            sanitize.loads_bounded(manifest.read_text(encoding="utf-8"), sanitize.MAX_JSON_DEPTH_FILE)
            if manifest.is_file()
            else {}
        )
    except (OSError, ValueError):
        return []
    shards = (doc.get("shards") or {}).items() if isinstance(doc, dict) else []
    return sorted(
        (name, e)
        for name, e in shards
        if isinstance(e, dict) and any(str(s).startswith("jira:") for s in e.get("sources") or [])
    )


def _fingerprint(shards: list[tuple[str, dict[str, Any]]]) -> str:
    h = hashlib.sha256(INDEX_VERSION.encode())
    for name, e in shards:
        h.update(f"{name}:{e.get('sha256')}\n".encode())
    return h.hexdigest()


def _ro_uri(db: Path) -> str:
    """A read-only SQLite URI that survives '#', '?' or '%' in the path (as_uri percent-encodes them)."""
    return db.resolve().as_uri() + "?mode=ro"


def _meta(db: Path) -> dict[str, str]:
    try:
        con = sqlite3.connect(_ro_uri(db), uri=True)
        try:
            return dict(con.execute("SELECT k, v FROM meta").fetchall())
        finally:
            con.close()
    except sqlite3.Error:
        return {}


def _records(data_dir: Path, shards: list[tuple[str, dict[str, Any]]]) -> Iterator[dict[str, Any]]:
    cdir = data_dir / "corpus"
    for _name, entry in shards:
        f = cdir / str(entry.get("file") or "")
        if not f.is_file() or f.parent != cdir:
            continue
        with f.open(encoding="utf-8") as fh:
            for line in fh:
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if isinstance(rec, dict) and str(rec.get("sourceId", "")).startswith("jira:"):
                    yield rec


def _sync_base(data_dir: Path) -> str:
    """The Jira site this copy was synced from (state.json), else Red Hat's."""
    try:
        state = json.loads((data_dir / "jira" / "state.json").read_text(encoding="utf-8"))
        base = str(state.get("baseUrl") or "") if isinstance(state, dict) else ""
    except (OSError, ValueError):
        base = ""
    return base.rstrip("/") if re.fullmatch(r"https://[A-Za-z0-9.-]+\.[A-Za-z]{2,}/?", base) else DEFAULT_BASE_URL


def _url(rec: dict[str, Any], key: str, base: str) -> str:
    """The record's link only if it points at the synced site; an imported record cannot relabel another site."""
    url = str(rec.get("url") or "")
    m = _URL.fullmatch(url)
    return url if m and m.group(1) == key and url.startswith(base + "/") else f"{base}/browse/{key}"


def _strs(value: Any, limit: int = 40) -> list[str]:
    return (
        [str(x)[:80] for x in value or [] if isinstance(x, str | int | float)][:limit]
        if isinstance(value, list)
        else []
    )


def _text(value: Any, limit: int) -> str:
    return value[:limit] if isinstance(value, str) else ""


def _row_values(rec: dict[str, Any], base: str) -> tuple[Any, ...] | None:
    key = _text(rec.get("id"), 60).removeprefix("jira-")
    m = ISSUE_KEY.fullmatch(key)
    if not m:
        return None
    title = _text(rec.get("title"), 500).removeprefix(f"{key}: ")
    itype, status, resolution = (_text(rec.get(k), 80) or None for k in ("issueType", "status", "resolution"))
    links_value = rec.get("links")
    raw_links: list[Any] = links_value if isinstance(links_value, list) else []
    links = [
        {k: _text(link.get(k), 60) for k in ("type", "relation", "key")}
        for link in raw_links
        if isinstance(link, dict) and ISSUE_KEY.fullmatch(_text(link.get("key"), 60))
    ][:20]
    return (
        key,
        m.group(1),
        title,
        itype,
        status,
        resolution,
        verdict(itype, status, resolution),
        json.dumps(_strs(rec.get("fixVersions"))),
        json.dumps(_strs(rec.get("affectsVersions"))),
        json.dumps(_strs(rec.get("components"))),
        json.dumps(links),
        _text(rec.get("created"), 32),
        _text(rec.get("updated"), 32),
        _text(rec.get("resolved"), 32),
        _text(rec.get("retrievedAt"), 32),
        _url(rec, key, base),
        _text(rec.get("text"), MAX_BODY),
    )


def _build(target: Path, data_dir: Path, shards: list[tuple[str, dict[str, Any]]], fingerprint: str) -> int:
    con = sqlite3.connect(target)
    try:
        try:
            con.executescript(
                """
                PRAGMA journal_mode=OFF;
                PRAGMA synchronous=OFF;
                CREATE TABLE meta (k TEXT PRIMARY KEY, v TEXT);
                CREATE TABLE tickets (
                    rowid INTEGER PRIMARY KEY, key TEXT UNIQUE, project TEXT, title TEXT, type TEXT, status TEXT,
                    resolution TEXT, verdict TEXT, fix TEXT, affects TEXT, components TEXT, links TEXT,
                    created TEXT, updated TEXT, resolved TEXT, retrieved TEXT, url TEXT, body TEXT);
                CREATE INDEX tickets_project ON tickets(project);
                CREATE VIRTUAL TABLE fts USING fts5(
                    title, body, content='tickets', content_rowid='rowid', tokenize='unicode61');
                CREATE VIRTUAL TABLE vocab USING fts5vocab(fts, 'row');
                """
            )
        except sqlite3.OperationalError as exc:
            raise TicketIndexError(
                f"this Python's SQLite has no full-text search (FTS5): {exc}. Use the kube-noob container image or "
                "a Python built with FTS5 (python.org, Homebrew and UBI builds include it)."
            ) from exc
        count = 0
        projects: set[str] = set()
        newest = ""
        base = _sync_base(data_dir)
        for rec in _records(data_dir, shards):
            try:
                row = _row_values(rec, base)
            except (TypeError, ValueError, AttributeError):
                continue  # a malformed record (hand-made or damaged shard) is skipped, never fatal
            if row is None:
                continue
            con.execute(
                "INSERT OR REPLACE INTO tickets (key, project, title, type, status, resolution, verdict, fix, affects, "
                "components, links, created, updated, resolved, retrieved, url, body) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                row,
            )
            count += 1
            projects.add(row[1])
            newest = max(newest, row[14])
        con.execute("INSERT INTO fts(fts) VALUES('rebuild')")
        meta = {
            "fingerprint": fingerprint,
            "tickets": str(count),
            "projects": json.dumps(sorted(projects)),
            "retrievedAt": newest,
            "builtAt": datetime.now(UTC).isoformat(timespec="seconds"),
        }
        con.executemany("INSERT INTO meta (k, v) VALUES (?, ?)", meta.items())
        con.commit()
        return count
    finally:
        con.close()


def ensure_index(data_dir: Path) -> Path | None:
    """The ticket index for this data folder, rebuilt when the local Jira copy changed; None without a copy."""
    shards = _ticket_shards(data_dir)
    if not shards:
        return None
    fingerprint = _fingerprint(shards)
    db = index_path(data_dir)
    if db.is_file() and (_meta(db).get("fingerprint") == fingerprint or _sync_running(data_dir)):
        return db  # current, or a sync is rewriting shards: answer from the last index rather than rebuild per shard
    if _failed.get(str(db)) == fingerprint:
        raise TicketIndexError("the local Jira copy could not be indexed (see the earlier error); fix or re-sync it")
    with _lock:
        db.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with open(db.parent / ".index.lock", "a", encoding="utf-8") as lockf:
            if fcntl is not None:
                fcntl.flock(lockf.fileno(), fcntl.LOCK_EX)
            try:
                if db.is_file() and _meta(db).get("fingerprint") == fingerprint:
                    return db
                tmpdir = Path(tempfile.mkdtemp(dir=db.parent, prefix=".tickets."))  # mode 0700
                tmp = tmpdir / "tickets.db"
                try:
                    _build(tmp, data_dir, shards, fingerprint)
                    os.chmod(tmp, 0o600)
                    os.replace(tmp, db)
                except (sqlite3.Error, OSError, TicketIndexError):
                    _failed[str(db)] = fingerprint  # do not rebuild on every question; a new copy retries
                    raise
                finally:
                    tmp.unlink(missing_ok=True)
                    tmpdir.rmdir()
            finally:
                if fcntl is not None:
                    fcntl.flock(lockf.fileno(), fcntl.LOCK_UN)
    return db


@contextlib.contextmanager
def _open(data_dir: Path | None) -> Iterator[sqlite3.Connection | None]:
    db = ensure_index(data_dir) if data_dir else None
    if db is None:
        yield None
        return
    con = sqlite3.connect(_ro_uri(db), uri=True)
    con.row_factory = sqlite3.Row
    try:
        yield con
    finally:
        con.close()


def _info(con: sqlite3.Connection) -> dict[str, Any]:
    meta = dict(con.execute("SELECT k, v FROM meta").fetchall())
    return {
        "tickets": int(meta.get("tickets") or 0),
        "projects": json.loads(meta.get("projects") or "[]"),
        "asOf": (meta.get("retrievedAt") or "")[:10] or None,
    }


def summary(data_dir: Path | None) -> dict[str, Any] | None:
    """Ticket count, projects and retrieval date from the corpus manifest alone (cheap: no index build or scan)."""
    if data_dir is None:
        return None
    shards = _ticket_shards(data_dir)
    if not shards:
        return None
    projects = sorted({str(s).removeprefix("jira:") for _, e in shards for s in e.get("sources") or []})
    dates = [str(e.get("writtenAt") or "") for _, e in shards]
    return {
        "tickets": sum(int(e.get("records") or 0) for _, e in shards),
        "projects": projects,
        "asOf": max(dates)[:10] if any(dates) else None,
    }


def stats(data_dir: Path | None) -> dict[str, Any] | None:
    """Ticket count, projects and retrieval date of the local Jira copy, or None when there is none."""
    try:
        with _open(data_dir) as con:
            if con is None:
                return None
            info = _info(con)
            info["byVerdict"] = dict(
                con.execute("SELECT verdict, count(*) FROM tickets GROUP BY verdict ORDER BY 2 DESC").fetchall()
            )
            return info
    except (TicketIndexError, sqlite3.Error):
        return None


# --------------------------------------------------------------------------------------------------------------------
# Matching


def _words(text: str) -> list[str]:
    return _WORD.findall(text.lower())


def _useful(word: str) -> bool:
    return len(word) > 2 and not word.isdigit()


def _variable(word: str) -> bool:
    """Words that change from one occurrence of an error to the next: numbers, hashes, pod suffixes."""
    digits = sum(c.isdigit() for c in word)
    return word.isdigit() or (digits > 0 and len(word) >= 5)


def error_phrases(text: str, limit: int = 4) -> list[str]:
    """Distinctive word runs from error-looking lines: each clause (split at punctuation and path separators) that
    has 5-10 words with no numbers or hashes in them, longest first."""
    found: list[str] = []
    for line in text.splitlines():
        if not _ERRORISH.search(line):
            continue
        for clause in _CLAUSE.split(line):
            run: list[str] = []
            for w in [*_words(clause), "0"]:  # the sentinel closes the last run
                if not _variable(w):
                    run.append(w)
                    continue
                if len(run) >= PHRASE_MIN_WORDS:
                    phrase = " ".join(run[:10])
                    if phrase not in found:
                        found.append(phrase)
                run = []
    return sorted(found, key=lambda p: -len(p.split()))[:limit]


def _general_count(word: str) -> int:
    from kube_noob.known_issues import _general_store

    return _general_store().doc_count(word)


def _row(con: sqlite3.Connection, key: str) -> sqlite3.Row | None:
    row: sqlite3.Row | None = con.execute("SELECT * FROM tickets WHERE key = ?", (key,)).fetchone()
    return row


def _ticket(row: sqlite3.Row) -> dict[str, Any]:
    t: dict[str, Any] = {k: row[k] for k in row.keys()}  # noqa: SIM118 - sqlite3.Row is not a mapping
    for k in ("fix", "affects", "components", "links"):
        t[k] = json.loads(t[k] or "[]")
    # Jira's Duplicate link reads "A duplicates B" on A's outward side: B is the ticket to follow.
    t["duplicateOf"] = next(
        (link["key"] for link in t["links"] if str(link.get("relation", "")).lower() == "duplicates"), None
    )
    return t


def _present(
    con: sqlite3.Connection, t: dict[str, Any], running: str | None, as_of: str | None
) -> tuple[dict[str, Any], bool | None]:
    # Cluster versions are OpenShift versions: compare them only with projects whose fixVersions are OpenShift releases.
    sentence, applies, fixed_in = describe(t, running if t["project"] in OPENSHIFT_VERSIONED else None)
    target = t.get("duplicateOf")
    if t["verdict"] == "duplicate" and target and (row := _row(con, target)) is not None:
        other = _ticket(row)
        other_running = running if other["project"] in OPENSHIFT_VERSIONED else None
        other_sentence, applies, fixed_in = describe(other, other_running)
        sentence += f" {target}: {other_sentence}"
    rem = remarks(t["body"] or "")
    out: dict[str, Any] = {
        "id": t["key"],
        "url": t["url"],
        "kind": "ticket",
        "source": f"Red Hat Jira, local copy retrieved {as_of or 'unknown'}",
        "summary": _clip(t["title"] or "", 200),
        "type": t["type"],
        "jiraStatus": t["status"],
        "resolution": t["resolution"],
        "verdict": t["verdict"],
        "status": sentence,
        "fixedIn": fixed_in,
        "fixVersions": t["fix"],
        "affectsVersions": t["affects"],
        "components": t["components"][:6],
        "workaround": next((r["text"] for r in rem if r["kind"] == "workaround"), None),
        "remarks": rem,
        "duplicateOf": target,
        "related": [{"relation": link["relation"], "key": link["key"]} for link in t["links"][:6]],
        "updated": (t["updated"] or "")[:10] or None,
    }
    return out, applies


def match(
    text: str, platform: str | None = None, version: str | None = None, limit: int = 3, data_dir: Path | None = None
) -> dict[str, Any]:
    """Tickets in the local Jira copy that describe ``text``, with what became of each."""
    try:
        with _open(data_dir) as con:
            if con is None:
                return {"available": False, "matches": []}
            return _match(con, text, platform, version, limit)
    except (TicketIndexError, sqlite3.Error, OSError) as exc:
        return {"available": False, "matches": [], "note": f"the local Jira copy is unavailable: {exc}"}


def _running(version: str | None) -> str | None:
    """The version compared against fix versions, read as every other surface reads it (kube_noob.versions)."""
    from kube_noob.versions import read_version

    cv = read_version(version)
    return cv.numeric if cv else None


def _match(con: sqlite3.Connection, text: str, platform: str | None, version: str | None, limit: int) -> dict[str, Any]:
    info = _info(con)
    out: dict[str, Any] = {"available": True, "knowledge": info, "matches": []}
    running = _running(version)
    skip_openshift = bool(platform) and platform not in OPENSHIFT_FAMILY
    words = {w for w in _words(text[:200_000]) if _useful(w)}
    n = max(info["tickets"], 1)
    df: dict[str, int] = {}
    wl = sorted(words)
    for i in range(0, len(wl), 500):
        part = wl[i : i + 500]
        q = f"SELECT term, doc FROM vocab WHERE term IN ({','.join('?' * len(part))})"  # noqa: S608 - placeholders only
        df.update({str(term): int(doc) for term, doc in con.execute(q, part).fetchall()})
    ceiling = max(1, int(RARE_SHARE * n))
    rare = {
        w
        for w, d in df.items()
        if 0 < d <= ceiling and w not in GENERIC_WORDS and _general_count(w) <= GENERAL_MAX_CHUNKS
    }
    project_filter = ""
    params: list[Any] = []
    if skip_openshift:
        project_filter = f" AND tickets.project NOT IN ({','.join('?' * len(OPENSHIFT_ONLY))})"
        params = list(OPENSHIFT_ONLY)
    candidates: dict[str, dict[str, Any]] = {}
    if rare:
        terms = sorted(rare, key=lambda w: (df[w], w))[:MAX_QUERY_TERMS]
        query = " OR ".join(f'"{w}"' for w in terms)
        rows = con.execute(
            "SELECT tickets.key AS key, bm25(fts, 4.0, 1.0) AS score "  # noqa: S608 - placeholders and constants
            "FROM fts JOIN tickets ON tickets.rowid = fts.rowid "
            f"WHERE fts MATCH ?{project_filter} ORDER BY score LIMIT {CANDIDATES}",
            [query, *params],
        ).fetchall()
        for row in rows:
            candidates[row["key"]] = {"score": -float(row["score"]), "exact": False}
    phrase_cap = min(PHRASE_MAX_HITS, max(2, int(n * PHRASE_MAX_SHARE)))
    for phrase in error_phrases(text):
        if len({w for w in phrase.split() if len(w) > 2 and w not in GENERIC_WORDS}) < PHRASE_MIN_DISTINCT:
            continue  # "back off restarting failed container" is in hundreds of tickets and identifies none
        rows = con.execute(
            "SELECT tickets.key AS key FROM fts JOIN tickets ON tickets.rowid = fts.rowid "  # noqa: S608 - placeholders
            f"WHERE fts MATCH ?{project_filter} LIMIT {PHRASE_MAX_HITS + 1}",
            [f'"{phrase}"', *params],
        ).fetchall()
        if 0 < len(rows) <= phrase_cap:
            for row in rows:
                candidates.setdefault(row["key"], {"score": 0.0, "exact": False})["exact"] = True
    ranked: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
    for key, c in candidates.items():
        row = _row(con, key)
        if row is None:
            continue
        t = _ticket(row)
        shared = sorted(rare & set(_words(f"{t['title']} {t['body']}")))
        if len(shared) < MIN_RARE_TERMS and not c["exact"]:
            continue
        item, applies = _present(con, t, running, info["asOf"])
        if running and applies is False:
            continue
        item.update({"exactError": c["exact"], "sharedTerms": shared[:8], "score": round(c["score"], 2)})
        ranked.append(((not c["exact"], -len(shared), -c["score"], key), item))
    ranked.sort(key=lambda p: p[0])
    out["matches"] = [item for _, item in ranked[:limit]]
    if not out["matches"]:
        out["note"] = (
            f"No ticket in the local Jira copy ({info['tickets']} tickets from {', '.join(info['projects'][:8])}"
            f"{'...' if len(info['projects']) > 8 else ''}, retrieved {info['asOf']}) matches this text closely."
        )
    return out


def ticket(key: str, data_dir: Path | None, version: str | None = None) -> dict[str, Any]:
    """One ticket from the local copy, with its verdict, remarks and links."""
    key = key.strip().upper()
    if not ISSUE_KEY.fullmatch(key):
        raise TicketIndexError(f"not a Jira issue key: {key!r}")
    try:
        with _open(data_dir) as con:
            if con is None:
                return {"found": False, "note": "No local Jira copy yet: kube-noob corpus jira --online"}
            row = _row(con, key)
            if row is None:
                info = _info(con)
                return {
                    "found": False,
                    "url": f"{DEFAULT_BASE_URL}/browse/{key}",
                    "note": f"{key} is not in the local copy ({info['tickets']} tickets, retrieved {info['asOf']}).",
                }
            running = _running(version)
            item, applies = _present(con, _ticket(row), running, _info(con)["asOf"])
            desc, comments = split_body(row["body"] or "")
            item.update(
                {
                    "found": True,
                    "appliesToVersion": applies,
                    "description": _clip(desc, 600),
                    "comments": len(comments),
                    "created": (row["created"] or "")[:10] or None,
                }
            )
            return item
    except (TicketIndexError, sqlite3.Error, OSError) as exc:
        return {"found": False, "note": f"the local Jira copy is unavailable: {exc}"}
