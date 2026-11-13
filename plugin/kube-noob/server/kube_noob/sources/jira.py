"""Jira Cloud ingestion with paced, rate-limit-aware pulls of Red Hat's public Jira (redhat.atlassian.net).

* Supported interfaces only: projects from ``/rest/api/3/project/search`` and issues from the enhanced search API
  ``/rest/api/3/search/jql`` with ``nextPageToken`` pagination. Atlassian's Acceptable Use Policy forbids reaching the
  service "by any means other than our publicly supported interfaces" (scraping is its example), so the web pages
  (``/jira/projects?page=N``) are never fetched.
* Polite by design: one request at a time, at least ``CRAWL_DELAY`` seconds apart (the site's robots.txt asks every
  crawler for one second) plus random jitter, exponential backoff with full jitter on 429/5xx, ``Retry-After``
  honoured, and a request budget per run so a sync never turns into a flood.
* ``sync_project`` keeps a local copy of every issue in a project, whatever its status or resolution: changes since
  the last run first, then older issues by key until the project is complete. ``pull_project`` is the older
  version-filtered pull (RHACS 4.10+).
* Privacy: reporter/assignee/author identities are never stored; emails and account ids are scrubbed from text;
  @mentions become ``@user``.
* Records are marked ``redistributable: false`` - public visibility is not a redistribution license. They stay in the
  local data folder of the install that pulled them; packages, plugins and dataset exports never include them.
"""

from __future__ import annotations

import contextlib
import json
import os
import random
import re
import tempfile
import threading
import time
from collections import Counter
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx

from kube_noob import sanitize
from kube_noob.errors import KubeNoobError
from kube_noob.jira_audit import BARE_ACCOUNT_ID
from kube_noob.jira_catalog import (  # noqa: F401 - re-exported for callers of the sync
    DEFAULT_BASE_URL,
    DEFAULT_PROJECTS,
    ISSUE_KEY,
    PROJECT_KEY,
    parse_version,
    product_of,
)

DEFAULT_FIELDS = (
    "summary,description,issuetype,status,priority,resolution,labels,components,fixVersions,versions,"
    "created,updated,resolutiondate,comment,parent"
)
SYNC_FIELDS = DEFAULT_FIELDS + ",issuelinks"
# Red Hat's Jira Cloud exposes "Target Version" as customfield_10855 (verified on ROX-36348, 2026-10-27).
DEFAULT_TARGET_FIELD = "customfield_10855"
_NON_PRODUCT_HINT = re.compile(r"(?i)\b(ocp|openshift|k8s|kubernetes|rhel|go|golang|python|node|helm|java|ubi)\b")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_ACCOUNT = re.compile(
    r"\[~[^\]\s]{1,120}\]"  # [~accountid:...] and Server-style [~jsmith]
    # accountId followed by any mix of quote, colon, equals and space, then the id. The earlier form demanded the id
    # start within one punctuation character, so the JSON spelling `{"accountId": "5b10..."}` -- a quote, a colon and
    # a space -- kept its id, and the corpus-refresh privacy gate caught it in stored text.
    r"|accountId[\"'=:\s]{1,6}[0-9a-f][0-9a-f:-]{9,}"
    r"|https?://[^\s/]+/(?:jira/)?(?:people|secure/ViewProfile\.jspa\?name=)[^\s)\]>\"']*"  # profile links
    # ...and the bare forms, from the one definition the privacy audit gates on. The two had drifted: an id pasted
    # bare into a description ("see 5b10... for details") survived this scrub and was then flagged by the audit,
    # which exits 1 -- so one such ticket failed the weekly refresh every week and discarded an hour of fetching.
    "|" + BARE_ACCOUNT_ID,
    re.IGNORECASE,
)
MAX_COMMENTS = 2_000  # comments kept per ticket: in practice every one
MAX_TEXT = 20_000
SYNC_MAX_TEXT = 1_000_000  # characters per ticket in the copy: the full anonymised text; a longer one keeps its end
TEXT_VERSION = 2  # 2: every comment, authors as pseudonyms; a copy made before refetches its tickets once
SCRUB_VERSION = 2  # 2: spelled-out and suffix-less emails, international phones, handles, profiles, signatures
COMMENT_PAGE = 100
_PHONE = re.compile(r"(?<![\w.])\+?\(?\d{1,4}\)?[ -]\d{2,4}[ -]\d{3,4}(?:[ -]\d{2,4})?(?!\w|\.\d)")
_PHONE_INTL = re.compile(r"(?<![\w.+])\+\d{1,3}(?:[ .-]?\(?\d{1,5}\)?){2,6}(?![\w.]?\d)")  # +1.415..., +33 1 23 ...
_EMAIL_SPELLED = re.compile(
    r"\b[A-Za-z0-9._%+-]{1,64}\s*(?:\(at\)|\[at\]|\{at\}|\s+at\s+)\s*[A-Za-z0-9-]{1,63}"
    r"(?:\s*(?:\.|\(dot\)|\[dot\]|\{dot\}|\s+dot\s+)\s*[A-Za-z0-9-]{1,63}){1,4}\b(?<=[A-Za-z]{2})",
    re.IGNORECASE,
)
_EMAIL_LOCAL = re.compile(  # user@host with no suffix, or URL-encoded; never image@sha256:..., pkg@1.2.3
    r"(?<![\w.%+-])[A-Za-z0-9._%+-]{1,64}(?:@|%40)(?!sha\d{3}:)[A-Za-z][A-Za-z0-9-]{0,62}(?:\.[A-Za-z0-9-]{1,63})*\b(?!:)"
)
_HANDLE = re.compile(
    r"(?<![\w@/.])@(?!(?:property|staticmethod|classmethod|Override|Test|Before|After|Autowired|Bean|Component|"
    r"Deprecated|SuppressWarnings|FunctionalInterface|dataclass|pytest|user|Commenter)\b)[A-Za-z][\w.-]{1,38}\w(?![\w/:@])"
)
_PROFILE_URL = re.compile(
    r"https?://(?:www\.)?(?:github\.com|gitlab\.com|twitter\.com|x\.com|bsky\.app/profile|keybase\.io)/"
    r"[A-Za-z0-9_.-]{1,60}/?(?=[\s)\]>\"',.;]|$)"
    r"|https?://(?:[a-z]{2,3}\.|www\.)?linkedin\.com/(?:in|pub)/[^\s)\]>\"']{1,100}"
    r"|https?://[^\s/]+/wiki/people/[^\s)\]>\"']{1,100}",
    re.IGNORECASE,
)
_QUOTE_HEADER = re.compile(r"^(>?[ \t]*On [^\n]{0,60}?,)[^\n<]{1,80}?(?:<+[^\n]{0,120}?>+)?[ \t]*wrote:", re.MULTILINE)
_CLOSING = re.compile(
    r"^((?:Thanks|Thank you|Cheers|Regards|Best regards|Best|BR|Kind regards)[ \t]*,?[ \t]*\n?[ \t]*)"
    r"[A-Z][a-z]{1,20}(?:[ \t]+[A-Z][a-z]{1,20}){0,2}[ \t]*$",
    re.MULTILINE,
)
_SIGNATURE = re.compile(r"^-- ?\n[^\n]{1,120}$", re.MULTILINE)  # the delimiter and the name line under it
_ADDRESS = r"(?:Hi|Hello|Hey|Thanks|Thank you|Thx|cc|CC|Cc|Dear|ping|@)[ ,]{1,2}"
LONG_JQL = 1500  # characters; above this the search request is sent as POST
MAX_RETRY_AFTER = 120.0  # seconds; a larger Retry-After is capped so a pull cannot hang for hours
CRAWL_DELAY = 1.0  # robots.txt on redhat.atlassian.net: "Crawl-delay: 1" for every crawler (checked 2026-10-28)
OVERLAP_MINUTES = 10  # forward syncs reach this far before the last run, so clock skew cannot lose an update
# Open tickets first on a new copy, so the tickets people reconcile are there within minutes; the JQL form is the one
# Atlassian documents (https://support.atlassian.com/jira/kb/how-to-search-using-statuscategory-statuscategorychangeddate-function-with-jql/).
OPEN_JQL = 'statusCategory in ("To Do", "In Progress")'
TRACKED = ("status", "statusCategory", "resolution", "fixVersions")
MAX_CHANGES = 200_000  # lines kept in jira/changes.jsonl, newest last


class JiraError(KubeNoobError):
    pass


class BudgetExhausted(JiraError):
    """The run's request budget is spent; the sync stops cleanly and resumes next time."""


def scrub(text: str) -> str:
    """Emails (also spelled out, URL-encoded or without a domain suffix), phone numbers (also international forms),
    account ids, profile links on Jira, GitHub, GitLab, LinkedIn and social sites, @handles that are not a known
    the name in a quoted reply's "On ..., Name wrote:" line, and signatures after "-- " (``scrub_handles`` then
    replaces the @handles ``unname`` did not label)."""
    import unicodedata

    if not text.isascii():
        text = unicodedata.normalize("NFKC", text)  # a full-width at sign is an at sign
    text = _EMAIL.sub("<email>", text)
    text = _EMAIL_LOCAL.sub("<email>", text)
    text = _EMAIL_SPELLED.sub("<email>", text)
    text = _PROFILE_URL.sub("<profile>", text)
    text = _PHONE_INTL.sub(lambda m: "<phone>" if sum(c.isdigit() for c in m.group(0)) >= 8 else m.group(0), text)
    text = _PHONE.sub("<phone>", text)
    text = _ACCOUNT.sub("<account>", text)
    text = _QUOTE_HEADER.sub(lambda m: f"{m.group(1)} someone wrote:", text)
    text = _CLOSING.sub(lambda m: f"{m.group(1)}someone", text)
    return _SIGNATURE.sub("-- \n<signature>", text)


def anonymise(text: str, by_name: dict[str, str]) -> str:
    """Every person-shaped thing out of one piece of ticket text, in the order that actually holds.

    ``scrub`` runs twice on purpose. It cannot recognise every display name as a person -- a non-ASCII one is not
    email-shaped or handle-shaped -- so a name survives the first pass and ``unname`` then swaps it for its label.
    That is what leaves text like "ping Commenter A at quay.io", which reads as a spelled-out email to the audit
    that gates the corpus. Scrubbing again after the names are labels removes what only becomes visible then, and
    the pass is cheap because the first one has already taken out the emails, phones, ids and profile links.
    """
    return scrub(scrub_handles(unname(scrub(text), by_name)))


def scrub_handles(text: str) -> str:
    """@handles left after the commenters' own were labelled (``unname`` runs first)."""
    return _HANDLE.sub("@user", text)


def _label(i: int) -> str:
    """A, B, ... Z, AA, AB, ...: the i-th commenter on a ticket."""
    out = ""
    i += 1
    while i:
        i, r = divmod(i - 1, 26)
        out = chr(65 + r) + out
    return out


def pseudonyms(comments: list[Any]) -> tuple[dict[str, str], dict[str, str]]:
    """Per ticket, in order of first comment: account id -> "Commenter A", and display name -> the same label. Neither
    the id nor the name is stored; the maps only replace them in the text."""
    by_id: dict[str, str] = {}
    by_name: dict[str, str] = {}
    for c in comments:
        author = c.get("author") if isinstance(c, dict) else None
        if not isinstance(author, dict):
            continue
        ident = str(author.get("accountId") or author.get("name") or author.get("displayName") or "")
        if not ident:
            continue
        label = by_id.setdefault(ident, f"Commenter {_label(len(by_id))}")
        name = str(author.get("displayName") or "").strip()
        if len(name) >= 3:
            by_name.setdefault(name, label)
    return by_id, by_name


def _fold(name: str) -> str:
    import unicodedata

    return "".join(c for c in unicodedata.normalize("NFKD", name) if not unicodedata.combining(c))


def unname(text: str, by_name: dict[str, str]) -> str:
    """Replace each commenter's display name in any letter case, with or without accents, and their first name
    where it addresses or thanks them ("Hi Jane", "cc Jane", "@Jane", "Thanks,\nJane"), with the commenter's
    label."""
    for name in sorted(by_name, key=len, reverse=True):
        label = by_name[name]
        forms = [name, _fold(name)]
        if name.count(",") == 1:  # "Doe, Sam" is written "Sam Doe" in the text
            last, first_name = (x.strip() for x in name.split(","))
            forms += [f"{first_name} {last}", _fold(f"{first_name} {last}")]
        for form in dict.fromkeys(forms):
            text = re.sub(rf"(?<!\w){re.escape(form)}(?!\w)", label, text, flags=re.IGNORECASE)
        first = name.split()[0]
        if len(name.split()) > 1 and len(first) >= 3 and first.isalpha():
            for form in dict.fromkeys((first, _fold(first))):
                address = re.compile(
                    rf"\b({_ADDRESS}|(?:Thanks|Thank you|Cheers|Regards|Best),?\s*\n){re.escape(form)}(?!\w)"
                )
                text = address.sub(rf"\g<1>{label}", text)
                text = re.sub(rf"@{re.escape(form)}(?!\w)", f"@{label}", text, flags=re.IGNORECASE)
    return text


def adf_to_text(node: Any, people: dict[str, str] | None = None) -> str:
    """Atlassian Document Format -> plain text (Markdown-ish). A mention of a known commenter becomes their label,
    any other mention ``@user``."""
    if node is None:
        return ""
    if isinstance(node, str):
        return node
    if isinstance(node, list):
        return "".join(adf_to_text(n, people) for n in node)
    if not isinstance(node, dict):
        return ""
    t = node.get("type")
    content = node.get("content") or []
    if t == "text":
        return str(node.get("text", ""))
    if t == "hardBreak":
        return "\n"
    if t == "mention":
        ident = str(_obj(node.get("attrs")).get("id") or "")
        return "@" + people[ident] if people and ident in people else "@user"
    if t == "emoji":
        return str(_obj(node.get("attrs")).get("text", ""))
    if t in {"inlineCard", "blockCard", "embedCard"}:
        return str(_obj(node.get("attrs")).get("url", ""))
    if t == "paragraph":
        return adf_to_text(content, people) + "\n\n"
    if t == "heading":
        level = int(_obj(node.get("attrs")).get("level", 2))
        return "#" * min(max(level, 1), 6) + " " + adf_to_text(content, people) + "\n\n"
    if t == "codeBlock":
        return "```\n" + adf_to_text(content, people) + "\n```\n\n"
    if t == "blockquote":
        return "".join("> " + ln + "\n" for ln in adf_to_text(content, people).strip().splitlines()) + "\n"
    if t in {"bulletList", "orderedList"}:
        items = []
        for i, li in enumerate(content):
            prefix = f"{i + 1}. " if t == "orderedList" else "- "
            items.append(prefix + adf_to_text(li, people).strip().replace("\n\n", "\n"))
        return "\n".join(items) + "\n\n"
    if t == "listItem":
        return adf_to_text(content, people)
    if t == "table":
        rows = []
        for row in content:
            cells = [adf_to_text(c, people).strip().replace("\n", " ") for c in (row.get("content") or [])]
            rows.append("| " + " | ".join(cells) + " |")
        return "\n".join(rows) + "\n\n"
    return adf_to_text(content, people)


@dataclass
class PullStats:
    requests: int = 0
    retries: int = 0
    pages: int = 0
    comment_pages: int = 0
    scanned: int = 0
    kept: int = 0
    strategy: str = ""
    errors: list[str] = field(default_factory=list)
    # Token of the search page that has not been fully applied. A budget stop resumes here instead of
    # repeating the pages already kept. None once the search is finished.
    resume_token: str | None = None


def _obj(value: Any) -> dict[str, Any]:
    """``value`` when it is a JSON object, else an empty one: a field that is null, a string or a list never breaks
    a sync."""
    return value if isinstance(value, dict) else {}


class JiraClient:
    def __init__(
        self,
        client: httpx.Client,
        base_url: str,
        *,
        min_delay: float = CRAWL_DELAY,
        jitter: float = 1.0,
        max_retries: int = 6,
        sleep: Callable[[float], None] = time.sleep,
        rng: random.Random | None = None,
        auth: tuple[str, str] | None = None,
        max_requests: int | None = None,
    ) -> None:
        if auth is not None and not base_url.startswith("https://"):
            raise JiraError("Jira credentials are only sent over https; use an https:// base URL")
        self.http = client
        self.auth = httpx.BasicAuth(*auth) if auth else None
        self.base = base_url.rstrip("/")
        self.min_delay = max(min_delay, CRAWL_DELAY)  # never faster than the site's robots.txt asks
        self.jitter = max(jitter, 0.0)
        self.max_retries = max_retries
        self.sleep = sleep
        self.rng = rng or random.Random()  # noqa: S311 - jitter, not crypto
        self.max_requests = max_requests
        self.stats = PullStats()

    def _pause(self) -> None:
        self.sleep(self.min_delay + self.rng.random() * self.jitter)

    @property
    def remaining(self) -> int | None:
        return None if self.max_requests is None else max(0, self.max_requests - self.stats.requests)

    def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        return self._request("GET", path, params=params)

    def post(self, path: str, body: dict[str, Any]) -> Any:
        return self._request("POST", path, body=body)

    def _request(
        self, method: str, path: str, params: dict[str, Any] | None = None, body: dict[str, Any] | None = None
    ) -> Any:
        url = f"{self.base}{path}"
        headers = {"Accept": "application/json"}
        if self.stats.requests:
            self._pause()  # every request after the first waits at least CRAWL_DELAY
        for attempt in range(self.max_retries + 1):
            if self.max_requests is not None and self.stats.requests >= self.max_requests:
                raise BudgetExhausted(f"request budget of {self.max_requests} spent")
            self.stats.requests += 1
            try:
                if method == "POST":
                    resp = self.http.post(
                        url, json=body, headers={**headers, "Content-Type": "application/json"}, auth=self._auth()
                    )
                else:
                    resp = self.http.get(url, params=params, headers=headers, auth=self._auth())
            except httpx.TransportError as exc:
                if attempt == self.max_retries:
                    raise JiraError(f"{method} {path} failed: {exc}") from exc
                self._backoff(attempt, None)
                continue
            if resp.status_code == 200:
                return resp.json()
            if resp.status_code in {429, 500, 502, 503, 504} and attempt < self.max_retries:
                self._backoff(attempt, resp.headers.get("Retry-After"))
                continue
            if resp.status_code in {401, 403}:
                raise JiraError(
                    f"{method} {path}: HTTP {resp.status_code}. The project may not allow anonymous "
                    "access; set JIRA_EMAIL and JIRA_API_TOKEN for authenticated pulls."
                )
            raise JiraError(f"{method} {path}: HTTP {resp.status_code}: {resp.text[:400]}")
        raise JiraError(f"{method} {path}: retries exhausted")

    def _auth(self) -> Any:
        return self.auth if self.auth is not None else httpx.USE_CLIENT_DEFAULT

    def _backoff(self, attempt: int, retry_after: str | None) -> None:
        self.stats.retries += 1
        delay = self.min_delay + self.rng.uniform(0, min(60.0, 2.0**attempt))  # never sooner than the crawl delay
        if retry_after:
            with contextlib.suppress(ValueError):
                delay = max(delay, min(float(retry_after), MAX_RETRY_AFTER))
        self.sleep(delay)

    def versions(self, project: str) -> list[dict[str, Any]]:
        data = self.get(f"/rest/api/3/project/{project}/versions")
        return data if isinstance(data, list) else []

    def search(
        self, jql: str, fields: str = DEFAULT_FIELDS, page_size: int = 100, page_token: str | None = None
    ) -> Iterator[dict[str, Any]]:
        """Enhanced JQL search. Long JQL goes in a POST body so it never hits URL length limits.

        ``page_token`` resumes a search whose previous run stopped mid-pagination. ``stats.resume_token`` is the
        page that has not been fully applied yet, so a budget stop can continue from it.
        """
        token: str | None = page_token or None
        use_post = len(jql) > LONG_JQL
        while True:
            self.stats.resume_token = token
            if use_post:
                body: dict[str, Any] = {"jql": jql, "fields": fields.split(","), "maxResults": page_size}
                if token:
                    body["nextPageToken"] = token
                data = self.post("/rest/api/3/search/jql", body)
            else:
                params: dict[str, Any] = {"jql": jql, "fields": fields, "maxResults": page_size}
                if token:
                    params["nextPageToken"] = token
                data = self.get("/rest/api/3/search/jql", params)
            self.stats.pages += 1
            issues = data.get("issues") or []
            yield from issues
            token = data.get("nextPageToken") if isinstance(data.get("nextPageToken"), str) else None
            if data.get("isLast", token is None) or not token or not issues:
                self.stats.resume_token = None
                return

    def projects(self, page_size: int = 100) -> list[dict[str, str]]:
        """Every project this caller can see, from the supported project search API (paged by startAt)."""
        out: list[dict[str, str]] = []
        start = 0
        while True:
            data = self.get("/rest/api/3/project/search", {"startAt": start, "maxResults": page_size})
            if not isinstance(data, dict):
                return out
            values = [v for v in data.get("values") or [] if isinstance(v, dict)]
            for v in values:
                key = str(v.get("key") or "")
                if PROJECT_KEY.fullmatch(key):
                    out.append({"key": key, "name": scrub(str(v.get("name") or ""))[:200]})
            start += len(values)
            total = data.get("total")
            if not values or data.get("isLast") is True or (isinstance(total, int) and start >= total):
                return out
            if "isLast" not in data and not isinstance(total, int):
                return out  # no paging information: one page is all we can trust


def _names(items: Any) -> list[str]:
    return [str(i.get("name")) for i in items or [] if isinstance(i, dict) and i.get("name")]


def _links(items: Any) -> list[dict[str, str]]:
    """Issue links as {type, relation, key}: "duplicates", "clones", "blocks"... (at most 20, keys validated)."""
    out: list[dict[str, str]] = []
    for link in items or []:
        if not isinstance(link, dict):
            continue
        ltype = link.get("type") or {}
        for side, phrase in (("outwardIssue", "outward"), ("inwardIssue", "inward")):
            other = link.get(side)
            key = str((other or {}).get("key") or "") if isinstance(other, dict) else ""
            if ISSUE_KEY.fullmatch(key):
                out.append(
                    {
                        "type": str(ltype.get("name") or "")[:40],
                        "relation": str(ltype.get(phrase) or phrase)[:60],
                        "key": key,
                    }
                )
    return out[:20]


def issue_to_record(
    issue: dict[str, Any],
    base_url: str,
    project: str,
    matched: list[str],
    basis: str,
    retrieved_at: str,
    target_field: str = DEFAULT_TARGET_FIELD,
    max_text: int = MAX_TEXT,
) -> dict[str, Any]:
    f = issue.get("fields") or {}
    target = _names(f.get(target_field)) if isinstance(f.get(target_field), list) else []
    key = issue.get("key", "")
    desc = f.get("description")
    comment_field = f.get("comment") or {}
    all_comments = [c for c in comment_field.get("comments") or [] if isinstance(c, dict)]
    comments = all_comments[-MAX_COMMENTS:]
    by_id, by_name = pseudonyms(comments)
    desc_text = adf_to_text(desc, by_id) if isinstance(desc, dict | list) else str(desc or "")
    comment_text = "\n".join(
        f"Comment ({str(c.get('created', ''))[:10]}) by "
        + by_id.get(
            str(_obj(c.get("author")).get("accountId") or _obj(c.get("author")).get("name") or ""),
            by_id.get(str(_obj(c.get("author")).get("displayName") or ""), "a commenter"),
        )
        + ": "
        + (
            adf_to_text(c.get("body"), by_id) if isinstance(c.get("body"), dict | list) else str(c.get("body") or "")
        ).strip()
        for c in comments
    )
    comments_total = max(int(comment_field.get("total") or 0), len(all_comments))
    fix, aff = _names(f.get("fixVersions")), _names(f.get("versions"))
    comps, labels = _names(f.get("components")), [str(x) for x in f.get("labels") or []]
    status = _obj(f.get("status")).get("name")
    itype = _obj(f.get("issuetype")).get("name")
    prio = _obj(f.get("priority")).get("name")
    resolution = _obj(f.get("resolution")).get("name")
    header = [
        f"# {key}: {f.get('summary', '')}",
        f"Type: {itype} | Status: {status} | Priority: {prio} | Resolution: {resolution or 'Unresolved'}",
        f"Fix versions: {', '.join(fix) or '-'} | Affects versions: {', '.join(aff) or '-'} | "
        f"Target versions: {', '.join(target) or '-'}",
        f"Components: {', '.join(comps) or '-'} | Labels: {', '.join(labels) or '-'}",
        f"Created: {str(f.get('created', ''))[:10]} | Updated: {str(f.get('updated', ''))[:10]}",
    ]
    cut = False
    if comment_text and len(desc_text) + len(comment_text) > max_text:
        # keep the latest comments (where fixes, workarounds and "not a bug" verdicts are written) within budget
        room = max(max_text // 2, max_text - len(desc_text) - 600)
        comment_text = "...\n" + comment_text[-room:].split("\n", 1)[-1]
        cut = True
    full = anonymise(
        "\n".join(header)
        + "\n\n## Description\n\n"
        + desc_text.strip()
        + ("\n\n## Comments\n\n" + comment_text if comment_text else ""),
        by_name,
    )
    text = full[:max_text]
    cut = cut or len(full) > max_text
    status_category = _obj(_obj(f.get("status")).get("statusCategory")).get("key")
    return {
        "id": f"jira-{key}",
        "title": anonymise(f"{key}: {f.get('summary', '')}", by_name),
        "text": text,
        "url": f"{base_url.rstrip('/')}/browse/{key}",
        "sourceId": f"jira:{project}",
        "license": "Red Hat public Jira content - no redistribution license; local retrieval/evaluation only",
        "redistributable": False,
        "retrievedAt": retrieved_at,
        "issueType": itype,
        "status": status,
        "priority": prio,
        "fixVersions": fix,
        "affectsVersions": aff,
        "targetVersions": target,
        "labels": labels,
        "components": comps,
        "updated": f.get("updated"),
        "created": f.get("created"),
        "resolution": resolution,
        "resolved": f.get("resolutiondate"),
        "statusCategory": status_category,
        "links": _links(f.get("issuelinks")),
        "version": ",".join(matched) or None,
        "versionBasis": basis,
        "comments": len(comments),
        "commentsTotal": comments_total,
        **({"textCut": True} if cut else {}),
    }


def classify(
    issue: dict[str, Any], min_v: tuple[int, int, int], ga_floor: str | None, target_field: str = DEFAULT_TARGET_FIELD
) -> tuple[list[str], str] | None:
    """Return (matched version names, basis) if the issue concerns ``min_v`` or later, else None."""
    f = issue.get("fields") or {}
    target = f.get(target_field) if isinstance(f.get(target_field), list) else []
    explicit_names = _names(f.get("fixVersions")) + _names(f.get("versions")) + _names(target)
    label_names = [str(x) for x in f.get("labels") or [] if re.fullmatch(r"v?\d+\.\d+(\.\d+)?", str(x))]

    def eligible(names: list[str]) -> tuple[list[str], bool]:
        out, any_product = [], False
        for n in names:
            if _NON_PRODUCT_HINT.search(n):
                continue
            v = parse_version(n)
            if v is None:
                continue
            any_product = True
            if v >= min_v:
                out.append(n)
        return out, any_product

    exp, exp_any = eligible(explicit_names)
    lab, lab_any = eligible(label_names)
    matched = sorted(set(exp + lab), key=lambda n: parse_version(n) or (0, 0, 0))
    if matched:
        return matched, "explicit-version" if exp else "version-label"
    if exp_any or lab_any:
        return None  # explicitly targets an older release
    created = str(f.get("created") or "")[:10]
    if ga_floor and created and created >= ga_floor:
        return [], f"created-after-{min_v[0]}.{min_v[1]}-release"
    return None


@dataclass
class PullResult:
    records: list[dict[str, Any]]
    stats: PullStats
    versions_considered: list[str]
    ga_floor: str | None


def pull_project(
    client: JiraClient,
    project: str,
    min_version: str,
    target: int,
    max_scan: int,
    base_url: str,
    now: datetime | None = None,
    target_field: str = DEFAULT_TARGET_FIELD,
) -> PullResult:
    mv = parse_version(min_version)
    if mv is None:
        raise JiraError(f"min_version {min_version!r} is not a version like 4.10")
    retrieved_at = (now or datetime.now(UTC)).isoformat(timespec="seconds")
    versions = client.versions(project)
    eligible = [
        v
        for v in versions
        if not _NON_PRODUCT_HINT.search(str(v.get("name", "")))
        and (pv := parse_version(str(v.get("name", "")))) is not None
        and pv >= mv
    ]
    names = sorted({str(v["name"]) for v in eligible})
    dated = sorted(str(v["releaseDate"]) for v in eligible if v.get("releaseDate"))
    ga_floor = dated[0] if dated else None
    records: list[dict[str, Any]] = []
    seen: set[str] = set()

    def consume(jql: str, strategy: str) -> None:
        client.stats.strategy = (client.stats.strategy + "+" if client.stats.strategy else "") + strategy
        fields = f"{DEFAULT_FIELDS},{target_field}" if target_field else DEFAULT_FIELDS
        for issue in client.search(jql, fields=fields):
            client.stats.scanned += 1
            key = issue.get("key", "")
            if key in seen:
                continue
            cls = classify(issue, mv, ga_floor, target_field)
            if cls is not None:
                seen.add(key)
                records.append(issue_to_record(issue, base_url, project, cls[0], cls[1], retrieved_at, target_field))
            if len(records) >= target or client.stats.scanned >= max_scan:
                return

    if names:
        # 1) Compact range JQL: version fields compare by the project's version order (verified on ROX, 2026-10-27).
        #    classify() re-checks every issue numerically, so out-of-order versions cannot leak in.
        lowest = min(names, key=lambda n: parse_version(n) or (0, 0, 0))
        fields_cmp = ["fixVersion", "affectedVersion"]
        if target_field.startswith("customfield_"):
            fields_cmp.append(f"cf[{target_field.removeprefix('customfield_')}]")
        ranged = " OR ".join(f"{f} >= {json.dumps(lowest)}" for f in fields_cmp)
        range_failed = False
        try:
            consume(f"project = {project} AND ({ranged}) ORDER BY updated DESC", "version-range")
        except JiraError as exc:
            client.stats.errors.append(f"version-range: {exc}")
            range_failed = True
        # 2) Explicit version list (POSTed when long) only if the range query was rejected.
        if range_failed and len(records) < target and client.stats.scanned < max_scan:
            quoted = ", ".join(json.dumps(n) for n in names)
            clauses = [f"{f} in ({quoted})" for f in fields_cmp]
            for label, cl in (("version-list", clauses), ("version-list-no-target", clauses[:2])):
                try:
                    consume(f"project = {project} AND ({' OR '.join(cl)}) ORDER BY updated DESC", label)
                    break
                except JiraError as exc:
                    client.stats.errors.append(f"{label}: {exc}")
                    if len(cl) == 2:
                        break
    if len(records) < target and client.stats.scanned < max_scan:
        consume(f"project = {project} ORDER BY updated DESC", "recent-scan")
    client.stats.kept = len(records)
    return PullResult(records, client.stats, names, ga_floor)


def insights(records: list[dict[str, Any]], project: str) -> dict[str, Any]:
    """Aggregate, non-identifying statistics - safe to share as derived insight."""

    def count(key: str, multi: bool = False) -> list[tuple[str, int]]:
        c: Counter[str] = Counter()
        for r in records:
            v = r.get(key)
            if multi:
                c.update(v or [])
            elif v:
                c[str(v)] += 1
        return c.most_common(15)

    version_counter: Counter[str] = Counter()
    for r in records:
        for v in (r.get("version") or "").split(","):
            if v:
                version_counter[v] += 1
    open_bugs = [r for r in records if r.get("issueType") == "Bug" and r.get("resolution") in (None, "Unresolved")]
    return {
        "project": project,
        "issues": len(records),
        "byType": count("issueType"),
        "byStatus": count("status"),
        "byPriority": count("priority"),
        "byComponent": count("components", multi=True),
        "byVersion": version_counter.most_common(20),
        "topLabels": count("labels", multi=True),
        "openBugs": len(open_bugs),
        "basis": count("versionBasis"),
    }


def insights_markdown(ins: dict[str, Any], retrieved_at: str, min_version: str) -> str:
    def table(rows: list[tuple[str, int]]) -> str:
        return "\n".join(f"- {k}: {v}" for k, v in rows) or "- (none)"

    return (
        f"# {ins['project']} issue insights ({min_version}+)\n\n"
        f"Aggregated from {ins['issues']} public issues retrieved {retrieved_at}. Counts only; see individual issues "
        "for details.\n\n"
        f"## By version\n\n{table(ins['byVersion'])}\n\n## By component\n\n{table(ins['byComponent'])}\n\n"
        f"## By type\n\n{table(ins['byType'])}\n\n## By status\n\n{table(ins['byStatus'])}\n\n"
        f"## By priority\n\n{table(ins['byPriority'])}\n\n## Top labels\n\n{table(ins['topLabels'])}\n\n"
        f"Open bugs: {ins['openBugs']}\n"
    )


# ---------------------------------------------------------------------------------------------------------------------
# Full-project sync: every issue, any status, kept up to date run after run.


def select_projects(spec: str, available: list[dict[str, str]] | None = None) -> list[str]:
    """``default`` (Kubernetes/OpenShift/RHACS set), ``all`` (every visible project) or ``KEY,KEY``."""
    known = [p["key"] for p in available or []]
    wanted = spec.strip()
    if wanted == "all":
        if not known:
            raise JiraError("'all' needs the project list from the server; none was returned")
        return known
    if wanted in {"", "default"}:
        keys = list(DEFAULT_PROJECTS)
        return [k for k in keys if k in known] if known else keys
    keys = list(dict.fromkeys(k.strip().upper() for k in wanted.split(",") if k.strip()))
    bad = [k for k in keys if not PROJECT_KEY.fullmatch(k)]
    if bad:
        raise JiraError(f"not Jira project keys: {', '.join(bad)}")
    if known:
        missing = [k for k in keys if k not in known]
        if missing:
            raise JiraError(
                f"projects not visible on this Jira: {', '.join(missing)} "
                "(list them with: kube-noob corpus jira-projects --online)"
            )
    return keys


def key_number(key: str) -> int:
    m = ISSUE_KEY.fullmatch(key)
    return int(m.group(2)) if m else -1


def jira_time(value: Any) -> datetime | None:
    """Jira timestamps look like 2026-10-27T10:21:33.123-0400."""
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(str(value), fmt).astimezone(UTC)
        except ValueError:
            continue
    return None


def _iso(t: datetime) -> str:
    return t.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse_iso(value: Any) -> datetime | None:
    try:
        t = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=UTC)


def shard_name(project: str) -> str:
    return f"jira-{project.lower().replace('_', '-')}"


def jira_dir(data_dir: Path) -> Path:
    d = data_dir / "jira"
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    return d


def load_shard(data_dir: Path, project: str) -> dict[str, dict[str, Any]]:
    path = data_dir / "corpus" / f"{shard_name(project)}.jsonl"
    out: dict[str, dict[str, Any]] = {}
    if not path.is_file():
        return out
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            with contextlib.suppress(ValueError):
                rec = json.loads(line)
                if isinstance(rec, dict) and isinstance(rec.get("id"), str):
                    out[rec["id"]] = rec
    return out


def load_state(data_dir: Path) -> dict[str, Any]:
    path = data_dir / "jira" / "state.json"
    if not path.is_file():
        return {}
    try:
        doc = sanitize.loads_bounded(path.read_text(encoding="utf-8"), sanitize.MAX_JSON_DEPTH_FILE)
    except (OSError, ValueError):
        return {}
    return doc if isinstance(doc, dict) else {}


def save_state(data_dir: Path, state: dict[str, Any]) -> None:
    d = jira_dir(data_dir)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".state.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(state, fh, indent=1, sort_keys=True)
        os.chmod(tmp, 0o600)
        os.replace(tmp, d / "state.json")
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def state_from_records(records: dict[str, dict[str, Any]], project: str) -> dict[str, Any]:
    """Resume from a copy that came without matching state (``corpus import``, or a state file from another copy).

    Only a copy written by this sync is contiguous by key, so only then is the lowest key a safe place to resume and
    the oldest retrieval time a safe start for the forward pass. Anything else (the version-filtered pull of 0.4 and
    earlier, a hand-made shard) starts over: the records are kept and refreshed as the sync reaches them."""
    recs = list(records.values())
    if not recs or any(r.get("versionBasis") != "sync" for r in recs):
        return {}
    keys = [str(r.get("id", "")).removeprefix("jira-") for r in recs]
    keys = [k for k in keys if ISSUE_KEY.fullmatch(k) and k.startswith(project + "-")]
    times = [t for r in recs if (t := _parse_iso(r.get("retrievedAt")))]
    if not keys or not times:
        return {}
    out: dict[str, Any] = {"complete": False, "lowestKey": min(keys, key=key_number), "lastSyncAt": _iso(min(times))}
    if all("commentsTotal" in r for r in recs):  # written with every comment: no need to fetch the tickets again
        out["textVersion"] = TEXT_VERSION
    return out


@dataclass
class ProjectSync:
    project: str
    fetched: int = 0
    total: int = 0
    complete: bool = False
    stopped: str | None = None
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {k: v for k, v in self.__dict__.items() if v is not None}


def change_event(
    prev: dict[str, Any] | None, rec: dict[str, Any], phase: str, since: datetime | None
) -> dict[str, Any] | None:
    """What changed for one ticket between the copy and the server: status, status category, resolution or fix
    versions, as a verdict ("fixed", "not-a-bug", "reopened", "fix-version", ...). A ticket the copy did not hold is
    "opened" only when the forward pass finds it created since the last sync; the backfill only fills history."""
    from kube_noob.tickets import verdict

    key = str(rec["id"]).removeprefix("jira-")
    to = {k: rec.get(k) for k in TRACKED}
    to["verdict"] = verdict(rec.get("issueType"), rec.get("status"), rec.get("resolution"))
    base = {
        "key": key,
        "project": str(rec.get("sourceId", "")).removeprefix("jira:"),
        "at": rec.get("retrievedAt"),
        "type": rec.get("issueType"),
    }
    if prev is None:
        created = _parse_iso(rec.get("created"))
        if phase == "forward" and since is not None and created is not None and created >= since:
            return {**base, "kind": "opened", "to": to}
        return None
    before = {k: prev.get(k) for k in TRACKED}
    if before == {k: to[k] for k in TRACKED}:
        return None
    before["verdict"] = verdict(prev.get("issueType"), prev.get("status"), prev.get("resolution"))
    if before.get("statusCategory") == "done" and to.get("statusCategory") != "done":
        kind = "reopened"
    elif before["verdict"] != to["verdict"]:
        kind = str(to["verdict"])
    elif before.get("fixVersions") != to.get("fixVersions"):
        kind = "fix-version"
    else:
        kind = "status"
    return {**base, "kind": kind, "from": before, "to": to}


def sync_project(
    client: JiraClient,
    project: str,
    records: dict[str, dict[str, Any]],
    state: dict[str, Any],
    base_url: str,
    now: datetime | None = None,
    target_field: str = DEFAULT_TARGET_FIELD,
    changes: list[dict[str, Any]] | None = None,
) -> ProjectSync:
    """Update ``records`` (id -> record) and ``state`` for one project, in place; append what changed to ``changes``.

    1. Forward: issues updated since the last completed forward pass, newest first (``ORDER BY updated DESC``). The
       window ``updated >= -Nm`` is relative to the server's clock, and N comes from this machine's clock read just
       before the search, so time zones and a steady clock offset never matter; ``OVERLAP_MINUTES`` covers drift.
       ``lastSyncAt`` only moves when the pass finished. A budget stop keeps the unfetched page token with the exact
       JQL and the next run continues there, so the same tickets are not fetched again and older updates in the
       window are not skipped. Re-applying a page is safe: an unchanged ticket is not written twice.
    2. Open tickets, once per copy: every ticket still to do or in progress, newest first, so the tickets people
       reconcile are in a new copy first.
    3. Backfill: issues below the lowest key held, newest first, until the project is complete.
    """
    if not PROJECT_KEY.fullmatch(project):
        raise JiraError(f"not a Jira project key: {project!r}")
    started = now or datetime.now(UTC)  # read here, per project: an earlier project may have taken an hour
    retrieved = _iso(started)
    fields = f"{SYNC_FIELDS},{target_field}" if target_field else SYNC_FIELDS
    res = ProjectSync(project)
    phase = "forward"
    since: datetime | None = None

    def keep(issue: dict[str, Any]) -> str:
        key = str(issue.get("key") or "")
        if not ISSUE_KEY.fullmatch(key) or not key.startswith(project + "-"):
            return ""
        prev = records.get(f"jira-{key}")
        fields_now = issue.get("fields") or {}
        total_now = int(
            (_obj(fields_now.get("comment")) if isinstance(fields_now.get("comment"), dict) else {}).get("total") or 0
        )
        if (
            prev
            and prev.get("updated") == fields_now.get("updated")
            and prev.get("status") == _obj(fields_now.get("status")).get("name")
            and prev.get("resolution") == _obj(fields_now.get("resolution")).get("name")
            and prev.get("fixVersions") == _names(fields_now.get("fixVersions"))
            and prev.get("comments") == prev.get("commentsTotal")
            and int(prev.get("commentsTotal") or 0) >= total_now
        ):
            res.fetched += 1  # unchanged since it was kept whole (the open pass and the backfill both meet it)
            return key
        # a budget that runs out here raises before the ticket is kept, so the next run fetches it whole
        issue = with_all_comments(client, key, issue)
        rec = issue_to_record(issue, base_url, project, [], "sync", retrieved, target_field, SYNC_MAX_TEXT)
        if changes is not None:
            event = change_event(records.get(rec["id"]), rec, phase, since)
            if event:
                changes.append(event)
        records[rec["id"]] = rec
        res.fetched += 1
        return key

    if int(state.get("scrubVersion") or 1) < SCRUB_VERSION:  # offline: what the newer anonymiser finds goes now
        for rec in records.values():
            rec["text"] = scrub_handles(scrub(str(rec.get("text") or "")))
            rec["title"] = scrub_handles(scrub(str(rec.get("title") or "")))
        state["scrubVersion"] = SCRUB_VERSION
    if int(state.get("textVersion") or 1) < TEXT_VERSION:
        if state.get("lowestKey") or state.get(
            "complete"
        ):  # a copy made before: refetch every ticket once, newest first
            state["complete"] = False
            state.pop("lowestKey", None)
        state["textVersion"] = TEXT_VERSION
    lowest = str(state.get("lowestKey") or "")
    if not (ISSUE_KEY.fullmatch(lowest) and lowest.startswith(project + "-")):
        state.pop("lowestKey", None)  # foreign or malformed: restart the backfill from the top
    last = _parse_iso(state.get("lastSyncAt")) if state.get("lastSyncAt") else None
    try:
        if last is not None:
            since = last - timedelta(minutes=OVERLAP_MINUTES)
            minutes = max(0, -int(-(started - last).total_seconds() // 60)) + OVERLAP_MINUTES  # rounded up
            jql = f"project = {project} AND updated >= -{minutes}m ORDER BY updated DESC"
            resume = state.get("forwardResume")
            page_token = None
            if isinstance(resume, dict) and resume.get("jql") == jql and isinstance(resume.get("token"), str):
                page_token = resume["token"]
            try:
                for issue in client.search(jql, fields, page_token=page_token):
                    keep(issue)
            except BudgetExhausted:
                token = client.stats.resume_token
                if token:
                    state["forwardResume"] = {"jql": jql, "token": token}
                raise
            state.pop("forwardResume", None)
            state["lastSyncAt"] = retrieved  # the forward pass finished: changes from here on
        else:
            state["lastSyncAt"] = retrieved  # first run: no forward window yet
        if not state.get("complete") and not state.get("openDone"):
            phase = "open"
            _open_pass(client, project, fields, state, keep)
        if not state.get("complete"):
            phase = "backfill"
            _backfill(client, project, fields, records, state, keep, res)
    except BudgetExhausted:
        res.stopped = "budget"
    except JiraError as exc:
        res.error = str(exc)[:400]
    res.complete = bool(state.get("complete"))
    res.total = len(records)
    return res


def with_all_comments(client: JiraClient, key: str, issue: dict[str, Any]) -> dict[str, Any]:
    """The issue with every comment (up to ``MAX_COMMENTS``): a search returns a ticket's latest comments only, so
    when its ``total`` is larger the rest come from the issue's paged comment endpoint, oldest first."""
    fields = issue.get("fields") or {}
    raw = fields.get("comment")
    field: dict[str, Any] = raw if isinstance(raw, dict) else {}
    got = [c for c in field.get("comments") or [] if isinstance(c, dict)]
    total = int(field.get("total") or len(got))
    if total <= len(got) or not ISSUE_KEY.fullmatch(key):
        return issue
    comments: list[dict[str, Any]] = []
    start = 0
    while start < min(total, MAX_COMMENTS):
        page = client.get(
            f"/rest/api/3/issue/{key}/comment", {"startAt": start, "maxResults": COMMENT_PAGE, "orderBy": "created"}
        )
        client.stats.comment_pages += 1
        batch = [c for c in (page.get("comments") or []) if isinstance(c, dict)] if isinstance(page, dict) else []
        if not batch:
            break
        comments.extend(batch)
        start += len(batch)
        total = max(total, int(page.get("total") or 0)) if isinstance(page, dict) else total
    seen = {str(c.get("id")) for c in comments if c.get("id") is not None}
    comments += [c for c in got if c.get("id") is None or str(c.get("id")) not in seen]  # newer than the paging
    comments.sort(key=lambda c: str(c.get("created") or ""))
    return {**issue, "fields": {**fields, "comment": {**field, "comments": comments[-MAX_COMMENTS:], "total": total}}}


def _open_pass(
    client: JiraClient,
    project: str,
    fields: str,
    state: dict[str, Any],
    keep: Callable[[dict[str, Any]], str],
) -> None:
    """Every open ticket, newest first, resuming below the lowest key fetched when a budget stopped the last run."""
    anchor = str(state.get("openLowestKey") or "")
    if not (ISSUE_KEY.fullmatch(anchor) and anchor.startswith(project + "-")):
        anchor = ""
    below = f" AND key < {anchor}" if anchor else ""
    try:
        for issue in client.search(f"project = {project} AND {OPEN_JQL}{below} ORDER BY key DESC", fields):
            key = keep(issue)
            low = str(state.get("openLowestKey") or "")
            if key and (not low or key_number(key) < key_number(low)):
                state["openLowestKey"] = key
    except BudgetExhausted:
        raise
    except JiraError as exc:
        if not (anchor and "400" in str(exc)):
            raise
        # the key is gone (moved or deleted): the backfill reaches every ticket anyway, so the open pass ends here
    state["openDone"] = True
    state.pop("openLowestKey", None)


def _backfill(
    client: JiraClient,
    project: str,
    fields: str,
    records: dict[str, dict[str, Any]],
    state: dict[str, Any],
    keep: Callable[[dict[str, Any]], str],
    res: ProjectSync,
) -> None:
    """Older issues by key. If the server rejects the lowest key held (moved or deleted since), resume below the
    next keys held instead; the few tickets fetched twice are simply refreshed."""
    held = sorted(
        (k for r in records.values() if (k := str(r.get("id", "")).removeprefix("jira-")).startswith(project + "-")),
        key=key_number,
    )
    lowest = str(state.get("lowestKey") or "")
    anchors = [lowest] if lowest else [""]
    if lowest:
        anchors += [k for k in held if key_number(k) > key_number(lowest)][:4]
    for i, anchor in enumerate(anchors):
        if anchor:
            state["lowestKey"] = anchor  # a rejected key is not kept: the next run starts from one that worked
        below = f" AND key < {anchor}" if anchor else ""
        try:
            for issue in client.search(f"project = {project}{below} ORDER BY key DESC", fields):
                key = keep(issue)
                if key and (not state.get("lowestKey") or key_number(key) < key_number(str(state["lowestKey"]))):
                    state["lowestKey"] = key
        except BudgetExhausted:
            raise
        except JiraError as exc:
            if anchor and i + 1 < len(anchors) and "400" in str(exc):
                res.error = None
                continue
            raise
        state["complete"] = True
        return


def sync_projects(
    client: JiraClient,
    projects: list[str],
    data_dir: Path,
    base_url: str,
    now: datetime | None = None,
    target_field: str = DEFAULT_TARGET_FIELD,
) -> dict[str, Any]:
    """Sync each project in turn, writing its shard and the state after every project so progress is never lost."""
    with sync_lock(data_dir):
        return sync_projects_locked(client, projects, data_dir, base_url, now, target_field)


_THREAD_LOCK = threading.Lock()


@contextlib.contextmanager
def sync_lock(data_dir: Path) -> Iterator[None]:
    """One sync per data folder at a time: two would double the load on the server and race on the same files.
    A thread lock covers this process (the service's background sync and a tool call); ``flock`` covers others."""
    if not _THREAD_LOCK.acquire(blocking=False):
        raise JiraError("another Jira sync is running in this process; try again when it finishes")
    try:
        try:
            import fcntl
        except ImportError:  # pragma: no cover - Windows: in-process lock only
            yield
            return
        with open(jira_dir(data_dir) / ".sync.lock", "a", encoding="utf-8") as fh:
            try:
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise JiraError("another Jira sync is running on this data folder; try again when it finishes") from exc
            try:
                yield
            finally:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
    finally:
        _THREAD_LOCK.release()


def sync_running(data_dir: Path) -> bool:
    """True while another process or thread holds the sync lock for this data folder."""
    if _THREAD_LOCK.locked():
        return True
    lock = data_dir / "jira" / ".sync.lock"
    if not lock.is_file():
        return False
    try:
        import fcntl
    except ImportError:  # pragma: no cover
        return False
    with open(lock, "a", encoding="utf-8") as fh:
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
    return False


def _shard_sha(data_dir: Path, project: str) -> str | None:
    from kube_noob.sources.corpus import read_manifest

    entry = (read_manifest(data_dir).get("shards") or {}).get(shard_name(project)) or {}
    return entry.get("sha256") if isinstance(entry, dict) else None


def sync_projects_locked(
    client: JiraClient,
    projects: list[str],
    data_dir: Path,
    base_url: str,
    now: datetime | None = None,
    target_field: str = DEFAULT_TARGET_FIELD,
) -> dict[str, Any]:
    from kube_noob.sources.corpus import write_shard

    state = load_state(data_dir)
    per = state.setdefault("projects", {})
    state["baseUrl"] = base_url
    results: list[dict[str, Any]] = []
    all_records: list[dict[str, Any]] = []
    changed: dict[str, int] = {}
    for project in projects:
        records = load_shard(data_dir, project)
        loaded = len(records)
        current = per.get(project)
        if not isinstance(current, dict) or current.get("shardSha256") != _shard_sha(data_dir, project):
            # no state, or the shard was replaced since (corpus import, an older kube-noob): derive it from the copy
            per[project] = state_from_records(records, project) if records else {}
        changes: list[dict[str, Any]] = []
        res = sync_project(client, project, records, per[project], base_url, now, target_field, changes)
        if loaded and len(records) < loaded:
            raise JiraError(
                f"{project}: refusing to replace {loaded} stored tickets with {len(records)}. "
                "A sync only adds or refreshes a ticket; a smaller shard would destroy the copy."
            )
        if changes:
            append_changes(data_dir, changes)
            for c in changes:
                changed[c["kind"]] = changed.get(c["kind"], 0) + 1
        if records:
            ordered = sorted(records.values(), key=lambda r: -key_number(str(r["id"]).removeprefix("jira-")))
            entry = write_shard(data_dir, shard_name(project), ordered)
            per[project]["shardSha256"] = entry["sha256"]
            all_records.extend(ordered)
        per[project]["total"] = res.total
        save_state(data_dir, state)
        results.append(res.as_dict())
        if res.stopped == "budget":
            break
    done = {r["project"] for r in results}
    skipped = [p for p in projects if p not in done]
    return {
        "projects": results,
        "skipped": skipped,
        "requests": client.stats.requests,
        "commentRequests": client.stats.comment_pages,
        "retries": client.stats.retries,
        "stoppedBy": "budget" if any(r.get("stopped") == "budget" for r in results) else None,
        "changes": dict(sorted(changed.items())),
        "records": all_records,
    }


def changes_path(data_dir: Path) -> Path:
    from kube_noob.ticket_changes import changes_path as path

    return path(data_dir)


def append_changes(data_dir: Path, events: list[dict[str, Any]]) -> None:
    """Add change events to ``jira/changes.jsonl`` (owner-only; newest last; at most ``MAX_CHANGES`` lines)."""
    path = changes_path(data_dir)
    jira_dir(data_dir)
    lines: list[str] = []
    if path.is_file():
        with path.open(encoding="utf-8") as fh:
            lines = fh.readlines()
    lines += [json.dumps(e, sort_keys=True) + "\n" for e in events]
    lines = lines[-MAX_CHANGES:]
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".changes.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.writelines(lines)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


# ---------------------------------------------------------------------------------------------------------------------
# Running a sync: the CLI (`kube-noob corpus jira`) and the background sync in `kube-noob serve`.


def jira_http(settings: Any, base_url: str) -> httpx.Client:
    """An HTTP client that can only talk to ``base_url``'s host over https: GET, plus POST to the search endpoint
    (long JQL). Built on the single outbound choke point, so the offline lock and proxies apply as everywhere."""
    from kube_noob.errors import DomainNotAllowedError
    from kube_noob.net import Purpose, host_allowed, http_client

    host = httpx.URL(base_url).host
    if not host_allowed(host, list(settings.web.allowed_domains)):
        raise DomainNotAllowedError(f"{host} (add it to web.allowedDomains to sync from it)")
    client = http_client(settings, Purpose.SOURCES, allow_sources=True, timeout=60)

    def _guard(request: httpx.Request) -> None:
        if request.url.scheme != "https" or request.url.host != host:
            raise DomainNotAllowedError(f"{request.url.host} (the Jira sync only reaches {host})")
        if request.method != "GET" and not (request.method == "POST" and request.url.path == "/rest/api/3/search/jql"):
            raise DomainNotAllowedError(f"{request.method} {request.url.path} (the Jira sync only reads)")

    hooks = client.event_hooks
    client.event_hooks = {"request": [*hooks.get("request", []), _guard], "response": hooks.get("response", [])}
    return client


def run_sync(
    settings: Any,
    projects: str | None = None,
    max_requests: int | None = None,
    auth: tuple[str, str] | None = None,
    now: datetime | None = None,
    http: httpx.Client | None = None,
) -> dict[str, Any]:
    """Sync the chosen projects into ``settings.data_dir``, write per-project insights, and rebuild the ticket index.
    Returns a summary without the records."""
    from kube_noob import tickets
    from kube_noob.sources.corpus import write_shard

    base_url = settings.jira.base_url
    spec = projects if projects is not None else settings.jira.projects
    budget = max_requests if max_requests is not None else settings.jira.max_requests
    now = now or datetime.now(UTC)  # stamps the insights; projects read the clock themselves
    own = http is None
    with sync_lock(settings.data_dir):  # before the first request: a second sync must not add load, even briefly
        client_http = http if http is not None else jira_http(settings, base_url)
        try:
            client = JiraClient(client_http, base_url, auth=auth, max_requests=budget)
            available = client.projects()
            chosen = select_projects(spec, available)
            # no fixed `now`: each project reads the clock when its forward pass starts
            out = sync_projects_locked(client, chosen, settings.data_dir, base_url, None)
        finally:
            if own:
                client_http.close()
    records = out.pop("records")
    by_project: dict[str, list[dict[str, Any]]] = {}
    for r in records:
        by_project.setdefault(str(r["sourceId"]).removeprefix("jira:"), []).append(r)
    stamp = _iso(now)
    insight_records = []
    for project, recs in sorted(by_project.items()):
        ins = insights(recs, project)
        insight_records.append(
            {
                "id": f"insights-jira-{project.lower()}",
                "title": f"{project} issue insights",
                "text": insights_markdown(ins, stamp, "all versions"),
                "url": f"{base_url}/browse/{project}",
                "sourceId": f"jira-insights:{project}",
                "license": "aggregate statistics derived by kube-noob",
                "redistributable": True,
                "retrievedAt": stamp,
            }
        )
    if insight_records:
        write_shard(settings.data_dir, "jira-insights", insight_records)
    index = tickets.stats(settings.data_dir)
    out.update(
        {
            "baseUrl": base_url,
            "visibleProjects": len(available),
            "selected": chosen,
            "budget": budget,
            "index": {k: index[k] for k in ("tickets", "asOf", "byVerdict")} if index else None,
        }
    )
    return out


def start_background(settings: Any, rng: random.Random | None = None) -> Any:
    """Keep the copy current from ``kube-noob serve``: a first run after a random 30 s to 10 min (pods that start
    together do not reach Jira together), then every ``jira.interval_hours`` +/- 10%."""
    import logging
    import threading

    from kube_noob.sources.pacing import jittered_interval, start_delay

    log = logging.getLogger("kube_noob.jira")
    stop = threading.Event()
    r = rng or random.Random()  # noqa: S311 - pacing, not crypto
    first = start_delay(r)

    def loop() -> None:
        if stop.wait(first):
            return
        while not stop.is_set():
            try:
                out = run_sync(settings)
                fetched = sum(int(p.get("fetched") or 0) for p in out["projects"])
                log.info(
                    "jira sync: %d tickets fetched in %d requests; %s",
                    fetched,
                    out["requests"],
                    "budget reached, resumes next run" if out.get("stoppedBy") else "up to date",
                )
            except Exception:  # one failed run must not stop the service
                log.exception("jira sync failed")
            stop.wait(jittered_interval(settings.jira.interval_hours * 3600, r))

    log.debug("jira sync: first run in %d s, then every %s h +/- 10%%", first, settings.jira.interval_hours)
    threading.Thread(target=loop, name="kube-noob-jira-sync", daemon=True).start()
    stop.first_delay = first  # type: ignore[attr-defined]  # for the operator log and tests
    return stop
