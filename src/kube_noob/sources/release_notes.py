"""Reported issues from the OpenShift release notes: known issues per minor release and the issues each update fixed.

Source: the AsciiDoc of the release notes in github.com/openshift/openshift-docs (Apache-2.0), branch
``enterprise-<minor>``: ``modules/rn-ocp-release-notes-known-issues.adoc`` (open issues in the release),
``modules/rn-ocp-release-notes-fixed-issues.adoc`` (fixed in the .0 release) and ``modules/zstream-<minor>-<n>.adoc``
(fixed in each update). Every record keeps the issue id (OCPBUGS-..., RHEL-..., OSSM-...), its tracker link and the
exact source file, so an answer can always cite both. A known issue gets ``fixedIn`` when a later update or minor
release lists the same id as fixed.

``fetch`` needs git and the network (maintainers, CI); ``parse_release`` works on files already on disk (tests).
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO = "openshift/openshift-docs"
LICENSE = "Apache-2.0"
ATTRIBUTION = "OpenShift release notes (c) Red Hat, Inc. and contributors, Apache-2.0, https://github.com/openshift/openshift-docs"
KNOWN = "modules/rn-ocp-release-notes-known-issues.adoc"
FIXED = "modules/rn-ocp-release-notes-fixed-issues.adoc"
ATTRIBUTES = "_attributes/common-attributes.adoc"
#: 4.19 and earlier keep the whole release notes in one book file instead of the ``modules/rn-ocp-*`` extracts:
#: the known issues, the ``.0`` fixed issues and the older updates' bug fixes are all sections of it. Reading only
#: the modules gave those releases their fixed issues from the z-stream modules alone and no known issues at all,
#: which is an index that answers "nothing reported" for a release whose notes report plenty.
BOOK = "release_notes/ocp-{dash}-release-notes.adoc"

_ID = re.compile(r"browse/([A-Z][A-Z0-9]+-\d+)")
_BARE_ID = re.compile(r"\b((?:OCPBUGS|RHEL|OSSM|NE|OCPNODE|HOSTEDCP|MCO|CNV|OCPEDGE|SDN|CORENET)-\d+)\b")
_ATTR_DEF = re.compile(r"^:([A-Za-z0-9_-]+):\s*(.*?)\s*$", re.MULTILINE)
_ATTR_USE = re.compile(r"\{([A-Za-z0-9_-]+)\}")
_ISSUED = re.compile(r"^Issued:\s*(\d{1,2} \w+ \d{4})", re.MULTILINE)
#: ``zstream-4-19-19.adoc`` and, since the notes were split further, ``zstream-4-19-19-bug-fixes.adoc`` beside
#: ``-about`` (which carries the Issued date) and ``-updating``. Matching only the first spelling silently skipped
#: every update of 4.14, 4.15, 4.18 and 4.19 that had been split.
_ZSTREAM = re.compile(r"zstream-(\d+)-(\d+)-(\d+)(-bug-fixes)?\.adoc$")
#: The anchor the docs build puts before each update's section in a book file: ``[id="ocp-4-14-58_{context}"]``.
_BLOCK_ID = re.compile(r'^\[id="ocp-(\d+)-(\d+)-(\d+)_', re.MULTILINE)
#: Where the asynchronous-errata part of a book begins. In 4.15 it is a level-2 heading, so the known-issues
#: section ends at it on its own; in 4.14, 4.18 and 4.19 it is an include whose own heading lives in the included
#: module, so "Known issues" is the LAST heading of its level and ran to the end of the file -- which turned every
#: fixed-issue bullet of every update into a known issue of the .0 release. Bounding on the marker is what keeps
#: a fixed bug from being reported as still open.
_ERRATA_START = re.compile(
    r"^(?:include::modules/(?:rn-async-errata|ocp-release-asynch-errata-updates|zstream-)|"
    r'\[id="ocp-\d+-\d+-\d+_|={1,3} Asynchronous errata)',
    re.MULTILINE,
)
_SENTENCE = re.compile(r"(?<=[.!?])\s+(?=[A-Z(`])")
#: A credential-shaped environment-variable name. The release notes quote shell examples
#: (``-H "Authorization: Bearer $API_TOKEN"``), and the Claude plugin bundles this index as data: a credential
#: variable name anywhere in the plugin copy is refused (``tests/test_plugin.py::
#: test_bundle_names_no_credential_variables``), because a reviewer scanning the bundle cannot tell a vendor's
#: placeholder from a variable kube-noob itself reads. Only the name is replaced, by ``CREDENTIAL_VARIABLE``;
#: every record still cites the exact source file and commit, so the original wording is one link away.
_CREDENTIAL_VAR = re.compile(r"\b[A-Z][A-Z0-9_]*_(?:TOKEN|API_KEY|SECRET_ACCESS_KEY|ACCESS_KEY_ID)\b")


@dataclass(frozen=True)
class Release:
    """One minor release's release-notes files on disk (the branch root of openshift-docs)."""

    minor: str
    root: Path
    commit: str = ""


def parse_attributes(text: str) -> dict[str, str]:
    raw = {m.group(1): m.group(2) for m in _ATTR_DEF.finditer(text)}
    resolved: dict[str, str] = {}
    for _ in range(5):  # attributes refer to other attributes a few levels deep
        known = dict(raw)
        for k, v in known.items():
            resolved[k] = _ATTR_USE.sub(lambda m, known=known: known.get(m.group(1), m.group(0)), v)
        raw = dict(resolved)
    return resolved


def clean(text: str, attrs: dict[str, str]) -> str:
    """AsciiDoc to plain sentences: attributes expanded, links and cross-references reduced to their text."""
    for _ in range(3):  # attribute values can contain attributes ({nbsp} inside a product name)
        text = _ATTR_USE.sub(lambda m: attrs.get(m.group(1), m.group(0)), text)
    text = _ATTR_USE.sub(lambda m: m.group(1), text)
    text = re.sub(r"(?:link|xref):\S+?\[([^\]]*)\]", r"\1", text)
    text = re.sub(r"https?://\S+?\[([^\]]*)\]", r"\1", text)
    lines = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s in {"+", "--", "----", "====", "...."} or re.fullmatch(r"\[[^\]]*\]", s) or s.startswith("//"):
            continue
        lines.append(re.sub(r"^\*{2,}\s+", "- ", s))
    out = " ".join(lines)
    out = re.sub(r"(?<![\w`])\*([^*\n]+?)\*(?![\w`])", r"\1", out)  # *bold* -> bold
    out = re.sub(r"\s+", " ", out).strip()
    return out.replace(" ()", "").replace("( )", "").strip()


def bullets(section: str) -> list[str]:
    """Top-level list items (lines starting with "* "), each with its continuation lines."""
    items: list[list[str]] = []
    for line in section.splitlines():
        if line.startswith("* "):
            items.append([line[2:]])
        elif re.match(r"^(=+ |\[id=)", line):
            if items:
                items.append([])  # a heading ends the current item
        elif items and items[-1]:
            items[-1].append(line)
    return ["\n".join(i) for i in items if i]


def section(text: str, heading: str) -> str:
    """The body of the first section whose title is ``heading`` (any level), up to the next heading of that level."""
    m = re.search(rf"^(=+) {re.escape(heading)}\s*$", text, re.MULTILINE)
    if not m:
        return ""
    level = len(m.group(1))
    rest = text[m.end() :]
    end = re.search(rf"^={{1,{level}}} \S", rest, re.MULTILINE)
    return rest[: end.start()] if end else rest


def issue_ids(item: str) -> list[str]:
    ids = _ID.findall(item) or _BARE_ID.findall(item)
    return list(dict.fromkeys(ids))


def _issued(text: str) -> str | None:
    m = _ISSUED.search(text)
    if not m:
        return None
    try:
        return datetime.strptime(m.group(1), "%d %B %Y").date().isoformat()
    except ValueError:
        return None


def _summary(text: str) -> str:
    first = _SENTENCE.split(text, maxsplit=1)[0]
    return first if len(first) <= 280 else first[:277].rsplit(" ", 1)[0] + "..."


def _workaround(text: str) -> str | None:
    for sentence in _SENTENCE.split(text):
        if re.match(r"(?i)(as a workaround|to work around|you can avoid|to avoid this|workaround:)", sentence):
            return sentence
    if re.search(r"(?i)there is no (supported )?workaround", text):
        return "There is no supported workaround."
    return None


def _record(
    kind: str, item: str, attrs: dict[str, str], minor: str, version: str, source: str, issued: str | None
) -> dict[str, Any] | None:
    ids = issue_ids(item)
    if not ids:
        return None
    text = _CREDENTIAL_VAR.sub("CREDENTIAL_VARIABLE", clean(item, attrs))
    if len(text) < 40:
        return None
    return {
        "id": ids[0],
        "ids": ids,
        "kind": kind,
        "product": "openshift",
        "minor": minor,
        "version": version,
        "issued": issued,
        "summary": _summary(text),
        "workaround": _workaround(text) if kind == "known" else None,
        "text": text,
        "url": f"https://redhat.atlassian.net/browse/{ids[0]}",
        "source": source,
    }


def parse_release(rel: Release) -> list[dict[str, Any]]:
    root = rel.root
    attr_file = root / ATTRIBUTES
    attrs = parse_attributes(attr_file.read_text(encoding="utf-8")) if attr_file.is_file() else {}
    attrs.update({"product-title": "OpenShift Container Platform", "product-version": rel.minor, "nbsp": " "})
    blob = f"https://github.com/{REPO}/blob/{rel.commit or 'enterprise-' + rel.minor}"
    out: list[dict[str, Any]] = []

    known = root / KNOWN
    if known.is_file():
        text = known.read_text(encoding="utf-8")
        body = text.split("= Known issues", 1)[-1]
        for item in bullets(body):
            rec = _record("known", item, attrs, rel.minor, rel.minor, f"{blob}/{KNOWN}", None)
            if rec:
                out.append(rec)

    fixed = root / FIXED
    if fixed.is_file():
        text = fixed.read_text(encoding="utf-8")
        for item in bullets(text):
            rec = _record("fixed", item, attrs, rel.minor, f"{rel.minor}.0", f"{blob}/{FIXED}", None)
            if rec:
                out.append(rec)

    for f in sorted((root / "modules").glob(f"zstream-{rel.minor.replace('.', '-')}-*.adoc")):
        m = _ZSTREAM.search(f.name)
        if not m:
            continue
        version = f"{m.group(1)}.{m.group(2)}.{m.group(3)}"
        text = f.read_text(encoding="utf-8")
        # A split update keeps its Issued date in the sibling ``-about`` file; without it every record of those
        # updates would carry no date while its neighbours from a one-file update carry one.
        issued = _issued(text) or (_issued_from_about(f) if m.group(4) else None)
        body = section(text, "Fixed issues") or section(text, "Bug fixes")
        for item in bullets(body):
            rec = _record("fixed", item, attrs, rel.minor, version, f"{blob}/modules/{f.name}", issued)
            if rec:
                out.append(rec)
    out.extend(_parse_book(rel, attrs, blob))
    return out


def _issued_from_about(bug_fixes: Path) -> str | None:
    about = bug_fixes.with_name(bug_fixes.name.replace("-bug-fixes.adoc", "-about.adoc"))
    return _issued(about.read_text(encoding="utf-8")) if about.is_file() else None


def inline_updates(text: str, minor: str) -> list[tuple[str, str]]:
    """``(version, section text)`` for each update written into a book file rather than its own module.

    4.19 and earlier moved only their newest updates into ``modules/zstream-*``; the rest stay as level-3
    sections of the book, each opened by the anchor the docs build writes (``[id="ocp-4-14-58_{context}"]``).
    The anchor is the delimiter because it is generated, unlike the heading text, which is advisory prose.
    """
    dash = minor.replace(".", "-")
    starts = [m for m in _BLOCK_ID.finditer(text) if f"{m.group(1)}-{m.group(2)}" == dash]
    out: list[tuple[str, str]] = []
    for n, m in enumerate(starts):
        if n + 1 < len(starts):
            end = starts[n + 1].start()
        else:  # the oldest update: stop at the next part of the book, never run to the end of the file
            nxt = re.search(r"^={1,2} \S", text[m.end() :], re.MULTILINE)
            end = m.end() + nxt.start() if nxt else len(text)
        out.append((f"{m.group(1)}.{m.group(2)}.{m.group(3)}", text[m.start() : end]))
    return out


def known_issues_body(text: str) -> str:
    """The known-issues section of a book, ending where the asynchronous-errata part begins."""
    body = section(text, "Known issues")
    cut = _ERRATA_START.search(body)
    return body[: cut.start()] if cut else body


def _parse_book(rel: Release, attrs: dict[str, str], blob: str) -> list[dict[str, Any]]:
    """The known issues, the ``.0`` fixed issues and the inline updates of a release whose notes are one file."""
    dash = rel.minor.replace(".", "-")
    book = rel.root / BOOK.format(dash=dash)
    if not book.is_file():
        return []
    text = book.read_text(encoding="utf-8")
    src = f"{blob}/{BOOK.format(dash=dash)}"
    out: list[dict[str, Any]] = []
    for item in bullets(known_issues_body(text)):
        rec = _record("known", item, attrs, rel.minor, rel.minor, src, None)
        if rec:
            out.append(rec)
    # The first "Bug fixes" section of a book is the one for the .0 release; every later one belongs to an update
    # and is read from that update's own block below, with that update's version and date.
    for item in bullets(section(text, "Bug fixes")):
        rec = _record("fixed", item, attrs, rel.minor, f"{rel.minor}.0", src, None)
        if rec:
            out.append(rec)
    for version, block in inline_updates(text, rel.minor):
        issued = _issued(block)
        for item in bullets(section(block, "Bug fixes")):
            rec = _record("fixed", item, attrs, rel.minor, version, src, issued)
            if rec:
                out.append(rec)
    return out


def _vkey(version: str) -> tuple[int, ...]:
    return tuple(int(p) for p in re.findall(r"\d+", version))


def link_fixes(records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Give each known issue the earliest release that lists one of its ids as fixed, and drop duplicate fixes."""
    recs = list(records)
    fixed_in: dict[str, str] = {}
    for r in recs:
        if r["kind"] == "fixed":
            for i in r["ids"]:
                if i not in fixed_in or _vkey(r["version"]) < _vkey(fixed_in[i]):
                    fixed_in[i] = r["version"]
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for r in recs:
        key = (r["kind"], r["id"], r["version"])
        if key in seen:
            continue
        seen.add(key)
        if r["kind"] == "known":
            later = [fixed_in[i] for i in r["ids"] if i in fixed_in and _vkey(fixed_in[i]) >= _vkey(r["minor"])]
            out.append({**r, "fixedIn": min(later, key=_vkey) if later else None})
        else:
            out.append(r)
    return out


def fetch(minors: Iterable[str], workdir: Path) -> tuple[list[dict[str, Any]], dict[str, str], dict[str, str]]:
    """Sparse-clone each enterprise-<minor> branch and parse it.

    Returns the records, the commit per minor, and the date each minor was retrieved. The retrieval date is per
    minor and not one date for the run: an index that spans nine releases is refreshed a few at a time, and one
    global date would then claim a freshness the older minors do not have. ``snapshot`` writes both into the
    file so every answer can cite the branch URL and the day it was read, per release.
    """
    from kube_noob.sources.git_ingest import _git

    records: list[dict[str, Any]] = []
    commits: dict[str, str] = {}
    retrieved: dict[str, str] = {}
    from kube_noob.sources.pacing import pause

    for i, minor in enumerate(minors):
        dest = workdir / f"openshift-docs-{minor}"
        if not dest.exists():
            if i:
                pause()  # jittered gap between clones from the same host
            clone = ["clone", "--quiet", "--depth", "1", "--filter=blob:none", "--sparse", "--branch"]
            _git([*clone, f"enterprise-{minor}", f"https://github.com/{REPO}", str(dest)])
            dash = minor.replace(".", "-")
            _git(
                [
                    "sparse-checkout",
                    "set",
                    "--no-cone",
                    f"/{KNOWN}",
                    f"/{FIXED}",
                    f"/{ATTRIBUTES}",
                    f"/modules/zstream-{dash}-*.adoc",
                    f"/{BOOK.format(dash=dash)}",
                ],
                cwd=dest,
            )
        commits[minor] = _git(["rev-parse", "HEAD"], cwd=dest).strip()
        retrieved[minor] = datetime.now(UTC).date().isoformat()
        records.extend(parse_release(Release(minor, dest, commits[minor])))
    return link_fixes(records), commits, retrieved


def branch_url(minor: str, commit: str = "") -> str:
    """The URL an answer cites for one minor's release notes: the commit if there is one, the branch otherwise."""
    return f"https://github.com/{REPO}/tree/{commit or 'enterprise-' + minor}"


def minor_sources(commits: dict[str, str], retrieved: dict[str, str] | None = None) -> dict[str, dict[str, str]]:
    """Per minor: the branch, the commit, the URL and the day it was read. One global ``retrievedAt`` cannot say
    that 4.14 was read in March and 4.22 yesterday, and an index spanning nine releases will be refreshed that
    way, so the per-minor record is what the coverage statement quotes."""
    dates = retrieved or {}
    return {
        minor: {
            "branch": f"enterprise-{minor}",
            "commit": commit,
            "url": branch_url(minor, commit),
            "retrievedAt": dates.get(minor, ""),
        }
        for minor, commit in sorted(commits.items(), key=lambda kv: _vkey(kv[0]))
    }


def snapshot(
    records: list[dict[str, Any]], commits: dict[str, str], retrieved: dict[str, str] | None = None
) -> dict[str, Any]:
    dates = sorted(v for v in (retrieved or {}).values() if v)
    return {
        # The newest per-minor date, so a reader is never told the whole index is as fresh as its freshest part
        # is not what this says: `minors` below carries the real date for each one, and the coverage statement
        # quotes that rather than this.
        "retrievedAt": dates[-1] if dates else datetime.now(UTC).date().isoformat(),
        "source": f"https://github.com/{REPO}",
        "license": LICENSE,
        "attribution": ATTRIBUTION,
        "commits": commits,
        "minors": minor_sources(commits, retrieved),
        "records": records,
    }
