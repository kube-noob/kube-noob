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

_ID = re.compile(r"browse/([A-Z][A-Z0-9]+-\d+)")
_BARE_ID = re.compile(r"\b((?:OCPBUGS|RHEL|OSSM|NE|OCPNODE|HOSTEDCP|MCO|CNV|OCPEDGE|SDN|CORENET)-\d+)\b")
_ATTR_DEF = re.compile(r"^:([A-Za-z0-9_-]+):\s*(.*?)\s*$", re.MULTILINE)
_ATTR_USE = re.compile(r"\{([A-Za-z0-9_-]+)\}")
_ISSUED = re.compile(r"^Issued:\s*(\d{1,2} \w+ \d{4})", re.MULTILINE)
_ZSTREAM = re.compile(r"zstream-(\d+)-(\d+)-(\d+)\.adoc$")
_SENTENCE = re.compile(r"(?<=[.!?])\s+(?=[A-Z(`])")


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
    text = clean(item, attrs)
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
        issued = _issued(text)
        body = section(text, "Fixed issues") or section(text, "Bug fixes")
        for item in bullets(body):
            rec = _record("fixed", item, attrs, rel.minor, version, f"{blob}/modules/{f.name}", issued)
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


def fetch(minors: Iterable[str], workdir: Path) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """Sparse-clone each enterprise-<minor> branch and parse it. Returns the records and the commit per minor."""
    from kube_noob.sources.git_ingest import _git

    records: list[dict[str, Any]] = []
    commits: dict[str, str] = {}
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
                ],
                cwd=dest,
            )
        commits[minor] = _git(["rev-parse", "HEAD"], cwd=dest).strip()
        records.extend(parse_release(Release(minor, dest, commits[minor])))
    return link_fixes(records), commits


def snapshot(records: list[dict[str, Any]], commits: dict[str, str]) -> dict[str, Any]:
    return {
        "retrievedAt": datetime.now(UTC).date().isoformat(),
        "source": f"https://github.com/{REPO}",
        "license": LICENSE,
        "attribution": ATTRIBUTION,
        "commits": commits,
        "records": records,
    }
