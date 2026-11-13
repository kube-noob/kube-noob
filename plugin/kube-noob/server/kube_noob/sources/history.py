"""Release history ("identify the history of sources"): version timelines from Git tags.

``tags_with_dates`` uses a treeless bare clone (commit/tag objects only) so dates are exact without downloading
file contents. Output feeds the corpus so the agent can answer "when did Helm 4 ship?" from local data.
"""

from __future__ import annotations

import re
import shutil
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from kube_noob.sources.git_ingest import _git

_SEMVER_TAG = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)\Z")


def tags_with_dates(repo: str, workdir: Path | None = None) -> list[tuple[str, str]]:
    owner = tempfile.TemporaryDirectory(prefix="kube-noob-hist-") if workdir is None else None
    base = Path(owner.name) if owner else workdir
    assert base is not None  # noqa: S101
    dest = base / (repo.replace("/", "_") + ".git")
    try:
        if dest.exists():
            shutil.rmtree(dest)
        _git(["clone", "--quiet", "--bare", "--filter=tree:0", f"https://github.com/{repo}", str(dest)], timeout=1800)
        out = _git(
            ["for-each-ref", "--sort=creatordate", "--format=%(refname:short)|%(creatordate:short)", "refs/tags"],
            cwd=dest,
        )
        rows = []
        for line in out.splitlines():
            if "|" in line:
                tag, date = line.split("|", 1)
                rows.append((tag.strip(), date.strip()))
        return rows
    finally:
        if owner is not None:
            owner.cleanup()


def minor_timeline(tags: list[tuple[str, str]]) -> list[dict[str, Any]]:
    """First GA (x.y.0) date per minor plus latest patch."""
    minors: dict[tuple[int, int], dict[str, Any]] = {}
    for tag, date in tags:
        m = _SEMVER_TAG.match(tag)
        if not m:
            continue
        major, minor, patch = (int(g) for g in m.groups())
        key = (major, minor)
        cur = minors.setdefault(
            key,
            {
                "minor": f"{major}.{minor}",
                "ga": None,
                "gaTag": None,
                "latestPatch": None,
                "latestTag": None,
                "latestDate": None,
            },
        )
        if patch == 0 and (cur["ga"] is None or date < cur["ga"]):
            cur["ga"], cur["gaTag"] = date, tag
        if cur["latestPatch"] is None or patch > cur["latestPatch"]:
            cur["latestPatch"], cur["latestTag"], cur["latestDate"] = patch, tag, date
    return [minors[k] for k in sorted(minors)]


def timeline_record(name: str, repo: str, timeline: list[dict[str, Any]]) -> dict[str, Any]:
    lines = [
        f"# {name} release history",
        "",
        f"Derived from Git tags of https://github.com/{repo} (first x.y.0 tag date per minor version).",
        "",
        "| Minor | GA tag | GA date | Latest patch | Latest date |",
        "|---|---|---|---|---|",
    ]
    for t in timeline:
        lines.append(
            f"| {t['minor']} | {t['gaTag'] or '-'} | {t['ga'] or '-'} | {t['latestTag']} | {t['latestDate']} |"
        )
    return {
        "id": f"history-{name}",
        "title": f"{name} release history",
        "text": "\n".join(lines),
        "url": f"https://github.com/{repo}/tags",
        "sourceId": f"history:{name}",
        "license": "facts derived from public Git metadata",
        "redistributable": True,
        "retrievedAt": datetime.now(UTC).isoformat(timespec="seconds"),
        "timeline": timeline,
    }
