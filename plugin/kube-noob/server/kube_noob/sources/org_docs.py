"""Bring your own runbooks: index an organisation's Markdown, AsciiDoc and text docs offline.

`kube-noob corpus add-docs <dir> --source <name>` turns a folder (a cloned wiki or runbook repo) into a corpus shard.
The docs become searchable and citable next to the built-in knowledge, so answers use the team's own procedures.

- Local only: no network, allowed under the offline lock.
- Credential-looking content is masked before anything is stored, and the shard is marked non-redistributable, so
  `train export` never includes it unless the operator passes --include-restricted on purpose.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from kube_noob.learn.memory import mask_credentials
from kube_noob.sources.corpus import write_shard
from kube_noob.sources.git_ingest import clean_text

SUFFIXES = (".md", ".markdown", ".adoc", ".asciidoc", ".txt", ".rst")
MAX_FILES = 5000
MAX_FILE_BYTES = 2_000_000
_SOURCE = re.compile(r"^[a-z0-9][a-z0-9-]{0,40}\Z")


def _slug(rel: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", rel.lower()).strip("-")[:120] or "doc"


def ingest_org_docs(root: Path, data_dir: Path, source: str, base_url: str | None = None) -> dict[str, Any]:
    if not _SOURCE.match(source):
        raise ValueError("--source must be a short lowercase name such as 'platform-runbooks'")
    if not root.is_dir():
        raise FileNotFoundError(f"{root} is not a directory")
    records: list[dict[str, Any]] = []
    masked_files: list[str] = []
    skipped: list[dict[str, str]] = []
    now = datetime.now(UTC).isoformat(timespec="seconds")
    files = sorted(
        p
        for p in root.rglob("*")
        if p.is_file()
        and p.suffix.lower() in SUFFIXES
        and not any(part.startswith(".") for part in p.relative_to(root).parts)
    )
    if len(files) > MAX_FILES:
        raise ValueError(f"{len(files)} files under {root}; point at a narrower folder (limit {MAX_FILES})")
    for path in files:
        rel = path.relative_to(root).as_posix()
        if path.stat().st_size > MAX_FILE_BYTES:
            skipped.append({"file": rel, "reason": f"larger than {MAX_FILE_BYTES} bytes"})
            continue
        try:
            raw = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            skipped.append({"file": rel, "reason": f"unreadable: {exc}"})
            continue
        title, text = clean_text(rel.replace(".markdown", ".md").replace(".asciidoc", ".adoc"), raw)
        text, masked = mask_credentials(text)
        if masked:
            masked_files.append(rel)
        if len(text.strip()) < 40:
            skipped.append({"file": rel, "reason": "too little text"})
            continue
        records.append(
            {
                "id": f"org-{source}-{_slug(rel)}",
                "title": title,
                "text": text,
                "url": f"{base_url.rstrip('/')}/{rel}" if base_url else f"file:{rel}",
                "license": "internal",
                "sourceId": f"org:{source}",
                "redistributable": False,
                "retrievedAt": now,
            }
        )
    if not records:
        raise ValueError(f"no indexable {', '.join(SUFFIXES)} files under {root}")
    entry = write_shard(data_dir, f"org-{source}", records)
    return {"shard": entry["shard"], "records": len(records), "maskedFiles": masked_files, "skipped": skipped}
