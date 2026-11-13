"""Ingest documentation from public Git repositories with full provenance.

Uses ``git`` (shallow, blobless, sparse) so only the selected paths are downloaded. Each file becomes a corpus record
with repo, commit SHA, path, permalink and SPDX license. Supports Markdown, AsciiDoc, plain text, YAML/JSON/HCL
examples (Terraform, Ansible, Helm charts).
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from kube_noob.errors import KubeNoobError
from kube_noob.sources.registry import GitSource

MAX_FILE_BYTES = 400_000
_HUGO_SHORTCODE = re.compile(r"\{\{[<%].*?[%>]\}\}", re.DOTALL)
_ADOC_ATTR = re.compile(r"^:[\w-]+:.*$", re.MULTILINE)
_ADOC_COMMENT = re.compile(r"^//.*$", re.MULTILINE)
_ADOC_INCLUDE = re.compile(r"^include::.*$", re.MULTILINE)
_ADOC_BLOCK_ATTR = re.compile(r"^\[[\w\s,.=\"'#-]*\]\s*$", re.MULTILINE)
_FRONT = re.compile(r"\A---\n.*?\n---\n", re.DOTALL)
_MDX_IMPORT_EXPORT = re.compile(r"^(?:import|export)\s.+$", re.MULTILINE)
_MDX_SELF_CLOSING = re.compile(r"^\s*<[A-Z][A-Za-z0-9.]*(?:\s[^>]*)?/>\s*$", re.MULTILINE)


def _git(args: list[str], cwd: Path | None = None, timeout: int = 600) -> str:
    git = shutil.which("git")
    if git is None:
        raise KubeNoobError("git is required for source ingestion")
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "/bin/false"}  # inherit proxy/CA settings
    proc = subprocess.run(
        [git, *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        env=env,
        stdin=subprocess.DEVNULL,
    )
    if proc.returncode != 0:
        raise KubeNoobError(f"git {' '.join(args[:2])} failed: {proc.stderr.strip()[:500]}")
    return proc.stdout


def _strip_mdx(text: str) -> str:
    """Drop MDX import/export lines and self-closing JSX components outside fenced code blocks."""
    parts = re.split(r"(^```.*?^```[^\n]*$)", text, flags=re.MULTILINE | re.DOTALL)
    for i in range(0, len(parts), 2):  # even indexes are prose, odd are fenced code
        parts[i] = _MDX_SELF_CLOSING.sub("", _MDX_IMPORT_EXPORT.sub("", parts[i]))
    return "".join(parts)


def clean_text(path: str, raw: str) -> tuple[str, str]:
    """Return (title, cleaned text)."""
    text = raw
    title = Path(path).stem.replace("-", " ").replace("_", " ")
    fm = _FRONT.match(text)
    if fm:
        m = re.search(r"^title:\s*[\"']?(.+?)[\"']?\s*$", fm.group(0), re.MULTILINE)
        if m:
            title = m.group(1)
        text = text[fm.end() :]
    if path.endswith(".adoc"):
        m = re.search(r"^=+\s+(.+)$", text, re.MULTILINE)
        if m:
            title = m.group(1).strip()
        text = _ADOC_ATTR.sub("", text)
        text = _ADOC_COMMENT.sub("", text)
        text = _ADOC_INCLUDE.sub("", text)
        text = _ADOC_BLOCK_ATTR.sub("", text)
        text = re.sub(r"^(=+)\s", lambda mm: "#" * len(mm.group(1)) + " ", text, flags=re.MULTILINE)
        text = text.replace("{product-title}", "OpenShift").replace("{rosa-short}", "ROSA")
    elif path.endswith((".md", ".mdx")):
        m = re.search(r"^#\s+(.+)$", text, re.MULTILINE)
        if m and not fm:
            title = m.group(1).strip()
        text = _HUGO_SHORTCODE.sub("", text)
        if path.endswith(".mdx"):
            text = _strip_mdx(text)
    elif path.endswith(".json"):
        try:
            obj = json.loads(raw)
            if isinstance(obj, dict) and obj.get("name"):
                title = str(obj["name"])
                text = "\n".join(f"{k}: {v}" for k, v in obj.items() if isinstance(v, str | int | float | bool))
                text += "\n\n```json\n" + json.dumps(obj, indent=1)[:8000] + "\n```"
        except json.JSONDecodeError:
            pass
    elif path.endswith((".yaml", ".yml", ".tf", ".hcl")):
        lang = "hcl" if path.endswith((".tf", ".hcl")) else "yaml"
        text = f"File {path}\n\n```{lang}\n{raw[:12000]}\n```"
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    return title.strip() or path, text


def _matches(path: str, includes: tuple[str, ...], excludes: tuple[str, ...]) -> bool:
    return any(fnmatch.fnmatch(path, g) for g in includes) and not any(fnmatch.fnmatch(path, g) for g in excludes)


def ingest(src: GitSource, workdir: Path | None = None, limit: int | None = None) -> Iterator[dict[str, Any]]:
    tmp_owner = tempfile.TemporaryDirectory(prefix="kube-noob-src-") if workdir is None else None
    base = Path(tmp_owner.name) if tmp_owner else workdir
    assert base is not None  # noqa: S101
    dest = base / src.source_id.replace(":", "_").replace("/", "_")
    try:
        if dest.exists():
            shutil.rmtree(dest)
        url = f"https://github.com/{src.repo}"
        clone = ["clone", "--quiet", "--depth", "1", "--filter=blob:none", "--sparse"]
        if src.ref:
            clone += ["--branch", src.ref]
        _git([*clone, url, str(dest)])
        _git(["sparse-checkout", "set", "--no-cone", *src.sparse_paths], cwd=dest)
        sha = _git(["rev-parse", "HEAD"], cwd=dest).strip()
        retrieved = datetime.now(UTC).isoformat(timespec="seconds")
        n = 0
        for f in sorted(dest.rglob("*")):
            if not f.is_file() or ".git" in f.parts:
                continue
            rel = f.relative_to(dest).as_posix()
            if not _matches(rel, src.include, src.exclude):
                continue
            if f.stat().st_size > MAX_FILE_BYTES:
                continue
            raw = f.read_text(encoding="utf-8", errors="replace")
            title, text = clean_text(rel, raw)
            if len(text) < src.min_chars:
                continue
            doc_id = f"{src.source_id.replace(':', '-')}/{rel}"
            yield {
                "id": re.sub(r"[^A-Za-z0-9._/-]", "-", doc_id),
                "title": title,
                "text": text,
                "url": f"https://github.com/{src.repo}/blob/{sha}/{rel}",
                "sourceId": src.source_id,
                "license": src.license,
                "redistributable": src.redistributable,
                "attribution": src.attribution,
                "repo": src.repo,
                "commit": sha,
                "path": rel,
                "retrievedAt": retrieved,
                "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                "version": src.ref or "default-branch",
            }
            n += 1
            if limit is not None and n >= limit:
                return
    finally:
        if tmp_owner is not None:
            tmp_owner.cleanup()
