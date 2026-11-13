"""Corpus storage: JSONL shards plus a manifest with provenance, licenses and checksums."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from kube_noob.errors import KubeNoobError

REQUIRED = ("id", "title", "text", "sourceId", "license", "redistributable")
# A shard file bigger than this is written as `<shard>.jsonl`, `<shard>-2.jsonl`, ... so `db_bundle.MAX_MEMBER`
# (300_000_000) still accepts it. The two numbers are held together by a test. One record is never split.
PART_MAX = 250_000_000


class CorpusError(KubeNoobError):
    """A shard cannot be written, or would be written in a state that must not reach a bundle."""


def corpus_dir(data_dir: Path) -> Path:
    d = data_dir / "corpus"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _validate(rec: dict[str, Any]) -> None:
    missing = [k for k in REQUIRED if k not in rec]
    if missing:
        raise ValueError(f"corpus record {rec.get('id')!r} missing {missing}")
    if not isinstance(rec["redistributable"], bool):
        raise ValueError(f"corpus record {rec['id']!r}: redistributable must be a bool")


def write_shard(
    data_dir: Path, shard: str, records: list[dict[str, Any]], *, allow_empty: bool = False
) -> dict[str, Any]:
    """Atomically replace ``corpus/<shard>.jsonl`` and update the manifest.

    A refresh that produced no records is refused unless ``allow_empty``. A source yielding nothing means its
    upstream layout moved far more often than it means the source is genuinely empty, and the write is
    ``os.replace``: it would truncate the shard it is replacing to nothing and take the records with it. Refusing
    keeps the previous shard, and keeps the empty file out of the bundle, where a file with no lines passes every
    per-line check there is.
    """
    if not shard.replace("-", "").replace("_", "").isalnum():
        raise ValueError(f"invalid shard name {shard!r}")
    if not records and not allow_empty:
        raise CorpusError(
            f"{shard}: the source produced 0 records, which is almost always a moved upstream path rather than an "
            "empty source. The existing shard is kept. Pass allow_empty to write an empty one on purpose."
        )
    cdir = corpus_dir(data_dir)
    for r in records:
        _validate(r)
        r.setdefault("sha256", hashlib.sha256(r["text"].encode("utf-8")).hexdigest())
    groups: list[list[tuple[dict[str, Any], str]]] = [[]]
    size = 0
    for r in records:
        line = json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n"
        encoded = len(line.encode("utf-8"))
        if groups[-1] and size + encoded > PART_MAX:
            groups.append([])
            size = 0
        groups[-1].append((r, line))
        size += encoded
    entries: list[dict[str, Any]] = []
    written: set[str] = set()
    for n, group in enumerate(groups, 1):
        name = shard if n == 1 else f"{shard}-{n}"
        fname = f"{shard}.jsonl" if n == 1 else f"{shard}-{n}.jsonl"
        target = cdir / fname
        fd, tmp = tempfile.mkstemp(dir=cdir, prefix=f".{name}.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                for _, line in group:
                    fh.write(line)
            os.replace(tmp, target)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
        part_records = [r for r, _ in group]
        entries.append(
            {
                "shard": name,
                "file": fname,
                "records": len(part_records),
                "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
                "licenses": dict(Counter(r["license"] for r in part_records)),
                "redistributable": bool(part_records) and all(r["redistributable"] for r in part_records),
                "sources": sorted({r["sourceId"] for r in part_records}),
                "writtenAt": datetime.now(UTC).isoformat(timespec="seconds"),
            }
        )
        written.add(name)
    kept = {e["file"] for e in entries}
    for old in cdir.glob(f"{shard}*.jsonl"):
        tail = old.name[len(shard) :]
        part = tail == ".jsonl" or (tail.startswith("-") and tail.endswith(".jsonl") and tail[1:-6].isdigit())
        if part and old.name not in kept:
            old.unlink()
    manifest_path = cdir / "MANIFEST.json"
    manifest: dict[str, Any] = {"shards": {}}
    if manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    shards = manifest.setdefault("shards", {})
    for key in list(shards):
        tail = key[len(shard) + 1 :] if key.startswith(shard + "-") else ""
        if (key == shard or tail.isdigit()) and key not in written:
            shards.pop(key)
    for entry in entries:
        shards[entry["shard"]] = entry
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if len(entries) == 1:
        return entries[0]
    out = dict(entries[0])
    out["records"] = sum(e["records"] for e in entries)
    out["parts"] = len(entries)
    return out


def read_manifest(data_dir: Path) -> dict[str, Any]:
    p = data_dir / "corpus" / "MANIFEST.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.is_file() else {"shards": {}}


def shard_paths(data_dir: Path, shard: str) -> list[Path]:
    """Every file of ``shard``, in part order. The plugin reads the same function from ``vuln.parts``."""
    from kube_noob.vuln.parts import shard_paths as paths

    return paths(data_dir, shard)


def import_corpus(source: Path, data_dir: Path) -> dict[str, Any]:
    """Import shards from a directory or .tgz produced by ``corpus build`` / the corpus-refresh workflow.

    Only files listed in the source MANIFEST.json are copied, names are validated, and every checksum must match.
    """
    import shutil
    import tarfile

    data_dir.mkdir(parents=True, exist_ok=True)
    # extract next to the data, not in /tmp: a Jira snapshot is gigabytes and the chart's /tmp holds 256 MiB
    with tempfile.TemporaryDirectory(dir=data_dir, prefix=".import-") as tmp:
        root = source
        if source.is_file():
            with tarfile.open(source, "r:gz") as tf:
                tf.extractall(tmp, filter="data")  # rejects absolute paths, '..', links outside, devices
            candidates = list(Path(tmp).rglob("MANIFEST.json"))
            if not candidates:
                raise ValueError(f"{source}: no MANIFEST.json inside the archive")
            root = candidates[0].parent
        manifest_file = root / "MANIFEST.json"
        if not manifest_file.is_file():
            raise ValueError(f"{root}: MANIFEST.json not found")
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        from kube_noob.sources.jira_snapshot import check_extras, restore_extras

        checked = check_extras(root, manifest, data_dir)  # a Jira snapshot: validated before anything is copied
        target = corpus_dir(data_dir)
        current = read_manifest(data_dir)
        imported: list[str] = []
        ready: list[tuple[str, dict[str, Any], Path]] = []
        for name, entry in manifest.get("shards", {}).items():  # every shard checked before any is copied
            fname = str(entry.get("file", ""))
            if not fname.endswith(".jsonl") or "/" in fname or "\\" in fname or fname.startswith("."):
                raise ValueError(f"refusing suspicious shard file name {fname!r}")
            src = root / fname
            if not src.is_file():
                continue  # e.g. redistributable-only bundles omit restricted shards
            if hashlib.sha256(src.read_bytes()).hexdigest() != entry.get("sha256"):
                raise ValueError(f"{fname}: checksum mismatch, refusing to import")
            with src.open(encoding="utf-8") as fh:  # a checksum proves integrity, not well-formedness
                for lineno, line in enumerate(fh, 1):
                    if not line.strip():
                        continue
                    try:
                        rec = json.loads(line)
                    except (json.JSONDecodeError, RecursionError) as exc:
                        raise ValueError(f"{fname} line {lineno}: invalid JSON") from exc
                    if not isinstance(rec, dict):
                        raise ValueError(f"{fname} line {lineno}: record must be a JSON object")
                    _validate(rec)
            ready.append((name, entry, src))
        staged: list[tuple[Path, Path]] = []
        try:
            for _name, _entry, src in ready:
                fd, tmp_name = tempfile.mkstemp(dir=target, prefix=f".import-{src.name}.", suffix=".tmp")
                os.close(fd)
                shutil.copyfile(src, tmp_name)
                staged.append((Path(tmp_name), target / src.name))
            for tmp_path, final in staged:
                os.replace(tmp_path, final)
        except BaseException:
            for tmp_path, _ in staged:
                tmp_path.unlink(missing_ok=True)
            raise
        for name, entry, _src in ready:
            current.setdefault("shards", {})[name] = entry
            imported.append(name)
        incoming = set(imported)
        families = set()
        for name in incoming:
            head, _, tail = name.rpartition("-")
            families.add(head if tail.isdigit() and head else name)
        for key in list(current.get("shards", {})):
            head, _, tail = key.rpartition("-")
            family = head if tail.isdigit() and head else key
            if family in families and key not in incoming:
                fname = str(current["shards"][key].get("file", ""))
                if fname and "/" not in fname and "\\" not in fname:
                    (target / fname).unlink(missing_ok=True)
                current["shards"].pop(key)
        (target / "MANIFEST.json").write_text(json.dumps(current, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        extras = restore_extras(checked, data_dir) if checked else {}  # its sync state and change log
    return {"imported": imported, "dataDir": str(data_dir), **({"jira": extras} if extras else {})}


def verify(data_dir: Path) -> list[str]:
    """Return problems: checksum mismatches, shards missing from the manifest, invalid records."""
    problems: list[str] = []
    manifest = read_manifest(data_dir)
    cdir = data_dir / "corpus"
    for name, entry in manifest.get("shards", {}).items():
        f = cdir / entry["file"]
        if not f.is_file():
            problems.append(f"{name}: file {entry['file']} missing")
            continue
        if hashlib.sha256(f.read_bytes()).hexdigest() != entry["sha256"]:
            problems.append(f"{name}: checksum mismatch (modified outside kube-noob?)")
    if cdir.is_dir():
        listed = {e["file"] for e in manifest.get("shards", {}).values()}
        problems.extend(f"{f.name}: not in MANIFEST.json" for f in cdir.glob("*.jsonl") if f.name not in listed)
    return problems
