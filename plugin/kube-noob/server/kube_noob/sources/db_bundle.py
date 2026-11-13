"""The public ``kube-noob-db`` bundle: everything kube-noob may share, in one checked archive (requirements R1.3).

``build`` packs the redistributable corpus shards (documentation with its licenses, release history) and the
release-note known issues of a data folder into ``kube-noob-db.tgz``: shards at the top next to ``MANIFEST.json``,
the known-issue files under ``known_issues/``, and ``ATTRIBUTION.md`` naming every source and its license. ``check``
is the gate CI runs on the archive and on the image built from it: every record must be redistributable under a
licence on the allow-list, nothing from Jira may appear (Red Hat ticket text stays in each organisation's private
copy, even counts), every file must be listed with its checksum, and nothing else may be in the archive. ``import``
validates the whole archive before it copies anything, then restores the shards and the known issues.
``seed_on_start`` imports the newest bundle in ``<dataDir>/seed-db/`` when it is newer than the one already in.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import re
import shutil
import tarfile
import tempfile
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from kube_noob import sanitize

FORMAT = "kube-noob-db/1"
ARCHIVE = "kube-noob-db.tgz"
LICENSES = frozenset(
    {
        "Apache-2.0",
        "CC-BY-4.0",
        "MIT",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "facts derived from public Git metadata",
    }
)
MAX_MEMBER = 300_000_000  # bytes per file in the archive
MAX_MEMBERS = 500
_SHARD = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,80}\.jsonl\Z")
_KNOWN = re.compile(r"^known_issues/[A-Za-z0-9][A-Za-z0-9._-]{0,80}\.json\Z")
FIXED = ("MANIFEST.json", "ATTRIBUTION.md")
SEED_RECORD = "DB_SEED.json"


class BundleError(ValueError):
    """The archive is not a kube-noob-db bundle, or breaks one of its rules."""


def _sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _record_problems(rec: Any, where: str) -> list[str]:
    if not isinstance(rec, dict):
        return [f"{where}: not a JSON object"]
    problems = []
    if rec.get("redistributable") is not True:
        problems.append(f"{where}: record {rec.get('id')!r} is not redistributable")
    if str(rec.get("license")) not in LICENSES:
        problems.append(f"{where}: record {rec.get('id')!r} has license {rec.get('license')!r}, not on the allow-list")
    if str(rec.get("sourceId", "")).startswith("jira"):
        problems.append(f"{where}: record {rec.get('id')!r} comes from Jira ({rec.get('sourceId')})")
    for key in ("id", "title", "text", "sourceId"):
        if not isinstance(rec.get(key), str):
            problems.append(f"{where}: record {rec.get('id')!r} has no {key}")
    return problems


def _shard_problems(path: Path, name: str) -> list[str]:
    problems: list[str] = []
    with path.open(encoding="utf-8", errors="strict") as fh:
        for n, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except (ValueError, RecursionError):
                problems.append(f"{name} line {n}: invalid JSON")
                continue
            problems += _record_problems(rec, f"{name} line {n}")
            if len(problems) > 50:
                break
    return problems


def _known_problems(path: Path, name: str) -> list[str]:
    from kube_noob import known_issues as ki

    try:
        doc = sanitize.loads_bounded(path.read_text(encoding="utf-8"), sanitize.MAX_JSON_DEPTH_FILE)
    except (ValueError, RecursionError):
        return [f"{name}: invalid JSON"]
    if not isinstance(doc, dict) or str(doc.get("license")) not in LICENSES or not doc.get("attribution"):
        return [f"{name}: needs a license on the allow-list and an attribution"]
    try:
        issues = ki._parse(doc)
    except (KeyError, TypeError, ValueError) as exc:
        return [f"{name}: not a known-issue file ({exc})"]
    return [] if issues else [f"{name}: holds no issues"]


def check(root: Path) -> list[str]:
    """Every rule a bundle directory must keep; empty when it keeps them all.

    `build` runs this over its staging tree before packing, so the writer and the reader share one predicate.
    """
    problems: list[str] = _member_problems(root)
    manifest_file = root / "MANIFEST.json"
    if not manifest_file.is_file():
        return ["MANIFEST.json is missing"]
    try:
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    except ValueError:
        return ["MANIFEST.json is not JSON"]
    bundle = manifest.get("bundle") if isinstance(manifest, dict) else None
    if not isinstance(bundle, dict) or bundle.get("format") != FORMAT:
        return [f"MANIFEST.json is not a {FORMAT} manifest"]
    if "jira" in manifest:
        problems.append("MANIFEST.json carries a Jira block")
    # `db-check` is what someone runs on a bundle they downloaded. A manifest declaring no shards, or shards whose
    # record counts are all zero, used to pass every check here: the per-shard loop below finds no bad lines in a
    # file with no lines, so an empty corpus reported clean and exited 0. The writer's guard is not enough, since
    # the writer is not who runs this.
    declared = (manifest.get("shards") or {}) if isinstance(manifest, dict) else {}
    if not declared:
        problems.append("MANIFEST.json declares no shards: an empty corpus is not a bundle")
    elif sum(int((e or {}).get("records", 0) or 0) for e in declared.values()) == 0:
        problems.append(
            f"MANIFEST.json declares {len(declared)} shard(s) with 0 records between them: an empty corpus is not "
            "a bundle"
        )
    listed: dict[str, str] = {}
    for name, entry in (manifest.get("shards") or {}).items():
        fname = str((entry or {}).get("file", ""))
        if not _SHARD.match(fname):
            problems.append(f"shard {name}: file name {fname!r} refused")
            continue
        if name.startswith("jira") or fname.startswith("jira"):
            problems.append(f"shard {name}: Jira data never goes into the public bundle")
        if entry.get("redistributable") is not True:
            problems.append(f"shard {name}: marked not redistributable")
        listed[fname] = str(entry.get("sha256", ""))
    for rel, digest in (bundle.get("files") or {}).items():
        if not _KNOWN.match(str(rel)):
            problems.append(f"file {rel!r} refused (only known_issues/<name>.json)")
            continue
        listed[str(rel)] = str(digest)
    present: set[str] = set()
    for p in root.rglob("*"):
        rel = p.relative_to(root).as_posix()
        if p.is_symlink() or not (p.is_file() or p.is_dir()):
            problems.append(f"{rel}: not a regular file")
            continue
        if p.is_dir():
            if rel != "known_issues":
                problems.append(f"{rel}/: unexpected folder")
            continue
        present.add(rel)
        if rel in FIXED:
            continue
        if rel not in listed:
            problems.append(f"{rel}: not listed in MANIFEST.json")
    for rel, digest in sorted(listed.items()):
        if rel not in present:
            problems.append(f"{rel}: listed but missing")
            continue
        path = root / rel
        if _sha(path) != digest:
            problems.append(f"{rel}: checksum mismatch")
            continue
        problems += _known_problems(path, rel) if rel.startswith("known_issues/") else _shard_problems(path, rel)
    if "ATTRIBUTION.md" not in present:
        problems.append("ATTRIBUTION.md is missing")
    return problems


def _attribution(sources: dict[str, dict[str, Any]], known: list[dict[str, str]]) -> str:
    lines = [
        "# kube-noob-db: sources and licenses",
        "",
        "Everything in this bundle may be redistributed under the license named next to its source. Keep this file "
        "with any copy. Red Hat Jira ticket text is never included: each organisation builds its own private copy.",
        "",
        "| Source | License | Records | Attribution |",
        "| --- | --- | --- | --- |",
    ]
    for sid, info in sorted(sources.items()):
        lines.append(f"| {sid} | {info['license']} | {info['records']} | {info['attribution']} |")
    for k in known:
        lines.append(f"| {k['file']} | {k['license']} | {k['issues']} issues | {k['attribution']} |")
    return "\n".join(lines) + "\n"


def _tar_add(tf: tarfile.TarFile, path: Path, arcname: str) -> None:
    info = tarfile.TarInfo(arcname)
    info.size = path.stat().st_size
    info.mtime = 0
    info.mode = 0o644
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    with path.open("rb") as fh:
        tf.addfile(info, fh)


def build(data_dir: Path, out: Path, now: datetime | None = None) -> dict[str, Any]:
    """Write the public bundle of ``data_dir`` to ``out`` (a .tgz); refuse when a shard it would ship breaks a
    rule. Shards marked not redistributable and every Jira shard are left out by design and listed in the result."""
    from kube_noob import __version__
    from kube_noob import known_issues as ki
    from kube_noob.sources.corpus import read_manifest
    from kube_noob.sources.registry import GIT_SOURCES

    attributions = {s.source_id: s.attribution for s in GIT_SOURCES}
    manifest = read_manifest(data_dir)
    shards: dict[str, Any] = {}
    left_out: list[str] = []
    sources: dict[str, dict[str, Any]] = {}
    licenses: Counter[str] = Counter()
    problems: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        stage = Path(tmp)
        for name, entry in sorted((manifest.get("shards") or {}).items()):
            fname = str(entry.get("file", ""))
            src = data_dir / "corpus" / fname
            if name.startswith("jira") or not entry.get("redistributable") or not _SHARD.match(fname):
                left_out.append(name)
                continue
            if not src.is_file():
                problems.append(f"{fname}: listed in the corpus manifest but missing")
                continue
            found = _shard_problems(src, fname)
            if found:
                problems += found
                continue
            with src.open(encoding="utf-8") as fh:
                for line in fh:
                    if not line.strip():
                        continue
                    rec = json.loads(line)
                    sid = str(rec["sourceId"])
                    info = sources.setdefault(
                        sid,
                        {
                            "license": rec["license"],
                            "records": 0,
                            "attribution": rec.get("attribution")
                            or attributions.get(sid)
                            or attributions.get(sid.split(":", 1)[0])
                            or (rec.get("url") or sid),
                        },
                    )
                    info["records"] += 1
                    licenses[str(rec["license"])] += 1
            shutil.copyfile(src, stage / fname)
            shards[name] = {**entry, "sha256": _sha(stage / fname)}
        if problems:
            raise BundleError("not built: " + "; ".join(problems[:10]))
        files: dict[str, str] = {}
        known: list[dict[str, str]] = []
        kdir = data_dir / "known_issues"
        if kdir.is_dir():
            (stage / "known_issues").mkdir()
            for f in sorted(kdir.glob("*.json")):
                rel = f"known_issues/{f.name}"
                if not _KNOWN.match(rel):
                    continue
                bad = _known_problems(f, rel)
                if bad:
                    raise BundleError("not built: " + "; ".join(bad))
                doc = sanitize.loads_bounded(f.read_text(encoding="utf-8"), sanitize.MAX_JSON_DEPTH_FILE)
                shutil.copyfile(f, stage / rel)
                files[rel] = _sha(stage / rel)
                known.append(
                    {
                        "file": rel,
                        "license": str(doc["license"]),
                        "attribution": str(doc["attribution"]),
                        "issues": str(len(ki._parse(doc))),
                    }
                )
            if not files:
                (stage / "known_issues").rmdir()
        if not shards and not files:
            raise BundleError("nothing to ship: build the public corpus first (kube-noob corpus build --online)")
        # A present-but-empty shard used to pass everything: `_shard_problems` finds no bad lines in a file with no
        # lines, so the bundle built and `db-check` reported it clean. An empty corpus must not be publishable.
        total = sum(int(e.get("records", 0)) for e in shards.values())
        if shards and total == 0:
            raise BundleError(
                "refusing to ship a bundle with 0 records: the shards it would carry are empty, which means the "
                "last `kube-noob corpus build` found nothing rather than that the corpus is small"
            )
        stamp = (now or datetime.now(UTC)).isoformat(timespec="seconds")
        bundle = {
            "format": FORMAT,
            "builtAt": stamp,
            "kubeNoobVersion": __version__,
            "records": total,
            "licenses": dict(sorted(licenses.items())),
            "files": files,
        }
        (stage / "MANIFEST.json").write_text(
            json.dumps({"bundle": bundle, "shards": shards}, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        (stage / "ATTRIBUTION.md").write_text(_attribution(sources, known), encoding="utf-8")
        found = check(stage)
        if found:
            raise BundleError("not built: " + "; ".join(found[:10]))
        out.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_out = tempfile.mkstemp(dir=out.parent, prefix=f".{out.name}.", suffix=".tmp")
        os.close(fd)
        try:
            with (  # no time or temporary name in the gzip header: the same data gives the same bytes
                open(tmp_out, "wb") as raw,
                gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9) as gz,
                tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as tf,
            ):
                for p in sorted(stage.rglob("*")):
                    if p.is_file():
                        _tar_add(tf, p, p.relative_to(stage).as_posix())
            os.chmod(tmp_out, 0o644)  # public data: readable by the image's and the init container's users
            os.replace(tmp_out, out)
        except BaseException:
            Path(tmp_out).unlink(missing_ok=True)
            raise
    return {
        "bundle": str(out),
        "sha256": _sha(out),
        "bytes": out.stat().st_size,
        "builtAt": stamp,
        "shards": sorted(shards),
        "records": bundle["records"],
        "knownIssueFiles": len(files),
        "licenses": bundle["licenses"],
        "leftOut": left_out,
    }


def _extract(archive: Path, into: Path) -> Path:
    """Extract a bundle safely (regular files only, size and count caps) and return its root."""
    try:
        with tarfile.open(archive, "r:gz") as tf:
            members = tf.getmembers()
            if len(members) > MAX_MEMBERS:
                raise BundleError(f"{archive.name}: more than {MAX_MEMBERS} files")
            for m in members:
                if not (m.isfile() or m.isdir()):
                    raise BundleError(f"{archive.name}: {m.name} is not a regular file")
                if m.size > MAX_MEMBER:
                    raise BundleError(f"{archive.name}: {m.name} is larger than {MAX_MEMBER} bytes")
            tf.extractall(into, filter="data")
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise BundleError(f"{archive.name}: not a readable .tgz ({exc})") from exc
    return into


def _member_problems(root: Path) -> list[str]:
    """The size and count caps `_extract` enforces on a .tgz, applied to a tree before it becomes one.

    `MAX_MEMBER` and `MAX_MEMBERS` were referenced only by the reader, so `build()` could pack an archive nothing
    could import and report success, and `check()` on a directory enforced neither.
    """
    files = sorted(p for p in root.rglob("*") if p.is_file())
    out: list[str] = []
    if len(files) > MAX_MEMBERS:
        out.append(f"{len(files)} files, more than {MAX_MEMBERS}")
    for f in files:
        size = f.stat().st_size
        if size > MAX_MEMBER:
            out.append(f"{f.relative_to(root)} is {size} bytes, larger than {MAX_MEMBER}")
    return out


def check_archive(archive: Path) -> list[str]:
    """``check`` for a directory or a .tgz."""
    if archive.is_dir():
        return check(archive)
    with tempfile.TemporaryDirectory() as tmp:
        try:
            return check(_extract(archive, Path(tmp)))
        except BundleError as exc:
            return [str(exc)]


def is_bundle(archive: Path) -> bool:
    """True when ``archive`` (a .tgz or directory) carries a kube-noob-db manifest."""
    try:
        if archive.is_dir():
            raw = (archive / "MANIFEST.json").read_bytes()
        else:
            with tarfile.open(archive, "r:gz") as tf:
                m = tf.getmember("MANIFEST.json")
                fh = tf.extractfile(m) if m.isfile() and m.size <= 10_000_000 else None
                raw = fh.read() if fh else b""
        doc = json.load(io.BytesIO(raw))
    except (KeyError, OSError, ValueError, tarfile.TarError, EOFError):
        return False
    return isinstance(doc, dict) and isinstance(doc.get("bundle"), dict) and doc["bundle"].get("format") == FORMAT


def import_bundle(archive: Path, data_dir: Path) -> dict[str, Any]:
    """Validate the whole bundle, then restore its shards (through ``corpus import``) and known issues."""
    from kube_noob import known_issues as ki
    from kube_noob.sources.corpus import import_corpus

    data_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=data_dir, prefix=".import-") as tmp:
        root = archive if archive.is_dir() else _extract(archive, Path(tmp))
        problems = check(root)
        if problems:
            raise BundleError("refused, nothing imported: " + "; ".join(problems[:10]))
        manifest = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
        bundle = manifest["bundle"]
        out = import_corpus(root, data_dir)
        files = sorted(bundle.get("files") or {})
        if files:
            kdir = data_dir / "known_issues"
            kdir.mkdir(parents=True, exist_ok=True)
            for rel in files:
                target = kdir / Path(rel).name
                fd, tmp_file = tempfile.mkstemp(dir=kdir, prefix=".import.", suffix=".tmp")
                os.close(fd)
                shutil.copyfile(root / rel, tmp_file)
                os.replace(tmp_file, target)
            with ki._lock:
                ki._cache.pop(str(data_dir), None)
    record = {"builtAt": bundle["builtAt"], "format": FORMAT, "kubeNoobVersion": bundle.get("kubeNoobVersion")}
    seed = data_dir / "corpus" / SEED_RECORD
    seed.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    return {**out, "bundle": record, "knownIssueFiles": len(files)}


def seed_on_start(data_dir: Path) -> dict[str, Any] | None:
    """Import the newest ``<dataDir>/seed-db/*.tgz`` when it was built after the bundle already imported (or none
    was); None when there is nothing newer. A newer image rolled out reaches pods on their next start."""
    folder = data_dir / "seed-db"
    seeds = sorted(folder.glob("*.tgz"), key=lambda p: p.stat().st_mtime) if folder.is_dir() else []
    if not seeds:
        return None
    newest = seeds[-1]
    with tempfile.TemporaryDirectory(dir=data_dir, prefix=".seed-") as tmp:
        root = _extract(newest, Path(tmp))
        try:
            built = str(json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))["bundle"]["builtAt"])
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise BundleError(f"{newest.name}: not a {FORMAT} bundle") from exc
        current = data_dir / "corpus" / SEED_RECORD
        have = ""
        if current.is_file():
            try:
                have = str(json.loads(current.read_text(encoding="utf-8")).get("builtAt", ""))
            except ValueError:
                have = ""
        if have and have >= built:
            return None
        return {"seed": str(newest), **import_bundle(root, data_dir)}
