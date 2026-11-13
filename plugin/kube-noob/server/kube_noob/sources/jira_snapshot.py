"""The main copy of the Red Hat Jira copy: one file that another install imports and keeps syncing from.

``kube-noob corpus jira-snapshot -o jira-snapshot.tgz`` packs the Jira shards (``corpus/jira-*.jsonl``, including the
ticket statistics), the sync state (``jira/state.json``) and the change log (``jira/changes.jsonl``) with a
``MANIFEST.json`` in the format ``kube-noob corpus import`` reads. An install that imports it holds the same copy,
resumes the sync exactly where the snapshot stopped (the state names each shard's checksum) and only fetches what
changed since. ``kube-noob serve`` imports the newest snapshot in ``<dataDir>/seed/`` on start when it has no copy yet,
so a new pod starts with tickets instead of waiting for a first sync.

The snapshot holds Red Hat's ticket text, which has no redistribution license: keep it inside your organisation (a
private registry, bucket or volume). Never publish it; ``corpus-refresh`` uploads it only encrypted.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import tarfile
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from kube_noob.sources.seal import is_sealed, read_secret, unseal

FORMAT = "kube-noob-jira-snapshot/1"
MAX_PART = 200_000_000  # bytes: the sync state or the change log inside a snapshot
README = """kube-noob Red Hat Jira snapshot

Import: kube-noob corpus import <this file>   (or drop it in <dataDir>/seed/ before kube-noob serve starts)

Contains Red Hat public Jira ticket text, which has no redistribution license. Keep this file inside your
organisation; do not publish it.
"""


def _add(tf: tarfile.TarFile, name: str, data: bytes) -> None:
    info = tarfile.TarInfo(f"jira-snapshot/{name}")
    info.size = len(data)
    info.mtime = int(time.time())
    info.mode = 0o600
    tf.addfile(info, io.BytesIO(data))


def export_snapshot(data_dir: Path, out: Path) -> dict[str, Any]:
    """Write the snapshot to ``out`` (owner-only); returns what it holds."""
    from kube_noob.sources.corpus import read_manifest
    from kube_noob.sources.jira import changes_path, load_state

    manifest = read_manifest(data_dir)
    shards = {
        name: entry
        for name, entry in (manifest.get("shards") or {}).items()
        if name.startswith("jira-") and isinstance(entry, dict)
    }
    if not any(name != "jira-insights" for name in shards):
        raise ValueError(f"{data_dir} holds no Jira copy to snapshot (kube-noob corpus jira --online first)")
    state = load_state(data_dir)
    changes = changes_path(data_dir).read_bytes() if changes_path(data_dir).is_file() else b""
    state_bytes = json.dumps(state, indent=1, sort_keys=True).encode()
    snap_manifest = {
        "format": FORMAT,
        "createdAt": datetime.now(UTC).isoformat(timespec="seconds"),
        "baseUrl": state.get("baseUrl"),
        "shards": shards,
        "jira": {
            "state": "jira-state.json",
            "stateSha256": hashlib.sha256(state_bytes).hexdigest(),
            "changes": "jira-changes.jsonl",
            "changesSha256": hashlib.sha256(changes).hexdigest(),
        },
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_name(f".{out.name}.tmp")
    tmp.touch(mode=0o600)
    tmp.chmod(0o600)
    with tarfile.open(tmp, "w:gz") as tf:
        for entry in shards.values():
            path = data_dir / "corpus" / str(entry["file"])
            if path.is_file():
                tf.add(path, f"jira-snapshot/{entry['file']}", filter=_private)
        _add(tf, "jira-state.json", state_bytes)
        _add(tf, "jira-changes.jsonl", changes)
        _add(tf, "README.txt", README.encode())
        _add(tf, "MANIFEST.json", json.dumps(snap_manifest, indent=2, sort_keys=True).encode())
    tmp.chmod(0o600)
    tmp.replace(out)
    tickets = sum(int(e.get("records") or 0) for n, e in shards.items() if n != "jira-insights")
    return {
        "snapshot": str(out),
        "bytes": out.stat().st_size,
        "projects": sorted(n.removeprefix("jira-").upper() for n in shards if n != "jira-insights"),
        "tickets": tickets,
        "changes": changes.count(b"\n"),
        "lastSync": max((str(p.get("lastSyncAt")) for p in (state.get("projects") or {}).values()), default=None),
        "note": "Red Hat ticket text inside: keep this file within your organisation.",
    }


def _private(info: tarfile.TarInfo) -> tarfile.TarInfo:
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.mode = 0o600
    return info


def check_extras(root: Path, manifest: dict[str, Any], data_dir: Path) -> dict[str, Any]:
    """Validate a snapshot's sync state and change log before anything is copied: checksums, shapes, and that the
    snapshot comes from the same Jira as this copy. Returns the parsed parts (empty for a plain corpus)."""
    from kube_noob.sources.jira import load_state

    extra = manifest.get("jira")
    if extra is None:
        return {}
    if not isinstance(extra, dict):
        raise ValueError("MANIFEST.json: 'jira' must be an object")
    out: dict[str, Any] = {}
    for part, digest in (("state", "stateSha256"), ("changes", "changesSha256")):
        name = extra.get(part)
        if not name:
            continue
        if not isinstance(name, str) or "/" in name or "\\" in name or name.startswith("."):
            raise ValueError(f"refusing suspicious snapshot file name {name!r}")
        path = root / name
        if not path.is_file():
            raise ValueError(f"{name}: listed in MANIFEST.json but missing")
        if path.stat().st_size > MAX_PART:
            raise ValueError(f"{name}: larger than {MAX_PART // 1_000_000} MB, refusing to import")
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != extra.get(digest):
            raise ValueError(f"{name}: checksum mismatch, refusing to import")
        out[part] = data
    if "state" in out:
        try:
            snap = json.loads(out["state"])
        except ValueError as exc:
            raise ValueError(f"jira-state.json: invalid JSON ({exc})") from exc
        if not isinstance(snap, dict) or not isinstance(snap.get("projects", {}), dict):
            raise ValueError("jira-state.json: not a sync state")
        if not all(isinstance(v, dict) for v in snap.get("projects", {}).values()):
            raise ValueError("jira-state.json: every project state must be an object")
        local = load_state(data_dir)
        if local.get("baseUrl") and snap.get("baseUrl") and local["baseUrl"] != snap["baseUrl"]:
            raise ValueError(f"the snapshot comes from {snap['baseUrl']}, this copy from {local['baseUrl']}")
        out["state"] = snap
    if "changes" in out:
        events: list[str] = []
        for line in out["changes"].decode("utf-8", errors="replace").splitlines():
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if isinstance(e, dict) and isinstance(e.get("key"), str) and isinstance(e.get("kind"), str):
                events.append(json.dumps(e, sort_keys=True))
        out["changes"] = events
    return out


def restore_extras(checked: dict[str, Any], data_dir: Path) -> dict[str, Any]:
    """After ``corpus import`` copied a snapshot's shards: its sync state (per project, so other projects' state is
    kept) and its change log (merged with the local one, each event once, oldest first)."""
    from kube_noob.sources.jira import MAX_CHANGES, changes_path, jira_dir, load_state, save_state

    out: dict[str, Any] = {}
    snap = checked.get("state")
    if isinstance(snap, dict):
        local = load_state(data_dir)
        merged = {**local, "baseUrl": snap.get("baseUrl") or local.get("baseUrl")}
        merged["projects"] = {**(local.get("projects") or {}), **(snap.get("projects") or {})}
        save_state(data_dir, merged)
        out["stateProjects"] = sorted((snap.get("projects") or {}).keys())
    incoming = checked.get("changes")
    if isinstance(incoming, list):
        path = changes_path(data_dir)
        jira_dir(data_dir)
        seen: set[str] = set()
        rows: list[tuple[str, str]] = []
        local_lines = path.read_text(encoding="utf-8").splitlines() if path.is_file() else []
        for line in [*local_lines, *incoming]:
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if not isinstance(e, dict):
                continue
            canon = json.dumps(e, sort_keys=True)
            if canon in seen:
                continue
            seen.add(canon)
            rows.append((str(e.get("at", "")), canon))
        rows.sort(key=lambda r: r[0])
        kept = rows[-MAX_CHANGES:]
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".changes.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.writelines(f"{canon}\n" for _, canon in kept)
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
        out["changes"] = len(kept)
    return out


def seed_on_start(data_dir: Path) -> dict[str, Any] | None:
    """Import the newest ``<dataDir>/seed/*.tgz`` (or ``*.tgz.enc``, sealed with the organisation's key, opened with
    the key file named by ``KUBE_NOOB_SEED_KEY_FILE``) when this data folder has no Jira copy yet; None otherwise.
    A sealed seed with no key or the wrong key raises SealError and nothing is imported."""
    from kube_noob.sources.corpus import import_corpus, read_manifest

    folder = data_dir / "seed"
    seeds = (
        sorted([*folder.glob("*.tgz"), *folder.glob("*.tgz.enc")], key=lambda p: p.stat().st_mtime)
        if folder.is_dir()
        else []
    )
    has_copy = any(
        n.startswith("jira-") and n != "jira-insights" for n in (read_manifest(data_dir).get("shards") or {})
    )
    if not seeds or has_copy:
        return None
    newest = seeds[-1]
    if not is_sealed(newest):
        return {"seed": str(newest), **import_corpus(newest, data_dir)}
    secret = read_secret()
    data_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=data_dir, prefix=".seed-") as tmp:
        plain = Path(tmp) / "jira-snapshot.tgz"
        unseal(newest, plain, secret)
        return {"seed": str(newest), "sealed": True, **import_corpus(plain, data_dir)}
