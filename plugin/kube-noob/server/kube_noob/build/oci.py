"""Read a built image from an OCI image layout on disk (``skopeo copy docker://<image> oci:<dir>``, ``podman save
--format oci-dir``, ``buildah push <image> oci:<dir>``) and look for credentials in its config, history and layers.

Nothing is extracted: each layer is read as a tar stream in memory, every blob is checked against its digest, and
reading stops at fixed budgets (bytes, files, layers). A file deleted by a later layer is still in the layer that
added it, so a credential there is reported with the layer that deleted it. Values are never returned, only their
kind, path, layer and a masked preview.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import re
import tarfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import IO, Any

from kube_noob import sanitize
from kube_noob.build import secrets

MAX_MANIFEST = 4_000_000
MAX_LAYERS = 200
MAX_MEMBERS = 500_000
MAX_FILE_READ = 1_048_576  # bytes of one file that are scanned
MAX_SCANNED = 256 * 1_048_576  # bytes of file content scanned per image
MAX_UNPACKED = 4 * 1024 * 1_048_576  # uncompressed layer bytes read per image
_DIGEST = re.compile(r"^sha256:([a-f0-9]{64})\Z")
_INDEX_TYPES = {"application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json"}
_TEXT_SUFFIX = re.compile(
    r"\.(?:env|ya?ml|json|properties|conf|cfg|ini|toml|sh|bash|txt|xml|npmrc|pypirc|netrc|pem|key|py|js|ts|rb|go|"
    r"java|config)$|(?:^|/)(?:\.[\w-]{2,30}rc|config|credentials|[\w.-]{0,40}secret[\w.-]{0,40})$",
    re.I,
)


class LayoutError(ValueError):
    """Not an OCI layout, a blob that does not match its digest, or a budget exceeded before anything was read."""


@dataclass
class ImageScan:
    manifest: str
    user: str
    env_names: list[str]
    labels: dict[str, str]
    layers: int
    hits: list[dict[str, Any]] = field(default_factory=list)
    config_hits: list[dict[str, Any]] = field(default_factory=list)
    not_read: list[str] = field(default_factory=list)
    files: int = 0
    scanned_bytes: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "manifest": self.manifest,
            "user": self.user or "(empty: root)",
            "envNames": self.env_names,
            "labels": self.labels,
            "layers": self.layers,
            "files": self.files,
            "scannedBytes": self.scanned_bytes,
            "layerSecrets": self.hits,
            "configSecrets": self.config_hits,
            "notRead": self.not_read,
        }


class _Counting(io.RawIOBase):
    """A read-only stream that hashes the bytes that pass through it."""

    def __init__(self, raw: IO[bytes]) -> None:
        self.raw, self.sha = raw, hashlib.sha256()

    def readable(self) -> bool:
        return True

    def readinto(self, b: Any) -> int:
        data = self.raw.read(len(b))
        self.sha.update(data)
        n = len(data)
        b[:n] = data
        return n


class _Budgeted(io.RawIOBase):
    def __init__(self, raw: IO[bytes], budget: list[int]) -> None:
        self.raw, self.budget = raw, budget

    def readable(self) -> bool:
        return True

    def readinto(self, b: Any) -> int:
        if self.budget[0] <= 0:
            raise LayoutError("uncompressed size budget reached")
        data = self.raw.read(min(len(b), self.budget[0]))
        self.budget[0] -= len(data)
        n = len(data)
        b[:n] = data
        return n


def _blob_path(root: Path, digest: Any) -> Path:
    m = _DIGEST.match(str(digest))
    if not m:
        raise LayoutError(f"unsupported or malformed digest {str(digest)[:80]!r}")
    path = root / "blobs" / "sha256" / m.group(1)
    if path.is_symlink() or not path.is_file():
        raise LayoutError(f"blob {digest} is missing or not a regular file")
    return path


def _small_blob(root: Path, digest: Any) -> bytes:
    path = _blob_path(root, digest)
    if path.stat().st_size > MAX_MANIFEST:
        raise LayoutError(f"blob {digest} is larger than {MAX_MANIFEST} bytes")
    data = path.read_bytes()
    if "sha256:" + hashlib.sha256(data).hexdigest() != digest:
        raise LayoutError(f"blob {digest} does not match its digest")
    return data


def _json(data: bytes, what: str) -> dict[str, Any]:
    try:
        doc = sanitize.loads_bounded(data, sanitize.MAX_JSON_DEPTH_FILE)
    except (ValueError, RecursionError) as exc:
        raise LayoutError(f"{what} is not JSON") from exc
    if not isinstance(doc, dict):
        raise LayoutError(f"{what} is not a JSON object")
    return doc


def _pick(root: Path, index: dict[str, Any], platform: str | None, depth: int = 0) -> dict[str, Any]:
    manifests = [m for m in index.get("manifests") or [] if isinstance(m, dict)]
    if not manifests:
        raise LayoutError("index.json lists no manifests")
    want_os, _, want_arch = (platform or "linux/amd64").partition("/")
    chosen = None
    for m in manifests:
        p = m.get("platform") if isinstance(m.get("platform"), dict) else {}
        if not p or (p.get("os") == want_os and p.get("architecture") == want_arch):
            chosen = m
            break
    chosen = chosen or manifests[0]
    if chosen.get("mediaType") in _INDEX_TYPES:
        if depth > 2:
            raise LayoutError("image indexes nested too deeply")
        return _pick(root, _json(_small_blob(root, chosen.get("digest")), "image index"), platform, depth + 1)
    return chosen


def _opener(media: str, raw: IO[bytes]) -> IO[bytes]:
    if media.endswith("+gzip") or media.endswith(".tar.gzip") or media.endswith("tar+gzip"):
        return gzip.GzipFile(fileobj=raw)  # type: ignore[return-value]
    if media.endswith("+zstd"):
        try:
            from compression import zstd  # type: ignore[import-not-found]  # Python 3.14+

            return zstd.ZstdFile(raw)  # type: ignore[no-any-return]
        except ImportError:
            try:
                import zstandard  # type: ignore[import-not-found]

                return zstandard.ZstdDecompressor().stream_reader(raw)  # type: ignore[no-any-return]
            except ImportError as exc:
                raise LayoutError("zstd layer: needs Python 3.14 or the zstandard package") from exc
    return raw


def _norm(name: str) -> str:
    while name.startswith(("./", "/")):
        name = name[2:] if name.startswith("./") else name[1:]
    return str(PurePosixPath("/" + name)).lstrip("/")


def scan(layout: Path, platform: str | None = None) -> ImageScan:
    root = layout
    marker = root / "oci-layout"
    if not marker.is_file() or not (root / "index.json").is_file():
        raise LayoutError(f"{layout} is not an OCI image layout (no oci-layout and index.json)")
    if (root / "index.json").stat().st_size > MAX_MANIFEST:
        raise LayoutError("index.json is too large")
    index = _json((root / "index.json").read_bytes(), "index.json")
    desc = _pick(root, index, platform)
    manifest = _json(_small_blob(root, desc.get("digest")), "manifest")
    raw_desc = manifest.get("config")
    config_desc: dict[str, Any] = raw_desc if isinstance(raw_desc, dict) else {}
    config = _json(_small_blob(root, config_desc.get("digest")), "image config")
    raw_cfg = config.get("config")
    cfg: dict[str, Any] = raw_cfg if isinstance(raw_cfg, dict) else {}
    env = [e for e in cfg.get("Env") or [] if isinstance(e, str)]
    raw_labels = cfg.get("Labels")
    labels = {str(k): str(v) for k, v in raw_labels.items()} if isinstance(raw_labels, dict) else {}
    out = ImageScan(
        manifest=str(desc.get("digest")),
        user=str(cfg.get("User") or ""),
        env_names=[e.split("=", 1)[0] for e in env][:200],
        labels=dict(list(labels.items())[:100]),
        layers=0,
    )
    for e in env:
        name, _, value = e.partition("=")
        for hit in secrets.scan_text(f"{name}={value}", f"config Env {name}"):
            out.config_hits.append(hit.as_dict())
    for k, v in labels.items():
        for hit in secrets.scan_text(f"{k}={v}", f"config Labels {k}"):
            out.config_hits.append(hit.as_dict())
    history = [h for h in config.get("history") or [] if isinstance(h, dict)]
    for n, h in enumerate(history[:500], 1):
        created = str(h.get("created_by") or "")[:20_000]
        for hit in secrets.scan_text(created, f"history #{n}"):
            out.config_hits.append(hit.as_dict())

    layers = [x for x in manifest.get("layers") or [] if isinstance(x, dict)]
    if len(layers) > MAX_LAYERS:
        out.not_read.append(f"{len(layers) - MAX_LAYERS} layers after the first {MAX_LAYERS}")
        layers = layers[:MAX_LAYERS]
    out.layers = len(layers)
    unpacked = [MAX_UNPACKED]
    scanned = [MAX_SCANNED]
    found: dict[str, list[dict[str, Any]]] = {}
    deleted: dict[str, int] = {}
    for li, layer in enumerate(layers, 1):
        try:
            _scan_layer(root, li, layer, out, unpacked, scanned, found, deleted)
        except LayoutError as exc:
            out.not_read.append(f"layer {li}: {exc}")
        except (tarfile.TarError, OSError, EOFError) as exc:
            out.not_read.append(f"layer {li}: not a readable tar ({type(exc).__name__})")
    for path, rows in found.items():
        for row in rows:
            later = [n for p, n in deleted.items() if (p == path or path.startswith(p + "/")) and n > row["layer"]]
            if later:
                row["deletedInLayer"] = min(later)
                row["note"] = (
                    f"deleted in layer {min(later)}, still in layer {row['layer']}: anyone who pulls the "
                    "image can read it"
                )
            out.hits.append(row)
    out.hits.sort(key=lambda h: (h["layer"], h["where"]))
    out.scanned_bytes = MAX_SCANNED - scanned[0]
    return out


def _scan_layer(
    root: Path,
    li: int,
    layer: dict[str, Any],
    out: ImageScan,
    unpacked: list[int],
    scanned: list[int],
    found: dict[str, list[dict[str, Any]]],
    deleted: dict[str, int],
) -> None:
    digest = str(layer.get("digest"))
    media = str(layer.get("mediaType") or "application/vnd.oci.image.layer.v1.tar")
    if "nondistributable" in media or "foreign" in media:
        out.not_read.append(f"layer {li}: foreign layer, not in the layout")
        return
    path = _blob_path(root, digest)
    with path.open("rb") as fh:
        counted = _Counting(fh)  # hashes the stored bytes as they are read
        stream = io.BufferedReader(_Budgeted(_opener(media, io.BufferedReader(counted)), unpacked))
        members = 0
        with tarfile.open(fileobj=stream, mode="r|") as tar:
            for member in tar:
                members += 1
                if members > MAX_MEMBERS:
                    out.not_read.append(f"layer {li}: files after the first {MAX_MEMBERS}")
                    break
                name = _norm(member.name)
                base = name.rsplit("/", 1)[-1]
                if base.startswith(".wh."):
                    parent = name.rsplit("/", 1)[0] if "/" in name else ""
                    target = parent if base == ".wh..wh..opq" else f"{parent}/{base[4:]}".lstrip("/")
                    deleted.setdefault(target, li)
                    continue
                if not member.isfile():
                    continue
                out.files += 1
                kind = secrets.name_kind(name)
                texty = kind is not None or bool(_TEXT_SUFFIX.search(name))
                if not texty or member.size > 16 * MAX_FILE_READ or scanned[0] <= 0:
                    if kind:
                        found.setdefault(name, []).append(
                            {"kind": kind, "where": f"/{name}", "layer": li, "preview": "****"}
                        )
                    continue
                f = tar.extractfile(member)
                if f is None:
                    continue
                data = f.read(min(MAX_FILE_READ, scanned[0]))
                scanned[0] -= len(data)
                if b"\x00" in data[:8192]:
                    if kind:
                        found.setdefault(name, []).append(
                            {"kind": kind, "where": f"/{name}", "layer": li, "preview": "****"}
                        )
                    continue
                hits = secrets.scan_text(data.decode("utf-8", "replace"), f"/{name}", assignments=True, limit=5)
                if hits:
                    for h in hits:
                        found.setdefault(name, []).append({**h.as_dict(), "layer": li})
                elif kind:
                    found.setdefault(name, []).append(
                        {"kind": kind, "where": f"/{name}", "layer": li, "preview": "****"}
                    )
        while counted.read(1 << 20):  # finish the hash over the rest of the blob
            pass
    # the digest covers the stored (compressed) bytes: compare it with what was read
    expected = digest.split(":", 1)[1]
    got = counted.sha.hexdigest()
    if got != expected:
        found_now = [k for k, v in found.items() if any(h["layer"] == li for h in v)]
        for k in found_now:
            found[k] = [h for h in found[k] if h["layer"] != li]
        raise LayoutError("does not match its digest; its findings were dropped")
