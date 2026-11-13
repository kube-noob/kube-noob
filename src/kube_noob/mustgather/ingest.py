"""Open a must-gather (a directory, ``.tar``, ``.tar.gz`` or ``.tgz``) safely: nothing is extracted to disk and
nothing is executed (backlog G1).

The layout, read from openshift/oc (``pkg/cli/admin/mustgather``, ``pkg/cli/admin/inspect``, checked 2026-10-28):

- ``oc adm must-gather`` writes ``must-gather.local.<cluster id>.<UTC time>.<random>/`` with ``timestamp`` and
  ``must-gather.logs`` at the top, and one directory per gather image named after the image's ``ImageID`` with every
  run of non-alphanumeric characters replaced by ``-`` (under a node directory with ``--node-selector``). Each image
  directory holds ``gather.logs``, a ``version`` file whose first line names the product ("openshift/must-gather"),
  and what the image's gather scripts wrote, mostly ``oc adm inspect`` output.
- ``oc adm inspect`` writes ``cluster-scoped-resources/<group>/<resource>/<name>.yaml`` and
  ``namespaces/<namespace>/<group>/<resource>.yaml`` (lists; the empty group is ``core``) or
  ``.../<resource>/<name>.yaml``, ``namespaces/<namespace>/<namespace>.yaml``, pods as
  ``namespaces/<namespace>/pods/<pod>/<pod>.yaml`` with logs in ``<pod>/<container>/<container>/logs/current.log``
  and ``previous.log`` (``*.insecure.log`` when TLS verification had to be skipped), and a ``timestamp`` file. It
  replaces every Secret value except ``tls.crt``, ``ca.crt`` and ``service-ca.crt`` with "N bytes long".

Rules: an archive member with an absolute path, a ``..`` segment or a NUL refuses the whole archive (a must-gather
never has one, so it was tampered with); symbolic links, hard links, devices and FIFOs are never followed or read
and are reported; files named like Secrets (``secrets.yaml``, anything under a ``secrets`` directory) are never
read, except OLM object files in the layout oc writes (``namespaces/<ns>/operators.coreos.com/...``), whose names
are operators' and namespaces'; nested archives are listed, not opened. Caps bound the member count, the bytes
processed (header sizes, so a gzip bomb stops at the cap), each file, what is kept in memory, and the nesting depth.
Resource YAML is kept whole up to ``MAX_FILE_BYTES``; logs keep their last ``LOG_TAIL_BYTES``.
"""

from __future__ import annotations

import os
import posixpath
import re
import stat
import tarfile
from collections import Counter, deque
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any

MAX_MEMBERS = 300_000
MAX_TOTAL_BYTES = 16 * 2**30  # processed, uncompressed
MAX_FILE_BYTES = 64 * 2**20  # a resource YAML kept whole
MAX_RETAINED_BYTES = 1 * 2**30
LOG_TAIL_BYTES = 1 * 2**20
MAX_DEPTH = 40
MAX_REPORTED = 200
ARCHIVE_SUFFIXES = (".tar", ".tar.gz", ".tgz")
_NESTED = re.compile(r"\.(?:gz|tgz|tar|zip|xz|bz2|zst|7z|rar)$", re.I)
_LOG = re.compile(r"\.log$|/logs/(?:rotated/)?[^/]+$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
GATHER_DIRS = ("cluster-scoped-resources", "namespaces")
#: The one reason ingest gives for the files it never opens by design (Secrets); completeness imports it.
NEVER_READ_REASON = "Secret data (never read)"


class MustGatherError(ValueError):
    """Not a must-gather we can open, or one that is unsafe or over the caps."""


# An OLM object file as oc adm inspect writes it. Its name is an operator's or a namespace's, never a Secret's, so a
# CSV named `secrets-store-csi-driver-operator.v4.14.0` or a namespace called `secrets` is read rather than
# dropped as "Secret data" -- which made the operator inventory answer without a real operator (G270).
_OLM_OBJECT = re.compile(
    r"(?:^|/)namespaces/[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?/operators\.coreos\.com/"
    r"(?:clusterserviceversions|subscriptions|installplans|operatorgroups)(?:\.(?:ya?ml|json)|/[^/]+\.(?:ya?ml|json))\Z"
)
MAX_SKIPPED_PATHS = 20_000


def secret_like(path: str) -> bool:
    """A file kube-noob never reads: ``secrets.yaml``, a file under a ``secrets`` directory, or a file named for one
    Secret (``secret-<name>.yaml``). An OLM object file in the layout oc adm inspect writes is not one."""
    if _OLM_OBJECT.search(path):
        return False
    parts = path.lower().split("/")
    name = parts[-1]
    return (
        "secrets" in parts[:-1]
        or name in {"secrets.yaml", "secrets.yml", "secrets.json", "secret.yaml", "secret.yml"}
        or bool(re.match(r"^secrets?[-_.]", name))
    )


def classify(path: str) -> str:
    """resource | log | meta | archive | other"""
    name = posixpath.basename(path)
    if name in {"version", "timestamp"} or name.endswith(".logs"):
        return "meta"
    if _NESTED.search(name):
        return "archive"
    if _LOG.search(path):
        return "log"
    if name.endswith((".yaml", ".yml", ".json")):
        return "resource"
    return "other"


@dataclass
class GatherRoot:
    prefix: str  # path of the directory holding cluster-scoped-resources/ or namespaces/ ("" for the top)
    version: str = ""  # first lines of its version file
    timestamp: str = ""
    resources: Counter[str] = field(default_factory=Counter)  # "<group>/<resource>" -> files
    namespaces: set[str] = field(default_factory=set)
    pods: set[str] = field(default_factory=set)
    logs: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.prefix or ".",
            "image": posixpath.basename(self.prefix) if self.prefix else "",
            "version": self.version,
            "timestamp": self.timestamp,
            "resourceFiles": sum(self.resources.values()),
            "resources": dict(sorted(self.resources.items(), key=lambda kv: (-kv[1], kv[0]))[:50]),
            "namespaces": len(self.namespaces),
            "pods": len(self.pods),
            "logs": self.logs,
        }


@dataclass
class Bundle:
    source: str
    kind: str  # directory | tar
    files: dict[str, bytes] = field(default_factory=dict)  # kept: resources, log tails, version, timestamp
    listed: int = 0
    total_bytes: int = 0
    kept_bytes: int = 0
    roots: dict[str, GatherRoot] = field(default_factory=dict)
    skipped: Counter[str] = field(default_factory=Counter)
    examples: dict[str, list[str]] = field(default_factory=dict)
    truncated: list[str] = field(default_factory=list)  # logs cut to their tail
    #: Every skipped path with its reason (up to MAX_SKIPPED_PATHS; past that only counted), so a reader that needs
    #: a kind of file can tell "not in the must-gather" from "in it, and not read".
    skipped_paths: list[tuple[str, str]] = field(default_factory=list)
    skipped_unlisted: int = 0

    def skip(self, reason: str, path: str) -> None:
        self.skipped[reason] += 1
        if len(self.skipped_paths) < MAX_SKIPPED_PATHS:
            self.skipped_paths.append((path, reason))
        else:
            self.skipped_unlisted += 1
        ex = self.examples.setdefault(reason, [])
        if len(ex) < 5:
            ex.append(_CONTROL.sub("?", path)[:300])

    def text(self, path: str) -> str:
        return self.files[path].decode("utf-8", "replace")

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "kind": self.kind,
            "files": self.listed,
            "bytes": self.total_bytes,
            "kept": {"files": len(self.files), "bytes": self.kept_bytes, "logsCutToTail": len(self.truncated)},
            "gatherRoots": [r.as_dict() for r in sorted(self.roots.values(), key=lambda r: r.prefix)],
            "skipped": [
                {"reason": reason, "count": n, "examples": self.examples.get(reason, [])}
                for reason, n in sorted(self.skipped.items(), key=lambda kv: (-kv[1], kv[0]))
            ],
        }


def root_of(path: str) -> tuple[str, list[str]] | None:
    """(gather root prefix, the parts after it) for paths under cluster-scoped-resources/ or namespaces/."""
    parts = path.split("/")
    for i, part in enumerate(parts[:-1]):
        if part in GATHER_DIRS:
            return "/".join(parts[:i]), parts[i:]
    return None


def _note(bundle: Bundle, path: str, kind: str) -> None:
    found = root_of(path)
    if found is None:
        return
    prefix, rest = found
    root = bundle.roots.setdefault(prefix, GatherRoot(prefix))
    if rest[0] == "cluster-scoped-resources" and len(rest) >= 3 and kind == "resource":
        root.resources[f"{rest[1]}/{rest[2].removesuffix('.yaml')}"] += 1
    elif rest[0] == "namespaces" and len(rest) >= 2:
        root.namespaces.add(rest[1])
        if len(rest) >= 4 and rest[2] == "pods":
            root.pods.add(f"{rest[1]}/{rest[3]}")
        elif len(rest) >= 4 and kind == "resource":
            root.resources[f"{rest[2]}/{rest[3].removesuffix('.yaml')}"] += 1
    if kind == "log":
        root.logs += 1


def _meta(bundle: Bundle, path: str, data: bytes) -> None:
    """A ``version`` or ``timestamp`` file: it belongs to the gather root in its directory; a top-level timestamp
    (``must-gather.local.*/timestamp``) also dates the roots below it that have none of their own."""
    name = posixpath.basename(path)
    parent = posixpath.dirname(path)
    text = data[:4096].decode("utf-8", "replace")
    lines = [_CONTROL.sub(" ", x).strip() for x in text.splitlines() if x.strip()][:3]
    bundle.files[path] = data[:4096]
    for prefix, root in bundle.roots.items():
        own = prefix == parent
        above = not own and (parent == "" or prefix.startswith(parent + "/"))
        if name == "version" and own:
            root.version = " ".join(lines)[:200]
        elif name == "timestamp" and (own or (above and not root.timestamp)):
            # Go's time.Time String() ends with the monotonic clock reading (" m=+0.03"): not a time, dropped
            root.timestamp = re.sub(r"\s+m=[+-][0-9.]+$", "", lines[0] if lines else "")[:100]


def _keep(bundle: Bundle, path: str, kind: str, size: int, read: Any) -> None:
    """Read a member through ``read(n)`` and keep it (whole, or a log's tail)."""
    if kind == "resource":
        if size > MAX_FILE_BYTES:
            bundle.skip(f"larger than {MAX_FILE_BYTES // 2**20} MiB (not read)", path)
            return
        data = read(MAX_FILE_BYTES + 1)
    else:  # a log: stream it, keep the tail
        tail: deque[bytes] = deque()
        kept = 0
        while True:
            chunk = read(1 << 20)
            if not chunk:
                break
            tail.append(chunk)
            kept += len(chunk)
            while kept - len(tail[0]) >= LOG_TAIL_BYTES:
                kept -= len(tail.popleft())
        data = b"".join(tail)
        if len(data) > LOG_TAIL_BYTES:
            data = data[-LOG_TAIL_BYTES:]
            nl = data.find(b"\n")
            data = data[nl + 1 :] if 0 <= nl < 4096 else data
            bundle.truncated.append(path)
        elif size > len(data):
            bundle.truncated.append(path)
    if bundle.kept_bytes + len(data) > MAX_RETAINED_BYTES:
        bundle.skip(f"over the {MAX_RETAINED_BYTES // 2**30} GiB kept in memory (not read)", path)
        return
    bundle.files[path] = data
    bundle.kept_bytes += len(data)


def _clean(name: str) -> str:
    """A member name as a relative POSIX path; refuses absolute paths, ``..`` and NULs."""
    if "\x00" in name:
        raise MustGatherError(f"unsafe archive: a member name holds a NUL byte ({name[:80]!r})")
    raw = name.replace("\\", "/")
    if raw.startswith("/") or re.match(r"^[A-Za-z]:/", raw):
        raise MustGatherError(f"unsafe archive: absolute member path {name[:200]!r}")
    if ".." in raw.split("/"):
        raise MustGatherError(f"unsafe archive: member path {name[:200]!r} leaves the archive root")
    norm = posixpath.normpath(raw)
    return "" if norm == "." else norm


def _visit(bundle: Bundle, path: str, size: int) -> str | None:
    """Count a regular file; the kind to read it as, or None to skip it."""
    bundle.listed += 1
    if bundle.listed > MAX_MEMBERS:
        raise MustGatherError(f"more than {MAX_MEMBERS} files: not a must-gather kube-noob reads")
    bundle.total_bytes += size
    if bundle.total_bytes > MAX_TOTAL_BYTES:
        raise MustGatherError(f"more than {MAX_TOTAL_BYTES // 2**30} GiB: not a must-gather kube-noob reads")
    if path.count("/") >= MAX_DEPTH:
        bundle.skip(f"nested deeper than {MAX_DEPTH} directories (not read)", path)
        return None
    if _CONTROL.search(path):
        bundle.skip("control characters in the name (not read)", path)
        return None
    if secret_like(path):
        bundle.skip(NEVER_READ_REASON, path)
        return None
    kind = classify(path)
    _note(bundle, path, kind)
    if kind == "archive":
        bundle.skip("nested archive (not opened)", path)
        return None
    if kind == "other":
        return None
    return kind


def _from_tar(path: Path, bundle: Bundle) -> None:
    try:
        tf = tarfile.open(path, mode="r|*")  # noqa: SIM115 - a stream read in order below, nothing seeked or extracted
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise MustGatherError(f"{path.name}: not a tar archive ({type(exc).__name__})") from exc
    metas: list[tuple[str, bytes]] = []
    with tf:
        try:
            for member in tf:
                name = _clean(member.name)
                if not name:
                    continue
                if member.isdir():
                    continue
                if member.issym() or member.islnk():
                    bundle.skip("link (never followed)", name)
                    bundle.listed += 1
                    continue
                if not member.isreg() or member.issparse():
                    bundle.skip("device, FIFO or sparse file (not read)", name)
                    bundle.listed += 1
                    continue
                kind = _visit(bundle, name, member.size)
                if kind is None:
                    continue
                f: IO[bytes] | None = tf.extractfile(member)
                if f is None:
                    continue
                if kind == "meta":
                    metas.append((name, f.read(4096)))
                    continue
                _keep(bundle, name, kind, member.size, f.read)
        except (tarfile.TarError, EOFError, OSError, ValueError) as exc:
            if isinstance(exc, MustGatherError):
                raise
            raise MustGatherError(f"{path.name}: the archive is damaged ({type(exc).__name__}: {exc})"[:300]) from exc
    for name, data in metas:
        _meta(bundle, name, data)


def _walk(root: Path) -> Iterator[tuple[str, os.stat_result]]:
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel_dir = os.path.relpath(dirpath, root).replace(os.sep, "/")
        rel_dir = "" if rel_dir == "." else rel_dir
        keep = []
        for d in sorted(dirnames):
            st = os.lstat(os.path.join(dirpath, d))
            if stat.S_ISLNK(st.st_mode):
                yield (f"{rel_dir}/{d}".lstrip("/"), st)
            else:
                keep.append(d)
        dirnames[:] = keep
        for fn in sorted(filenames):
            yield (f"{rel_dir}/{fn}".lstrip("/"), os.lstat(os.path.join(dirpath, fn)))


def _from_dir(root: Path, bundle: Bundle) -> None:
    metas: list[tuple[str, bytes]] = []
    for rel, st in _walk(root):
        if stat.S_ISLNK(st.st_mode):
            bundle.skip("link (never followed)", rel)
            bundle.listed += 1
            continue
        if not stat.S_ISREG(st.st_mode):
            bundle.skip("device, FIFO or sparse file (not read)", rel)
            bundle.listed += 1
            continue
        kind = _visit(bundle, rel, st.st_size)
        if kind is None:
            continue
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(root / rel, flags)
        except OSError:
            bundle.skip("could not be opened (not read)", rel)
            continue
        with os.fdopen(fd, "rb") as f:
            if kind == "meta":
                metas.append((rel, f.read(4096)))
                continue
            _keep(bundle, rel, kind, st.st_size, f.read)
    for name, data in metas:
        _meta(bundle, name, data)


def open_bundle(path: Path) -> Bundle:
    """The must-gather at ``path``: a directory, or a ``.tar``, ``.tar.gz`` or ``.tgz`` archive."""
    if path.is_symlink():
        raise MustGatherError(f"{path}: a symbolic link; pass the must-gather itself")
    if path.is_dir():
        bundle = Bundle(str(path), "directory")
        _from_dir(path, bundle)
    elif path.is_file():
        if not path.name.lower().endswith(ARCHIVE_SUFFIXES):
            raise MustGatherError(f"{path.name}: pass a must-gather directory or a .tar, .tar.gz or .tgz archive")
        bundle = Bundle(str(path), "tar")
        _from_tar(path, bundle)
    else:
        raise MustGatherError(f"{path}: no such file or directory")
    if not bundle.roots:
        raise MustGatherError(
            f"{path.name}: no cluster-scoped-resources/ or namespaces/ directory; not a must-gather or inspect output"
        )
    return bundle


def render_text(bundle: Bundle) -> str:
    d = bundle.as_dict()
    lines = [
        f"must-gather {bundle.source} ({bundle.kind}): {d['files']} files, {d['bytes'] // 2**20} MiB; "
        f"kept {d['kept']['files']} files, {d['kept']['bytes'] // 2**20} MiB",
    ]
    for r in d["gatherRoots"]:
        when = f", collected {r['timestamp']}" if r["timestamp"] else ""
        lines.append(f"  {r['path']}: {r['version'] or 'no version file'}{when}")
        top = ", ".join(f"{k} {v}" for k, v in list(r["resources"].items())[:8])
        lines.append(
            f"    {r['resourceFiles']} resource files ({top}); {r['namespaces']} namespaces, {r['pods']} pods, "
            f"{r['logs']} logs"
        )
    for s in d["skipped"]:
        example = f" (e.g. {s['examples'][0]})" if s["examples"] else ""
        lines.append(f"  skipped {s['count']}: {s['reason']}{example}")
    return "\n".join(lines)
