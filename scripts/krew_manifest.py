#!/usr/bin/env python3
"""Build the krew plugin: the entry-point script, its archive (with the licence) and the krew-index manifest.

`krew/kubectl-noob.in` is the source; the version is substituted into it here so the committed
`krew/kubectl-noob` is the file that actually ships, and `krew/noob.yaml` carries the SHA-256 of the archive
built from it. The archive is byte-reproducible -- fixed mtime, uid, gid and name, and gzip with no timestamp and
no compression, because compressed bytes differ between zlib builds --
so the digest in the manifest is a property of the script rather than of the machine that packed it. Without
that, every release would produce a different hash for identical content and the manifest could not be checked.

One platform entry covers Linux and macOS: the plugin is a POSIX shell script, so there is no architecture
matrix to publish. Windows is not claimed, because the script is not a Windows executable.

    python scripts/krew_manifest.py --check    # exit 1 when the committed files are stale
    python scripts/krew_manifest.py            # rewrite them
    python scripts/krew_manifest.py --archive dist/kubectl-noob.tar.gz   # also write the release archive
"""

from __future__ import annotations

import argparse
import hashlib
import io
import re
import sys
import tarfile
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "krew" / "kubectl-noob.in"
SCRIPT = ROOT / "krew" / "kubectl-noob"
MANIFEST = ROOT / "krew" / "noob.yaml"
LICENSE = ROOT / "LICENSE"
PLUGIN_NAME = "noob"
BIN = "kubectl-noob"
REPO = "https://github.com/kube-noob/kube-noob"


def version() -> str:
    text = (ROOT / "src" / "kube_noob" / "__init__.py").read_text(encoding="utf-8")
    m = re.search(r'__version__ = "(.+)"', text)
    if m is None:  # pragma: no cover - the package always declares one
        raise SystemExit("src/kube_noob/__init__.py declares no __version__")
    return m.group(1)


def script(ver: str | None = None) -> str:
    """The entry-point script with the release version substituted for the placeholder."""
    text = TEMPLATE.read_text(encoding="utf-8")
    if "__VERSION__" not in text:
        raise SystemExit(f"{_rel(TEMPLATE)} has no __VERSION__ placeholder to substitute")
    return text.replace("__VERSION__", ver or version())


def _member(name: str, payload: bytes, mode: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size = len(payload)
    info.mode = mode
    info.mtime = 0
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.type = tarfile.REGTYPE
    return info


def archive(ver: str | None = None) -> bytes:
    """A reproducible .tar.gz holding the executable script, named as krew expects to find it, and the licence.

    krew's pre-submit checklist asks for the licence inside the archive and extracted at install
    (https://krew.sigs.k8s.io/docs/developer-guide/release/new-plugin/, read 2026-11-12). The manifest names no
    `files`, so krew extracts both. Archives up to v0.9.2 held the script alone.
    """
    members = ((BIN, script(ver).encode("utf-8"), 0o755), ("LICENSE", LICENSE.read_bytes(), 0o644))
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for name, payload, mode in members:
            tar.addfile(_member(name, payload, mode), io.BytesIO(payload))
    return _gzip_stored(raw.getvalue())


def _gzip_stored(data: bytes) -> bytes:
    """gzip (RFC 1952) whose deflate stream is stored blocks only (RFC 1951 BTYPE 00): no compression.

    Compressed deflate output is not a property of the input: zlib and zlib-ng, which some Python builds link,
    produce different bytes for the same data, so the same archive hashed differently on a developer's machine and
    in CI. A stored block has one encoding. The archive is about 16 KB either way. mtime 0, no file name, OS 255.
    """
    out = bytearray(b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff")
    chunks = [data[i : i + 0xFFFF] for i in range(0, len(data), 0xFFFF)] or [b""]
    for n, chunk in enumerate(chunks):
        out.append(1 if n == len(chunks) - 1 else 0)  # BFINAL on the last block, BTYPE 00, padded to the byte
        out += len(chunk).to_bytes(2, "little") + (len(chunk) ^ 0xFFFF).to_bytes(2, "little") + chunk
    out += zlib.crc32(data).to_bytes(4, "little") + (len(data) & 0xFFFFFFFF).to_bytes(4, "little")
    return bytes(out)


def manifest(ver: str | None = None) -> str:
    ver = ver or version()
    digest = hashlib.sha256(archive(ver)).hexdigest()
    uri = f"{REPO}/releases/download/v{ver}/{BIN}-v{ver}.tar.gz"
    return f"""apiVersion: krew.googlecontainertools.github.com/v1alpha2
kind: Plugin
metadata:
  name: {PLUGIN_NAME}
spec:
  version: v{ver}
  homepage: {REPO}
  shortDescription: Audit, debug and learn Kubernetes offline. No AI inside.
  description: |
    kube-noob audits manifests against {{rules}} deterministic rules, explains why a NetworkPolicy allows or
    denies traffic, diagnoses pasted events and logs, and reads an OpenShift must-gather -- offline, with no
    model and no network. Findings name the NIST SP 800-53 Rev. 5 controls they are evidence for, and a verdict
    it cannot reach is reported as undetermined rather than as a pass.

    The plugin forwards every argument to the kube-noob CLI unchanged, so `kubectl noob --help` lists what it
    can do. It uses kube-noob from your PATH when it is there, and otherwise runs this pinned release through
    uvx, so the plugin is usable on a machine with no Python environment set up.
  caveats: |
    Needs either kube-noob on PATH (pipx install kube-noob=={ver}) or uv installed, in which case the pinned
    release is fetched from PyPI on first use. Nothing in kube-noob reaches the network or your cluster unless
    you enable it explicitly.
  platforms:
    - bin: {BIN}
      uri: {uri}
      sha256: {digest}
      selector:
        matchExpressions:
          - key: os
            operator: In
            values: [darwin, linux]
"""


def _rel(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true", help="exit 1 when the committed files are stale")
    ap.add_argument("--archive", type=Path, help="also write the release archive to this path")
    a = ap.parse_args(argv)
    rules = _rule_count()
    want_script, want_manifest = script(), manifest().replace("{rules}", str(rules))
    if a.check:
        stale = [
            _rel(p)
            for p, want in ((SCRIPT, want_script), (MANIFEST, want_manifest))
            if (p.read_text(encoding="utf-8") if p.is_file() else "") != want
        ]
        if stale:
            print(f"stale, run python scripts/krew_manifest.py: {', '.join(stale)}", file=sys.stderr)
            return 1
        print(f"{_rel(SCRIPT)} and {_rel(MANIFEST)} are current (v{version()}, {rules} rules)")
        return 0
    SCRIPT.write_text(want_script, encoding="utf-8")
    SCRIPT.chmod(0o755)
    MANIFEST.write_text(want_manifest, encoding="utf-8")
    print(f"wrote {_rel(SCRIPT)} and {_rel(MANIFEST)} (v{version()}, {rules} rules)")
    if a.archive:
        a.archive.parent.mkdir(parents=True, exist_ok=True)
        a.archive.write_bytes(archive())
        print(f"wrote {_rel(a.archive)} ({len(archive())} bytes)")
    return 0


def _rule_count() -> int:
    sys.path.insert(0, str(ROOT / "src"))
    from kube_noob.audit.rules import RULES

    return len(RULES)


if __name__ == "__main__":
    raise SystemExit(main())
