"""Seal a Jira snapshot with the organisation's own key: AES-256-GCM in 1 MiB chunks (requirements R1.4).

A sealed file is ``KNSEAL1\\n``, a 16-byte salt, the PBKDF2 iteration count and the chunk size (the header, which is
also every chunk's associated data), then the chunks. The file key is PBKDF2-HMAC-SHA256 of the secret and the
salt, so every file has its own key and chunk nonces can be counters: an 11-byte chunk number and a last-chunk flag
(the STREAM construction ``age`` uses). Reordered, dropped, truncated or altered chunks and a wrong key all fail the
tag check, and nothing is written in place of the output until every chunk has verified.

The secret comes from a file (a Kubernetes Secret mounted read-only, ``KUBE_NOOB_SEED_KEY_FILE``), never from the
chart's values or the image.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import struct
import tempfile
from pathlib import Path

MAGIC = b"KNSEAL1\n"
CHUNK = 1 << 20
ITERATIONS = 600_000
MIN_SECRET = 16
_HEADER = struct.Struct(">16sII")
HEADER_LEN = len(MAGIC) + _HEADER.size
MAX_CHUNK = 16 << 20
KEY_ENV = "KUBE_NOOB_SEED_KEY_FILE"


class SealError(ValueError):
    """The file is not sealed, the key does not open it, or it was altered."""


def _aead(key: bytes):  # type: ignore[no-untyped-def]
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:  # pragma: no cover - cryptography ships with kube-noob's dependencies
        raise SealError("sealing needs the cryptography package (pip install cryptography)") from exc
    return AESGCM(key)


def read_secret(path: Path | str | None = None) -> bytes:
    """The secret from ``path`` or the file named by ``KUBE_NOOB_SEED_KEY_FILE``; surrounding whitespace dropped."""
    where = path or os.environ.get(KEY_ENV)
    if not where:
        raise SealError(
            f"a sealed snapshot needs its key: pass --key-file or set {KEY_ENV} (chart: jira.seed.keySecret)"
        )
    try:
        raw = Path(where).read_bytes().strip()
    except OSError as exc:
        raise SealError(f"cannot read the key file {where}: {exc.strerror or exc}") from exc
    if len(raw) < MIN_SECRET:
        raise SealError(
            f"the key in {where} is shorter than {MIN_SECRET} characters; make one with: openssl rand -base64 32"
        )
    return raw


def is_sealed(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            return fh.read(len(MAGIC)) == MAGIC
    except OSError:
        return False


def _key(secret: bytes, salt: bytes, iterations: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", secret, salt, iterations, dklen=32)


def _nonce(counter: int, last: bool) -> bytes:
    return counter.to_bytes(11, "big") + (b"\x01" if last else b"\x00")


def _atomic_target(dst: Path) -> tuple[int, str]:
    dst.parent.mkdir(parents=True, exist_ok=True)
    return tempfile.mkstemp(dir=dst.parent, prefix=f".{dst.name}.", suffix=".tmp")


def seal(src: Path, dst: Path, secret: bytes, iterations: int = ITERATIONS, chunk: int = CHUNK) -> dict[str, int]:
    """Write ``src`` sealed to ``dst`` (owner-only)."""
    salt = secrets.token_bytes(16)
    header = MAGIC + _HEADER.pack(salt, iterations, chunk)
    aead = _aead(_key(secret, salt, iterations))
    fd, tmp = _atomic_target(dst)
    chunks = 0
    try:
        with os.fdopen(fd, "wb") as out, src.open("rb") as fh:
            os.chmod(tmp, 0o600)
            out.write(header)
            block = fh.read(chunk)
            while True:
                nxt = fh.read(chunk)
                last = not nxt
                out.write(aead.encrypt(_nonce(chunks, last), block, header))
                chunks += 1
                if last:
                    break
                block = nxt
        os.replace(tmp, dst)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return {"chunks": chunks, "bytes": dst.stat().st_size}


def unseal(src: Path, dst: Path, secret: bytes) -> dict[str, int]:
    """Write the plaintext of ``src`` to ``dst`` (owner-only) once every chunk has verified; SealError otherwise."""
    from cryptography.exceptions import InvalidTag

    fd, tmp = _atomic_target(dst)
    chunks = 0
    try:
        with os.fdopen(fd, "wb") as out, src.open("rb") as fh:
            os.chmod(tmp, 0o600)
            header = fh.read(HEADER_LEN)
            if len(header) < HEADER_LEN or not header.startswith(MAGIC):
                raise SealError(f"{src.name} is not a sealed kube-noob snapshot")
            salt, iterations, chunk = _HEADER.unpack(header[len(MAGIC) :])
            if not (10_000 <= iterations <= 10_000_000 and 1024 <= chunk <= MAX_CHUNK):
                raise SealError(f"{src.name}: header out of range (iterations {iterations}, chunk {chunk})")
            aead = _aead(_key(secret, salt, iterations))
            size = chunk + 16
            block = fh.read(size)
            if not block:
                raise SealError(f"{src.name} is truncated: no chunks after the header")
            while True:
                nxt = fh.read(size)
                last = not nxt
                try:
                    out.write(aead.decrypt(_nonce(chunks, last), block, header))
                except InvalidTag:
                    if chunks == 0:
                        raise SealError(
                            f"the key does not open {src.name} (a wrong key or a damaged file); nothing was imported"
                        ) from None
                    raise SealError(
                        f"{src.name} was altered or truncated after chunk {chunks}; nothing was imported"
                    ) from None
                chunks += 1
                if last:
                    break
                block = nxt
        os.replace(tmp, dst)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return {"chunks": chunks, "bytes": dst.stat().st_size}
