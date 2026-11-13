"""docs/compliance.md said kube-noob's crypto "runs in the validated module" and that `doctor` checks FIPS mode.

`doctor` reads two things and prints one line. It cannot establish that any module is CMVP-validated, and the
code does not use "only SHA-256 and the system OpenSSL": sealing a Jira snapshot is AES-256-GCM through the
`cryptography` package, whose wheel carries its own OpenSSL build. The SC-13 row and the posture output now state
what is read, what is printed and which primitives the code calls, and make no validation claim (G292).
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from kube_noob.config import load_settings
from kube_noob.posture import crypto_posture, posture, render_text

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "compliance.md"


def _sc13_row() -> str:
    lines = DOC.read_text(encoding="utf-8").splitlines()
    rows = [x for x in lines if x.startswith("| SC-13 | ") and x != "| SC-13 | Cryptographic Protection |"]
    assert len(rows) == 1, rows  # the deployment row; the control-titles table has its own SC-13 line
    return rows[0]


def _primitives_in_source() -> set[str]:
    names: set[str] = set()
    for p in (ROOT / "src" / "kube_noob").rglob("*.py"):
        text = p.read_text(encoding="utf-8")
        names.update(f"hashlib.{m}" for m in re.findall(r"\bhashlib\.([a-z0-9_]+)\(", text))
        names.update(f"hmac.{m}" for m in re.findall(r"\bhmac\.([a-z_]+)\(", text))
        names.update(re.findall(r"from cryptography\.hazmat\.primitives\.ciphers\.aead import (\w+)", text))
        if re.search(r"^\s*import ssl\b|^\s*from ssl\b|ssl\.create_default_context", text, re.M):
            names.add("ssl")
    return names


def test_the_code_uses_exactly_the_primitives_the_document_names() -> None:
    """The list in the document is derived from the source, so a new primitive fails here before it ships."""
    assert _primitives_in_source() == {"hashlib.sha256", "hashlib.pbkdf2_hmac", "hmac.compare_digest", "AESGCM", "ssl"}
    row = _sc13_row()
    algorithms = crypto_posture()["algorithms"]
    for word in ("SHA-256", "PBKDF2-HMAC-SHA256", "HMAC", "AES-256-GCM", "`cryptography`", "TLS"):
        assert word in row, word
        assert word.strip("`") in algorithms, word
    assert "own OpenSSL build" in row and "own OpenSSL build" in algorithms


def test_the_sc13_row_states_what_doctor_reads_and_prints_and_makes_no_validation_claim() -> None:
    row = _sc13_row()
    for source in ("`/proc/sys/crypto/fips_enabled`", "`_hashlib.get_fips_mode()`", "`ssl.OPENSSL_VERSION`"):
        assert source in row, source
    quoted = set(re.findall(r"`FIPS mode (\w+)`", row))
    assert quoted == {"on", "off", "unknown"}, "every value the line can carry is named, and nothing else"
    line = next(x for x in render_text(posture(load_settings())).splitlines() if x.strip().startswith("FIPS mode"))
    assert re.fullmatch(r"\s*FIPS mode\s+(on|off|unknown) \(.+\)", line), line
    assert "sha256 backend" in render_text(posture(load_settings()))
    assert "CMVP" in row and "makes no validation claim" in row
    assert "certificate" in row and "module name" in row and "version" in row
    for claim in ("runs in the validated module", "uses only SHA-256", "FIPS-validated", "must show"):
        assert claim not in row, claim
    gaps = DOC.read_text(encoding="utf-8")
    assert "FIPS mode is checked by `doctor`" not in gaps
    assert "`doctor` reports the kernel flag and OpenSSL's mode; it validates nothing" in gaps


def test_doctor_reports_which_sha256_it_runs_and_what_it_read() -> None:
    c = crypto_posture()
    backend = "OpenSSL (_hashlib)" if type(hashlib.sha256()).__module__ == "_hashlib" else "CPython built-in (_sha2)"
    assert c["sha256Backend"] == backend
    assert set(c) >= {"fipsMode", "kernelFipsEnabled", "opensslFipsMode", "openssl", "algorithms", "sha256Backend"}
    assert c["kernelFipsEnabled"] in {True, False, None} and c["opensslFipsMode"] in {True, False, None}
    assert "validated" not in (crypto_posture.__doc__ or "").replace("CMVP-validated: that is", "")
    text = render_text(posture(load_settings()))
    assert f"sha256 backend {backend}" in text
