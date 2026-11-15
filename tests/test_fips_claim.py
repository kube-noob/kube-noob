"""docs/compliance.md said kube-noob's crypto "runs in the validated module" and that `doctor` checks FIPS mode.

`doctor` reads two things and prints one line. It cannot establish that any module is CMVP-validated, and the
code does not use "only SHA-256 and the system OpenSSL": sealing a Jira snapshot is AES-256-GCM through the
`cryptography` package, whose wheel carries its own OpenSSL build. The SC-13 row and the posture output now state
what is read, what is printed and which primitives the code calls, and make no validation claim (G292).
"""

from __future__ import annotations

import ast
import hashlib
import re
from pathlib import Path

import pytest

from kube_noob.config import load_settings
from kube_noob.posture import crypto_posture, posture, render_text

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "compliance.md"


def _sc13_row() -> str:
    lines = DOC.read_text(encoding="utf-8").splitlines()
    rows = [x for x in lines if x.startswith("| SC-13 | ") and x != "| SC-13 | Cryptographic Protection |"]
    assert len(rows) == 1, rows  # the deployment row; the control-titles table has its own SC-13 line
    return rows[0]


CRYPTO_MODULES = ("hashlib", "hmac", "uuid", "secrets", "ssl", "cryptography")


def _primitives_in(tree: ast.AST) -> set[str]:
    """Every reference to a crypto, hash, id or random primitive in one module, by its qualified name, however it
    is spelled: `hashlib.sha256(...)`, `from hashlib import sha256`, `import hashlib as h; h.sha256`, a bare
    reference without a call (`D = hashlib.sha1`), and `hashlib.new("md5")` with its named algorithm. A regex on
    call syntax missed four of those (review, G292)."""
    modules: dict[str, str] = {}  # local name -> module
    names: dict[str, str] = {}  # local name -> qualified primitive
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] in CRYPTO_MODULES:
                    modules[a.asname or a.name.split(".")[0]] = a.name
        elif isinstance(node, ast.ImportFrom) and node.module and node.module.split(".")[0] in CRYPTO_MODULES:
            for a in node.names:
                names[a.asname or a.name] = f"{node.module}.{a.name}"
                found.add(f"{node.module}.{a.name}")
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id in modules:
            found.add(f"{modules[node.value.id]}.{node.attr}")
        elif isinstance(node, ast.Name) and node.id in names:
            found.add(names[node.id])
        if isinstance(node, ast.Call):
            fn = node.func
            target = None
            if isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name) and fn.value.id in modules:
                target = f"{modules[fn.value.id]}.{fn.attr}"
            elif isinstance(fn, ast.Name) and fn.id in names:
                target = names[fn.id]
            if target in {"hashlib.new", "hmac.new"} and node.args and isinstance(node.args[-1], ast.Constant):
                found.add(f"{target}({node.args[-1].value})")
            if target == "hmac.new":
                for kw in node.keywords:
                    if kw.arg == "digestmod" and isinstance(kw.value, ast.Constant):
                        found.add(f"hmac.new({kw.value.value})")
    return {f for f in found if not f.startswith("uuid.NAMESPACE_")}


def _primitives_in_source() -> set[str]:
    out: set[str] = set()
    for p in (ROOT / "src" / "kube_noob").rglob("*.py"):
        out |= _primitives_in(ast.parse(p.read_text(encoding="utf-8")))
    return out


NEGATIVE_CORPUS = {
    "from hashlib import md5\nmd5(b'x')": "hashlib.md5",
    "import hashlib as h\nh.md5(b'x')": "hashlib.md5",
    "import hashlib\nD = hashlib.sha1": "hashlib.sha1",
    "import hashlib\nhashlib.new('md5')": "hashlib.new(md5)",
    "import hmac\nhmac.new(b'k', b'm', digestmod='md5')": "hmac.new(md5)",
    "import uuid\nuuid.uuid3(uuid.NAMESPACE_DNS, 'x')": "uuid.uuid3",
    "from uuid import uuid5 as five\nfive(None, 'x')": "uuid.uuid5",
    "import secrets\nsecrets.token_urlsafe()": "secrets.token_urlsafe",
    "from cryptography.hazmat.primitives.ciphers import algorithms\nalgorithms.TripleDES": (
        "cryptography.hazmat.primitives.ciphers.algorithms"
    ),
}


def test_the_primitive_scan_catches_every_spelling_the_review_got_past_it() -> None:
    for code, expected in NEGATIVE_CORPUS.items():
        assert expected in _primitives_in(ast.parse(code)), (code, expected)
    assert _primitives_in(ast.parse("from kube_noob.build import secrets\nsecrets.scan_text('x')")) == set()


EXPECTED = {
    "hashlib.sha256",
    "hashlib.pbkdf2_hmac",
    "hmac.compare_digest",
    "uuid.uuid4",
    "uuid.uuid5",
    "secrets.token_bytes",
    "secrets.token_hex",
    "cryptography.hazmat.primitives.ciphers.aead.AESGCM",
    "cryptography.exceptions.InvalidTag",
    "ssl.create_default_context",
    "ssl.SSLContext",
    "ssl.SSLError",
    "ssl.OPENSSL_VERSION",
}


def test_the_code_uses_exactly_the_primitives_the_document_names() -> None:
    """The list in the document is derived from the source, so a new primitive fails here before it ships."""
    found = _primitives_in_source()
    assert found == EXPECTED, {"new": found - EXPECTED, "gone": EXPECTED - found}
    assert not any(".md5" in f or ".sha1" in f or "(md5)" in f or "(sha1)" in f for f in found)
    row = _sc13_row()
    algorithms = crypto_posture()["algorithms"]
    words = ("SHA-256", "PBKDF2-HMAC-SHA256", "HMAC", "AES-256-GCM", "`cryptography`", "TLS")
    words += ("UUIDv5", "SHA-1", "`secrets`")
    for word in words:
        assert word in row, word
        assert word.strip("`") in algorithms, word
    assert "own OpenSSL build" in row and "own OpenSSL build" in algorithms
    assert "no MD5, SHA-1" not in algorithms and "no MD5, SHA-1" not in row, "the code uses SHA-1 through UUIDv5"


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
    assert "OpenSSL's reading decides" in row and "kernel flag disagrees" in row
    assert "`_sha2`" in row and "`_sha256`" in row, "the built-in module is named per Python version"
    for claim in ("runs in the validated module", "uses only SHA-256", "FIPS-validated", "must show"):
        assert claim not in row, claim
    gaps = DOC.read_text(encoding="utf-8")
    assert "FIPS mode is checked by `doctor`" not in gaps
    assert "`doctor` reports the kernel flag and OpenSSL's mode; it validates nothing" in gaps


def test_doctor_reports_which_sha256_it_runs_and_what_it_read() -> None:
    c = crypto_posture()
    module = type(hashlib.sha256()).__module__
    backend = "OpenSSL (_hashlib)" if module == "_hashlib" else f"CPython built-in ({module})"
    assert c["sha256Backend"] == backend
    assert "_sha2)" not in c["sha256Backend"] or module == "_sha2", "never a hard-coded module name"
    assert set(c) >= {"fipsMode", "kernelFipsEnabled", "opensslFipsMode", "openssl", "algorithms", "sha256Backend"}
    assert c["kernelFipsEnabled"] in {True, False, None} and c["opensslFipsMode"] in {True, False, None}
    assert "validated" not in (crypto_posture.__doc__ or "").replace("CMVP-validated: that is", "")
    text = render_text(posture(load_settings()))
    assert f"sha256 backend {backend}" in text


@pytest.mark.parametrize(
    ("kernel", "openssl", "mode", "disagree"),
    [
        (True, True, "on", False),
        (True, False, "off", True),
        (True, None, "on", False),
        (False, True, "on", True),
        (False, False, "off", False),
        (False, None, "off", False),
        (None, True, "on", False),
        (None, False, "off", False),
        (None, None, "unknown", False),
    ],
)
def test_the_fips_truth_table_is_the_one_the_document_states(
    monkeypatch: pytest.MonkeyPatch, kernel: bool | None, openssl: bool | None, mode: str, disagree: bool
) -> None:
    """OpenSSL's reading decides; the kernel flag decides only when OpenSSL's could not be read; a disagreement
    is said, in JSON and on the text line (review finding 6)."""
    import _hashlib

    from kube_noob import host_fips

    monkeypatch.setattr(host_fips, "kernel_fips", lambda: kernel)
    if openssl is None:
        monkeypatch.delattr(_hashlib, "get_fips_mode", raising=False)
    else:
        monkeypatch.setattr(_hashlib, "get_fips_mode", lambda: int(openssl))
    c = crypto_posture()
    assert c["fipsMode"] == mode
    assert ("fipsNote" in c) == disagree
    text = render_text(posture(load_settings()))
    line = next(x for x in text.splitlines() if x.strip().startswith("FIPS mode"))
    assert ("kernel flag disagrees" in line) == disagree, line
