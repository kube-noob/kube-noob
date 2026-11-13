"""Secret shapes for Containerfiles and image layers: what a credential looks like, never what it is.

Findings carry the kind, where it is and a masked preview (the first four characters); the value itself never leaves
this module. Patterns are bounded so a hostile file cannot make matching slow.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePosixPath

# Content: (kind, pattern). Each names one credential format.
CONTENT: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----")),
    ("AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b|\bgithub_pat_[A-Za-z0-9_]{22,255}\b")),
    ("GitLab token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,64}\b")),
    ("Slack token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,255}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("Vault token", re.compile(r"\bhv[sbr]\.[A-Za-z0-9_-]{20,255}\b")),
    ("JSON web token", re.compile(r"\beyJ[A-Za-z0-9_-]{8,2000}\.eyJ[A-Za-z0-9_-]{8,4000}\.[A-Za-z0-9_-]{8,2000}")),
    ("npm token", re.compile(r":_authToken=(?!\$\{)[^\s]{8,255}|\bnpm_[A-Za-z0-9]{36}\b")),
    ("registry auth", re.compile(r'"auth"\s{0,5}:\s{0,5}"[A-Za-z0-9+/=]{12,2000}"')),
    ("URL with a password", re.compile(r"\b[a-z][a-z0-9+.-]{1,20}://[^\s:/@]{1,100}:[^\s@/$]{3,200}@[\w.-]{1,253}")),
    (
        "Kubernetes credential",
        re.compile(r"^\s{0,40}(?:token|client-key-data|client-certificate-data):\s{0,5}[A-Za-z0-9+/=._-]{20,}", re.M),
    ),
    (
        "password assignment",
        re.compile(
            r"(?i)\b[\w.-]{0,40}(?:password|passwd|secret|api[_-]?key|access[_-]?key|token)[\w.-]{0,20}\s{0,5}[:=]\s{0,5}"
            r"[\"']?(?!\$|\{\{|<|changeme\b|example\b|xxx|\*{3})[^\s\"'#]{8,200}"
        ),
    ),
)
# File names that hold credentials whatever their contents (compared on the last path segments).
NAMES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "private key file",  # .pem is left to the content check: in images most are certificates (CA, product)
        re.compile(r"(?:^|/)(?:id_(?:rsa|dsa|ecdsa|ed25519)|[\w.-]{1,100}\.(?:key|p12|pfx|jks|keystore))$"),
    ),
    ("environment file", re.compile(r"(?:^|/)\.env(?:\.[\w-]{1,30})?$")),
    ("package registry credentials", re.compile(r"(?:^|/)\.(?:npmrc|pypirc|netrc|git-credentials)$")),
    (
        "cloud credentials",
        re.compile(
            r"(?:^|/)\.aws/credentials$|(?:^|/)credentials\.json$|"
            r"(?:^|/)service[-_]account[\w-]{0,40}\.json$|(?:^|/)\.config/gcloud/"
        ),
    ),
    ("registry credentials", re.compile(r"(?:^|/)\.docker/config\.json$|(?:^|/)auth\.json$|(?:^|/)\.dockercfg$")),
    ("kubeconfig", re.compile(r"(?:^|/)\.kube/config$|(?:^|/)kubeconfig(?:\.ya?ml)?$")),
)
# Public certificates and examples that look like key files but are not secrets.
_NOT_SECRET = re.compile(
    r"(?:^|/)(?:etc/ssl/certs|etc/pki/(?:ca-trust|tls/certs)|usr/share/(?:ca-certificates|doc|man)|"
    r"usr/lib/python3[\w.]*/site-packages/[\w.-]+/tests?|node_modules/[\w@.-]+/(?:test|fixtures?|example)s?)/|"
    r"(?:^|/)[\w.-]*(?:example|sample|template|test|dummy|fake)[\w.-]*$|\.(?:crt|cert)$|\.env\.(?:example|sample|"
    r"template|dist)$|/cacert\.pem$|/ca-bundle[\w.-]*\.pem$|/certifi/cacert\.pem$"
)
_PUBLIC_PEM = re.compile(r"-----BEGIN (?:CERTIFICATE|PUBLIC KEY|X509 CRL)-----")


@dataclass(frozen=True)
class Hit:
    kind: str
    where: str  # a path, an instruction, a layer and path
    line: int | None
    preview: str  # four characters and a mask, never the value

    def as_dict(self) -> dict[str, object]:
        out: dict[str, object] = {"kind": self.kind, "where": self.where, "preview": self.preview}
        if self.line is not None:
            out["line"] = self.line
        return out


# Formats whose first characters are a fixed prefix (ghp_, AKIA, xoxb, AIza, hvs., glpat, npm_, eyJ): showing them
# says which kind of token it is and nothing of the secret part. Everything else is masked whole.
_PREFIXED = frozenset(
    {
        "AWS access key id",
        "GitHub token",
        "GitLab token",
        "Slack token",
        "Google API key",
        "Vault token",
        "npm token",
        "JSON web token",
    }
)


def mask(value: str, kind: str = "") -> str:
    v = value.strip().strip("\"'")
    return (v[:4] + "****") if kind in _PREFIXED and len(v) > 8 else "****"


def _relative(path: str) -> str:
    """``./a/b``, ``/a/b`` and ``a/b`` are the same path (prefixes removed, never the dots of a dotfile)."""
    while path.startswith(("./", "/")):
        path = path[2:] if path.startswith("./") else path[1:]
    return path


def name_kind(path: str) -> str | None:
    """The kind of credential file a path names, or None (certificates, examples and test data are not secrets)."""
    p = str(PurePosixPath("/" + _relative(path)))
    if _NOT_SECRET.search(p):
        return None
    for kind, rx in NAMES:
        if rx.search(p):
            return kind
    return None


_REF_KEY = re.compile(r"(?i)_(?:FILE|PATH|DIR|URL|URI|HOST|USER|USERNAME|NAME|REF|ENV|ID)\s{0,5}[:=]")
_REF_VALUE = re.compile(r"[:=]\s{0,5}[\"']?(?:/|\$|https?://|file:|vault:|secret(?:s)?/|arn:)")


def _reference(assignment: str) -> bool:
    """A setting that points at a credential (a file, a variable, a vault path) rather than holding one."""
    return bool(_REF_KEY.search(assignment) or _REF_VALUE.search(assignment))


def scan_text(text: str, where: str, *, assignments: bool = True, limit: int = 20) -> list[Hit]:
    """Credential shapes in text. ``assignments`` adds ``password=...``-style lines (off for files that merely
    mention the words, such as source code)."""
    hits: list[Hit] = []
    if _PUBLIC_PEM.search(text) and not CONTENT[0][1].search(text):
        return hits  # a certificate bundle: public by design
    for n, full in enumerate(text.splitlines()[:200_000], 1):
        line = full[:8_000]
        for kind, rx in CONTENT:
            if kind == "password assignment" and not assignments:
                continue
            m = rx.search(line)
            if m and not (kind == "password assignment" and _reference(m.group(0))):
                hits.append(Hit(kind, where, n, mask(m.group(0), kind)))
                break
        if len(hits) >= limit:
            break
    return hits
