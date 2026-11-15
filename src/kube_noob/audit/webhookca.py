"""Whether an admission webhook's `clientConfig.caBundle` is a certificate the API server could use (G303).

A ValidatingWebhookConfiguration or MutatingWebhookConfiguration tells the API server which certificate
authority to verify the webhook's serving certificate against. The field is optional: with no `caBundle` the API
server verifies against the system trust roots on the API server's host, which for a Service inside the cluster
is a certificate nothing in that trust store signed, so the call fails and `failurePolicy` (KN-S030) decides
what happens to the object. A bundle that is present but not usable is worse than an absent one, because the
manifest looks configured: the API server cannot build a pool from it, every call to the webhook fails the same
way, and the check the cluster believes it has is not running.

**No new dependency.** `cryptography` is in `requirements.lock` at 50.0.2, but only indirectly (via `pyjwt`, via
`mcp`), and whether to make it a DIRECT dependency is the owner's decision, not this change's. So the whole
reader is the standard library:

* `base64.b64decode(..., validate=True)` says whether the field is base64 at all;
* `ssl.PEM_cert_to_DER_cert` says whether a block is PEM-framed and decodes its DER;
* `ssl.SSLContext.load_verify_locations(cadata=...)` is OpenSSL's own parser -- it raises when the text holds no
  certificate -- and `SSLContext.get_ca_certs()` then returns each certificate's `notBefore` and `notAfter`,
  which `ssl.cert_time_to_seconds` turns into a number.

That last call has one limit worth naming rather than hiding: `load_verify_locations` builds a TRUST STORE, so
`get_ca_certs()` returns only the certificates that can be trust anchors. A `caBundle` holding a leaf
certificate -- a shape that happens, and that the API server also cannot use as an authority -- loads without
error and comes back with nothing. So the reader counts the PEM blocks in the field itself and compares: a block
OpenSSL did not hand back is reported as a certificate whose validity window kube-noob did not read, never as a
bundle with no certificates in it (class 1, class 15).
"""

from __future__ import annotations

import base64
import binascii
import re
import ssl
from collections.abc import Mapping
from dataclasses import dataclass

#: One PEM certificate block. Matched on the whole label, so a PRIVATE KEY or a CERTIFICATE REQUEST block is not
#: counted as a certificate (class 3).
PEM_BLOCK = re.compile(
    r"-----BEGIN CERTIFICATE-----(?:.*?)-----END CERTIFICATE-----",
    re.DOTALL,
)
#: How large a `caBundle` is decoded. The API server's own limit on the field is its object size limit; this one
#: keeps a pathological bundle from being parsed, and a larger one is declined rather than read in part.
MAX_BUNDLE_BYTES = 256 * 1024


@dataclass(frozen=True)
class Window:
    """One certificate's validity window, in seconds since the epoch."""

    not_before: int
    not_after: int
    subject: str


@dataclass(frozen=True)
class Bundle:
    """What one `caBundle` value is, as far as the standard library can say.

    ``problem`` is a fixed phrase and never carries text from the field: a decline reason that quoted the input
    would let a crafted bundle write kube-noob's own sentences (class 7, G281).
    """

    #: "" when the bundle parsed; otherwise the fixed phrase saying what it is instead of a certificate.
    problem: str = ""
    #: How many PEM certificate blocks the decoded text holds.
    blocks: int = 0
    #: The validity windows OpenSSL handed back, one per certificate it accepted as a trust anchor.
    windows: tuple[Window, ...] = ()

    @property
    def unread(self) -> int:
        """Blocks OpenSSL did not return a window for: a leaf certificate, or one it would not store."""
        return max(0, self.blocks - len(self.windows))


def read_bundle(value: object) -> Bundle:
    """What `clientConfig.caBundle` holds, or the fixed phrase saying why it is not a certificate.

    The field is `[]byte` in the API type, so JSON and YAML carry it base64-encoded; a value that is not a
    string is one the API server does not decode. Every failure is its own phrase, because "invalid" covers an
    empty field, a typo in the base64, a private key pasted in by mistake and an expired authority, and those
    are four different things to fix.
    """
    if value is None:
        return Bundle(problem="")
    if not isinstance(value, str):
        return Bundle(problem="is not a string, so the API server does not decode it as a certificate bundle")
    if not value:
        return Bundle(problem="is empty, so it names no certificate authority at all")
    if len(value) > MAX_BUNDLE_BYTES:
        return Bundle(problem="is larger than kube-noob decodes, so its certificates were not read")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return Bundle(problem="is not valid base64, so the API server cannot decode it")
    if not raw:
        return Bundle(problem="decodes to nothing, so it names no certificate authority at all")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        return Bundle(problem="does not decode to PEM text, so it holds no certificate the API server can read")
    blocks = PEM_BLOCK.findall(text)
    if not blocks:
        return Bundle(problem="holds no PEM CERTIFICATE block, so it is not a certificate bundle")
    for block in blocks:
        try:
            ssl.PEM_cert_to_DER_cert(block + "\n")
        except (ValueError, binascii.Error):
            return Bundle(
                problem="holds a PEM CERTIFICATE block whose body is not DER, so the API server cannot parse it",
                blocks=len(blocks),
            )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    try:
        context.load_verify_locations(cadata=text)
    except (ssl.SSLError, ValueError):
        return Bundle(
            problem="holds a PEM CERTIFICATE block whose body is not a DER certificate, so the API server cannot "
            "parse it",
            blocks=len(blocks),
        )
    windows: list[Window] = []
    for cert in context.get_ca_certs():
        before, after = cert.get("notBefore"), cert.get("notAfter")
        if not isinstance(before, str) or not isinstance(after, str):
            continue
        try:
            windows.append(Window(ssl.cert_time_to_seconds(before), ssl.cert_time_to_seconds(after), _subject(cert)))
        except ValueError:
            continue
    return Bundle(blocks=len(blocks), windows=tuple(windows))


def _subject(cert: Mapping[str, object]) -> str:
    """The certificate's common name, for a message -- from the certificate, so never trusted as our own words."""
    subject = cert.get("subject")
    if not isinstance(subject, tuple):
        return ""
    for rdn in subject:
        if not isinstance(rdn, tuple):
            continue
        for pair in rdn:
            if isinstance(pair, tuple) and len(pair) == 2 and pair[0] == "commonName" and isinstance(pair[1], str):
                return pair[1]
    return ""
