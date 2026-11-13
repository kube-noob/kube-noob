"""One reading of an OpenShift (or Kubernetes) version for every surface that takes one.

The known-issue index, the gate, team memory, the local Jira copy, ``operators issues``, the command-line flags
(``--version``, ``--openshift-version``) and every tool model read a version here, so a value is either accepted
everywhere with the same meaning or refused everywhere with the same sentence (G277, R5). The grammar is the one
``operators issues`` set (R5): ``x.y`` or ``x.y.z``, ASCII digits without leading zeros, optionally followed by ``-``
or ``+`` and a build: a pre-release (``4.21.0-rc.1``), a nightly (``4.16.0-0.nightly-2024-05-01-111111``), an OKD
build (``4.20.0-okd-scos.6``) or a release-image architecture (``4.21.3-x86_64``, which IS the release 4.21.3).
Nothing else is a version: not a leading ``v``, not surrounding white space (``"4.21\\n"`` from an unstripped
variable is refused, not read as 4.21, so a value is never silently different from what was typed), not a word.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from kube_noob import sanitize

_NUM = r"(?:0|[1-9][0-9]{0,2})"
_Z = r"(?:0|[1-9][0-9]{0,4})"
_BUILD = r"[0-9A-Za-z._-]{1,64}"  # x86_64 has an underscore
#: For pydantic's ``pattern`` (Rust regex: ``$`` is the end of the text, so a before-validator refuses white space).
VERSION_FIELD_PATTERN = rf"^{_NUM}\.{_NUM}(\.{_Z})?([-+]{_BUILD})?$"
MAX_SHOWN = 80
_TEXT = re.compile(rf"({_NUM})\.({_NUM})(?:\.({_Z}))?(?:[-+]({_BUILD}))?")
#: Release-image tags name the architecture after the version; the release is the same one.
ARCHITECTURES = frozenset({"x86_64", "amd64", "aarch64", "arm64", "ppc64le", "s390x", "multi"})
#: OKD, the community distribution built from the same sources, writes an ``okd`` token in its build
#: (``4.20.0-okd-scos.0`` in okd.io's 4.20 release notes; ``4.20.0-0.okd-scos-<date>`` in its release stream).
_OKD = re.compile(r"(?i)(?:^|[._-])okd(?:[._-]|$)")
EXAMPLES = "4.21, 4.21.9 or 4.21.0-rc.1"


@dataclass(frozen=True)
class ClusterVersion:
    shown: str  # as given, on one line and bounded
    numeric: str  # 4.16.0 (or 4.16): what is compared
    minor: str  # 4.16
    has_z: bool
    build: str  # "" for a release; rc.1, 0.nightly-..., okd-scos.6 otherwise
    okd: bool  # OKD is built from the same sources, but its builds are not OpenShift Container Platform releases
    arch: str  # x86_64 for a release-image tag, else ""


def shown_version(raw: object) -> str | None:
    """``raw`` on one visible line, bounded; ``None`` for nothing (absent, empty or blank)."""
    if raw is None:
        return None
    return sanitize.one_line(str(raw))[:MAX_SHOWN] or None


def read_version(raw: object) -> ClusterVersion | None:
    """The version in ``raw``, or ``None`` when there is none or it is not one (white space around it included)."""
    if raw is None:
        return None
    text = str(raw)
    m = _TEXT.fullmatch(text)
    shown = shown_version(text)
    if m is None or shown is None:
        return None
    major, minor, z, build = m.groups()
    build = build or ""
    arch = build if build.lower() in ARCHITECTURES else ""
    if arch:
        build = ""
    return ClusterVersion(
        shown=shown,
        numeric=f"{major}.{minor}" + (f".{z}" if z is not None else ""),
        minor=f"{major}.{minor}",
        has_z=z is not None,
        build=build,
        okd=bool(build and _OKD.search(build)),
        arch=arch,
    )


def is_version(value: object) -> bool:
    """Whether ``value`` is a string the grammar accepts, exactly as typed."""
    return isinstance(value, str) and read_version(value) is not None


def refusal(flag: str = "--version") -> str:
    """The one sentence a refused version gets on every command and tool (R5's wording)."""
    return f"{flag} must be an OpenShift version such as {EXAMPLES} (ASCII digits, no leading zeros, no whitespace)"


def strict_field(name: str) -> Any:
    """A pydantic before-validator for a version field: the value exactly as the command line takes it. It runs
    before the model strips white space and before the pattern, whose ``$`` would accept a trailing newline, so
    ``"4.21\\n"`` is refused with ``refusal(name)``, never read as 4.21."""

    def check(value: Any) -> Any:
        if value is not None and not is_version(value):
            raise ValueError(refusal(name))
        return value

    return check


def same_release(a: object, b: object) -> bool:
    """Whether two versions name the same release: ``4.21`` does not contradict ``4.21.0``, and ``4.21.3-x86_64`` is
    ``4.21.3``. Text that is not a version is compared as shown."""
    ra, rb = read_version(a), read_version(b)
    if ra is None or rb is None:
        return shown_version(a) == shown_version(b)
    if (ra.minor, ra.build.lower()) != (rb.minor, rb.build.lower()):
        return False
    return not (ra.has_z and rb.has_z) or ra.numeric == rb.numeric
