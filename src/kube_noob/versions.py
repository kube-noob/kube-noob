"""One reading of an OpenShift (or Kubernetes) version for every surface that takes one.

The known-issue index, the gate, team memory, the local Jira copy, the command-line flags and every tool model read a
version here, so a value is either accepted everywhere with the same meaning or refused everywhere (G277). Accepted:
``x.y`` or ``x.y.z``, ASCII digits without leading zeros, optionally after a ``v`` (``v4.20``, as GitHub Action users
write it) and optionally followed by ``-`` or ``+`` and a build: a pre-release (``4.21.0-rc.1``), a nightly
(``4.16.0-0.nightly-2024-05-01-111111``), an OKD build (``4.20.0-okd-scos.6``) or a release-image architecture
(``4.21.3-x86_64``, which IS the release 4.21.3). Surrounding whitespace is ignored; anything else is not a version.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from kube_noob import sanitize

_NUM = r"(?:0|[1-9][0-9]{0,2})"
_Z = r"(?:0|[1-9][0-9]{0,4})"
_BUILD = r"[0-9A-Za-z][0-9A-Za-z._-]{0,63}"  # x86_64 has an underscore
#: For pydantic's ``pattern`` (Rust regex: ``$`` is the end of the text). The value is stripped first (``VersionT``).
VERSION_FIELD_PATTERN = rf"^v?{_NUM}\.{_NUM}(\.{_Z})?([-+]{_BUILD})?$"
MAX_SHOWN = 80
_TEXT = re.compile(rf"v?({_NUM})\.({_NUM})(?:\.({_Z}))?(?:[-+]({_BUILD}))?")
#: Release-image tags name the architecture after the version; the release is the same one.
ARCHITECTURES = frozenset({"x86_64", "amd64", "aarch64", "arm64", "ppc64le", "s390x", "multi"})
_OKD = re.compile(r"(?i)(?:^|[._-])okd(?:[._-]|$)")


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
    """The version in ``raw``, or ``None`` when there is none or it is not one."""
    shown = shown_version(raw)
    m = _TEXT.fullmatch(shown) if shown else None
    if shown is None or m is None:
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


def strip_version(value: object) -> object:
    """For pydantic: a string is compared without the whitespace around it, as the command line compares it."""
    return value.strip() if isinstance(value, str) else value


def refusal(raw: object, flag: str = "--version") -> str:
    """The one sentence a refused version gets on every command."""
    shown = shown_version(raw) or ""
    return (
        f"{flag} {shown[:40]!r} is not a version: give x.y or x.y.z (4.21, 4.21.3), optionally with a leading v or a "
        "build after a hyphen (4.21.0-rc.1, 4.20.0-okd-scos.6)"
    )


def same_release(a: object, b: object) -> bool:
    """Whether two versions name the same release: ``4.21`` does not contradict ``4.21.0``, ``v4.21.0`` is
    ``4.21.0``. Text that is not a version is compared as shown."""
    ra, rb = read_version(a), read_version(b)
    if ra is None or rb is None:
        return shown_version(a) == shown_version(b)
    if (ra.minor, ra.build.lower()) != (rb.minor, rb.build.lower()):
        return False
    return not (ra.has_z and rb.has_z) or ra.numeric == rb.numeric
