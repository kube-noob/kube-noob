"""Read what scanners already produce into one normalised finding (requirements R5.1).

Formats, with the fields read (each checked against the producer's source, see .claude/loop/STATE.md):

- Trivy JSON (``trivy image -f json``): ``Results[].Vulnerabilities[]`` (``VulnerabilityID``, ``PkgName``,
  ``PkgIdentifier.PURL``, ``InstalledVersion``, ``FixedVersion``, ``Status``, ``Severity``, ``SeveritySource``,
  ``CVSS``, ``Layer``), ``Results[].Packages[]`` when ``--list-all-pkgs`` was given (``SrcName``), ``Metadata``
  (``OS``, ``ImageID``, ``RepoTags``, ``RepoDigests``).
- Grype JSON (``grype -o json``): ``matches[]`` (``vulnerability.id``, ``severity``, ``fix.versions``, ``fix.state``,
  ``cvss[]``, ``knownExploited[]``; ``relatedVulnerabilities[].id``; ``artifact.name``, ``version``, ``type``,
  ``purl``, ``upstreams[]``), ``distro``, ``source.target``. ``ignoredMatches`` are counted, not read.
- CycloneDX JSON 1.4-1.6: ``components[]`` (nested too) and, when present, ``vulnerabilities[]`` (``id``,
  ``references[].id``, ``ratings[]``, ``affects[].ref`` and ``.versions[]``, ``recommendation``, ``analysis``). Trivy
  writes the fix as ``recommendation`` ("Upgrade <package> to version <fix>"), Grype as an ``unaffected`` range
  ``vers:<type>/>=<fix>``; both are read. Without ``vulnerabilities`` the document is an SBOM.
- SPDX JSON 2.2 and 2.3: ``packages[]`` with their ``purl`` external reference; always an SBOM (SPDX 2 has no
  vulnerability section). SPDX 3 (JSON-LD) is refused with a message.
- RHACS image (``GET /v1/images/{id}`` on Central, ``storage.Image``): ``scan.components[].vulns[]`` (``cve``,
  ``cvss``, ``severity``, ``fixedBy``, ``cisaKev``), ``scan.operatingSystem``, ``id``, ``name.fullName``.

SBOMs carry packages, not findings: ``kube_noob.vuln.vex`` matches their RPMs against Red Hat VEX statements. RPM
versions are written ``[epoch:]version-release`` with a zero epoch dropped, whichever way the producer wrote them
(Trivy and syft put the epoch in the version, both put it in the purl's ``epoch`` qualifier), so the same package
compares equal across formats.
"""

from __future__ import annotations

import dataclasses
import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote

from kube_noob import sanitize
from kube_noob.vuln import rpmver

MAX_BYTES = 64_000_000
MAX_FINDINGS = 200_000
MAX_PACKAGES = 200_000
MAX_DEPTH = 12  # nested CycloneDX components
_CVE = re.compile(r"^CVE-\d{4}-\d{4,7}\Z", re.I)
_VULN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:._-]{2,79}\Z")
_RECOMMEND = re.compile(r"Upgrade (\S+) to version ([^;]+)")
_VERS_FIX = re.compile(r"^vers:[a-z0-9.+-]+/>=([^|]+)\Z")
SEVERITIES = ("critical", "high", "medium", "low", "negligible", "unknown")
SEVERITY_RANK = {s: len(SEVERITIES) - i for i, s in enumerate(SEVERITIES)}
_SEVERITY_WORDS = {
    "critical": "critical",
    "important": "high",
    "high": "high",
    "moderate": "medium",
    "medium": "medium",
    "low": "low",
    "negligible": "negligible",
    "none": "negligible",
    "info": "negligible",
    "unknown": "unknown",
}
ECOSYSTEM_BY_PURL = {
    "rpm": "rpm",
    "deb": "deb",
    "apk": "apk",
    "pypi": "pypi",
    "npm": "npm",
    "maven": "maven",
    "golang": "golang",
    "gem": "gem",
    "nuget": "nuget",
    "cargo": "cargo",
    "composer": "composer",
    "conan": "conan",
    "swift": "swift",
    "hex": "hex",
    "pub": "pub",
    "cocoapods": "cocoapods",
}
_ECOSYSTEM_BY_TRIVY = {
    **dict.fromkeys(
        ("redhat", "centos", "rocky", "alma", "amazon", "oracle", "fedora", "photon", "suse", "opensuse", "azurelinux"),
        "rpm",
    ),
    **dict.fromkeys(("debian", "ubuntu"), "deb"),
    **dict.fromkeys(("alpine", "wolfi", "chainguard"), "apk"),
    **dict.fromkeys(("python-pkg", "pip", "pipenv", "poetry", "uv"), "pypi"),
    **dict.fromkeys(("node-pkg", "npm", "yarn", "pnpm", "bun"), "npm"),
    **dict.fromkeys(("jar", "pom", "gradle", "sbt"), "maven"),
    **dict.fromkeys(("gobinary", "gomod"), "golang"),
    **dict.fromkeys(("gemspec", "bundler"), "gem"),
    **dict.fromkeys(("nuget", "dotnet-core", "packages-props"), "nuget"),
    **dict.fromkeys(("cargo", "rustbinary"), "cargo"),
    "composer": "composer",
}
_ECOSYSTEM_BY_GRYPE = {
    "rpm": "rpm",
    "deb": "deb",
    "apk": "apk",
    "python": "pypi",
    "npm": "npm",
    "java-archive": "maven",
    "go-module": "golang",
    "gem": "gem",
    "dotnet": "nuget",
    "rust-crate": "cargo",
    "php-composer": "composer",
}
_RPM_FAMILIES = frozenset({"rhel", "centos", "fedora", "rocky", "almalinux", "amzn", "ol", "suse", "opensuse"})
_ECOSYSTEM_BY_RHACS = {
    "PYTHON": "pypi",
    "JAVA": "maven",
    "RUBY": "gem",
    "NODEJS": "npm",
    "GO": "golang",
    "DOTNETCORERUNTIME": "nuget",
}


class ReportError(ValueError):
    """Not a scanner report or SBOM this module reads, or one over its bounds."""


@dataclass(frozen=True)
class Purl:
    type: str
    namespace: str
    name: str
    version: str
    qualifiers: dict[str, str]


def parse_purl(text: str) -> Purl | None:
    """A package URL (https://github.com/package-url/purl-spec), or None when ``text`` is not one."""
    if not isinstance(text, str) or not text.startswith("pkg:") or len(text) > 2000:
        return None
    rest = text[4:].lstrip("/")
    rest = rest.partition("#")[0]
    rest, _, query = rest.partition("?")
    qualifiers: dict[str, str] = {}
    for part in query.split("&") if query else []:
        key, eq, value = part.partition("=")
        if eq and key:
            qualifiers[key.lower()] = unquote(value)
    typ, _, path = rest.partition("/")
    if not typ or not path:
        return None
    version = ""
    if "@" in path:
        path, _, version = path.rpartition("@")
    segments = [unquote(s) for s in path.split("/") if s]
    if not segments:
        return None
    return Purl(typ.lower(), "/".join(segments[:-1]), segments[-1], unquote(version), qualifiers)


def srpm_name(srpm: str) -> str:
    """``openssl-3.0.7-24.el9.src.rpm`` -> ``openssl``."""
    base = srpm.strip()
    for suffix in (".src.rpm", ".nosrc.rpm"):
        base = base.removesuffix(suffix)
    parts = base.rsplit("-", 2)
    return parts[0] if len(parts) == 3 else base


_CVSS_BANDS = ((9.0, "critical"), (7.0, "high"), (4.0, "medium"), (0.1, "low"))


def gating_severity(sev: str, cvss: float | None, known_exploited: bool) -> str:
    """The severity a gate compares with ``--fail-on``: the higher of the report's severity and the band of its CVSS
    base score; ``unknown`` with no score counts as medium; a known-exploited finding counts as high at least."""
    ranked = [sev if sev in SEVERITY_RANK and sev != "unknown" else ("medium" if cvss is None else "negligible")]
    if cvss is not None:
        ranked.append(next((name for floor, name in _CVSS_BANDS if cvss >= floor), "negligible"))
    if known_exploited:
        ranked.append("high")
    return max(ranked, key=lambda s: SEVERITY_RANK[s])


def severity(value: Any) -> str:
    word = str(value or "").strip().lower().removesuffix("_vulnerability_severity")
    return _SEVERITY_WORDS.get(word, "unknown")


def _s(value: Any, limit: int = 300) -> str:
    """A bounded one-line string from a report: control characters and line breaks become a space, so a package or
    image name cannot start a new line in a log, SARIF message or job summary."""
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        return ""
    return sanitize.visible_squeezed(str(value)[:limit])


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _dicts(value: Any) -> list[dict[str, Any]]:
    return [x for x in _list(value) if isinstance(x, dict)]


def _score(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    v = float(value)
    return v if 0.0 < v <= 10.0 else None


@dataclass(frozen=True)
class Package:
    name: str
    version: str  # normalised: RPM [epoch:]version-release with a zero epoch dropped
    ecosystem: str
    purl: str = ""
    source: str = ""  # the source package (an RPM's SRPM name) when the producer says
    namespace: str = ""  # the purl namespace (redhat, debian, ...)

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.ecosystem, self.name, self.version)

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"name": self.name, "version": self.version, "ecosystem": self.ecosystem}
        if self.source and self.source != self.name:
            out["sourcePackage"] = self.source
        if self.purl:
            out["purl"] = self.purl
        return out


def make_package(name: Any, version: Any, ecosystem: str = "", purl: Any = "", source: Any = "") -> Package:
    p = parse_purl(purl) if isinstance(purl, str) and purl else None
    eco = ECOSYSTEM_BY_PURL.get(p.type, p.type) if p else (ecosystem or "generic")
    ver = _s(version) or (p.version if p else "")
    src = _s(source)
    if eco == "rpm":
        epoch = p.qualifiers.get("epoch", "") if p else ""
        if epoch.isdigit() and epoch != "0" and ":" not in ver:
            ver = f"{epoch}:{ver}"
        ver = rpmver.normalise(ver)
        if not src and p and p.qualifiers.get("upstream"):
            src = srpm_name(p.qualifiers["upstream"])
    return Package(
        _s(name) or (p.name if p else ""), ver[:300], eco[:40], _s(purl, 2000), src, p.namespace[:100] if p else ""
    )


def _fix_list(values: Any, eco: str) -> tuple[str, ...]:
    out: list[str] = []
    for v in values if isinstance(values, (list, tuple)) else [values]:
        for raw in _s(v, 1000).split(","):
            part = raw.strip()
            if part:
                out.append(rpmver.normalise(part) if eco == "rpm" else part[:200])
    return tuple(sorted(dict.fromkeys(out)))


@dataclass
class Finding:
    vuln_id: str
    cve: str
    package: Package
    fix_versions: tuple[str, ...] = ()
    fix_state: str = "unknown"  # fixed | not-fixed | wont-fix | unknown
    severity: str = "unknown"
    cvss: float | None = None
    known_exploited: bool = False
    sources: list[str] = field(default_factory=list)
    layer: str = ""
    title: str = ""
    notes: list[str] = field(default_factory=list)
    vex: list[dict[str, Any]] = field(default_factory=list)  # the VEX statements that speak to it
    paths: tuple[str, ...] = ()  # where in the image the scanner found the package (lockfile, site-packages, jar)

    @property
    def key(self) -> tuple[str, str, str, str]:
        return (*self.package.key, self.cve)

    @property
    def fix_version(self) -> str:
        return ", ".join(self.fix_versions)

    def normalised(self) -> dict[str, str]:
        """The four fields every format must agree on (R5.1 acceptance)."""
        return {
            "package": self.package.name,
            "version": self.package.version,
            "cve": self.cve,
            "fixVersion": self.fix_version,
        }

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": f"{self.package.ecosystem}/{self.package.name}@{self.package.version}/{self.cve}",
            "cve": self.cve,
            "package": self.package.as_dict(),
            "fixVersion": self.fix_version or None,
            "fixState": self.fix_state,
            "severity": self.severity,
            "cvss": self.cvss,
            "knownExploited": self.known_exploited,
            "sources": sorted(set(self.sources)),
        }
        if self.vuln_id != self.cve:
            out["reportedAs"] = self.vuln_id
        if self.layer:
            out["layer"] = self.layer
        if self.title:
            out["title"] = self.title
        if self.notes:
            out["notes"] = self.notes
        if self.vex:
            out["vex"] = self.vex
        if self.paths:
            out["paths"] = list(self.paths[:10])
        return out


_LOCKFILES = frozenset(
    {
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "requirements.txt",
        "Pipfile.lock",
        "poetry.lock",
        "uv.lock",
        "go.mod",
        "go.sum",
        "Gemfile.lock",
        "Cargo.lock",
        "composer.lock",
        "packages.lock.json",
        "pom.xml",
        "gradle.lockfile",
    }
)


def _image_paths(values: Any) -> tuple[str, ...]:
    """Absolute paths in the image: Trivy writes them without the leading slash, Grype and syft with it."""
    out: list[str] = []
    for v in values:
        s = _s(v, 1000).strip()
        if s and not s.startswith(("http://", "https://")) and ".." not in s.split("/"):
            out.append(s if s.startswith("/") else "/" + s)
    return tuple(dict.fromkeys(out))[:20]


@dataclass
class ImageInfo:
    names: list[str] = field(default_factory=list)  # registry/repo:tag
    digests: list[str] = field(default_factory=list)  # registry/repo@sha256:..., or sha256:...
    image_id: str = ""
    distro: tuple[str, str] | None = None  # ("rhel", "9.4")

    def __post_init__(self) -> None:
        self.names = [n for n in (_s(x, 500).strip() for x in self.names) if n]
        self.digests = [d for d in (_s(x, 500).strip() for x in self.digests) if d]
        self.image_id = _s(self.image_id, 200).strip()

    @property
    def label(self) -> str:
        return (self.names or self.digests or [self.image_id or "unnamed image"])[0]

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"name": self.label}
        if self.digests:
            out["digests"] = self.digests[:10]
        if self.image_id:
            out["imageId"] = self.image_id
        if self.distro:
            out["distro"] = f"{self.distro[0]} {self.distro[1]}".strip()
        return out


@dataclass
class ScanReport:
    format: str  # trivy | grype | cyclonedx | spdx | rhacs
    image: ImageInfo
    findings: list[Finding]
    packages: list[Package]
    sbom: bool  # True when the document lists packages but no vulnerabilities
    own_vex: list[dict[str, Any]] = field(default_factory=list)  # the document's own VEX (CycloneDX analysis)
    notes: list[str] = field(default_factory=list)


def distro_id(value: Any) -> str:
    v = _s(value, 40).strip().lower()
    return {"redhat": "rhel", "red hat": "rhel", "ubi": "rhel", "rhel": "rhel"}.get(v, v)


def _distro_from_purls(packages: list[Package]) -> tuple[str, str] | None:
    for pkg in packages:
        p = parse_purl(pkg.purl)
        d = p.qualifiers.get("distro", "") if p else ""
        name, _, version = d.partition("-")
        if name and version:
            return distro_id(name), version[:20]
    return None


def _cve(vuln_id: str, aliases: list[str]) -> str:
    vuln_id = vuln_id.strip()
    if _CVE.match(vuln_id):
        return vuln_id.upper()
    for a in aliases:
        if _CVE.match(a.strip()):
            return a.strip().upper()
    return vuln_id


class _Findings(list[Finding]):
    """Findings of one report, with the entries that could not be read counted (never dropped silently)."""

    rejected: list[str]

    def __init__(self) -> None:
        super().__init__()
        self.rejected = []


def _add(out: list[Finding], f: Finding, where: str) -> None:
    if len(out) >= MAX_FINDINGS:
        raise ReportError(f"{where}: more than {MAX_FINDINGS} findings")
    f.vuln_id = f.vuln_id.strip()
    f.cve = f.cve.strip()
    if not _VULN_ID.match(f.vuln_id) or not f.package.name:
        if isinstance(out, _Findings):
            out.rejected.append(f"{f.vuln_id[:40]!r} in {f.package.name[:40] or '?'!r}")
        return
    out.append(f)


# -- Trivy -----------------------------------------------------------------------------------------------------------


def _trivy_version(pkg: dict[str, Any]) -> str:
    version, release, epoch = _s(pkg.get("Version")), _s(pkg.get("Release")), pkg.get("Epoch")
    v = f"{version}-{release}" if release else version
    return f"{epoch}:{v}" if isinstance(epoch, int) and not isinstance(epoch, bool) and epoch else v


def _trivy(doc: dict[str, Any], where: str) -> ScanReport:
    meta = _dict(doc.get("Metadata"))
    os_ = _dict(meta.get("OS"))
    image = ImageInfo(
        names=[n for n in [_s(doc.get("ArtifactName"), 500), *(_s(t, 500) for t in _list(meta.get("RepoTags")))] if n],
        digests=[_s(d, 500) for d in _list(meta.get("RepoDigests")) if _s(d)],
        image_id=_s(meta.get("ImageID"), 100),
        distro=(distro_id(os_.get("Family")), _s(os_.get("Name"), 20)) if os_.get("Family") else None,
    )
    findings = _Findings()
    packages: list[Package] = []
    for res in _dicts(doc.get("Results")):
        rtype = _s(res.get("Type"), 40).lower()
        eco = _ECOSYSTEM_BY_TRIVY.get(rtype, "generic")
        target = _s(res.get("Target"), 1000) if _s(res.get("Class"), 40) == "lang-pkgs" else ""
        # a lockfile's path ("usr/src/app/package-lock.json"); "Python", "Node.js" and "Java" name installed packages,
        # whose own path is the vulnerability's PkgPath
        lockfile = target if "/" in target or target in _LOCKFILES else ""
        sources: dict[tuple[str, str], str] = {}
        for raw in _dicts(res.get("Packages")):
            ident = _dict(raw.get("Identifier"))
            pkg = make_package(raw.get("Name"), _trivy_version(raw), eco, ident.get("PURL", ""), raw.get("SrcName"))
            if pkg.name and len(packages) < MAX_PACKAGES:
                packages.append(pkg)
                if pkg.source:
                    sources[(pkg.name, pkg.version)] = pkg.source
        for raw in _list(res.get("Vulnerabilities")):
            v = _dict(raw)
            ident = _dict(v.get("PkgIdentifier"))
            pkg = make_package(v.get("PkgName"), v.get("InstalledVersion"), eco, ident.get("PURL", ""))
            if not pkg.source and (pkg.name, pkg.version) in sources:
                pkg = Package(
                    pkg.name, pkg.version, pkg.ecosystem, pkg.purl, sources[(pkg.name, pkg.version)], pkg.namespace
                )
            fixes = _fix_list(v.get("FixedVersion"), pkg.ecosystem)
            status = _s(v.get("Status"), 40).lower()
            state = {
                "fixed": "fixed",
                "will_not_fix": "wont-fix",
                "end_of_life": "wont-fix",
                "affected": "not-fixed",
                "fix_deferred": "not-fixed",
                "under_investigation": "not-fixed",
            }.get(status, "unknown")
            if fixes:
                state = "fixed"
            cvss_map = _dict(v.get("CVSS"))
            preferred = [_s(v.get("SeveritySource"), 40), "redhat", "nvd", *sorted(cvss_map)]
            score = next((s for k in preferred if (s := _score(_dict(cvss_map.get(k)).get("V3Score")))), None)
            vid = _s(v.get("VulnerabilityID"), 80)
            layer = _dict(v.get("Layer"))
            _add(
                findings,
                Finding(
                    vid,
                    _cve(vid, [_s(x, 80) for x in _list(v.get("VendorIDs"))]),
                    pkg,
                    fixes,
                    state,
                    severity(v.get("Severity")),
                    score,
                    sources=["trivy"],
                    layer=_s(layer.get("Digest") or layer.get("DiffID"), 100),
                    title=_s(v.get("Title"), 200),
                    paths=_image_paths([v.get("PkgPath") or lockfile] if (v.get("PkgPath") or lockfile) else []),
                ),
                where,
            )
    if not isinstance(doc.get("Results"), list) and doc.get("Results") is not None:
        raise ReportError(f"{where}: Trivy Results is not a list")
    return ScanReport("trivy", image, findings, packages, sbom=False)


# -- Grype -----------------------------------------------------------------------------------------------------------


def _grype_score(entries: Any) -> float | None:
    best: float | None = None
    for c in _dicts(entries):
        if _s(c.get("version"), 10).startswith(("3", "4")):
            s = _score(_dict(c.get("metrics")).get("baseScore"))
            if s is not None and (best is None or s > best):
                best = s
    return best


def _grype(doc: dict[str, Any], where: str) -> ScanReport:
    target = _dict(_dict(doc.get("source")).get("target"))
    distro = _dict(doc.get("distro"))
    image = ImageInfo(
        names=[n for n in [_s(target.get("userInput"), 500), *(_s(t, 500) for t in _list(target.get("tags")))] if n],
        digests=[_s(d, 500) for d in _list(target.get("repoDigests")) if _s(d)],
        image_id=_s(target.get("imageID"), 100),
        distro=(distro_id(distro.get("name")), _s(distro.get("version"), 20)) if distro.get("name") else None,
    )
    findings = _Findings()
    for m in _dicts(doc.get("matches")):
        v, a = _dict(m.get("vulnerability")), _dict(m.get("artifact"))
        upstreams = [_dict(u) for u in _list(a.get("upstreams"))]
        pkg = make_package(
            a.get("name"),
            a.get("version"),
            _ECOSYSTEM_BY_GRYPE.get(_s(a.get("type"), 40), "generic"),
            a.get("purl", ""),
            upstreams[0].get("name", "") if upstreams else "",
        )
        related = [_dict(r) for r in _list(m.get("relatedVulnerabilities"))]
        fix = _dict(v.get("fix"))
        fixes = _fix_list(fix.get("versions") or [], pkg.ecosystem)
        state = {"fixed": "fixed", "not-fixed": "not-fixed", "wont-fix": "wont-fix"}.get(
            _s(fix.get("state"), 20), "unknown"
        )
        score = _grype_score(v.get("cvss"))
        for r in related:
            rs = _grype_score(r.get("cvss"))
            if score is None and rs is not None:
                score = rs
        vid = _s(v.get("id"), 80)
        _add(
            findings,
            Finding(
                vid,
                _cve(vid, [_s(r.get("id"), 80) for r in related]),
                pkg,
                fixes,
                "fixed" if fixes else state,
                severity(v.get("severity")),
                score,
                known_exploited=bool(_list(v.get("knownExploited"))),
                sources=["grype"],
                paths=_image_paths(_dict(loc).get("path") for loc in _list(a.get("locations"))),
            ),
            where,
        )
    notes = []
    ignored = len(_list(doc.get("ignoredMatches")))
    if ignored:
        notes.append(f"{ignored} matches Grype itself ignored (its ignore rules or VEX) are not read")
    return ScanReport("grype", image, findings, [f.package for f in findings], sbom=False, notes=notes)


# -- CycloneDX -------------------------------------------------------------------------------------------------------


_CDX_PATH = re.compile(r"^(?:aquasecurity:trivy:FilePath|syft:location:\d{1,3}:path)\Z")


def _cdx_components(
    doc: dict[str, Any], where: str, paths_by_ref: dict[str, tuple[str, ...]] | None = None
) -> tuple[dict[str, Package], list[Package], tuple[str, str] | None]:
    by_ref: dict[str, Package] = {}
    packages: list[Package] = []
    distro: tuple[str, str] | None = None
    stack: list[tuple[Any, int]] = [(c, 0) for c in _list(doc.get("components"))]
    while stack:
        raw, depth = stack.pop()
        c = _dict(raw)
        if depth < MAX_DEPTH:
            stack.extend((x, depth + 1) for x in _list(c.get("components")))
        ctype = _s(c.get("type"), 40)
        if ctype == "operating-system":
            distro = (distro_id(c.get("name")), _s(c.get("version"), 20))
            continue
        if ctype not in {"library", "application", "framework", ""} or not c.get("name"):
            continue
        props = {_s(_dict(p).get("name"), 100): _s(_dict(p).get("value"), 300) for p in _list(c.get("properties"))}
        src = props.get("aquasecurity:trivy:SrcName", "")
        if not src and props.get("syft:metadata:sourceRpm"):
            src = srpm_name(props["syft:metadata:sourceRpm"])
        pkg = make_package(c.get("name"), c.get("version"), "", c.get("purl", ""), src)
        if len(packages) >= MAX_PACKAGES:
            raise ReportError(f"{where}: more than {MAX_PACKAGES} components")
        packages.append(pkg)
        ref = _s(c.get("bom-ref"), 2000)
        if ref:
            by_ref[ref] = pkg
            if paths_by_ref is not None:
                found = _image_paths(v for k, v in props.items() if _CDX_PATH.match(k))
                if found:
                    paths_by_ref[ref] = found
    return by_ref, packages, distro


def _cdx_image(doc: dict[str, Any]) -> ImageInfo:
    comp = _dict(_dict(doc.get("metadata")).get("component"))
    props = {_s(_dict(p).get("name"), 100): _s(_dict(p).get("value"), 500) for p in _list(comp.get("properties"))}
    names = [n for n in [_s(comp.get("name"), 500), props.get("aquasecurity:trivy:RepoTag", "")] if n]
    digests = [d for d in [props.get("aquasecurity:trivy:RepoDigest", "")] if d]
    version = _s(comp.get("version"), 200)
    if version.startswith("sha256:"):
        digests.append(version)
    return ImageInfo(names, digests, props.get("aquasecurity:trivy:ImageID", ""))


def _cdx(doc: dict[str, Any], where: str) -> ScanReport:
    paths_by_ref: dict[str, tuple[str, ...]] = {}
    by_ref, packages, distro = _cdx_components(doc, where, paths_by_ref)
    image = _cdx_image(doc)
    image.distro = distro or _distro_from_purls(packages)
    if "vulnerabilities" not in doc:
        return ScanReport("cyclonedx", image, [], packages, sbom=True)
    findings = _Findings()
    excluded: list[dict[str, Any]] = []
    for raw in _list(doc.get("vulnerabilities")):
        v = _dict(raw)
        vid = _s(v.get("id"), 80)
        aliases = [_s(_dict(r).get("id"), 80) for r in _list(v.get("references"))]
        ratings = [_dict(r) for r in _list(v.get("ratings"))]
        sev = max((severity(r.get("severity")) for r in ratings), key=lambda s: SEVERITY_RANK[s], default="unknown")
        score = max((s for r in ratings if (s := _score(r.get("score"))) is not None), default=None)
        analysis = _dict(v.get("analysis"))
        state = _s(analysis.get("state"), 40)
        recs = _RECOMMEND.findall(_s(v.get("recommendation"), 4000))
        for aff in _dicts(v.get("affects")):
            ref = _s(aff.get("ref"), 2000)
            pkg = by_ref.get(ref)
            if pkg is None:
                stripped = re.sub(r"[?&]package-id=[^&]*", "", ref)
                pkg = make_package("", "", "", stripped) if parse_purl(stripped) else None
            if pkg is None or not pkg.name:
                continue
            fixes: list[str] = []
            installed = pkg.version
            for ver in _dicts(aff.get("versions")):
                status = _s(ver.get("status"), 20)
                if status == "unaffected":
                    m = _VERS_FIX.match(_s(ver.get("range"), 300))
                    if m:
                        fixes.append(m.group(1))
                elif status == "affected" and ver.get("version") and not installed:
                    installed = _s(ver.get("version"))
            for name, versions in recs:
                if name == pkg.name:
                    fixes.extend(versions.split(","))
            if installed != pkg.version:
                pkg = make_package(pkg.name, installed, pkg.ecosystem, pkg.purl, pkg.source)
            fix_versions = _fix_list(fixes, pkg.ecosystem)
            finding = Finding(
                vid,
                _cve(vid, aliases),
                pkg,
                fix_versions,
                "fixed" if fix_versions else "unknown",
                sev,
                score,
                sources=["cyclonedx"],
                paths=paths_by_ref.get(ref, ()),
            )
            if state in {"not_affected", "resolved", "resolved_with_pedigree", "false_positive"}:
                # the report's own VEX: kept as a finding unless the caller trusts it (assess(trust_report_vex=...))
                finding.notes.append(f"the report's own analysis says {state}")
                _add(findings, finding, where)
                excluded.append(
                    {
                        "key": list(finding.key),
                        "finding": finding.as_dict(),
                        "reason": f"the CycloneDX document's own analysis says {state}",
                        "statements": [
                            {
                                "source": "CycloneDX analysis in the input",
                                "status": state,
                                **(
                                    {"justification": _s(analysis.get("justification"), 80)}
                                    if analysis.get("justification")
                                    else {}
                                ),
                                **({"detail": _s(analysis.get("detail"), 300)} if analysis.get("detail") else {}),
                            }
                        ],
                    }
                )
                continue
            _add(findings, finding, where)
    return ScanReport("cyclonedx", image, findings, packages, sbom=False, own_vex=excluded)


# -- SPDX ------------------------------------------------------------------------------------------------------------


def _spdx(doc: dict[str, Any], where: str) -> ScanReport:
    packages: list[Package] = []
    image = ImageInfo(names=[n for n in [_s(doc.get("name"), 500)] if n])
    distro: tuple[str, str] | None = None
    for raw in _list(doc.get("packages")):
        p = _dict(raw)
        purpose = _s(p.get("primaryPackagePurpose"), 40)
        purl = ""
        for ref in _dicts(p.get("externalRefs")):
            if _s(ref.get("referenceType"), 40) == "purl":
                purl = _s(ref.get("referenceLocator"), 2000)
                break
        if purpose == "OPERATING-SYSTEM":
            distro = (distro_id(p.get("name")), _s(p.get("versionInfo"), 20))
            continue
        if purpose == "CONTAINER":
            pu = parse_purl(purl)
            if pu and pu.version.startswith("sha256:"):
                repo = pu.qualifiers.get("repository_url", "")
                image.digests.append(f"{repo}@{pu.version}" if repo else pu.version)
            continue
        if not p.get("name"):
            continue
        if len(packages) >= MAX_PACKAGES:
            raise ReportError(f"{where}: more than {MAX_PACKAGES} packages")
        packages.append(make_package(p.get("name"), p.get("versionInfo"), "", purl))
    image.distro = distro or _distro_from_purls(packages)
    return ScanReport("spdx", image, [], packages, sbom=True)


# -- RHACS -----------------------------------------------------------------------------------------------------------


def _rhacs(doc: dict[str, Any], where: str) -> ScanReport:
    scan = _dict(doc.get("scan"))
    os_text = _s(scan.get("operatingSystem"), 40)
    family, _, version = os_text.partition(":")
    family = distro_id(family)
    os_eco = "rpm" if family in _RPM_FAMILIES else {"debian": "deb", "ubuntu": "deb", "alpine": "apk"}.get(family, "")
    names = [_s(_dict(doc.get("name")).get("fullName"), 500)]
    names += [_s(_dict(n).get("fullName"), 500) for n in _list(doc.get("names"))]
    image = ImageInfo(
        names=list(dict.fromkeys(n for n in names if n)),
        digests=[d for d in [_s(doc.get("id"), 100)] if d.startswith("sha256:")],
        distro=(family, version[:20]) if family else None,
    )
    findings = _Findings()
    packages: list[Package] = []
    for raw in _list(scan.get("components")):
        c = _dict(raw)
        source = _s(c.get("source"), 40) or "OS"
        eco = os_eco if source == "OS" else _ECOSYSTEM_BY_RHACS.get(source, "generic")
        pkg = make_package(c.get("name"), c.get("version"), eco or "generic")
        packages.append(pkg)
        for rv in _dicts(c.get("vulns")):
            cve = _s(rv.get("cve"), 80)
            fixes = _fix_list(rv.get("fixedBy") or [], pkg.ecosystem)
            _add(
                findings,
                Finding(
                    cve,
                    _cve(cve, []),
                    pkg,
                    fixes,
                    "fixed" if fixes else "not-fixed",
                    severity(rv.get("severity")),
                    _score(rv.get("cvss")),
                    known_exploited=rv.get("cisaKev") is True,
                    sources=["rhacs"],
                    title=_s(rv.get("summary"), 200),
                ),
                where,
            )
    return ScanReport("rhacs", image, findings, packages, sbom=False)


# -- detection -------------------------------------------------------------------------------------------------------


def detect(doc: dict[str, Any]) -> str:
    if doc.get("bomFormat") == "CycloneDX":
        return "cyclonedx"
    spdx = doc.get("spdxVersion")
    if isinstance(spdx, str) and spdx.startswith("SPDX-2."):
        return "spdx"
    if "SchemaVersion" in doc and ("Results" in doc or "ArtifactName" in doc):
        return "trivy"
    if isinstance(doc.get("matches"), list) and ("descriptor" in doc or "source" in doc or "distro" in doc):
        return "grype"
    if isinstance(doc.get("scan"), dict) and isinstance(doc["scan"].get("components"), list):
        return "rhacs"
    if "@context" in doc and "spdx" in json.dumps(doc.get("@context"))[:2000].lower():
        raise ReportError(
            "SPDX 3 (JSON-LD) is not read yet: export SPDX 2.3 JSON (syft -o spdx-json, trivy -f spdx-json)"
        )
    if isinstance(doc.get("document"), dict) and str(doc["document"].get("category", "")).startswith("csaf"):
        raise ReportError("this is a CSAF document: pass VEX with --vex, not as a scanner report")
    if isinstance(doc.get("vulnerabilities"), list) and "catalogVersion" in doc:
        raise ReportError("this is the CISA KEV catalog: pass it with --kev, not as a scanner report")
    raise ReportError(
        "not a Trivy or Grype JSON report, a CycloneDX or SPDX 2 JSON SBOM, or an RHACS image (GET /v1/images/{id})"
    )


def parse(data: str | bytes, where: str = "report", max_depth: int = sanitize.MAX_JSON_DEPTH) -> ScanReport:
    raw = data.encode("utf-8") if isinstance(data, str) else data
    if len(raw) > MAX_BYTES:
        raise ReportError(f"{where}: larger than {MAX_BYTES} bytes")
    try:
        doc = sanitize.loads_bounded(raw, max_depth)
    except (sanitize.JsonTooDeep, RecursionError) as exc:
        raise ReportError(f"{where}: JSON nested too deeply") from exc
    except ValueError as exc:
        raise ReportError(f"{where}: not JSON ({str(exc)[:120]})") from exc
    if not isinstance(doc, dict):
        raise ReportError(f"{where}: not a JSON object")
    fmt = detect(doc)
    report = {"trivy": _trivy, "grype": _grype, "cyclonedx": _cdx, "spdx": _spdx, "rhacs": _rhacs}[fmt](doc, where)
    rejected = getattr(report.findings, "rejected", [])
    if rejected:
        report.notes.append(
            f"{len(rejected)} findings were not read: no usable vulnerability id or package name (first: "
            f"{', '.join(rejected[:3])})"
        )
    report.findings = list(report.findings)
    return report


def merge(findings: list[Finding]) -> list[Finding]:
    """One finding per (ecosystem, package, version, CVE): sources joined, the highest severity and CVSS kept, fix
    versions joined, known exploitation if any report says so."""
    out: dict[tuple[str, str, str, str], Finding] = {}
    for f in findings:
        cur = out.get(f.key)
        if cur is None:
            out[f.key] = dataclasses.replace(f, sources=list(f.sources), notes=list(f.notes), vex=list(f.vex))
            continue
        cur.sources.extend(s for s in f.sources if s not in cur.sources)
        if SEVERITY_RANK[f.severity] > SEVERITY_RANK[cur.severity]:
            cur.severity = f.severity
        if f.cvss is not None and (cur.cvss is None or f.cvss > cur.cvss):
            cur.cvss = f.cvss
        if f.fix_versions and f.fix_versions != cur.fix_versions:
            if cur.fix_versions:
                cur.notes.append(
                    f"{'/'.join(f.sources)} gives fix {f.fix_version}, {'/'.join(cur.sources[:1])} {cur.fix_version}"
                )
            cur.fix_versions = tuple(sorted(set(cur.fix_versions) | set(f.fix_versions)))
            cur.fix_state = "fixed"
        cur.known_exploited = cur.known_exploited or f.known_exploited
        if f.paths:
            cur.paths = tuple(dict.fromkeys((*cur.paths, *f.paths)))[:20]
        if not cur.package.source and f.package.source:
            cur.package = f.package
    return sorted(out.values(), key=lambda f: (f.package.ecosystem, f.package.name, f.package.version, f.cve))
