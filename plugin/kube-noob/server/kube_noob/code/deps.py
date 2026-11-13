"""Where a vulnerable language package is declared in the repository (requirements R4.7, SCA via SBOM).

A scanner run on the image or its SBOM (Trivy, Grype, CycloneDX from Trivy or syft) says which package version is
vulnerable and where in the image it found it (``Finding.paths``: a lockfile such as ``/app/package-lock.json``, or
an installed package such as ``.../site-packages/requests-2.0.0.dist-info/METADATA``). This module turns that into
the line to change in the repository:

1. a lockfile or manifest the image got by ``COPY`` maps back to its repository file (``ship.source_of``);
2. otherwise, and for the direct declaration next to a lockfile, the repository's dependency files for the package's
   ecosystem are searched for the package name (``requirements*.txt``, ``pyproject.toml``, ``Pipfile[.lock]``,
   ``poetry.lock``, ``uv.lock``, ``package.json``, ``package-lock.json``, ``yarn.lock``, ``pnpm-lock.yaml``,
   ``pom.xml``, ``build.gradle[.kts]``, ``go.mod``, ``go.sum``, ``Gemfile[.lock]``, ``Cargo.toml``, ``Cargo.lock``,
   ``*.csproj``, ``packages.lock.json``, ``composer.json``, ``composer.lock``).

Nothing is resolved or installed: the files are read as text, bounded.
"""

from __future__ import annotations

import fnmatch
import posixpath
import re
from dataclasses import dataclass
from typing import Any

MAX_FILES = 500
MAX_FILE_BYTES = 5_000_000
MAX_HITS = 5
MAX_LINE = 4_096  # longer lines are not matched (no declaration is that long; patterns stay linear)
NPM_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")

MANIFESTS: dict[str, tuple[tuple[str, str], ...]] = {  # (filename pattern, kind)
    "pypi": (
        ("requirements*.txt", "manifest"),
        ("requirements*.in", "manifest"),
        ("pyproject.toml", "manifest"),
        ("Pipfile", "manifest"),
        ("setup.cfg", "manifest"),
        ("Pipfile.lock", "lockfile"),
        ("poetry.lock", "lockfile"),
        ("uv.lock", "lockfile"),
    ),
    "npm": (
        ("package.json", "manifest"),
        ("package-lock.json", "lockfile"),
        ("npm-shrinkwrap.json", "lockfile"),
        ("yarn.lock", "lockfile"),
        ("pnpm-lock.yaml", "lockfile"),
    ),
    "maven": (("pom.xml", "manifest"), ("build.gradle", "manifest"), ("build.gradle.kts", "manifest")),
    "golang": (("go.mod", "manifest"), ("go.sum", "lockfile")),
    "gem": (("Gemfile", "manifest"), ("*.gemspec", "manifest"), ("Gemfile.lock", "lockfile")),
    "cargo": (("Cargo.toml", "manifest"), ("Cargo.lock", "lockfile")),
    "nuget": (("*.csproj", "manifest"), ("Directory.Packages.props", "manifest"), ("packages.lock.json", "lockfile")),
    "composer": (("composer.json", "manifest"), ("composer.lock", "lockfile")),
}
DEPENDENCY_FILES = tuple(sorted({pat for pats in MANIFESTS.values() for pat, _ in pats}))
SKIP_DIRS = frozenset({".git", "node_modules", "vendor", ".venv", "venv", "__pycache__", "target", "dist", "build"})


def is_dependency_file(path: str) -> bool:
    name = posixpath.basename(path)
    return any(fnmatch.fnmatchcase(name, pat) for pat in DEPENDENCY_FILES)


def _pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _patterns(ecosystem: str, name: str, filename: str) -> list[re.Pattern[str]]:
    n = re.escape(name)
    if ecosystem == "pypi":
        loose = "[-_.]+".join(re.escape(part) for part in re.split(r"[-_.]+", name))
        # One \s* before an optional "[extras]" that carries its own trailing \s*: two \s* around an optional
        # group backtrack quadratically on a long run of spaces.
        if fnmatch.fnmatchcase(filename, "requirements*") or filename in {"Pipfile", "setup.cfg"}:
            return [re.compile(rf"(?i)^\s*{loose}\s*(?:\[[^\]]*\]\s*)?(?:[=<>!~;@#]|$)")]
        if filename == "pyproject.toml":
            return [
                re.compile(rf"(?i)[\"']{loose}\s*(?:\[[^\]]*\]\s*)?(?:[=<>!~;@\"']|$)"),
                re.compile(rf"(?i)^\s*{loose}\s*="),
            ]
        return [re.compile(rf'(?i)^\s*name\s*=\s*"{loose}"'), re.compile(rf'(?i)^\s*"{loose}"\s*:')]
    if ecosystem == "npm":
        if filename == "yarn.lock":
            return [re.compile(rf'^"?{n}@')]
        if filename == "pnpm-lock.yaml":
            return [re.compile(rf"^\s*/?{n}[@/:]"), re.compile(rf"^\s*'?{n}'?:")]
        if filename in {"package-lock.json", "npm-shrinkwrap.json"}:
            # v2/v3: the top-level "node_modules/<name>" entry; v1: a package entry (an object), never a string in
            # another package's "requires" or "dependencies" map
            return [re.compile(rf'^\s*"node_modules/{n}"\s*:'), re.compile(rf'^\s*"{n}"\s*:\s*\{{')]
        return [re.compile(rf'^\s*"{n}"\s*:')]
    if ecosystem == "maven":
        group, _, artifact = name.rpartition(":")
        a = re.escape(artifact or name)
        if filename.startswith("build.gradle"):
            g = re.escape(group) + ":" if group else r"[\w.\-]+:"
            return [re.compile(rf"[\"']{g}{a}(?::|[\"'])")]
        return [re.compile(rf"<artifactId>\s*{a}\s*</artifactId>")]
    if ecosystem == "golang":
        return [re.compile(rf"^\s*(?:require\s+)?{n}\s+v\d")]
    if ecosystem == "gem":
        if filename == "Gemfile.lock":
            return [re.compile(rf"^\s{{4}}{n} \(")]
        return [
            re.compile(
                rf"""^\s*(?:gem|s\.add_(?:runtime_)?dependency|spec\.add_(?:runtime_)?dependency)\s*\(?\s*["']{n}["']"""
            )
        ]
    if ecosystem == "cargo":
        if filename == "Cargo.lock":
            return [re.compile(rf'^name\s*=\s*"{n}"')]
        return [re.compile(rf"^\s*{n}\s*=")]
    if ecosystem == "nuget":
        if filename == "packages.lock.json":
            return [re.compile(rf'(?i)^\s*"{n}"\s*:')]
        return [re.compile(rf'(?i)<Package(?:Reference|Version)\s+Include\s*=\s*"{n}"')]
    if ecosystem == "composer":
        if filename == "composer.lock":
            return [re.compile(rf'^\s*"name"\s*:\s*"{n}"')]
        return [re.compile(rf'^\s*"{n}"\s*:')]
    return []


def _kind(ecosystem: str, filename: str) -> str:
    for pat, kind in MANIFESTS.get(ecosystem, ()):
        if fnmatch.fnmatchcase(filename, pat):
            return kind
    return ""


@dataclass(frozen=True)
class Declared:
    file: str
    line: int
    text: str
    kind: str  # manifest (where a person declares it) | lockfile (where the resolved version is pinned)
    how: str  # copied into the image from here | found by name

    def as_dict(self) -> dict[str, Any]:
        return {"file": self.file, "line": self.line, "text": self.text, "kind": self.kind, "how": self.how}


def find(
    files: dict[str, str],
    ecosystem: str,
    name: str,
    copied_from: list[str] | None = None,
) -> list[Declared]:
    """The lines that declare ``name`` in the repository's dependency files for ``ecosystem``. Files the image's
    lockfile was copied from come first, then the files in the same directories, then the rest."""
    if ecosystem not in MANIFESTS or not name:
        return []
    copied = list(dict.fromkeys(copied_from or []))
    dirs = {posixpath.dirname(c) for c in copied}

    def order(path: str) -> tuple[int, str]:
        rank = 0 if path in copied else 1 if posixpath.dirname(path) in dirs else 2
        kind = _kind(ecosystem, posixpath.basename(path))
        return (rank * 2 + (0 if kind == "manifest" else 1), path)

    hits: list[Declared] = []
    for path in sorted(files, key=order):
        filename = posixpath.basename(path)
        kind = _kind(ecosystem, filename)
        if not kind:
            continue
        lines = files[path].splitlines()[:200_000]
        number = _line_for(ecosystem, name, filename, lines)
        if number:
            hits.append(
                Declared(
                    path,
                    number,
                    lines[number - 1].strip()[:200],
                    kind,
                    "copied into the image from here" if path in copied else "found by name",
                )
            )
        if len(hits) >= MAX_HITS:
            break
    return hits


def _line_for(ecosystem: str, name: str, filename: str, lines: list[str]) -> int | None:
    """The 1-based line that declares ``name`` in one dependency file, or None."""
    if ecosystem == "maven" and filename == "pom.xml":
        return _pom_line(name, lines)
    if ecosystem == "npm" and filename == "package.json":
        return _package_json_line(name, lines)
    patterns = _patterns(ecosystem, name, filename)
    for rx in patterns:  # in order of preference: the first pattern that matches anywhere wins
        for number, line in enumerate(lines, start=1):
            if len(line) <= MAX_LINE and rx.search(line):  # no declaration is that long; cutting one would fake "$"
                return number
    return None


_POM_TOKEN = re.compile(r"<(/?)(dependency|exclusions)\b[^>]{0,200}>|<(groupId|artifactId)>\s*([^<\s]{1,300})\s*</\3>")


def _pom_line(name: str, lines: list[str]) -> int | None:
    """The ``<artifactId>`` line of a ``<dependency>`` (not one inside its ``<exclusions>``, not a plugin or the
    parent) whose groupId matches when the name carries one (``group:artifact``)."""
    group, _, artifact = name.rpartition(":")
    artifact = artifact or name
    in_dep = in_excl = False
    dep_group, dep_line, dep_artifact = "", 0, ""
    for number, line in enumerate(lines, start=1):
        for m in _POM_TOKEN.finditer(line[:MAX_LINE]):
            close, tag, field, value = m.group(1), m.group(2), m.group(3), m.group(4)
            if tag == "exclusions":
                in_excl = not close
            elif tag == "dependency" and not in_excl:
                if not close:
                    in_dep, dep_group, dep_line, dep_artifact = True, "", 0, ""
                else:
                    if in_dep and dep_artifact == artifact and (not group or dep_group == group):
                        return dep_line
                    in_dep = False
            elif field and in_dep and not in_excl:
                if field == "groupId":
                    dep_group = value
                else:
                    dep_artifact, dep_line = value, number
    return None


def _package_json_line(name: str, lines: list[str]) -> int | None:
    """``"<name>":`` inside one of the dependency maps, not a script or another field with the same key."""
    key = re.compile(rf'"{re.escape(name)}"\s*:')
    opening = re.compile(rf'^\s*"({"|".join(NPM_SECTIONS)})"\s*:\s*\{{(.*)$')
    inside = False
    for number, line in enumerate(lines, start=1):
        text = line[:MAX_LINE]
        m = opening.match(text)
        if m:
            inside = "}" not in m.group(2)
            if key.search(m.group(2)):
                return number
            continue
        if inside:
            if key.match(text.strip()):
                return number
            if text.strip().startswith("}"):
                inside = False
    return None


def normalised_name(ecosystem: str, name: str) -> str:
    return _pep503(name) if ecosystem == "pypi" else name
