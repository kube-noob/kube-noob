#!/usr/bin/env python3
"""Bump the kube-noob release version everywhere it ships, and add a CHANGELOG entry.

Usage: python scripts/bump_version.py 0.1.1 "Security: rebuild on patched UBI base image."
Then: commit, push, wait for CI, tag v0.1.1 and push the tag (docs/operations.md). The plugin's bundled server copy,
pyproject.toml and uv.lock move with it; CI checks them with scripts/sync_plugin_server.py --check.
"""

from __future__ import annotations

import datetime as dt
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_SEMVER = re.compile(r"^\d+\.\d+\.\d+$")

# file -> regex patterns whose group "v" is the version to replace, or group "m" its MAJOR.MINOR (an image tag that
# follows the newest release of a minor)
TARGETS: dict[str, tuple[str, ...]] = {
    "src/kube_noob/__init__.py": (r'__version__ = "(?P<v>[^"]+)"',),
    "server.json": (r'"version": "(?P<v>[^"]+)"',),
    ".claude-plugin/marketplace.json": (r'"version": "(?P<v>[^"]+)"',),
    "plugin/kube-noob/.claude-plugin/plugin.json": (r'"version": "(?P<v>[^"]+)"',),
    "plugin/kube-noob-skills/.claude-plugin/plugin.json": (r'"version": "(?P<v>[^"]+)"',),
    "plugin/kube-noob/pyproject.toml": (r'^version = "(?P<v>[^"]+)"$',),
    "plugin/kube-noob/uv.lock": (r'^name = "kube-noob-plugin"\nversion = "(?P<v>[^"]+)"$',),
    "plugin/kube-noob/server/kube_noob/__init__.py": (r'__version__ = "(?P<v>[^"]+)"',),
    # When the plugin's launcher becomes `uvx kube-noob==<version> mcp` (from 0.7.1; plugin/kube-noob/README.md says
    # why not before), add plugin/kube-noob/.mcp.json here with this same pattern, and to FILES in
    # tests/test_bump_version.py. A stale pin there would install the previous release.
    "README.md": (r"kube-noob==(?P<v>\d+\.\d+\.\d+)",),
    "deploy/helm/kube-noob/Chart.yaml": (r"^version: (?P<v>\S+)$", r'^appVersion: "(?P<v>[^"]+)"$'),
    "deploy/sidecar/app-with-kube-noob-sidecar.yaml": (r"ghcr\.io/kube-noob/kube-noob:(?P<v>\d+\.\d+\.\d+)",),
    "Containerfile": (r"^ARG VERSION=(?P<v>\S+)$",),
    "deploy/tekton/kube-noob-gate.yaml": (
        r'app\.kubernetes\.io/version: "(?P<v>[^"]+)"',
        r"ghcr\.io/kube-noob/kube-noob:(?P<v>\d+\.\d+\.\d+)",
    ),
    "deploy/gitlab/kube-noob-gate.gitlab-ci.yml": (r"ghcr\.io/kube-noob/kube-noob:(?P<v>\d+\.\d+\.\d+)",),
    "docs/install.md": (
        r"ghcr\.io/kube-noob/kube-noob:(?P<m>\d+\.\d+)(?![.\d])",
        # the directory plugin's install line and the Claude Desktop config, and the no-krew kubectl path (G276)
        r"kube-noob==(?P<v>\d+\.\d+\.\d+)",
        r"/v(?P<v>\d+\.\d+\.\d+)/",
        r"kubectl-noob-v(?P<v>\d+\.\d+\.\d+)\.tar\.gz",
    ),
    # the owner's commands for the OpenShift Helm catalog pull request: every version in it is the release's
    "docs/openshift-catalog.md": (r"(?<![\d.])(?P<v>\d+\.\d+\.\d+)(?!\.?\d)",),
}


def _ver(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in v.split("."))


def current_version(root: Path = ROOT) -> str:
    m = re.search(r'__version__ = "([^"]+)"', (root / "src/kube_noob/__init__.py").read_text())
    if not m:
        raise ValueError("cannot find __version__")
    return m.group(1)


def bump(root: Path, new: str, note: str) -> list[str]:
    if not _SEMVER.match(new):
        raise ValueError(f"{new!r} is not MAJOR.MINOR.PATCH")
    old = current_version(root)
    if _ver(new) <= _ver(old):
        raise ValueError(f"{new} must be greater than the current {old}")
    if not note.strip():
        raise ValueError("a CHANGELOG note is required")
    changed = []
    for rel, patterns in TARGETS.items():
        path = root / rel
        text = path.read_text()
        updated = text
        for pat in patterns:
            rx = re.compile(pat, re.MULTILINE)
            if not rx.search(updated):
                raise ValueError(f"{rel}: pattern {pat!r} not found")
            key, value = ("m", ".".join(new.split(".")[:2])) if "m" in rx.groupindex else ("v", new)
            updated = rx.sub(lambda m, k=key, v=value: m.group(0).replace(m.group(k), v), updated)
        if updated != text:
            path.write_text(updated)
            changed.append(rel)
    log = root / "CHANGELOG.md"
    text = log.read_text()
    header = f"## {new} - {dt.date.today().isoformat()}\n\n- {note.strip()}\n"
    if "\n## Unreleased\n\n" in text:
        # The notes gathered under "Unreleased" already describe the release: they become its entry as written.
        log.write_text(text.replace("\n## Unreleased\n\n", f"\n## {new} - {dt.date.today().isoformat()}\n\n", 1))
    else:
        first = text.index("\n## ") + 1
        log.write_text(text[:first] + header + "\n" + text[first:])
    changed.append("CHANGELOG.md")
    return changed


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    for rel in bump(ROOT, sys.argv[1], sys.argv[2]):
        print(f"updated {rel}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
