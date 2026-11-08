#!/usr/bin/env python3
"""Write the Homebrew formula (Formula/kube-noob.rb) for a kube-noob release that is already on PyPI.

Usage:
  python scripts/brew_formula.py [VERSION]           print the formula (default: the version in src/kube_noob)
  python scripts/brew_formula.py VERSION --write     write Formula/kube-noob.rb
  python scripts/brew_formula.py --check             exit 1 if Formula/kube-noob.rb differs from what PyPI implies

Homebrew builds without network access, so every file is a formula resource that brew downloads and checks by
sha256 first: the release wheel, and one wheel per dependency at the exact version pinned in the release sdist's
requirements.lock (pure-Python wheels once; compiled ones for Apple silicon macOS and for Linux arm64/x86_64).
Install is then `pip install --no-index --no-deps` of those files into a private virtualenv: nothing is compiled or
fetched.
Users install it with:
  brew tap kube-noob/kube-noob https://github.com/aashishmahajan/kube-noob
  brew trust --formula kube-noob/kube-noob/kube-noob
  brew install kube-noob
The release workflow runs `VERSION --write` once PyPI has the release and pushes the result to main.
Needs the `packaging` library (installed with kube-noob's dev extras).
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import sys
import tarfile
import urllib.request
from pathlib import Path
from typing import Any

from packaging import tags
from packaging.markers import Marker
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name, parse_wheel_filename
from packaging.version import Version

ROOT = Path(__file__).resolve().parents[1]
FORMULA = ROOT / "Formula" / "kube-noob.rb"
PYTHON_FORMULA = "python@3.13"
PY = (3, 13)
_SEMVER = re.compile(r"^\d+\.\d+\.\d+$")

# (homebrew os block, homebrew arch block) -> marker environment. Intel Macs are left out: current cryptography (an mcp
# dependency) ships no macOS x86_64 wheel, and Homebrew moved Intel macOS to its lowest support tier.
TARGETS: dict[tuple[str, str], dict[str, Any]] = {
    ("macos", "arm"): {"sys_platform": "darwin", "platform_system": "Darwin", "platform_machine": "arm64"},
    ("linux", "arm"): {"sys_platform": "linux", "platform_system": "Linux", "platform_machine": "aarch64"},
    ("linux", "intel"): {"sys_platform": "linux", "platform_system": "Linux", "platform_machine": "x86_64"},
}


def _platforms(os_name: str, machine: str) -> list[str]:
    if os_name == "macos":
        return list(tags.mac_platforms((13, 0), machine))
    # Homebrew on Linux ships glibc 2.35; accept every manylinux tag up to it.
    return [f"manylinux_2_{m}_{machine}" for m in range(35, 16, -1)] + [f"manylinux2014_{machine}", "linux_" + machine]


def _supported_tags(os_name: str, machine: str) -> list[tags.Tag]:
    plats = _platforms(os_name, machine)
    return list(tags.cpython_tags(PY, abis=["cp313"], platforms=plats)) + list(
        tags.compatible_tags(PY, "cp313", platforms=plats)
    )


def _env(target: tuple[str, str]) -> dict[str, str]:
    base = {
        "python_version": "3.13",
        "python_full_version": "3.13.0",
        "implementation_name": "cpython",
        "platform_python_implementation": "CPython",
        "os_name": "posix",
        "platform_release": "",
        "platform_version": "",
        "implementation_version": "3.13.0",
        "extra": "",
    }
    return {**base, **TARGETS[target]}


def _get_json(url: str) -> dict[str, Any]:
    with urllib.request.urlopen(url, timeout=60) as resp:  # noqa: S310 - fixed https URL
        return json.load(resp)  # type: ignore[no-any-return]


def _release(name: str, version: str) -> list[dict[str, Any]]:
    return _get_json(f"https://pypi.org/pypi/{name}/{version}/json")["urls"]  # type: ignore[no-any-return]


def _lock_from_sdist(sdist: dict[str, Any], version: str) -> list[Requirement]:
    with urllib.request.urlopen(sdist["url"], timeout=120) as resp:  # noqa: S310 - PyPI file URL
        data = resp.read()
    if hashlib.sha256(data).hexdigest() != sdist["digests"]["sha256"]:
        raise SystemExit("sdist sha256 mismatch")
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        member = tar.extractfile(f"kube_noob-{version}/requirements.lock")
        if member is None:
            raise SystemExit("the release sdist has no requirements.lock")
        text = member.read().decode()
    reqs = []
    for line in text.splitlines():
        if line and not line[0].isspace() and not line.startswith("#"):
            reqs.append(Requirement(line.rstrip(" \\")))
    return reqs


def _pick(files: list[dict[str, Any]], supported: list[tags.Tag]) -> dict[str, Any] | None:
    rank = {t: i for i, t in enumerate(supported)}
    best: tuple[int, dict[str, Any]] | None = None
    for f in files:
        if not f["filename"].endswith(".whl"):
            continue
        _, _, _, wheel_tags = parse_wheel_filename(f["filename"])
        score = min((rank[t] for t in wheel_tags if t in rank), default=None)
        if score is not None and (best is None or score < best[0]):
            best = (score, f)
    return best[1] if best else None


def resources(version: str) -> tuple[dict[str, str], list[tuple[str, dict[str, str]]], dict[tuple[str, str], list]]:
    if not _SEMVER.match(version):
        raise SystemExit(f"{version!r} is not MAJOR.MINOR.PATCH")
    files = _release("kube-noob", version)
    sdist = next((f for f in files if f["packagetype"] == "sdist"), None)
    wheel = next((f for f in files if f["filename"] == f"kube_noob-{version}-py3-none-any.whl"), None)
    if not sdist or not wheel:
        raise SystemExit(f"kube-noob {version} on PyPI lacks an sdist or a py3-none-any wheel")
    head = {"sdist_url": sdist["url"], "sdist_sha256": sdist["digests"]["sha256"]}
    common: list[tuple[str, dict[str, str]]] = [
        ("kube-noob", {"url": wheel["url"], "sha256": wheel["digests"]["sha256"]})
    ]
    per_target: dict[tuple[str, str], list[tuple[str, dict[str, str]]]] = {t: [] for t in TARGETS}
    for req in _lock_from_sdist(sdist, version):
        pinned = next(iter(req.specifier)).version
        name = str(canonicalize_name(req.name))
        targets = [t for t in TARGETS if req.marker is None or Marker(str(req.marker)).evaluate(_env(t))]
        if not targets:
            continue
        rel = _release(name, pinned)
        picks = {t: _pick(rel, _supported_tags(t[0], TARGETS[t]["platform_machine"])) for t in targets}
        found = {t: f for t, f in picks.items() if f is not None}
        if len(found) != len(picks):
            raise SystemExit(f"{name}=={pinned} has no wheel for {sorted(set(picks) - set(found))}")
        if len({f["url"] for f in found.values()}) == 1 and len(targets) == len(TARGETS):
            f = next(iter(found.values()))
            common.append((name, {"url": f["url"], "sha256": f["digests"]["sha256"]}))
        else:
            for t, f in found.items():
                per_target[t].append((name, {"url": f["url"], "sha256": f["digests"]["sha256"]}))
    return head, common, per_target


def _resource(name: str, r: dict[str, str], indent: str) -> str:
    return f'{indent}resource "{name}" do\n{indent}  url "{r["url"]}"\n{indent}  sha256 "{r["sha256"]}"\n{indent}end\n'


# The short command `noob` ships from this release on; older wheels have only `kube-noob`.
NOOB_SINCE = Version("0.2.3")


def render(version: str) -> str:
    head, common, per_target = resources(version)
    noob = Version(version) >= NOOB_SINCE
    link_noob = '\n    bin.install_symlink libexec/"bin/noob"' if noob else ""
    test_noob = '\n    assert_match version.to_s, shell_output("#{bin}/noob --version")' if noob else ""
    out = [
        "# Generated by scripts/brew_formula.py from the PyPI release files. Do not edit by hand.\n",
        "class KubeNoob < Formula\n",
        '  desc "Kubernetes, OpenShift, ROSA HCP, Helm and RHACS audit, debugging and learning tools"\n',
        '  homepage "https://github.com/aashishmahajan/kube-noob"\n',
        f'  url "{head["sdist_url"]}"\n',
        f'  sha256 "{head["sdist_sha256"]}"\n',
        '  license "Apache-2.0"\n\n',
        f'  depends_on "{PYTHON_FORMULA}"\n\n',
    ]
    for name, r in common:
        out.append(_resource(name, r, "  ") + "\n")
    out.append("  on_macos do\n    depends_on arch: :arm64\n\n")
    out.extend(_resource(name, r, "    ") for name, r in per_target[("macos", "arm")])
    out.append("  end\n\n  on_linux do\n")
    for arch in ("arm", "intel"):
        out.append(f"    on_{arch} do\n")
        out.extend(_resource(name, r, "      ") for name, r in per_target[("linux", arch)])
        out.append("    end\n")
    out.append("  end\n\n")
    out.append(
        f"""  def install
    python = Formula["{PYTHON_FORMULA}"].opt_libexec/"bin/python"
    system python, "-m", "venv", libexec
    wheels = buildpath/"wheels"
    wheels.mkpath
    resources.each {{ |r| cp r.cached_download, wheels/File.basename(r.url) }}
    system libexec/"bin/python", "-m", "pip", "--disable-pip-version-check", "install", "--no-index", "--no-deps",
           *wheels.children
    system libexec/"bin/python", "-m", "pip", "--disable-pip-version-check", "check"
    bin.install_symlink libexec/"bin/kube-noob"{link_noob}
  end

  test do
    assert_match version.to_s, shell_output("#{{bin}}/kube-noob --version"){test_noob}
    (testpath/"deploy.yaml").write <<~YAML
      apiVersion: apps/v1
      kind: Deployment
      metadata:
        name: api
      spec:
        selector:
          matchLabels:
            app: api
        template:
          metadata:
            labels:
              app: api
          spec:
            containers:
              - name: api
                image: quay.io/example/api:latest
                securityContext:
                  privileged: true
    YAML
    audit_cmd = "#{{bin}}/kube-noob audit -f #{{testpath}}/deploy.yaml --platform openshift --fail-on never"
    audit = shell_output("#{{audit_cmd}} --format json")
    assert_match "\\"score\\"", audit
    (testpath/"events.txt").write "Last State: Terminated\\nReason: OOMKilled\\nExit Code: 137\\n"
    assert_match "DBG-OOM", shell_output("#{{bin}}/kube-noob diagnose -f #{{testpath}}/events.txt --format json")
  end
end
"""
    )
    return "".join(out)


def formula_version(text: str) -> str:
    m = re.search(r"/kube_noob-(\d+\.\d+\.\d+)\.tar\.gz\"", text)
    if not m:
        raise SystemExit("Formula/kube-noob.rb has no kube_noob-<version>.tar.gz url")
    return m.group(1)


def _current_version() -> str:
    m = re.search(r'__version__ = "([^"]+)"', (ROOT / "src/kube_noob/__init__.py").read_text())
    if not m:
        raise SystemExit("cannot find __version__")
    return m.group(1)


def main(argv: list[str]) -> int:
    if argv == ["--check"]:
        text = FORMULA.read_text()
        version = formula_version(text)
        if text != render(version):
            print(f"Formula/kube-noob.rb does not match PyPI kube-noob {version}", file=sys.stderr)
            return 1
        print(f"Formula/kube-noob.rb matches PyPI kube-noob {version}")
        return 0
    write = "--write" in argv
    rest = [a for a in argv if a != "--write"]
    if len(rest) > 1 or any(a.startswith("-") for a in rest):
        print(__doc__)
        return 2
    text = render(rest[0] if rest else _current_version())
    if write:
        FORMULA.parent.mkdir(exist_ok=True)
        FORMULA.write_text(text)
        print(f"wrote {FORMULA.relative_to(ROOT)}")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
