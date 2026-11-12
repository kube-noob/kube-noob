"""The krew plugin: a passthrough script, and a manifest whose digest is a property of the script (G194)."""

from __future__ import annotations

import hashlib
import io
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SH = shutil.which("sh") or "/bin/sh"
sys.path.insert(0, str(ROOT / "scripts"))
import krew_manifest as km  # noqa: E402

from kube_noob import __version__  # noqa: E402
from kube_noob.audit.rules import RULES  # noqa: E402


@pytest.fixture(scope="module")
def doc() -> dict:
    data = yaml.safe_load(km.MANIFEST.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def test_the_committed_script_and_manifest_are_current() -> None:
    assert km.main(["--check"]) == 0, "run: python scripts/krew_manifest.py"


def test_the_shipped_script_has_no_placeholder_left_and_pins_this_version() -> None:
    text = km.SCRIPT.read_text(encoding="utf-8")
    assert "__VERSION__" not in text, "the committed script must be the one that ships, not the template"
    assert f'VERSION="{__version__}"' in text
    # The uvx fallback has to pin, or `kubectl noob --version` disagrees with what krew installed.
    assert '--from "kube-noob==$VERSION"' in text


def test_the_script_parses_as_posix_sh() -> None:
    for path in (km.TEMPLATE, km.SCRIPT):
        done = subprocess.run([SH, "-n", str(path)], capture_output=True, text=True, check=False)
        assert done.returncode == 0, (path, done.stderr)


def test_the_script_never_searches_for_the_bare_noob_alias() -> None:
    """The package installs `noob` too, but it is generic enough to collide on a shared machine."""
    text = km.SCRIPT.read_text(encoding="utf-8")
    assert "command -v kube-noob" in text
    assert re.search(r"command -v noob\b", text) is None


def test_the_archive_is_byte_reproducible() -> None:
    assert km.archive() == km.archive(), "a digest that changes per build cannot be checked"
    assert hashlib.sha256(km.archive()).hexdigest() != ""


def test_the_archive_bytes_do_not_depend_on_the_zlib_build() -> None:
    """The digest has to be the same on every machine that builds it, and compressed output is not: zlib and zlib-ng
    (which some Python builds link) produce different deflate streams for the same input. The archive with LICENSE in it
    hashed b586a8ef... on a zlib-ng Python and b641267b... on CI's zlib, so CI failed while the local gate passed.
    Stored (uncompressed) deflate blocks have exactly one encoding, so every block must be one."""
    data = km.archive()
    assert data[:4] == b"\x1f\x8b\x08\x00", "gzip, deflate, no optional header fields"
    pos, final = 10, False
    while not final:
        header = data[pos]
        final, btype = bool(header & 1), (header >> 1) & 3
        assert btype == 0, f"a compressed deflate block at byte {pos}: its bytes depend on the zlib build"
        size = int.from_bytes(data[pos + 1 : pos + 3], "little")
        assert int.from_bytes(data[pos + 3 : pos + 5], "little") == size ^ 0xFFFF
        pos += 5 + size
    assert len(data) == pos + 8, "nothing after the last block but the CRC-32 and the size"
    import gzip
    import zlib

    payload = gzip.decompress(data)
    assert data[pos:] == zlib.crc32(payload).to_bytes(4, "little") + len(payload).to_bytes(4, "little")


def test_the_manifest_digest_is_the_archive_digest(doc: dict) -> None:
    platform = doc["spec"]["platforms"][0]
    assert platform["sha256"] == hashlib.sha256(km.archive()).hexdigest()
    assert len(platform["sha256"]) == 64


def test_the_archive_holds_the_executable_named_as_krew_expects_and_the_licence(doc: dict) -> None:
    """krew's pre-submit checklist: "Adopt an open source license, and add it to your plugin archive file" and
    "Make sure to extract the LICENSE file during the plugin installation"
    (https://krew.sigs.k8s.io/docs/developer-guide/release/new-plugin/, read 2026-11-12). With no `files` in the
    manifest krew extracts everything, so the licence is installed beside the script (G276)."""
    with tarfile.open(fileobj=io.BytesIO(km.archive()), mode="r:gz") as tar:
        members = tar.getmembers()
        licence = tar.extractfile("LICENSE")
        assert licence is not None
        shipped = licence.read().decode("utf-8")
    assert [m.name for m in members] == [km.BIN, "LICENSE"]
    assert shipped == (ROOT / "LICENSE").read_text(encoding="utf-8")
    assert doc["spec"]["platforms"][0]["bin"] == km.BIN
    assert "files" not in doc["spec"]["platforms"][0], "with no `files`, krew extracts the licence too"
    assert members[0].mode == 0o755 and members[1].mode == 0o644
    for m in members:
        assert m.mtime == 0 and m.uid == 0 and m.gid == 0 and m.uname == ""


def test_the_description_lists_no_commands(doc: dict) -> None:
    """The manifest guide: "Avoid including a list of commands or options for your plugin" in `description`
    (https://krew.sigs.k8s.io/docs/developer-guide/plugin-manifest/, read 2026-11-12)."""
    lines = [ln.strip() for ln in doc["spec"]["description"].splitlines()]
    assert not [ln for ln in lines if ln.startswith("kubectl ")], "a command line in the description"
    assert "--help" in doc["spec"]["description"], "point at the help instead of listing commands"


def test_the_install_hints_name_only_documented_install_routes() -> None:
    """The script once told a user to `brew install kube-noob/tap/kube-noob`, a tap the install guide never names.
    The Homebrew route is the guide's three commands (tests/test_distribution.py holds them there)."""
    out = subprocess.run(
        [SH, str(km.SCRIPT), "audit"], capture_output=True, text=True, check=False, env={"PATH": "/nonexistent"}
    )
    assert "kube-noob/tap" not in out.stderr and "kube-noob/tap" not in km.MANIFEST.read_text(encoding="utf-8")
    assert "brew tap kube-noob/kube-noob https://github.com/aashishmahajan/kube-noob" in out.stderr
    assert "brew trust --formula kube-noob/kube-noob/kube-noob" in out.stderr


def test_the_plugin_name_and_bin_follow_krew_naming(doc: dict) -> None:
    name = doc["metadata"]["name"]
    assert re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", name), name
    assert f"kubectl-{name}" == km.BIN, "krew runs the plugin as kubectl-<name>"


def test_the_manifest_states_the_release_this_build_is(doc: dict) -> None:
    spec = doc["spec"]
    assert spec["version"] == f"v{__version__}"
    assert spec["platforms"][0]["uri"].endswith(f"/v{__version__}/kubectl-noob-v{__version__}.tar.gz")
    assert doc["apiVersion"] == "krew.googlecontainertools.github.com/v1alpha2" and doc["kind"] == "Plugin"


def test_the_manifest_claims_only_the_platforms_a_shell_script_runs_on(doc: dict) -> None:
    selectors = doc["spec"]["platforms"][0]["selector"]["matchExpressions"]
    assert selectors == [{"key": "os", "operator": "In", "values": ["darwin", "linux"]}]
    assert "windows" not in km.MANIFEST.read_text(encoding="utf-8")


def test_the_description_states_the_real_rule_count(doc: dict) -> None:
    assert f"{len(RULES)} deterministic rules" in doc["spec"]["description"]
    assert "{rules}" not in km.MANIFEST.read_text(encoding="utf-8"), "the placeholder was not substituted"


def test_the_short_description_fits_krews_listing(doc: dict) -> None:
    assert len(doc["spec"]["shortDescription"]) <= 80


def test_the_caveats_name_both_ways_to_satisfy_the_dependency(doc: dict) -> None:
    caveats = doc["spec"]["caveats"]
    assert "kube-noob on PATH" in caveats and "uv" in caveats


def test_the_script_forwards_every_argument_unchanged(tmp_path: Path) -> None:
    """A passthrough that reorders or drops arguments is worse than no plugin."""
    spy = tmp_path / "spy"
    spy.write_text('#!/usr/bin/env sh\nprintf "%s\\n" "$@"\n', encoding="utf-8")
    spy.chmod(0o755)
    args = ["audit", "-f", "k8s/", "--platform", "openshift", "--version", "4.22", "--fail-on", "high"]
    out = subprocess.run(
        [SH, str(km.SCRIPT), *args],
        capture_output=True,
        text=True,
        check=False,
        env={"PATH": "/usr/bin:/bin", "KUBE_NOOB_BIN": str(spy)},
    )
    assert out.returncode == 0, out.stderr
    assert out.stdout.splitlines() == args


def test_with_nothing_installed_it_says_so_and_exits_127() -> None:
    # An absolute interpreter, because PATH is emptied for the script's own lookups.
    out = subprocess.run(
        [SH, str(km.SCRIPT), "audit"],
        capture_output=True,
        text=True,
        check=False,
        env={"PATH": "/nonexistent"},
    )
    assert out.returncode == 127
    assert "neither kube-noob nor uv is installed" in out.stderr
    assert __version__ in out.stderr, "the message has to name the version this plugin pins"
    # This is the ONE path that runs when PATH is unusable, so the message may not shell out to print itself:
    # a heredoc fed to `cat` printed "cat: not found" here instead of the instructions.
    for line in ("pipx install", "brew install", "astral.sh/uv", "offline by default"):
        assert line in out.stderr, f"the install message lost {line!r} -- is it using an external command?"
