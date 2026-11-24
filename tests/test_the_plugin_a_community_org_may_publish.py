"""The published plugin folder stays inside what the directory accepts from a community organization (G380).

The Claude plugin directory accepts a ``command`` hook, an MCP server that runs on the user's computer, and files
that are not Markdown, text, JSON, YAML or an allowed image ONLY from Verified organizations. `kube-noob/kube-noob`
is not one, so `plugin/kube-noob` -- a `PreToolUse` hook, a stdio server started with `uv run`, 118 `.py` files,
`uv.lock`, `pyproject.toml`, an `.svg` and three `.tmpl` files -- is refused once per category, and no edit to it
clears a finding whose content is "not from you".

`plugin/kube-noob-skills` is what is submitted. These tests hold its SHAPE rather than re-deriving the policy,
because a policy constraint is exactly what a later commit re-breaks without noticing: one skill that needs a helper
script, one convenience hook, one `requirements.txt`, and the submission is refused again with no test having failed.

`claude plugin validate` passes on the folder and does not check any of this.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PUBLISHED = ROOT / "plugin" / "kube-noob-skills"

#: Markdown, text, JSON, YAML and the image types the directory allows. A file with no extension is read as text and
#: checked as text (LICENSE); anything else here is a file the directory refuses from an unverified organization.
ALLOWED_SUFFIXES = frozenset(
    {".md", ".txt", ".json", ".yaml", ".yml", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico"}
)

#: Names that mark a package manager's configuration or its list of packages. The directory refuses each, and
#: refuses a file that merely shares the name, so this is matched on the name and not on the contents.
PACKAGE_MANAGER_NAMES = frozenset(
    {
        "package.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "pnpm-workspace.yaml",
        "yarn.lock",
        "npm-shrinkwrap.json",
        ".npmrc",
        "requirements.txt",
        "requirements-dev.txt",
        "constraints.txt",
        "Pipfile",
        "Pipfile.lock",
        "poetry.lock",
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "uv.lock",
        "uv.toml",
        "pip.conf",
        "Gemfile",
        "Gemfile.lock",
        "go.mod",
        "go.sum",
        "Cargo.toml",
        "Cargo.lock",
    }
)

#: The directory refuses a plugin whose own instructions sit in one of these names, because Claude Code reads them
#: as repository instructions rather than as part of the plugin.
RESERVED_INSTRUCTION_NAMES = frozenset({"claude.md", "claude.local.md", "agents.md"})

#: The directory's per-file and per-plugin limits.
MAX_FILE_BYTES = 256 * 1024
MAX_FILES = 512

#: A command the directory extracts must hold fewer than this many `<` characters.
MAX_ANGLE_BRACKETS = 3


def _files() -> list[Path]:
    return sorted(p for p in PUBLISHED.rglob("*") if p.is_file())


def _fenced_blocks(text: str) -> list[list[str]]:
    """Every fenced block in a Markdown document, as its lines. The fence marker lines are not included."""
    blocks: list[list[str]] = []
    current: list[str] | None = None
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            if current is None:
                current = []
            else:
                blocks.append(current)
                current = None
            continue
        if current is not None:
            current.append(line)
    if current is not None:  # an unclosed fence: judge what it holds rather than dropping it
        blocks.append(current)
    return blocks


def test_the_published_plugin_is_markdown_a_manifest_and_an_icon() -> None:
    offenders = []
    for p in _files():
        if p.suffix:
            if p.suffix.lower() not in ALLOWED_SUFFIXES:
                offenders.append(str(p.relative_to(PUBLISHED)))
        else:
            # No extension: the directory reads it as text, so it must BE text.
            try:
                p.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                offenders.append(str(p.relative_to(PUBLISHED)))
    assert offenders == [], (
        "the directory accepts a file of another type only from a Verified organization, and these would be "
        f"refused: {offenders}. Put the code in plugin/kube-noob/ and keep this folder Markdown (G380)."
    )


def test_no_file_in_it_begins_with_a_shebang() -> None:
    offenders = [str(p.relative_to(PUBLISHED)) for p in _files() if p.read_bytes()[:2] == b"#!"]
    assert offenders == [], f"a file beginning #! is a program to the directory, whatever its name: {offenders}"


def test_every_text_file_is_utf_8_with_no_nul_byte() -> None:
    bad_encoding, has_nul = [], []
    for p in _files():
        if p.suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico"}:
            continue
        raw = p.read_bytes()
        if b"\x00" in raw:
            has_nul.append(str(p.relative_to(PUBLISHED)))
        try:
            raw.decode("utf-8")
        except UnicodeDecodeError:
            bad_encoding.append(str(p.relative_to(PUBLISHED)))
    assert bad_encoding == [], f"the directory requires UTF-8: {bad_encoding}"
    assert has_nul == [], f"the directory refuses a text file holding a NUL byte: {has_nul}"


def test_the_icon_is_a_png_and_not_an_archive() -> None:
    icon = PUBLISHED / "icon.png"
    assert icon.is_file(), "the manifest names ./icon.png"
    raw = icon.read_bytes()
    assert raw[:8] == b"\x89PNG\r\n\x1a\n", "icon.png must be a real PNG"
    # The directory refuses an image that looks like it holds a zip archive. A PNG never needs these signatures.
    for sig in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        assert sig not in raw, "icon.png holds a zip signature and would be refused as an archive wearing the name"


def test_it_declares_no_hook_and_no_mcp_server() -> None:
    manifest = json.loads((PUBLISHED / ".claude-plugin" / "plugin.json").read_text())
    for key in ("hooks", "mcpServers", "mcpServerss"):
        assert key not in manifest, f"the directory accepts {key} only from a Verified organization"
    stray = [
        str(p.relative_to(PUBLISHED))
        for p in _files()
        if p.name in {"hooks.json", ".mcp.json", ".lsp.json", "monitors.json"}
    ]
    assert stray == [], f"these are refused or unread by Claude Code, so the directory refuses the plugin: {stray}"
    assert not (PUBLISHED / "hooks").exists(), "a hooks/ folder is a Verified-only part"


def test_it_holds_no_package_manager_file_and_no_lockfile() -> None:
    offenders = [
        str(p.relative_to(PUBLISHED))
        for p in _files()
        if p.name in PACKAGE_MANAGER_NAMES or p.suffix.lower() == ".lock"
    ]
    assert offenders == [], f"the directory refuses a package manager's file or a lockfile here: {offenders}"
    reserved = [str(p.relative_to(PUBLISHED)) for p in _files() if p.name.lower() in RESERVED_INSTRUCTION_NAMES]
    assert reserved == [], f"the directory refuses these names; put the instructions in a skill: {reserved}"
    assert not (PUBLISHED / "node_modules").exists()
    for folder in (".claude/skills", ".claude/commands", ".claude/agents", ".claude/rules"):
        assert not (PUBLISHED / folder).exists(), f"{folder} is refused inside a plugin"


@pytest.mark.parametrize("doc", [p for p in _files() if p.suffix == ".md"], ids=lambda p: p.name)
def test_no_fenced_command_holds_three_angle_brackets(doc: Path) -> None:
    """A command the directory extracts must hold fewer than three `<`, and no argument may be only `<`.

    The placeholders in these blocks are `NAME`, `NS` and `POD` rather than angle brackets for exactly this reason
    (G380). Prose and tables outside a fenced block are documentation and are not read as commands.
    """
    for block in _fenced_blocks(doc.read_text()):
        for line in block:
            count = line.count("<")
            assert count < MAX_ANGLE_BRACKETS, (
                f"{doc.name}: a fenced command holds {count} '<' characters, which the directory refuses; use an "
                f"uppercase placeholder such as NAME or NS instead: {line.strip()!r}"
            )
            assert "<" not in line.split(), f"{doc.name}: an argument that is only '<' is refused: {line.strip()!r}"
        joined = " ".join(line.strip() for line in block if line.strip())
        assert joined.count("<") < MAX_ANGLE_BRACKETS, (
            f"{doc.name}: a fenced block read as one command holds {joined.count('<')} '<' characters"
        )


def test_it_is_within_the_file_count_and_file_size_limits() -> None:
    files = _files()
    assert len(files) <= MAX_FILES, f"{len(files)} files against a limit of {MAX_FILES}"
    oversized = {str(p.relative_to(PUBLISHED)): p.stat().st_size for p in files if p.stat().st_size > MAX_FILE_BYTES}
    assert oversized == {}, f"over {MAX_FILE_BYTES} bytes: {oversized}"


def test_the_marketplace_still_offers_both_plugins() -> None:
    """The refused folder is kept, and the marketplace path has no directory policy in it.

    `plugin/kube-noob` is what ships once the organization is Verified, and adding this repository as a marketplace
    installs it today. Deleting it to make the directory happy would remove the MCP server and the pre-action hook
    from the users who can already have them.
    """
    market = json.loads((ROOT / ".claude-plugin" / "marketplace.json").read_text())
    sources = {entry["name"]: entry["source"] for entry in market["plugins"]}
    assert sources.get("kube-noob") == "./plugin/kube-noob"
    assert sources.get("kube-noob-skills") == "./plugin/kube-noob-skills"
