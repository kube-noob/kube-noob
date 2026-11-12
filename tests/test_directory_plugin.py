"""plugin/kube-noob-skills is the plugin the Claude directory will accept, and it has to stay acceptable.

The directory refused plugin/kube-noob on 2026-11-10 with two findings, both gated on an organization label this
project cannot apply for: "Local MCP servers accepted only from Verified organizations" and "Files outside the
allowed types accepted only from Verified organizations". That plugin is 218 files, 99 of them a type the gate
refuses, and it declares a local stdio server. No edit keeps the server and passes.

So the directory gets a second plugin that carries the knowledge and no code. The danger in that is specific: the
seven skills in plugin/kube-noob were written to call `kubenoob_*` MCP tools, and copying them into a plugin with no
server would ship seven skills telling Claude to call tools that are not there -- an absence reading as a pass,
aimed at this project's own listing. These tests refuse that, and they refuse a `kube-noob` command line that the
CLI would not accept, because a skill whose remedy does not run is the same failure one step later.
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
LITE = ROOT / "plugin" / "kube-noob-skills"
FULL = ROOT / "plugin" / "kube-noob"

# What the directory accepts from an organization that is not Verified, as the live check stated it on 2026-11-10:
# Markdown, text, JSON, YAML, and a PNG, JPEG, GIF, WebP or ICO image. A LICENSE, a README and the icon may stay.
ALLOWED_SUFFIXES = {".md", ".txt", ".json", ".yaml", ".yml", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico"}
ALLOWED_NAMES = {"LICENSE", "LICENCE", ".gitignore"}

# A package-manager configuration file is refused whatever its contents.
PACKAGE_MANAGER_FILES = {
    "pyproject.toml",
    "uv.lock",
    "uv.toml",
    "poetry.lock",
    "requirements.txt",
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "bun.lock",
    "bun.lockb",
    ".npmrc",
    "bunfig.toml",
    "pnpm-workspace.yaml",
    "pnpm-lock.yaml",
    "yarn.lock",
}


def _files() -> list[Path]:
    return sorted(p for p in LITE.rglob("*") if p.is_file())


def test_the_directory_plugin_exists_with_a_manifest() -> None:
    assert (LITE / ".claude-plugin" / "plugin.json").is_file(), "the directory plugin needs its manifest"


def test_every_file_is_a_type_the_directory_accepts() -> None:
    """The finding that blocked plugin/kube-noob. 99 files there; none of that shape may appear here."""
    bad = [
        p.relative_to(LITE).as_posix()
        for p in _files()
        if p.suffix.lower() not in ALLOWED_SUFFIXES and p.name not in ALLOWED_NAMES
    ]
    assert not bad, "the directory refuses these file types from an unverified organization:\n" + "\n".join(bad)


def test_no_file_starts_with_a_shebang() -> None:
    """A `#!` line makes a file a program, which the directory refuses whatever its extension says."""
    bad = [p.relative_to(LITE).as_posix() for p in _files() if p.read_bytes()[:2] == b"#!"]
    assert not bad, "these start with a shebang:\n" + "\n".join(bad)


def test_every_text_file_is_utf8_with_no_nul_byte() -> None:
    bad: list[str] = []
    for p in _files():
        if p.suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico"}:
            continue
        raw = p.read_bytes()
        if b"\x00" in raw:
            bad.append(f"{p.relative_to(LITE).as_posix()}: NUL byte")
            continue
        try:
            raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            bad.append(f"{p.relative_to(LITE).as_posix()}: {exc}")
    assert not bad, "\n".join(bad)


def test_no_mcp_server_is_declared() -> None:
    """The other blocking finding. A local server is what the gate refuses; a remote one this project will not have."""
    assert not (LITE / ".mcp.json").exists(), "a .mcp.json here brings back the finding this plugin exists to avoid"
    manifest = json.loads((LITE / ".claude-plugin" / "plugin.json").read_text())
    assert "mcpServers" not in manifest, "plugin.json must not declare an MCP server"


def test_no_package_manager_configuration_ships() -> None:
    bad = [p.relative_to(LITE).as_posix() for p in _files() if p.name in PACKAGE_MANAGER_FILES]
    assert not bad, "the directory refuses package-manager configuration:\n" + "\n".join(bad)


def test_no_skill_tells_claude_to_call_a_tool_that_is_not_there() -> None:
    """The whole point. There is no MCP server in this plugin, so no `kubenoob_` tool exists to call."""
    bad: list[str] = []
    for p in _files():
        if p.suffix.lower() != ".md":
            continue
        for n, line in enumerate(p.read_text().splitlines(), 1):
            if "kubenoob_" in line:
                bad.append(f"{p.relative_to(LITE).as_posix()}:{n}: {line.strip()[:80]}")
    assert not bad, (
        "these name an MCP tool that this plugin does not ship, which is an absence reading as a pass:\n"
        + "\n".join(bad)
    )


def test_every_skill_in_the_full_plugin_has_a_counterpart_here() -> None:
    """A skill added to one plugin and forgotten in the other is how the two drift apart."""
    full = {p.parent.name for p in FULL.glob("skills/*/SKILL.md")}
    lite = {p.parent.name for p in LITE.glob("skills/*/SKILL.md")}
    assert full == lite, f"only in plugin/kube-noob: {sorted(full - lite)}; only here: {sorted(lite - full)}"


def test_every_skill_has_front_matter_the_directory_accepts() -> None:
    """Invalid YAML front matter, or a `description` that is a list rather than one text value, blocks the listing."""
    import yaml

    for p in sorted(LITE.glob("skills/*/SKILL.md")):
        text = p.read_text()
        assert text.startswith("---\n"), f"{p.relative_to(LITE)} has no front matter"
        end = text.find("\n---", 4)
        assert end > 0, f"{p.relative_to(LITE)}: front matter is not closed"
        front = yaml.safe_load(text[4:end])
        assert isinstance(front, dict), f"{p.relative_to(LITE)}: front matter is not a mapping"
        assert set(front) == {"name", "description"}, (
            f"{p.relative_to(LITE)}: front matter is {sorted(front)}; Agent Skills take name and description only"
        )
        assert front["name"] == p.parent.name, f"{p.relative_to(LITE)}: name is {front['name']!r}"
        assert isinstance(front["description"], str) and front["description"].strip(), (
            f"{p.relative_to(LITE)}: description must be one non-empty text value, not a list"
        )
        assert len(front["description"]) <= 1024, f"{p.relative_to(LITE)}: description over 1,024 characters"
        assert len(text.splitlines()) <= 500, f"{p.relative_to(LITE)}: SKILL.md over 500 lines"


def test_every_skill_says_what_it_cannot_do() -> None:
    """Knowledge without the tools is useful; knowledge pretending to be the tools is not."""
    for p in sorted(LITE.glob("skills/*/SKILL.md")):
        assert "## What this skill cannot do" in p.read_text(), (
            f"{p.relative_to(LITE)} does not say which tools it lacks"
        )


def test_the_readme_is_long_enough_and_says_there_is_no_server() -> None:
    text = (LITE / "README.md").read_text()
    prose = re.sub(r"```.*?```", "", text, flags=re.S)
    assert len(prose.split()) >= 40, "the directory requires a README of at least 40 words outside code blocks"
    assert "no MCP server" in text, "the README has to say plainly that there is no server in this plugin"


def test_the_licence_is_here_and_is_the_projects() -> None:
    assert (LITE / "LICENSE").is_file(), "the directory requires a LICENSE in the plugin folder"
    assert (LITE / "LICENSE").read_text() == (ROOT / "LICENSE").read_text(), "not the project's licence"


def test_the_version_matches_the_rest_of_the_project() -> None:
    lite = json.loads((LITE / ".claude-plugin" / "plugin.json").read_text())["version"]
    full = json.loads((FULL / ".claude-plugin" / "plugin.json").read_text())["version"]
    assert lite == full, f"kube-noob-skills is {lite} and kube-noob is {full}; bump_version.py must move both"


def test_the_plugin_stays_inside_the_directory_file_limits() -> None:
    files = _files()
    assert len(files) <= 512, f"{len(files)} files; the directory holds a plugin over 512 for a reviewer"
    big = [
        f"{p.relative_to(LITE).as_posix()} ({p.stat().st_size} bytes)"
        for p in files
        if p.suffix.lower() not in {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico"} and p.stat().st_size > 256 * 1024
    ]
    assert not big, "over 256 KiB:\n" + "\n".join(big)


def test_nothing_the_directory_shows_names_the_account_the_project_moved_out_of() -> None:
    """The listing renders plugin.json's fields and the plugin folder's README, and both named the old account for
    three releases after the move, because the test that should have caught it pinned the old owner as a literal.

    The generated server copy under plugin/kube-noob/server is not rendered by the directory, so it is not listed
    here; it is held, with every other tracked file, by
    test_distribution.py::test_no_tracked_file_names_the_owner_the_project_moved_out_of (G275).
    """
    shown: list[Path] = []
    for plugin in (FULL, LITE):
        shown += [plugin / "README.md", plugin / ".claude-plugin" / "plugin.json"]
        shown += sorted(plugin.glob("skills/*/SKILL.md"))
    shown.append(ROOT / ".claude-plugin" / "marketplace.json")
    bad: list[str] = []
    for path in shown:
        if not path.is_file():
            continue
        for n, line in enumerate(path.read_text().splitlines(), 1):
            if "aashishmahajan" in line:
                bad.append(f"{path.relative_to(ROOT).as_posix()}:{n}: {line.strip()[:80]}")
    assert not bad, "the directory shows these, and they name the previous owner:\n" + "\n".join(bad)


# --- the commands the skills hand to the user have to be commands the CLI accepts --------------------------------


def _subparsers(parser: argparse.ArgumentParser) -> dict[str, argparse.ArgumentParser]:
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return dict(action.choices)
    return {}


def _options(parser: argparse.ArgumentParser) -> set[str]:
    return {opt for action in parser._actions for opt in action.option_strings}


def _kube_noob_lines() -> list[tuple[str, int, str]]:
    out: list[tuple[str, int, str]] = []
    for p in sorted(LITE.rglob("*.md")):
        inside = False
        for n, line in enumerate(p.read_text().splitlines(), 1):
            if line.startswith("```"):
                inside = not inside
                continue
            if not inside:
                continue
            for raw in line.split("|"):
                segment = raw.strip()
                if segment.startswith("kube-noob "):
                    out.append((p.relative_to(LITE).as_posix(), n, segment))
    return out


def test_the_skills_name_at_least_one_command_each() -> None:
    """If this finds nothing, the check below is measuring nothing."""
    assert len(_kube_noob_lines()) >= 7, "expected a kube-noob command in every skill"


@pytest.mark.parametrize("where,line", [(f"{f}:{n}", c) for f, n, c in _kube_noob_lines()])
def test_every_command_a_skill_hands_the_user_is_one_the_cli_accepts(where: str, line: str) -> None:
    """A wrong flag in a skill is a wrong command in a terminal. Five of these were wrong when first written."""
    from kube_noob.cli import build_parser

    tokens = shlex.split(line)[1:]
    parser = build_parser()
    chain = ["kube-noob"]
    while tokens and not tokens[0].startswith("-"):
        children = _subparsers(parser)
        if tokens[0] not in children:
            break
        chain.append(tokens[0])
        parser = children[tokens.pop(0)]
    flags = {t for t in tokens if t.startswith("-") and t != "-" and not t[1:].isdigit()}
    known = _options(parser)
    unknown = sorted(f for f in flags if f not in known)
    assert not unknown, f"{where}: `{' '.join(chain)}` has no {', '.join(unknown)}"
    if _subparsers(parser) and len(chain) == 2:
        rest = [t for t in tokens if not t.startswith("-")]
        assert any(t in _subparsers(parser) for t in rest) or "--help" in flags, (
            f"{where}: `{' '.join(chain)}` needs a subcommand: {sorted(_subparsers(parser))}"
        )
