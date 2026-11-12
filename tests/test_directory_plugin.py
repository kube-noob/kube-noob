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

Since G276 the skills also DO something: each looks for the kube-noob CLI the user installed (`kube-noob --version`),
runs it through Claude's Bash tool with `--format json` into a private folder, and reads the verdict and the
not-evaluated lists from the output. When no engine is there, the skill says so and gives one
install command; it never answers from its own knowledge as if a check had run. The plugin still ships Markdown and
JSON only, with no server, no script and no hook.
"""

from __future__ import annotations

import argparse
import io
import json
import re
import shlex
import sys
from contextlib import redirect_stderr
from dataclasses import dataclass
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
LITE = ROOT / "plugin" / "kube-noob-skills"
FULL = ROOT / "plugin" / "kube-noob"

# What the directory accepts from an organization that is not Verified, as the live check stated it on 2026-11-10:
# Markdown, text, JSON, YAML, and a PNG, JPEG, GIF, WebP or ICO image. A LICENSE, a README and the icon may stay.
# The published checklist (https://claude.com/docs/plugins/pre-submission-checklist, read 2026-11-12) admits text
# files and complete PNG, JPEG, GIF and WebP images, and holds "any other binary file, such as an `.ico`" for a
# reviewer. The 2026-11-10 live check named `.ico` as accepted; the stricter of the two is the one held here.
ALLOWED_SUFFIXES = {".md", ".txt", ".json", ".yaml", ".yml", ".png", ".jpg", ".jpeg", ".gif", ".webp"}
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

    The generated server copy under plugin/kube-noob/server is excluded: those URLs come from src/ and redirect, and
    G266 left redirecting forms alone on purpose. The directory does not render them.
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


# How a skill line names the engine: `kube-noob ...`, optionally after `VAR=value` assignments (the run form puts
# `KUBE_NOOB_FOR_MODEL=1 KUBE_NOOB_LEARNING_ENABLED=false` in front), and followed by redirections or `; echo ...`,
# which belong to the shell, not to kube-noob. Everything from the first `>`, `2>`, `;` or `&&` is cut before the
# line is parsed.
_ASSIGNMENT = re.compile(r"^[A-Z_][A-Z0-9_]*=\S*\Z")
_SHELL_TAIL = {">", "2>", ";", "&&", "||"}
# The placeholders a command line may carry, each explained in the skill text beside it. A token shaped like a
# placeholder that is not here is a value nobody declared, and it fails when the command runs.
PLACEHOLDERS = {"$KN", "INCIDENT_ID", "<name>", "<ns>"}
_PLACEHOLDER_SHAPE = re.compile(r"<[^>]+>|\A[A-Z][A-Z_]{2,}\Z")


@dataclass(frozen=True)
class _Cmd:
    where: str  # file:line, for the failure message
    skill: str  # the skill folder the line is in, "" outside skills/
    line: str  # normalised: begins with `kube-noob `, shell tail removed
    runs: bool  # in a ```bash block Claude runs it; in a bare ``` block it is a line for the user to run
    inline: bool = False  # an inline `kube-noob ...` span in prose: often a partial command, so flags only


def _normalise(segment: str) -> str | None:
    try:
        tokens = shlex.split(segment)
    except ValueError:
        return None
    while tokens and _ASSIGNMENT.match(tokens[0]):
        tokens.pop(0)
    if not tokens or tokens[0] != "kube-noob" or len(tokens) < 2:
        return None
    kept: list[str] = []
    for t in tokens:
        if t in _SHELL_TAIL or t.startswith(">") or t.startswith("2>"):
            break
        kept.append(t)
    return shlex.join(kept)


def _commands() -> list[_Cmd]:
    out: list[_Cmd] = []
    for p in sorted(LITE.rglob("*.md")):
        rel = p.relative_to(LITE)
        skill = rel.parts[1] if rel.parts[0] == "skills" and len(rel.parts) > 2 else ""
        fence: str | None = None
        for n, line in enumerate(p.read_text().splitlines(), 1):
            if line.startswith("```"):
                fence = line[3:].strip() if fence is None else None
                continue
            if fence is None:
                for span in re.findall(r"`([^`]+)`", line):
                    norm = _normalise(span)
                    if norm is not None:
                        out.append(_Cmd(f"{rel.as_posix()}:{n}", skill, norm, False, inline=True))
                continue
            for raw in line.split("|"):
                norm = _normalise(raw.strip())
                if norm is not None:
                    out.append(_Cmd(f"{rel.as_posix()}:{n}", skill, norm, fence == "bash"))
    return out


def _parse(line: str) -> tuple[list[str], set[str], argparse.ArgumentParser, list[str]]:
    """The subcommand chain, the flags, the parser the flags belong to and the tokens after the chain."""
    from kube_noob.cli import build_parser

    tokens = shlex.split(line)[1:]
    parser = build_parser()
    chain: list[str] = []
    while tokens and not tokens[0].startswith("-"):
        children = _subparsers(parser)
        if tokens[0] not in children:
            break
        chain.append(tokens[0])
        parser = children[tokens.pop(0)]
    flags = {t for t in tokens if t.startswith("-") and t != "-" and not t[1:].isdigit()}
    return chain, flags, parser, tokens


def test_every_skill_runs_at_least_one_command() -> None:
    """If this finds nothing, the checks below are measuring nothing."""
    skills = {p.parent.name for p in LITE.glob("skills/*/SKILL.md")}
    with_runs = {c.skill for c in _commands() if c.runs}
    assert skills and with_runs >= skills, f"skills that run no kube-noob command: {sorted(skills - with_runs)}"


@pytest.mark.parametrize("cmd", _commands(), ids=lambda c: c.where)
def test_every_command_a_skill_hands_the_user_is_one_the_cli_accepts(cmd: _Cmd) -> None:
    """A wrong flag in a skill is a wrong command in a terminal. Five of these were wrong when first written. A fenced
    command must also PARSE: required arguments, choices and positional order, which a flag check never saw."""
    from kube_noob.cli import build_parser

    chain, flags, parser, _ = _parse(cmd.line)
    unknown = sorted(f for f in flags if f not in _options(parser))
    assert not unknown, f"{cmd.where}: `kube-noob {' '.join(chain)}` has no {', '.join(unknown)}"
    if cmd.inline or flags & {"--version", "--help"}:
        return
    for t in shlex.split(cmd.line):
        if "$" in t:
            assert t.startswith("$KN/") or t == "$KN", f"{cmd.where}: `{t}` is not a declared placeholder"
        for shape in _PLACEHOLDER_SHAPE.findall(t):
            assert shape in PLACEHOLDERS, f"{cmd.where}: `{shape}` looks like a placeholder nobody declared"
    err = io.StringIO()
    try:
        with redirect_stderr(err):
            build_parser().parse_args(shlex.split(cmd.line)[1:])
    except SystemExit as exc:
        raise AssertionError(f"{cmd.where}: `{cmd.line}` does not parse: {err.getvalue().strip()[-300:]}") from exc


def test_every_declared_placeholder_is_explained_where_it_is_used() -> None:
    text = "\n".join(p.read_text() for p in LITE.rglob("*.md"))
    for name in PLACEHOLDERS:
        if name in text:
            assert f"`{name}` stands for" in text or name in {"<name>", "<ns>"}, f"{name} is used and never explained"


# --- the directory plugin drives the CLI the user installed (G276) ------------------------------------------------
#
# Every MCP tool the seven full skills call, and the CLI command a directory skill runs in its place. A tool with no
# CLI command, or one this plugin deliberately does not run, is in _DROPPED with the reason, so a tool added to a full
# skill fails here until someone decides which it is.
_TOOL_COMMANDS: dict[str, str] = {
    "audit_manifests": "audit",
    "validate_manifests": "validate",
    "red_team": "redteam",
    "fix_manifests": "fix",
    "run_protocol": "protocol",
    "clarify_requirements": "protocol",  # `protocol --blueprint` returns status needs-clarification and the questions
    "generate_manifests": "generate",
    "generate_helm_chart": "helm-chart",
    "search_knowledge": "search",
    "learning_summary": "learning show",
    "learning_profile_set": "learning profile",
    "insight": "insight",
    "diagnose": "diagnose",
    "extract_signals": "signals",
    "known_issues": "known-issues",
    "ticket": "ticket",
    "ticket_changes": "corpus jira-changes",
    "explain_denial": "policy explain",
    "check_network_policy": "policy reach",
    "incidents": "incidents list",
    "incident_confirm": "incidents confirm",
    "config_status": "config",
    "learn_tracks": "learn tracks",
    "learn_lesson": "learn lesson",
    "learn_exercise": "learn exercise",
    "learn_submit": "learn submit",
    "learn_quiz": "learn quiz",
    "policy_generate": "policy generate",
    "posture_scan": "posture scan",
    "rhacs_compare": "rhacs compare",
    "build_diagnose": "build diagnose",
    "vuln_report": "vuln report",
    "threat_model": "vuln threat",
}
_DROPPED: dict[str, str] = {
    "api_history": "no CLI command returns the removed-API table on its own; the version map stays in the skill as "
    "knowledge, and `validate --version` reports a removed API for a manifest",
    "cluster_check_traffic": "reads the live cluster; this plugin never turns cluster access on",
    "cluster_debug_workload": "reads the live cluster; this plugin never turns cluster access on",
    "memory_propose": "writes an entry into the team's memory repository; the full plugin writes only from its stdio "
    "server after the user confirms, and the directory skills do not write into a repository",
}

# Flags and subcommands that would reach a network, a cluster or a model, or start a server. A command Claude runs
# carries none of them; the user may still be handed one in a bare block, as their own decision.
_NOT_OFFLINE_FLAGS = {"--web-enabled", "--cluster-enabled", "--live", "--online", "--allow-unauthenticated"}
_NOT_OFFLINE_COMMANDS = {"serve", "mcp", "watch", "ask", "debug", "bundle", "admission", "train"}


def _full_tools() -> dict[str, set[str]]:
    return {
        p.parent.name: set(re.findall(r"kubenoob_([a-z][a-z_]*[a-z])", p.read_text()))
        for p in sorted(FULL.glob("skills/*/SKILL.md"))
    }


def test_every_tool_the_full_skills_call_is_run_here_or_dropped_with_a_reason() -> None:
    called = set().union(*_full_tools().values())
    assert called, "found no kubenoob_ tool in plugin/kube-noob/skills; this test is measuring nothing"
    assert not set(_TOOL_COMMANDS) & set(_DROPPED), "a tool cannot be both run and dropped"
    unaccounted = called - set(_TOOL_COMMANDS) - set(_DROPPED)
    assert not unaccounted, f"decide a CLI command or a stated reason for: {sorted(unaccounted)}"
    stale = (set(_TOOL_COMMANDS) | set(_DROPPED)) - called
    assert not stale, f"no full skill calls these any more: {sorted(stale)}"
    assert all(reason.strip() for reason in _DROPPED.values())


@pytest.mark.parametrize("tool,command", sorted(_TOOL_COMMANDS.items()))
def test_every_mapped_command_is_a_real_cli_command(tool: str, command: str) -> None:
    chain, _, _, _ = _parse(f"kube-noob {command}")
    assert chain == command.split(), f"{tool}: `kube-noob {command}` is not a command the CLI has"


@pytest.mark.parametrize("skill", sorted(_full_tools()))
def test_each_directory_skill_runs_what_its_full_counterpart_called_a_tool_for(skill: str) -> None:
    """The point of the item: a directory install can run what the full plugin's skill would have run."""
    want = {_TOOL_COMMANDS[t] for t in _full_tools()[skill] if t in _TOOL_COMMANDS}
    runs = {" ".join(_parse(c.line)[0]) for c in _commands() if c.skill == skill and c.runs}
    missing = sorted(want - runs)
    assert not missing, f"skills/{skill} does not run: {', '.join('kube-noob ' + m for m in missing)}"


def test_no_command_a_skill_runs_reaches_a_network_a_cluster_or_a_model() -> None:
    bad: list[str] = []
    for c in _commands():
        if not c.runs:
            continue
        chain, flags, _, _ = _parse(c.line)
        if flags & _NOT_OFFLINE_FLAGS or (chain and chain[0] in _NOT_OFFLINE_COMMANDS):
            bad.append(f"{c.where}: {c.line}")
    assert not bad, "a command Claude runs from this plugin has to stay offline and off the cluster:\n" + "\n".join(bad)


def test_every_command_a_skill_runs_asks_for_json() -> None:
    """The verdict and the not-evaluated lists are read from the JSON, so every run has to ask for it."""
    bad: list[str] = []
    for c in _commands():
        if not c.runs:
            continue
        _, flags, _, tokens = _parse(c.line)
        if flags & {"--version", "--help"}:
            continue
        i = tokens.index("--format") if "--format" in tokens else -1
        if i < 0 or tokens[i + 1 : i + 2] != ["json"]:
            bad.append(f"{c.where}: {c.line}")
    assert not bad, "run these with --format json:\n" + "\n".join(bad)


def _section(text: str, heading: str) -> str:
    start = text.find(f"\n{heading}\n")
    assert start >= 0, f"no `{heading}` section"
    end = text.find("\n## ", start + len(heading) + 2)
    return text[start : end if end >= 0 else len(text)]


def test_every_skill_looks_for_the_engine_the_same_way_before_it_answers() -> None:
    """The presence check is the guard against an absence read as a pass, so it is the same text in every skill."""

    blocks = {
        p.parent.name: _section(p.read_text(), "## Run kube-noob first") for p in sorted(LITE.glob("skills/*/SKILL.md"))
    }
    assert len(set(blocks.values())) == 1, f"the engine check differs between skills: {sorted(blocks)}"
    block = next(iter(blocks.values()))
    assert "```bash\nkube-noob --version\n```" in block, "the presence check is one command the user can read"
    assert "kube-noob is not installed, so nothing has been audited" in block, "an absence must be said as one"
    assert f"```\npipx install 'kube-noob>={MIN_ENGINE}'\n```" in block, "one install command when nothing is there"
    assert "this kube-noob is older than these skills need, so nothing has been audited" in block
    assert "```\npipx upgrade kube-noob\n```" in block
    assert "not checked by kube-noob" in block, "knowledge without a run has to be labelled as such"


def test_every_skill_says_how_to_read_what_kube_noob_returns() -> None:
    blocks = {p: _section(p.read_text(), "## Reading what kube-noob returns") for p in LITE.glob("skills/*/SKILL.md")}
    assert len(set(blocks.values())) == 1, "the reading guide differs between skills"
    for p, block in sorted(blocks.items()):
        for word in ("undetermined", "notEvaluated", "assumptions", "unreadable", "skipped", "untrusted"):
            assert word in block, f"{p.relative_to(LITE)}: the reading guide never mentions `{word}`"


# The first release with what the skills rely on: KUBE_NOOB_FOR_MODEL, exit 4 for a crash, `undecided`, one JSON
# document from `helm-audit`, `fix -o` JSON. A fixed fact about the engine, so the bump script does not move it.
MIN_ENGINE = "0.9.3"


def test_the_skills_require_the_release_that_has_what_they_rely_on() -> None:
    """Written for 0.9.2 they would have read an engine that cleans nothing and exits 1 on a crash (second review)."""
    from packaging.version import Version

    sys.path.insert(0, str(ROOT / "scripts"))
    import bump_version

    named: set[str] = set()
    for p in sorted(LITE.rglob("*.md")):
        text = p.read_text()
        assert "kube-noob==" not in text, f"{p.relative_to(LITE)} pins one release; the skills need a minimum"
        named |= set(re.findall(r"kube-noob>=(\d+\.\d+\.\d+)", text))
        assert p.relative_to(ROOT).as_posix() not in bump_version.TARGETS
    assert named == {MIN_ENGINE} and Version(MIN_ENGINE) > Version("0.9.2")


def test_an_older_engine_is_named_as_older_and_not_read(tmp_path: Path) -> None:
    """A fake 0.9.2 on the PATH: the rule the skills give, applied to what it prints, says it is too old."""
    import subprocess

    from packaging.version import Version

    fake = tmp_path / "kube-noob"
    fake.write_text("#!/bin/sh\necho 'kube-noob 0.9.2'\n")
    fake.chmod(0o755)
    printed = subprocess.run([str(fake), "--version"], capture_output=True, text=True, check=True).stdout
    block = _section(_first_skill(), "## Run kube-noob first")
    stated = re.search(r"need \*\*kube-noob (\d+\.\d+\.\d+) or later\*\*", block)
    assert stated and stated.group(1) == MIN_ENGINE
    assert Version(printed.split()[1]) < Version(stated.group(1))
    assert "If the\nversion it printed is lower than 0.9.3" in block or "lower than 0.9.3" in block
    assert "first key is not `forModel`" in block


def test_no_skill_runs_a_command_as_it_loads() -> None:
    """A `!`cmd`` line runs before Claude reads the skill, needs a permission grant and aborts the skill when it fails,
    and the directory's validator follows it as code. The presence check is an instruction instead."""
    bad = [
        f"{p.relative_to(LITE).as_posix()}:{n}"
        for p in sorted(LITE.rglob("*.md"))
        for n, line in enumerate(p.read_text().splitlines(), 1)
        if re.search(r"(^|\s)!`", line) or line.startswith("```!")
    ]
    assert not bad, "\n".join(bad)


def test_no_file_names_an_mcp_tool_the_plugin_cannot_reach() -> None:
    """The plugin declares no server, so a `kubenoob_` name in any file it ships is a tool that is not there."""
    assert "mcpServers" not in json.loads((LITE / ".claude-plugin" / "plugin.json").read_text())
    assert not (LITE / ".mcp.json").exists()
    bad = [
        f"{p.relative_to(LITE).as_posix()}:{n}"
        for p in _files()
        if p.suffix.lower() in {".md", ".json", ".txt", ".yaml", ".yml"}
        for n, line in enumerate(p.read_text().splitlines(), 1)
        if "kubenoob_" in line
    ]
    assert not bad, "\n".join(bad)


def test_the_readme_says_what_the_skills_run_and_fetch() -> None:
    """The directory's security scan looks for behaviour the README does not disclose."""
    text = (LITE / "README.md").read_text()
    for needle in (
        "kube-noob --version",
        "no MCP server",
        "permission",
        "KUBE_NOOB_FOR_MODEL",
        "KUBE_NOOB_LEARNING_ENABLED",
        "mktemp",
        "helm-audit",
        "build audit",
        "must-gather analyze",
        "learning show",
        "incidents list",
    ):
        assert needle in text, f"the README does not disclose `{needle}`"


def _fenced(text: str) -> list[tuple[str, str]]:
    """(info string, body) of every fenced block."""
    return re.findall(r"^```([^\n]*)\n(.*?)^```", text, flags=re.M | re.S)


def test_no_pasted_text_goes_through_a_heredoc_or_a_fixed_temporary_path() -> None:
    """A fixed heredoc delimiter let pasted text end the heredoc and run the next line as a command, and fixed
    `/tmp/kn-*` paths were shared between sessions, followed planted links and stayed world-readable (G276)."""
    bad: list[str] = []
    for p in sorted(LITE.rglob("*.md")):
        text = p.read_text()
        for info, body in _fenced(text):
            if "<<" in body:
                bad.append(f"{p.relative_to(LITE)}: a heredoc or here-string in a ``` {info} block")
            # The neighbours of a heredoc: any shell command that builds a file from text it was handed.
            for builder in ("printf", "tee ", "cat >", 'echo "$', "echo '"):
                if builder in body:
                    bad.append(f"{p.relative_to(LITE)}: `{builder.strip()}` builds a file from text in a block")
        if re.search(r"/tmp/(?!kube-noob\.XXXXXX)", text.replace("${TMPDIR:-/tmp}/kube-noob.XXXXXX", "")):
            bad.append(f"{p.relative_to(LITE)}: a fixed path under /tmp")
        if "KN_EOF" in text:
            bad.append(f"{p.relative_to(LITE)}: a fixed heredoc delimiter")
    assert not bad, "\n".join(bad)


def _first_skill() -> str:
    return (LITE / "skills" / "kube-debugging" / "SKILL.md").read_text()


def test_every_skill_makes_a_private_folder_writes_with_the_file_tool_and_removes_it() -> None:
    block = _section(_first_skill(), "## Run kube-noob first")
    assert '```bash\numask 077 && mktemp -d "${TMPDIR:-/tmp}/kube-noob.XXXXXX"\n```' in block
    assert "`$KN` stands for" in block
    assert "file-writing tool" in block and "never through `echo`" in block
    assert '```bash\ntest -s "$KN/input.txt" && echo written\n```' in block
    assert '```bash\nrm -rf "$KN"\n```' in block


RUN_FORM = (
    'KUBE_NOOB_FOR_MODEL=1 KUBE_NOOB_LEARNING_ENABLED=false kube-noob audit -f "$KN/app.yaml" --format json '
    '> "$KN/out.json" 2> "$KN/err.txt"; echo "exit $?"'
)


def test_every_command_runs_into_a_file_with_its_exit_code_and_the_model_mode() -> None:
    """Output to a file because a long result is cut in a tool's output and the not-read keys can be at its end; the
    exit printed because without it a crash and a result look alike; the two variables because the CLI's JSON is not
    cleaned for a model without the first and writes counters to the data folder without the second."""
    block = _section(_first_skill(), "## Run kube-noob first")
    assert f"```bash\n{RUN_FORM}\n```" in block
    no_shell = [b for i, b in _fenced(block) if i == "" and "kube-noob audit" in b]
    assert no_shell and 'echo "exit $code"' in no_shell[0], "the no-shell form has to report the exit code too"


def test_the_reading_guide_says_what_is_not_a_result() -> None:
    guide = _section(_first_skill(), "## Reading what kube-noob returns")
    for words in (
        "exit 0 or 1 with one complete JSON document",
        "Exit 0 means the command ran",
        "3 (clarification",
        "127",
        "141",
        "killed",
        "`rm -f",
        "nothing was cleaned",
        "older than these skills need",
    ):
        assert words in guide or words in _section(_first_skill(), "## Run kube-noob first"), words


def test_the_plugin_names_no_package_launcher_and_no_engine_that_fetches_one() -> None:
    """The checklist's "Choices a reviewer always checks" holds any pinned launcher (`Runs a pinned npx or uvx
    package`), and `kubectl noob` with no kube-noob on the PATH runs exactly that through `uvx`. The engine is the one
    the user installed."""
    launchers = re.compile(r"\b(uvx|npx|bunx|pipx run|uv run|uv tool run|pnpm dlx|yarn dlx)\b")
    bad = [
        f"{p.relative_to(LITE).as_posix()}:{n}"
        for p in _files()
        if p.suffix.lower() in {".md", ".json"}
        for n, line in enumerate(p.read_text().splitlines(), 1)
        if launchers.search(line)
    ]
    assert not bad, "\n".join(bad)
    assert not [c for c in _commands() if c.runs and "kubectl" in c.line]


def test_the_icon_is_at_the_plugin_root() -> None:
    """The manifest reference: "Put every other plugin file at the plugin root, not inside `.claude-plugin/`"."""
    manifest = json.loads((LITE / ".claude-plugin" / "plugin.json").read_text())
    icon = manifest["icon"]
    assert icon.startswith("./") and not icon.startswith("./.claude-plugin/"), icon
    assert (LITE / icon).is_file()
    assert [p.name for p in (LITE / ".claude-plugin").iterdir()] == ["plugin.json"]


# --- every command's table row is checked against the command's real output -------------------------------------

_VOCABULARY = re.compile(
    r"\A(assumptions|unreadable|notEvaluated|notRead|notChecked|unparsed|coverage|skipped|excluded|notShipped|"
    r"limitations|withheld|secretsIgnored|openQuestions|note|notes|causeNote|unexplained|undeterminedBy)\Z"
)


@dataclass(frozen=True)
class _Row:
    where: str
    command: str
    exit: str
    fields: tuple[str, ...]  # verdict and not-evaluated fields named; a trailing `?` marks one that may be absent


def _rows() -> list[_Row]:
    rows: list[_Row] = []
    for p in sorted(LITE.glob("skills/*/SKILL.md")):
        for line in _section(p.read_text(), "## Which command").splitlines():
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if len(cells) != 4 or not cells[0].startswith("`"):
                continue
            fields = tuple(re.findall(r"`([A-Za-z]+\??)`", cells[2] + " " + cells[3]))
            rows.append(_Row(p.parent.name, cells[0].strip("`"), cells[1], fields))
    return rows


def _fixture_argv(command: str, tmp: Path) -> list[str]:
    """A real input for each command a table names, from the repository's own fixtures."""
    import subprocess

    ex = str(ROOT / "examples" / "insecure-deployment.yaml")
    eg = ROOT / "examples"
    fx = ROOT / "tests" / "fixtures"
    first = command.split(maxsplit=1)[0]
    if first in {"vuln", "code", "must-gather"}:
        subprocess.run([sys.executable, str(fx / first / "generate.py"), str(tmp / first)], check=True)
    table: dict[str, list[str]] = {
        "audit": ["audit", "-f", ex],
        "validate": ["validate", "-f", ex],
        "redteam": ["redteam", "-f", ex],
        "fix": ["fix", "-f", ex, "-o", str(tmp / "fixed.yaml")],
        "protocol": ["protocol", "review", "-f", ex],
        "generate": ["generate", "--blueprint", str(eg / "blueprint.yaml"), "-o", str(tmp / "g.yaml")],
        "helm-chart": ["helm-chart", "--blueprint", str(eg / "blueprint.yaml"), "-o", str(tmp / "ch")],
        "search": ["search", "restricted-v2"],
        "learning show": ["learning", "show"],
        "insight": ["insight", "-f", str(eg / "events-scc.txt")],
        "incidents list": ["incidents", "list"],
        "diagnose": ["diagnose", "-f", str(eg / "events-crashloop.txt")],
        "signals": ["signals", "-f", str(eg / "events-crashloop.txt")],
        "known-issues": ["known-issues", "-f", str(eg / "events-crashloop.txt"), "--version", "4.20.8"],
        "ticket": ["ticket", "OCPBUGS-1"],
        "corpus jira-changes": ["corpus", "jira-changes", "--since", "1d"],
        "policy explain": ["policy", "explain", "-f", str(eg / "denial-multi.txt")],
        "policy reach": [
            *("policy", "reach", "-f", str(eg / "netpol-shop.yaml")),
            *("--from", "web/frontend", "--to", "shop/orders-api", "--port", "8080"),
        ],
        "config": ["config"],
        "learn tracks": ["learn", "tracks"],
        "learn lesson": ["learn", "lesson", "k8s-102-security"],
        "learn exercise": ["learn", "exercise", "k8s-ex-hardened-deployment"],
        "learn submit": ["learn", "submit", "k8s-ex-hardened-deployment", "-f", str(eg / "exercise-answer.yaml")],
        "learn quiz": ["learn", "quiz", "k8s-q-exit137"],
        "policy generate": ["policy", "generate", "--mode", "audit", "-o", str(tmp / "p.yaml")],
        "posture scan": ["posture", "scan", "-f", ex],
        "rhacs compare": ["rhacs", "compare", "-f", str(fx / "rhacs" / "default-policies-export.json")],
        "build diagnose": ["build", "diagnose", "-f", str(fx / "build_logs" / "03-github-actions-compile.log")],
        "build audit": [
            *("build", "audit", "-f", str(fx / "containerfile" / "KN-B001.bad.Containerfile")),
            *("--context", str(fx / "containerfile")),
        ],
        "vuln report": ["vuln", "report", "-r", str(tmp / "vuln" / "trivy.json"), "-m", str(fx / "vuln" / "shop.yaml")],
        "vuln threat": ["vuln", "threat", "-f", str(fx / "vuln" / "shop.yaml")],
        "code report": [
            *("code", "report", "-s", str(tmp / "code" / "semgrep.sarif")),
            *("--repo", str(tmp / "code" / "repo"), "-m", str(fx / "code" / "shop.yaml")),
        ],
        "must-gather analyze": ["must-gather", "analyze", str(tmp / "must-gather")],
    }
    assert command in table, f"no fixture for `{command}`; add one to _fixture_argv"
    return table[command]


def test_every_command_a_skill_runs_has_a_table_row_and_every_row_a_command() -> None:
    rows = {(r.where, r.command) for r in _rows()}
    assert len(rows) >= 30, "the tables were not found; this test is measuring nothing"
    untabled = {"learning profile", "incidents confirm"}  # writes the user asked for, explained in the prose
    runs = {(c.skill, " ".join(_parse(c.line)[0])) for c in _commands() if c.runs and c.skill}
    runs = {(s, c) for s, c in runs if c and c not in untabled}
    # The run form in the shared block shows `audit` as its example; it is not a command that skill chose.
    example = _normalise(RUN_FORM)
    shown = {(c.skill, "audit") for c in _commands() if c.runs and c.line == example}
    runs = (runs - shown) | {(s, c) for s, c in runs & shown if (s, c) in rows}
    assert not runs - rows, f"run but not in the skill's table: {sorted(runs - rows)}"
    assert not rows - runs, f"in a table, never run: {sorted(rows - runs)}"


@pytest.mark.parametrize("row", _rows(), ids=lambda r: f"{r.where}:{r.command}")
def test_each_table_row_matches_what_the_command_really_prints(
    row: _Row, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every field the row names is in the output (unless marked `?`), every key in the output that says what was not
    read is named by the row, and an `always 0` row exits 0 on the fixture (G276)."""
    import os
    from contextlib import redirect_stdout

    from kube_noob import cli

    monkeypatch.setenv("KUBE_NOOB_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("KUBE_NOOB_LEARNING_ENABLED", "false")
    monkeypatch.setenv("KUBE_NOOB_FOR_MODEL", "1")
    monkeypatch.delenv("KUBE_NOOB_CONFIG", raising=False)
    if row.command == "helm-audit":
        chart = tmp_path / "chart"
        chart.mkdir()
        (chart / "Chart.yaml").write_text("apiVersion: v2\nname: web\nversion: 0.1.0\n")
        helm = tmp_path / "bin" / "helm"
        helm.parent.mkdir()
        helm.write_text(f"#!/bin/sh\ncat '{ROOT / 'examples' / 'insecure-deployment.yaml'}'\n")
        helm.chmod(0o755)
        monkeypatch.setenv("PATH", f"{helm.parent}{os.pathsep}{os.environ['PATH']}")
        argv = ["helm-audit", str(chart)]
    else:
        argv = _fixture_argv(row.command, tmp_path)
    out = io.StringIO()
    with redirect_stdout(out), redirect_stderr(io.StringIO()):
        rc = cli.main([*argv, "--format", "json"])
    doc = json.loads(out.getvalue())
    keys = set(doc)
    required = {f for f in row.fields if not f.endswith("?")}
    named = {f.rstrip("?") for f in row.fields}
    assert not required - keys, f"{row.where}: `{row.command}` prints no {sorted(required - keys)}; has {sorted(keys)}"
    unnamed = sorted(k for k in keys if _VOCABULARY.match(k) and k not in named)
    assert not unnamed, f"{row.where}: `{row.command}` reports what it did not read in {unnamed}; the row omits them"
    if row.exit.startswith("always 0"):
        assert rc == 0, f"{row.where}: the row says always 0; `{row.command}` exited {rc}"


def test_words_written_on_a_command_line_are_single_quoted_and_cannot_run(tmp_path: Path) -> None:
    """Double quotes still expand `$(...)` and backticks, so a phrase in them could run a command (second review,
    G276). Every argument a skill quotes is a `$KN` path in double quotes or a phrase in single quotes, and a
    hostile phrase dropped into the documented form runs nothing."""
    import subprocess

    lines = [
        line
        for p in sorted(LITE.rglob("*.md"))
        for info, body in _fenced(p.read_text())
        for line in body.splitlines()
        if "kube-noob " in line
    ]
    assert lines
    for line in lines:
        head = re.split(r" > | 2> |; ", line)[0]
        for quoted in re.findall(r'"([^"]*)"', head):
            assert quoted.startswith("$KN") or quoted.startswith("${TMPDIR"), f"double-quoted word in: {line}"
    phrased = [ln for ln in lines if re.search(r"kube-noob (search|protocol) '", ln)]
    assert phrased, "the search and protocol forms are what this test is about"
    marker = tmp_path / "pwned"
    for line in phrased:
        hostile = re.sub(r"'[^']*'", f"'$(touch {marker})`touch {marker}`'", line, count=1)
        shell = hostile.replace("kube-noob ", "true ", 1).replace("$KN", str(tmp_path))
        subprocess.run(["bash", "-c", shell], check=False, capture_output=True)  # noqa: S607 -- the shell under test
        assert not marker.exists(), f"a phrase ran as a command in: {line}"
