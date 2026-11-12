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

Since G276 the skills also DO something: each looks for the kube-noob CLI the user installed (`kube-noob`, then
`kubectl noob`, then a pinned `uvx` run), runs it through Claude's Bash tool with `--format json`, and reads the
verdict and the not-evaluated lists from the output. When no engine is there, the skill says so and gives one
install command; it never answers from its own knowledge as if a check had run. The plugin still ships Markdown and
JSON only, with no server, no script and no hook.
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
import sys
from dataclasses import dataclass
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


# A skill names the engine one of three ways, in the order it looks for it. Each is normalised to `kube-noob ...`
# before it is parsed, so a flag that is wrong after `kubectl noob` or after the uvx pin fails exactly like one after
# `kube-noob`.
_UVX = re.compile(r"^uvx --from kube-noob==(?P<v>\d+\.\d+\.\d+) kube-noob (?P<rest>.+)\Z")
_KUBECTL = "kubectl noob "


@dataclass(frozen=True)
class _Cmd:
    where: str  # file:line, for the failure message
    skill: str  # the skill folder the line is in, "" outside skills/
    line: str  # normalised to begin with `kube-noob `
    runs: bool  # in a ```bash block Claude runs it; in a bare ``` block it is a line for the user to run


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
                continue
            for raw in line.split("|"):
                segment = raw.strip()
                m = _UVX.match(segment)
                if m:
                    segment = "kube-noob " + m["rest"]
                elif segment.startswith(_KUBECTL):
                    segment = "kube-noob " + segment[len(_KUBECTL) :]
                if segment.startswith("kube-noob "):
                    out.append(_Cmd(f"{rel.as_posix()}:{n}", skill, segment, fence == "bash"))
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
    """A wrong flag in a skill is a wrong command in a terminal. Five of these were wrong when first written."""
    chain, flags, parser, tokens = _parse(cmd.line)
    unknown = sorted(f for f in flags if f not in _options(parser))
    assert not unknown, f"{cmd.where}: `kube-noob {' '.join(chain)}` has no {', '.join(unknown)}"
    if _subparsers(parser) and len(chain) == 1:
        rest = [t for t in tokens if not t.startswith("-")]
        assert any(t in _subparsers(parser) for t in rest) or "--help" in flags, (
            f"{cmd.where}: `kube-noob {' '.join(chain)}` needs a subcommand: {sorted(_subparsers(parser))}"
        )


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
    from kube_noob import __version__

    blocks = {
        p.parent.name: _section(p.read_text(), "## Run kube-noob first") for p in sorted(LITE.glob("skills/*/SKILL.md"))
    }
    assert len(set(blocks.values())) == 1, f"the engine check differs between skills: {sorted(blocks)}"
    block = next(iter(blocks.values()))
    order = [
        "```bash\nkube-noob --version\n```",
        "```bash\nkubectl noob --version\n```",
        f"```bash\nuvx --from kube-noob=={__version__} kube-noob --version\n```",
    ]
    at = [block.find(step) for step in order]
    assert all(i >= 0 for i in at) and at == sorted(at), "look for kube-noob, then kubectl noob, then the uvx pin"
    assert "kube-noob is not installed, so nothing has been audited" in block, "an absence must be said as one"
    assert f"```\npipx install kube-noob=={__version__}\n```" in block, "one install command when nothing is there"
    assert "not checked by kube-noob" in block, "knowledge without a run has to be labelled as such"


def test_every_skill_says_how_to_read_what_kube_noob_returns() -> None:
    blocks = {p: _section(p.read_text(), "## Reading what kube-noob returns") for p in LITE.glob("skills/*/SKILL.md")}
    assert len(set(blocks.values())) == 1, "the reading guide differs between skills"
    for p, block in sorted(blocks.items()):
        for word in ("undetermined", "notEvaluated", "assumptions", "unreadable", "skipped", "untrusted"):
            assert word in block, f"{p.relative_to(LITE)}: the reading guide never mentions `{word}`"


def test_the_pinned_release_is_this_release_and_the_bump_script_moves_it() -> None:
    """The uvx fallback and the install command pin a version, and bump_version.py has to move every one of them."""
    from kube_noob import __version__

    sys.path.insert(0, str(ROOT / "scripts"))
    import bump_version

    pinned: dict[str, set[str]] = {}
    for p in sorted(LITE.rglob("*.md")):
        found = set(re.findall(r"kube-noob==(\d+\.\d+\.\d+)", p.read_text()))
        if found:
            pinned[p.relative_to(ROOT).as_posix()] = found
    assert len(pinned) >= 7, "every skill pins the uvx fallback"
    assert all(v == {__version__} for v in pinned.values()), f"stale pins: {pinned}"
    untracked = sorted(set(pinned) - set(bump_version.TARGETS))
    assert not untracked, f"bump_version.py would leave these behind: {untracked}"


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
    for needle in ("kube-noob --version", "kubectl noob", "uvx", "PyPI", "no MCP server", "permission"):
        assert needle in text, f"the README does not disclose `{needle}`"
