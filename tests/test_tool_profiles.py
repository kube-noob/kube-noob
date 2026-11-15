"""MCP tool profiles: a client gets a named set of tools, and what is outside the set says so.

The server offers 54 tools. A client pays for every one of them in its context window before it calls any: the
``tools/list`` payload of the default server is about 74 KB. The project's own review called that breadth an
anti-moat, so ``kube-noob mcp --tools PROFILE`` narrows the surface to a named, tested set.

The defect this file exists to refuse is class 13 and class 15 of docs/review-classes.md: a tool left out of the
profile must not answer "unknown tool", because an absence that reads as "no such thing" sends a client (and the
person reading its transcript) looking for a capability kube-noob has. ``tools/list`` is the profile; a
``tools/call`` for a tool that exists and is merely outside it is an error that says so and names the profiles
that hold it.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from kube_noob import tool_profiles
from kube_noob.config import ConfigError, Settings, load_settings
from kube_noob.server.mcp_app import TOOL_PREFIX, build_server
from kube_noob.toolkit import Toolkit

ROOT = Path(__file__).resolve().parents[1]


def _rich() -> Settings:
    """Every optional surface on, so the profiles are checked against every tool that can exist."""
    s = Settings()
    s.cluster.enabled = True
    s.web_enabled = True
    s.rhacs.enabled = True
    s.memory.paths = [str(ROOT / "tests")]
    return s


def _names(settings: Settings) -> set[str]:
    return {spec.name for spec in Toolkit(settings).specs()}


def _listed(settings: Settings) -> set[str]:
    server = build_server(settings)
    return {t.name for t in asyncio.run(server.list_tools())}


# -- the profiles are a named set, not a prefix --------------------------------------------------------------


def test_the_profiles_are_named_sets_and_all_is_one_of_them() -> None:
    assert tool_profiles.ALL == "all"
    assert tool_profiles.ALL in tool_profiles.PROFILES
    assert set(tool_profiles.PROFILES) == {"all", "compliance", "incident", "learn", "review"}


def test_no_profile_is_a_prefix_match() -> None:
    """``cluster_*``, ``learn_*`` and ``posture_*`` each span more than one profile, so a prefix rule cannot
    express them: the membership is a literal name in a literal set."""
    assert "cluster_posture_scan" in tool_profiles.PROFILES["review"]
    assert "cluster_posture_scan" not in tool_profiles.PROFILES["incident"]
    assert "cluster_debug_workload" in tool_profiles.PROFILES["incident"]
    assert "cluster_debug_workload" not in tool_profiles.PROFILES["review"]


def test_every_tool_that_can_exist_is_in_at_least_one_named_profile() -> None:
    """A tool in no profile is reachable only by ``--tools all``, which is how a new tool quietly becomes
    unreachable for every profile user. Whoever adds a tool classifies it here."""
    named = set().union(*(v for k, v in tool_profiles.PROFILES.items() if k != tool_profiles.ALL))
    missing = sorted(_names(_rich()) - named)
    assert not missing, f"tools in no named profile: {missing}"


def test_no_profile_names_a_tool_that_does_not_exist() -> None:
    """The mirror: a renamed tool must not leave a dead name in a profile, which would silently shrink it."""
    everything = _names(_rich())
    for name, tools in tool_profiles.PROFILES.items():
        dead = sorted(t for t in tools if t not in everything)
        assert not dead, f"profile {name} names tools that no configuration offers: {dead}"


def test_every_profile_carries_the_three_tools_every_answer_needs() -> None:
    """``all`` holds everything by definition, so its set is empty in the table and ``select`` never reads it."""
    assert tool_profiles.PROFILES[tool_profiles.ALL] == frozenset()
    for name, tools in tool_profiles.PROFILES.items():
        if name == tool_profiles.ALL:
            continue
        assert {"config_status", "search_knowledge", "get_knowledge"} <= tools, name


def test_resolve_refuses_an_unknown_profile_and_names_the_ones_that_exist() -> None:
    with pytest.raises(ValueError) as err:
        tool_profiles.resolve("securuty")
    message = str(err.value)
    for name in tool_profiles.PROFILES:
        assert name in message, message
    assert "securuty" in message


def test_a_profile_name_is_taken_exactly_as_typed() -> None:
    for bad in ("All", " all", "all ", "incident,review", "incident*"):
        with pytest.raises(ValueError):
            tool_profiles.resolve(bad)


# -- tools/list is the profile -------------------------------------------------------------------------------


def test_all_is_the_default_and_lists_exactly_what_the_server_listed_before() -> None:
    settings = Settings()
    assert settings.server.tools == tool_profiles.ALL
    assert _listed(settings) == {TOOL_PREFIX + n for n in _names(settings)}


def test_a_profile_lists_its_own_set_and_nothing_else() -> None:
    for name in tool_profiles.PROFILES:
        settings = _rich()
        settings.server.tools = name
        expected = {TOOL_PREFIX + n for n in tool_profiles.select(name, _names(settings))}
        assert _listed(settings) == expected, name


def test_a_profile_is_the_intersection_with_what_this_configuration_offers() -> None:
    """``incident`` names the live-cluster tools; a server with cluster access off offers none of them, and the
    profile is what is left rather than a promise the server cannot keep."""
    settings = Settings()
    settings.server.tools = "incident"
    listed = _listed(settings)
    assert TOOL_PREFIX + "cluster_debug_workload" not in listed
    assert TOOL_PREFIX + "diagnose" in listed


def test_every_profile_is_smaller_than_all_and_big_enough_to_be_useful() -> None:
    settings = _rich()
    whole = len(_names(settings))
    for name in tool_profiles.PROFILES:
        if name == tool_profiles.ALL:
            continue
        held = len(tool_profiles.select(name, _names(settings)))
        assert 5 <= held < whole, f"{name}: {held} of {whole}"


# -- a tool outside the profile is not an unknown tool (class 13) ---------------------------------------------


def _call(settings: Settings, tool: str, args: dict[str, Any] | None = None) -> Any:
    server = build_server(settings)
    return asyncio.run(server.call_tool(TOOL_PREFIX + tool, args or {}))


def test_a_tool_outside_the_profile_is_refused_by_name_not_as_unknown() -> None:
    settings = Settings()
    settings.server.tools = "incident"
    with pytest.raises(ToolError) as err:
        _call(settings, "audit_manifests", {"manifests": "{}"})
    message = str(err.value)
    assert "unknown tool" not in message.lower()
    assert "kubenoob_audit_manifests" in message
    assert "incident" in message


def test_the_refusal_names_a_profile_that_does_hold_the_tool() -> None:
    settings = Settings()
    settings.server.tools = "learn"
    with pytest.raises(ToolError) as err:
        _call(settings, "fedramp_ksi", {})
    message = str(err.value)
    assert "compliance" in message, message
    assert "--tools" in message


def test_a_tool_no_configuration_offers_is_still_an_unknown_tool() -> None:
    settings = Settings()
    settings.server.tools = "incident"
    with pytest.raises(ToolError) as err:
        _call(settings, "no_such_tool_at_all", {})
    assert "no_such_tool_at_all" in str(err.value)


def test_a_tool_inside_the_profile_still_runs() -> None:
    settings = Settings()
    settings.server.tools = "incident"
    result = _call(settings, "config_status", {})
    assert not result.is_error, result.content


def test_under_all_nothing_is_refused_for_being_outside_a_profile() -> None:
    settings = Settings()
    result = _call(settings, "config_status", {})
    assert not result.is_error


# -- the server says which profile it is running -------------------------------------------------------------


def test_the_initialize_instructions_state_the_profile_and_its_size() -> None:
    settings = Settings()
    settings.server.tools = "compliance"
    server = build_server(settings)
    held = len(tool_profiles.select("compliance", _names(settings)))
    whole = len(_names(settings))
    assert f"Tool profile: compliance ({held} of {whole} tools" in (server.instructions or "")


def test_under_all_the_instructions_say_so_rather_than_saying_nothing() -> None:
    server = build_server(Settings())
    assert "Tool profile: all" in (server.instructions or "")
    assert "NOT offered under this profile" not in (server.instructions or "")


def test_the_instructions_name_the_tools_they_recommend_that_the_profile_withholds() -> None:
    """The instructions are prose that names about thirty tools ("start with kubenoob_insight"). Under a narrowed
    profile some are not registered, so the server's own first message would otherwise send a client to tools it
    cannot call -- the caveat living in tools/list and nowhere a model reads it (class 6)."""
    settings = Settings()
    settings.server.tools = "compliance"
    instructions = build_server(settings).instructions or ""
    assert "kubenoob_insight" in instructions.split("Tool profile:")[1]
    assert "NOT offered under this profile" in instructions
    assert "Do not call them" in instructions


def test_the_withheld_list_names_only_tools_this_configuration_really_has() -> None:
    """``kubenoob_learn_*`` and ``kubenoob_cluster_*`` appear in the instructions as globs, and a glob is not a
    tool: naming one would send a client after something that never existed."""
    settings = Settings()
    settings.server.tools = "compliance"
    tail = (build_server(settings).instructions or "").split("NOT offered under this profile:")[1]
    everything = {TOOL_PREFIX + n for n in _names(settings)}
    for word in tail.replace(",", " ").replace(".", " ").split():
        if word.startswith(TOOL_PREFIX):
            assert word in everything, word


# -- the setting, the flag and the refusal -------------------------------------------------------------------


def test_the_setting_refuses_an_unknown_profile_as_a_configuration_error() -> None:
    with pytest.raises(ConfigError) as err:
        load_settings(overrides={"server": {"tools": "everything"}})
    for name in tool_profiles.PROFILES:
        assert name in str(err.value)


def test_the_environment_variable_sets_the_profile(monkeypatch: pytest.MonkeyPatch) -> None:
    """A host that can set an environment variable but cannot pass a flag (a plugin's .mcp.json) still chooses."""
    monkeypatch.setenv("KUBE_NOOB_MCP_TOOLS", "review")
    assert load_settings().server.tools == "review"


def test_the_environment_variable_refuses_an_unknown_profile(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KUBE_NOOB_MCP_TOOLS", "evrything")
    with pytest.raises(ConfigError) as err:
        load_settings()
    assert "incident" in str(err.value)


@pytest.mark.parametrize("command", ["mcp", "serve"])
def test_the_command_exits_2_on_an_unknown_profile_and_names_the_profiles(command: str, capsys: Any) -> None:
    """Both front doors, not only the one the feature was asked for: a flag on one and not its sibling is how a
    fix lands on one surface and misses the other (docs/review-classes.md class 25)."""
    from kube_noob.cli import main

    assert main([command, "--tools", "securuty"]) == 2
    err = capsys.readouterr().err
    for name in tool_profiles.PROFILES:
        assert name in err, err


# -- the profile says what it left out (class 15) -------------------------------------------------------------


def test_config_status_names_the_profile_and_every_tool_outside_it() -> None:
    """A narrowed tools/list is a match tier. A tier that does not say what it excluded lets a client conclude
    kube-noob cannot do the excluded thing, so the one tool every profile carries says so, by name."""
    settings = Settings()
    settings.server.tools = "learn"
    status = json.loads(_call(settings, "config_status", {}).content[0].text)["tools"]
    assert status["profile"] == "learn"
    assert status["profiles"] == list(tool_profiles.NAMES)
    assert "audit_manifests" in status["outsideProfile"]
    assert "learn_quiz" in status["offered"]
    assert "--tools all" in status["outsideProfileNote"]
    assert set(status["offered"]) & set(status["outsideProfile"]) == set()
    assert set(status["offered"]) | set(status["outsideProfile"]) == _names(settings)


def test_under_all_config_status_says_nothing_is_outside_rather_than_an_empty_list_alone() -> None:
    status = json.loads(_call(Settings(), "config_status", {}).content[0].text)["tools"]
    assert status["outsideProfile"] == []
    assert "No tool" in status["outsideProfileNote"]


# -- the document is generated from the code -----------------------------------------------------------------


def test_the_document_and_the_code_agree() -> None:
    import scripts.tool_profiles_doc as doc

    assert doc.render() == (ROOT / "docs" / "mcp-tool-profiles.md").read_text(encoding="utf-8")


def test_the_document_names_every_tool_of_every_profile() -> None:
    text = (ROOT / "docs" / "mcp-tool-profiles.md").read_text(encoding="utf-8")
    for name, tools in tool_profiles.PROFILES.items():
        if name == tool_profiles.ALL:
            continue
        for tool in tools:
            assert TOOL_PREFIX + tool in text, f"{name}: {tool}"


# -- the REST surface is deliberately not narrowed ------------------------------------------------------------


def test_the_rest_routes_keep_every_tool_whatever_the_profile() -> None:
    """The documented difference, held by a test rather than left to be discovered. A REST route is one URL the
    caller already knows: it costs no context window, so narrowing it would take a capability away and buy
    nothing. docs/mcp-tool-profiles.md says this sentence, and this asserts both halves."""
    from mcp.server.transport_security import TransportSecuritySettings

    narrowed = Settings()
    narrowed.server.tools = "learn"
    paths = {r.path for r in build_server(narrowed, rest=TransportSecuritySettings())._custom_starlette_routes}
    whole = {r.path for r in build_server(Settings(), rest=TransportSecuritySettings())._custom_starlette_routes}
    assert paths == whole
    assert "/v1/audit" in paths
    assert "narrows the **MCP tool surface only**" in (ROOT / "docs" / "mcp-tool-profiles.md").read_text(
        encoding="utf-8"
    )


# -- the plugin's own copy ------------------------------------------------------------------------------------


def test_the_bundled_plugin_stays_on_all_because_its_skills_span_the_surface() -> None:
    """``plugin/kube-noob`` ships seven skills that name tools from three different profiles, so any narrower
    default would make those skills call tools their own server does not offer (class 13 again, one layer up)."""
    config = json.loads((ROOT / "plugin" / "kube-noob" / ".mcp.json").read_text(encoding="utf-8"))
    env = config["mcpServers"]["kube-noob"]["env"]
    assert env["KUBE_NOOB_MCP_TOOLS"] == tool_profiles.ALL
    named = set()
    for skill in (ROOT / "plugin" / "kube-noob" / "skills").rglob("*.md"):
        for word in skill.read_text(encoding="utf-8").split():
            token = word.strip("`.,:;()[]*\"'")
            if token.startswith(TOOL_PREFIX):
                named.add(token.removeprefix(TOOL_PREFIX))
    spanned = {p for p, tools in tool_profiles.PROFILES.items() if p != tool_profiles.ALL and named & tools}
    assert len(spanned) >= 3, spanned
    assert not any(named <= tools for p, tools in tool_profiles.PROFILES.items() if p != tool_profiles.ALL)
