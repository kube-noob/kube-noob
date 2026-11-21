"""A tool profile may hide a tool from a client. It may not hide one from the model's knowledge of what exists.

The product rule applied to the tool surface: a tool a profile withheld must read as withheld, never as a tool
kube-noob does not have. A model that cannot see ``kubenoob_fedramp_ksi`` and is not told why answers the question
from its own knowledge, and the user reads an unaudited answer in a session that looked audited.
"""

from __future__ import annotations

import ast
import inspect
import re
from pathlib import Path

import pytest

from kube_noob.cli import main
from kube_noob.config import Settings, load_settings
from kube_noob.server import tool_profiles as tp
from kube_noob.server.mcp_app import TOOL_PREFIX, build_server
from kube_noob.toolkit import Toolkit


def _every_tool_name() -> frozenset[str]:
    """Every name `Toolkit` can ever register, read from the source rather than from one configuration.

    A tool can be gated behind a capability tier or behind a configured endpoint (`rhacs_compare_live` needs an
    RHACS address, not just `cluster.enabled`), so no single `load_settings` produces the whole surface, and a
    universe built from one would call a perfectly real name a typo.
    """
    tree = ast.parse(Path(inspect.getfile(Toolkit)).read_text(encoding="utf-8"))
    names = {
        node.args[0].value
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "ToolSpec"
        and node.args
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
    }
    return frozenset(names)


def test_every_tool_is_reachable_through_some_profile() -> None:
    """A tool in no profile is a tool only `--tools all` can ever offer.

    That is not a false pass by itself, but it is how one starts: someone adds a tool, no profile carries it, and a
    caller who uses a profile never learns it exists. The sum of the profiles has to cover the surface.
    """
    offered = {s.name for s in Toolkit(load_settings(None)).specs()}
    covered: frozenset[str] = frozenset().union(*tp.PROFILES.values())
    assert sorted(offered - covered) == [], "tools no profile carries; add each to the profile whose job it serves"


def test_no_profile_names_a_tool_that_does_not_exist() -> None:
    """A typo in a profile set is silent: the name matches nothing, so the profile is quietly smaller.

    This caught `tutor` while the profiles were being written -- an MCP *prompt*, not a tool, so `learn` would have
    offered ten tools while its author believed it offered eleven.
    """
    real = _every_tool_name()
    assert real, "no tool names could be read; the rest of this test would pass vacuously"
    for name, members in sorted(tp.PROFILES.items()):
        unknown = sorted(m for m in members if m not in real)
        assert unknown == [], f"profile {name!r} names tools that do not exist: {unknown}"


def test_all_offers_exactly_what_the_configuration_allows(settings: Settings) -> None:
    specs = Toolkit(settings).specs()
    keep, withheld = tp.select(specs, (tp.ALL,))
    assert [s.name for s in keep] == [s.name for s in specs]
    assert withheld == []


def test_a_profile_withholds_the_rest_and_says_which(settings: Settings) -> None:
    specs = Toolkit(settings).specs()
    keep, withheld = tp.select(specs, ("compliance",))
    names = {s.name for s in keep}
    assert "fedramp_ksi" in names and "diagnose" not in names
    # The two sets partition the surface: nothing is both offered and withheld, nothing is neither.
    assert names | set(withheld) == {s.name for s in specs}
    assert not names & set(withheld)
    assert len(names) < len(specs), "a profile that withholds nothing is not a profile"


def test_a_withheld_tool_is_named_in_the_instructions(settings: Settings) -> None:
    """The one thing that keeps a profile from being a false pass."""
    server = build_server(settings, profiles=("compliance",))
    instructions = server.instructions or ""
    _, withheld = tp.select(Toolkit(settings).specs(), ("compliance",))
    assert withheld, "nothing was withheld, so this test proves nothing"
    for name in withheld:
        assert TOOL_PREFIX + name in instructions, f"{name} was withheld and the model is not told it exists"
    assert "NOT offering them" in instructions
    assert "never say kube-noob cannot do it" in instructions.lower()


def test_the_prose_never_recommends_a_tool_the_server_does_not_list(settings: Settings) -> None:
    """Review class 9, two sources of truth: the hand-written instructions name tools, and the registered tool list
    decides what exists. A profile can withhold a tool the prose tells the model to use.

    So for every profile, every `kubenoob_*` name the instructions mention is either registered or in the withheld
    list -- never mentioned and silently absent.
    """
    for profile in tp.PROFILES:
        server = build_server(settings, profiles=(profile,))
        instructions = server.instructions or ""
        mentioned = set(re.findall(rf"{TOOL_PREFIX}[a-z_]+", instructions))
        offered, withheld = tp.select(Toolkit(settings).specs(), (profile,))
        known = {TOOL_PREFIX + s.name for s in offered} | {TOOL_PREFIX + n for n in withheld}
        # The prose also names tool *families* (`kubenoob_learn_*`, `kubenoob_cluster_*`); drop what is a prefix of
        # a real name rather than a name.
        stray = {m for m in mentioned - known if not any(k.startswith(m) for k in known)}
        assert stray == set(), (
            f"profile {profile!r}: the instructions name {sorted(stray)}, which this server "
            "neither offers nor lists as withheld"
        )


def test_an_unknown_profile_is_a_usage_error_not_a_quiet_fallback() -> None:
    with pytest.raises(tp.UnknownProfile) as exc:
        tp.parse("complaince")
    assert "complaince" in str(exc.value) and "incident" in str(exc.value)
    with pytest.raises(tp.UnknownProfile):
        tp.parse("incident,")
    with pytest.raises(tp.UnknownProfile):
        tp.parse("")


def test_the_cli_exits_2_on_an_unknown_profile(capsys: pytest.CaptureFixture[str]) -> None:
    """Exit 2 is the configuration-or-usage code. Not 0 with a smaller server, and not 1, which means findings."""
    assert main(["mcp", "--tools", "complaince"]) == 2
    err = capsys.readouterr().err
    assert "complaince" in err and "compliance" in err


def test_parse_accepts_several_and_collapses_all() -> None:
    assert tp.parse(None) == (tp.ALL,)
    assert tp.parse("all") == (tp.ALL,)
    assert tp.parse("incident,review") == ("incident", "review")
    assert tp.parse(" incident , incident ") == ("incident",)
    # `all` with anything else is `all`: the union cannot be smaller than one of its parts.
    assert tp.parse("incident,all") == (tp.ALL,)


def test_two_profiles_offer_the_union(settings: Settings) -> None:
    specs = Toolkit(settings).specs()
    one, _ = tp.select(specs, ("incident",))
    two, _ = tp.select(specs, ("review",))
    both, _ = tp.select(specs, ("incident", "review"))
    assert {s.name for s in both} == {s.name for s in one} | {s.name for s in two}


def test_a_profile_changes_what_is_listed_and_never_what_a_tool_answers(settings: Settings) -> None:
    """Determinism: the same call on two servers started with different profiles returns the same bytes.

    If a profile could change an answer there would be a second thing to reason about for every verdict, and a
    verdict that depends on how the server was started is not reproducible.
    """
    # One `specs()` call: it builds fresh ToolSpec objects each time, so selecting twice from one list is what
    # shows the profile did not substitute anything.
    specs = Toolkit(settings).specs()
    everything = {s.name: s for s in tp.select(specs, (tp.ALL,))[0]}
    narrowed = {s.name: s for s in tp.select(specs, ("review",))[0]}
    shared = sorted(set(everything) & set(narrowed))
    assert "audit_manifests" in shared
    for name in shared:
        # The same ToolSpec object, so the same function, model and description: there is no per-profile variant
        # of a tool to drift from the other.
        assert everything[name] is narrowed[name]


def test_the_core_tools_are_in_every_profile() -> None:
    """`config_status` above all: a caller that cannot read the configuration cannot tell a capability tier that is
    off from a tool a profile withheld, and those have different fixes."""
    for name, members in tp.PROFILES.items():
        for core in ("config_status", "list_rules", "explain_rule"):
            assert core in members, f"{core} is not in profile {name!r}"
