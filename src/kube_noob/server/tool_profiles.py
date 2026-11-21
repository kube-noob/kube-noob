"""Named subsets of the MCP tool surface, so a client is offered the tools for one job rather than all of them.

Fifty-six tools is more than most MCP clients list usefully and more than a model chooses well between: the ones
that matter for the job in hand compete with fifty that do not. ``kube-noob mcp --tools incident`` offers the
twenty-odd tools someone uses while something is broken, and so on for ``review``, ``compliance`` and ``learn``.

A profile decides only **which tools are listed**. It never changes what a tool does, what it answers or what it
reads, so two servers started with different profiles give the same answer to the same call. There is no
profile-dependent behaviour to reason about, and none to drift.

What a profile must never do is make a withheld tool look like a tool kube-noob does not have. A model that cannot
see ``kubenoob_fedramp_ksi`` does not conclude "this cannot be checked"; it answers the question from its own
knowledge, and the user reads an unaudited answer in a session that looked audited. That is the product's own
defect -- an absence reading as a complete answer -- in the tool surface rather than in a verdict. So every
withheld tool is named in the server's instructions, with the flag that would offer it (``withheld_sentence``),
and an unknown profile name is a usage error rather than a silent fall back to all or to none.

The reason a tool is not listed is part of the answer too, because the two reasons have different fixes. A profile
withheld it: start the server with another ``--tools``. A capability tier is off (``cluster.enabled`` and the rest,
see ``kube_noob.tiers``): that is a decision about what kube-noob may do, and no profile overrides it. The tiers
filter in ``Toolkit.specs`` runs first, so this module only ever sees tools the configuration already allows and
cannot report a tier-gated tool as one a profile hid.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - imported for the annotation only
    from kube_noob.toolkit import ToolSpec

ALL = "all"

# Offered under every profile: what the input is, what the rules are, and what this server's configuration allows.
# `config_status` especially -- a caller that cannot read the configuration cannot tell a tier that is off from a
# tool a profile withheld, which is the distinction the module docstring turns on.
_CORE = frozenset({"config_status", "search_knowledge", "get_knowledge", "list_rules", "explain_rule"})

_INCIDENT = frozenset(
    {
        "insight",
        "diagnose",
        "extract_signals",
        "alert_report",
        "alert_report_list",
        "alert_report_get",
        "incidents",
        "incident",
        "incident_confirm",
        "known_issues",
        "operator_known_issues",
        "operator_inventory",
        "upgrade_risks",
        "ticket",
        "ticket_changes",
        "explain_denial",
        "analyze_must_gather",
        "memory_match",
        "memory_propose",
        "cluster_get",
        "cluster_debug_workload",
        "cluster_check_namespace",
        "cluster_version",
        "cluster_operator_inventory",
        "cluster_operator_known_issues",
    }
)

_REVIEW = frozenset(
    {
        "verify_change",
        "audit_manifests",
        "validate_manifests",
        "fix_manifests",
        "red_team",
        "check_network_policy",
        "posture_scan",
        "posture_reach",
        "threat_model",
        "vuln_report",
        "containerfile_audit",
        "code_report",
        "build_diagnose",
        "run_protocol",
        "clarify_requirements",
        "generate_manifests",
        "generate_helm_chart",
        "api_history",
        "cluster_check_traffic",
        "cluster_posture_scan",
        "cluster_posture_reach",
    }
)

_COMPLIANCE = frozenset(
    {
        "fedramp_ksi",
        "compliance_results",
        "posture_report",
        "audit_manifests",
        "policy_generate",
        "policy_migrate_check",
        "rhacs_compare",
        "rhacs_compare_live",
        "threat_model",
        "vuln_report",
        "operator_inventory",
        "cluster_operator_inventory",
        "cluster_posture_scan",
    }
)

_LEARN = frozenset(
    {
        "learn_tracks",
        "learn_lesson",
        "learn_exercise",
        "learn_submit",
        "learn_quiz",
        "learn_progress",
        "grade_answer",
        "learning_summary",
        "learning_note_add",
        "learning_profile_set",
    }
)

# `web_fetch` belongs to no job in particular: it is offered when `webEnabled` is on, which is already the decision
# about whether this server reaches the network at all, so every profile that is offered it keeps it.
_ALWAYS = frozenset({"web_fetch"})

PROFILES: dict[str, frozenset[str]] = {
    "incident": _CORE | _INCIDENT | _ALWAYS,
    "review": _CORE | _REVIEW | _ALWAYS,
    "compliance": _CORE | _COMPLIANCE | _ALWAYS,
    "learn": _CORE | _LEARN | _ALWAYS,
}

NAMES: tuple[str, ...] = (ALL, *sorted(PROFILES))


class UnknownProfile(ValueError):
    """A ``--tools`` value that names no profile. Carries the message the CLI prints before exiting 2."""


def parse(value: str | None) -> tuple[str, ...]:
    """``"incident,review"`` -> ``("incident", "review")``; ``None`` or ``"all"`` -> ``("all",)``.

    An unknown name raises rather than being dropped. Dropping it would start a server offering some other set of
    tools than the one asked for, and nothing in the session would say so -- the caller would read a typo as a
    smaller product.
    """
    if value is None:
        return (ALL,)
    wanted = [part.strip() for part in value.split(",")]
    if any(not part for part in wanted):
        raise UnknownProfile(f"--tools {value!r} has an empty name; give one of: {', '.join(NAMES)}")
    unknown = [part for part in wanted if part != ALL and part not in PROFILES]
    if unknown:
        raise UnknownProfile(
            f"--tools: no profile named {', '.join(repr(u) for u in unknown)}; give one of: {', '.join(NAMES)}"
        )
    seen: list[str] = []
    for part in wanted:
        if part not in seen:
            seen.append(part)
    return (ALL,) if ALL in seen else tuple(seen)


def select(specs: Sequence[ToolSpec], profiles: Iterable[str]) -> tuple[list[ToolSpec], list[str]]:
    """The tools to register, and the names of the ones this profile withheld (sorted, for a stable instruction
    string and a stable test).

    ``specs`` has already been through the tier and shared-server filters in ``Toolkit.specs``, so a name missing
    from it was never this module's to offer and is not reported as withheld.
    """
    chosen = tuple(profiles)
    if ALL in chosen:
        return list(specs), []
    offered: frozenset[str] = frozenset().union(*(PROFILES[p] for p in chosen)) if chosen else frozenset()
    keep = [spec for spec in specs if spec.name in offered]
    withheld = sorted(spec.name for spec in specs if spec.name not in offered)
    return keep, withheld


def withheld_sentence(profiles: Iterable[str], withheld: Sequence[str], prefix: str) -> str:
    """What the server tells the model about the tools it is not listing.

    Said plainly and last, because the instructions above it name tools by hand and a profile can withhold one of
    them: a model reading "use kubenoob_policy_generate" and not finding it has to be told which of the two is
    true. Without this the only honest reading left is that kube-noob cannot do the thing at all.
    """
    chosen = ", ".join(profiles)
    if not withheld:
        return f" This server is offering the {chosen} tool profile, which withholds none of the tools it has."
    names = ", ".join(prefix + name for name in withheld)
    return (
        f" This server is offering the {chosen} tool profile, so the tools above are not all listed to you. "
        f"kube-noob HAS these tools and this server is NOT offering them: {names}. "
        "If one of them is what the user needs, say that kube-noob can do it and that this server was started "
        "without it, and give them the command that offers it (kube-noob mcp --tools all, or the profile that "
        "carries it). Never answer the question from your own knowledge as though the check had run, and never "
        "say kube-noob cannot do it."
    )
