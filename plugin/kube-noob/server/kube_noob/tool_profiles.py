"""Named subsets of the MCP tool surface, so a client does not pay for 54 tools to use six of them.

The server offers 54 tools in its default configuration and 67 across every optional surface. An MCP client reads
every one of their schemas before it calls any: the default ``tools/list`` payload is about 74 KB, roughly 18k
tokens of a window the model also needs for the user's manifests. The project's own review named that breadth an
anti-moat -- a client that spends its context on tool definitions picks worse among them.

A profile is a **literal set of tool names**, not a prefix rule. ``cluster_debug_workload`` and
``cluster_posture_scan`` share a prefix and belong to different profiles; ``posture_reach`` is review work and
``operator_inventory`` is both incident work and compliance evidence. A prefix cannot say that, and a prefix rule
would silently change meaning the next time a tool is named after an existing one.

``all`` is the default and is exactly the surface this server had before profiles existed. What a profile leaves
out is **left out of ``tools/list``, not made to disappear**: ``kube_noob.server.mcp_app`` refuses a call for an
excluded tool with a message naming the profiles that hold it, because "unknown tool" for a tool kube-noob has is
an absence reading as "no such thing" (docs/review-classes.md classes 13 and 15).
"""

from __future__ import annotations

from collections.abc import Iterable

#: Every answer needs these three whatever the task: the posture this server runs under (what it will not do),
#: and the knowledge store the instructions require every factual claim to cite.
CORE: frozenset[str] = frozenset({"config_status", "search_knowledge", "get_knowledge"})

ALL = "all"

#: Something is failing now: read the evidence the user has (events, logs, an Alertmanager payload, a must-gather,
#: a denial, a failed build), name the reported issue behind it and what the team already did about it.
_INCIDENT: frozenset[str] = CORE | frozenset(
    {
        "insight",
        "diagnose",
        "extract_signals",
        "explain_denial",
        "known_issues",
        "operator_known_issues",
        "operator_inventory",
        "upgrade_risks",
        "ticket",
        "ticket_changes",
        "incidents",
        "incident",
        "incident_confirm",
        "alert_report",
        "alert_report_list",
        "alert_report_get",
        "analyze_must_gather",
        "build_diagnose",
        "memory_match",
        "memory_propose",
        "check_network_policy",
        "api_history",
        "web_fetch",
        "cluster_get",
        "cluster_debug_workload",
        "cluster_check_namespace",
        "cluster_check_traffic",
        "cluster_version",
        "cluster_operator_inventory",
        "cluster_operator_known_issues",
    }
)

#: Manifests, charts, images and code in front of you, before they ship: validate, audit, red-team, fix, and the
#: posture questions ("what could an attacker reach from what we expose?").
_REVIEW: frozenset[str] = CORE | frozenset(
    {
        "insight",
        "run_protocol",
        "validate_manifests",
        "audit_manifests",
        "red_team",
        "fix_manifests",
        "clarify_requirements",
        "generate_manifests",
        "generate_helm_chart",
        "threat_model",
        "posture_scan",
        "posture_reach",
        "posture_report",
        "check_network_policy",
        "policy_generate",
        "policy_migrate_check",
        "explain_rule",
        "list_rules",
        "api_history",
        "vuln_report",
        "code_report",
        "containerfile_audit",
        "rhacs_compare",
        "rhacs_compare_live",
        "web_fetch",
        "cluster_posture_scan",
        "cluster_posture_reach",
    }
)

#: Evidence for a reader outside the team: the findings, what the rules mean and which controls they speak to, the
#: KSI crosswalk, the posture report and the operator inventory. No ``web_fetch``: a document a reviewer keeps
#: should not depend on a fetch that the next run may not be allowed to make.
_COMPLIANCE: frozenset[str] = CORE | frozenset(
    {
        "audit_manifests",
        "fedramp_ksi",
        "posture_report",
        "posture_scan",
        "list_rules",
        "explain_rule",
        "policy_generate",
        "operator_inventory",
        "api_history",
        "cluster_posture_scan",
        "cluster_operator_inventory",
    }
)

#: The tutor surface: tracks, lessons, exercises, quizzes, the grader and the local learning profile.
_LEARN: frozenset[str] = CORE | frozenset(
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
        "explain_rule",
        "list_rules",
        "api_history",
        "web_fetch",
    }
)

#: What each profile is for, in one line: the document and ``--help`` are generated from this, never retyped.
SUMMARIES: dict[str, str] = {
    ALL: "Every tool this configuration offers. The default, and exactly what the server did before profiles existed.",
    "incident": "Something is failing now: diagnose pasted events, logs, alerts, denials, a failed build or a "
    "must-gather, and name the reported issue and the team's own fix behind it.",
    "review": "Manifests, charts, images and code before they ship: validate, audit, red-team, fix, generate, and "
    "the posture and reachability questions.",
    "compliance": "Evidence for a reader outside the team: findings, what each rule means and which NIST controls "
    "it speaks to, the FedRAMP 20x KSI crosswalk, the posture report and the operator inventory.",
    "learn": "The tutor surface: tracks, lessons, exercises, quizzes, the grader and the local learning profile.",
}

#: The profiles. ``all`` is a sentinel whose membership is decided by the configuration, not by this table, so it
#: is empty here and ``select`` never consults it.
PROFILES: dict[str, frozenset[str]] = {
    ALL: frozenset(),
    "compliance": _COMPLIANCE,
    "incident": _INCIDENT,
    "learn": _LEARN,
    "review": _REVIEW,
}

#: The names in the order a message lists them.
NAMES: tuple[str, ...] = tuple(sorted(PROFILES))


def names_sentence() -> str:
    return ", ".join(NAMES)


def resolve(value: str) -> str:
    """``value`` if it names a profile; otherwise ``ValueError`` naming the ones that exist.

    The value is taken exactly as typed -- no case folding, no stripping, no comma list, no glob. A profile is a
    set someone tested; "almost a profile name" is a typo whose cost is a silently different tool surface.
    """
    if value in PROFILES:
        return value
    raise ValueError(f"{value!r} is not a kube-noob MCP tool profile; the profiles are: {names_sentence()}")


def select(profile: str, available: Iterable[str]) -> frozenset[str]:
    """The tool names ``profile`` offers out of ``available`` (what this configuration actually registers).

    A profile names tools an install may not have (the live-cluster tools without ``cluster.enabled``, ``web_fetch``
    without ``webEnabled``), so the answer is the intersection: a profile is never a promise the server cannot keep.
    """
    have = frozenset(available)
    if resolve(profile) == ALL:
        return have
    return have & PROFILES[profile]


def holders(tool: str) -> tuple[str, ...]:
    """The named profiles that hold ``tool``, excluding ``all``, which holds everything."""
    return tuple(name for name in NAMES if name != ALL and tool in PROFILES[name])


def outside_message(tool: str, profile: str, prefix: str = "") -> str:
    """Why a tool that exists is not offered here, and how to get it. Never "unknown tool": the tool is real, and a
    client told otherwise stops looking for a capability kube-noob has (classes 13 and 15)."""
    has = holders(tool)
    where = (
        f"It is in the {'profile' if len(has) == 1 else 'profiles'} {', '.join(has)} "
        f"-- start the server with --tools {has[0]} (or --tools all) to call it."
        if has
        else "It is in no named profile -- start the server with --tools all to call it."
    )
    return (
        f"{prefix}{tool} exists but is not in this server's {profile!r} tool profile, so it is not offered here. "
        f"{where}"
    )


MAX_WITHHELD_NAMED = 12


def profile_line(profile: str, held: int, whole: int, withheld_named: list[str] | None = None) -> str:
    """The sentence the ``initialize`` response carries, so a client can see which surface it got.

    ``withheld_named``: tools the instructions above name that this profile does not offer. Saying nothing about
    them would leave the server's own first message pointing at tools the client cannot call.
    """
    line = (
        f" Tool profile: {profile} ({held} of {whole} tools this configuration offers; the profiles are "
        f"{names_sentence()}, and --tools all offers every one). A tool outside the profile is refused by name, "
        "never as an unknown tool: it exists, and the refusal says which profile has it."
    )
    if withheld_named:
        shown = withheld_named[:MAX_WITHHELD_NAMED]
        more = len(withheld_named) - len(shown)
        line += (
            f" These tools named above are NOT offered under this profile: {', '.join(shown)}"
            + (f" and {more} more" if more else "")
            + ". Do not call them; say the profile does not offer them rather than that kube-noob cannot do it."
        )
    return line
