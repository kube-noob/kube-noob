"""Completeness of a must-gather analysis as the fold of every leg that reported itself (G285).

``Analysis.completeness()`` folded the eight analysers and the files none of them could read. The command runs more
legs than that -- the operator inventory, the operator release-note lookup, the finding-level release-note search,
and the ingest layer that skips what it will not open -- and each already said when it was partial. Each said it
in its own place, and none of them reached ``complete`` or the exit code, so ``--require-complete`` exited 0 under
"operator inventory: partial -- Subscriptions were not read" and "skipped 1: nested archive (not opened)".

Every leg has one of three states. ``complete``: it read what it set out to read. ``partial``: it read some and
named what it did not (a thing it could not read, or could not determine, is partial here: the verdict word must
agree with the exit code, and only ``complete`` is a clean bill). ``not-applicable``: it had nothing to look for.
The headline ``complete`` is true exactly when no leg is ``partial``.
"""

from __future__ import annotations

from typing import Any

from kube_noob import sanitize
from kube_noob.mustgather.analyse import Analysis
from kube_noob.mustgather.ingest import Bundle, root_of

#: Every leg, in the order it is reported; a consumer can key on the names because they are always all present.
LEGS = (
    "analysers",
    "files",
    "skipped files",
    "secrets",
    "operator inventory",
    "operator known issues",
    "release notes",
)
STATES = ("complete", "partial", "not-applicable")
NEVER_READ = "Secret data (never read)"  # ingest's reason for the files it opens by design never
MAX_WHY = 600
#: The resources under ``cluster-scoped-resources/<group>/<resource>`` an analyser reads.
_CLUSTER_SCOPED = frozenset(
    {
        ("config.openshift.io", "clusterversions"),
        ("config.openshift.io", "clusteroperators"),
        ("config.openshift.io", "infrastructures"),
        ("core", "nodes"),
        ("machineconfiguration.openshift.io", "machineconfigpools"),
    }
)
#: Under ``namespaces/<ns>/``: pods and their logs, core (events), and the OLM group the inventory reads.
_NAMESPACED = frozenset({"pods", "core", "operators.coreos.com"})


def read_by_an_analyser(path: str) -> bool:
    """Would an analyser (or the operator inventory) have opened a file at this path, had it been a plain file?

    Decides whether a skipped path is a gap in the answer or a noted skip. It errs towards the gap: any file under
    ``namespaces/<ns>/core/`` counts, because ``events.yaml`` lives there, although most of its siblings are not
    read."""
    found = root_of(path)
    if found is None:
        return False
    rest = found[1]
    if rest[0] == "cluster-scoped-resources":
        return len(rest) >= 4 and (rest[1], rest[2]) in _CLUSTER_SCOPED
    return len(rest) >= 4 and rest[2] in _NAMESPACED


def _why(text: str) -> str:
    return sanitize.visible(" ".join(str(text).split()))[:MAX_WHY]


def _leg(name: str, state: str, why: str) -> dict[str, str]:
    if state not in STATES:
        raise ValueError(f"unknown leg state {state!r}")
    return {"leg": name, "state": state, "why": _why(why)}


def _analyser_legs(analysis: Analysis) -> list[dict[str, str]]:
    c = analysis.completeness()
    if c["notCollected"]:
        where = ", ".join(c["notCollected"])
        why = f"{c['analysersRead']} of {c['analysersExpected']} analysers had data; not collected: {where}"
        analysers = _leg("analysers", "partial", why)
    else:
        had = f"{c['analysersRead']} of {c['analysersExpected']} analysers had data"
        analysers = _leg("analysers", "complete", had)
    if c["unreadableFiles"]:
        first = "; ".join(f"{u['path']} ({u['reason']})" for u in analysis.unparsed[:3])
        more = f"; and {c['unreadableFiles'] - 3} more" if c["unreadableFiles"] > 3 else ""
        files = _leg("files", "partial", f"{c['unreadableFiles']} file(s) could not be read: {first}{more}")
    else:
        files = _leg("files", "complete", "every file an analyser opened was read")
    return [analysers, files]


def _skipped_legs(bundle: Bundle) -> list[dict[str, str]]:
    """Ingest's skips. Secret data is a deliberate skip and never a gap; every other reason is a gap when the path is
    one an analyser reads, and a noted skip otherwise. Paths past the listing cap cannot be placed, so they count as
    a gap: not knowing where a skipped file was is not knowing whether it was needed."""
    never_read = bundle.skipped.get(NEVER_READ, 0)
    if never_read:
        why = f"{never_read} Secret file(s) never read, by design: no analyser needs their data"
        by_design = _leg("secrets", "not-applicable", why)
    else:
        by_design = _leg("secrets", "not-applicable", "no Secret file in this must-gather; none would have been read")
    others = {r: n for r, n in bundle.skipped.items() if r != NEVER_READ}
    if not others and not bundle.skipped_unlisted:
        return [_leg("skipped files", "not-applicable", "nothing was skipped"), by_design]
    gaps: list[str] = []
    for path, reason in bundle.skipped_paths:
        if reason != NEVER_READ and read_by_an_analyser(path):
            gaps.append(f"{path} ({reason})")
    summary = "; ".join(f"{n} {reason}" for reason, n in sorted(others.items(), key=lambda kv: (-kv[1], kv[0])))
    if bundle.skipped_unlisted:
        why = (
            f"{summary}; {bundle.skipped_unlisted} skipped path(s) past the listing cap could not be placed, so "
            "whether an analyser needed them is not known"
        )
        if gaps:
            why = f"{len(gaps)} in directories an analyser reads: {'; '.join(gaps[:3])}; {why}"
        return [_leg("skipped files", "partial", why), by_design]
    if gaps:
        more = f"; and {len(gaps) - 3} more" if len(gaps) > 3 else ""
        why = f"{len(gaps)} skipped file(s) in directories an analyser reads: {'; '.join(gaps[:3])}{more} ({summary})"
        return [_leg("skipped files", "partial", why), by_design]
    examples = [p for p, r in bundle.skipped_paths if r != NEVER_READ][:2]
    shown = f" (e.g. {'; '.join(examples)})" if examples else ""
    why = f"{summary}{shown}: no analyser reads those directories, so nothing the analysis needs was skipped"
    return [_leg("skipped files", "not-applicable", why), by_design]


def _inventory_leg(inventory: dict[str, Any]) -> dict[str, str]:
    verdict = inventory.get("verdict")
    summary = str(inventory.get("summary") or "")
    if verdict == "listed":
        return _leg("operator inventory", "complete", summary or "listed")
    if verdict == "no-olm":
        return _leg("operator inventory", "not-applicable", summary or "no OLM: nothing to inventory")
    if verdict == "partial":
        return _leg("operator inventory", "partial", summary or "partial")
    # not-determined, or a verdict this does not know: neither is a clean bill
    return _leg("operator inventory", "partial", f"not determined: {summary or verdict!s}")


def _operator_issues_leg(issues: dict[str, Any]) -> dict[str, str]:
    because = [str(x) for x in issues.get("incompleteBecause") or []]
    if issues.get("complete") is True and not because:
        if issues.get("counts", {}).get("operators", 1) == 0 and issues.get("inventory", {}).get("verdict") == "no-olm":
            return _leg("operator known issues", "not-applicable", "no OLM: no operator to look up")
        return _leg("operator known issues", "complete", str(issues.get("summary") or "complete"))
    return _leg("operator known issues", "partial", "; ".join(because) or "incomplete, with no reason given")


def _release_notes_leg(report: dict[str, Any]) -> dict[str, str]:
    verdict = report.get("knownIssuesVerdict")
    note = str(report.get("knownIssuesNote") or "")
    version = (report.get("cluster") or {}).get("version")
    if verdict == "not-applicable":
        return _leg("release notes", "not-applicable", note or "not OpenShift")
    if verdict == "looked-up" and version:
        return _leg("release notes", "complete", f"findings were matched against the release notes for {version}")
    if verdict == "looked-up":
        return _leg(
            "release notes",
            "partial",
            "the cluster's OpenShift version is not known, so matches were not narrowed to a release",
        )
    return _leg("release notes", "partial", f"{verdict}: {note}" if note else str(verdict))


def fold(
    analysis: Analysis, bundle: Bundle, inventory: dict[str, Any], issues: dict[str, Any], report: dict[str, Any]
) -> dict[str, Any]:
    """The completeness block: the analyser-level keys as before, plus ``legs`` and a ``complete`` that is true only
    when no leg is partial."""
    legs = [
        *_analyser_legs(analysis),
        *_skipped_legs(bundle),
        _inventory_leg(inventory),
        _operator_issues_leg(issues),
        _release_notes_leg(report),
    ]
    if [leg["leg"] for leg in legs] != list(LEGS):
        raise ValueError("the legs folded are not the legs declared")
    partial = [leg["leg"] for leg in legs if leg["state"] == "partial"]
    return {
        **analysis.completeness(),
        "complete": not partial,
        "legs": legs,
        "partialLegs": partial,
    }


def render_line(c: dict[str, Any]) -> str | None:
    """The text view's one line about completeness, or None when every leg is complete or not applicable."""
    if c.get("complete", False) or not c.get("legs"):
        return None
    parts = [f"{leg['leg']}: {leg['why']}" for leg in c["legs"] if leg["state"] == "partial"]
    return (
        f"evidence is partial: {'; '.join(parts)}. A verdict from this is not a clean bill of health; "
        "--require-complete exits 5 on it."
    )
