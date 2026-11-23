"""The lines that say which rules reached no verdict, shared by every renderer.

They lived in `kube_noob/cli.py` because the text view printed them first (G272). `gate.py` and `report_html.py`
then imported them FROM the CLI -- a library module reaching into the command-line entry point, which is
backwards, and harmless only for as long as nothing follows the gate's import graph. G280's plugin hook does
follow it: `kube_noob.hook` imports `kube_noob.verify`, which imports `kube_noob.gate`, which imported
`kube_noob.cli`, which imports everything -- including `kube_noob.sources.jira`, the one module that names the
Jira client's credential variable. `scripts/sync_plugin_server.py` copies that closure into the plugin, so the
plugin would have shipped the Jira client over three string helpers (G262 forbids exactly that, and
`tests/test_plugin.py::test_bundle_names_no_credential_variables` refuses the variable's name anywhere in the
plugin copy, this docstring included).

So they live here: no imports of their own beyond typing, nothing to follow, and one definition every renderer
reads. `cli.py` re-exports them, so every existing caller keeps working.
"""

from __future__ import annotations

from typing import Any

#: How many rule ids one caveat line names before it says "and N more". A line a terminal cannot show is not a
#: statement anyone reads, and the count that follows is part of the answer, never a silent cut.
MAX_NOT_EVALUATED_NAMED = 20


def not_evaluated_line(summary: dict[str, Any]) -> str:
    """One bounded line naming the rules that reached no verdict on this input, or "" when every rule did.

    The ids come from ``rulesNotEvaluated``, the one list of them, which carries each rule's reason beside it.
    This used to read a bare ``notEvaluatedRules`` list of the same ids, which was a strict SUBSET of that one:
    a rule not evaluated because its kind was absent from the input appeared in ``rulesNotEvaluated`` with its
    reason and not in ``notEvaluatedRules`` at all, so the text view, the SARIF notes and the HTML report named
    fewer rules than the JSON did and a reader reconciling the two got different answers from one audit (G281,
    and review class 9 -- two lists of the same thing that can disagree). Every renderer reads this function,
    so they now all count the same rules."""
    rows = [r for r in summary.get("rulesNotEvaluated") or [] if isinstance(r, dict) and r.get("ruleId")]
    ids = [str(r["ruleId"]) for r in rows]
    if not ids:
        return ""
    more = f" and {len(ids) - MAX_NOT_EVALUATED_NAMED} more" if len(ids) > MAX_NOT_EVALUATED_NAMED else ""
    return (
        f"not evaluated: {', '.join(ids[:MAX_NOT_EVALUATED_NAMED])}{more} -- these rules reached no verdict on "
        "this input, so they are neither clean nor findings"
    )


def partly_evaluated_line(summary: dict[str, Any]) -> str:
    """One bounded line naming the rules that found something and declined on some object, or ""."""
    ids = [str(r) for r in summary.get("partlyEvaluatedRules") or []]
    if not ids:
        return ""
    more = f" and {len(ids) - MAX_NOT_EVALUATED_NAMED} more" if len(ids) > MAX_NOT_EVALUATED_NAMED else ""
    return (
        f"partly evaluated: {', '.join(ids[:MAX_NOT_EVALUATED_NAMED])}{more} -- these rules found something and "
        "declined on other objects; their findings are counted, and the declined objects are not clean"
    )


def caveat_lines(summary: dict[str, Any]) -> list[str]:
    """The not-evaluated and partly-evaluated lines, in that order, leaving out an empty one."""
    return [ln for ln in (not_evaluated_line(summary), partly_evaluated_line(summary)) if ln]
