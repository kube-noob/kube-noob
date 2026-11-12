"""A control that was checked and is clean must not look like a control nothing evaluated.

`controlSummary` listed only controls that had findings, so an empty list meant either "every check
passed" or "no check ran", and nothing in the output could tell them apart. Every compliance claim
built on that inherits the same ambiguity, and claiming satisfaction from silence is the specific
failure FedRAMP's own guidance warns about.

The module docstring in controls.py already argued this for excepted findings -- "a control somebody
signed off on indistinguishable from a control nothing evaluated... the one confusion a compliance
record must not create". This applies the same principle to the other direction.
"""

from __future__ import annotations

from kube_noob.audit.controls import RULE_CONTROLS, summary
from kube_noob.audit.engine import analyze
from kube_noob.yamlio import load_documents

_CLEAN = """
apiVersion: v1
kind: ConfigMap
metadata: {name: c, namespace: prod}
data: {a: "1"}
"""


def test_without_a_coverage_list_the_old_shape_is_kept() -> None:
    """A caller that cannot say what ran must not be handed a coverage claim it has not earned."""
    out = summary(["KN-S001"])
    assert out["controls"], "a finding must still produce controls"
    for entry in out["controls"]:
        assert "clean" not in entry and "notEvaluated" not in entry


def test_a_clean_control_is_named_rather_than_absent() -> None:
    ran = sorted(RULE_CONTROLS)
    out = summary([], None, ran)
    ids = {c["id"] for c in out["controls"]}
    assert ids, "no controls were reported even though every rule ran"
    for entry in out["controls"]:
        assert entry["findings"] == 0
        assert entry["clean"] > 0, f"{entry['id']} ran clean and was reported as nothing"
        assert entry["notEvaluated"] == 0


def test_an_unevaluated_control_is_distinguishable_from_a_clean_one() -> None:
    """The whole point: the two states must not produce the same output."""
    clean = summary([], None, sorted(RULE_CONTROLS))
    none_ran = summary([], None, [])
    by_id_clean = {c["id"]: c for c in clean["controls"]}
    by_id_none = {c["id"]: c for c in none_ran["controls"]}
    assert by_id_clean.keys() == by_id_none.keys(), "both should name the same controls"
    assert by_id_clean != by_id_none, "clean and unevaluated produced identical output"
    for cid, entry in by_id_none.items():
        assert entry["notEvaluated"] > 0 and entry["clean"] == 0, cid


def test_a_rule_with_findings_is_not_also_counted_clean() -> None:
    out = summary(["KN-S001"], None, sorted(RULE_CONTROLS))
    for entry in out["controls"]:
        for cid in RULE_CONTROLS["KN-S001"]:
            if entry["id"] == cid:
                assert entry["findings"] >= 1


def test_an_audit_records_every_rule_it_ran_and_accounts_for_the_rest() -> None:
    """Every rule is either recorded as evaluated or recorded as having declined -- never neither.

    This asserted that EVERY rule appears in `evaluated_rules`, which held only while every rule could always
    decide. KN-S036 cannot: a registry allowlist is a policy from the configuration file, and with none
    configured the rule declines (G241). The invariant that matters is not "all evaluated" but "all accounted
    for": a rule missing from both lists is one whose verdict nobody can describe, which is how a skipped rule
    came to be published as clean (G202).
    """
    from kube_noob.audit.engine import build_context, run_rules

    docs = load_documents(_CLEAN)
    ctx = build_context(docs, "kubernetes", None)
    evaluated: list[str] = []
    run_rules(ctx, None, evaluated)
    # Three buckets since G281: evaluated, declined, and nothing of its kind in the input.
    assert set(evaluated) | ctx.undecided | set(ctx.no_subject) == set(RULE_CONTROLS), (
        f"unaccounted: {sorted(set(RULE_CONTROLS) - set(evaluated) - ctx.undecided - set(ctx.no_subject))}"
    )
    assert not set(evaluated) & ctx.undecided, "a rule was recorded as both evaluated and undecided"
    assert not set(evaluated) & set(ctx.no_subject) and not ctx.undecided & set(ctx.no_subject)
    assert len(set(evaluated)) == len(evaluated), "a rule was recorded twice"

    rep = analyze(_CLEAN, "kubernetes", None)
    assert len(set(rep.evaluated_rules)) == len(rep.evaluated_rules), "a rule was recorded twice"
    assert set(rep.evaluated_rules) <= set(RULE_CONTROLS)


def test_a_clean_bundle_reports_coverage_rather_than_an_empty_list() -> None:
    """The case that used to be indistinguishable from 'nothing ran'."""
    d = analyze(_CLEAN, "kubernetes", None).as_dict()
    controls = d["controlSummary"]["controls"]
    assert controls, "a clean audit reported no controls at all, which reads as 'nothing was checked'"
    assert all(c["findings"] == 0 for c in controls)
    assert any(c["clean"] > 0 for c in controls), "nothing was reported as checked-and-clean"


def test_a_stage_filter_shows_up_as_not_evaluated() -> None:
    """Asking for one stage really does leave rules unrun, and the record has to say so."""
    from kube_noob.audit.model import Stage

    rep = analyze(_CLEAN, "kubernetes", None, stages={Stage.VALIDATE})
    assert len(rep.evaluated_rules) < len(RULE_CONTROLS), "the stage filter ran everything"
    entries = {c["id"]: c for c in rep.as_dict()["controlSummary"]["controls"]}
    assert any(e["notEvaluated"] > 0 for e in entries.values()), "rules were skipped and nothing said so"
