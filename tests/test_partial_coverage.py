"""A rule the partial-bundle guard skipped is NOT "ran and found nothing" (G202).

G186 made absence-based rules silent on a partial bundle, because they cannot tell a real gap from an object
you did not pass. G191 then started reporting a control whose rules ran and found nothing as `clean`. Together
they said a skipped rule was clean: `audit -f one-file.yaml` reported SC-7 as "0 findings, 12 clean" when the
twelfth rule had declined to look.
"""

from __future__ import annotations

from pathlib import Path

from kube_noob.audit.engine import analyze

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = (ROOT / "examples" / "insecure-deployment.yaml").read_text(encoding="utf-8")

# The rules whose partial-bundle guard returns before they evaluate anything.
GUARDED = ("KN-N001", "KN-N013", "KN-C008", "KN-C015")


def _controls(partial: bool) -> dict[str, dict]:
    rep = analyze(BUNDLE, "openshift", "4.22", partial_bundle=partial).as_dict()
    return {c["id"]: c for c in rep["controlSummary"]["controls"]}


def test_a_guarded_rule_is_not_recorded_as_evaluated_on_a_partial_bundle() -> None:
    whole = analyze(BUNDLE, "openshift", "4.22")
    part = analyze(BUNDLE, "openshift", "4.22", partial_bundle=True)
    for rule_id in GUARDED:
        assert rule_id in whole.evaluated_rules, rule_id
        assert rule_id not in part.evaluated_rules, f"{rule_id} declined to decide but was recorded as evaluated"


def test_the_skipped_rule_moves_to_not_evaluated_rather_than_clean() -> None:
    whole, part = _controls(False), _controls(True)
    # SC-7 is KN-N001's control, and the complete bundle genuinely has a finding for it.
    assert whole["SC-7"]["findings"] == 1
    assert part["SC-7"]["findings"] == 0
    # KN-N001 and KN-N013 both map to SC-7, and both are guarded, so exactly two rules move.
    from kube_noob.audit.controls import RULE_CONTROLS

    guarded_here = [r for r in GUARDED if "SC-7" in RULE_CONTROLS[r]]
    # Since G281 the bucket also holds the SC-7 rules whose kind this bundle lacks (no Ingress, no Route, no
    # EgressFirewall), on the whole bundle and the partial one alike; the guard moves exactly the two guarded
    # rules on top of those, and each is named with the guard's own reason.
    assert part["SC-7"]["notEvaluated"] - whole["SC-7"]["notEvaluated"] == len(guarded_here) == 2, part["SC-7"]
    assert set(guarded_here) <= set(part["SC-7"]["notEvaluatedRules"])
    assert not set(guarded_here) & set(whole["SC-7"].get("notEvaluatedRules", []))
    # Nothing was invented: the rules that did run are the same ones, and the total is conserved.
    assert sum(part["SC-7"][k] for k in ("findings", "clean", "notEvaluated")) == sum(
        whole["SC-7"][k] for k in ("findings", "clean", "notEvaluated")
    )
    assert part["SC-7"]["clean"] < whole["SC-7"]["clean"], "a rule that was counted clean must have moved out"


def test_the_buckets_still_account_for_every_rule_on_a_partial_bundle() -> None:
    from kube_noob.audit.controls import RULE_CONTROLS

    total: dict[str, int] = {}
    for cs in RULE_CONTROLS.values():
        for c in cs:
            total[c] = total.get(c, 0) + 1
    for partial in (False, True):
        for cid, e in _controls(partial).items():
            got = e["findings"] + e.get("excepted", 0) + e["clean"] + e.get("withheld", 0) + e["notEvaluated"]
            assert got == total[cid], (partial, cid, e)


def test_a_complete_bundle_records_them_as_evaluated() -> None:
    """The guard is the only reason to withhold the claim; a directory audit still earns it.

    `notEvaluated` is no longer zero on the whole bundle: the rules about kinds the bundle does not carry sit
    there since G281. What a directory audit earns is that no rule is withheld by the guard, so every reason on
    these controls names an absent kind and none says a namespace was passed in part.
    """
    rep = analyze(BUNDLE, "openshift", "4.22").as_dict()["controlSummary"]
    reasons = {r["ruleId"]: r["why"] for r in rep["rulesNotEvaluated"]}
    for rule_id in GUARDED:
        assert rule_id not in reasons, (rule_id, reasons.get(rule_id))
    whole = _controls(False)
    for cid in ("SC-7", "AC-4"):
        for rule_id in whole[cid].get("notEvaluatedRules", []):
            assert reasons[rule_id].startswith("no ") and " in the input" in reasons[rule_id], (cid, rule_id)
