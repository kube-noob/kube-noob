"""An exception must not erase the control it was filed against.

`Report.as_dict` builds `controlSummary` from `self.findings`. The exceptions filter in `Toolkit.audit` replaced
that list with the findings that survived, and only then called `as_dict` -- so a control whose only evidence was
an excepted finding dropped out of the report entirely.

That is backwards for a compliance record. An exception is an owned, reviewed, expiring decision *about* a
control; it is the case where you most want the control still named. Before this fix, filing one well-formed
exception against KN-N001 on a bundled example removed AC-4, SC-7 and SC-7(5) from `controlSummary`, leaving them
indistinguishable from controls no rule had ever looked at.
"""

from __future__ import annotations

from pathlib import Path

from kube_noob.config import Settings
from kube_noob.toolkit import AuditIn, Toolkit

EXAMPLE = Path(__file__).resolve().parent.parent / "examples" / "netpol-shop.yaml"

# KN-N001 and KN-N013 are the rules in this example that carry AC-4, SC-7 and SC-7(5). Both have to be
# excepted for the control to have no open evidence left: the example's shop default-deny restricts egress
# and allows no route to DNS, which is a real finding and the reason KN-N013 exists.
EXCEPTION = """apiVersion: kube-noob.io/v1
kind: ExceptionList
exceptions:
- id: EXC-001
  rule: KN-N001
  scope: {namespace: web, kind: Deployment, name: frontend}
  owner: team-net
  reason: North-south traffic is handled at the edge gateway; reviewed with security
  expires: 2027-06-30
- id: EXC-002
  rule: KN-N013
  scope: {namespace: shop, kind: NetworkPolicy, name: default-deny}
  owner: team-net
  reason: This example demonstrates reachability; DNS egress is out of its scope and reviewed
  expires: 2027-06-30
"""
ERASED = {"AC-4", "SC-7", "SC-7(5)"}


def _audit(exceptions: str | None = None) -> dict:
    tk = Toolkit(Settings())
    man = EXAMPLE.read_text(encoding="utf-8")
    return tk.audit(AuditIn(manifests=man, exceptions=exceptions) if exceptions else AuditIn(manifests=man))


def _ids(report: dict) -> set[str]:
    return {c["id"] for c in report["controlSummary"]["controls"]}


def test_an_exception_keeps_the_control_in_the_summary() -> None:
    before, after = _audit(), _audit(EXCEPTION)
    assert after.get("excepted"), "the exception must actually have matched, or this test proves nothing"
    assert _ids(before) == _ids(after), (
        f"filing an exception dropped {sorted(_ids(before) - _ids(after))} from the compliance record"
    )
    assert _ids(after) >= ERASED


def test_an_excepted_control_is_counted_apart_from_an_open_one() -> None:
    """`findings: 0, excepted: n` is the whole point: the control is named, and nobody can read it as clean.

    The count is asserted as "at least one" rather than exactly one on purpose: how many rules carry a given
    control is a property of the rulebook that changes whenever a rule is added, and pinning it here would
    turn every new rule into a failure in a test that is not about rule inventory.
    """
    after = _audit(EXCEPTION)
    entries = {c["id"]: c for c in after["controlSummary"]["controls"]}
    for cid in sorted(ERASED):
        assert entries[cid]["findings"] == 0, f"{cid} has no open evidence left"
        assert entries[cid]["excepted"] >= 1, f"{cid} must record that its evidence was excepted"
    assert "excepted" in after["controlSummary"]["note"]


def test_a_run_with_no_exceptions_is_unchanged() -> None:
    """The fix must not add a key, a count or a sentence to the ordinary report."""
    before = _audit()
    assert not any("excepted" in c for c in before["controlSummary"]["controls"])
    assert "excepted" not in before["controlSummary"]["note"]
    # `rulesNotEvaluated` and `rulesEvaluatedWithout` are the coverage record's own (G281), present with or
    # without an exceptions file; what this guards is that the exceptions path adds nothing of its own.
    assert set(before["controlSummary"]) == {
        "catalog",
        "controls",
        "note",
        "rulesNotEvaluated",
        "rulesEvaluatedWithout",
    }
    assert set(_audit(EXCEPTION)["controlSummary"]) == set(before["controlSummary"])


def test_open_findings_still_outrank_excepted_ones_in_the_order() -> None:
    after = _audit(EXCEPTION)
    counts = [c["findings"] for c in after["controlSummary"]["controls"]]
    assert counts == sorted(counts, reverse=True), "most open evidence first, as before"
