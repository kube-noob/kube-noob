"""A finding that vanished because kube-noob stopped reading the object is not a fixed finding.

`diff` already refused to call an object **removed** when its whole KIND went unread (G281's sibling, the RBAC
regression that published a lost `list networkpolicies` as a security improvement). It applied the same guard to
findings -- and the guard was a set of KINDS.

A kind is the wrong granularity. Move one Deployment to an apiVersion the rules refuse while another Deployment
in the input is still read, and the kind `Deployment` never enters `notReadKinds`: the refused object's findings
fall straight through into `fixed`. Measured on this fixture before the fix: **15 findings fixed**, among them
the critical KN-S001, with `undetermined` empty -- from a one-line change of `apps/v1` to `apps.k8s.io/v1`.

The report named the object the whole time. `coverage.notAudited` carries `Deployment/prod/payments`, built by
`_not_audited_row` in the same `Kind/namespace/name` shape a finding's `resource` uses. The two lists were never
joined.

The contract this file holds (G366): a finding may move to `fixed` only when the object it was raised against
was read in the new snapshot. Evidence that disappeared must never promote the report to a more favourable
conclusion -- which is the product rule applied to a delta rather than to a scan.
"""

from __future__ import annotations

import copy
import datetime as dt
from typing import Any

from kube_noob import drift

PRIVILEGED = {
    "apiVersion": "apps/v1",
    "kind": "Deployment",
    "metadata": {"name": "payments", "namespace": "prod", "resourceVersion": "1"},
    "spec": {
        "template": {
            "spec": {"containers": [{"name": "c", "image": "p:latest", "securityContext": {"privileged": True}}]}
        }
    },
}
#: The same object under a group the API server does not serve it under. The rules refuse it, so nothing about
#: it is known -- including whether it is still privileged.
REFUSED = {**copy.deepcopy(PRIVILEGED), "apiVersion": "apps.k8s.io/v1"}
#: A second Deployment that stays readable, so the KIND is never blind and the old kind-level guard cannot fire.
READABLE = {
    "apiVersion": "apps/v1",
    "kind": "Deployment",
    "metadata": {"name": "web", "namespace": "prod", "resourceVersion": "1"},
    "spec": {"template": {"spec": {"containers": [{"name": "c", "image": "web@sha256:" + "a" * 64}]}}},
}
#: The honest fix: still read, no longer privileged.
REMEDIATED = {
    "apiVersion": "apps/v1",
    "kind": "Deployment",
    "metadata": {"name": "payments", "namespace": "prod", "resourceVersion": "2"},
    "spec": {"template": {"spec": {"containers": [{"name": "c", "image": "p@sha256:" + "b" * 64}]}}},
}


def _snap(objects: list[dict[str, Any]], when: str, not_read: list[str] | None = None) -> dict[str, Any]:
    return drift.snapshot(
        objects,
        source="live",
        platform="kubernetes",
        taken_at=dt.datetime.fromisoformat(when),
        not_read=not_read or [],
    )


def _report(before: list[dict[str, Any]], after: list[dict[str, Any]]) -> dict[str, Any]:
    return drift.diff(
        _snap(before, "2026-11-01T00:00:00+00:00"),
        _snap(after, "2026-11-02T00:00:00+00:00"),
    )


def test_the_kind_is_not_blind_so_the_old_guard_could_not_have_fired() -> None:
    """The premise of the whole file. If `notReadKinds` held `Deployment`, the kind-level guard would already
    cover this and there would be nothing to fix -- so the fixture has to keep one Deployment readable."""
    after = _snap([REFUSED, READABLE], "2026-11-02T00:00:00+00:00")
    assert "Deployment" not in (after.get("notReadKinds") or [])


def test_the_refused_object_is_named_in_the_same_report() -> None:
    """The join this fix makes is possible only because both sides already exist, in the same shape."""
    after = _snap([REFUSED, READABLE], "2026-11-02T00:00:00+00:00")
    rows = (after.get("coverage") or {}).get("notAudited") or []
    assert "Deployment/prod/payments" in {r.get("object") for r in rows}


def test_a_finding_on_an_object_that_went_unread_is_never_fixed() -> None:
    """The headline. Nothing about the object is known any more, so nothing about it was fixed."""
    report = _report([PRIVILEGED, READABLE], [REFUSED, READABLE])
    fixed = report["findings"]["fixed"]
    assert not any(f["resource"] == "Deployment/prod/payments" for f in fixed), fixed
    assert report["findings"]["fixed"] == [], report["findings"]["fixed"]


def test_those_findings_are_carried_as_undetermined_and_not_dropped() -> None:
    """Not fixed is not the same as gone. A finding that stops being provable has to stay visible, or the fix
    is just a quieter version of the same lie."""
    report = _report([PRIVILEGED, READABLE], [REFUSED, READABLE])
    undetermined = report["findings"].get("undetermined") or []
    refs = {f["resource"] for f in undetermined}
    assert refs == {"Deployment/prod/payments"}, undetermined
    assert "KN-S001" in {f["ruleId"] for f in undetermined}


def test_nothing_is_lost_between_the_two_lists() -> None:
    """Every finding that was open before and is not open now lands in exactly one of `fixed` or
    `undetermined`. A guard that silently drops rows would pass the two tests above."""
    before_snap = _snap([PRIVILEGED, READABLE], "2026-11-01T00:00:00+00:00")
    after_snap = _snap([REFUSED, READABLE], "2026-11-02T00:00:00+00:00")
    report = drift.diff(before_snap, after_snap)
    old_ids = {f["id"] for f in before_snap["findings"] if not f.get("excepted")}
    new_ids = {f["id"] for f in after_snap["findings"] if not f.get("excepted")}
    gone = old_ids - new_ids
    accounted = len(report["findings"]["fixed"]) + len(report["findings"].get("undetermined") or [])
    assert accounted == len(gone), (accounted, len(gone))


def test_a_real_fix_is_still_reported_as_fixed() -> None:
    """The negative control, and the reason this is a join rather than a blanket refusal. The object is still
    read and no longer privileged: that is remediation and must keep reading as remediation, or the gate becomes
    useless and gets turned off."""
    report = _report([PRIVILEGED, READABLE], [REMEDIATED, READABLE])
    fixed_rules = {f["ruleId"] for f in report["findings"]["fixed"]}
    assert "KN-S001" in fixed_rules, report["findings"]
    assert (report["findings"].get("undetermined") or []) == []


def test_the_headline_line_does_not_announce_the_loss_as_a_repair() -> None:
    """What an operator actually reads. `markdown` prints the counts; before the fix this sentence said
    '1 new, 15 fixed' about a report that had lost sight of the object entirely.

    The `new` count is deliberately not asserted to be zero: refusing the Deployment genuinely changes what the
    remaining readable objects are evaluated against, and KN-N001 firing on `Deployment/prod/web` is a real
    finding on an object the snapshot still reads. `fixed` is the number that was lying.
    """
    report = _report([PRIVILEGED, READABLE], [REFUSED, READABLE])
    text = drift.markdown(report)
    assert "0 fixed" in text, text[:400]
    assert "15 fixed" not in text, text[:400]
    assert "verdict undetermined" in text, text[:200]


def test_an_unchanged_input_moves_nothing() -> None:
    """The other negative control: with nothing refused, both lists stay empty and no row is invented."""
    report = _report([PRIVILEGED, READABLE], [PRIVILEGED, READABLE])
    assert report["findings"]["fixed"] == []
    assert (report["findings"].get("undetermined") or []) == []
