"""N1: the OpenShift Compliance Operator results reader. Every test is named for a behaviour, and almost all of them
are about the one thing the operator's own output makes easy to get wrong: a suite that reads as compliant because
the checks that would have failed were tailored out, skipped, or never finished.

The four headline cases live in ``tests/fixtures/compliance``: a rule a TailoredProfile disabled, a scan that
errored, a NOT-APPLICABLE check, and a rule the profile lists that no result names.
"""

from __future__ import annotations

import io
import json
import random
import tarfile
from pathlib import Path
from typing import Any

import pytest
import yaml

from kube_noob import compliance_results as cr
from kube_noob import toolkit as tk
from kube_noob.cli import main
from kube_noob.config import load_settings
from kube_noob.mustgather import compliance as mg_cr
from kube_noob.mustgather import ingest

ROOT = "mg/img"
FIXTURES = Path(__file__).parent / "fixtures" / "compliance"
CO = "compliance.openshift.io/v1alpha1"

# the rules the fixture Profile lists, and what should become of each
TAILORED_OUT = "ocp4-scc-limit-privileged-containers"
MANUAL = "ocp4-audit-log-forwarding-enabled"
FROM_BAD_SCAN = "ocp4-kubelet-enable-protect-kernel-defaults"
NOT_APPLICABLE = "ocp4-api-server-anonymous-auth"
MISSING = "ocp4-api-server-tls-cipher-suites"
PASSING = "ocp4-api-server-encryption-provider-cipher"


# -- builders ------------------------------------------------------------------------------------------------------


def _check(
    name: str,
    *,
    rule: str | None,
    status: str = "PASS",
    scan: str | None = "s1",
    severity: str = "medium",
    annotations: dict[str, str] | None = None,
    ns: str = "openshift-compliance",
) -> dict[str, Any]:
    meta: dict[str, Any] = {"name": name, "namespace": ns, "labels": {}, "annotations": dict(annotations or {})}
    if rule is not None:
        meta["annotations"][cr.RULE_ANNOTATION] = rule
    if scan is not None:
        meta["labels"][cr.SCAN_LABEL] = scan
    return {
        "apiVersion": CO,
        "kind": "ComplianceCheckResult",
        "metadata": meta,
        "id": f"xccdf_org.ssgproject.content_rule_{name.replace('-', '_')}",
        "status": status,
        "severity": severity,
    }


def _scan(name: str = "s1", *, phase: str = "DONE", result: str = "COMPLIANT", error: str = "") -> dict[str, Any]:
    status: dict[str, Any] = {"phase": phase, "result": result}
    if error:
        status["errormsg"] = error
    return {
        "apiVersion": CO,
        "kind": "ComplianceScan",
        "metadata": {"name": name, "namespace": "openshift-compliance"},
        "spec": {"scanType": "Platform"},
        "status": status,
    }


def _profile(name: str = "p1", rules: Any = ("r1",)) -> dict[str, Any]:
    return {
        "apiVersion": CO,
        "kind": "Profile",
        "metadata": {"name": name, "namespace": "openshift-compliance"},
        "id": f"xccdf_org.ssgproject.content_profile_{name}",
        "title": name,
        "description": name,
        "rules": list(rules) if isinstance(rules, (list, tuple)) else rules,
    }


def _tailored(
    name: str = "tp1",
    *,
    extends: str | None = "p1",
    disable: Any = (),
    enable: Any = (),
    manual: Any = (),
    state: str = "READY",
) -> dict[str, Any]:
    spec: dict[str, Any] = {"title": name, "description": name}
    if extends is not None:
        spec["extends"] = extends
    for key, value in (("disableRules", disable), ("enableRules", enable), ("manualRules", manual)):
        if value or value == []:
            spec[key] = value
    return {
        "apiVersion": CO,
        "kind": "TailoredProfile",
        "metadata": {"name": name, "namespace": "openshift-compliance"},
        "spec": spec,
        "status": {"state": state},
    }


def _suite(name: str = "suite1", *, result: str = "COMPLIANT", phase: str = "DONE", scans: Any = ("s1",)) -> Any:
    return {
        "apiVersion": CO,
        "kind": "ComplianceSuite",
        "metadata": {"name": name, "namespace": "openshift-compliance"},
        "spec": {"scans": [{"name": s} for s in scans]},
        "status": {"phase": phase, "result": result, "scanStatuses": [{"name": s, "phase": phase} for s in scans]},
    }


def _rule_cr(name: str, *, nist: str | None = None, severity: str = "medium", check_type: str = "Platform") -> Any:
    annotations = {} if nist is None else {f"{cr.CONTROL_PREFIX}{cr.NIST}": nist}
    return {
        "apiVersion": CO,
        "kind": "Rule",
        "metadata": {"name": name, "namespace": "openshift-compliance", "annotations": annotations},
        "id": f"xccdf_org.ssgproject.content_rule_{name.replace('-', '_')}",
        "title": f"title of {name}",
        "severity": severity,
        "checkType": check_type,
    }


def _yaml(*docs: Any) -> str:
    return yaml.safe_dump_all(list(docs), sort_keys=True)


def _assess(*docs: Any) -> dict[str, Any]:
    return cr.assess(cr.from_manifests(_yaml(*docs)))


def _rule(out: dict[str, Any], name: str) -> dict[str, Any]:
    hits = [r for r in out["rules"] if r["rule"] == name]
    assert len(hits) == 1, [r["rule"] for r in out["rules"]]
    return hits[0]


def _control(out: dict[str, Any], control: str) -> dict[str, Any]:
    hits = [r for r in out["controls"] if r["control"] == control]
    assert len(hits) == 1, control
    return hits[0]


def _bundle(tmp_path: Path, files: dict[str, str], name: str = "t.tgz") -> ingest.Bundle:
    path = tmp_path / name
    with tarfile.open(path, "w:gz") as tf:
        for rel, data in files.items():
            raw = data.encode()
            info = tarfile.TarInfo(f"{ROOT}/{rel}")
            info.size, info.mode = len(raw), 0o644
            tf.addfile(info, io.BytesIO(raw))
    return ingest.open_bundle(path)


def _list(kind: str, *docs: Any) -> str:
    return json.dumps({"apiVersion": CO, "kind": kind, "items": list(docs)})


def _fixture_text() -> str:
    return "\n---\n".join(p.read_text(encoding="utf-8") for p in sorted(FIXTURES.glob("*.yaml")))


def _fixture_out() -> dict[str, Any]:
    return cr.assess(cr.from_manifests(_fixture_text(), "fixtures"))


# -- the four headline cases ---------------------------------------------------------------------------------------


def test_a_suite_that_tailored_out_its_failures_is_not_compliant() -> None:
    out = _assess(
        _profile("p1", ["r1", "r2"]),
        _tailored(disable=[{"name": "r2", "rationale": "accepted for the build namespace"}]),
        _scan(),
        _suite(),
        _check("c1", rule="r1"),
    )
    assert out["verdict"] == "undetermined" and out["complete"] is False
    assert out["counts"] == {**out["counts"], "passing": 1, "failing": 0, "notEvaluated": 1, "tailoredOut": 1}
    assert out["passRate"] is None and "not evaluated" in out["passRateWithheld"]
    suite = out["suites"][0]
    assert suite["claimedResult"] == "COMPLIANT" and suite["agrees"] is False
    assert "never evaluated" in suite["why"]
    assert any("tailored" in r.lower() or "disabled" in r.lower() for r in out["undeterminedBecause"])


def test_a_rule_disabled_by_a_tailored_profile_names_the_profile_and_its_rationale() -> None:
    out = _assess(
        _profile("p1", ["r1"]),
        _tailored(disable=[{"name": "r1", "rationale": "accepted for the build namespace"}]),
        _scan(),
    )
    row = _rule(out, "r1")
    assert row["outcome"] == "not-evaluated" and row["reason"] == "disabled-by-tailoring"
    assert "tp1" in row["detail"] and "accepted for the build namespace" in row["detail"]
    assert "TailoredProfile disabled this rule" in row["why"]


def test_a_not_applicable_check_is_not_evaluated_and_is_never_folded_into_a_pass() -> None:
    out = _assess(
        _profile("p1", ["r1", "r2"]), _scan(), _check("c1", rule="r1"), _check("c2", rule="r2", status="NOT-APPLICABLE")
    )
    assert _rule(out, "r1")["outcome"] == "pass"
    row = _rule(out, "r2")
    assert row["outcome"] == "not-evaluated" and row["reason"] == "not-applicable"
    assert out["counts"]["passing"] == 1 and out["counts"]["notApplicable"] == 1
    assert out["verdict"] == "undetermined"


def test_a_rule_in_the_profile_with_no_result_at_all_is_reported_as_missing_from_the_results() -> None:
    out = _assess(_profile("p1", ["r1", "silent"]), _scan(), _check("c1", rule="r1"))
    row = _rule(out, "silent")
    assert row["outcome"] == "not-evaluated" and row["reason"] == "missing-from-results"
    assert "nothing evaluated it" in row["why"]
    assert out["counts"]["missingFromResults"] == 1 and out["verdict"] == "undetermined"


def test_a_scan_that_did_not_reach_done_makes_its_passes_not_passes() -> None:
    out = _assess(_profile("p1", ["r1"]), _scan(phase="RUNNING", result="NOT-AVAILABLE"), _check("c1", rule="r1"))
    row = _rule(out, "r1")
    assert row["outcome"] == "not-evaluated" and row["reason"] == "scan-not-done"
    assert "phase RUNNING" in row["detail"]
    assert out["counts"]["passing"] == 0 and out["counts"]["scansNotDone"] == 1
    assert out["verdict"] == "undetermined"


def test_a_scan_with_an_error_message_makes_its_passes_not_passes() -> None:
    out = _assess(_profile("p1", ["r1"]), _scan(error="timed out waiting for the scan pod"), _check("c1", rule="r1"))
    row = _rule(out, "r1")
    assert row["outcome"] == "not-evaluated" and row["reason"] == "scan-errored"
    assert "timed out waiting for the scan pod" in row["detail"]
    assert out["counts"]["passing"] == 0


def test_a_scan_both_unfinished_and_errored_gives_a_detail_that_agrees_with_its_reason() -> None:
    """The reason is scan-errored whenever an error is set, so the detail beside it must name the error too."""
    out = _assess(
        _profile("p1", ["r1"]),
        _scan(phase="RUNNING", result="NOT-AVAILABLE", error="timed out waiting for the scan pod"),
        _check("c1", rule="r1"),
    )
    row = _rule(out, "r1")
    assert row["reason"] == "scan-errored"
    assert "reported an error" in row["detail"] and "timed out waiting for the scan pod" in row["detail"]
    assert "phase RUNNING" in row["detail"]


def test_a_failing_check_is_still_reported_when_its_scan_did_not_complete() -> None:
    """An absence never turns a pass into a pass; it also never withdraws a failure the operator did report."""
    out = _assess(_profile("p1", ["r1"]), _scan(phase="RUNNING"), _check("c1", rule="r1", status="FAIL"))
    row = _rule(out, "r1")
    assert row["outcome"] == "fail"
    assert out["verdict"] == "non-compliant" and out["complete"] is False
    check = out["rules"][0]
    assert any("does not withdraw a failure" in n for n in check["notes"])


# -- absence is never a pass, a zero or "complete" ------------------------------------------------------------------


def test_an_input_with_no_check_results_is_undetermined_rather_than_zero_findings() -> None:
    out = _assess({"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "web", "namespace": "shop"}})
    assert out["verdict"] == "undetermined" and out["complete"] is False
    assert out["rules"] == [] and out["counts"]["rules"] == 0
    assert out["passRate"] is None
    results = next(s for s in out["sources"] if s["resource"] == "compliancecheckresults")
    assert results["state"] == "not-read" and "no ComplianceCheckResult" in results["reason"]
    assert any("no ComplianceCheckResult was read" in r for r in out["undeterminedBecause"])
    assert "0 findings" not in out["summary"] and "compliant" not in out["summary"].split(";")[0]


def test_results_with_no_profile_cannot_see_the_silent_case_and_say_so() -> None:
    out = _assess(_scan(), _check("c1", rule="r1"))
    assert out["verdict"] == "undetermined"
    assert any("no Profile or TailoredProfile was read" in r for r in out["undeterminedBecause"])
    assert any("produced no result at all cannot be seen" in r for r in out["undeterminedBecause"])


def test_a_tailored_profile_extending_a_profile_that_was_not_read_is_undetermined() -> None:
    out = _assess(_tailored(extends="not-in-the-input"), _scan(), _check("c1", rule="r1"))
    assert out["verdict"] == "undetermined"
    assert any("extends not-in-the-input" in r and "not read" in r for r in out["undeterminedBecause"])


def test_a_pass_whose_scan_was_not_read_is_not_a_pass() -> None:
    out = _assess(_profile("p1", ["r1"]), _check("c1", rule="r1", scan="s-not-here"))
    row = _rule(out, "r1")
    assert row["outcome"] == "not-evaluated" and row["reason"] == "scan-not-read"
    assert out["counts"]["passing"] == 0


def test_a_pass_with_no_scan_label_is_not_a_pass() -> None:
    out = _assess(_profile("p1", ["r1"]), _scan(), _check("c1", rule="r1", scan=None))
    row = _rule(out, "r1")
    assert row["outcome"] == "not-evaluated" and row["reason"] == "scan-not-read"
    assert any(cr.SCAN_LABEL in n for n in row["notes"])


def test_a_check_whose_rule_annotation_is_absent_is_named_rather_than_counted_as_a_pass() -> None:
    out = _assess(_profile("p1", ["r1"]), _scan(), _check("c1", rule=None))
    assert out["counts"]["checksWithoutARule"] == 1
    assert out["checksWithoutARule"][0]["name"] == "c1"
    assert _rule(out, "r1")["reason"] == "missing-from-results"
    assert any("name no rule this could join" in r for r in out["undeterminedBecause"])


def test_an_enabled_rule_outside_the_base_profile_is_part_of_the_expected_set() -> None:
    out = _assess(
        _profile("p1", ["r1"]),
        _tailored(enable=[{"name": "extra", "rationale": "asked for by the assessor"}]),
        _scan(),
        _check("c1", rule="r1"),
    )
    row = _rule(out, "extra")
    assert row["reason"] == "missing-from-results"
    assert any("enableRules" in s for s in row["expectedFrom"])


def test_a_result_that_was_present_but_could_not_be_joined_is_never_only_an_absence() -> None:
    """Review class 24: a refusal one layer down must not read as "there was nothing here" one layer up. The rule
    is missing-from-results AND the result that was in the input is named, in the same answer."""
    out = _assess(_profile("p1", ["r1"]), _scan(), _check("c1", rule=None, status="FAIL"))
    row = _rule(out, "r1")
    assert row["reason"] == "missing-from-results"
    assert out["counts"]["checksWithoutARule"] == 1
    named = out["checksWithoutARule"][0]
    assert named["name"] == "c1" and named["status"] == "FAIL"
    assert any("name no rule this could join" in r and "c1" in r for r in out["undeterminedBecause"])
    text = cr.render_text(out)
    assert "NOT JOINED TO A RULE" in text and "c1" in text


def test_a_newline_in_an_object_name_cannot_forge_a_row_in_the_text_view() -> None:
    """Review class 7: every input-derived string goes through the one output boundary."""
    forged = "evil\n  ocp4-forged  PASS"
    out = cr.assess(
        cr.from_documents([_profile("p1", ["r1"]), _scan(), _check(forged, rule="r1", status="NOT-APPLICABLE")])
    )
    text = cr.render_text(out)
    assert "\n  ocp4-forged  PASS" not in text
    assert not any(line.strip().startswith("ocp4-forged") for line in text.splitlines())
    assert "<evil" in text and _rule(out, "r1")["outcome"] == "not-evaluated"


# -- review class 4: an unrecognised value is never the benign default ----------------------------------------------


def test_a_check_status_in_the_wrong_case_is_not_read_as_a_pass() -> None:
    out = _assess(_profile("p1", ["r1"]), _scan(), _check("c1", rule="r1", status="pass"))
    row = _rule(out, "r1")
    assert row["outcome"] == "not-evaluated" and row["reason"] == "unrecognised-status"
    assert "'pass'" in row["detail"]
    assert out["counts"]["passing"] == 0


@pytest.mark.parametrize("status", ["", None, True, 1, "PASSED", "Pass", ["PASS"]])
def test_no_status_the_operator_does_not_define_is_ever_read_as_a_pass(status: Any) -> None:
    check = _check("c1", rule="r1")
    if status is None:
        check.pop("status")
    else:
        check["status"] = status
    out = cr.assess(cr.from_documents([_profile("p1", ["r1"]), _scan(), check]))
    assert _rule(out, "r1")["outcome"] == "not-evaluated"
    assert out["counts"]["passing"] == 0


@pytest.mark.parametrize("phase", ["done", "Done", "FINISHED", "", None, 7])
def test_a_scan_phase_the_operator_does_not_define_is_not_a_completed_scan(phase: Any) -> None:
    scan = _scan()
    if phase is None:
        scan["status"].pop("phase")
    else:
        scan["status"]["phase"] = phase
    out = cr.assess(cr.from_documents([_profile("p1", ["r1"]), scan, _check("c1", rule="r1")]))
    assert out["scans"][0]["usable"] is False
    assert _rule(out, "r1")["outcome"] == "not-evaluated"


def test_a_profile_rule_list_that_is_a_scalar_is_not_read_as_an_empty_profile() -> None:
    out = _assess(_profile("p1", rules="r1"), _scan(), _check("c1", rule="r1"))
    assert any("rules field that is not a list" in r for r in out["undeterminedBecause"])
    assert out["verdict"] == "undetermined"


def test_a_disable_rules_list_that_is_not_a_list_is_named_rather_than_ignored() -> None:
    out = _assess(_profile("p1", ["r1"]), _tailored(disable="r1"), _scan(), _check("c1", rule="r1"))
    assert any("spec.disableRules is not a list" in r for r in out["undeterminedBecause"])
    assert out["verdict"] == "undetermined"


def test_a_suite_result_the_operator_does_not_define_does_not_hold() -> None:
    suite = _suite(result="GREEN")
    out = cr.assess(cr.from_documents([_profile("p1", ["r1"]), _scan(), _check("c1", rule="r1"), suite]))
    row = out["suites"][0]
    assert row["agrees"] is False and "is not one the operator defines" in row["why"]


# -- review class 3: the group is part of the kind ------------------------------------------------------------------


def test_a_kind_of_the_same_name_from_another_api_group_is_ignored_and_named() -> None:
    foreign = {
        "apiVersion": "kyverno.io/v1",
        "kind": "Rule",
        "metadata": {"name": "r1", "namespace": "openshift-compliance"},
    }
    out = _assess(_profile("p1", ["r1"]), _scan(), _check("c1", rule="r1"), foreign)
    assert any("another API group were ignored" in r for r in out["undeterminedBecause"])
    assert _rule(out, "r1")["controls"] == []


def test_a_compliance_kind_with_no_api_version_is_still_read() -> None:
    check = _check("c1", rule="r1")
    check.pop("apiVersion")
    out = cr.assess(cr.from_documents([_profile("p1", ["r1"]), _scan(), check]))
    assert _rule(out, "r1")["outcome"] == "pass"


@pytest.mark.parametrize("warnings", ["boom", 7, {"a": 1}, [1, "real"], [None]])
def test_a_warning_that_could_not_be_read_is_named_rather_than_treated_as_no_warning(warnings: Any) -> None:
    check = _check("c1", rule="r1")
    check["warnings"] = warnings
    out = cr.assess(cr.from_documents([_profile("p1", ["r1"]), _scan(), check]))
    notes = _rule(out, "r1")["notes"]
    assert any("warnings" in n and "not read" in n for n in notes), notes


# -- review classes 1 and 23: the wrapper's own defects ------------------------------------------------------------


@pytest.mark.parametrize("items", [{"a": 1}, "nope", 7, None])
def test_a_list_wrapper_whose_items_are_not_a_list_is_counted_not_dropped(items: Any) -> None:
    wrapper = {"apiVersion": CO, "kind": "ComplianceCheckResultList", "items": items}
    out = cr.assess(cr.from_documents([_profile("p1", ["r1"]), _scan(), wrapper]))
    assert out["verdict"] == "undetermined"
    assert any("were not usable objects of it" in r for r in out["undeterminedBecause"])


def test_an_untyped_list_with_no_items_list_is_named_rather_than_read_as_empty() -> None:
    wrapper = {"apiVersion": "v1", "kind": "List", "items": "nope"}
    out = cr.assess(cr.from_documents([_profile("p1", ["r1"]), _scan(), wrapper]))
    assert any("has no items list" in r for r in out["undeterminedBecause"])


def test_a_duplicate_key_on_the_list_wrapper_itself_makes_the_answer_undetermined() -> None:
    text = (
        f"apiVersion: {CO}\nkind: ComplianceCheckResultList\nmetadata:\n  name: a\n  name: b\nitems:\n"
        "  - apiVersion: " + CO + "\n    kind: ComplianceCheckResult\n    metadata:\n"
        "      name: c1\n      namespace: openshift-compliance\n      annotations:\n"
        f"        {cr.RULE_ANNOTATION}: r1\n      labels:\n        {cr.SCAN_LABEL}: s1\n    status: PASS\n"
        "    severity: medium\n"
    )
    out = cr.assess(cr.from_manifests(text, "dup.yaml"))
    assert out["verdict"] == "undetermined"
    assert any("twice" in r and "API server refuses" in r for r in out["undeterminedBecause"])


def test_a_duplicate_key_inside_a_check_result_makes_the_answer_undetermined() -> None:
    text = (
        f"apiVersion: {CO}\nkind: ComplianceCheckResult\nmetadata:\n  name: c1\n"
        "  namespace: openshift-compliance\n  annotations:\n"
        f"    {cr.RULE_ANNOTATION}: r1\n  labels:\n    {cr.SCAN_LABEL}: s1\nstatus: PASS\nstatus: FAIL\n"
        "severity: medium\n"
    )
    out = cr.assess(cr.from_manifests(text, "dup2.yaml"))
    assert out["verdict"] in ("undetermined", "non-compliant")
    assert any("twice" in r for r in out["undeterminedBecause"])


# -- review classes 5 and 7: duplicates, ordering and input-derived strings -----------------------------------------


def test_two_check_results_of_one_name_that_disagree_are_flagged_and_neither_is_the_answer() -> None:
    a = _check("c1", rule="r1", status="PASS")
    b = _check("c1", rule="r1", status="NOT-APPLICABLE")
    out = cr.assess(cr.from_documents([_profile("p1", ["r1"]), _scan(), a, b]))
    assert any("appeared more than once with different content" in r for r in out["undeterminedBecause"])
    assert _rule(out, "r1")["outcome"] != "pass"


def test_two_results_for_one_rule_that_disagree_do_not_pick_a_winner() -> None:
    out = cr.assess(
        cr.from_documents(
            [
                _profile("p1", ["r1"]),
                _scan(),
                _check("c1", rule="r1", status="PASS"),
                _check("c2", rule="r1", status="NOT-APPLICABLE"),
            ]
        )
    )
    row = _rule(out, "r1")
    assert row["outcome"] == "not-evaluated" and row["reason"] == "results-disagree"
    assert "c1" in row["detail"] and "c2" in row["detail"]


def test_a_rule_name_with_invisible_unicode_does_not_join_to_a_profile_rule_and_is_marked() -> None:
    sneaky = f"{TAILORED_OUT}­"  # a soft hyphen: looks identical, is a different name
    out = cr.assess(cr.from_documents([_profile("p1", [TAILORED_OUT]), _scan(), _check("c1", rule=sneaky)]))
    # The real rule got no result; the PASS does not stand in for it, and the name it carried is not shown as a name.
    assert _rule(out, TAILORED_OUT)["reason"] == "missing-from-results"
    assert out["counts"]["passing"] == 0
    unjoined = out["checksWithoutARule"]
    assert [r["name"] for r in unjoined] == ["c1"]
    marked = [n for n in unjoined[0]["notes"] if "not a usable rule name" in n]
    assert marked and f"<{TAILORED_OUT}>" in marked[0]
    assert "­" not in json.dumps(out, ensure_ascii=False)


def test_the_same_objects_in_any_order_give_identical_bytes() -> None:
    docs = [
        _profile("p1", ["r1", "r2", "r3"]),
        _tailored(disable=[{"name": "r3", "rationale": "x"}]),
        _scan(),
        _scan("s2", phase="RUNNING"),
        _suite(scans=["s1", "s2"]),
        _check("c1", rule="r1"),
        _check("c2", rule="r2", status="FAIL"),
        _rule_cr("r1", nist="CM-6"),
        _rule_cr("r2", nist="AC-6;SC-39"),
    ]
    first = json.dumps(cr.assess(cr.from_documents(docs)), sort_keys=True)
    rng = random.Random(7)
    for _ in range(6):
        shuffled = list(docs)
        rng.shuffle(shuffled)
        assert json.dumps(cr.assess(cr.from_documents(shuffled)), sort_keys=True) == first


def test_a_secret_in_the_input_is_dropped_unread() -> None:
    secret = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": "s", "namespace": "openshift-compliance"},
        "data": {"token": "aGVsbG8="},
    }
    out = cr.assess(cr.from_documents([_profile("p1", ["r1"]), _scan(), _check("c1", rule="r1"), secret]))
    assert out["droppedUnread"] == 1
    assert "aGVsbG8" not in json.dumps(out)


# -- review classes 13 and 25: one predicate decides the headline ---------------------------------------------------


def test_the_pass_rate_is_withheld_while_anything_was_not_evaluated() -> None:
    skipped = _assess(_profile("p1", ["r1", "r2"]), _scan(), _check("c1", rule="r1"))
    assert skipped["passRate"] is None and "passRateWithheld" in skipped
    clean = _assess(_profile("p1", ["r1"]), _scan(), _suite(), _check("c1", rule="r1"), _rule_cr("r1", nist="CM-6"))
    assert clean["verdict"] == "compliant" and clean["complete"] is True
    assert clean["passRate"] == 100.0 and "passRateWithheld" not in clean
    assert clean["undeterminedBecause"] == []


def test_the_headline_word_never_says_compliant_while_a_reason_is_listed() -> None:
    for docs in (
        [_profile("p1", ["r1", "r2"]), _scan(), _check("c1", rule="r1")],
        [_profile("p1", ["r1"]), _scan(phase="RUNNING"), _check("c1", rule="r1")],
        [_profile("p1", ["r1"]), _tailored(disable=[{"name": "r1", "rationale": "x"}]), _scan()],
        [_scan(), _check("c1", rule="r1")],
    ):
        out = cr.assess(cr.from_documents(docs))
        assert out["undeterminedBecause"], docs
        assert out["verdict"] != "compliant"
        assert out["complete"] is False
        assert out["passRate"] is None


def test_every_renderer_reads_the_same_completeness_predicate() -> None:
    out = _assess(_profile("p1", ["r1", "r2"]), _scan(), _suite(), _check("c1", rule="r1"))
    text = cr.render_text(out)
    assert out["verdict"] in text.splitlines()[0]
    assert "pass rate withheld" in text
    for reason in out["undeterminedBecause"]:
        assert f"undetermined because: {reason}" in text


# -- review class 6: the caveat is never only in the JSON -----------------------------------------------------------


def test_the_text_view_carries_every_not_evaluated_reason_the_json_does() -> None:
    out = _fixture_out()
    text = cr.render_text(out)
    for row in out["notEvaluated"]:
        assert row["rule"] in text
        assert row["reason"] in text
        assert row["why"] in text
    for row in out["controls"]:
        if row["evidence"] == "neither":
            assert row["control"] in text
            assert row["note"] in text


def test_the_mcp_tool_result_carries_the_not_evaluated_detail() -> None:
    kit = tk.Toolkit(load_settings())
    out = kit.compliance_results(tk.ComplianceResultsIn(manifests=_fixture_text()))
    assert out["verdict"] == "undetermined" and out["complete"] is False
    assert out["undeterminedBecause"]
    reasons = {r["reason"] for r in out["notEvaluated"]}
    assert {"disabled-by-tailoring", "manual-by-tailoring", "missing-from-results", "not-applicable"} <= reasons
    assert out["passRate"] is None and out["passRateWithheld"]


# -- the control crosswalk ------------------------------------------------------------------------------------------


def test_a_control_evidenced_by_both_sides_says_so() -> None:
    out = _assess(_profile("p1", ["r1"]), _scan(), _check("c1", rule="r1"), _rule_cr("r1", nist="CM-6"))
    row = _control(out, "CM-6")
    assert row["evidence"] == "both" and row["status"] == "passing"
    assert row["operatorPassing"] == 1 and row["kubeNoobRules"]


def test_a_control_whose_only_compliance_operator_rule_was_tailored_out_is_not_passing() -> None:
    out = _assess(
        _profile("p1", ["r1"]),
        _tailored(disable=[{"name": "r1", "rationale": "x"}]),
        _scan(),
        _rule_cr("r1", nist="CM-6"),
    )
    row = _control(out, "CM-6")
    assert row["status"] == "not-evaluated" and row["operatorPassing"] == 0
    assert row["evidence"] == "kube-noob-rule"
    assert "evaluated no rule for this control" in row["note"]
    assert all(r["status"] != "satisfied" for r in out["controls"])


def test_a_control_with_no_evidence_from_either_side_is_reported_as_neither() -> None:
    # IA-2 is a control the Compliance Operator names and kube-noob has no rule for.
    out = _assess(
        _profile("p1", ["r1"]),
        _scan(),
        _check("c1", rule="r1", status="NOT-APPLICABLE"),
        _rule_cr("r1", nist="IA-2"),
    )
    row = _control(out, "IA-2")
    assert row["evidence"] == "neither" and row["status"] == "not-evaluated"
    assert "nothing in this answer is evidence about it" in row["note"]
    assert out["counts"]["controlsEvidencedByNeither"] >= 1


def test_a_control_a_failing_rule_names_is_reported_as_failing() -> None:
    out = _assess(_profile("p1", ["r1"]), _scan(), _check("c1", rule="r1", status="FAIL"), _rule_cr("r1", nist="CM-6"))
    assert _control(out, "CM-6")["status"] == "failing"


def test_other_frameworks_are_carried_on_the_rule_and_never_joined_to_nist_controls() -> None:
    rule = _rule_cr("r1", nist="CM-6")
    rule["metadata"]["annotations"][f"{cr.CONTROL_PREFIX}CIS-OCP"] = "1.2.31;1.2.32"
    rule["metadata"]["annotations"][f"{cr.CONTROL_PREFIX}SRG"] = "SRG-APP-000429-CTR-001060"
    out = cr.assess(cr.from_documents([_profile("p1", ["r1"]), _scan(), _check("c1", rule="r1"), rule]))
    row = _rule(out, "r1")
    assert row["frameworks"]["CIS-OCP"] == ["1.2.31", "1.2.32"]
    assert row["frameworks"]["SRG"] == ["SRG-APP-000429-CTR-001060"]
    assert row["controls"] == ["CM-6"]
    assert [c["control"] for c in out["controls"] if c["evidence"] != "kube-noob-rule"] == ["CM-6"]


def test_a_control_annotation_that_is_not_a_string_is_named_rather_than_dropped() -> None:
    rule = _rule_cr("r1")
    rule["metadata"]["annotations"] = {f"{cr.CONTROL_PREFIX}{cr.NIST}": ["CM-6"]}
    out = cr.assess(cr.from_documents([_profile("p1", ["r1"]), _scan(), _check("c1", rule="r1"), rule]))
    row = _rule(out, "r1")
    assert row["controls"] == []
    assert any("not a string" in n for n in row["notes"])


# -- the must-gather reader -----------------------------------------------------------------------------------------


def _mg_path(resource: str) -> str:
    return f"namespaces/openshift-compliance/{cr.GROUP}/{resource}.yaml"


def test_a_must_gather_without_compliance_directories_is_undetermined_not_no_operator(tmp_path: Path) -> None:
    node = "kind: Node\nmetadata: {name: n1}\n"
    out = cr.assess(mg_cr.collect(_bundle(tmp_path, {"cluster-scoped-resources/core/nodes/n1.yaml": node})))
    assert out["verdict"] == "undetermined" and out["rules"] == []
    reads = {s["resource"]: s for s in out["sources"]}
    assert reads["compliancecheckresults"]["state"] == "not-read"
    assert "not in this must-gather" in reads["compliancecheckresults"]["reason"]
    assert f"{cr.GROUP}/compliancecheckresults" in reads["compliancecheckresults"]["reason"]
    assert "not installed" not in json.dumps(out)


def test_a_must_gather_with_the_four_cases_reports_each_of_them(tmp_path: Path) -> None:
    files = {
        _mg_path("compliancecheckresults"): (FIXTURES / "check-results.yaml").read_text(encoding="utf-8"),
        _mg_path("profiles"): _list("ProfileList", *_only(FIXTURES / "profiles.yaml", "Profile")),
        _mg_path("tailoredprofiles"): _list(
            "TailoredProfileList", *_only(FIXTURES / "profiles.yaml", "TailoredProfile")
        ),
        _mg_path("compliancescans"): _list("ComplianceScanList", *_only(FIXTURES / "scans.yaml", "ComplianceScan")),
        _mg_path("compliancesuites"): _list("ComplianceSuiteList", *_only(FIXTURES / "suite.yaml", "ComplianceSuite")),
        _mg_path("rules"): (FIXTURES / "rules.yaml").read_text(encoding="utf-8"),
    }
    out = cr.assess(mg_cr.collect(_bundle(tmp_path, files)))
    assert out["source"] == "must-gather"
    reasons = {r["rule"]: r["reason"] for r in out["notEvaluated"]}
    assert reasons[TAILORED_OUT] == "disabled-by-tailoring"
    assert reasons[MANUAL] == "manual-by-tailoring"
    assert reasons[NOT_APPLICABLE] == "not-applicable"
    assert reasons[MISSING] == "missing-from-results"
    assert reasons[FROM_BAD_SCAN] == "scan-errored"
    assert _rule(out, PASSING)["outcome"] == "pass"
    assert out["verdict"] == "undetermined"


def _only(path: Path, kind: str) -> list[Any]:
    return [d for d in yaml.safe_load_all(path.read_text(encoding="utf-8")) if d and d.get("kind") == kind]


def test_an_unreadable_check_results_file_in_a_must_gather_is_named_and_makes_it_undetermined(tmp_path: Path) -> None:
    files = {
        _mg_path("compliancecheckresults"): "kind: [unterminated\n",
        _mg_path("profiles"): _list("ProfileList", _profile("p1", ["r1"])),
    }
    out = cr.assess(mg_cr.collect(_bundle(tmp_path, files)))
    assert out["verdict"] == "undetermined"
    assert [u["path"] for u in out["unreadable"]] == [f"{ROOT}/{_mg_path('compliancecheckresults')}"]
    assert any("file(s) could not be read" in r for r in out["undeterminedBecause"])


def test_an_empty_check_results_list_in_a_must_gather_is_a_read_of_zero(tmp_path: Path) -> None:
    files = {
        _mg_path("compliancecheckresults"): _list("ComplianceCheckResultList"),
        _mg_path("profiles"): _list("ProfileList", _profile("p1", [])),
        _mg_path("compliancescans"): _list("ComplianceScanList", _scan()),
        _mg_path("rules"): _list("RuleList"),
    }
    out = cr.assess(mg_cr.collect(_bundle(tmp_path, files)))
    reads = {s["resource"]: s for s in out["sources"]}
    assert reads["compliancecheckresults"]["state"] == "read"
    assert any("not the same as nothing to report" in r for r in out["undeterminedBecause"])


def test_a_compliance_file_outside_the_layout_is_named_rather_than_passed_over(tmp_path: Path) -> None:
    files = {
        f"namespaces/openshift-compliance/{cr.GROUP}/extra/deep/compliancecheckresults.yaml": _list(
            "ComplianceCheckResultList"
        ),
        _mg_path("profiles"): _list("ProfileList", _profile("p1", ["r1"])),
    }
    out = cr.assess(mg_cr.collect(_bundle(tmp_path, files)))
    assert any("outside the layout" in u["reason"] for u in out["unreadable"])
    assert out["verdict"] == "undetermined"


# -- the CLI --------------------------------------------------------------------------------------------------------


def test_the_cli_reports_the_four_headline_cases_from_the_fixture_suite(capsys: Any) -> None:
    assert main(["compliance", "results", "-f", str(FIXTURES)]) == 0
    text = capsys.readouterr().out
    assert "undetermined" in text.splitlines()[0]
    assert TAILORED_OUT in text and "disabled-by-tailoring" in text
    assert NOT_APPLICABLE in text and "not-applicable" in text
    assert MISSING in text and "missing-from-results" in text
    assert FROM_BAD_SCAN in text and "scan-errored" in text
    assert "pass rate withheld" in text
    assert "DOES NOT HOLD" in text


def test_require_complete_exits_five_on_a_tailored_out_suite(capsys: Any) -> None:
    assert main(["compliance", "results", "-f", str(FIXTURES), "--require-complete"]) == 5
    assert "refusing a complete verdict" in capsys.readouterr().err


def test_the_cli_json_and_yaml_carry_the_same_reasons_as_the_text(capsys: Any) -> None:
    assert main(["compliance", "results", "-f", str(FIXTURES), "--format", "json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert main(["compliance", "results", "-f", str(FIXTURES), "--format", "yaml"]) == 0
    as_yaml = yaml.safe_load(capsys.readouterr().out)
    assert out["undeterminedBecause"] == as_yaml["undeterminedBecause"]
    assert out["verdict"] == as_yaml["verdict"] == "undetermined"
    assert out["passRate"] is None and as_yaml["passRate"] is None


def test_the_cli_refuses_more_than_one_input(capsys: Any) -> None:
    assert main(["compliance", "results", "-f", str(FIXTURES), "--must-gather", "x"]) == 2
    assert "exactly one" in capsys.readouterr().err


def test_the_cli_names_a_file_in_a_directory_it_could_not_read(tmp_path: Path, capsys: Any) -> None:
    (tmp_path / "good.yaml").write_text(_yaml(_profile("p1", ["r1"]), _scan(), _check("c1", rule="r1")))
    (tmp_path / "bad.yaml").write_text("kind: [unterminated\n")
    assert main(["compliance", "results", "-f", str(tmp_path), "--format", "json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert [u["path"] for u in out["unreadable"]] == ["bad.yaml"]
    assert out["verdict"] == "undetermined"


# -- bounds ---------------------------------------------------------------------------------------------------------


def test_rules_past_the_cap_are_counted_and_never_silent(monkeypatch: pytest.MonkeyPatch) -> None:
    out = cr.assess(cr.from_documents([_profile("p1", [f"r{i}" for i in range(5)]), _scan()]), top=2)
    assert len(out["rules"]) == 2 and out["rulesTotal"] == 5 and out["notShown"] == 3
    assert "3 more rule(s) not shown" in cr.render_text(out)


def test_a_profile_listing_more_rules_than_the_cap_says_so(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cr, "MAX_RULES", 3)
    out = cr.assess(cr.from_documents([_profile("p1", [f"r{i}" for i in range(10)]), _scan()]))
    assert any("only the first 3" in r for r in out["undeterminedBecause"])
