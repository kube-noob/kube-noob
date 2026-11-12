"""A rule about a kind that is absent from the input is not evaluated, and never clean (G281).

The coverage record (`controlSummary` in an audit, `coverage` in a posture snapshot, the KSI crosswalk's columns)
counted a rule as evaluated when its check ran, whatever it ran over. `kube-noob audit -f exceptions.yaml`
therefore recorded 91 of 93 rules as checked-and-clean on a file holding one ExceptionList: no Pod was "pod
security clean", no Role was "no wildcard RBAC", no Service was "no NodePort". The product rule is older than this
fix: no subject, no verdict. A rule with nothing to look at is `notEvaluated`, with the reason "no <Kind> in the
input", in JSON, YAML, the text view, the MCP tool results, the gate, the OSCAL document and the posture report.
"""

from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Any

import pytest
import yaml

from kube_noob.audit.controls import RULE_CONTROLS
from kube_noob.audit.engine import analyze, build_context
from kube_noob.audit.model import Stage
from kube_noob.audit.rules import RULES, run_rules
from kube_noob.yamlio import load_documents

ROOT = Path(__file__).resolve().parents[1]

CONFIGMAP = """
apiVersion: v1
kind: ConfigMap
metadata: {name: c, namespace: prod}
data: {a: "1"}
"""

DEPLOYMENT = """
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: prod}
spec:
  replicas: 2
  selector: {matchLabels: {app: web}}
  template:
    metadata: {labels: {app: web}}
    spec:
      containers:
        - name: web
          image: registry.example.com/web@sha256:0000000000000000000000000000000000000000000000000000000000000000
"""

SERVICE = """
apiVersion: v1
kind: Service
metadata: {name: web, namespace: prod}
spec:
  selector: {app: web}
  ports: [{port: 80, targetPort: 8080}]
"""


def _summary(text: str, **kw: Any) -> dict[str, Any]:
    out: dict[str, Any] = analyze(text, "kubernetes", None, **kw).as_dict()["controlSummary"]
    return out


def _not_evaluated(summary: dict[str, Any]) -> dict[str, str]:
    return {row["ruleId"]: row["why"] for row in summary["rulesNotEvaluated"]}


# ---------------------------------------------------------------------------
# The engine
# ---------------------------------------------------------------------------


def test_no_pod_in_the_input_is_not_pod_security_clean() -> None:
    rep = analyze(CONFIGMAP, "kubernetes", None)
    assert "KN-S001" not in rep.evaluated_rules, "the privileged-container rule was recorded as evaluated with no pod"
    assert "KN-N004" not in rep.evaluated_rules, "the NodePort rule was recorded as evaluated with no Service"
    assert "KN-S015" not in rep.evaluated_rules, "the wildcard-RBAC rule was recorded as evaluated with no Role"
    # The rules whose subject IS in the input still run: the ConfigMap rules and the per-document validations.
    assert {"KN-S026", "KN-N010", "KN-V001", "KN-V002", "KN-V014"} <= set(rep.evaluated_rules)


def test_the_reason_names_the_absent_kind() -> None:
    rep = analyze(CONFIGMAP, "kubernetes", None)
    assert rep.not_evaluated["KN-N004"] == "no Service in the input"
    assert rep.not_evaluated["KN-S015"] == "no Role or ClusterRole in the input"
    assert rep.not_evaluated["KN-S001"].startswith("no pod spec in the input (no Pod, Deployment, ")
    assert rep.not_evaluated["KN-N014"] == "no AdminNetworkPolicy or BaselineAdminNetworkPolicy in the input"


def test_every_rule_is_evaluated_declined_or_without_a_subject_and_never_two_of_them() -> None:
    """The accounting invariant of G202, with a third bucket: the three must partition the rule set."""
    docs = load_documents(CONFIGMAP)
    ctx = build_context(docs, "kubernetes", None)
    evaluated: list[str] = []
    run_rules(ctx, None, evaluated)
    buckets = [set(evaluated), set(ctx.undecided), set(ctx.no_subject)]
    assert set().union(*buckets) == set(RULES)
    assert sum(len(b) for b in buckets) == len(RULES), "a rule landed in two buckets"
    assert len(evaluated) == len(set(evaluated))
    rep = analyze(CONFIGMAP, "kubernetes", None)
    assert set(rep.evaluated_rules) | set(rep.not_evaluated) == set(RULES)
    assert not set(rep.evaluated_rules) & set(rep.not_evaluated)


def test_a_declined_rule_keeps_its_own_reason() -> None:
    rep = analyze(DEPLOYMENT, "kubernetes", None)
    assert "KN-S036" in rep.not_evaluated and "registr" in rep.not_evaluated["KN-S036"]
    partial = analyze(DEPLOYMENT, "kubernetes", None, partial_bundle=True)
    assert "KN-C008" in partial.not_evaluated and "not passed" in partial.not_evaluated["KN-C008"]


def test_a_stage_that_was_not_requested_is_a_reason_too() -> None:
    rep = analyze(CONFIGMAP, "kubernetes", None, stages={Stage.VALIDATE})
    assert rep.not_evaluated["KN-S026"] == "stage audit was not requested"


def test_a_rule_with_several_subject_kinds_runs_on_the_present_ones_and_names_the_absent() -> None:
    """KN-S014 reads ServiceAccounts and workloads: with a Deployment alone it is evaluated, minus the kind."""
    rep = analyze(DEPLOYMENT, "kubernetes", None)
    assert "KN-S014" in rep.evaluated_rules
    assert rep.absent_subjects["KN-S014"] == ["ServiceAccount"]
    assert "KN-S014" not in rep.not_evaluated
    summary = rep.as_dict()["controlSummary"]
    assert {"ruleId": "KN-S014", "absent": ["ServiceAccount"]} in summary["rulesEvaluatedWithout"]
    # And with both kinds there, nothing is absent for it.
    sa = "---\napiVersion: v1\nkind: ServiceAccount\nmetadata: {name: web, namespace: prod}\n"
    both = analyze(DEPLOYMENT + sa, "kubernetes", None)
    assert "KN-S014" not in both.absent_subjects


def test_a_kind_of_the_same_name_in_another_group_is_not_the_subject() -> None:
    """KN-S035 reads config.openshift.io APIServer; a foreign `APIServer` is present, found and not the subject."""
    foreign = "apiVersion: example.com/v1\nkind: APIServer\nmetadata: {name: cluster}\nspec: {}\n"
    rep = analyze(foreign, "openshift", "4.20")
    assert "KN-S035" not in rep.evaluated_rules
    assert "KN-S035" in rep.not_evaluated and "config.openshift.io" in rep.not_evaluated["KN-S035"]


def test_the_record_is_the_same_bytes_whatever_the_document_order() -> None:
    docs = [CONFIGMAP, DEPLOYMENT, SERVICE, "apiVersion: v1\nkind: Namespace\nmetadata: {name: prod}\n"]
    first = None
    for seed in range(4):
        order = list(docs)
        random.Random(seed).shuffle(order)
        out = json.dumps(_summary("---\n".join(order)), sort_keys=True)
        assert first is None or out == first
        first = out


# ---------------------------------------------------------------------------
# The control summary: counts and names agree (class 13)
# ---------------------------------------------------------------------------


def test_counts_and_names_agree_per_control() -> None:
    summary = _summary(CONFIGMAP)
    reasons = _not_evaluated(summary)
    assert reasons and all(why for why in reasons.values())
    for c in summary["controls"]:
        named = c.get("notEvaluatedRules", []) + ["…"] * int(c.get("moreNotEvaluated", 0))
        assert c["notEvaluated"] == len(named), c["id"]
        assert c["notEvaluated"] == sum(1 for r in reasons if c["id"] in RULE_CONTROLS[r]), c["id"]
        for rid in c.get("notEvaluatedRules", []):
            assert rid in reasons
    # The subject-less rules are not in `clean`: AC-6's clean count is only the RBAC and pod rules that had an object.
    ac6 = next(c for c in summary["controls"] if c["id"] == "AC-6")
    assert ac6["clean"] == 0 and ac6["notEvaluated"] > 0


def test_an_exception_list_file_is_not_ninety_one_clean_rules() -> None:
    """The shipped shape: `audit -f examples/kube-noob-exceptions.yaml` recorded 91 rules as clean."""
    rep = analyze((ROOT / "examples" / "kube-noob-exceptions.yaml").read_text(), "kubernetes", None)
    clean = set(rep.evaluated_rules) - set(rep.fired_rules)
    assert len(clean) < 20, sorted(clean)
    assert all(RULES[r].stage is Stage.VALIDATE for r in clean), sorted(clean)


def test_without_reasons_the_summary_keeps_the_older_shape() -> None:
    from kube_noob.audit.controls import summary

    out = summary([], None, ["KN-V001"])
    assert "rulesNotEvaluated" not in out and "rulesEvaluatedWithout" not in out
    assert all("notEvaluatedRules" not in c for c in out["controls"])


# ---------------------------------------------------------------------------
# Every surface: text, JSON, YAML, MCP tools, gate, OSCAL, posture
# ---------------------------------------------------------------------------


def _cli(capsys: pytest.CaptureFixture[str], *args: str) -> tuple[int, str]:
    from kube_noob.cli import main

    code = main(list(args))
    return code, capsys.readouterr().out


def test_the_text_view_and_json_and_yaml_carry_the_same_record(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    f = tmp_path / "cm.yaml"
    f.write_text(CONFIGMAP, encoding="utf-8")
    code, text = _cli(capsys, "audit", "-f", str(f))
    assert code == 0, "an absent kind is not a finding and not an error: the exit code contract is unchanged"
    assert "not evaluated" in text and "no Service in the input: " in text and "KN-N004" in text
    assert "no pod spec in the input" in text and "KN-S001" in text
    code, js = _cli(capsys, "audit", "-f", str(f), "--format", "json")
    assert code == 0
    reasons = _not_evaluated(json.loads(js)["controlSummary"])
    assert reasons["KN-N004"] == "no Service in the input"
    code, ym = _cli(capsys, "audit", "-f", str(f), "--format", "yaml")
    assert code == 0
    assert _not_evaluated(yaml.safe_load(ym)["controlSummary"]) == reasons
    # The text view says how many, and the number is the JSON's.
    assert f"{len(reasons)} not evaluated" in text


def test_the_mcp_audit_tool_carries_the_record_with_and_without_an_exceptions_file() -> None:
    from kube_noob.config import Settings
    from kube_noob.toolkit import Toolkit

    kit = Toolkit(Settings())
    spec = next(s for s in kit.specs() if s.name == "audit_manifests")
    out = spec.fn(spec.model(manifests=CONFIGMAP))
    assert _not_evaluated(out["controlSummary"])["KN-S001"].startswith("no pod spec in the input")
    exceptions = (ROOT / "examples" / "kube-noob-exceptions.yaml").read_text(encoding="utf-8")
    out = spec.fn(spec.model(manifests=CONFIGMAP, exceptions=exceptions))
    assert "exceptions" in out, "the rebuild path was not taken"
    assert _not_evaluated(out["controlSummary"])["KN-S001"].startswith("no pod spec in the input")
    compact = spec.fn(spec.model(manifests=CONFIGMAP, compact=True))
    assert _not_evaluated(compact["controlSummary"])["KN-N004"] == "no Service in the input"


def test_the_ksi_crosswalk_names_the_reason_in_json_and_text(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    from kube_noob.config import Settings
    from kube_noob.toolkit import Toolkit

    kit = Toolkit(Settings())
    spec = next(s for s in kit.specs() if s.name == "fedramp_ksi")
    out = spec.fn(spec.model(manifests=CONFIGMAP))
    reasons = _not_evaluated(out)
    assert reasons["KN-S001"].startswith("no pod spec in the input")
    row = next(r for r in out["indicators"] if "KN-S001" in r.get("notEvaluatedRules", []))
    assert row["clean"] == 0 or row["notEvaluated"] >= 1
    f = tmp_path / "cm.yaml"
    f.write_text(CONFIGMAP, encoding="utf-8")
    code, text = _cli(capsys, "ksi", "-f", str(f))
    assert code == 0
    assert "no pod spec in the input" in text and "no Service in the input: " in text


def test_the_gate_publishes_the_reasons(tmp_path: Path) -> None:
    from kube_noob import gate

    out = gate.run([gate.Source(uri="cm.yaml", text=CONFIGMAP, lines=CONFIGMAP.count("\n"))], fail_on="never")
    assert _not_evaluated(out["controlSummary"])["KN-N004"] == "no Service in the input"


def test_oscal_excludes_a_control_whose_rules_had_nothing_to_look_at() -> None:
    from kube_noob import oscal

    rep = analyze(CONFIGMAP, "kubernetes", None).as_dict()
    doc = oscal.assessment_results(rep)
    result = doc["assessment-results"]["results"][0]
    selection = result["reviewed-controls"]["control-selections"][0]
    excluded = {c["control-id"] for c in selection.get("exclude-controls", [])}
    assert oscal.control_id("AC-6") in excluded, "AC-6 has no evaluated rule on a ConfigMap and must not be reviewed"
    satisfied = {f["title"] for f in result.get("findings", []) if f["target"]["status"]["state"] == "satisfied"}
    assert not any(t.startswith("AC-6 ") for t in satisfied)
    remarks = selection.get("remarks", "")
    assert "no Service in the input" in remarks


# ---------------------------------------------------------------------------
# Posture snapshots and the report built from them
# ---------------------------------------------------------------------------


def _objects(text: str) -> list[dict[str, Any]]:
    return [d for d in yaml.safe_load_all(text) if d]


def test_a_snapshot_records_why_a_rule_was_not_evaluated_and_standing_names_it() -> None:
    import datetime as dt

    from kube_noob import drift

    when = dt.datetime(2026, 11, 12, 3, 0, tzinfo=dt.UTC)
    snap = drift.snapshot(_objects(CONFIGMAP), source="manifests", taken_at=when)
    reasons = {r["ruleId"]: r["why"] for r in snap["coverage"]["notEvaluated"]}
    assert reasons["KN-S001"].startswith("no pod spec in the input")
    assert "KN-S001" not in snap["coverage"]["evaluatedRules"]
    report = drift.first_report(snap)
    standing = report["controlStanding"]
    assert _not_evaluated(standing)["KN-N004"] == "no Service in the input"
    ac6 = next(c for c in standing["controls"] if c["id"] == "AC-6")
    assert ac6["clean"] == 0 and "KN-S001" in ac6["notEvaluatedRules"]
    md = drift.markdown(report)
    assert "no Service in the input" in md and "KN-N004" in md
    from kube_noob import report_html

    page = report_html.render(report)
    assert "no Service in the input" in page and "KN-N004" in page


def test_a_kind_the_cluster_refused_is_named_as_not_read_in_the_reason() -> None:
    import datetime as dt

    from kube_noob import drift

    when = dt.datetime(2026, 11, 12, 3, 0, tzinfo=dt.UTC)
    snap = drift.snapshot(
        _objects(CONFIGMAP),
        source="live",
        taken_at=when,
        not_read=["roles in prod: forbidden (403)"],
    )
    reasons = {r["ruleId"]: r["why"] for r in snap["coverage"]["notEvaluated"]}
    assert reasons["KN-S015"] == "no Role or ClusterRole in the input (roles could not be read from the cluster)"


def test_a_diff_against_a_snapshot_from_before_this_fix_reports_nothing_regressed() -> None:
    """A snapshot written by 0.9.2 lists the subject-less rules as evaluated and carries no reasons."""
    import datetime as dt

    from kube_noob import drift

    t1 = dt.datetime(2026, 11, 11, 3, 0, tzinfo=dt.UTC)
    t2 = dt.datetime(2026, 11, 12, 3, 0, tzinfo=dt.UTC)
    old = drift.snapshot(_objects(CONFIGMAP), source="manifests", taken_at=t1)
    old["coverage"] = {
        "evaluatedRules": sorted(set(old["coverage"]["evaluatedRules"]) | {"KN-S001", "KN-N004", "KN-S015"}),
        "firedRules": old["coverage"]["firedRules"],
    }
    new = drift.snapshot(_objects(CONFIGMAP), source="manifests", taken_at=t2)
    report = drift.diff(old, new)
    assert report["findings"]["new"] == [] and report["findings"]["fixed"] == []
    assert report["objects"]["changed"] == [] and report["objects"]["removed"] == []
    # And the other way round: the old record's standing is not consulted, so nothing is "regressed" there either.
    back = drift.diff(new, old)
    assert back["findings"]["new"] == [] and back["findings"]["fixed"] == []
    assert "rulesNotEvaluated" not in (back.get("controlStanding") or {}), "an old record has no reasons to show"


def test_no_input_derived_text_reaches_a_reason() -> None:
    """Reasons are built from the kinds a rule asked for, never from what the input called itself."""
    hostile = 'apiVersion: v1\nkind: "Pod\\u202eSecret"\nmetadata: {name: x}\nspec: {}\n'
    rep = analyze(hostile + "---\n" + CONFIGMAP, "kubernetes", None)
    everything = json.dumps(rep.as_dict()["controlSummary"])
    assert "\\u202e" not in everything and "Pod" + chr(0x202E) + "Secret" not in everything
    assert rep.not_evaluated["KN-S018"] == "no Secret in the input"
