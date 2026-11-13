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
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import pytest
import yaml

from kube_noob.audit.controls import RULE_CONTROLS
from kube_noob.audit.engine import analyze, build_context
from kube_noob.audit.model import Stage
from kube_noob.audit.rules import RULES, WORKLOAD_SUBJECT, run_rules
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
    assert rep.not_evaluated["KN-S015"] == "no rbac.authorization.k8s.io ClusterRole or Role in the input"
    assert rep.not_evaluated["KN-S001"].startswith("no pod spec in the input (no Pod, Deployment, ")
    assert rep.not_evaluated["KN-N014"] == (
        "no policy.networking.k8s.io AdminNetworkPolicy or BaselineAdminNetworkPolicy in the input"
    )


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
    assert rep.not_evaluated["KN-S035"] == (
        "1 APIServer not audited (apiVersion names a group kube-noob does not know APIServer under)"
    )
    why = "apiVersion names a group kube-noob does not know APIServer under"
    assert [(r["object"], r["kind"], r["why"]) for r in rep.not_audited] == [("APIServer/cluster", "APIServer", why)]


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
    assert reasons["KN-S015"] == (
        "no rbac.authorization.k8s.io ClusterRole or Role (roles could not be read from the cluster)"
    )


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


# ---------------------------------------------------------------------------
# Review round two: declared subjects, groups, hash seeds, a rule that both declined and fired
# ---------------------------------------------------------------------------

NAMESPACE = "apiVersion: v1\nkind: Namespace\nmetadata: {name: prod}\n"
DEP_ONLY = {"KN-V011", "KN-V012", "KN-V023", "KN-N012", "KN-N013", "KN-C009", "KN-S031"}


def test_a_rule_that_reads_context_first_is_still_not_evaluated_without_its_subject() -> None:
    """The reviewer's shape: workloads read first, the subject (Service, NetworkPolicy, PDB, claim) second.

    The first version inferred the subject from what the rule asked for and called these "evaluated without
    Service": a Deployment-only file was "every Service selects a pod" clean. Subjects are declared now.
    """
    rep = analyze(DEPLOYMENT, "kubernetes", None)
    for rid in sorted(DEP_ONLY):
        assert rid not in rep.evaluated_rules, rid
        assert rid in rep.not_evaluated, rid
        assert rid not in rep.absent_subjects, rid
    assert rep.not_evaluated["KN-V011"] == "no Service in the input"
    assert rep.not_evaluated["KN-N012"] == "no networking.k8s.io NetworkPolicy in the input"
    assert rep.not_evaluated["KN-C009"] == "no policy PodDisruptionBudget in the input"
    assert rep.not_evaluated["KN-S031"] == "no resource.k8s.io ResourceClaim or ResourceClaimTemplate in the input"
    # And the other way round: a Service with no pod spec is not "every targetPort names a container port".
    svc = analyze(SERVICE, "kubernetes", None)
    for rid in ("KN-V011", "KN-V012", "KN-V023"):
        assert rid not in svc.evaluated_rules, rid
        assert svc.not_evaluated[rid].startswith("no pod spec in the input"), rid
    both = analyze(DEPLOYMENT + "---\n" + SERVICE, "kubernetes", None)
    assert {"KN-V011", "KN-V012", "KN-V023"} <= set(both.evaluated_rules)


def test_a_workload_with_no_network_policy_still_fires_on_a_whole_namespace(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """KN-N001's subject is the namespace's workloads; the NetworkPolicy is what it looks FOR, not what it is about."""
    rep = analyze(NAMESPACE + "---\n" + DEPLOYMENT, "kubernetes", None, partial_bundle=False)
    assert "KN-N001" in rep.fired_rules and "KN-N001" in rep.evaluated_rules
    assert rep.absent_subjects["KN-N001"] == ["networking.k8s.io NetworkPolicy"]
    d = tmp_path / "ns"
    d.mkdir()
    (d / "ns.yaml").write_text(NAMESPACE, encoding="utf-8")
    (d / "deployment.yaml").write_text(DEPLOYMENT, encoding="utf-8")
    code, out = _cli(capsys, "audit", "-f", str(d), "--format", "json")
    assert code == 0
    assert any(f["ruleId"] == "KN-N001" for f in json.loads(out)["findings"])


def test_every_rule_declares_its_subject_and_every_kind_it_asks_for_has_a_group() -> None:
    import re

    from kube_noob.audit.rules import ANY_OBJECT, SUBJECT_GROUPS, WORKLOAD_SUBJECT

    for rid, r in RULES.items():
        assert r.subjects, rid
        for sub in r.subjects:
            for k in sub:
                assert k in SUBJECT_GROUPS or k in (ANY_OBJECT, WORKLOAD_SUBJECT), (rid, k)
    src = (ROOT / "src" / "kube_noob" / "audit" / "rules.py").read_text(encoding="utf-8")
    asked = set(re.findall(r"by_kind\(([^)]*)\)", src))
    for call in asked:
        for kind in re.findall(r'"([A-Za-z]+)"', call):
            assert kind in SUBJECT_GROUPS, kind


@pytest.mark.parametrize(
    ("doc", "rule", "why"),
    [
        (
            "apiVersion: apps.open-cluster-management.io/v1\nkind: Subscription\nmetadata: {name: a, namespace: a}\n"
            "spec: {channel: x/y}\n",
            "KN-S034",
            "1 Subscription not audited (apiVersion names a group kube-noob does not know Subscription under)",
        ),
        (
            "apiVersion: example.com/v1\nkind: MachineConfigPool\nmetadata: {name: worker}\nspec: {paused: true}\n",
            "KN-S033",
            "1 MachineConfigPool not audited "
            "(apiVersion names a group kube-noob does not know MachineConfigPool under)",
        ),
        (
            "apiVersion: serving.knative.dev/v1\nkind: Service\nmetadata: {name: s, namespace: a}\n"
            "spec: {template: {spec: {containers: [{image: x}]}}}\n",
            "KN-N004",
            "1 Service not audited (apiVersion names a group kube-noob does not know Service under)",
        ),
    ],
)
def test_a_kind_of_another_api_group_is_not_the_subject(doc: str, rule: str, why: str) -> None:
    rep = analyze(doc + "---\n" + CONFIGMAP, "openshift", "4.20")
    assert rule not in rep.evaluated_rules and rule not in rep.fired_rules
    assert rep.not_evaluated[rule] == why
    docs = load_documents(doc)
    ctx = build_context(docs, "openshift", "4.20")
    assert ctx.by_kind(docs[0].kind) == [], "by_kind returned a document of another group"


def test_the_record_is_the_same_bytes_under_different_hash_seeds(tmp_path: Path) -> None:
    """A subject built from a frozenset gave a reason whose kind order followed PYTHONHASHSEED (D3)."""
    import os
    import subprocess
    import sys

    f = tmp_path / "dep.yaml"
    f.write_text(DEPLOYMENT + "---\n" + CONFIGMAP, encoding="utf-8")
    script = (
        "import json, sys; from kube_noob.audit.engine import analyze; "
        "r = analyze(open(sys.argv[1]).read(), 'kubernetes', None).as_dict(); "
        "sys.stdout.write(json.dumps(r['controlSummary'], sort_keys=True))"
    )
    outs = []
    for seed in ("1", "2"):
        env = {**os.environ, "PYTHONHASHSEED": seed}
        res = subprocess.run(
            [sys.executable, "-c", script, str(f)], capture_output=True, text=True, env=env, check=True
        )
        outs.append(res.stdout)
    assert outs[0] == outs[1]
    assert "DeploymentConfig" in outs[0] and "HorizontalPodAutoscaler" in outs[0]


MIXED = """
apiVersion: serving.kserve.io/v1beta1
kind: InferenceService
metadata: {name: i, namespace: ns, labels: {app: m}}
spec:
  predictor:
    containers:
      - {name: p, image: x}
---
apiVersion: v1
kind: Service
metadata: {name: s-undecided, namespace: ns}
spec:
  selector: {runtime: kserve-sklearn}
  ports: [{port: 80}]
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: other}
spec:
  replicas: 1
  selector: {matchLabels: {app: web}}
  template:
    metadata: {labels: {app: web}}
    spec:
      containers:
        - {name: web, image: x}
---
apiVersion: v1
kind: Service
metadata: {name: s-wrong, namespace: other}
spec:
  selector: {app: nothing}
  ports: [{port: 80}]
"""


def test_a_rule_that_declined_on_one_object_and_fired_on_another_is_evaluated_not_both() -> None:
    """KN-V011 declines on the kserve Service and fires on the other: it ran. It is in `firedRules`, and so
    it is not in `notEvaluated` -- a posture snapshot carried it in both lists (D4). The decline stays as a note."""
    import datetime as dt

    from kube_noob import drift

    rep = analyze(MIXED, "kubernetes", None)
    assert "KN-V011" in rep.fired_rules and "KN-V011" in rep.evaluated_rules
    assert "KN-V011" not in rep.not_evaluated
    assert any("KN-V011" in a and "declined" in a for a in rep.assumptions), rep.assumptions
    snap = drift.snapshot(_objects(MIXED), source="manifests", taken_at=dt.datetime(2026, 11, 12, tzinfo=dt.UTC))
    listed = {r["ruleId"] for r in snap["coverage"]["notEvaluated"]}
    assert "KN-V011" in snap["coverage"]["firedRules"] and "KN-V011" not in listed
    assert not listed & set(snap["coverage"]["firedRules"])
    assert not listed & set(snap["coverage"]["evaluatedRules"])


def test_the_gate_summary_text_and_html_carry_a_coverage_line() -> None:
    """A clean gate over a Deployment-only change must not read as "every Service rule passed" (D7, G221)."""
    from kube_noob import gate, report_html

    out = gate.run([gate.Source(uri="dep.yaml", text=DEPLOYMENT, lines=DEPLOYMENT.count("\n"))], fail_on="never")
    md = gate.markdown(out)
    assert "rules evaluated, " in md and "not evaluated: no Service in the input (" in md
    page = report_html.render(out)
    assert "Not evaluated" in page and "no Service in the input (" in page


def test_the_ksi_html_says_not_evaluated_and_why() -> None:
    """The KSI page called every unevaluated rule "Declined to decide" and gave no reason (D6)."""
    from kube_noob import report_html
    from kube_noob.config import Settings
    from kube_noob.toolkit import Toolkit

    kit = Toolkit(Settings())
    spec = next(s for s in kit.specs() if s.name == "fedramp_ksi")
    page = report_html.render(spec.fn(spec.model(manifests=CONFIGMAP)))
    assert "Declined to decide" not in page
    assert "Not evaluated: " in page
    assert "no Service in the input" in page and "KN-N004" in page


def test_a_snapshot_names_the_resource_for_a_grouped_kind_the_cluster_refused() -> None:
    import datetime as dt

    from kube_noob import drift

    when = dt.datetime(2026, 11, 12, 3, 0, tzinfo=dt.UTC)
    snap = drift.snapshot(
        _objects(CONFIGMAP), source="live", taken_at=when, not_read=["networkpolicies in prod: forbidden"]
    )
    reasons = {r["ruleId"]: r["why"] for r in snap["coverage"]["notEvaluated"]}
    assert reasons["KN-N007"] == (
        "no networking.k8s.io NetworkPolicy (networkpolicies could not be read from the cluster)"
    )


# ---------------------------------------------------------------------------
# Review 3: a group the rules did not know, and no group at all (G281)
# ---------------------------------------------------------------------------

# The shape the in-cluster backend returns: API list items carry NO apiVersion of their own, and `collect_live`
# sets only `kind`. Refusing these as "a kind of another group" evaluated three rules on a live cluster.
LIVE_KINDS: dict[str, str] = {
    "Pod": "pods", "Service": "services", "Deployment": "deployments", "Ingress": "ingresses", "Job": "jobs",
    "Role": "roles", "ClusterServiceVersion": "clusterserviceversions", "Subscription": "subscriptions",
}  # fmt: skip

LIVE_NOAPI: list[dict[str, Any]] = [
    {
        "kind": "Deployment",
        "metadata": {"name": "web", "namespace": "shop"},
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": {"app": "web"}},
            "template": {
                "metadata": {"labels": {"app": "web"}},
                "spec": {"containers": [{"name": "w", "image": "x:latest", "securityContext": {"privileged": True}}]},
            },
        },
    },
    {
        "kind": "Role",
        "metadata": {"name": "r", "namespace": "shop"},
        "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}],
    },
    {
        "kind": "NetworkPolicy",
        "metadata": {"name": "np", "namespace": "shop"},
        "spec": {"podSelector": {}, "ingress": [{}]},
    },
    {"kind": "Namespace", "metadata": {"name": "shop"}},
]

# What 0.9.2 reported for LIVE_NOAPI, measured with `kube_noob.drift.snapshot(objs, source="live")` on main.
LIVE_NOAPI_FIRED = {
    "KN-C001", "KN-C002", "KN-C004", "KN-C005", "KN-C007", "KN-C016", "KN-N007", "KN-S001", "KN-S002",
    "KN-S003", "KN-S006", "KN-S007", "KN-S008", "KN-S012", "KN-S014", "KN-S015", "KN-S032", "KN-V001", "KN-V002",
}  # fmt: skip


def test_an_object_with_no_api_version_is_an_unknown_group_not_a_contradiction() -> None:
    """A live snapshot's objects have no apiVersion; every non-core rule had stopped evaluating them (N1)."""
    from kube_noob import drift
    from kube_noob.audit.rules import kind_in_group

    doc = load_documents("kind: Deployment\nmetadata: {name: a, namespace: b}\nspec: {}\n")[0]
    assert doc.api_version == ""
    assert kind_in_group(doc, "Deployment")
    foreign = load_documents("apiVersion: example.com/v1\nkind: Deployment\nmetadata: {name: a}\n")[0]
    assert not kind_in_group(foreign, "Deployment")

    snap = drift.snapshot(LIVE_NOAPI, source="live")
    fired = {f["ruleId"] for f in snap["findings"]}
    assert fired == LIVE_NOAPI_FIRED
    reasons = {r["ruleId"]: r["why"] for r in snap["coverage"]["notEvaluated"]}
    for rid in ("KN-S001", "KN-S015", "KN-N007", "KN-S012", "KN-C007"):
        assert rid not in reasons, (rid, reasons.get(rid))
        assert rid in snap["coverage"]["evaluatedRules"]


class _NoApiVersionBackend:
    """The in-cluster backend's shape: a `<Kind>List` whose items carry no apiVersion of their own."""

    def __init__(self, items: dict[str, list[dict[str, Any]]]) -> None:
        self.items = items

    def get(self, resource: str, namespace: str | None = None, selector: str | None = None) -> dict[str, Any]:
        from kube_noob.debug.cluster import ALLOWED_RESOURCES

        kind = {v: k for k, v in LIVE_KINDS.items()}.get(resource)
        gv = ALLOWED_RESOURCES[resource].group_version if resource in ALLOWED_RESOURCES else "v1"
        items = [dict(i) for i in self.items.get(resource, [])]
        return {"kind": f"{kind}List" if kind else "List", "apiVersion": gv, "items": items}


def test_collect_live_stamps_the_api_version_the_resource_was_listed_under() -> None:
    """The record is complete on its own: a stored object says which API it came from, as kubectl's output does."""
    from kube_noob import drift
    from kube_noob.debug.cluster import ALLOWED_RESOURCES

    backend = _NoApiVersionBackend(
        {
            "deployments": [{"metadata": {"name": "web", "namespace": "shop"}, "spec": {}}],
            # A backend that already says (kubectl fills apiVersion in): its own word is kept.
            "ingresses": [{"apiVersion": "extensions/v1beta1", "metadata": {"name": "i", "namespace": "shop"}}],
            # An empty, null or non-string apiVersion is not the backend's word: the stamp wins (review 4, R8).
            "services": [{"apiVersion": "", "metadata": {"name": "s", "namespace": "shop"}}],
            "pods": [{"apiVersion": None, "metadata": {"name": "p", "namespace": "shop"}}],
            "jobs": [{"apiVersion": 7, "metadata": {"name": "j", "namespace": "shop"}}],
        }
    )
    objects, not_read = drift.collect_live(backend, ["shop"])
    assert not_read == []
    by_kind = {o["kind"]: o for o in objects}
    assert by_kind["Deployment"]["apiVersion"] == ALLOWED_RESOURCES["deployments"].group_version == "apps/v1"
    assert by_kind["Ingress"]["apiVersion"] == "extensions/v1beta1"
    assert by_kind["Service"]["apiVersion"] == "v1"
    assert by_kind["Pod"]["apiVersion"] == "v1"
    assert by_kind["Job"]["apiVersion"] == "batch/v1"


def test_a_list_the_structural_check_refuses_is_a_failed_read_and_never_stamped() -> None:
    """`list_items` (G279) runs first: a response with no `kind` is not a list of the resource, so it lands in
    `notRead` named, and nothing in it is stamped or stored (review 4, R2)."""
    from kube_noob import attack_paths as ap
    from kube_noob import drift

    class Backend:
        def get(self, resource: str, namespace: str | None = None, selector: str | None = None) -> dict[str, Any]:
            if resource == "deployments":  # no kind: a proxy's own JSON, not the API server's list
                return {"items": [{"metadata": {"name": "web", "namespace": namespace}, "spec": {}}]}
            return {"kind": "List", "apiVersion": "v1", "items": []}

    objects, not_read = drift.collect_live(Backend(), ["shop"])
    assert objects == []
    assert any(e.startswith("deployments in shop: ") and "no kind" in e for e in not_read), not_read
    inv = ap.collect_live(Backend(), ["shop"])
    assert inv.of("Deployment") == []
    assert any(e.startswith("deployments in shop: ") and "no kind" in e for e in inv.not_read), inv.not_read


LEGACY = """
apiVersion: extensions/v1beta1
kind: Deployment
metadata: {name: web, namespace: shop}
spec:
  replicas: 1
  template:
    metadata: {labels: {app: web}}
    spec:
      containers:
        - name: web
          image: web:latest
          securityContext: {privileged: true}
---
apiVersion: extensions/v1beta1
kind: Ingress
metadata: {name: web, namespace: shop}
spec:
  rules:
    - host: web.example.com
      http:
        paths:
          - path: /
            backend: {serviceName: web, servicePort: 80}
---
apiVersion: extensions/v1beta1
kind: NetworkPolicy
metadata: {name: allow-all, namespace: shop}
spec:
  podSelector: {}
  ingress:
    - {}
"""

# `kube-noob audit -f <dir of LEGACY> --version 1.15 --format json` on main: the fired set.
LEGACY_FIRED_MAIN = {
    "KN-C001", "KN-C002", "KN-C004", "KN-C005", "KN-C007", "KN-N003", "KN-N007", "KN-S001", "KN-S002", "KN-S003",
    "KN-S006", "KN-S007", "KN-S008", "KN-S012", "KN-S014", "KN-V006", "KN-V010",
}  # fmt: skip


def test_subject_groups_know_every_group_a_kind_was_ever_served_under() -> None:
    """Derived from the removed-API history, not hand-listed: `extensions/v1beta1 Deployment` is a Deployment."""
    from kube_noob.audit.rules import SUBJECT_GROUPS, subject_label
    from kube_noob.catalog import REMOVED_APIS, api_group

    for removed in REMOVED_APIS:
        if removed.kind in SUBJECT_GROUPS:
            assert api_group(removed.group_version) in SUBJECT_GROUPS[removed.kind], removed
    assert {"apps", "extensions"} <= SUBJECT_GROUPS["Deployment"]
    assert {"networking.k8s.io", "extensions"} <= SUBJECT_GROUPS["Ingress"]
    # The label names the group the kind is served in today, not its history.
    assert subject_label(("Deployment",)) == "apps Deployment"
    assert subject_label(("NetworkPolicy",)) == "networking.k8s.io NetworkPolicy"


def test_a_legacy_group_bundle_is_audited_as_main_audited_it(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`extensions/v1beta1` is Kubernetes' own history, not somebody else's kind (N2)."""
    d = tmp_path / "legacy"
    d.mkdir()
    (d / "old.yaml").write_text(LEGACY, encoding="utf-8")
    code, out = _cli(capsys, "audit", "-f", str(d), "--version", "1.15", "--format", "json")
    assert code == 1
    report = json.loads(out)
    assert {f["ruleId"] for f in report["findings"]} == LEGACY_FIRED_MAIN
    code, _ = _cli(capsys, "audit", "-f", str(d), "--version", "1.15", "--fail-on", "high")
    assert code == 1


def test_the_legacy_fixture_keeps_its_findings_and_gains_no_false_service_finding() -> None:
    """Dropping the Deployment while reading the Service made KN-V011 say the Service selects nothing."""
    text = (ROOT / "tests" / "fixtures" / "legacy-bundle.yaml").read_text(encoding="utf-8")
    rep = analyze(text, "kubernetes", None)
    assert {"KN-C001", "KN-C002", "KN-C009", "KN-C010", "KN-C014", "KN-N003", "KN-V010"} <= set(rep.fired_rules)
    assert "KN-V011" in rep.evaluated_rules and "KN-V011" not in rep.fired_rules
    assert rep.evaluated_rules.count("KN-V011") == 1


FOREIGN_DEPLOYMENT = """
apiVersion: example.com/v1
kind: Deployment
metadata: {name: web, namespace: prod}
spec:
  replicas: 1
  selector: {matchLabels: {app: web}}
  template:
    metadata: {labels: {app: web}}
    spec:
      containers:
        - name: w
          image: x:latest
          securityContext: {privileged: true}
"""

OTHER_DEPLOYMENT = DEPLOYMENT.replace("name: web", "name: other").replace("app: web", "app: other")


def test_a_workload_of_a_group_the_rules_do_not_know_is_named_and_decides_nothing_against_it() -> None:
    """The neighbour of N2 (class 21): a Deployment in `example.com/v1` beside a real one and a Service.

    It is right not to read it (another group's schema is another object), and wrong to say nothing: its
    privileged container produced no finding and no word, while KN-V011 told the reader the Service it fronts
    has no endpoints. The subject check and the reader agree; the rule that would conclude from the gap declines.
    """
    rep = analyze(FOREIGN_DEPLOYMENT + "---" + OTHER_DEPLOYMENT + "---" + SERVICE, "kubernetes", None)
    assert "KN-V011" not in rep.fired_rules
    assert rep.not_evaluated["KN-V011"] == (
        "a Deployment was not audited (apiVersion names a group kube-noob does not know Deployment under), so whether "
        "its pods are the ones selected cannot be decided"
    )
    assert any("example.com" in a and "Deployment/prod/web" in a and "not audited" in a for a in rep.assumptions), (
        rep.assumptions
    )
    assert [(r["object"], r["kind"], r["why"]) for r in rep.not_audited] == [
        ("Deployment/prod/web", "Deployment", "apiVersion names a group kube-noob does not know Deployment under")
    ]
    # A NetworkPolicy's "selects nothing" is the same conclusion from the same gap.
    netpol = (
        "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata: {name: web, namespace: prod}\n"
        "spec: {podSelector: {matchLabels: {app: web}}, policyTypes: [Ingress]}\n"
    )
    rep2 = analyze(FOREIGN_DEPLOYMENT + "---" + OTHER_DEPLOYMENT + "---" + netpol, "kubernetes", None)
    assert "KN-N012" not in rep2.fired_rules and "KN-N012" in rep2.not_evaluated


CRONJOB_ONLY = """
apiVersion: v1
kind: Namespace
metadata: {name: shop}
---
apiVersion: batch/v1
kind: CronJob
metadata: {name: cj, namespace: shop}
spec:
  schedule: "* * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: Never
          containers:
            - name: c
              image: registry.example.com/c@sha256:0000000000000000000000000000000000000000000000000000000000000000
"""

POD_ONLY = """
apiVersion: v1
kind: Pod
metadata: {name: p, namespace: shop}
spec:
  containers:
    - name: c
      image: registry.example.com/c@sha256:0000000000000000000000000000000000000000000000000000000000000000
"""


def test_v010_declares_the_kinds_it_judges_not_every_pod_spec() -> None:
    """KN-V010 reads only the four apps/v1 kinds; on a CronJob or a Pod it was evaluated and clean (N3)."""
    assert RULES["KN-V010"].subjects == (("DaemonSet", "Deployment", "ReplicaSet", "StatefulSet"),)
    for text in (CRONJOB_ONLY, POD_ONLY):
        rep = analyze(text, "kubernetes", None, partial_bundle=False)
        assert "KN-V010" not in rep.evaluated_rules
        assert rep.not_evaluated["KN-V010"] == "no apps DaemonSet, Deployment, ReplicaSet or StatefulSet in the input"


def test_n001_declares_the_long_running_kinds_it_fires_for() -> None:
    """KN-N001 fires for long-running workloads and Pods only; a CronJob-only namespace was 'evaluated' (N4)."""
    from kube_noob.audit.podspec import LONG_RUNNING_EMBEDDED_KINDS, LONG_RUNNING_KINDS

    assert RULES["KN-N001"].subjects == (tuple(sorted(LONG_RUNNING_KINDS | LONG_RUNNING_EMBEDDED_KINDS | {"Pod"})),)
    rep = analyze(CRONJOB_ONLY, "kubernetes", None, partial_bundle=False)
    assert "KN-N001" not in rep.evaluated_rules and "KN-N001" in rep.not_evaluated
    assert "no apps DaemonSet" in rep.not_evaluated["KN-N001"] and "Pod" in rep.not_evaluated["KN-N001"]
    pod = analyze(NAMESPACE + "---" + POD_ONLY.replace("namespace: shop", "namespace: prod"), "kubernetes", None)
    assert "KN-N001" in pod.fired_rules


def test_st001_declares_the_storage_class_it_reads() -> None:
    assert RULES["KN-ST001"].context == ("StorageClass",)


#: Calls inside a rule body that read a kind: the method or function name, and which argument carries the kind
#: (a string, a tuple of strings, or `*` for "every positional argument"). `workloads`, `refused_workloads` and
#: `refused_subject_group` read pod specs rather than one kind, and count as asking for the pod-spec subject.
_KIND_READERS: dict[str, int | str] = {"by_kind": "*", "has_subject": 0, "kind_in_group": 1}
_POD_SPEC_READERS = frozenset(
    {"workloads", "refused_workloads", "unread_pod_spec_docs", "refused_subject_group", "refusal"}
)


def _kinds_asked(tree: Any, names: Iterable[str]) -> dict[str, set[str]]:
    """Every kind each named module-level function reads (through the helpers it calls, transitively).

    A literal is taken as written; a starred name (`*REPLICATED_KINDS`), an indexed constant (`ADMIN_TIER_KINDS[0]`)
    and a loop variable (`for kind in _CLAIM_SOURCE_KINDS.values()`) are resolved against the module's own
    constants. Reads through `has_subject((k, ...))` and `kind_in_group(d, k)` count like `by_kind(k)`, so a helper
    that sidesteps `by_kind` cannot read an undeclared kind unnoticed.
    """
    import ast

    from kube_noob.audit import rules as rules_module

    funcs: dict[str, ast.FunctionDef] = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}

    def constant(expr: ast.expr) -> Any:
        return eval(ast.unparse(expr), vars(rules_module))  # noqa: S307 -- the module's own source, not input

    def loop_values(fn: ast.FunctionDef, name: str) -> set[str]:
        for loop in ast.walk(fn):
            if not isinstance(loop, ast.For):
                continue
            if isinstance(loop.target, ast.Name) and loop.target.id == name:
                return {str(v) for v in constant(loop.iter)}
            if isinstance(loop.target, ast.Tuple):
                for i, elt in enumerate(loop.target.elts):
                    if isinstance(elt, ast.Name) and elt.id == name:
                        return {str(item[i]) for item in constant(loop.iter)}
        raise AssertionError(f"{fn.name}: {name} is not a literal, a starred constant or a loop variable")

    def kinds_of(fn: ast.FunctionDef, arg: ast.expr) -> set[str]:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            return {arg.value}
        if isinstance(arg, ast.Tuple | ast.List | ast.Set):
            return {k for elt in arg.elts for k in kinds_of(fn, elt)}
        if isinstance(arg, ast.Starred):
            return {str(v) for v in constant(arg.value)}
        if isinstance(arg, ast.Name) and arg.id in vars(rules_module):
            value = constant(arg)
            return {value} if isinstance(value, str) else {str(v) for v in value}
        if isinstance(arg, ast.Name):
            return loop_values(fn, arg.id)
        value = constant(arg)  # `ADMIN_TIER_KINDS[0]`: an index into a module constant
        assert isinstance(value, str), f"{fn.name}: {ast.unparse(arg)} is not one kind"
        return {value}

    def kinds_in(fn: ast.FunctionDef, seen: set[str]) -> set[str]:
        if fn.name in seen:
            return set()
        seen.add(fn.name)
        out: set[str] = set()
        for node in ast.walk(fn):
            if not isinstance(node, ast.Call):
                continue
            name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
            if name in _KIND_READERS:
                which = _KIND_READERS[name]
                args = node.args if which == "*" else node.args[int(which) : int(which) + 1]
                for arg in args:
                    out |= kinds_of(fn, arg)
            elif name in _POD_SPEC_READERS:
                out.add(WORKLOAD_SUBJECT)
            elif isinstance(node.func, ast.Name) and node.func.id in funcs:
                out |= kinds_in(funcs[node.func.id], seen)
            elif any(isinstance(a, ast.Name) and a.id == "ctx" for a in node.args):
                # A helper outside this module given the context could read any kind: not classified (R7).
                out.add(f"?{fn.name} passes ctx to {ast.unparse(node.func)}, which this walk does not follow")
        for node in ast.walk(fn):
            # A traversal of `ctx.docs` by hand, a `.kind ==` comparison or a `.get("kind")` read selects kinds
            # this walk cannot name: loud, never an empty set (review 4, R7).
            if isinstance(node, ast.Attribute) and node.attr == "docs" and ast.unparse(node.value) == "ctx":
                out.add(f"?{fn.name} walks ctx.docs")
            if isinstance(node, ast.Compare) and isinstance(node.left, ast.Attribute) and node.left.attr == "kind":
                # `d.kind == "Route"` / `d.kind in KINDS` selects kinds: resolved like a `by_kind` argument, or loud.
                for side in node.comparators:
                    if isinstance(side, ast.Name) and side.id == "WORKLOAD_KINDS":
                        out.add(WORKLOAD_SUBJECT)  # membership in the pod-spec kinds is the pod-spec subject
                        continue
                    try:
                        out |= kinds_of(fn, side)
                    except Exception:  # noqa: BLE001 -- the walk reports, the assertion below decides
                        # A runtime value (`ref.get("kind")`, another object's kind) is a match between two
                        # objects already read, not a selection; a name or literal that will not resolve is loud.
                        if not any(isinstance(n, ast.Call) for n in ast.walk(side)):
                            out.add(f"?{fn.name} compares .kind with {ast.unparse(side)}")
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "get"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and node.args[0].value == "kind"
                and ast.unparse(node.func.value).endswith(".data")  # a document's own kind, not a subject's
            ):
                out.add(f"?{fn.name} reads .get('kind')")
        return out

    return {name: kinds_in(funcs[name], set()) for name in names}


def _by_kind_calls_per_rule() -> dict[str, set[str]]:
    """Every kind each rule's check reads, by rule id (see `_kinds_asked`)."""
    import ast

    src = (ROOT / "src" / "kube_noob" / "audit" / "rules.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    checks: dict[str, str] = {}
    for fn in (n for n in tree.body if isinstance(n, ast.FunctionDef)):
        for deco in fn.decorator_list:
            if isinstance(deco, ast.Call) and isinstance(deco.func, ast.Name) and deco.func.id == "rule":
                rid = deco.args[0]
                assert isinstance(rid, ast.Constant)
                checks[str(rid.value)] = fn.name
    asked = _kinds_asked(tree, checks.values())
    return {rid: asked[name] for rid, name in checks.items()}


def test_every_kind_a_rule_asks_by_kind_for_is_declared_as_its_subject_or_context() -> None:
    """A rule that reads a kind it did not declare has a half the record cannot name when it is absent (N6)."""
    from kube_noob.audit.rules import SUBJECT_GROUPS, WORKLOAD_KINDS

    by_rule = _by_kind_calls_per_rule()
    assert by_rule.keys() == RULES.keys()
    from kube_noob.audit.rules import ANY_OBJECT

    for rid, asked in by_rule.items():
        r = RULES[rid]
        declared = {k for sub in r.subjects for k in sub} | set(r.context)
        unknown = sorted(k[1:] for k in asked if k.startswith("?"))
        if ANY_OBJECT in declared:
            continue  # it reads every object by declaration; what it compares kinds to is a refinement
        assert not unknown, f"unknown pattern in {rid}: {'; '.join(unknown)}"
        for kind in asked:
            if kind.startswith("?"):
                continue
            if kind == WORKLOAD_SUBJECT:
                # `workloads()` is the pod-spec subject, or a declared subset of its kinds (KN-V010, KN-N001).
                assert WORKLOAD_SUBJECT in declared or declared & set(WORKLOAD_KINDS), f"{rid} reads workloads"
                continue
            assert kind in SUBJECT_GROUPS, (rid, kind)
            assert kind in declared, f"{rid} reads {kind} and declares it as neither subject nor context"


def test_the_pod_spec_kinds_are_spelled_out_inside_an_alternative_label_too() -> None:
    """ "no networking.k8s.io Ingress or pod spec in the input" sent a reader looking for a kind called pod spec."""
    from kube_noob.audit.rules import WORKLOAD_SUBJECT, subject_label, subject_reason

    why = subject_reason([subject_label(("Ingress", WORKLOAD_SUBJECT))])
    assert why.startswith("no networking.k8s.io Ingress or pod spec in the input (no Pod, Deployment")
    why = subject_reason([subject_label(("Secret",)), subject_label((WORKLOAD_SUBJECT, "ServiceAccount"))])
    assert "(no Pod, Deployment" in why
    # A kind whose name merely contains the letters is not expanded.
    assert "(no Pod" not in subject_reason(["Service"])


def test_the_first_diff_after_stamping_names_api_version_as_the_one_changed_field() -> None:
    """A snapshot the in-cluster backend took before this release has no apiVersion on its objects; the first
    diff after upgrading reports that field, and only that field, as changed on each of them -- said here so the
    CHANGELOG sentence about it is held by a test, not a hope."""
    import datetime as dt

    from kube_noob import drift

    when = dt.datetime(2026, 11, 12, 3, 0, tzinfo=dt.UTC)
    before = drift.snapshot(LIVE_NOAPI, source="live", taken_at=when)
    stamped = [{"apiVersion": "apps/v1", **o} if o["kind"] == "Deployment" else o for o in LIVE_NOAPI]
    after = drift.snapshot(stamped, source="live", taken_at=when + dt.timedelta(days=1))
    report = drift.diff(before, after)
    objects, findings = report["objects"], report["findings"]
    assert [(row["object"], row["fields"]) for row in objects["changed"]] == [("Deployment/shop/web", ["apiVersion"])]
    assert objects["unchanged"] == len(LIVE_NOAPI) - 1
    # The only findings that go: "missing apiVersion" (KN-V001/V002), which the stamped record no longer earns.
    assert findings["new"] == []
    assert {f["ruleId"] for f in findings["fixed"]} == {"KN-V001", "KN-V002"}


def test_the_oscal_numbers_the_changelog_quotes_for_a_deployment_only_directory() -> None:
    """`kube-noob audit -f <dir holding DEPLOYMENT> --format json --oscal`: 9 of 30 controls excluded, 7 satisfied
    (0.9.2 excluded none and reported 16 satisfied). The CHANGELOG sentence is measured here, not remembered."""
    from kube_noob import oscal
    from kube_noob.audit.controls import RULE_CONTROLS

    rep = analyze(DEPLOYMENT, "kubernetes", None, partial_bundle=False).as_dict()
    result = oscal.assessment_results(rep)["assessment-results"]["results"][0]
    selection = result["reviewed-controls"]["control-selections"][0]
    assert len({c for cs in RULE_CONTROLS.values() for c in cs}) == 30
    assert len(selection["exclude-controls"]) == 9
    assert sum(1 for f in result["findings"] if f["target"]["status"]["state"] == "satisfied") == 7


def test_the_text_headline_names_only_controls_with_findings_and_lists_the_unevaluated_apart(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`NIST SP 800-53 controls with findings: CM-7 (5), ... AU-2 (0)` listed every touched control with its count,
    so a control whose only rule was not evaluated read as checked-and-zero in the one line a reader scans, while
    the JSON said notEvaluated: 1 (class 6/13, review 3)."""
    import re

    _, out = _cli(capsys, "audit", "-f", str(ROOT / "examples" / "insecure-deployment.yaml"), "--format", "json")
    controls = json.loads(out)["controlSummary"]["controls"]
    _, text = _cli(capsys, "audit", "-f", str(ROOT / "examples" / "insecure-deployment.yaml"))
    headline = next(line for line in text.splitlines() if line.startswith("NIST SP 800-53 controls with findings:"))
    named = set(re.findall(r"([A-Z]{2}-\d+(?:\(\d+\))?) \(", headline))
    assert named == {c["id"] for c in controls if c["findings"] > 0}
    assert "(0)" not in headline
    not_evaluated_line = next(line for line in text.splitlines() if line.startswith("controls not evaluated"))
    # A ConfigMap alone has no finding at all: no headline, and the not-evaluated line still names the controls.
    cm = tmp_path / "cm.yaml"
    cm.write_text(CONFIGMAP, encoding="utf-8")
    _, quiet = _cli(capsys, "audit", "-f", str(cm))
    assert "controls with findings" not in quiet and "controls not evaluated" in quiet
    with_unevaluated = {c["id"]: c for c in controls if c.get("notEvaluated")}
    assert set(re.findall(r"([A-Z]{2}-\d+(?:\(\d+\))?) \(", not_evaluated_line)) == set(with_unevaluated)
    for cid, c in with_unevaluated.items():
        for rid in c["notEvaluatedRules"]:
            assert rid in not_evaluated_line, (cid, rid)
        if c.get("clean"):
            assert f"{c['clean']} clean" in not_evaluated_line, cid  # partly clean, partly unevaluated: both said
    assert "AU-2 (KN-S035" in not_evaluated_line


# ---------------------------------------------------------------------------
# Review 4 preparation: OpenShift 3.x legacy `v1`, apiVersion stamping everywhere, the AST test widened
# ---------------------------------------------------------------------------

OCP3 = """
apiVersion: v1
kind: Route
metadata: {name: web, namespace: shop}
spec:
  to: {kind: Service, name: web}
---
apiVersion: v1
kind: DeploymentConfig
metadata: {name: web, namespace: shop}
spec:
  replicas: 1
  template:
    metadata: {labels: {app: web}}
    spec:
      containers:
        - name: web
          image: web:latest
          securityContext: {privileged: true}
"""

# `analyze(OCP3, "openshift", "4.20", partial_bundle=False)` on main: the fired set.
OCP3_FIRED_MAIN = {
    "KN-C001", "KN-C002", "KN-C004", "KN-C005", "KN-C007", "KN-N001", "KN-N002", "KN-S001", "KN-S002", "KN-S003",
    "KN-S006", "KN-S007", "KN-S008", "KN-S012", "KN-S014", "KN-V002", "KN-V008",
}  # fmt: skip


def test_openshift_three_legacy_v1_kinds_are_read_not_refused() -> None:
    """`oc get -o yaml` on OpenShift 3.x wrote `apiVersion: v1` for DeploymentConfig, Route, BuildConfig, ...: that
    is OpenShift's own history (openshift/api release-3.11 <group>/v1/legacy.go), not a kind of another group.
    Refused-with-a-note was a coverage regression on the most common shape in old OpenShift repositories."""
    from kube_noob.audit.rules import CURRENT_GROUPS, SUBJECT_GROUPS, kind_in_group
    from kube_noob.catalog import LEGACY_OPENSHIFT_V1

    for kind, group in LEGACY_OPENSHIFT_V1.items():
        assert group.endswith(".openshift.io"), (kind, group)
        if kind in CURRENT_GROUPS:
            assert "" in SUBJECT_GROUPS[kind] and group in SUBJECT_GROUPS[kind], kind
    for kind in ("DeploymentConfig", "Route", "BuildConfig", "Build", "ImageStream", "ImageStreamTag", "Template",
                 "Project", "SecurityContextConstraints", "ClusterResourceQuota"):  # fmt: skip
        assert kind in LEGACY_OPENSHIFT_V1, kind
        assert "" in SUBJECT_GROUPS[kind], kind
    # Exactly those kinds, and no others: a core `v1 Deployment` is still not a Deployment.
    assert "" not in SUBJECT_GROUPS["Deployment"] and "" not in SUBJECT_GROUPS["Ingress"]
    v1_dep = load_documents("apiVersion: v1\nkind: Deployment\nmetadata: {name: a, namespace: b}\nspec: {}\n")[0]
    assert not kind_in_group(v1_dep, "Deployment")

    rep = analyze(OCP3, "openshift", "4.20", partial_bundle=False)
    assert set(rep.fired_rules) == OCP3_FIRED_MAIN
    assert "KN-V002" in rep.fired_rules  # the API is still the removed one: say so, and read the object
    assert not any("not audited" in a for a in rep.assumptions), rep.assumptions
    # The reason label still names today's group, never the input's apiVersion.
    rep_route_only = analyze(OCP3.split("---", maxsplit=1)[0], "openshift", "4.20")
    assert rep_route_only.not_evaluated["KN-S001"].startswith("no pod spec in the input")


def test_attack_paths_collect_live_stamps_the_api_version_the_resource_was_listed_under() -> None:
    from kube_noob import attack_paths as ap

    backend = _NoApiVersionBackend(
        {
            "pods": [{"metadata": {"name": "p", "namespace": "shop"}, "spec": {"containers": [{"name": "c"}]}}],
            "ingresses": [{"apiVersion": "networking.k8s.io/v1beta1", "metadata": {"name": "i", "namespace": "shop"}}],
        }
    )
    inv = ap.collect_live(backend, ["shop"])
    assert inv.of("Pod")[0]["apiVersion"] == "v1"
    assert inv.of("Ingress")[0]["apiVersion"] == "networking.k8s.io/v1beta1"  # the backend's own word is kept


def test_operators_collect_live_stamps_the_api_version_the_resource_was_listed_under() -> None:
    from kube_noob import operators

    csv = {"metadata": {"name": "etcd.v1", "namespace": "shop"}, "spec": {"version": "1.0.0"}, "status": {}}
    sub = {"apiVersion": "operators.coreos.com/v1alpha1", "metadata": {"name": "etcd", "namespace": "shop"}, "spec": {}}
    c = operators.collect_live(
        _NoApiVersionBackend({"clusterserviceversions": [csv], "subscriptions": [sub]}), ["shop"]
    )
    assert c.objects["clusterserviceversions"][0].doc["apiVersion"] == "operators.coreos.com/v1alpha1"
    assert c.objects["subscriptions"][0].doc["apiVersion"] == "operators.coreos.com/v1alpha1"
    assert not c.foreign


def test_a_kind_read_outside_by_kind_is_caught_by_the_declaration_walk() -> None:
    """`has_subject((k,))`, `kind_in_group(d, k)` and `refused_subject_group` reads inside a rule body count as the
    rule asking for that kind, so a helper that sidesteps `by_kind` cannot read an undeclared kind unnoticed."""
    import ast

    src = (ROOT / "src" / "kube_noob" / "audit" / "rules.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    probe = ast.parse(
        "def _probe(ctx, r):\n"
        "    for d in ctx.by_kind('Route'):\n"
        "        if ctx.has_subject(('StorageClass',)) and kind_in_group(d, 'IngressClass') and d.kind == 'Gateway':\n"
        "            return d\n"
    ).body[0]
    tree.body.append(probe)
    found = _kinds_asked(tree, ["_probe"])["_probe"]
    assert found == {"StorageClass", "IngressClass", "Route", "Gateway"}
    # And every traversal pattern the walk cannot classify is LOUD, never an empty set (review 4, R7).
    for body in (
        "    return [d for d in ctx.docs if d.kind == 'Route']\n",
        "    return list(filter(lambda d: d.kind == 'Route', ctx.docs))\n",
        "    return [d for d in ctx.by_kind('Route') if d.data.get('kind') == 'Route']\n",
        "    return other_module_helper(ctx)\n",
    ):
        probe = ast.parse("def _probe2(ctx, r):\n" + body).body[0]
        tree.body.append(probe)
        found = _kinds_asked(tree, ["_probe2"])["_probe2"]
        assert any(k.startswith("?") for k in found), (body, found)
        tree.body.remove(probe)


# ---------------------------------------------------------------------------
# Review 4: a refused object is never a pass (R1), and its neighbours (R3-R12)
# ---------------------------------------------------------------------------

REFUSED_SHAPES: dict[str, str] = {
    "v1slash": '"v1/"',
    "upper": '"APPS/v1"',
    "lead": '" apps/v1"',
    "foreign": "example.com/v1",
    "slashv1": '"/v1"',
    "appsslash": '"apps/"',
    "int7": "7",
    "list": "[apps, v1]",
}


def _refused_bundle(api_version: str, kind: str = "Deployment") -> str:
    """The reviewer's q1 shape: a privileged workload under a refused apiVersion, beside a Service selecting it."""
    spec = (
        "spec:\n  replicas: 1\n  selector: {matchLabels: {app: web}}\n  template:\n    metadata: {labels: {app: web}}\n"
        "    spec:\n      containers:\n        - name: web\n          image: web:latest\n"
        "          securityContext: {privileged: true}\n"
        if kind != "Pod"
        else "spec:\n  containers:\n    - name: web\n      image: web:latest\n"
        "      securityContext: {privileged: true}\n"
    )
    return (
        f"apiVersion: {api_version}\nkind: {kind}\nmetadata: {{name: web, namespace: shop}}\n{spec}---\n"
        "apiVersion: v1\nkind: Service\nmetadata: {name: web, namespace: shop}\n"
        "spec:\n  selector: {app: web}\n  ports: [{port: 80}]\n"
    )


@pytest.mark.parametrize("shape", sorted(REFUSED_SHAPES))
def test_a_refused_object_is_undetermined_in_every_format_never_a_pass(
    shape: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A typo in apiVersion (`v1/`, `APPS/v1`, a leading space) or a foreign group on a known kind turned a failing
    gate into a passing one whose every output said no workload was present (review 4, R1). Now: `audit` and
    `gate` exit 1, every format names the object, and "no pod spec in the input" is said nowhere."""
    from kube_noob import gate, report_html

    text = _refused_bundle(REFUSED_SHAPES[shape])
    d = tmp_path / shape
    d.mkdir()
    (d / "bundle.yaml").write_text(text, encoding="utf-8")
    code, out = _cli(capsys, "audit", "-f", str(d), "--format", "json")
    assert code == 1
    rep = json.loads(out)
    assert [r["object"] for r in rep["notAudited"]] == ["Deployment/shop/web"]
    assert not any(f["ruleId"] == "KN-V011" for f in rep["findings"]), "the Service was judged against unread pods"
    assert "no pod spec in the input" not in out
    assert "Deployment not audited" in _not_evaluated(rep["controlSummary"])["KN-S001"]
    code, text_view = _cli(capsys, "audit", "-f", str(d))
    assert code == 1
    assert "not audited: 1 object(s)" in text_view and "Deployment/shop/web" in text_view
    assert "undetermined" in text_view and "no pod spec in the input" not in text_view
    code, _ = _cli(capsys, "audit", "-f", str(d), "--fail-on", "never")
    assert code == 1, "undetermined is 1 whatever --fail-on says"
    code, sarif_text = _cli(capsys, "audit", "-f", str(d), "--format", "sarif")
    assert code == 1 and "no pod spec in the input" not in sarif_text
    run = json.loads(sarif_text)["runs"][0]
    assert [r["object"] for r in run["invocations"][0]["properties"]["notAudited"]] == ["Deployment/shop/web"]
    assert [r["message"]["text"] for r in run["results"] if r["level"] == "note"] == [
        f"Deployment/shop/web: not audited, {rep['notAudited'][0]['why']}"
    ]

    src = gate.Source(uri="bundle.yaml", text=text, lines=text.count("\n"))
    report = gate.run([src], fail_on="never")
    assert report["passed"] is False
    assert [(r["object"], r["why"]) for r in report["notAudited"]] == [
        (r["object"], r["why"]) for r in rep["notAudited"]
    ]
    assert any("not audited" in f and "Deployment/shop/web" in f for f in report["failures"])
    md = gate.markdown(report)
    assert "gate passed" not in md and "Not passed: 1 object(s) not audited" in md and "Deployment/shop/web" in md
    page = report_html.render(report)
    assert "The gate passed" not in page and "Not passed: 1 object(s) not audited" in page
    doc = gate.sarif(report, invocation={"executionSuccessful": True})
    assert [r["object"] for r in doc["runs"][0]["invocations"][0]["properties"]["notAudited"]] == [
        "Deployment/shop/web"
    ]
    assert any(
        r["level"] == "note" and "Deployment/shop/web" in r["message"]["text"] for r in doc["runs"][0]["results"]
    )
    for blob in (json.dumps(report), md, page, json.dumps(doc)):
        assert "no pod spec in the input" not in blob
    code, _ = _cli(capsys, "gate", "-f", str(d), "--fail-on", "never")
    assert code == 1


@pytest.mark.parametrize("api_version", ['"/v1"', "7"])
def test_slashless_garbage_on_a_core_kind_is_refused_and_named(
    api_version: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`apiVersion: 7` or `/v1` on a Pod was read as core v1 with only KN-V002 saying anything (review 4, R12)."""
    d = tmp_path / "pod"
    d.mkdir()
    (d / "pod.yaml").write_text(_refused_bundle(api_version, "Pod"), encoding="utf-8")
    code, out = _cli(capsys, "audit", "-f", str(d), "--format", "json")
    assert code == 1
    rep = json.loads(out)
    assert [r["object"] for r in rep["notAudited"]] == ["Pod/shop/web"]
    assert "KN-S001" not in rep["controlSummary"].get("rulesEvaluated", []) and "None" not in out


def test_a_null_api_version_is_a_missing_one_and_a_non_string_is_named_by_shape() -> None:
    """`apiVersion:` (null) was refused while a missing key was read, and "None" reached the note and KN-V002;
    `apiVersion: 7` printed Python's "7" (review 4, R6)."""
    null = _refused_bundle("null")
    missing = null.replace("apiVersion: null\n", "", 1)
    a, b = analyze(null, "kubernetes", None), analyze(missing, "kubernetes", None)
    assert set(a.fired_rules) == set(b.fired_rules) and "KN-S001" in a.fired_rules
    assert a.not_audited == [] and not any("None" in x for x in a.assumptions)
    for f in a.findings:
        assert "None" not in f.message, f
    seven = analyze(_refused_bundle("7"), "kubernetes", None)
    assert seven.not_audited[0]["why"] == "apiVersion is not a string"
    v002 = next(f for f in seven.findings if f.rule_id == "KN-V002")
    assert v002.message.startswith("Deployment's apiVersion is not a string.")
    listed = analyze(_refused_bundle("[apps, v1]"), "kubernetes", None)
    assert listed.not_audited[0]["why"] == "apiVersion is not a string"
    assert not any("[" in a for a in listed.assumptions if "undetermined" in a)


def test_no_input_text_reaches_a_reason_for_a_hostile_api_version(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A bidi override in the apiVersion reached `rulesNotEvaluated[].why` through the group text (review 4, R3).
    The `why` is built from the kind and fixed phrases; the cleaned value appears in the assumption line only."""
    hostile = "exam\u202eple.com/v1\u00ad"
    text = (
        f'apiVersion: "{hostile}"\nkind: Deployment\nmetadata: {{name: foreign, namespace: shop}}\n'
        "spec:\n  template:\n    spec:\n      containers:\n        - name: x\n          image: x:latest\n---\n"
        "apiVersion: v1\nkind: Service\nmetadata: {name: orphan, namespace: shop}\n"
        "spec:\n  selector: {app: nothing}\n  ports: [{port: 80}]\n---\n" + DEPLOYMENT.replace("prod", "shop")
    )
    d = tmp_path / "hostile"
    d.mkdir()
    (d / "h.yaml").write_text(text, encoding="utf-8")
    _, out = _cli(capsys, "audit", "-f", str(d), "--format", "json")
    rep = json.loads(out)
    for row in rep["controlSummary"]["rulesNotEvaluated"] + rep["notAudited"]:
        assert "\u202e" not in row["why"] and "\u00ad" not in row["why"] and "exam" not in row["why"], row
    assert "\u202e" not in out and "\u00ad" not in out
    _, text_view = _cli(capsys, "audit", "-f", str(d))
    assert "\u202e" not in text_view and "\u00ad" not in text_view
    assert "KN-V011" in _not_evaluated(rep["controlSummary"])


def test_a_pod_spec_in_a_kind_with_no_reader_declines_the_selector_rules_too() -> None:
    """An Argo Rollout and a Knative Service describe pods the rules did not read, exactly as a refused Deployment
    does; KN-V011 and KN-N012 still concluded "selects nothing" from them (review 4, R4)."""
    knative = (
        "apiVersion: serving.knative.dev/v1\nkind: Service\nmetadata: {name: hello, namespace: shop}\n"
        "spec:\n  template:\n    metadata: {labels: {app: hello}}\n    spec:\n      containers:\n"
        "        - image: hello:latest\n"
    )
    rollout = (
        "apiVersion: argoproj.io/v1alpha1\nkind: Rollout\nmetadata: {name: canary, namespace: shop}\n"
        "spec:\n  selector: {matchLabels: {app: canary}}\n  template:\n    metadata: {labels: {app: canary}}\n"
        "    spec:\n      containers:\n        - name: c\n          image: c:latest\n"
    )
    svc = (
        "apiVersion: v1\nkind: Service\nmetadata: {name: %s-svc, namespace: shop}\n"
        "spec:\n  selector: {app: %s}\n  ports: [{port: 80}]\n"
    )
    netpol = (
        "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata: {name: protect-%s, namespace: shop}\n"
        "spec: {podSelector: {matchLabels: {app: %s}}, policyTypes: [Ingress]}\n"
    )
    bundle = "---\n".join(
        [knative, rollout, svc % ("hello", "hello"), svc % ("canary", "canary"), netpol % ("hello", "hello"),
         netpol % ("canary", "canary"), DEPLOYMENT.replace("prod", "shop")]
    )  # fmt: skip
    rep = analyze(bundle, "kubernetes", None, partial_bundle=False)
    assert "KN-V011" not in rep.fired_rules and "KN-N012" not in rep.fired_rules
    assert "no reader for" in rep.not_evaluated["KN-V011"] and "no reader for" in rep.not_evaluated["KN-N012"]
    assert "canary" not in rep.not_evaluated["KN-V011"]  # the kind's name is input text; the phrase is fixed
    # The Rollout alone (no refused object) says the same, from the one shared helper.
    alone = analyze("---\n".join([rollout, svc % ("canary", "canary")]), "kubernetes", None)
    assert "KN-V011" not in alone.fired_rules
    assert alone.not_evaluated["KN-V011"] == "1 object not audited (pods are in a kind kube-noob has no reader for)"
    assert "no pod spec in the input" not in alone.not_evaluated["KN-S001"]


OCP3_RBAC = """
apiVersion: v1
kind: RoleBinding
metadata: {name: admin-everyone, namespace: shop}
groupNames: [system:authenticated]
userNames: null
roleRef: {name: cluster-admin}
subjects: null
---
apiVersion: v1
kind: ClusterRoleBinding
metadata: {name: cluster-admins-legacy}
groupNames: [system:unauthenticated]
userNames: [alice]
roleRef: {name: cluster-admin}
---
apiVersion: authorization.openshift.io/v1
kind: ClusterRoleBinding
metadata: {name: cluster-admins-full}
roleRef: {name: cluster-admin}
subjects:
  - {kind: SystemGroup, name: system:authenticated}
"""


def test_openshift_three_bindings_name_who_they_bind() -> None:
    """A 3.x binding keeps its subjects in `userNames`/`groupNames` or as `SystemGroup`/`SystemUser` subjects;
    read as a Kubernetes binding it granted cluster-admin "to []" and bound nobody to system:authenticated (R5)."""
    rep = analyze(OCP3_RBAC, "openshift", "4.20")
    s016 = {f.resource: f.message for f in rep.findings if f.rule_id == "KN-S016"}
    assert s016["RoleBinding/shop/admin-everyone"].endswith("to Group/system:authenticated.")
    assert s016["ClusterRoleBinding/cluster-admins-legacy"].endswith("to User/alice, Group/system:unauthenticated.")
    assert s016["ClusterRoleBinding/cluster-admins-full"].endswith("to Group/system:authenticated.")
    assert not any("[]" in m for m in s016.values())
    s028 = {(f.resource, f.path) for f in rep.findings if f.rule_id == "KN-S028"}
    assert s028 == {
        ("RoleBinding/shop/admin-everyone", "groupNames[0]"),
        ("ClusterRoleBinding/cluster-admins-legacy", "groupNames[0]"),
        ("ClusterRoleBinding/cluster-admins-full", "subjects[0]"),
    }
    # The one conversion the attack-path scan uses: no second copy of the legacy rules (class 9).
    from kube_noob import attack_paths
    from kube_noob.audit import rbac_legacy

    assert attack_paths._legacy_rbac is rbac_legacy.legacy_rbac


def test_the_openshift_refusal_note_does_not_call_the_legacy_api_core() -> None:
    """Kubernetes' core never served a Route; the "" an OpenShift kind carries is the legacy ungrouped API (R9)."""
    rep = analyze(
        "apiVersion: apps.openshift.io/v1\nkind: Route\nmetadata: {name: r, namespace: a}\nspec: {}\n",
        "openshift",
        "4.20",
    )
    note = next(a for a in rep.assumptions if "undetermined" in a)
    assert "the legacy ungrouped API (v1)" in note and "core" not in note
    dep = analyze("apiVersion: v1\nkind: Deployment\nmetadata: {name: r, namespace: a}\nspec: {}\n", "kubernetes", None)
    note = next(a for a in dep.assumptions if "undetermined" in a)
    assert "knows Deployment under apps, extensions" in note


def test_live_snapshot_reasons_never_say_in_the_input() -> None:
    """ "no Secret in the input" told a drift reader the cluster had no Secrets, when a live read never requests them;
    a live reason says what was read from the cluster and what is never requested (review 4, R10)."""
    from kube_noob import drift

    snap = drift.snapshot(LIVE_NOAPI, source="live")
    reasons = {r["ruleId"]: r["why"] for r in snap["coverage"]["notEvaluated"]}
    assert not any(" in the input" in why for why in reasons.values()), reasons
    assert reasons["KN-C013"] == (
        "no Secret read from the cluster; Secret is never requested from a cluster (not on the read-only allowlist)"
    )
    assert reasons["KN-N004"] == "no Service read from the cluster"
    assert reasons["KN-C009"].startswith("no policy PodDisruptionBudget read from the cluster")
    files = drift.snapshot(LIVE_NOAPI, source="manifests")
    assert {r["ruleId"]: r["why"] for r in files["coverage"]["notEvaluated"]}["KN-N004"] == "no Service in the input"
    assert snap["coverage"]["notAudited"] == []


def test_duplicate_objects_are_told_apart_by_group() -> None:
    """A serving.knative.dev/v1 Service and a core v1 Service named alike do not collide on apply (R11)."""
    text = (
        "apiVersion: serving.knative.dev/v1\nkind: Service\nmetadata: {name: hello, namespace: shop}\n"
        "spec: {template: {spec: {containers: [{image: hello:latest}]}}}\n---\n"
        "apiVersion: v1\nkind: Service\nmetadata: {name: hello, namespace: shop}\nspec: {selector: {app: hello}}\n"
    )
    assert "KN-V014" not in analyze(text, "kubernetes", None).fired_rules
    same = text.replace("serving.knative.dev/v1", "v1")
    assert "KN-V014" in analyze(same, "kubernetes", None).fired_rules


def test_the_one_intended_fixture_drift_is_the_bad_bundle_route() -> None:
    """tests/fixtures/bad-bundle.yaml holds an `apps.openshift.io/v1 Route`: 0.9.2 read it as a Route and fired
    KN-N002; it is now refused (and named, and the verdict undetermined), and KN-V002 still fires on it."""
    text = (ROOT / "tests" / "fixtures" / "bad-bundle.yaml").read_text(encoding="utf-8")
    rep = analyze(text, "openshift", "4.20")
    assert "KN-N002" not in rep.fired_rules and "KN-V002" in rep.fired_rules
    assert any(r["kind"] == "Route" for r in rep.not_audited)


# ---------------------------------------------------------------------------
# Review 5: the nearest neighbours of "a refused object is never a pass"
# ---------------------------------------------------------------------------

ROLLOUT_PRIV = """
apiVersion: argoproj.io/v1alpha1
kind: Rollout
metadata: {name: canary, namespace: shop}
spec:
  selector: {matchLabels: {app: canary}}
  template:
    metadata: {labels: {app: canary}}
    spec:
      containers:
        - name: c
          image: c:latest
          securityContext: {privileged: true}
"""


def _dep_with_kind(kind_literal: str) -> str:
    return (
        f"apiVersion: apps/v1\nkind: {kind_literal}\nmetadata: {{name: web, namespace: shop}}\n"
        "spec:\n  replicas: 1\n  selector: {matchLabels: {app: web}}\n  template:\n"
        "    metadata: {labels: {app: web}}\n    spec:\n      containers:\n        - name: web\n"
        "          image: web:latest\n          securityContext: {privileged: true}\n---\n"
        "apiVersion: v1\nkind: Service\nmetadata: {name: web, namespace: shop}\n"
        "spec:\n  selector: {app: web}\n  ports: [{port: 80}]\n"
    )


@pytest.mark.parametrize(
    ("name", "text", "why"),
    [
        ("rollout", ROLLOUT_PRIV, "pods are in a kind kube-noob has no reader for"),
        ("kind-lower", _dep_with_kind("deployment"), "kind is not well-formed (an UpperCamelCase name)"),
        ("kind-trailing-space", _dep_with_kind('"Deployment "'), "kind is not well-formed (an UpperCamelCase name)"),
        ("kind-int", _dep_with_kind("7"), "kind is not a string"),
    ],
)
def test_a_pod_spec_the_reader_cannot_read_is_not_audited_and_the_verdict_undetermined(
    name: str, text: str, why: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The neighbour of review 4's fix: a typo in `kind` (or a kind with no reader) carrying a privileged
    container was exit 0 and score 100.0 while the same JSON said "1 object not audited" (review 5, item 1)."""
    d = tmp_path / name
    d.mkdir()
    (d / "b.yaml").write_text(text, encoding="utf-8")
    code, out = _cli(capsys, "audit", "-f", str(d), "--format", "json")
    assert code == 1
    rep = json.loads(out)
    assert [r["why"] for r in rep["notAudited"]] == [why]
    assert rep["summary"]["score"] is None and rep["summary"]["verdict"] == "undetermined"
    assert not any(f["ruleId"] == "KN-V011" for f in rep["findings"])
    code, text_view = _cli(capsys, "audit", "-f", str(d))
    assert code == 1 and "score=not determined (1 object(s) not audited)" in text_view.splitlines()[0]


def test_not_audited_is_non_empty_whenever_a_reason_says_not_audited() -> None:
    """The invariant behind item 1: the record and the verdict come from one helper, so a `why` saying "not
    audited" is never beside an empty `notAudited`."""
    for text in (ROLLOUT_PRIV, _dep_with_kind("deployment"), _refused_bundle('"v1/"'), CONFIGMAP, DEPLOYMENT):
        rep = analyze(text, "kubernetes", None)
        says = any("not audited" in why for why in rep.not_evaluated.values())
        assert says == bool(rep.not_audited), (text[:40], rep.not_evaluated, rep.not_audited)
        assert (rep.undetermined() is not None) == bool(rep.not_audited)


def test_an_unknown_kind_in_an_unknown_group_is_not_a_refusal() -> None:
    """`example.com/v1 Widget`: nothing claims to read it, so it is neither audited nor "not audited" (item 4)."""
    rep = analyze(
        "apiVersion: example.com/v1\nkind: Widget\nmetadata: {name: w, namespace: a}\nspec: {x: 1}\n"
        + "---"
        + DEPLOYMENT,
        "kubernetes",
        None,
    )
    assert rep.not_audited == [] and rep.undetermined() is None


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("name", "web\n  Deployment/shop/forged: apiVersion is fine"),
        ("name", "we\u202eb"),
        ("namespace", "sh\u202eop"),
        ("name", "w" * 10_000),
        ("namespace", "s\n" + "x" * 10_000),
    ],
)
def test_the_not_audited_object_is_cleaned_once_where_it_is_built(
    field: str, value: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`notAudited[].object` was the raw `d.ref()`: a newline in a name forged a second note row in the text
    view and reached audit/gate JSON and SARIF; a 10 KB name was a 10 KB field (review 5, item 2). Asserted on
    PARSED values, not on ASCII-escaped bytes."""
    import yaml as _yaml

    from kube_noob import gate

    meta = {"name": "web", "namespace": "shop"}
    meta[field] = value
    doc = {
        "apiVersion": "example.com/v1",
        "kind": "Deployment",
        "metadata": meta,
        "spec": {"template": {"spec": {"containers": [{"name": "c", "image": "c:latest"}]}}},
    }
    text = _yaml.safe_dump(doc, allow_unicode=True)
    d = tmp_path / "h"
    d.mkdir()
    (d / "h.yaml").write_text(text, encoding="utf-8")
    _, out = _cli(capsys, "audit", "-f", str(d), "--format", "json")
    rep = json.loads(out)
    obj = rep["notAudited"][0]["object"]
    assert "\n" not in obj and "\u202e" not in obj and len(obj) <= 120

    def clean(value: Any) -> bool:
        blob = json.dumps(value, ensure_ascii=False)
        return "\n" not in blob.replace("\\n", "") and "\u202e" not in blob and "forged" not in blob.replace(obj, "")

    # Every surface built from the row: the rows, the assumptions, the gate's failure line, the SARIF note and the
    # invocation property. (A finding's own `resource` is the audit's older field and is not this row.)
    assert clean(rep["notAudited"]) and clean(rep["assumptions"]) and clean(rep["resources"])
    _, text_view = _cli(capsys, "audit", "-f", str(d))
    notes = [line for line in text_view.splitlines() if "not audited, so this verdict" in line]
    assert len(notes) == 1
    assert not any(line.startswith("Deployment/shop/forged") for line in text_view.splitlines())
    report = gate.run([gate.Source(uri="h.yaml", text=text, lines=text.count("\n"))], fail_on="never")
    assert clean(report["failures"]) and clean(report["notAudited"]) and clean(report["assumptions"])
    doc_sarif = gate.sarif(report, invocation={"executionSuccessful": True})
    run = doc_sarif["runs"][0]
    assert clean(run["invocations"][0]["properties"]["notAudited"])
    assert clean([r for r in run["results"] if r["ruleId"] == "KN-NOT-AUDITED"])


def test_the_verdict_word_is_on_every_headline_and_the_score_is_withheld(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """One predicate, `Report.undetermined()`, drives summary.score/verdict, the text headline, the gate's
    headline, `fix.after`, `ksi`/`fedramp_ksi` and the posture report (review 5, item 3)."""
    from kube_noob import drift, gate, report_html
    from kube_noob.toolkit import FixIn, KsiIn, Toolkit

    knative = (
        "apiVersion: serving.knative.dev/v1\nkind: Service\nmetadata: {name: hello, namespace: prod}\n"
        "spec:\n  template:\n    spec:\n      containers:\n        - image: hello:latest\n"
    )
    text = knative + "---" + DEPLOYMENT
    rep = analyze(text, "kubernetes", None)
    assert rep.undetermined() == "1 object(s) not audited"
    summary = rep.as_dict()["summary"]
    assert summary["score"] is None and summary["verdict"] == "undetermined"
    d = tmp_path / "v"
    d.mkdir()
    (d / "v.yaml").write_text(text, encoding="utf-8")
    _, text_view = _cli(capsys, "audit", "-f", str(d))
    assert "score=not determined (1 object(s) not audited)" in text_view.splitlines()[0]
    report = gate.run([gate.Source(uri="v.yaml", text=text, lines=text.count("\n"))], fail_on="never")
    assert gate.markdown(report).startswith("## kube-noob gate incomplete")
    assert "The gate is incomplete" in report_html.render(report)
    kit = Toolkit.__new__(Toolkit)
    from kube_noob.config import Settings

    kit = Toolkit(Settings())
    fixed = kit.fix(FixIn(manifests=text, platform="kubernetes", version=None, harden=True))
    assert fixed["after"]["score"] is None and fixed["after"]["verdict"] == "undetermined"
    ksi = kit.fedramp_ksi(KsiIn(manifests=text, platform="kubernetes"))
    assert ksi["verdict"] == "undetermined" and [r["object"] for r in ksi["notAudited"]] == ["Service/prod/hello"]
    code, _ = _cli(capsys, "ksi", "-f", str(d))
    assert code == 1
    snap = drift.snapshot(_objects(text), source="manifests")
    posture = drift.first_report(snap)
    assert posture["verdict"] == "undetermined" and [r["object"] for r in posture["notAudited"]] == [
        "Service/prod/hello"
    ]
    assert "not audited" in drift.markdown(posture) and "undetermined" in drift.markdown(posture)
    (d / "snap.json").write_text(json.dumps(snap), encoding="utf-8")
    code, _ = _cli(capsys, "posture", "diff", str(d / "snap.json"), str(d / "snap.json"))
    assert code == 1


EXC_NOT_AUDITED = """
apiVersion: kube-noob.io/v1
kind: ExceptionList
exceptions:
  - id: EXC-KNATIVE
    notAudited: {namespace: prod, kind: Service, name: hello, apiGroup: serving.knative.dev}
    owner: team-web
    reason: Knative Services are audited by the serving team's own pipeline
    expires: 2027-11-01
"""


def test_an_exception_list_can_accept_a_known_foreign_object(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A Helm render with an Istio Gateway or a Knative Service had a red gate forever and `--exceptions` could not
    name it (review 5, item 4): a `notAudited:` entry (owner, reason, expiry; never a `rule:`) accepts the row,
    which stays listed with `acceptedBy`, and the verdict is determined again."""
    from kube_noob import gate
    from kube_noob.audit import exceptions as exc

    knative = (
        "apiVersion: serving.knative.dev/v1\nkind: Service\nmetadata: {name: hello, namespace: prod}\n"
        "spec:\n  template:\n    spec:\n      containers:\n        - image: hello:latest\n"
    )
    text = knative + "---" + DEPLOYMENT
    rev = exc.review(EXC_NOT_AUDITED)
    assert [e.status for e in rev.entries] == ["active"] and rev.entries[0].as_dict()["notAudited"]["kind"] == "Service"
    d = tmp_path / "a"
    d.mkdir()
    (d / "v.yaml").write_text(text, encoding="utf-8")
    (d / "exc.yaml").write_text(EXC_NOT_AUDITED, encoding="utf-8")
    code, out = _cli(capsys, "audit", "-f", str(d / "v.yaml"), "--exceptions", str(d / "exc.yaml"), "--format", "json")
    assert code == 0, out
    rep = json.loads(out)
    assert rep["notAudited"][0]["acceptedBy"] == "EXC-KNATIVE" and rep["summary"].get("verdict") != "undetermined"
    assert rep["summary"]["score"] is not None and rep["exceptions"]["unused"] == []
    report = gate.run(
        [gate.Source(uri="v.yaml", text=text, lines=text.count("\n"))], fail_on="never", exceptions=EXC_NOT_AUDITED
    )
    assert report["passed"] is True and report["notAudited"][0]["acceptedBy"] == "EXC-KNATIVE"
    assert "incomplete" not in gate.markdown(report)
    # The SARIF help points at the entry, not at removing the object from the gate.
    doc = gate.sarif(gate.run([gate.Source(uri="v.yaml", text=text, lines=text.count("\n"))], fail_on="never"))
    rule = next(r for r in doc["runs"][0]["tool"]["driver"]["rules"] if r["id"] == "KN-NOT-AUDITED")
    assert "notAudited" in rule["help"]["text"] and "remove it from the gate" not in rule["help"]["text"]
    # A `rule:` entry cannot name it, and an entry with both or neither is refused with the reason.
    both = EXC_NOT_AUDITED.replace("    notAudited:", "    rule: KN-S001\n    notAudited:")
    assert exc.review(both).entries[0].status == "refused"
    other = exc.review(EXC_NOT_AUDITED.replace("name: hello", "name: other"))
    rep2 = analyze(text, "kubernetes", None)
    assert exc.accept_not_audited(other, rep2.not_audited) == set() and "acceptedBy" not in rep2.not_audited[0]


def test_duplicates_collide_across_the_groups_a_kind_was_served_under() -> None:
    """R11's neighbour: `extensions/v1beta1` and `apps/v1` Deployment `web` are one stored object, as are the two
    RoleBinding groups OpenShift serves as proxies; a Knative and a core Service are not (review 5, item 5)."""

    def dep(api: str) -> str:
        return f"apiVersion: {api}\nkind: Deployment\nmetadata: {{name: web, namespace: shop}}\nspec: {{}}\n"

    assert "KN-V014" in analyze(dep("extensions/v1beta1") + "---\n" + dep("apps/v1"), "kubernetes", "1.15").fired_rules

    def rb(api: str) -> str:
        return f"apiVersion: {api}\nkind: RoleBinding\nmetadata: {{name: rb, namespace: shop}}\nroleRef: {{name: x}}\n"

    assert (
        "KN-V014"
        in analyze(
            rb("authorization.openshift.io/v1") + "---\n" + rb("rbac.authorization.k8s.io/v1"), "openshift", "4.20"
        ).fired_rules
    )

    def svc(api: str) -> str:
        return f"apiVersion: {api}\nkind: Service\nmetadata: {{name: hello, namespace: shop}}\nspec: {{}}\n"

    assert "KN-V014" not in analyze(svc("serving.knative.dev/v1") + "---\n" + svc("v1"), "kubernetes", None).fired_rules


def test_legacy_binding_names_that_are_not_strings_are_refused_by_shape() -> None:
    """`userNames: [7, null, {a: b}]` printed "User/7, User/None, User/{'a': 'b'}" (review 5, item 6)."""
    text = (
        "apiVersion: v1\nkind: ClusterRoleBinding\nmetadata: {name: odd}\nroleRef: {name: cluster-admin}\n"
        "userNames: [alice, 7, null]\ngroupNames: [{a: b}]\n"
    )
    rep = analyze(text, "openshift", "4.20")
    s016 = next(f for f in rep.findings if f.rule_id == "KN-S016")
    assert "None" not in s016.message and "{'a'" not in s016.message and "User/7" not in s016.message
    assert "userNames[1] is not a string" in s016.message
    out = json.dumps(rep.as_dict())
    assert "User/None" not in out and "{'a': 'b'}" not in out


def test_an_empty_user_names_list_beside_subjects_says_why_nobody_is_bound() -> None:
    """Per openshift/api, `userNames: []` is SET, so `subjects` is ignored; the reader saw a subject list and a
    message saying nobody, with no why (review 5, item 7)."""
    text = (
        "apiVersion: v1\nkind: ClusterRoleBinding\nmetadata: {name: empty}\nroleRef: {name: cluster-admin}\n"
        "userNames: []\nsubjects:\n  - {kind: Group, name: system:authenticated}\n"
    )
    rep = analyze(text, "openshift", "4.20")
    s016 = next(f for f in rep.findings if f.rule_id == "KN-S016")
    assert "names nobody (userNames is set and empty; subjects are ignored when userNames is present" in s016.message
    assert "openshift/api authorization/v1" in s016.message


def test_the_attack_path_scan_reads_openshift_three_rbac_like_the_audit() -> None:
    """R5's sibling: `posture scan` said "apiVersion v1 is not rbac.authorization.k8s.io, so it was ignored" for
    the same objects the audit's KN-S016 now reads (review 5, item 8): one reader, `rbac_legacy`."""
    from kube_noob import attack_paths as ap

    text = (
        "apiVersion: v1\nkind: ClusterRole\nmetadata: {name: admin}\nrules:\n"
        "  - {apiGroups: ['*'], resources: ['*'], verbs: ['*']}\n---\n"
        "apiVersion: v1\nkind: RoleBinding\nmetadata: {name: web-admin, namespace: shop}\n"
        "roleRef: {name: admin}\nuserNames: [alice]\n---\n"
        "apiVersion: v1\nkind: ServiceAccount\nmetadata: {name: web, namespace: shop}\n"
    )
    inv = ap.Inventory.from_documents(list(yaml.safe_load_all(text)))
    assert not any("is not rbac.authorization.k8s.io" in n for n in inv.not_read), inv.not_read
    assert [o["metadata"]["name"] for o in inv.of("RoleBinding")] == ["web-admin"]
    assert inv.of("RoleBinding")[0]["subjects"] == [{"kind": "User", "name": "alice"}]


@pytest.mark.parametrize("value", ["[]", "{}", "0", "true", "1.5"])
def test_a_non_string_api_version_gets_exactly_one_message(value: str) -> None:
    """`apiVersion: []` earned KN-V001 "missing apiVersion" AND KN-V002 "not a string" AND a refusal: "missing"
    is for absent, null and "" only (review 5, item 9)."""
    rep = analyze(_refused_bundle(value), "kubernetes", None)
    v001 = [f for f in rep.findings if f.rule_id == "KN-V001" and "apiVersion" in f.message]
    assert v001 == [], [f.message for f in v001]
    assert [f.message for f in rep.findings if f.rule_id == "KN-V002"] == [
        "Deployment's apiVersion is not a string. Use apps/v1."
    ]
    assert [r["why"] for r in rep.not_audited] == ["apiVersion is not a string"]


def test_the_not_audited_sarif_result_has_a_location_and_a_fingerprint(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """GitHub code scanning lists a location-less result nowhere; the audit knows the object's line (item 10)."""
    from kube_noob import gate

    text = CONFIGMAP.lstrip("\n") + "---\n" + _refused_bundle('"v1/"')  # the toolkit strips a leading blank line
    d = tmp_path / "s"
    d.mkdir()
    (d / "b.yaml").write_text(text, encoding="utf-8")
    _, out = _cli(capsys, "audit", "-f", str(d), "--format", "sarif")
    note = next(r for r in json.loads(out)["runs"][0]["results"] if r["ruleId"] == "KN-NOT-AUDITED")
    assert note["kind"] == "review" and note["partialFingerprints"]["kubeNoob/v1"]
    loc = note["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"].endswith("b.yaml") and loc["region"]["startLine"] == CONFIGMAP.count("\n") + 1
    report = gate.run([gate.Source(uri="b.yaml", text=text, lines=text.count("\n"))], fail_on="never")
    note = next(r for r in gate.sarif(report)["runs"][0]["results"] if r["ruleId"] == "KN-NOT-AUDITED")
    assert (
        note["kind"] == "review"
        and note["locations"][0]["physicalLocation"]["region"]["startLine"] == CONFIGMAP.count("\n") + 1
    )
