"""`audit --cni`: an AdminNetworkPolicy the cluster's CNI does not enforce, as a finding a gate can fail on.

`policy reach --cni` answers one reachability question. The policy being inert is a property of the bundle, not of
that question, so it belongs in the audit too -- and with the three-valued machinery, because the rule cannot
decide it from manifests alone. Without `--cni` the rule does not run and must be recorded as NOT EVALUATED rather
than clean (G202): "no CNI was named" is not "the policy is enforced".
"""

from __future__ import annotations

from kube_noob.audit.engine import analyze
from kube_noob.audit.model import Finding, Severity

RULE = "KN-N014"

ANP = """
apiVersion: policy.networking.k8s.io/v1alpha1
kind: AdminNetworkPolicy
metadata:
  name: guardrail
spec:
  priority: 10
  subject:
    namespaces:
      matchLabels:
        tier: app
  ingress:
    - name: deny-all
      action: Deny
      from:
        - namespaces: {}
"""

BANP = """
apiVersion: policy.networking.k8s.io/v1alpha1
kind: BaselineAdminNetworkPolicy
metadata:
  name: default
spec:
  subject:
    namespaces:
      matchLabels:
        tier: app
  ingress:
    - name: baseline
      action: Deny
      from:
        - namespaces: {}
"""

NETPOL = """
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: web
  namespace: shop
spec:
  podSelector: {}
  policyTypes: [Ingress]
"""


def _hits(text: str = ANP, cni: str | None = None) -> list[Finding]:
    return [f for f in analyze(text, platform="kubernetes", cni=cni).findings if f.rule_id == RULE]


def _report(text: str = ANP, cni: str | None = None) -> object:
    return analyze(text, platform="kubernetes", cni=cni)


def test_a_policy_the_named_cni_ignores_is_reported() -> None:
    hit = _hits(ANP, cni="calico:3.32")
    assert len(hit) == 1
    assert hit[0].severity is Severity.HIGH  # a policy gate that silently stopped applying
    assert "3.32" in hit[0].message and "ClusterNetworkPolicy" in hit[0].remediation


def test_both_kinds_are_reported() -> None:
    assert sorted(f.resource for f in _hits("\n---\n".join((ANP, BANP)), cni="calico:3.32")) == [
        "AdminNetworkPolicy/guardrail",
        "BaselineAdminNetworkPolicy/default",
    ]


def test_an_enforcing_cni_is_clean_and_evaluated() -> None:
    report = analyze(ANP, platform="kubernetes", cni="ovn-kubernetes")
    assert [f for f in report.findings if f.rule_id == RULE] == []
    assert RULE in report.evaluated_rules  # it ran and found nothing, which is a pass and must read as one


def test_with_no_cni_the_rule_declines_to_decide_rather_than_passing() -> None:
    """The whole point. "Nobody told me the CNI" is not "the policy is enforced", and a compliance record that
    counted this rule clean would be reporting a check that never ran (G202)."""
    report = analyze(ANP, platform="kubernetes")
    assert [f for f in report.findings if f.rule_id == RULE] == []
    assert RULE not in report.evaluated_rules


def test_an_undocumented_cni_also_declines_to_decide() -> None:
    report = analyze(ANP, platform="kubernetes", cni="cilium:1.18")
    assert [f for f in report.findings if f.rule_id == RULE] == []
    assert RULE not in report.evaluated_rules


def test_a_bundle_with_no_admin_policy_is_not_evaluated_and_says_why() -> None:
    """Nothing to decide is not a failure to decide, and it is not a pass either (G281 reversed G210 here).

    This asserted that the rule was evaluated and clean on a bundle with no admin policy. A rule whose subject
    kind is absent has looked at nothing, and the coverage record now says so with the kinds named, instead of
    counting the rule among the clean ones.
    """
    report = analyze(NETPOL, platform="kubernetes", cni="calico:3.32")
    assert [f for f in report.findings if f.rule_id == RULE] == []
    assert RULE not in report.evaluated_rules
    assert report.not_evaluated[RULE] == "no AdminNetworkPolicy or BaselineAdminNetworkPolicy in the input"


def test_a_coarse_version_declines_to_decide() -> None:
    assert _hits(ANP, cni="calico:3") == []
    assert RULE not in analyze(ANP, platform="kubernetes", cni="calico:3").evaluated_rules


def test_the_finding_fails_a_gate(tmp_path: object) -> None:
    """A gate is the surface that matters: an inert cluster-wide policy should stop a merge."""
    from pathlib import Path

    from kube_noob import gate

    f = Path(str(tmp_path)) / "anp.yaml"
    f.write_text(ANP, encoding="utf-8")
    sources = gate.collect([str(f)], lambda path: Path(path).read_text(encoding="utf-8"))
    report = gate.run(sources, platform="kubernetes", fail_on="high", cni="calico:3.32")
    assert report["passed"] is False
    assert RULE in {x["ruleId"] for x in report["findings"]}
    assert gate.run(sources, platform="kubernetes", fail_on="high")["passed"] is True


def test_the_cli_reports_it_and_a_bad_value_is_refused(capsys: object, tmp_path: object) -> None:
    """The flag has to reach the rule from the command line, and a typo must not read as "no CNI given"."""
    from pathlib import Path

    from kube_noob.cli import main

    f = Path(str(tmp_path)) / "anp.yaml"
    f.write_text(ANP, encoding="utf-8")
    assert main(["audit", "-f", str(f), "--platform", "kubernetes"]) == 0
    assert main(["audit", "-f", str(f), "--platform", "kubernetes", "--cni", "calico:3.32"]) == 1
    out = capsys.readouterr().out  # type: ignore[attr-defined]
    assert RULE in out and "3.32" in out
    assert main(["audit", "-f", str(f), "--cni", "calico:"]) == 4


def test_the_tool_schema_documents_the_flag() -> None:
    from kube_noob.toolkit import AuditIn

    prop = AuditIn.model_json_schema()["properties"]["cni"]
    assert "KN-N014" in prop["description"] and "NOT EVALUATED" in prop["description"]
