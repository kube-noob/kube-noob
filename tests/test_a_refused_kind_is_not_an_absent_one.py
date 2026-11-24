"""A kind the input HOLDS and the rules refused is not a kind that was absent (G368, review classes 9 and 24).

`has_subject` and `by_kind` are group-matched, and correctly so: a `projectcalico.org/v3 NetworkPolicy` is a real
and different kind, and G231 and G365 are the fixes that stopped kube-noob reading one as the Kubernetes
NetworkPolicy. The consequence nothing had followed up is that a refused object is then indistinguishable from no
object at all, to every rule that reasons from the absence of its `context=` kinds -- and eight rules do.

Measured on a bundle holding one Deployment in `prod` and one `projectcalico.org/v3 NetworkPolicy` in `prod`:

- `notAudited` named `NetworkPolicy/prod/dd` and the verdict was undetermined, exit 1. That half was right.
- KN-N001 fired a MEDIUM finding whose text was *"No NetworkPolicy for namespace prod in this bundle."* -- a
  false statement about a bundle that holds one, eleven lines below the block naming it, with remediation
  telling the reader to add a policy they may already have.
- Five rules recorded `evaluated without networking.k8s.io NetworkPolicy` -- KN-C007, KN-C008, KN-C015, KN-N001
  and KN-S014 -- which is `rulesEvaluatedWithout` in the control summary, the FedRAMP KSI record, OSCAL, `drift`,
  `gate` and the MCP toolkit, and is read there as "the input held no such object".
- The red-team block of the same report said *"1 object(s) in this input were not audited, so this scenario
  cannot be called mitigated"* and marked two scenarios UNDECIDED. The honest phrase existed twelve lines below
  the wrong one: class 9, two sources of truth for one question, which is G366's shape again one layer up.

`ctx.cannot_judge_absence` is the join. The reason it records is `refused_summary`, the phrase a refused SUBJECT
already produces, and not `partner_unreadable`'s channel, whose published prose is about a field of the wrong
type and would have printed a true verdict under a false explanation.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from kube_noob.audit.engine import analyze
from kube_noob.audit.model import Report

ROOT = Path(__file__).resolve().parents[1]

WORKLOAD = """
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: prod}
spec:
  replicas: 1
  selector: {matchLabels: {app: web}}
  template:
    metadata: {labels: {app: web}}
    spec:
      containers:
        - name: app
          image: registry.example.com/app@sha256:%s
""" % ("a" * 64)

#: A second workload in another namespace, so the per-namespace granularity has something to be wrong about.
OTHER_NAMESPACE = WORKLOAD.replace("namespace: prod", "namespace: staging")

#: A real and different kind: Calico's NetworkPolicy has `selector`/`types`, not `podSelector`/`policyTypes`.
REFUSED_NETPOL = """
apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata: {name: dd, namespace: prod}
spec:
  selector: all()
  types: [Ingress]
"""

#: The one the rules do read, for the negative control.
READ_NETPOL = """
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: dd, namespace: prod}
spec:
  podSelector: {}
  policyTypes: [Ingress]
"""

REFUSED_HPA = """
apiVersion: autoscaling.k8s.io/v2
kind: HorizontalPodAutoscaler
metadata: {name: h, namespace: prod}
spec:
  minReplicas: 2
  maxReplicas: 5
  scaleTargetRef: {kind: Deployment, name: web, apiVersion: apps/v1}
"""


def _report(*parts: str) -> Report:
    return analyze("---".join(parts))


def _n001(rep: Report) -> list[str]:
    return [f.message for f in rep.findings if f.rule_id == "KN-N001"]


@pytest.fixture(scope="module")
def absent() -> Report:
    """The namespace genuinely has no NetworkPolicy. KN-N001 is right to fire, and must keep doing so."""
    return _report(WORKLOAD)


@pytest.fixture(scope="module")
def refused() -> Report:
    """The namespace holds a NetworkPolicy the rules refused. Nothing here is a fact about isolation."""
    return _report(WORKLOAD, REFUSED_NETPOL)


def test_the_report_names_the_refused_object_and_withholds_its_verdict(refused: Report) -> None:
    """The premise. If the refusal were not recorded the fix would be to record it, not to join two records."""
    assert [r["object"] for r in refused.not_audited] == ["NetworkPolicy/prod/dd"]
    assert refused.undetermined() is not None


def test_a_genuinely_absent_networkpolicy_still_fires_the_finding(absent: Report) -> None:
    """The negative control, first: a guard that silences the rule everywhere is a worse bug than the one fixed."""
    assert _n001(absent) == ["No NetworkPolicy for namespace prod in this bundle."]


def test_a_refused_networkpolicy_is_not_reported_as_no_networkpolicy(refused: Report) -> None:
    """The headline. The finding asserted the absence of an object the same report names."""
    assert _n001(refused) == []
    assert not any("No NetworkPolicy for namespace prod" in f.message for f in refused.findings)


def test_the_rule_is_recorded_as_undecided_rather_than_silently_dropped(refused: Report) -> None:
    """Suppressing the finding without recording why would make an unknown read as clean: the product's defect."""
    assert "KN-N001" not in refused.evaluated_rules
    reason = refused.not_evaluated.get("KN-N001") or refused.partly_evaluated.get("KN-N001") or ""
    assert "NetworkPolicy not audited" in reason, refused.not_evaluated.get("KN-N001")


def test_the_reason_is_the_refusal_phrase_and_not_the_wrong_type_prose(refused: Report) -> None:
    """`partner_unreadable` would have explained a refused apiVersion as a field of the wrong type."""
    reason = refused.not_evaluated.get("KN-N001") or refused.partly_evaluated.get("KN-N001") or ""
    assert "apiVersion names a group kube-noob does not know NetworkPolicy under" in reason
    assert "wrong type" not in reason
    assert "Fix the field" not in reason


def test_evaluated_without_no_longer_claims_a_refused_kind_was_absent(refused: Report) -> None:
    """`rulesEvaluatedWithout` reaches the control summary, the KSI record, OSCAL, drift, gate and the MCP tools."""
    for rule_id, labels in refused.absent_subjects.items():
        assert not any("NetworkPolicy" in label for label in labels), (rule_id, labels)


def test_evaluated_without_still_reports_a_kind_that_really_is_absent(absent: Report) -> None:
    """The other negative control: the record must keep saying "no NetworkPolicy in the input" when that is true."""
    labelled = any("NetworkPolicy" in label for labels in absent.absent_subjects.values() for label in labels)
    assert labelled, absent.absent_subjects


def test_a_refusal_in_one_namespace_does_not_blind_the_rule_in_another() -> None:
    """Granularity, which is what G366 was about: the guard is per namespace, not per bundle."""
    rep = _report(WORKLOAD, OTHER_NAMESPACE, REFUSED_NETPOL)
    assert _n001(rep) == ["No NetworkPolicy for namespace staging in this bundle."]


def test_a_readable_networkpolicy_is_still_read_and_the_rule_is_clean() -> None:
    """The whole point of the group match stays intact: a Kubernetes NetworkPolicy covers its namespace."""
    rep = _report(WORKLOAD, READ_NETPOL)
    assert _n001(rep) == []
    assert "KN-N001" in rep.evaluated_rules
    assert rep.undetermined() is None


def test_a_refused_context_object_of_another_kind_is_joined_the_same_way() -> None:
    """One mechanism, not a patch on one rule: KN-C007 reasons from the absence of an HorizontalPodAutoscaler."""
    rep = _report(WORKLOAD, REFUSED_HPA)
    for rule_id, labels in rep.absent_subjects.items():
        assert not any("HorizontalPodAutoscaler" in label for label in labels), (rule_id, labels)
    reason = rep.not_evaluated.get("KN-C007") or rep.partly_evaluated.get("KN-C007") or ""
    assert "HorizontalPodAutoscaler not audited" in reason, reason


def test_nothing_in_the_input_is_lost_between_the_two_answers(refused: Report) -> None:
    """The refused object is accounted for exactly once, and not as both absent and refused."""
    refs = [r["object"] for r in refused.not_audited]
    assert refs == ["NetworkPolicy/prod/dd"]
    assert "NetworkPolicy/prod/dd" in str(refused.declined)
