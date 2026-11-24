"""One declaration of a rule's evidence dependency, and one check against both unreadability predicates (G369).

G368 separated "the input holds no NetworkPolicy" from "the input holds one the rules refused", and applied the
finding-level guard to KN-N001. It left two things, both recorded in its own "Not covered" clause.

**Two declarations of one question (class 9).** A rule's evidence dependency was declared twice:

- `context=` on eight rules, which drives the "evaluated without X" record (`absent_subjects` ->
  `rulesEvaluatedWithout`), checked by G368 against a refused apiVersion group;
- `_PARTNER_KINDS` on ten rules, which drives `partner_unreadable`, checked against `object_unreadable` -- a
  malformed shape -- and never against a refusal.

They overlapped in exactly one rule, KN-C008, so which half of the question a rule got asked depended on which
list it happened to be in. Measured on one Deployment in `prod` with three replicas, one readable `policy/v1`
PodDisruptionBudget that permits a disruption, and one refused `policy.k8s.io/v1` PodDisruptionBudget whose
`minAvailable: 3` on three replicas is the exact thing KN-C009 exists to catch: KN-C009 was in neither
`rulesNotEvaluated` nor `partlyEvaluatedRules` and produced no finding, which is how the control summary counts a
rule checked-and-clean -- over a bundle whose own `notAudited` block names a PodDisruptionBudget it never read.

`evidence_kinds` is the one declaration and `ctx.cannot_judge_absence` the one check. Both predicates run there,
and each document is explained by the one that caught it: `refused_summary` for a refused apiVersion group, and
`partner_unreadable`'s channel -- whose published prose is "a field in the input has the wrong type for what the
rule reads ... Fix the field (the schema findings name it)" -- for a field of the wrong type, which is what that
sentence is about. Letting a refused group borrow it would print a true verdict under a false explanation, which
is the G368 defect one layer down.

**The finding-level guard for the remaining seven rules.** Measured, each on a bundle holding the refused object
the rule reasons from the absence of:

- KN-C016, beside a `quota.k8s.io/v1` ResourceQuota in `prod`: *"Namespace prod has workloads and no
  ResourceQuota in this bundle."*
- KN-C008, beside a `policy.k8s.io/v1` PodDisruptionBudget selecting the workload: *"No PodDisruptionBudget
  selects this workload."*
- KN-C015, beside a `dra.k8s.io/v1` ResourceClaim named `c1` in `prod`: *"...the ResourceClaim 'c1', which no
  document in this bundle defines in namespace prod."*
- KN-C007, beside an `autoscaling.k8s.io/v2` HorizontalPodAutoscaler scaling it to 2..5: *"Deployment runs 1
  replica(s)."*
- KN-S014, beside a refused ServiceAccount `app` with `automountServiceAccountToken: false`: *"Pod automounts
  the token of ServiceAccount 'app'."*
- KN-ST001, beside a `csi.storage.k8s.io/v1` StorageClass named `shared-sc`: *"StorageClass 'shared-sc' is
  neither defined in this bundle nor a known platform class"*.
- KN-S031, beside a `config.openshift.io/v1` Namespace `prod`: the generic message, the one a namespace managed
  elsewhere earns.

Three of those texts -- KN-C015's, KN-C016's and KN-ST001's -- are false statements about the input, which is
review class 24; KN-C008's is the same shape. KN-C007's and KN-S014's texts are true, and what was wrong there is
deciding the question the refused object was the answer to. KN-S031 is the one case where the finding is NOT
withheld: `adminAccess: true` is a HIGH finding whichever branch the message takes, and silencing it would be a
worse defect than explaining it imprecisely, so the rule is recorded as partly declined with the Namespace named.

The negative controls are the point, and there are two for every rule: a kind that is genuinely absent still
fires the finding and is still recorded under "evaluated without", and a readable object of that kind is still
read and the rule is still clean. Granularity is the other point (G366): every guard is per namespace or per
named object, never per bundle, so a refusal in `prod` cannot blind the rule in `staging`.
"""

from __future__ import annotations

import pytest

from kube_noob.audit.engine import analyze
from kube_noob.audit.evidence import _EVIDENCE_KINDS, _READS_THE_WORKLOAD_IT_JUDGES, evidence_kinds
from kube_noob.audit.model import Report
from kube_noob.audit.rules import RULES

# --------------------------------------------------------------------------------------------------------------
# The objects. A refused one has an apiVersion naming a group the rules do not know its kind under, which is a
# real and different API rather than a typo: the group match that makes it refused is G231's and G365's fix.
# --------------------------------------------------------------------------------------------------------------

NAMESPACE = """
apiVersion: v1
kind: Namespace
metadata: {name: prod}
"""

WORKLOAD = """
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: prod}
spec:
  replicas: 3
  selector: {matchLabels: {app: web}}
  template:
    metadata: {labels: {app: web}}
    spec:
      containers: [{name: app, image: "registry.example.com/app:1.0"}]
"""
SINGLE_REPLICA = WORKLOAD.replace("replicas: 3", "replicas: 1")

LIMIT_RANGE = """
apiVersion: v1
kind: LimitRange
metadata: {name: lr, namespace: prod}
spec:
  limits: [{type: Container, default: {cpu: 100m}}]
"""
QUOTA_READ = """
apiVersion: v1
kind: ResourceQuota
metadata: {name: rq, namespace: prod}
spec: {hard: {cpu: "10"}}
"""
QUOTA_REFUSED = QUOTA_READ.replace("apiVersion: v1", "apiVersion: quota.k8s.io/v1")
#: A readable kind whose spec is a scalar: `object_unreadable`, not `refusal`, and the other reason channel.
QUOTA_MALFORMED = """
apiVersion: v1
kind: ResourceQuota
metadata: {name: rq, namespace: prod}
spec: 7
"""

PDB_READ = """
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata: {name: pdb, namespace: prod}
spec:
  maxUnavailable: 1
  selector: {matchLabels: {app: web}}
"""
PDB_REFUSED = PDB_READ.replace("apiVersion: policy/v1", "apiVersion: policy.k8s.io/v1")
#: What KN-C009 exists to catch, in a shape KN-C009 never saw: three of three must stay up.
PDB_REFUSED_BLOCKING = PDB_REFUSED.replace("maxUnavailable: 1", "minAvailable: 3").replace("name: pdb", "name: blocker")
PDB_MALFORMED = """
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata: {name: broken, namespace: prod}
spec: 7
"""

HPA_READ = """
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata: {name: hpa, namespace: prod}
spec:
  minReplicas: 2
  maxReplicas: 5
  scaleTargetRef: {kind: Deployment, name: web, apiVersion: apps/v1}
"""
HPA_REFUSED = HPA_READ.replace("apiVersion: autoscaling/v2", "apiVersion: autoscaling.k8s.io/v2")

CLAIMING_POD = """
apiVersion: v1
kind: Pod
metadata: {name: p, namespace: prod}
spec:
  resourceClaims: [{name: gpu, resourceClaimName: c1}]
  containers: [{name: app, image: "registry.example.com/app:1.0"}]
"""
CLAIM_READ = """
apiVersion: resource.k8s.io/v1
kind: ResourceClaim
metadata: {name: c1, namespace: prod}
spec:
  devices:
    requests: [{name: r, exactly: {deviceClassName: gpu.example.com}}]
"""
CLAIM_REFUSED = CLAIM_READ.replace("apiVersion: resource.k8s.io/v1", "apiVersion: dra.k8s.io/v1")
#: The same refusal about an object the finding is not about: the name is the granularity of the claim.
CLAIM_REFUSED_OTHER_NAME = CLAIM_REFUSED.replace("name: c1", "name: somethingelse")

ADMIN_CLAIM = """
apiVersion: resource.k8s.io/v1
kind: ResourceClaim
metadata: {name: admin, namespace: prod}
spec:
  devices:
    requests: [{name: r, exactly: {deviceClassName: gpu.example.com, adminAccess: true}}]
"""
NAMESPACE_REFUSED = NAMESPACE.replace("apiVersion: v1", "apiVersion: config.openshift.io/v1")

SA_POD = """
apiVersion: v1
kind: Pod
metadata: {name: p, namespace: prod}
spec:
  serviceAccountName: app
  containers: [{name: app, image: "registry.example.com/app:1.0"}]
"""
SA_READ = """
apiVersion: v1
kind: ServiceAccount
metadata: {name: app, namespace: prod}
automountServiceAccountToken: false
"""
SA_REFUSED = SA_READ.replace("apiVersion: v1", "apiVersion: rbac.authorization.k8s.io/v1")
SA_REFUSED_OTHER_NAME = SA_REFUSED.replace("name: app", "name: other")

RWX_CLAIM = """
apiVersion: v1
kind: PersistentVolumeClaim
metadata: {name: pvc, namespace: prod}
spec:
  accessModes: [ReadWriteMany]
  storageClassName: shared-sc
  resources: {requests: {storage: 1Gi}}
"""
SC_READ = """
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata: {name: shared-sc}
provisioner: efs.csi.aws.com
"""
SC_REFUSED = SC_READ.replace("apiVersion: storage.k8s.io/v1", "apiVersion: csi.storage.k8s.io/v1")
SC_REFUSED_OTHER_NAME = SC_REFUSED.replace("name: shared-sc", "name: other-sc")


def _report(*parts: str) -> Report:
    return analyze("---".join(parts))


def _messages(rep: Report, rule_id: str) -> list[str]:
    return [f.message for f in rep.findings if f.rule_id == rule_id]


def _reason(rep: Report, rule_id: str) -> str:
    return rep.not_evaluated.get(rule_id) or rep.partly_evaluated.get(rule_id) or ""


def _names_kind(labels: list[str], kind: str) -> bool:
    """Whether "evaluated without" names this kind, by its last token and not by substring.

    `subject_label` writes one group and one kind per entry ("quota.openshift.io ClusterResourceQuota"), and a
    substring test reads that entry as naming ResourceQuota, and "resource.k8s.io ResourceClaimTemplate" as
    naming ResourceClaim. Two of the seven rules in this file depend on the difference.
    """
    return any(label.split()[-1] == kind for label in labels)


# --------------------------------------------------------------------------------------------------------------
# One case per rule: the bundle where the evidence is refused, the one where it is genuinely absent (negative
# control (a)), and the one where it is readable (negative control (b)).
# --------------------------------------------------------------------------------------------------------------

CASES: dict[str, tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...], str, str]] = {
    # rule id: (refused bundle, absent bundle, readable bundle, the kind, the text the absence claims)
    "KN-C016": (
        (NAMESPACE, WORKLOAD, LIMIT_RANGE, QUOTA_REFUSED),
        (NAMESPACE, WORKLOAD, LIMIT_RANGE),
        (NAMESPACE, WORKLOAD, LIMIT_RANGE, QUOTA_READ),
        "ResourceQuota",
        "has workloads and no ResourceQuota in this bundle",
    ),
    "KN-C008": (
        (WORKLOAD, PDB_REFUSED),
        (WORKLOAD,),
        (WORKLOAD, PDB_READ),
        "PodDisruptionBudget",
        "No PodDisruptionBudget selects this workload.",
    ),
    "KN-C015": (
        (CLAIMING_POD, CLAIM_REFUSED),
        (CLAIMING_POD,),
        (CLAIMING_POD, CLAIM_READ),
        "ResourceClaim",
        "no document in this bundle defines in namespace prod",
    ),
    "KN-C007": (
        (SINGLE_REPLICA, HPA_REFUSED),
        (SINGLE_REPLICA,),
        (SINGLE_REPLICA, HPA_READ),
        "HorizontalPodAutoscaler",
        "Deployment runs 1 replica(s).",
    ),
    "KN-S014": (
        (SA_POD, SA_REFUSED),
        (SA_POD,),
        (SA_POD, SA_READ),
        "ServiceAccount",
        "Pod automounts the token of ServiceAccount 'app'.",
    ),
    "KN-ST001": (
        (RWX_CLAIM, SC_REFUSED),
        (RWX_CLAIM,),
        (RWX_CLAIM, SC_READ),
        "StorageClass",
        "is neither defined in this bundle nor a known platform class",
    ),
}


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_a_genuinely_absent_kind_still_fires_the_finding(rule_id: str) -> None:
    """Negative control (a), first: a guard that silences a rule everywhere is worse than the bug it fixes."""
    _refused, absent, _read, _kind, claim = CASES[rule_id]
    rep = _report(*absent)
    assert any(claim in m for m in _messages(rep, rule_id)), (rule_id, _messages(rep, rule_id))


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_a_genuinely_absent_kind_is_still_recorded_as_evaluated_without_it(rule_id: str) -> None:
    """The other half of control (a): `rulesEvaluatedWithout` must keep saying "no X" where that is true."""
    _refused, absent, _read, kind, _claim = CASES[rule_id]
    rep = _report(*absent)
    assert _names_kind(rep.absent_subjects.get(rule_id) or [], kind), (rule_id, rep.absent_subjects)


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_a_readable_object_of_that_kind_is_still_read_and_the_rule_is_clean(rule_id: str) -> None:
    """Negative control (b): the group match stays intact and the rule still reaches a verdict."""
    _refused, _absent, readable, _kind, _claim = CASES[rule_id]
    rep = _report(*readable)
    assert _messages(rep, rule_id) == []
    assert rule_id in rep.evaluated_rules, (rule_id, _reason(rep, rule_id))


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_a_rule_does_not_state_or_excuse_an_absence_a_refusal_explains(rule_id: str) -> None:
    """The headline: the finding rested on an absence the same report names an object for."""
    refused, _absent, _read, _kind, claim = CASES[rule_id]
    rep = _report(*refused)
    assert not any(claim in m for m in _messages(rep, rule_id)), _messages(rep, rule_id)
    assert not any(claim in f.message for f in rep.findings), [f.rule_id for f in rep.findings]


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_the_refusal_is_recorded_rather_than_the_finding_silently_dropped(rule_id: str) -> None:
    """Suppressing the finding without recording why would make an unknown read as clean: the product's defect."""
    refused, _absent, _read, kind, _claim = CASES[rule_id]
    rep = _report(*refused)
    assert rule_id not in rep.evaluated_rules
    assert f"{kind} not audited" in _reason(rep, rule_id), _reason(rep, rule_id)
    assert rep.undetermined() is not None


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_a_refused_apiversion_is_never_explained_as_a_field_of_the_wrong_type(rule_id: str) -> None:
    """The near-miss G368 caught, one layer down: the fix for a refused group is not a field."""
    refused, _absent, _read, kind, _claim = CASES[rule_id]
    rep = _report(*refused)
    reason = _reason(rep, rule_id)
    assert f"apiVersion names a group kube-noob does not know {kind} under" in reason, reason
    assert "wrong type" not in reason
    assert "Fix the field" not in reason
    assert not any("has the wrong type" in a and rule_id in a for a in rep.assumptions), rep.assumptions


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_the_refused_object_is_named_once_and_not_also_called_absent(rule_id: str) -> None:
    """Nothing in the input is lost between the two answers, and nothing is counted under both."""
    refused, _absent, _read, kind, _claim = CASES[rule_id]
    rep = _report(*refused)
    assert [r["object"] for r in rep.not_audited if r["object"].startswith(kind + "/")], rep.not_audited
    assert not _names_kind(rep.absent_subjects.get(rule_id) or [], kind), rep.absent_subjects
    assert kind in str(rep.declined.get(rule_id))


# --------------------------------------------------------------------------------------------------------------
# Granularity. G366's lesson: a guard belongs at the granularity of the thing it guards. A refusal in `prod`
# must not blind the rule in `staging`, and a refusal about one object must not blind the rule about another.
# --------------------------------------------------------------------------------------------------------------


def test_a_refused_quota_in_one_namespace_does_not_blind_kn_c016_in_another() -> None:
    rep = _report(
        NAMESPACE,
        WORKLOAD,
        LIMIT_RANGE,
        QUOTA_REFUSED,
        NAMESPACE.replace("name: prod", "name: staging"),
        WORKLOAD.replace("namespace: prod", "namespace: staging"),
        LIMIT_RANGE.replace("namespace: prod", "namespace: staging"),
    )
    assert _messages(rep, "KN-C016") == [
        "Namespace staging has workloads and no ResourceQuota in this bundle. A ClusterResourceQuota or a "
        "cluster default may still cover it; this bundle cannot show that."
    ]


def test_a_refused_pdb_in_one_namespace_does_not_blind_kn_c008_in_another() -> None:
    rep = _report(WORKLOAD, WORKLOAD.replace("namespace: prod", "namespace: staging"), PDB_REFUSED)
    fired = [f.resource for f in rep.findings if f.rule_id == "KN-C008"]
    assert fired == ["Deployment/staging/web"], fired


def test_a_refused_hpa_in_one_namespace_does_not_blind_kn_c007_in_another() -> None:
    other = SINGLE_REPLICA.replace("namespace: prod", "namespace: staging")
    rep = _report(SINGLE_REPLICA, other, HPA_REFUSED)
    fired = [f.resource for f in rep.findings if f.rule_id == "KN-C007"]
    assert fired == ["Deployment/staging/web"], fired


def test_a_refused_claim_of_another_name_does_not_blind_kn_c015() -> None:
    """KN-C015 names the object it cannot find, so the guard is by name: that IS the claim's granularity."""
    rep = _report(CLAIMING_POD, CLAIM_REFUSED_OTHER_NAME)
    assert any("no document in this bundle defines in namespace prod" in m for m in _messages(rep, "KN-C015"))


def test_a_refused_serviceaccount_of_another_name_does_not_blind_kn_s014() -> None:
    rep = _report(SA_POD, SA_REFUSED_OTHER_NAME)
    assert _messages(rep, "KN-S014") == ["Pod automounts the token of ServiceAccount 'app'."]


def test_a_refused_storageclass_of_another_name_does_not_blind_kn_st001() -> None:
    rep = _report(RWX_CLAIM, SC_REFUSED_OTHER_NAME)
    assert any("neither defined in this bundle" in m for m in _messages(rep, "KN-ST001"))


# --------------------------------------------------------------------------------------------------------------
# KN-S031, the one rule whose finding is NOT withheld.
# --------------------------------------------------------------------------------------------------------------

ADMIN_MESSAGE = (
    "ResourceClaim request 'r' sets adminAccess: true, so it ignores every ordinary claim to the device and "
    "reaches devices another workload holds exclusively."
)


def test_a_refused_namespace_does_not_silence_the_admin_access_finding() -> None:
    """A HIGH security finding stands on either branch of the message; withholding it would be the worse bug."""
    rep = _report(ADMIN_CLAIM, NAMESPACE_REFUSED)
    assert _messages(rep, "KN-S031") == [ADMIN_MESSAGE]


def test_a_refused_namespace_is_recorded_against_kn_s031_rather_than_read_as_absent() -> None:
    """What was wrong is the branch, not the finding: the namespace half was decided from an absence it had not."""
    rep = _report(ADMIN_CLAIM, NAMESPACE_REFUSED)
    # A rule that declined on part of the input and reported on the rest IS in `evaluated_rules`, and is
    # accounted for in `partlyEvaluatedRules` with the object it declined on (D4). That is the record this
    # rule should have had, and did not: it was evaluated in full over a namespace it never read.
    assert "KN-S031" in rep.partly_evaluated, rep.partly_evaluated
    assert "Namespace not audited" in _reason(rep, "KN-S031"), _reason(rep, "KN-S031")
    assert "Namespace/prod" in str(rep.declined.get("KN-S031"))
    assert not _names_kind(rep.absent_subjects.get("KN-S031") or [], "Namespace")


def test_a_genuinely_absent_namespace_leaves_kn_s031_evaluated_and_firing() -> None:
    """Negative control (a) for KN-S031: a namespace this bundle does not declare is not a refusal."""
    rep = _report(ADMIN_CLAIM)
    assert _messages(rep, "KN-S031") == [ADMIN_MESSAGE]
    assert "KN-S031" in rep.evaluated_rules
    assert _names_kind(rep.absent_subjects.get("KN-S031") or [], "Namespace")
    assert "KN-S031" not in rep.partly_evaluated


def test_a_readable_namespace_still_decides_which_message_kn_s031_prints() -> None:
    """Negative control (b): the stronger sentence is the one a readable, unlabelled Namespace earns."""
    rep = _report(ADMIN_CLAIM, NAMESPACE)
    assert _messages(rep, "KN-S031") == [
        "ResourceClaim request 'r' sets adminAccess: true, and namespace prod in this bundle does not carry "
        'resource.kubernetes.io/admin-access: "true". The API server will refuse this object, so the claim does '
        "not exist and nothing that depends on it will schedule."
    ]
    assert "KN-S031" in rep.evaluated_rules


# --------------------------------------------------------------------------------------------------------------
# Part 1: one declaration, one check, both reason channels.
# --------------------------------------------------------------------------------------------------------------


def test_the_evidence_declaration_does_not_repeat_what_a_rule_already_declares() -> None:
    """Two lists for one question is how each came to know half of it (class 9). `_EVIDENCE_KINDS` is the rest."""
    for rule_id, kinds in _EVIDENCE_KINDS.items():
        assert rule_id in RULES, rule_id
        assert not (kinds & frozenset(RULES[rule_id].context)), (rule_id, kinds)
        assert kinds <= evidence_kinds(rule_id)


def test_every_rule_that_depends_on_another_object_has_exactly_one_declaration() -> None:
    """The former `_PARTNER_KINDS` keys and every `context=` rule answer through the same function."""
    for rule_id in _READS_THE_WORKLOAD_IT_JUDGES:
        assert evidence_kinds(rule_id), rule_id
    for rule_id, rule in RULES.items():
        declared = frozenset(rule.context) - {"*", "pod spec"}
        assert declared <= evidence_kinds(rule_id), rule_id


def test_a_refused_partner_beside_a_readable_one_is_no_longer_counted_clean() -> None:
    """The measurement: KN-C009 read as checked-and-clean over a PDB it never read, and the PDB blocked drains."""
    rep = _report(WORKLOAD, PDB_READ, PDB_REFUSED_BLOCKING)
    assert "KN-C009" not in rep.evaluated_rules
    assert "PodDisruptionBudget not audited" in _reason(rep, "KN-C009"), _reason(rep, "KN-C009")
    # The readable PDB is still read: only the refused one is in `notAudited`, and the rule is undecided
    # because of that one and not because the join made it blind to both.
    assert [r["object"] for r in rep.not_audited] == ["PodDisruptionBudget/prod/blocker"]


def test_a_readable_partner_alone_still_leaves_the_rule_evaluated() -> None:
    """Negative control for the join: one readable PDB that permits a disruption is still read and still clean."""
    rep = _report(WORKLOAD, PDB_READ)
    assert "KN-C009" in rep.evaluated_rules
    assert _messages(rep, "KN-C009") == []


def test_a_malformed_evidence_object_keeps_the_wrong_type_prose() -> None:
    """The other channel, unchanged: a field of the wrong type IS what that sentence is about, and the fix is one."""
    rep = _report(WORKLOAD, PDB_READ, PDB_MALFORMED)
    assert "KN-C009" not in rep.evaluated_rules
    assert "could not be read" in _reason(rep, "KN-C009"), _reason(rep, "KN-C009")
    assert any("has the wrong type" in a for a in rep.assumptions), rep.assumptions


def test_a_malformed_context_object_is_joined_through_the_same_check() -> None:
    """The half `_PARTNER_KINDS` knew, for a `context=` rule that was never asked it: KN-C016 and a scalar spec."""
    rep = _report(NAMESPACE, WORKLOAD, LIMIT_RANGE, QUOTA_MALFORMED)
    assert _messages(rep, "KN-C016") == []
    assert "KN-C016" not in rep.evaluated_rules
    assert "could not be read" in _reason(rep, "KN-C016"), _reason(rep, "KN-C016")


def test_a_refused_object_beside_a_readable_one_of_the_same_kind_is_caught_too() -> None:
    """The gap the join closes for every one of these rules, not only for KN-C009.

    G368's guard hangs off the `context=` loop, which runs only for a kind `has_subject` says is not in the
    input at all. One readable ServiceAccount anywhere in the bundle answers that question `True`, and the
    refused one next to it then went unasked -- so the pod was reported for mounting a token the input says it
    does not mount, with nothing in the record to say so.
    """
    rep = _report(SA_POD, SA_REFUSED, SA_READ.replace("name: app", "name: unrelated"))
    assert _messages(rep, "KN-S014") == []
    assert "ServiceAccount not audited" in _reason(rep, "KN-S014"), _reason(rep, "KN-S014")


def test_a_readable_pdb_in_another_namespace_does_not_answer_for_a_refused_one_here() -> None:
    """The same gap, and the granularity in both directions: `staging` readable, `prod` refused."""
    rep = _report(WORKLOAD, PDB_REFUSED, PDB_READ.replace("namespace: prod", "namespace: staging"))
    assert _messages(rep, "KN-C008") == []
    assert "PodDisruptionBudget not audited" in _reason(rep, "KN-C008"), _reason(rep, "KN-C008")


def test_the_join_withholds_the_clean_claim_and_not_the_findings() -> None:
    """A guard that suppressed a finding per BUNDLE would be the worse bug: the join suppresses nothing.

    `check_evidence` asks about the whole input, because the record it feeds -- "this rule was evaluated and is
    clean" -- is about the whole input. What it must not do is take a finding away: KN-C009's own verdict on a
    readable PodDisruptionBudget that blocks every eviction is still reported, and the refused one beside it is
    recorded as a decline on top of it (`partlyEvaluatedRules`), not instead of it.
    """
    blocking = PDB_READ.replace("maxUnavailable: 1", "minAvailable: 3")
    rep = _report(WORKLOAD, blocking, PDB_REFUSED_BLOCKING)
    assert _messages(rep, "KN-C009") == [
        "PodDisruptionBudget/prod/pdb allows no disruptions for Deployment/prod/web (3 replicas)."
    ]
    assert "KN-C009" in rep.partly_evaluated, rep.partly_evaluated
    assert "PodDisruptionBudget/prod/blocker" in str(rep.declined.get("KN-C009"))
