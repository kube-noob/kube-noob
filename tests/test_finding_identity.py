"""A finding's identity must survive edits that did not change the finding.

Without this, a baseline is worthless: inserting a sidecar at the front of `containers` renames every
finding on every other container, so the next run reports N fixed and N new for a change that fixed
nothing, the team runs `baseline update` to get CI green, and the update absorbs whatever real
regression landed that week.

The identity is the rule, the object and the NAME-KEYED location. It is deliberately not the message
(messages carry counts and sorted lists that change on their own), not the file path (a move, or a run
from a subdirectory, rewrites it), not the line, not the document index (adding a file to the bundle
shifts every later one) and not the severity (several rules override it per finding).

This is a separate thing from the SARIF `partialFingerprints` key that gate.py emits. That one is
GitHub's alert-matching key, and redefining it would reset every alert's history, so it is untouched.
"""

from __future__ import annotations

import json

from kube_noob.audit.engine import analyze
from kube_noob.yamlio import locator

_BASE = """
apiVersion: apps/v1
kind: Deployment
metadata: {name: app, namespace: prod}
spec:
  replicas: 2
  selector: {matchLabels: {app: app}}
  template:
    metadata: {labels: {app: app}}
    spec:
      containers:
%s
"""
_API = """        - name: api
          image: acme/api:latest
"""
_SIDECAR = """        - name: logger
          image: acme/logger:latest
"""


def _by_rule(manifests: str) -> dict[tuple[str, str], str]:
    """{(ruleId, container-ish locator): fingerprint} for findings that name a container."""
    rep = analyze(manifests, "kubernetes", None)
    return {(f.rule_id, f.locator): f.fingerprint() for f in rep.findings if "name=api" in f.locator}


def test_inserting_a_sidecar_does_not_rotate_the_api_container_fingerprints() -> None:
    """The case that makes or breaks a baseline."""
    before = _by_rule(_BASE % _API)
    after = _by_rule(_BASE % (_SIDECAR + _API))
    assert before, "the fixture produced no container findings, so this proves nothing"
    assert before == after, (
        "inserting a sidecar rotated the identity of findings on another container: "
        f"{sorted(set(before.items()) ^ set(after.items()))}"
    )


def test_the_locator_is_name_keyed_not_index_keyed() -> None:
    doc = {"spec": {"containers": [{"name": "sidecar"}, {"name": "api", "securityContext": {}}]}}
    assert locator(doc, ("spec", "containers", 1, "securityContext")) == "spec.containers[name=api].securityContext"


def test_a_scalar_list_entry_identifies_itself() -> None:
    doc = {"spec": {"capabilities": {"add": ["SYS_ADMIN"]}}}
    assert locator(doc, ("spec", "capabilities", "add", 0)) == "spec.capabilities.add[SYS_ADMIN]"


def test_an_item_with_no_natural_key_keeps_its_index() -> None:
    """A NetworkPolicy rule is identified by position in the API itself; pretending otherwise is worse."""
    assert locator({"spec": {"ingress": [{}]}}, ("spec", "ingress", 0)) == "spec.ingress[0]"


def test_the_fingerprint_is_in_the_report() -> None:
    rep = analyze(_BASE % _API, "kubernetes", None)
    blob = json.dumps(rep.as_dict())
    assert '"fingerprint"' in blob
    for f in rep.findings:
        assert len(f.fingerprint()) == 32 and f.fingerprint().isalnum()


def test_different_rules_on_one_object_have_different_identities() -> None:
    rep = analyze(_BASE % _API, "kubernetes", None)
    prints = [f.fingerprint() for f in rep.findings]
    assert len(prints) == len(set(prints)), "two findings collided onto one identity"


def test_the_message_is_not_part_of_the_identity() -> None:
    """KN-N012's message counts the pod templates in the namespace, so an unrelated workload used to
    rotate it. The identity must not move when only the wording does."""
    one = """
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: p, namespace: prod}
spec:
  podSelector: {matchLabels: {app: nothing}}
  policyTypes: [Ingress]
"""
    extra = """
apiVersion: v1
kind: Pod
metadata: {name: other, namespace: prod, labels: {app: other}}
spec:
  containers: [{name: c, image: i:1}]
"""

    def n012(text: str) -> set[str]:
        return {f.fingerprint() for f in analyze(text, "kubernetes", None).findings if f.rule_id == "KN-N012"}

    base = n012("\n---\n".join((_BASE % _API, one)))
    assert base, "KN-N012 did not fire, so this proves nothing"
    assert base == n012("\n---\n".join((_BASE % _API, one, extra)))


def test_a_name_shared_by_two_siblings_is_not_a_key() -> None:
    """A duplicated name identifies nothing, so the locator keeps the index for those items (G195).

    Two different defects on two entries that share a name used to collapse to one fingerprint, and a
    baseline entry for either then suppressed the other.
    """
    from kube_noob.yamlio import locator

    data = {"spec": {"resourceClaims": [{"name": "gpu"}, {"name": "gpu"}, {"name": "fpga"}]}}
    assert locator(data, ("spec", "resourceClaims", 0)) == "spec.resourceClaims[0]"
    assert locator(data, ("spec", "resourceClaims", 1)) == "spec.resourceClaims[1]"
    # The unique one still gets its name: only the ambiguous entries fall back.
    assert locator(data, ("spec", "resourceClaims", 2)) == "spec.resourceClaims[name=fpga]"


def test_two_defects_on_a_duplicated_claim_name_keep_distinct_identities() -> None:
    from kube_noob.audit.engine import analyze

    text = """
apiVersion: v1
kind: Pod
metadata: {name: p, namespace: ml}
spec:
  resourceClaims:
  - {name: gpu, resourceClaimName: a, resourceClaimTemplateName: b}
  - {name: gpu, resourceClaimTemplateName: t2}
  containers: [{name: c, image: i}]
"""
    found = [f for f in analyze(text, "kubernetes").findings if f.rule_id == "KN-V021"]
    assert len(found) == 2
    assert len({f.fingerprint() for f in found}) == 2, "a baseline entry for one would suppress the other"


def test_duplicate_container_names_also_fall_back_to_the_index() -> None:
    """Not DRA-specific: the same ambiguity exists wherever a list is keyed on a name the author repeated."""
    from kube_noob.yamlio import locator

    data = {"spec": {"containers": [{"name": "api"}, {"name": "api"}]}}
    assert locator(data, ("spec", "containers", 0, "securityContext")) == "spec.containers[0].securityContext"


def test_the_one_definition_of_the_identity_is_the_shared_function() -> None:
    """``Finding.fingerprint`` and ``fingerprint_for`` are one key, not two that agree today.

    The receipt fingerprints the gate's finding dicts -- which carry CVE and SAST results beside audit rules and
    are no longer ``Finding`` objects -- so the key had to be reachable as a function. A second implementation of
    it would be the defect class where a private copy of a shared list turns out to be a subset of it, so there is
    one definition and the method calls it. This test fails if the method ever stops doing that.
    """
    from kube_noob.audit.model import Finding, Severity, Stage, fingerprint_for

    f = Finding(
        rule_id="KN-S001",
        title="t",
        severity=Severity.HIGH,
        stage=Stage.AUDIT,
        category="security",
        resource="Deployment/prod/app",
        message="m",
        remediation="r",
        path="spec.template",
        locator="spec.template.spec.containers[name=api]",
    )
    assert f.fingerprint() == fingerprint_for(f.rule_id, f.resource, f.locator)
    bare = Finding(
        rule_id="KN-S001",
        title="t",
        severity=Severity.HIGH,
        stage=Stage.AUDIT,
        category="security",
        resource="Deployment/prod/app",
        message="m",
        remediation="r",
        path="spec.template",
    )
    assert bare.fingerprint() == fingerprint_for("KN-S001", "Deployment/prod/app", "spec.template")
