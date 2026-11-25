"""A Pod that names an object nothing in the namespace defines (G396).

The input that found this: a Pod naming a ConfigMap volume, a Secret volume, a PersistentVolumeClaim, a
ServiceAccount and an ``envFrom.configMapRef``, none of them in the input, audited at exit 0 with one
unrelated LOW finding and no word about any of the five. KN-C013 is about a pull secret in the WRONG namespace
and KN-C015 reads only ResourceClaims, so no rule asked the question.

The first answer (KN-C017 firing on every such name in a directory) was wrong in the other direction, and the
full suite showed it: 98 failures, every one a correct repository. A directory is taken to be the whole
namespace, which is sound for what people commit (a NetworkPolicy) and unsound for what they do not: a correct
GitOps repository carries no Secrets -- sealed-secrets, external-secrets, cert-manager or a person create them --
and often no ServiceAccounts or claims either. So absence is evidence only for a kind the bundle demonstrably
manages in that namespace:

- the namespace defines at least one object of that kind -> a name with nothing behind it is a real gap, most
  often a typo (``db-creds`` defined, ``db-cred`` referenced): it fires;
- it defines none -> its absence says nothing: the rule records that it did not judge that kind, and why;
- a fragment (one file) -> it abstains outright, as before.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from kube_noob.audit.engine import analyze
from kube_noob.audit.model import Severity, Stage
from kube_noob.audit.rules import RULES

RULE = "KN-C017"
ROOT = Path(__file__).resolve().parents[1]

#: The reproduction, trimmed of the hardening that is not what this rule is about.
DANGLE = """
apiVersion: v1
kind: Pod
metadata: {name: dangle, namespace: shop}
spec:
  serviceAccountName: no-such-sa
  volumes:
    - name: cfg
      configMap: {name: no-such-configmap}
    - name: sec
      secret: {secretName: no-such-secret}
    - name: data
      persistentVolumeClaim: {claimName: no-such-pvc}
  containers:
    - name: c
      image: registry.example.com/c:1
      envFrom:
        - configMapRef: {name: also-missing}
"""

#: One object of each kind in `shop`, none of them the name the Pod asks for: the namespace now MANAGES all four
#: kinds, so a name with nothing behind it is evidence.
MANAGED = """
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: other-sa, namespace: shop}
---
apiVersion: v1
kind: ConfigMap
metadata: {name: other-cm, namespace: shop}
---
apiVersion: v1
kind: Secret
metadata: {name: other-secret, namespace: shop}
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata: {name: other-pvc, namespace: shop}
"""

#: The five names the Pod asks for, in `shop`.
PRESENT = """
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: no-such-sa, namespace: shop}
---
apiVersion: v1
kind: ConfigMap
metadata: {name: no-such-configmap, namespace: shop}
---
apiVersion: v1
kind: Secret
metadata: {name: no-such-secret, namespace: shop}
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata: {name: no-such-pvc, namespace: shop}
---
apiVersion: v1
kind: ConfigMap
metadata: {name: also-missing, namespace: shop}
"""

FIVE = ("no-such-sa", "no-such-configmap", "no-such-secret", "no-such-pvc", "also-missing")


def _rule_findings(text: str, **kw: Any) -> list:
    return [f for f in analyze(text, "kubernetes", **kw).findings if f.rule_id == RULE]


def _messages(text: str, **kw: Any) -> list[str]:
    return [f.message for f in _rule_findings(text, **kw)]


# --- the three directions -----------------------------------------------------------------------------------


def test_a_namespace_that_manages_the_kinds_and_misses_five_names_fires_five_times() -> None:
    found = _rule_findings(DANGLE + MANAGED)
    named = " | ".join(f.message for f in found)
    for want in FIVE:
        assert want in named, f"{want} is named by the Pod and nothing in the namespace defines it: {named}"
    assert len(found) == 5, named
    for f in found:
        assert f.severity >= Severity.HIGH, f
        assert f.line is not None and f.path, "a defect the file proves must carry its line and path"
        assert "shop" in f.message, f.message
    rep = analyze(DANGLE + MANAGED, "kubernetes")
    assert RULE in rep.evaluated_rules and RULE not in rep.not_evaluated and RULE not in rep.partly_evaluated


def test_a_namespace_that_defines_none_of_the_kinds_is_not_judged_and_says_which() -> None:
    """The reproduction itself: a directory that defines no ConfigMap, Secret, claim or ServiceAccount in `shop`
    is no evidence that any of the five is missing -- a correct GitOps repository looks exactly like this."""
    rep = analyze(DANGLE, "kubernetes")
    assert [f for f in rep.findings if f.rule_id == RULE] == [], "absence of an unmanaged kind is not evidence"
    assert RULE not in rep.evaluated_rules, "not judging is not judging clean"
    why = rep.not_evaluated[RULE]
    for kind in ("ConfigMap", "PersistentVolumeClaim", "Secret", "ServiceAccount"):
        assert kind in why, why
    assert "namespace shop" in why and "outside" in why, why


def test_a_fragment_abstains_with_a_reason_a_reader_can_act_on() -> None:
    """One file is not the namespace, so a dangling name there is not evidence -- even of a managed kind."""
    rep = analyze(DANGLE + MANAGED, "kubernetes", partial_bundle=True)
    assert [f for f in rep.findings if f.rule_id == RULE] == [], "a fragment cannot prove an object is absent"
    assert RULE not in rep.evaluated_rules, "abstaining is not evaluating"
    why = rep.not_evaluated[RULE]
    assert "part of a namespace was passed" in why and "did not pass" in why, why


# --- the split, per kind: one object of the kind defined and the name a typo of it ---------------------------

_TYPO_POD = """
apiVersion: v1
kind: Pod
metadata: {{name: p, namespace: shop}}
spec:
  {spec}
  containers:
    - name: c
      image: registry.example.com/c:1
      {container}
---
apiVersion: v1
kind: {kind}
metadata: {{name: db-creds, namespace: shop}}
"""

KINDS = {
    "Secret": ("volumes: [{name: v, secret: {secretName: db-cred}}]", ""),
    "ConfigMap": ("", "envFrom: [{configMapRef: {name: db-cred}}]"),
    "PersistentVolumeClaim": ("volumes: [{name: v, persistentVolumeClaim: {claimName: db-cred}}]", ""),
    "ServiceAccount": ("serviceAccountName: db-cred", ""),
}


@pytest.mark.parametrize("kind", sorted(KINDS))
def test_a_managed_kind_with_a_typod_name_fires(kind: str) -> None:
    spec, container = KINDS[kind]
    text = _TYPO_POD.format(spec=spec, container=container, kind=kind)
    found = _messages(text)
    assert len(found) == 1 and f"{kind} 'db-cred'" in found[0], found
    # The reader of a typo needs the name that IS there.
    assert "'db-creds'" in found[0], found[0]


@pytest.mark.parametrize("kind", sorted(KINDS))
def test_an_unmanaged_kind_abstains_and_names_that_kind(kind: str) -> None:
    spec, container = KINDS[kind]
    # The same Pod, with the one object of that kind moved to another namespace: `shop` now manages none.
    text = _TYPO_POD.format(spec=spec, container=container, kind=kind).replace(
        "metadata: {name: db-creds, namespace: shop}", "metadata: {name: db-creds, namespace: elsewhere}"
    )
    rep = analyze(text, "kubernetes")
    assert [f for f in rep.findings if f.rule_id == RULE] == [], rep.findings
    why = rep.not_evaluated[RULE]
    assert f"no {kind}" in why and "namespace shop" in why, why


def test_a_managed_kind_fires_beside_an_unmanaged_one_and_the_record_names_the_unjudged_kind() -> None:
    """Fires on the Secret (managed, typo'd) and does not judge the ConfigMap (unmanaged). It RAN, so it is
    partly evaluated -- and the note must be this rule's own reason, not the engine's fallback for a field of a
    type it could not read, which is what a `nothing_to_judge` beside a finding used to produce."""
    text = (
        _TYPO_POD.format(spec=KINDS["Secret"][0], container="envFrom: [{configMapRef: {name: cm}}]", kind="Secret")
        + "\n"
    )
    rep = analyze(text, "kubernetes")
    found = [f.message for f in rep.findings if f.rule_id == RULE]
    assert len(found) == 1 and "Secret 'db-cred'" in found[0], found
    assert RULE in rep.evaluated_rules and RULE not in rep.not_evaluated
    note = rep.partly_evaluated[RULE]
    assert "no ConfigMap" in note and "namespace shop" in note, note
    assert "type it cannot read" not in note, note


def test_the_rule_is_an_audit_stage_wiring_rule_like_its_neighbour() -> None:
    r = RULES[RULE]
    assert r.stage is Stage.AUDIT and r.category == "wiring"
    # KN-C015 is the same shape -- a name in a pod spec with no object behind it, and a Pod that never runs.
    assert r.severity is RULES["KN-C015"].severity


# --- a referent that IS there -------------------------------------------------------------------------------


def test_a_referent_that_is_present_does_not_fire() -> None:
    assert _rule_findings(DANGLE + PRESENT) == []
    assert RULE in analyze(DANGLE + PRESENT, "kubernetes").evaluated_rules


def test_the_reference_is_namespaced() -> None:
    """These four kinds are namespaced, so one of the same name in another namespace does not satisfy them."""
    elsewhere = DANGLE + MANAGED + PRESENT.replace("namespace: shop", "namespace: other")
    assert len(_rule_findings(elsewhere)) == 5, _messages(elsewhere)


# --- the escape hatches (each with its kind MANAGED, so the hatch, not the abstention, is what is tested) -----

OPTIONAL = (
    """
apiVersion: v1
kind: Pod
metadata: {name: opt, namespace: shop}
spec:
  volumes:
    - name: cfg
      configMap: {name: gone-cm, optional: true}
    - name: sec
      secret: {secretName: gone-sec, optional: true}
    - name: proj
      projected:
        sources:
          - configMap: {name: gone-proj-cm, optional: true}
          - secret: {name: gone-proj-sec, optional: true}
  containers:
    - name: c
      image: registry.example.com/c:1
      envFrom:
        - configMapRef: {name: gone-ef-cm, optional: true}
        - secretRef: {name: gone-ef-sec, optional: true}
      env:
        - name: A
          valueFrom:
            configMapKeyRef: {name: gone-k-cm, key: a, optional: true}
        - name: B
          valueFrom:
            secretKeyRef: {name: gone-k-sec, key: b, optional: true}
"""
    + MANAGED
)


def test_optional_true_is_the_apis_own_escape_hatch_and_never_a_finding() -> None:
    """kubelet starts the container without it, so an absent referent is the declared behaviour."""
    assert _rule_findings(OPTIONAL) == [], _messages(OPTIONAL)


def test_without_optional_every_one_of_those_references_is_read() -> None:
    """The same manifest with the hatch closed: the rule must reach all eight, not only the volumes."""
    required = OPTIONAL.replace(", optional: true", "").replace(" optional: true,", "")
    found = _messages(required)
    for want in (
        "gone-cm",
        "gone-sec",
        "gone-proj-cm",
        "gone-proj-sec",
        "gone-ef-cm",
        "gone-ef-sec",
        "gone-k-cm",
        "gone-k-sec",
    ):
        assert any(want in m for m in found), f"{want} not read: {found}"


DEFAULT_SA = (
    """
apiVersion: v1
kind: Pod
metadata: {name: d, namespace: shop}
spec:
  serviceAccountName: default
  containers:
    - {name: c, image: registry.example.com/c:1}
"""
    + MANAGED
)


def test_the_default_service_account_always_exists() -> None:
    """The controller manager creates `default` in every namespace, and an unset field selects it too."""
    assert _rule_findings(DEFAULT_SA) == [], _messages(DEFAULT_SA)
    assert _rule_findings(DEFAULT_SA.replace("  serviceAccountName: default\n", "")) == []


STS = (
    """
apiVersion: apps/v1
kind: StatefulSet
metadata: {name: db, namespace: shop}
spec:
  serviceName: db
  selector: {matchLabels: {app: db}}
  volumeClaimTemplates:
    - metadata: {name: data}
      spec: {accessModes: [ReadWriteOnce], resources: {requests: {storage: 1Gi}}}
  template:
    metadata: {labels: {app: db}}
    spec:
      volumes:
        - name: data
          persistentVolumeClaim: {claimName: data}
      containers:
        - {name: c, image: registry.example.com/c:1}
"""
    + MANAGED
)


def test_a_claim_a_volume_claim_template_generates_is_not_a_dangling_claim() -> None:
    """The StatefulSet controller creates `data-db-0`; no PersistentVolumeClaim named `data` is in the bundle,
    and saying so would be a finding on a correct StatefulSet."""
    assert _rule_findings(STS) == [], _messages(STS)


def test_a_refused_object_of_that_kind_suppresses_the_claim() -> None:
    """ "nothing in namespace shop defines it" is a false statement about a bundle that holds one the rules
    refused to read (G368, class 24)."""
    refused = (
        DANGLE
        + MANAGED
        + """
---
apiVersion: notanapi/v9
kind: ConfigMap
metadata: {name: no-such-configmap, namespace: shop}
"""
    )
    assert not any("no-such-configmap" in m for m in _messages(refused)), _messages(refused)


# --- the surfaces a new rule has to be declared on ----------------------------------------------------------


def test_the_rule_is_skipped_at_admission() -> None:
    """Admission sees one object and the context cache fetches no ConfigMaps, Secrets or ServiceAccounts, so
    without this it would warn that a ConfigMap is missing on every correct Pod (KN-C015's own reason)."""
    from kube_noob.admission import CROSS_OBJECT, SKIPPED_RULES

    assert RULE in SKIPPED_RULES
    assert RULE not in CROSS_OBJECT, "SKIPPED_RULES already stops it; listing both is a second answer"


def _cli(directory: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        check=False,
        args=[sys.executable, "-m", "kube_noob", "audit", "-f", str(directory), "--format", "json"],
        capture_output=True,
        text=True,
        env={"PYTHONPATH": str(ROOT / "src"), "PATH": "/usr/bin:/bin"},
    )


def test_the_cli_fails_a_directory_whose_managed_kinds_miss_a_name(tmp_path: Path) -> None:
    (tmp_path / "pod.yaml").write_text(DANGLE + MANAGED, encoding="utf-8")
    proc = _cli(tmp_path)
    assert proc.returncode == 1, (proc.returncode, proc.stderr[-2000:])
    assert sum(f["ruleId"] == RULE for f in json.loads(proc.stdout)["findings"]) == 5


def test_the_cli_names_the_unjudged_kinds_on_the_reproduction_rather_than_passing_it(tmp_path: Path) -> None:
    (tmp_path / "pod.yaml").write_text(DANGLE, encoding="utf-8")
    proc = _cli(tmp_path)
    report = json.loads(proc.stdout)
    assert not any(f["ruleId"] == RULE for f in report["findings"])
    assert "Secret" in report["notEvaluated"][RULE], report["notEvaluated"].get(RULE)
