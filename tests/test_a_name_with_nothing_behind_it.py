"""A Pod that names an object nothing in the namespace defines (G396).

The input that found this: a Pod naming a ConfigMap volume, a Secret volume, a PersistentVolumeClaim, a
ServiceAccount and an ``envFrom.configMapRef``, none of them in the input, audited at exit 0 with one
unrelated LOW finding. KN-C013 abstained (``no Secret in the input``) and KN-C015 covers only ResourceClaims,
so no rule decided it and five names with nothing behind them read as a pass.

The two directions are the whole of the rule. A single file cannot tell "this ConfigMap does not exist" from
"you did not pass it", so on a fragment the rule must land in ``notEvaluated`` with a reason a reader can act
on; a directory is taken to be the whole namespace, so there the same name IS a gap and the rule must fire.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

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


def _rule_findings(text: str, **kw: Any) -> list:
    return [f for f in analyze(text, "kubernetes", **kw).findings if f.rule_id == RULE]


def _messages(text: str, **kw: Any) -> list[str]:
    return [f.message for f in _rule_findings(text, **kw)]


# --- the two directions -------------------------------------------------------------------------------------


def test_a_whole_namespace_naming_five_absent_objects_is_not_a_clean_audit() -> None:
    """The reproduction. A whole namespace is evidence about itself, so every one of the five is a gap."""
    found = _rule_findings(DANGLE)
    named = " | ".join(f.message for f in found)
    for want in ("no-such-sa", "no-such-configmap", "no-such-secret", "no-such-pvc", "also-missing"):
        assert want in named, f"{want} is named by the Pod and nothing in the namespace defines it: {named}"
    assert len(found) == 5, named
    for f in found:
        assert f.severity >= Severity.HIGH, f
        assert f.line is not None and f.path, "a defect the file proves must carry its line and path"
        assert "shop" in f.message, f.message


def test_a_fragment_abstains_with_a_reason_a_reader_can_act_on() -> None:
    """One file is not the namespace, so a dangling name there is not evidence of anything."""
    rep = analyze(DANGLE, "kubernetes", partial_bundle=True)
    assert [f for f in rep.findings if f.rule_id == RULE] == [], "a fragment cannot prove an object is absent"
    assert RULE not in rep.evaluated_rules, "abstaining is not evaluating"
    why = rep.not_evaluated[RULE]
    assert "part of a namespace was passed" in why, why
    assert "did not pass" in why, why


def test_the_rule_is_an_audit_stage_wiring_rule_like_its_neighbour() -> None:
    r = RULES[RULE]
    assert r.stage is Stage.AUDIT and r.category == "wiring"
    # KN-C015 is the same shape -- a name in a pod spec with no object behind it, and a Pod that never runs.
    assert r.severity is RULES["KN-C015"].severity


# --- a referent that IS there -------------------------------------------------------------------------------

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


def test_a_referent_that_is_present_does_not_fire() -> None:
    assert _rule_findings(DANGLE + PRESENT) == []


def test_the_reference_is_namespaced() -> None:
    """These four kinds are namespaced, so one of the same name in another namespace does not satisfy them."""
    elsewhere = DANGLE + PRESENT.replace("namespace: shop", "namespace: other")
    assert len(_rule_findings(elsewhere)) == 5, _messages(elsewhere)


# --- the escape hatches -------------------------------------------------------------------------------------

OPTIONAL = """
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


DEFAULT_SA = """
apiVersion: v1
kind: Pod
metadata: {name: d, namespace: shop}
spec:
  serviceAccountName: default
  containers:
    - {name: c, image: registry.example.com/c:1}
"""


def test_the_default_service_account_always_exists() -> None:
    """The controller manager creates `default` in every namespace, and an unset field selects it too."""
    assert _rule_findings(DEFAULT_SA) == [], _messages(DEFAULT_SA)
    assert _rule_findings(DEFAULT_SA.replace("  serviceAccountName: default\n", "")) == []


STS = """
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


def test_a_claim_a_volume_claim_template_generates_is_not_a_dangling_claim() -> None:
    """The StatefulSet controller creates `data-db-0`; no PersistentVolumeClaim named `data` is in the bundle,
    and saying so would be a finding on a correct StatefulSet."""
    assert _rule_findings(STS) == [], _messages(STS)


def test_a_refused_object_of_that_kind_suppresses_the_claim() -> None:
    """ "nothing in namespace shop defines it" is a false statement about a bundle that holds one the rules
    refused to read (G368, class 24)."""
    refused = (
        DANGLE
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


def test_the_cli_does_not_exit_0_on_a_directory_holding_the_reproduction(tmp_path: Path) -> None:
    import subprocess
    import sys

    (tmp_path / "pod.yaml").write_text(DANGLE, encoding="utf-8")
    proc = subprocess.run(
        check=False,
        args=[sys.executable, "-m", "kube_noob", "audit", "-f", str(tmp_path), "--format", "json"],
        capture_output=True,
        text=True,
        env={"PYTHONPATH": str(ROOT / "src"), "PATH": "/usr/bin:/bin"},
    )
    assert proc.returncode == 1, (proc.returncode, proc.stderr[-2000:])
    assert RULE in proc.stdout, proc.stdout[:2000]
