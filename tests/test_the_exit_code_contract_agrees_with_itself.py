"""Two commands derived the same verdict twice and disagreed with the report they had just printed (G370).

`AGENTS.md` publishes one exit-code contract: 0 ok, 1 a verdict that is not a pass, 2 config or usage, 3
clarification, 4 internal or refused, 5 evidence incomplete -- and "1 and 5 are not two answers to the same
question". Two commands answered it from their own arithmetic instead of from the verdict in hand.

**`validate` exited 0 on `summary.verdict: undetermined`.** Measured on a hardened Pod beside an
`rbac.k8s.io/v1 ClusterRoleBinding` (an apiVersion no API server serves, which the rules refuse):

    audit    -f mixed/ --fail-on never   exit 1
    validate -f mixed/                   exit 0   <- and its own report said verdict: undetermined

`validate` wrote `verdict: undetermined` with `verdictReason: "1 ClusterRoleBinding not audited ..."` into the
report it printed, then returned `1 if high + critical else 0` -- counts that are 0 when the only thing wrong is
that an object was not read. Eleven lines above it in the same function, `audit` calls
`receipt.audit_exit_code`, whose docstring says it is the ONE place for this arithmetic and that it reads
`summary.verdict`. Class 9, and class 25: the predicate was moved to one place and this caller kept its copy.

**`posture scan --fail-above N` exited 0 beside a ClusterRoleBinding granting cluster-admin to
`system:authenticated`.** The binding was in the input under `rbac.k8s.io/v1`; the scan refused to read it as
RBAC (correctly -- "a CRD that happens to be called Role is not RBAC: reading it as one would invent rights"),
recorded it in `notRead`, and filed the cause as `unmodelled`, which `GATED_CAUSES` excludes:

    paths: []   refused: []   notRead: ["ClusterRoleBinding/everyone-admin: apiVersion rbac.k8s.io/v1 is not
    rbac.authorization.k8s.io, so it was ignored"]   exit 0

The command's own `--help` says "exit 5 when an object or a read was refused ... listed under `refused`, because
the gate did not see everything". The reason given for leaving `unmodelled` ungated -- "a CRD the cluster does not
serve or a built-in role the bundle does not carry is normal" -- describes the `absent` cause, which has exactly
one call site and is the only one it fits. A present-but-misgrouped object was filed with the genuinely absent
ones: G368's finding ("a refused kind is not an absent kind") in a third module.

The rule now is agreement with the AUDIT -- the scan withholds a pass for exactly the objects the audit does not
audit -- which is what settled how wide the fix should be. Measured on all three `unmodelled` call sites:

    rbac.k8s.io/v1 ClusterRoleBinding (cluster-admin to system:authenticated)   audit 1, scan 0
    argoproj.io/v1alpha1 Rollout with a privileged container                    audit 1, scan 0
    serving.knative.dev/v1 Route and example.com/v1 Role                        audit refuses both outright

The Knative Route and the CRD called `Role` are the cases that look like they should stay ungated, and measuring
`kube_noob.audit.rules.refusal` on them is what decided otherwise: it returns a reason for each, so `audit`
already exits 1 on a bundle holding one. The scan was the outlier, and the escape hatch for such a bundle is a
`notAudited` exception rather than a quieter scan. `absent` -- "is not in the input" -- stays ungated, and it is
the one cause the ungated reasoning was ever written for.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

HARDENED_POD = """\
apiVersion: v1
kind: Pod
metadata: {name: ok, namespace: prod}
spec:
  automountServiceAccountToken: false
  securityContext: {runAsNonRoot: true, seccompProfile: {type: RuntimeDefault}}
  containers:
    - name: app
      image: registry.example.com/app@sha256:%s
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities: {drop: [ALL]}
      resources: {limits: {cpu: "1", memory: 256Mi}, requests: {cpu: 100m, memory: 128Mi}}
""" % ("a" * 64)

#: cluster-admin to every authenticated user, under an apiVersion no API server serves. The most dangerous object
#: this scan can be handed, in the one shape it cannot read.
MISGROUPED_CRB = """\
apiVersion: rbac.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: everyone-admin}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: cluster-admin}
subjects:
  - {kind: Group, apiGroup: rbac.authorization.k8s.io, name: "system:authenticated"}
"""

#: The same binding the scan DOES read, for the negative control: it must still be ranked, not refused.
READ_CRB = MISGROUPED_CRB.replace("rbac.k8s.io/v1", "rbac.authorization.k8s.io/v1")


def _run(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    return subprocess.run(
        [sys.executable, "-m", "kube_noob", *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )


def _dir(tmp_path: Path, name: str, **files: str) -> Path:
    d = tmp_path / name
    d.mkdir(parents=True, exist_ok=True)
    for stem, body in files.items():
        (d / f"{stem}.yaml").write_text(body)
    return d


@pytest.fixture(scope="module")
def mixed(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return _dir(tmp_path_factory.mktemp("g370"), "mixed", pod=HARDENED_POD, crb=MISGROUPED_CRB)


def test_the_premise_audit_calls_this_input_undetermined_and_exits_one(mixed: Path) -> None:
    """If `audit` did not already answer 1 here, the fix would be to `audit`, not to its neighbours."""
    assert _run(["audit", "-f", str(mixed), "--fail-on", "never"], ROOT).returncode == 1


def test_validate_says_undetermined_in_the_report_it_prints(mixed: Path) -> None:
    """The report was always honest. Only the exit code was not."""
    import json

    out = _run(["validate", "-f", str(mixed), "--format", "json"], ROOT)
    rep = json.loads(out.stdout)
    assert rep["summary"]["verdict"] == "undetermined", rep["summary"]
    assert rep["summary"]["counts"]["high"] + rep["summary"]["counts"]["critical"] == 0, rep["summary"]["counts"]


def test_validate_no_longer_exits_zero_on_an_undetermined_report(mixed: Path) -> None:
    """The headline. Exit 0 beside `verdict: undetermined` is an unknown reading as a pass."""
    assert _run(["validate", "-f", str(mixed)], ROOT).returncode == 1


def test_validate_still_exits_zero_on_an_input_it_could_read(tmp_path: Path) -> None:
    """Negative control: a guard that fails everything is worse than the bug it replaces."""
    clean = _dir(tmp_path, "clean", pod=HARDENED_POD)
    assert _run(["validate", "-f", str(clean)], ROOT).returncode == 0


def test_validate_and_audit_now_agree_about_this_directory(mixed: Path) -> None:
    """Three commands giving three answers about one directory was the shape of the finding."""
    assert (
        _run(["validate", "-f", str(mixed)], ROOT).returncode
        == _run(["audit", "-f", str(mixed), "--fail-on", "never"], ROOT).returncode
    )


def test_posture_scan_reports_the_misgrouped_binding_under_refused(mixed: Path) -> None:
    """`--help` promises a refused object is "listed under `refused`". It was only ever in `notRead`."""
    import json

    out = _run(["posture", "scan", "-f", str(mixed), "--fail-above", "1", "--format", "json"], ROOT)
    rep = json.loads(out.stdout)
    assert any("everyone-admin" in e for e in rep["refused"]), rep["refused"]
    assert any("everyone-admin" in e for e in rep["notRead"]), rep["notRead"]


def test_posture_scan_no_longer_exits_zero_beside_a_binding_it_could_not_read(mixed: Path) -> None:
    """Exit 5, the documented "the gate did not see everything", not 0 with `paths: []`."""
    assert _run(["posture", "scan", "-f", str(mixed), "--fail-above", "1"], ROOT).returncode == 5


def test_posture_scan_still_exits_zero_when_it_read_everything(tmp_path: Path) -> None:
    """Negative control, and the reason `misgrouped` is a cause of its own rather than all of `unmodelled`."""
    clean = _dir(tmp_path, "clean2", pod=HARDENED_POD)
    assert _run(["posture", "scan", "-f", str(clean), "--fail-above", "1"], ROOT).returncode == 0


def test_a_binding_under_the_group_the_scan_reads_is_still_read(tmp_path: Path) -> None:
    """The whole point of the group match stays intact: the real binding is read, so nothing withholds the gate.

    Readability is the claim here, not ranking. `posture scan` ranks attack PATHS, which need an entry edge, and
    this fixture exposes nothing -- the same binding under the correct group produces `paths: []` too, and that is
    the documented model rather than a second defect. What must hold after this change is that the readable object
    appears in NEITHER `refused` nor `notRead`, which is exactly the distinction the fix turns on."""
    import json

    d = _dir(tmp_path, "readable", pod=HARDENED_POD, crb=READ_CRB)
    out = _run(["posture", "scan", "-f", str(d), "--fail-above", "1", "--format", "json"], ROOT)
    rep = json.loads(out.stdout)
    assert rep["refused"] == [], rep["refused"]
    assert rep["notRead"] == [], rep["notRead"]
    assert out.returncode == 0, out.stderr


def test_fail_above_absent_still_does_nothing_on_its_own(mixed: Path) -> None:
    """Unchanged behaviour: without a threshold or --require-complete the command reports and exits 0 (G353)."""
    assert _run(["posture", "scan", "-f", str(mixed)], ROOT).returncode == 0


def test_the_gated_causes_are_the_ones_that_name_something_the_input_held() -> None:
    """The taxonomy itself, so a later edit cannot quietly re-file a present object as an absent one."""
    from kube_noob.attack_paths import GATED_CAUSES

    assert frozenset({"refused", "unmodelled"}) == GATED_CAUSES
    assert "absent" not in GATED_CAUSES, "a built-in role the bundle does not carry is not a refusal"


#: Argo's Rollout: a kind the scan does not rank at all, carrying a privileged container no rule read.
PRIVILEGED_ROLLOUT = """\
apiVersion: argoproj.io/v1alpha1
kind: Rollout
metadata: {name: r, namespace: prod}
spec:
  replicas: 1
  selector: {matchLabels: {app: r}}
  template:
    metadata: {labels: {app: r}}
    spec:
      containers:
        - name: app
          image: nginx:latest
          securityContext: {privileged: true}
"""


def test_the_audit_refuses_the_two_shapes_that_look_like_they_should_not_gate() -> None:
    """The measurement that decided how wide the fix should be, and the reason it is not a taxonomy preference.

    A Knative Route and a CRD that happens to be called `Role` are the cases for which "leave it ungated, this is
    normal" sounds right. It is not: the audit -- the product's one refusal detector -- returns a reason for both,
    so `audit` already exits 1 on a bundle holding one. Had this come back `None`, the scan would have been right
    and the fix would have had to be narrower."""
    from kube_noob.audit.rules import refusal
    from kube_noob.yamlio import Document

    for api, kind in (
        ("serving.knative.dev/v1", "Route"),
        ("example.com/v1", "Role"),
        ("rbac.k8s.io/v1", "ClusterRoleBinding"),
    ):
        doc = Document(index=0, data={"apiVersion": api, "kind": kind, "metadata": {"name": "x"}})
        assert refusal(doc), f"the audit reads {api} {kind}, so the scan gating on it would be wrong"
    ok = Document(
        index=0,
        data={"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding", "metadata": {"name": "x"}},
    )
    assert refusal(ok) is None, "the correctly grouped binding must still be read"


def test_the_scan_and_the_audit_agree_about_a_kind_the_scan_does_not_rank(tmp_path: Path) -> None:
    """The third `unmodelled` site, and the widest consequence: an Argo Rollout with a privileged container.

    `audit` lists it under `notAudited` and exits 1 (G360). The scan named it in `notRead` -- "carries a pod spec
    kube-noob has no reader for, so not ranked" -- and exited 0 with `refused: []`. A privileged container nothing
    read, and a gate that passed it."""
    import json

    d = _dir(tmp_path, "rollout", pod=HARDENED_POD, ro=PRIVILEGED_ROLLOUT)
    assert _run(["audit", "-f", str(d), "--fail-on", "never"], ROOT).returncode == 1
    out = _run(["posture", "scan", "-f", str(d), "--fail-above", "1", "--format", "json"], ROOT)
    rep = json.loads(out.stdout)
    assert any("Rollout/prod/r" in e for e in rep["refused"]), rep["refused"]
    assert _run(["posture", "scan", "-f", str(d), "--fail-above", "1"], ROOT).returncode == 5
