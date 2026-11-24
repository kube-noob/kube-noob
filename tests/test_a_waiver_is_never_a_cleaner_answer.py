"""An exception that accepts an unread object must not buy a better answer than not having it (G379).

`AGENTS.md`: a waiver is never a cleaner answer about the same evidence. Measured on `78b0484`, it was.

    hardened Deployment, 3 replicas, probes, no NetworkPolicy      exit 1, score 94.0, KN-N001 open
    + an allow-all `projectcalico.org/v3` NetworkPolicy            exit 1, score withheld, undetermined
    + that policy and a `notAudited` exception accepting it        exit 0, score 98.0, NO findings

Adding a policy the rules cannot read, and waiving it, scored four points HIGHER than the same Deployment with
no policy at all, and passed `--fail-on medium`, which the cleaner input fails. Before G368 the same three
inputs gave 94 / withheld / **94 with KN-N001 open** -- so this is a regression those two entries introduced,
not a standing defect.

The seam. `Report.undetermined` stops a decline withholding the score once an exception accepts every object
the rule declined on (`_all_accepted`, G281 review 5). That was sound while a decline only ever meant "the rule
found nothing there because it did not look". G368 and G369 made a decline able to stand IN FOR a finding: a
rule that would have reported "no NetworkPolicy for namespace prod" now declines instead, because the namespace
may be isolated by a policy nothing could read. Accepting the object then re-opened the score while the
suppressed finding stayed suppressed, and the rule was scored as though it had been evaluated and found
nothing.

Accepting an object says the reader may stop asking to read it. It does not say what the rule would have found
in it. So a decline that replaced a finding is never covered by an acceptance, and the report stays
undetermined -- which is the true answer, not the one the old code gave and not the one before G368 either.

The distinction has to be per decline, not per rule and not per report: the accept path is the only way a
Calico, Istio or Knative shop ever reaches a verdict, and blunting it would push every such user onto a flag
that turns the whole check off.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

HARDENED = """\
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: prod}
spec:
  replicas: 3
  selector: {matchLabels: {app: web}}
  template:
    metadata: {labels: {app: web}}
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
          readinessProbe: {httpGet: {path: /healthz, port: 8080}}
          livenessProbe: {httpGet: {path: /healthz, port: 8080}}
""" % ("a" * 64)

#: Allow-all, and under a group the rules do not know: the worst thing to be unable to read.
REFUSED_NETPOL = """\
apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata: {name: allow-all, namespace: prod}
spec:
  selector: all()
  types: [Ingress]
  ingress: [{action: Allow}]
"""

WAIVE_NETPOL = """\
apiVersion: kube-noob.io/v1
kind: ExceptionList
metadata: {name: waivers}
exceptions:
  - id: EXC-CNI-001
    notAudited: {namespace: prod, kind: NetworkPolicy, name: allow-all, apiGroup: projectcalico.org}
    reason: the cluster runs Calico and kube-noob has no reader for its policies
    owner: platform-team
    expires: 2027-06-30
"""

#: A refused object no rule reasons from the absence of: its decline suppresses nothing, so accepting it must
#: still restore the score. This is the path G281's review-5 entry added and that must survive untouched.
REFUSED_CLAIM = """\
apiVersion: dra.k8s.io/v1
kind: ResourceClaim
metadata: {name: unused, namespace: prod}
spec: {devices: {}}
"""

READ_NETPOL = """\
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: default-deny, namespace: prod}
spec: {podSelector: {}, policyTypes: [Ingress]}
"""

WAIVE_CLAIM = """\
apiVersion: kube-noob.io/v1
kind: ExceptionList
metadata: {name: waivers}
exceptions:
  - id: EXC-DRA-001
    notAudited: {namespace: prod, kind: ResourceClaim, name: unused, apiGroup: dra.k8s.io}
    reason: this cluster uses a DRA driver kube-noob has no reader for
    owner: platform-team
    expires: 2027-06-30
"""


def _audit(tmp_path: Path, name: str, *, waiver: str | None = None, **files: str) -> dict:
    d = tmp_path / name
    d.mkdir(parents=True, exist_ok=True)
    for stem, body in files.items():
        (d / f"{stem}.yaml").write_text(body)
    argv = ["audit", "-f", str(d), "--format", "json", "--fail-on", "medium"]
    if waiver is not None:
        exc = tmp_path / f"{name}-exc.yaml"
        exc.write_text(waiver)
        argv += ["--exceptions", str(exc)]
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    out = subprocess.run(
        [sys.executable, "-m", "kube_noob", *argv],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    rep = json.loads(out.stdout)
    rep["_exit"] = out.returncode
    return rep


@pytest.fixture(scope="module")
def alone(tmp_path_factory: pytest.TempPathFactory) -> dict:
    return _audit(tmp_path_factory.mktemp("g379a"), "alone", dep=HARDENED)


@pytest.fixture(scope="module")
def waived(tmp_path_factory: pytest.TempPathFactory) -> dict:
    return _audit(tmp_path_factory.mktemp("g379b"), "waived", waiver=WAIVE_NETPOL, dep=HARDENED, np=REFUSED_NETPOL)


def test_the_cleaner_input_is_the_baseline(alone: dict) -> None:
    """The input with nothing unreadable in it. Every other answer is compared against this one."""
    assert alone["_exit"] == 1
    assert alone["summary"]["score"] == 94.0
    assert any(f["ruleId"] == "KN-N001" for f in alone["findings"]), "KN-N001 is the finding at stake"


def test_an_unreadable_policy_alone_withholds_the_verdict(tmp_path: Path) -> None:
    """Unwaived, the refusal is honest and was never the defect."""
    rep = _audit(tmp_path, "refused", dep=HARDENED, np=REFUSED_NETPOL)
    assert rep["_exit"] == 1
    assert rep["summary"].get("verdict") == "undetermined"
    assert rep["summary"]["score"] is None


def test_a_waiver_does_not_buy_a_better_answer_than_the_cleaner_input(waived: dict, alone: dict) -> None:
    """The headline. Waived, this scored 98.0 and exited 0 where the input without the policy scores 94.0."""
    assert waived["_exit"] != 0, "an allow-all policy nothing read, waived, must not pass"
    assert waived["summary"]["score"] != 98.0
    score = waived["summary"]["score"]
    assert score is None or score <= alone["summary"]["score"], (score, alone["summary"]["score"])


def test_the_waived_report_is_undetermined_rather_than_clean(waived: dict) -> None:
    """Accepting the object says the reader may stop asking to read it, not what the rule would have found."""
    assert waived["summary"].get("verdict") == "undetermined"
    assert "KN-N001" in (waived["summary"].get("verdictReason") or ""), waived["summary"].get("verdictReason")


def test_the_suppressing_decline_is_marked_as_such(waived: dict) -> None:
    """The marker the accept path reads. Written only when true, so an older report reads as 'no'."""
    assert waived["declined"]["KN-N001"].get("suppressedFinding") is True, waived["declined"].get("KN-N001")


def test_a_waiver_over_a_decline_that_suppressed_nothing_still_restores_the_score(tmp_path: Path) -> None:
    """The negative control, and the reason this is per decline rather than per report.

    The accept path is how a Calico, Istio or Knative shop reaches a verdict at all. A refused object no rule
    reasons from the absence of declines without standing in for anything, and accepting it must still restore
    the score exactly as it did before (G281, review 5)."""
    files = {"dep": HARDENED, "np": READ_NETPOL, "claim": REFUSED_CLAIM}
    before = _audit(tmp_path, "dra-open", **files)
    assert before["_exit"] == 1 and before["summary"].get("verdict") == "undetermined"
    after = _audit(tmp_path, "dra-waived", waiver=WAIVE_CLAIM, **files)
    assert after["_exit"] == 0, after["summary"]
    assert after["summary"]["score"] == 98.0, after["summary"]
    assert after["summary"].get("verdict") != "undetermined"


def test_that_decline_is_not_marked_as_suppressing(tmp_path: Path) -> None:
    """The other side of the same distinction: nothing was replaced, so nothing is marked."""
    rep = _audit(tmp_path, "dra-mark", dep=HARDENED, np=READ_NETPOL, claim=REFUSED_CLAIM)
    for rid, record in (rep.get("declined") or {}).items():
        assert record.get("suppressedFinding") is not True, rid
