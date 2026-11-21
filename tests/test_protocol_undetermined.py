"""`run_protocol` is a renderer of the audit's report, and `ready` is the strongest word it says (G339).

It decided `ready` from an absence of HIGH findings and never read `Report.undetermined()`, the one predicate
every other renderer reads. So the same privileged container was `blocked` in a Deployment and `ready` -- exit 0,
`remainingBlockers: []`, with `kubectl apply -f manifest.yaml` printed under it -- in a kind no rule reads.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kube_noob.audit import protocol
from kube_noob.cli import main

PRIVILEGED = "{name: c, image: 'docker:24-dind', securityContext: {privileged: true}}"

#: An Argo Rollout: a pod spec in a kind no rule reads, which the audit reports as not audited.
ROLLOUT = f"""
apiVersion: argoproj.io/v1alpha1
kind: Rollout
metadata: {{name: web, namespace: shop}}
spec:
  selector: {{matchLabels: {{app: web}}}}
  template:
    metadata: {{labels: {{app: web}}}}
    spec:
      containers: [{PRIVILEGED}]
"""

#: A Kubeflow Notebook: a second kind no rule reads, so the test does not rest on one name.
NOTEBOOK = ROLLOUT.replace("argoproj.io/v1alpha1", "kubeflow.org/v1").replace("kind: Rollout", "kind: Notebook")

DEPLOYMENT = ROLLOUT.replace("argoproj.io/v1alpha1", "apps/v1").replace("kind: Rollout", "kind: Deployment")

BLUEPRINT = {"name": "api", "namespace": "shop", "image": "quay.io/a/api:1.0.0", "platform": "kubernetes"}


def test_a_generated_workload_is_still_ready() -> None:
    """The negative control, first: what the audit read in full and found no blocker in keeps the word. A fix
    that held every run undetermined would be an alert nobody reads."""
    out = protocol.run_protocol("build it", blueprint=BLUEPRINT)
    assert out["status"] == "ready"
    assert out["auditValidationBrief"]["after"].get("verdict") != "undetermined"
    assert "statusReason" not in out


def test_a_reviewed_manifest_the_audit_read_in_full_is_still_ready() -> None:
    """The same control through the review path: the generator's own output, handed back as manifests."""
    generated = protocol.run_protocol("build it", blueprint=BLUEPRINT)["productionManifest"]
    out = protocol.run_protocol("review this", manifests=generated, platform="kubernetes")
    assert out["status"] == "ready"


def test_a_blocker_is_still_blocked() -> None:
    out = protocol.run_protocol("review this", manifests=DEPLOYMENT, platform="kubernetes")
    assert out["status"] == "blocked"
    assert out["redTeamFindingsAndSafeguards"]["remainingBlockers"]


@pytest.mark.parametrize("manifests", [ROLLOUT, NOTEBOOK], ids=["an Argo Rollout", "a Kubeflow Notebook"])
def test_an_object_the_audit_did_not_read_is_not_ready(manifests: str) -> None:
    out = protocol.run_protocol("is this ready for production?", manifests=manifests, platform="kubernetes")
    assert out["auditValidationBrief"]["after"]["verdict"] == "undetermined"  # the audit already says so
    assert out["status"] == "undetermined"
    assert "shop/web" in out["statusReason"]


def test_the_scenarios_that_could_not_be_decided_are_beside_the_ones_that_were() -> None:
    """`exposedScenarios: []` beside a scenario the red team could not decide is an empty list standing in for
    "nothing to report"."""
    out = protocol.run_protocol("review this", manifests=ROLLOUT, platform="kubernetes")
    safeguards = out["redTeamFindingsAndSafeguards"]
    undecided = [s["scenarioId"] for s in out["steps"]["redTeam"]["scenarios"] if s["verdict"] == "undecided"]
    assert undecided, "the fixture no longer leaves a scenario undecided"
    assert [s["scenarioId"] for s in safeguards["undecidedScenarios"]] == undecided
    assert safeguards["exposedScenarios"] == []


def test_a_blocker_beside_an_unread_object_is_blocked_and_says_what_was_not_read() -> None:
    """Two independent facts: a finding is a finding, and part of the input was never read."""
    out = protocol.run_protocol("review this", manifests=DEPLOYMENT + "---" + ROLLOUT, platform="kubernetes")
    assert out["status"] == "blocked"
    assert "Rollout" in out["statusReason"]


def test_the_command_does_not_exit_0_on_an_undetermined_run(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    f = tmp_path / "rollout.yaml"
    f.write_text(ROLLOUT)
    rc = main(["protocol", "is this ready?", "-f", str(f), "--platform", "kubernetes", "--format", "json"])
    assert json.loads(capsys.readouterr().out)["status"] == "undetermined"
    assert rc == 5
    rc = main(["protocol", "is this ready?", "-f", str(f), "--platform", "kubernetes"])
    text = capsys.readouterr().out
    assert rc == 5
    assert "status: undetermined" in text
    assert "kubectl apply -f manifest.yaml" not in text.split("validationCommands")[0]


def test_the_command_still_exits_0_and_1_where_it_did(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    good = tmp_path / "good.yaml"
    good.write_text(protocol.run_protocol("build it", blueprint=BLUEPRINT)["productionManifest"])
    assert main(["protocol", "review", "-f", str(good), "--platform", "kubernetes"]) == 0
    bad = tmp_path / "bad.yaml"
    bad.write_text(DEPLOYMENT)
    assert main(["protocol", "review", "-f", str(bad), "--platform", "kubernetes"]) == 1
    capsys.readouterr()


def test_a_status_the_command_does_not_know_is_not_a_pass(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The exit code came from `{...}.get(status, 0)`: every status nobody had listed, `undetermined` among them,
    exited 0."""
    from kube_noob import toolkit as tk

    monkeypatch.setattr(tk.Toolkit, "run_protocol", lambda self, p: {"status": "a-word-added-later"})
    f = tmp_path / "x.yaml"
    f.write_text(DEPLOYMENT)
    assert main(["protocol", "review", "-f", str(f), "--format", "json"]) == 4
