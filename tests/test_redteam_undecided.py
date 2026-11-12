"""A red-team scenario whose source rule was not evaluated is `undecided`, never `mitigated` (G276, second review).

`mitigated` means "every rule this scenario reads ran and found nothing". A PodDisruptionBudget with `selector: 7`
made KN-C009 decline -- correctly, it could not read the input -- and RT-UPGRADE-BLOCK, which reads only KN-C009,
then reported the cluster's upgrade path as mitigated: an absence read as a pass. The scenarios are parametrised from
`SCENARIOS` itself, and the rules each one reads are recorded while it runs, so a scenario added later is covered.
"""

from __future__ import annotations

import io
import json
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pytest

from kube_noob import cli
from kube_noob.audit import redteam
from kube_noob.audit.engine import build_context
from kube_noob.yamlio import load_documents

ROOT = Path(__file__).resolve().parents[1]

# A bundle in which every scenario applies: replicated workloads, a PVC, a Route-exposed Service, a PDB.
BUNDLE = """
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: shop}
spec:
  replicas: 3
  selector: {matchLabels: {app: web}}
  template:
    metadata: {labels: {app: web}}
    spec:
      volumes: [{name: d, persistentVolumeClaim: {claimName: data}}]
      containers: [{name: web, image: nginx, ports: [{containerPort: 8080}]}]
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata: {name: data, namespace: shop}
spec: {accessModes: [ReadWriteMany], resources: {requests: {storage: 1Gi}}}
---
apiVersion: v1
kind: Service
metadata: {name: web, namespace: shop}
spec: {type: LoadBalancer, selector: {app: web}, ports: [{port: 80, targetPort: 8080}]}
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata: {name: web, namespace: shop}
spec: {minAvailable: 1, selector: {matchLabels: {app: web}}}
"""


@pytest.mark.parametrize("fn", redteam.SCENARIOS, ids=lambda f: f.__name__)
def test_a_scenario_whose_rules_did_not_run_is_undecided(fn: redteam.ScenarioFn) -> None:
    ctx = build_context(load_documents(BUNDLE), "openshift", "4.20", False, None, ())
    read = redteam.rules_read(fn, ctx, [])
    assert read, f"{fn.__name__} reads no rule; then it has nothing to be mitigated by"
    ctx.undecided.update(read)
    [scenario] = redteam.red_team_with(ctx, [], (fn,))
    # Exposed stays exposed when the input itself shows the exposure; what it may never be is mitigated.
    assert scenario.verdict in ("undecided", "exposed"), (fn.__name__, scenario.verdict)
    said = " ".join(scenario.evidence)
    assert all(r in said for r in read), (fn.__name__, scenario.evidence)


def test_the_reviewers_bad_pdb_makes_the_upgrade_scenario_undecided(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("KUBE_NOOB_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("KUBE_NOOB_LEARNING_ENABLED", "false")
    f = tmp_path / "pdb-bad.yaml"
    f.write_text(
        "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: web, namespace: shop}\nspec:\n  replicas: 3\n"
        "  selector: {matchLabels: {app: web}}\n  template:\n    metadata: {labels: {app: web}}\n"
        "    spec: {containers: [{name: web, image: nginx}]}\n---\napiVersion: policy/v1\n"
        "kind: PodDisruptionBudget\nmetadata: {name: web, namespace: shop}\n"
        "spec: {minAvailable: 3, selector: {matchLabels: {app: web}}}\n---\napiVersion: policy/v1\n"
        "kind: PodDisruptionBudget\nmetadata: {name: other, namespace: shop}\nspec: {minAvailable: 1, selector: 7}\n"
    )
    out = io.StringIO()
    with redirect_stdout(out), redirect_stderr(io.StringIO()):
        cli.main(["redteam", "-f", str(f), "--format", "json"])
    doc = json.loads(out.getvalue())
    upgrade = next(s for s in doc["scenarios"] if s["scenarioId"] == "RT-UPGRADE-BLOCK")
    assert upgrade["verdict"] != "mitigated", upgrade
    assert any("KN-C009" in a for a in doc["assumptions"]), "the redteam document says what was not evaluated"
