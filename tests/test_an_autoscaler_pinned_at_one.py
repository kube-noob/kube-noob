"""An autoscaler whose floor is one replica does not keep a workload off a single replica.

KN-C007 fires on a replicated workload declaring fewer than two replicas, and was excused by ANY
HorizontalPodAutoscaler whose `scaleTargetRef` names it. `_has_hpa` never read the autoscaler's own
`minReplicas`, which defaults to 1. An HPA at `1..5` lets the workload idle at one replica, and an HPA at `1..1`
pins it there -- exactly the "downtime on every node drain, upgrade or node failure" the rule's own rationale
names. Measured before this change: one replica with either autoscaler produced no KN-C007 finding and no
`notEvaluated` entry, so the walk's hop "Nothing here is left at a single replica" HELD on a workload left at one.

The silence is the defect class the walk exposed (G395): a rule that skips its subject records nothing, so no
consumer can tell "checked and satisfied" from "never looked". Here the skip was simply wrong, so the fix is in
the rule. The floor is read the way KN-C014 in the same module already reads it -- `minReplicas` if it is an
int, the API's default of 1 otherwise.
"""

from __future__ import annotations

import pytest

from kube_noob.audit.engine import analyze

ONE_REPLICA = """\
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: shop}
spec:
  replicas: 1
  selector: {matchLabels: {app: web}}
  template:
    metadata: {labels: {app: web}}
    spec:
      containers:
        - name: c
          image: registry.example.com/web@sha256:7777777777777777777777777777777777777777777777777777777777777777
"""

HPA = """\
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata: {name: web, namespace: shop}
spec:
  scaleTargetRef: {apiVersion: apps/v1, kind: Deployment, name: web}
%(floor)s  maxReplicas: %(ceiling)d
  metrics: []
"""


def _kn_c007(*docs: str) -> list[dict[str, object]]:
    report = analyze("---\n".join(docs), "kubernetes", None).as_dict()
    return [f for f in report.get("findings") or () if f["ruleId"] == "KN-C007"]


@pytest.mark.parametrize(
    ("floor", "ceiling"),
    [("  minReplicas: 1\n", 1), ("  minReplicas: 1\n", 5), ("", 5)],
    ids=["pinned-at-one", "floor-one-ceiling-five", "floor-defaulted-to-one"],
)
def test_an_autoscaler_whose_floor_is_one_does_not_excuse_a_single_replica(floor: str, ceiling: int) -> None:
    found = _kn_c007(ONE_REPLICA, HPA % {"floor": floor, "ceiling": ceiling})
    assert found, "a workload an autoscaler may hold at one replica was excused by the autoscaler's mere presence"


def test_an_autoscaler_whose_floor_is_two_does_excuse_it() -> None:
    """The other direction, or the rule fires on every correctly autoscaled workload that omits spec.replicas."""
    assert not _kn_c007(ONE_REPLICA, HPA % {"floor": "  minReplicas: 2\n", "ceiling": 5})


def test_no_autoscaler_still_fires() -> None:
    assert _kn_c007(ONE_REPLICA)


def test_an_autoscaler_for_another_workload_excuses_nothing() -> None:
    other = (HPA % {"floor": "  minReplicas: 3\n", "ceiling": 5}).replace("name: web}", "name: api}")
    assert other.count("name: api}") == 1, "the fixture did not retarget the autoscaler"
    assert _kn_c007(ONE_REPLICA, other)
