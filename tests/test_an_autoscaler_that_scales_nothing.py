"""A HorizontalPodAutoscaler whose floor is above its ceiling, or whose target is not in its namespace (G433).

Three rules read an HPA (KN-C007, KN-C012, KN-C014) and each matched `scaleTargetRef` to a workload inline, by
name, kind and namespace. None of them said anything about the autoscaler itself: one that the API server refuses
(`minReplicas` above `maxReplicas`) excused KN-C007's single replica, and one whose target is in another
namespace -- a HorizontalPodAutoscaler scales only a target in its own -- matched nothing, so nothing was said.

Measured (G433) with `kube_noob.audit.engine.analyze`: one `apps/v1` Deployment `web` (one replica) and one
`autoscaling/v2` HPA `web`, both in `shop`, a whole namespace unless the row says fragment. "nE" is the rule's
`notEvaluated` reason and HPA is HorizontalPodAutoscaler. KN-V025 did not exist before, so its "before" is that no
rule spoke.

| case                                    | before: any rule about the HPA itself | KN-V025 after                 |
|-----------------------------------------|---------------------------------------|-------------------------------|
| target here, 2..5                       | -                                     | - (evaluated)                 |
| minReplicas 6, maxReplicas 5            | - (and KN-C007 is excused by it)      | finding, spec.minReplicas     |
| minReplicas 5, maxReplicas 5            | -                                     | -                             |
| no minReplicas (1), maxReplicas 0       | -                                     | finding, spec.maxReplicas     |
| `autoscaling/v1`, 6 above 5             | -                                     | finding, spec.minReplicas     |
| a bound that is "3", "5" or `true`      | KN-V007 (type)                        | declined: not an integer      |
| target absent, nothing else here        | -                                     | nE: outside the bundle        |
| target absent, another Deployment here  | -                                     | nE: outside the bundle        |
| a StatefulSet of that name (unrelated)  | -                                     | nE: outside the bundle        |
| target only in namespace `other`        | -                                     | finding, scaleTargetRef.name  |
| target only in `other`, fragment        | -                                     | nE: part of a namespace       |
| target absent, fragment                 | -                                     | nE: part of a namespace       |
| target in `shop` and in `other`         | -                                     | -                             |
| ref `extensions/v1beta1`, object `apps` | - (KN-C014 matches it)                | nE: another API group         |
| ref with no apiVersion                  | - (KN-C014 matches it)                | - (a stated limit, below)     |
| ref kind Rollout (`argoproj.io`)        | -                                     | nE: kind not resolved         |
| HPA of group `autoscaling.example.com`  | notAudited; three rules nE            | nE: 1 HPA not audited         |
| that refused HPA beside a readable one  | notAudited; C007, C012 declined       | declined: 1 HPA not audited   |
| target of group `apps.example.com`      | notAudited; three rules nE            | nE: 1 Deployment not audited  |
| scaleTargetRef is a string              | KN-V007; three rules could not read   | nE: could not read, HPA named |
| no scaleTargetRef, or an empty name     | KN-V007 (required)                    | nE: names no scale target     |
| no HPA                                  | KN-C012, KN-C014 nE                   | nE: no autoscaling HPA        |

How the two awkward shapes are treated, and why:

- **An apiVersion group mismatch is not evaluated, never a pass.** The controller resolves the target by group and
  kind, so `extensions/v1beta1 Deployment web` is not the `apps` Deployment `web` on a current cluster -- but
  which groups serve a kind depends on the cluster's version, and the shared resolver deliberately does not
  compare groups, because KN-C007's behaviour must not change. So KN-V025 neither calls the object the target
  nor calls the target missing. A ref with NO apiVersion is read as naming the object of that kind and name, as
  the other three rules read it; that it fails on a real cluster is not reported by any rule, and is pinned here.
- **A refused HPA is the subject gate's and the evidence check's**, exactly as for KN-C012: alone it leaves the
  rule not evaluated and the verdict undetermined; beside a readable HPA the rule is declined on it by name.

`hpa_scales` is the one resolver: KN-C007's `_has_hpa`, KN-C012, KN-C014 and KN-V025 all call it, and the first
three answer byte for byte what they answered before (`test_the_three_older_rules_answer_what_they_answered`).
"""

from __future__ import annotations

import ast
import copy
from pathlib import Path
from typing import Any

import pytest
import yaml

from kube_noob.audit.engine import analyze

ROOT = Path(__file__).resolve().parents[1]
RULE = "KN-V025"
OUTSIDE = "may be created outside the bundle"


def _workload(name: str = "web", ns: str = "shop", kind: str = "Deployment", api: str = "apps/v1") -> dict[str, Any]:
    image = "registry.example.com/web@sha256:" + "7" * 64
    resources = {"requests": {"cpu": "100m", "memory": "64Mi"}, "limits": {"memory": "64Mi"}}
    spec: dict[str, Any] = {
        "replicas": 1,
        "selector": {"matchLabels": {"app": name}},
        "template": {
            "metadata": {"labels": {"app": name}},
            "spec": {"containers": [{"name": "c", "image": image, "resources": resources}]},
        },
    }
    if kind == "StatefulSet":
        spec["serviceName"] = name
    return {"apiVersion": api, "kind": kind, "metadata": {"name": name, "namespace": ns}, "spec": spec}


def _hpa(
    low: object = 2,
    high: object = 5,
    *,
    kind: str = "Deployment",
    api: str | None = "apps/v1",
    hpa_api: str = "autoscaling/v2",
    name: str = "web",
    **spec_changes: object,
) -> dict[str, Any]:
    ref = {"kind": kind, "name": "web"} if api is None else {"apiVersion": api, "kind": kind, "name": "web"}
    cpu = {"name": "cpu", "target": {"type": "Utilization", "averageUtilization": 70}}
    spec: dict[str, Any] = {"scaleTargetRef": ref, "maxReplicas": high}
    if low is not None:
        spec["minReplicas"] = low
    if hpa_api == "autoscaling/v2":
        spec["metrics"] = [{"type": "Resource", "resource": cpu}]
    spec.update(copy.deepcopy(spec_changes))
    spec = {k: v for k, v in spec.items() if v is not ...}
    meta = {"name": name, "namespace": "shop"}
    return {"apiVersion": hpa_api, "kind": "HorizontalPodAutoscaler", "metadata": meta, "spec": spec}


#: case -> (documents, fragment?, path of the KN-V025 finding or None, words in its notEvaluated/declined reason)
CASES: dict[str, tuple[list[dict[str, Any]], bool, str | None, str | None]] = {
    "fine": ([_workload(), _hpa()], False, None, None),
    "floor-above-ceiling": ([_workload(), _hpa(6, 5)], False, "spec.minReplicas", None),
    "floor-equals-ceiling": ([_workload(), _hpa(5, 5)], False, None, None),
    "default-floor-above-ceiling": ([_workload(), _hpa(None, 0)], False, "spec.maxReplicas", None),
    "v1-floor-above-ceiling": ([_workload(), _hpa(6, 5, hpa_api="autoscaling/v1")], False, "spec.minReplicas", None),
    "floor-not-an-integer": ([_workload(), _hpa("3", 5)], False, None, "is not an integer"),
    "ceiling-not-an-integer": ([_workload(), _hpa(2, "5")], False, None, "is not an integer"),
    "floor-a-boolean": ([_workload(), _hpa(True, 5)], False, None, "is not an integer"),
    "target-absent-alone": ([_hpa()], False, None, OUTSIDE),
    "target-absent-beside-another": ([_workload("api"), _hpa()], False, None, OUTSIDE),
    "same-name-other-kind": ([_workload(kind="StatefulSet"), _hpa()], False, None, OUTSIDE),
    "target-only-in-another-namespace": ([_workload(ns="other"), _hpa()], False, "spec.scaleTargetRef.name", None),
    "target-only-in-another-namespace-fragment": (
        [_workload(ns="other"), _hpa()],
        True,
        None,
        "part of a namespace was passed",
    ),
    "target-absent-fragment": ([_workload("api"), _hpa()], True, None, "part of a namespace was passed"),
    "target-in-both-namespaces": ([_workload(), _workload(ns="other"), _hpa()], False, None, None),
    "statefulset-target": (
        [_workload(kind="StatefulSet"), _hpa(kind="StatefulSet")],
        False,
        None,
        None,
    ),
    "ref-group-mismatch": ([_workload(), _hpa(api="extensions/v1beta1")], False, None, "names an API group other"),
    "ref-without-apiversion": ([_workload(), _hpa(api=None)], False, None, None),
    "ref-kind-not-resolved": (
        [_workload(), _hpa(kind="Rollout", api="argoproj.io/v1alpha1")],
        False,
        None,
        "a kind this rule does not resolve",
    ),
    "refused-hpa": (
        [_workload(), _hpa(6, 5, hpa_api="autoscaling.example.com/v1")],
        False,
        None,
        "1 HorizontalPodAutoscaler not audited",
    ),
    "refused-hpa-beside-a-readable-one": (
        [_workload(), _hpa(6, 5, hpa_api="autoscaling.example.com/v1"), _hpa(name="ok")],
        False,
        None,
        "1 HorizontalPodAutoscaler not audited",
    ),
    "refused-target": ([_workload(api="apps.example.com/v1"), _hpa()], False, None, "1 Deployment not audited"),
    "ref-not-a-mapping": ([_workload(), _hpa(scaleTargetRef="web")], False, None, "HorizontalPodAutoscaler/shop/web"),
    "no-ref": ([_workload(), _hpa(scaleTargetRef=...)], False, None, "names no scale target"),
    "ref-name-empty": ([_workload(), _hpa(scaleTargetRef={"kind": "Deployment", "name": ""})], False, None, "names no"),
    "no-hpa": ([_workload()], False, None, "no autoscaling HorizontalPodAutoscaler in the input"),
}


def _report(docs: list[dict[str, Any]], fragment: bool = False) -> dict[str, Any]:
    text = "---\n".join(yaml.safe_dump(d, sort_keys=False) for d in docs)
    return analyze(text, "kubernetes", None, partial_bundle=fragment).as_dict()


def _why_not(report: dict[str, Any]) -> str:
    """Everything the report says about why KN-V025 did not decide: the record's reason and the per-object ones."""
    declined = (report.get("declined") or {}).get(RULE) or {}
    words = [(report.get("notEvaluated") or {}).get(RULE, ""), *(e["reason"] for e in declined.get("entries", []))]
    return " | ".join(w for w in words if w)


@pytest.mark.parametrize("case", sorted(CASES))
def test_the_measurement_table_still_holds(case: str) -> None:
    docs, fragment, path, reason = CASES[case]
    report = _report(docs, fragment)
    found = [f for f in report["findings"] if f["ruleId"] == RULE]
    assert [f["path"] for f in found] == ([path] if path else []), found
    why = _why_not(report)
    if reason is None:
        assert why == "", f"{case}: a rule that judged everything it was given declines on nothing: {why}"
    else:
        assert reason in why, (case, why)
        assert not found, "never a finding and never a pass"
    for f in found:
        assert f["resource"] == "HorizontalPodAutoscaler/shop/web" and f["stage"] == "validate"


def test_an_absent_target_is_not_evaluated_and_the_reason_names_what_was_absent() -> None:
    report = _report([_workload("api"), _hpa()])
    why = report["notEvaluated"][RULE]
    assert "the Deployment a HorizontalPodAutoscaler names as its scale target is not in its namespace" in why
    assert OUTSIDE in why
    assert RULE not in report["summary"].get("firedRules", [])
    # Nothing went unread, so the score stands: this is not a decline that withholds it.
    assert report["summary"].get("verdict") != "undetermined"
    assert RULE not in (report.get("declined") or {})


def test_a_target_in_another_namespace_names_both_namespaces() -> None:
    (f,) = [
        f for f in _report([_workload(ns="other"), _workload(ns="third"), _hpa()])["findings"] if f["ruleId"] == RULE
    ]
    assert "'web'" in f["message"] and "other, third" in f["message"] and "not in shop" in f["message"]


def test_a_floor_above_the_ceiling_is_reported_whatever_the_target_is() -> None:
    """Both halves are judged on one HPA: the bounds are a finding and the absent target is still not evaluated."""
    report = analyze(yaml.safe_dump(_hpa(6, 5)), "kubernetes", None)
    assert [f.path for f in report.findings if f.rule_id == RULE] == ["spec.minReplicas"]
    assert OUTSIDE in report.partly_evaluated.get(RULE, ""), report.partly_evaluated
    assert RULE in report.as_dict()["controlSummary"]["partlyEvaluatedRules"]


def test_a_refused_object_of_the_targets_name_here_is_not_an_absent_one() -> None:
    """`apps.example.com/v1 Deployment web` in `shop` beside the real one in `other`: the audit refused it, so the
    HPA's target is not known to be missing from `shop` and the other-namespace finding is withheld (G368)."""
    report = _report([_workload(api="apps.example.com/v1"), _workload(ns="other"), _hpa()])
    assert not [f for f in report["findings"] if f["ruleId"] == RULE]
    assert "1 Deployment not audited" in _why_not(report)


def test_an_unreadable_hpa_does_not_crash_the_rule() -> None:
    for spec in (None, 7, [], {"scaleTargetRef": {"kind": 3, "name": ["x"]}, "maxReplicas": 5}):
        hpa = _hpa()
        hpa["spec"] = spec
        report = _report([_workload(), hpa])
        assert not [f for f in report["findings"] if f["ruleId"] == RULE], spec
        assert RULE in (report.get("notEvaluated") or {}), (spec, "never evaluated and clean")


# --- the shared resolver ------------------------------------------------------------------------------------------

#: What KN-C007, KN-C012 and KN-C014 answered for every case above, whole and fragment, before `hpa_scales`
#: replaced the three inline matches: (case, fragment) -> sorted (rule, path) findings and the rules not evaluated.
OLDER = ("KN-C007", "KN-C012", "KN-C014")
C7, C12, C14 = (("KN-C007", "spec.replicas"),), (("KN-C012", "spec.metrics"),), (("KN-C014", "spec.replicas"),)
BEFORE: dict[str, tuple[tuple[tuple[str, str], ...], tuple[str, ...]]] = {
    "fine": (C14, ()),
    "floor-above-ceiling": (C14, ()),
    "floor-equals-ceiling": (C14, ()),
    "default-floor-above-ceiling": (C7 + C14, ()),
    "v1-floor-above-ceiling": (C14, ()),
    "floor-not-an-integer": (C7 + C14, ()),
    "ceiling-not-an-integer": (C14, ()),
    "floor-a-boolean": (C7 + C14, ()),
    "target-absent-alone": ((), OLDER),
    "target-absent-beside-another": (C7, ()),
    "same-name-other-kind": (C7, ()),
    "target-only-in-another-namespace": (C7, ()),
    "target-only-in-another-namespace-fragment": (C7, ()),
    "target-absent-fragment": (C7, ()),
    "target-in-both-namespaces": (C7 + C14, ()),
    "statefulset-target": (C14, ()),
    "ref-group-mismatch": (C14, ()),
    "ref-without-apiversion": (C14, ()),
    "ref-kind-not-resolved": (C7, ()),
    "refused-hpa": ((), OLDER),
    "refused-hpa-beside-a-readable-one": (C14, ("KN-C007", "KN-C012")),
    "refused-target": ((), OLDER),
    "ref-not-a-mapping": ((), OLDER),
    "no-ref": (C7, ()),
    "ref-name-empty": (C7, ()),
    "no-hpa": (C7, ("KN-C012", "KN-C014")),
}


@pytest.mark.parametrize("case", sorted(CASES))
def test_the_three_older_rules_answer_what_they_answered(case: str) -> None:
    docs, fragment, _, _ = CASES[case]
    report = _report(docs, fragment)
    found = tuple(sorted((f["ruleId"], f["path"]) for f in report["findings"] if f["ruleId"] in OLDER))
    silent = tuple(sorted(r for r in report.get("notEvaluated") or {} if r in OLDER))
    assert (found, silent) == BEFORE[case]


def test_no_rule_matches_a_scale_target_inline_any_more() -> None:
    """One resolver. A fourth inline `ref.get("name") == d.name` is how two rules come to disagree about a target."""
    audit = ROOT / "src" / "kube_noob" / "audit"
    callers: dict[str, int] = {}
    for module in ("rules.py", "cprules.py"):
        tree = ast.parse((audit / module).read_text(encoding="utf-8"))
        for fn in (n for n in tree.body if isinstance(n, ast.FunctionDef)):
            source = ast.unparse(fn)
            if fn.name == "hpa_scales":
                assert "scaleTargetRef" in source
                continue
            calls = sum(
                1
                for n in ast.walk(fn)
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "hpa_scales"
            )
            if calls:
                callers[fn.name] = calls
            if "scaleTargetRef" in source:
                assert "ref.get('name') ==" not in source and "!= ref.get('name')" not in source, fn.name
                assert "== ref.get('name')" not in source, fn.name
    assert set(callers) == {"_has_hpa", "_c012", "_c014", "_v025"}, callers
