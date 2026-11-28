"""`kube-noob policy migrate-check`: legacy Kyverno policies, rule by rule, against the CEL policy types (POL4).

Lint only: every finding names the rule, the field path, the CEL target kind, the reason and the documentation section
it comes from; simple direct mappings get a draft labelled as such and a `kyverno test` skeleton to prove it.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from kube_noob import kyverno_migrate as km
from kube_noob.cli import main
from kube_noob.errors import InputTooLarge, ManifestError

FIX = Path(__file__).parent / "fixtures" / "kyverno-migrate"


def _check(name: str, **kw: Any) -> dict[str, Any]:
    return km.check((FIX / name).read_text(encoding="utf-8"), **kw)


def _policy(report: dict[str, Any], ref: str) -> dict[str, Any]:
    return next(p for p in report["policies"] if p["policy"] == ref)


def _rule(policy: dict[str, Any], name: str) -> dict[str, Any]:
    return next(r for r in policy["rules"] if r["rule"] == name)


def _finding(items: list[dict[str, Any]], path: str) -> dict[str, Any]:
    found = [f for f in items if f["path"] == path]
    assert found, (path, [f["path"] for f in items])
    return found[0]


def _yaml(text: str) -> list[Any]:
    return [d for d in yaml.safe_load_all(text) if d is not None]


# --- direct mappings with a draft -------------------------------------------------------------------------------


def test_label_pattern_is_direct_with_a_labelled_draft() -> None:
    p = _policy(_check("require-labels.yaml"), "ClusterPolicy/require-labels")
    assert p["verdict"] == "direct" and p["targets"] == ["ValidatingPolicy"]
    action = _finding(p["findings"], "spec.validationFailureAction")
    assert action["verdict"] == "direct" and "validationActions" in action["mapsTo"] and "Deny" in action["mapsTo"]
    assert _finding(p["findings"], "spec.background")["mapsTo"] == "spec.evaluation.background.enabled"
    r = _rule(p, "check-for-labels")
    assert r["verdict"] == "direct" and r["target"] == "ValidatingPolicy"
    kinds = _finding(r["findings"], "spec.rules[0].match.any[0].resources.kinds")
    assert kinds["verdict"] == "direct" and kinds["mapsTo"].startswith("spec.matchConstraints.resourceRules")
    pattern = _finding(r["findings"], "spec.rules[0].validate.pattern")
    assert pattern["verdict"] == "direct" and pattern["source"].startswith("migration-to-cel: Validate Rule")
    assert pattern["line"] == 24 and pattern["rule"] == "check-for-labels" and pattern["target"] == "ValidatingPolicy"
    draft = r["draft"]
    assert draft.startswith("# DRAFT") and "prove with kyverno test" in draft
    doc = _yaml(draft)[0]
    assert doc["apiVersion"] == "policies.kyverno.io/v1" and doc["kind"] == "ValidatingPolicy"
    assert doc["metadata"]["name"] == "require-labels"
    spec = doc["spec"]
    assert spec["validationActions"] == ["Deny"]
    assert spec["evaluation"] == {"background": {"enabled": True}}
    assert spec["matchConstraints"]["resourceRules"] == [
        {"apiGroups": [""], "apiVersions": ["v1"], "operations": ["CREATE", "UPDATE"], "resources": ["pods"]}
    ]
    (validation,) = spec["validations"]
    assert validation["message"] == "The label `app.kubernetes.io/name` is required."
    assert '"app.kubernetes.io/name"' in validation["expression"] and '!= ""' in validation["expression"]


def test_pod_rules_say_what_autogen_does_in_both_worlds() -> None:
    p = _policy(_check("require-labels.yaml"), "ClusterPolicy/require-labels")
    autogen = _finding(p["findings"], 'metadata.annotations["pod-policies.kyverno.io/autogen-controllers"]')
    assert autogen["verdict"] == "direct" and autogen["mapsTo"] == "spec.autogen.podControllers.controllers"
    assert "replicationcontrollers" in autogen["reason"]


def test_kyverno_test_fixture_proves_the_draft_against_the_legacy_rule() -> None:
    p = _policy(_check("require-labels.yaml"), "ClusterPolicy/require-labels")
    files = p["fixture"]["files"]
    assert set(files) == {
        "require-labels/resources.yaml",
        "require-labels/legacy/kyverno-test.yaml",
        "require-labels/legacy/policy.yaml",
        "require-labels/cel/kyverno-test.yaml",
        "require-labels/cel/require-labels.yaml",
    }
    pods = {d["metadata"]["name"]: d for d in _yaml(files["require-labels/resources.yaml"])}
    assert pods["good-check-for-labels"]["metadata"]["labels"]["app.kubernetes.io/name"]
    assert "app.kubernetes.io/name" not in (pods["bad-check-for-labels"]["metadata"].get("labels") or {})
    legacy = _yaml(files["require-labels/legacy/kyverno-test.yaml"])[0]
    assert legacy["apiVersion"] == "cli.kyverno.io/v1alpha1" and legacy["kind"] == "Test"
    assert legacy["policies"] == ["policy.yaml"] and legacy["resources"] == ["../resources.yaml"]
    expected = {(r["rule"], r["resources"][0], r["result"]) for r in legacy["results"]}
    assert expected == {
        ("check-for-labels", "bad-check-for-labels", "fail"),
        ("check-for-labels", "good-check-for-labels", "pass"),
    }
    assert _yaml(files["require-labels/legacy/policy.yaml"])[0]["kind"] == "ClusterPolicy"
    cel = _yaml(files["require-labels/cel/kyverno-test.yaml"])[0]
    assert cel["policies"] == ["require-labels.yaml"]
    assert all(r["isValidatingPolicy"] is True and "rule" not in r for r in cel["results"])
    assert {(r["resources"][0], r["result"]) for r in cel["results"]} == {
        ("bad-check-for-labels", "fail"),
        ("good-check-for-labels", "pass"),
    }
    assert files["require-labels/cel/require-labels.yaml"] == _rule(p, "check-for-labels")["draft"]


def test_foreach_with_a_simple_pattern_is_direct_and_a_negated_one_inverted() -> None:
    p = _policy(_check("disallow-latest-tag.yaml"), "ClusterPolicy/disallow-latest-tag")
    tag = _rule(p, "require-image-tag")
    assert tag["verdict"] == "direct"
    latest = _rule(p, "validate-image-tag")
    assert latest["verdict"] == "inverted" and p["verdict"] == "inverted"
    assert _finding(latest["findings"], "spec.rules[1].validate.foreach")["verdict"] == "inverted"
    doc = _yaml(latest["draft"])[0]
    assert doc["metadata"]["name"] == "disallow-latest-tag-validate-image-tag"
    assert doc["spec"]["validationActions"] == ["Audit"]
    expr = doc["spec"]["validations"][0]["expression"]
    assert "containers" in expr and "initContainers" in expr and ":latest" in expr and "!" in expr
    resources = _yaml(p["fixture"]["files"]["disallow-latest-tag/resources.yaml"])
    bad = next(d for d in resources if d["metadata"]["name"] == "bad-validate-image-tag")
    good = next(d for d in resources if d["metadata"]["name"] == "good-validate-image-tag")
    assert bad["spec"]["containers"][0]["image"].endswith(":latest")
    assert not good["spec"]["containers"][0]["image"].endswith(":latest")


def test_deny_is_inverted_and_the_draft_states_what_is_allowed() -> None:
    p = _policy(_check("replica-limit.yaml"), "ClusterPolicy/replica-limit")
    r = _rule(p, "max-ten-replicas")
    assert r["verdict"] == "inverted"
    deny = _finding(r["findings"], "spec.rules[0].validate.deny")
    assert deny["verdict"] == "inverted" and "invert" in deny["reason"]
    spec = _yaml(r["draft"])[0]["spec"]
    assert spec["validations"][0]["expression"] == "object.spec.replicas <= 10"
    assert spec["validationActions"] == ["Deny"]
    assert spec["matchConstraints"]["resourceRules"][0]["resources"] == ["deployments"]
    assert spec["matchConstraints"]["excludeResourceRules"] == [
        {
            "apiGroups": ["apps"],
            "apiVersions": ["v1"],
            "operations": ["CREATE", "UPDATE"],
            "resources": ["statefulsets"],
        }
    ]
    resources = {d["metadata"]["name"]: d for d in _yaml(p["fixture"]["files"]["replica-limit/resources.yaml"])}
    assert resources["bad-max-ten-replicas"]["spec"]["replicas"] == 11
    assert resources["good-max-ten-replicas"]["spec"]["replicas"] == 10
    assert resources["good-max-ten-replicas"]["apiVersion"] == "apps/v1"


def test_legacy_cel_rule_copies_its_expressions() -> None:
    p = _policy(_check("cleanup-exception-namespaced.yaml"), "ClusterPolicy/restrict-node-port")
    r = _rule(p, "validate-nodeport")
    assert r["verdict"] == "direct"
    spec = _yaml(r["draft"])[0]["spec"]
    assert spec["validations"] == [
        {
            "expression": "has(object.spec.type) ? (object.spec.type != 'NodePort') : true",
            "message": "Services of type NodePort are not allowed.",
        }
    ]
    assert spec["validationActions"] == ["Audit"]


def _balanced(expr: str) -> bool:
    pairs, stack, quote, i = {")": "(", "]": "[", "}": "{"}, [], "", 0
    while i < len(expr):
        c = expr[i]
        if quote:
            if c == "\\":
                i += 1
            elif c == quote:
                quote = ""
        elif c in "\"'":
            quote = c
        elif c in "([{":
            stack.append(c)
        elif c in pairs and (not stack or stack.pop() != pairs[c]):
            return False
        i += 1
    return not stack and not quote


def test_draft_expressions_are_balanced_and_use_only_upstream_idioms() -> None:
    text = "\n---\n".join(f.read_text() for f in sorted(FIX.glob("*.yaml")))
    report = km.check(text)
    exprs: list[str] = []
    for p in report["policies"]:
        for holder in [p, *p["rules"]]:
            if "draft" not in holder:
                continue
            spec = _yaml(holder["draft"])[0]["spec"]
            for key in ("validations", "matchConditions", "conditions", "variables"):
                exprs += [v["expression"] for v in spec.get(key, [])]
            exprs += [m["jsonPatch"]["expression"] for m in spec.get("mutations", [])]
    assert len(exprs) >= 8
    for expr in exprs:
        assert _balanced(expr), expr
        assert ".value()" not in expr and "{{" not in expr, expr


_SEMANTICS = """
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata: {name: semantics}
spec:
  rules:
  - name: ingress-class
    match: {any: [{resources: {kinds: [Ingress]}}]}
    validate:
      pattern: {metadata: {annotations: {kubernetes.io/ingress.class: "HAProxy | nginx"}}}
  - name: run-as-user
    match: {any: [{resources: {kinds: [Pod]}}]}
    validate:
      pattern: {spec: {securityContext: {runAsUser: "1000"}}}
  - name: replicas-at-most
    match: {any: [{resources: {kinds: [Deployment]}}]}
    validate:
      pattern: {spec: {replicas: "<=5"}}
  - name: memory-limit
    match: {any: [{resources: {kinds: [Pod]}}]}
    validate:
      pattern: {spec: {containers: [{resources: {limits: {memory: "1Gi"}}}]}}
  - name: bad-kernels
    match: {any: [{resources: {kinds: [Node]}}]}
    validate:
      deny:
        conditions:
          any:
          - {key: "{{ request.object.status.nodeInfo.kernelVersion }}", operator: Equals, value: "5.10.84-1"}
          - {key: "{{ request.object.status.nodeInfo.kernelVersion }}", operator: Equals, value: "5.15.5-2"}
  - name: sar
    match: {any: [{resources: {kinds: [ConfigMap]}}]}
    exclude: {any: [{resources: {namespaces: [kube-system]}}]}
    context:
    - name: review
      apiCall: {urlPath: /apis/authorization.k8s.io/v1/subjectaccessreviews, method: POST}
    validate:
      deny: {conditions: {any: [{key: "{{ review.status.allowed }}", operator: NotEquals, value: true}]}}
"""


def _expr(rule: dict[str, Any]) -> str:
    return str(_yaml(rule["draft"])[0]["spec"]["validations"][0]["expression"])


def test_pattern_and_condition_semantics_follow_kyverno_not_text() -> None:
    """Regressions found by comparing drafts with kyverno/policies' own CEL versions (pattern.go semantics)."""
    p = _policy(km.check(_SEMANTICS), "ClusterPolicy/semantics")
    # alternatives are trimmed around |
    assert _expr(_rule(p, "ingress-class")) == (
        'object.metadata.?annotations[?"kubernetes.io/ingress.class"].orValue("") in ["HAProxy", "nginx"]'
    )
    # a quoted number compares as a number for an int field, and a missing field reads as 0
    assert _expr(_rule(p, "run-as-user")) == 'string(object.?spec.?securityContext.?runAsUser.orValue(0)) == "1000"'
    assert _expr(_rule(p, "replicas-at-most")) == "object.?spec.?replicas.orValue(0) <= 5"
    files = p["fixture"]["files"]
    pods = {d["metadata"]["name"]: d for d in _yaml(files["semantics/resources.yaml"])}
    assert pods["good-run-as-user"]["spec"]["securityContext"]["runAsUser"] == 1000
    assert pods["bad-run-as-user"]["spec"]["securityContext"]["runAsUser"] == 1001
    # a quantity compares by value, not text: hand work
    memory = _rule(p, "memory-limit")
    assert (
        memory["verdict"] == "manual"
        and "quantity" in _finding(memory["findings"], "spec.rules[3].validate.pattern")["reason"]
    )
    # any of two conditions, inverted once, without nested parentheses; an exclude without kinds is not "no kinds"
    kernels = _rule(p, "bad-kernels")
    assert _expr(kernels) == (
        '!(object.status.nodeInfo.kernelVersion == "5.10.84-1" || object.status.nodeInfo.kernelVersion == "5.15.5-2")'
    )
    # a POST API call is resource.Post()
    sar = _rule(p, "sar")
    assert "resource.Post()" in _finding(sar["findings"], "spec.rules[5].context[0].apiCall")["mapsTo"]
    assert not [f for f in sar["findings"] if f["path"].startswith("spec.rules[5].exclude.any[0].resources.kinds")]
    assert _finding(sar["findings"], "spec.rules[5].exclude.any[0].resources.namespaces")["verdict"] == "manual"


# --- manual and blocked ------------------------------------------------------------------------------------------


def test_lookups_jmespath_anchors_and_pod_security_need_hand_work() -> None:
    p = _policy(_check("manual-and-blocked.yaml"), "ClusterPolicy/hand-work")
    api = _rule(p, "limit-services-per-namespace")
    assert api["verdict"] == "manual" and "draft" not in api
    call = _finding(api["findings"], "spec.rules[0].context[0].apiCall")
    assert call["verdict"] == "manual" and "resource.List" in call["mapsTo"]
    assert call["source"].startswith("migration-to-cel: Rule Fields")
    anchors = _rule(p, "no-host-path-in-containers")
    assert (
        anchors["verdict"] == "manual"
        and "anchor" in _finding(anchors["findings"], "spec.rules[3].validate.foreach")["reason"]
    )
    pss = _rule(p, "baseline")
    assert pss["verdict"] == "manual"
    assert _finding(pss["findings"], "spec.rules[4].validate.podSecurity")["verdict"] == "manual"


def test_undocumented_or_unsupported_features_are_blocked() -> None:
    p = _policy(_check("manual-and-blocked.yaml"), "ClusterPolicy/hand-work")
    assert p["verdict"] == "blocked"
    ssa = _finding(p["findings"], "spec.useServerSideApply")
    assert ssa["verdict"] == "blocked" and "14853" in ssa["reason"]
    total = _rule(p, "total-memory")
    assert total["verdict"] == "blocked"
    fn = _finding(total["findings"], "spec.rules[1].context[0].variable.jmesPath")
    assert fn["verdict"] == "blocked" and "sum()" in fn["reason"] and fn["source"].startswith("jmespath-to-cel")
    manifests = _rule(p, "signed-manifests")
    assert _finding(manifests["findings"], "spec.rules[2].validate.manifests")["verdict"] == "blocked"
    assert all("draft" not in r for r in p["rules"])


# --- other action types and legacy kinds -------------------------------------------------------------------------


def test_mutate_generate_and_verify_images_name_their_target_kinds() -> None:
    report = _check("mutate-generate-images.yaml")
    mutate = _policy(report, "ClusterPolicy/add-defaults")
    patch = _rule(mutate, "add-managed-label")
    assert patch["verdict"] == "direct" and patch["target"] == "MutatingPolicy"
    mutation = _yaml(patch["draft"])[0]["spec"]["mutations"][0]
    assert mutation["patchType"] == "JSONPatch"
    assert "JSONPatch{" in mutation["jsonPatch"]["expression"]
    assert "/metadata/labels/managed-by" in mutation["jsonPatch"]["expression"]
    smp = _rule(mutate, "default-pull-policy")
    assert smp["verdict"] == "manual" and smp["target"] == "MutatingPolicy"
    assert "ApplyConfiguration" in _finding(smp["findings"], "spec.rules[1].mutate.patchStrategicMerge")["mapsTo"]
    gen = _rule(_policy(report, "ClusterPolicy/add-networkpolicy"), "default-deny")
    assert gen["verdict"] == "manual" and gen["target"] == "GeneratingPolicy"
    sync = _finding(gen["findings"], "spec.rules[0].generate.synchronize")
    assert sync["verdict"] == "direct" and sync["mapsTo"] == "spec.evaluation.synchronize.enabled"
    images = _policy(report, "ClusterPolicy/verify-signatures")
    img = _rule(images, "check-signature")
    assert img["verdict"] == "manual" and img["target"] == "ImageValidatingPolicy"
    refs = _finding(img["findings"], "spec.rules[0].verifyImages[0].imageReferences")
    assert refs["verdict"] == "direct" and refs["mapsTo"] == "spec.matchImageReferences"
    assert _finding(img["findings"], "spec.rules[0].verifyImages[0].attestors")["verdict"] == "manual"
    timeout = _finding(images["findings"], "spec.webhookTimeoutSeconds")
    assert timeout["mapsTo"] == "spec.webhookConfiguration.timeoutSeconds"


def test_cleanup_policies_become_deleting_policies() -> None:
    report = _check("cleanup-exception-namespaced.yaml")
    bare = _policy(report, "ClusterCleanupPolicy/clean-bare-pods")
    assert bare["targets"] == ["DeletingPolicy"] and bare["verdict"] == "manual"
    assert _finding(bare["findings"], "spec.conditions")["verdict"] == "manual"
    assert _finding(bare["findings"], "spec.schedule")["mapsTo"] == "spec.schedule"
    scratch = _policy(report, "CleanupPolicy/team-a/clean-scratch-configmaps")
    assert scratch["targets"] == ["NamespacedDeletingPolicy"] and scratch["verdict"] == "direct"
    doc = _yaml(scratch["draft"])[0]
    assert doc["kind"] == "NamespacedDeletingPolicy" and doc["metadata"]["namespace"] == "team-a"
    assert doc["spec"]["schedule"] == "0 1 * * *"
    assert doc["spec"]["matchConstraints"]["objectSelector"] == {"matchLabels": {"scratch": "true"}}
    assert doc["spec"]["matchConstraints"]["resourceRules"] == [
        {"apiGroups": [""], "apiVersions": ["v1"], "resources": ["configmaps"]}
    ]


def test_policy_exception_moves_to_policy_refs_and_match_conditions() -> None:
    alone = _policy(_check("cleanup-exception-namespaced.yaml"), "PolicyException/team-a/allow-debug-pods")
    assert alone["targets"] == ["PolicyException"]
    assert _finding(alone["findings"], "spec.exceptions[0].ruleNames")["verdict"] == "manual"
    text = (
        (FIX / "require-labels.yaml").read_text() + "\n---\n" + (FIX / "cleanup-exception-namespaced.yaml").read_text()
    )
    exc = _policy(km.check(text), "PolicyException/team-a/allow-debug-pods")
    assert exc["verdict"] == "direct"
    assert _finding(exc["findings"], "spec.exceptions[0].policyName")["mapsTo"] == "spec.policyRefs[].name"
    doc = _yaml(exc["draft"])[0]
    assert doc["apiVersion"] == "policies.kyverno.io/v1" and doc["kind"] == "PolicyException"
    assert doc["spec"]["policyRefs"] == [{"name": "require-labels", "kind": "ValidatingPolicy"}]
    (cond,) = doc["spec"]["matchConditions"]
    assert 'object.metadata.name.startsWith("debug-")' in cond["expression"]
    assert '"Pod"' in cond["expression"] and '"team-a"' in cond["expression"]


def test_namespaced_policy_targets_namespaced_kinds_and_namespaced_fixture_names() -> None:
    p = _policy(_check("cleanup-exception-namespaced.yaml"), "Policy/team-a/team-owner")
    assert p["targets"] == ["NamespacedValidatingPolicy"]
    doc = _yaml(_rule(p, "owner-label")["draft"])[0]
    assert doc["kind"] == "NamespacedValidatingPolicy" and doc["metadata"]["namespace"] == "team-a"
    files = p["fixture"]["files"]
    legacy = _yaml(files["team-owner/legacy/kyverno-test.yaml"])[0]
    assert {r["policy"] for r in legacy["results"]} == {"team-a/team-owner"}
    assert "team-a/bad-owner-label" in {r["resources"][0] for r in legacy["results"]}
    resources = _yaml(files["team-owner/resources.yaml"])
    assert all(d["metadata"]["namespace"] == "team-a" and d["kind"] == "Deployment" for d in resources)


# --- contract: every finding is complete and cited ---------------------------------------------------------------


def test_every_finding_names_rule_path_target_reason_and_a_pinned_source() -> None:
    reports = [_check(f.name) for f in sorted(FIX.glob("*.yaml"))]
    keys = {"rule", "path", "line", "verdict", "target", "mapsTo", "reason", "source"}
    count = 0
    for report in reports:
        assert set(report["sources"]) <= set(km.SOURCES)
        for p in report["policies"]:
            for f in p["findings"] + [f for r in p["rules"] for f in r["findings"]]:
                count += 1
                assert set(f) == keys, f
                assert f["verdict"] in km.VERDICTS and f["target"] and f["reason"] and f["line"] >= 1
                assert f["source"].split(":")[0] in report["sources"]
    assert count > 60
    for src in km.SOURCES.values():
        assert re.fullmatch(r"[0-9a-f]{40}", src.commit) and src.commit in src.url
        assert src.url.startswith("https://github.com/") and src.date


def test_mapping_tables_cite_only_known_sources() -> None:
    rows = km.mapping_rows()
    assert len(rows) >= 50
    for table, field, row in rows:
        assert row.source in km.SOURCES, (table, field)
        assert row.section and row.reason and row.verdict in km.VERDICTS
    blocked = {fn for fn, _ in km.JMESPATH_TO_CEL.items() if fn in km.JMESPATH_BLOCKED}
    assert blocked == {"multiply", "divide", "sum", "compare", "regex_replace_all", "regex_replace_all_literal"}


def test_summary_counts_units_and_reports_the_worst_verdict() -> None:
    report = _check("manual-and-blocked.yaml")
    s = report["summary"]
    assert s["policies"] == 1 and s["rules"] == 5 and s["worst"] == "blocked"
    assert s["verdicts"] == {"direct": 0, "inverted": 0, "manual": 3, "blocked": 2}
    assert "nothing was applied" in report["note"].lower()
    assert km.failing(report, "blocked") and km.failing(report, "manual") and not km.failing(report, "never")
    assert not km.failing(_check("require-labels.yaml"), "manual")


# --- hostile input, secrets, determinism -------------------------------------------------------------------------


def test_secrets_are_never_read_and_other_documents_are_listed() -> None:
    text = """
apiVersion: v1
kind: Secret
metadata: {name: creds}
stringData: {password: hunter2-do-not-echo}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: web}
---
apiVersion: policies.kyverno.io/v1
kind: ValidatingPolicy
metadata: {name: already}
"""
    report = km.check(text)
    assert "hunter2" not in json.dumps(report)
    reasons = {s["ref"]: s["reason"] for s in report["skipped"]}
    assert "not read" in reasons["Secret/creds"]
    assert "not a legacy Kyverno policy" in reasons["Deployment/web"]
    assert "already" in reasons["ValidatingPolicy/already"]
    assert report["policies"] == [] and report["summary"]["worst"] is None


def test_malformed_policies_are_reported_not_crashed() -> None:
    text = """
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata: {name: odd}
spec:
  rules:
  - 5
  - name: no-action
    match: 7
  - name: weird
    match: {any: [{resources: {kinds: ["*"]}}]}
    validate: {pattern: [1, 2]}
---
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata: {name: odder}
spec: [1, 2]
"""
    report = km.check(text)
    odd = _policy(report, "ClusterPolicy/odd")
    assert [r["verdict"] for r in odd["rules"]] == ["manual", "manual", "manual"]
    assert _policy(report, "ClusterPolicy/odder")["verdict"] == "manual"


def test_deep_patterns_and_long_strings_stay_bounded() -> None:
    pattern: Any = "?*"
    for i in range(60):
        pattern = {f"k{i}": pattern}
    doc = {
        "apiVersion": "kyverno.io/v1",
        "kind": "ClusterPolicy",
        "metadata": {"name": "deep"},
        "spec": {
            "rules": [
                {
                    "name": "x" * 300,
                    "match": {"any": [{"resources": {"kinds": ["Pod"]}}]},
                    "validate": {"message": "m" * 5000, "pattern": pattern},
                }
            ]
        },
    }
    report = km.check(yaml.safe_dump(doc))
    p = _policy(report, "ClusterPolicy/deep")
    assert p["rules"][0]["verdict"] in km.VERDICTS
    for path in p.get("fixture", {}).get("files", {}):
        assert all(len(part) <= 63 for part in path.split("/"))


def test_bounded_input_and_alias_bombs_are_refused() -> None:
    from kube_noob.yamlio import MAX_INPUT_BYTES

    with pytest.raises(ManifestError):
        km.check("a: " + "x" * (MAX_INPUT_BYTES + 1))
    bomb = "a: &a [x, x, x, x, x, x, x, x, x]\n" + "".join(
        f"{c}: &{c} [{', '.join([f'*{p}'] * 9)}]\n" for p, c in zip("abcdefgh", "bcdefghi", strict=True)
    )
    with pytest.raises(ManifestError):
        km.check(bomb)


def test_hostile_names_never_escape_the_fixture_directory() -> None:
    text = (FIX / "require-labels.yaml").read_text().replace("name: require-labels", "name: ../../etc/passwd")
    p = km.check(text)["policies"][0]
    for path in p["fixture"]["files"]:
        assert ".." not in path.split("/") and not path.startswith("/")


def test_several_files_keep_their_own_lines_and_exceptions_resolve_across_them() -> None:
    from kube_noob.yamlio import MAX_INPUT_BYTES

    names = ("require-labels.yaml", "cleanup-exception-namespaced.yaml")
    report = km.check_files([(n, (FIX / n).read_text()) for n in names])
    labels = _policy(report, "ClusterPolicy/require-labels")
    assert labels["file"] == "require-labels.yaml" and labels["line"] == 4
    exc = _policy(report, "PolicyException/team-a/allow-debug-pods")
    assert exc["file"] == "cleanup-exception-namespaced.yaml" and exc["verdict"] == "direct"
    half = "a: " + "x" * (MAX_INPUT_BYTES // 2 + 10) + "\n"
    with pytest.raises(ManifestError):
        km.check_files([("a.yaml", half), ("b.yaml", half)])


def test_names_with_newlines_cannot_inject_yaml_into_written_files() -> None:
    doc = yaml.safe_load((FIX / "require-labels.yaml").read_text())
    doc["metadata"]["name"] = "evil\nkind: Secret"
    doc["spec"]["rules"][0]["name"] = "rule apiVersion: v1\n---\nkind: Secret"
    doc["spec"]["rules"].append(dict(doc["spec"]["rules"][0], name="second\nrule"))
    p = km.check(yaml.safe_dump(doc))["policies"][0]
    texts = [r["draft"] for r in p["rules"] if "draft" in r] + list(p["fixture"]["files"].values())
    assert len(texts) >= 6
    for text in texts:
        head = text.split("---\n", 1)[0]
        assert all(line.startswith("# ") for line in head.splitlines()), head
        assert " " not in head
        for d in _yaml(text):
            assert d.get("kind") != "Secret"


def test_output_is_deterministic() -> None:
    text = "\n---\n".join(f.read_text() for f in sorted(FIX.glob("*.yaml")))
    assert json.dumps(km.check(text), sort_keys=True) == json.dumps(km.check(text), sort_keys=True)


def test_drafts_can_be_left_out() -> None:
    report = _check("require-labels.yaml", drafts=False)
    p = report["policies"][0]
    assert "fixture" not in p and all("draft" not in r for r in p["rules"])


def test_the_module_is_offline_and_never_writes() -> None:
    source = Path(km.__file__).read_text(encoding="utf-8")
    for banned in ("kube_noob.net", "http_client", "subprocess", "socket", "urllib", "open(", "write_text"):
        assert banned not in source, banned


# --- CLI and MCP -------------------------------------------------------------------------------------------------


def test_cli_prints_findings_drafts_and_fixtures(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["policy", "migrate-check", "-f", str(FIX / "require-labels.yaml")]) == 0
    out = capsys.readouterr().out
    assert "ClusterPolicy/require-labels" in out and "check-for-labels" in out and "direct" in out
    assert "# DRAFT" in out and "require-labels/legacy/kyverno-test.yaml" in out
    assert "nothing was applied" in out.lower()


def test_cli_json_and_fail_on(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--format", "json", "policy", "migrate-check", "-f", str(FIX / "replica-limit.yaml")]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["verdicts"]["inverted"] == 1
    blocked = str(FIX / "manual-and-blocked.yaml")
    assert main(["policy", "migrate-check", "-f", blocked, "--fail-on", "blocked"]) == 1
    assert main(["policy", "migrate-check", "-f", str(FIX / "require-labels.yaml"), "--fail-on", "manual"]) == 0
    mutate = str(FIX / "mutate-generate-images.yaml")
    assert main(["policy", "migrate-check", "-f", mutate, "--fail-on", "manual"]) == 1
    assert main(["policy", "migrate-check", "-f", mutate, "--fail-on", "blocked"]) == 0
    capsys.readouterr()
    assert main(["policy", "migrate-check", "-f", mutate, "-f", blocked, "--no-drafts"]) == 0
    out = capsys.readouterr().out
    assert f"ClusterPolicy/hand-work ({blocked} line 4)" in out and "# DRAFT" not in out


def test_cli_writes_drafts_and_fixtures_only_into_a_fresh_directory(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "migration"
    hostile = tmp_path / "hostile.yaml"
    hostile.write_text((FIX / "require-labels.yaml").read_text().replace("name: require-labels", "name: ../../evil"))
    assert main(["policy", "migrate-check", "-f", str(FIX / "require-labels.yaml"), "-o", str(out)]) == 0
    assert (out / "require-labels" / "cel" / "require-labels.yaml").read_text().startswith("# DRAFT")
    assert (out / "require-labels" / "legacy" / "kyverno-test.yaml").is_file()
    assert main(["policy", "migrate-check", "-f", str(FIX / "require-labels.yaml"), "-o", str(out)]) == 2
    assert "exists" in capsys.readouterr().err
    other = tmp_path / "other"
    assert main(["policy", "migrate-check", "-f", str(hostile), "-o", str(other)]) == 0
    assert (other / "evil" / "legacy" / "kyverno-test.yaml").is_file()
    assert not (tmp_path / "evil").exists() and not (tmp_path.parent / "evil").exists()
    capsys.readouterr()


def test_mcp_tool_is_read_only_and_strict() -> None:
    from pydantic import ValidationError

    from kube_noob import toolkit as tk
    from kube_noob.config import load_settings

    kit = tk.Toolkit(load_settings())
    spec = next(s for s in kit.specs() if s.name == "policy_migrate_check")
    assert spec.read_only and not spec.open_world and spec.tier is None
    text = (FIX / "replica-limit.yaml").read_text()
    out = kit.policy_migrate_check(tk.PolicyMigrateCheckIn(policies=text))
    assert out["summary"]["worst"] == "inverted"
    assert (
        "draft"
        not in kit.policy_migrate_check(tk.PolicyMigrateCheckIn(policies=text, drafts=False))["policies"][0]["rules"][0]
    )
    with pytest.raises(ValidationError):
        tk.PolicyMigrateCheckIn(policies=text, apply=True)  # type: ignore[call-arg]
    # Refused as it always was, and in one line now: the size, the cap and what to do (G447).
    with pytest.raises(InputTooLarge, match="1,000,001 characters and one request carries at most 1,000,000"):
        tk.PolicyMigrateCheckIn(policies="x" * (tk.MAX_MANIFEST_CHARS + 1))


def test_the_eval_reads_only_the_policies_kyverno_io_group(tmp_path: Path) -> None:
    """The upstream CEL files are told apart by API group, compared whole (CodeQL: a prefix test is a substring)."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "eval_kyverno_migrate", Path(__file__).resolve().parents[1] / "scripts" / "eval_kyverno_migrate.py"
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    (tmp_path / "a.yaml").write_text(
        "apiVersion: policies.kyverno.io/v1\nkind: ValidatingPolicy\n---\n"
        "apiVersion: kyverno.io/v1\nkind: ClusterPolicy\n---\n"
        "apiVersion: evil.policies.kyverno.io/v1\nkind: Lookalike\n---\n"
        "apiVersion: policies.kyverno.io.evil/v1\nkind: Lookalike\n---\n- not a mapping\n"
    )
    assert [d["kind"] for d in mod._cel_docs(tmp_path, ["a.yaml"])] == ["ValidatingPolicy"]
