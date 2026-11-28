"""What the requester writes must never decide whether the webhook looks (G440).

The webhook skipped a Pod, a ReplicaSet or a Job that carried `ownerReferences[].controller: true`, "because its
owner was checked". The API server does not check that an owner controls anything, and whoever can create a Pod
can write that stanza, so one field turned `admission.enforce` off: the red team's privileged Pod was denied
(`r_bad.json`) and the same Pod with a forged owner was admitted with no warning (`r_owned.json`). The chart's
`matchConditions` did the same thing one step earlier, so on Kubernetes 1.30+ the request never arrived.

Who SENT the request is what the requester does not control: `request.userInfo` is written by the API server from
the authenticated identity. A child is skipped when kube-controller-manager's own controller made it, of an owner
kind the webhook is sent, and never otherwise -- in warn mode and in enforce mode alike, so the Deployment's
warning is still not repeated on its ReplicaSet and its Pods.

The request files under `tests/fixtures/admission/` are the red team's, unchanged.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from kube_noob import admission as adm
from kube_noob.cli import main
from tests import policy_cel

ROOT = Path(__file__).resolve().parents[1]
REQUESTS = ROOT / "tests" / "fixtures" / "admission"
CHART = ROOT / "deploy" / "helm" / "kube-noob"
ENFORCE = ["KN-S001", "KN-S009"]  # what `cfg.yaml` enforces

SPEC = {
    "hostNetwork": True,
    "hostPID": True,
    "containers": [{"name": "c", "image": "nginx:latest", "securityContext": {"privileged": True}}],
}
KCM = "system:serviceaccount:kube-system:"

#: (kind, apiVersion, owner kind, owner apiVersion, the controller that makes it): what kube-controller-manager
#: creates from the workload kinds the webhook is sent.
REAL_CHILDREN = (
    ("Pod", "v1", "ReplicaSet", "apps/v1", "replicaset-controller"),
    ("Pod", "v1", "StatefulSet", "apps/v1", "statefulset-controller"),
    ("Pod", "v1", "DaemonSet", "apps/v1", "daemon-set-controller"),
    ("Pod", "v1", "Job", "batch/v1", "job-controller"),
    ("ReplicaSet", "apps/v1", "Deployment", "apps/v1", "deployment-controller"),
    ("Job", "batch/v1", "CronJob", "batch/v1", "cronjob-controller"),
)


def _request(name: str) -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads((REQUESTS / name).read_text())
    return loaded


def _child(
    kind: str, api: str, owner: str | None, owner_api: str = "apps/v1", controller: Any = True
) -> dict[str, Any]:
    meta: dict[str, Any] = {"name": "bad", "namespace": "default"}
    if owner is not None:
        meta["ownerReferences"] = [
            {"apiVersion": owner_api, "kind": owner, "name": "o", "uid": "1", "controller": controller}
        ]
    spec: dict[str, Any] = SPEC if kind == "Pod" else {"template": {"spec": SPEC}}
    return {"apiVersion": api, "kind": kind, "metadata": meta, "spec": spec}


def _review(obj: dict[str, Any], username: Any = "dev", ns: str = "default", **extra: Any) -> dict[str, Any]:
    req: dict[str, Any] = {
        "uid": "u-123",
        "operation": "CREATE",
        "namespace": ns,
        "kind": {"group": "", "version": "v1", "kind": obj["kind"]},
        "object": obj,
        **extra,
    }
    if username is not None:
        req["userInfo"] = {"username": username, "groups": ["system:authenticated"]}
    return {"apiVersion": adm.API_VERSION, "kind": "AdmissionReview", "request": req}


def _answer(doc: dict[str, Any], cfg: adm.Config) -> dict[str, Any]:
    out: dict[str, Any] = adm.review(doc, cfg)["response"]
    return out


SKIPPED = {"uid": "u-123", "allowed": True}


@pytest.mark.parametrize("name", ["r_owned.json", "r_owned_cm.json", "r_bad.json", "r_dep_owned.json"])
def test_a_forged_owner_reference_does_not_skip_an_enforced_rule(name: str, capsys: pytest.CaptureFixture[str]) -> None:
    """The red team's four requests, through the command it used. `r_owned` and `r_owned_cm` were `allowed: true`
    with no warning; all four are denied, for the same rule and with the same warnings."""
    cfg = adm.Config.build(enforce=ENFORCE)
    out = _answer(_request(name), cfg)
    assert out["allowed"] is False, name
    assert "KN-S001" in out["status"]["message"] and out["warnings"], name
    assert main(["--config", str(REQUESTS / "cfg.yaml"), "admission", "review", "-f", str(REQUESTS / name)]) == 1
    assert json.loads(capsys.readouterr().out)["response"]["allowed"] is False
    forged = _answer(_request("r_owned.json"), cfg)
    bare = _answer(_request("r_bad.json"), cfg)
    assert forged == bare, "the owner stanza changes nothing about the answer"


@pytest.mark.parametrize("enforce", [ENFORCE, []], ids=["enforce", "warn"])
@pytest.mark.parametrize("child", REAL_CHILDREN, ids=[f"{c[0]}-of-{c[2]}" for c in REAL_CHILDREN])
def test_a_real_controllers_own_child_keeps_its_existing_behaviour(
    child: tuple[str, str, str, str, str], enforce: list[str]
) -> None:
    """De-duplication, kept: the Deployment was judged, so the ReplicaSet its controller makes and the Pods that
    one makes are not judged again -- in warn mode (no second and third copy of every warning) and in enforce
    mode (a Deployment that predates the rule keeps getting its Pods back after a node drain)."""
    kind, api, owner, owner_api, controller = child
    cfg = adm.Config.build(enforce=enforce)
    obj = _child(kind, api, owner, owner_api)
    assert _answer(_review(obj, KCM + controller), cfg) == SKIPPED
    # kube-controller-manager without --use-service-account-credentials acts as itself
    assert _answer(_review(obj, "system:kube-controller-manager"), cfg) == SKIPPED
    # ... and the same object from anyone else is judged, whatever it says about its owner
    judged = _answer(_review(obj, "dev"), cfg)
    assert judged.get("warnings"), "a person who wrote the stanza gets the object's findings"
    assert judged["allowed"] is (not enforce)


@pytest.mark.parametrize("enforce", [ENFORCE, []], ids=["enforce", "warn"])
def test_neither_the_identity_nor_the_owner_is_enough_alone(enforce: list[str]) -> None:
    """Each half of the condition, taken away in turn: the neighbouring inputs a review tries first."""
    cfg = adm.Config.build(enforce=enforce)
    owned = _child("Pod", "v1", "ReplicaSet")

    def judged(doc: dict[str, Any], why: str) -> None:
        out = _answer(doc, cfg)
        assert out.get("warnings") and out["allowed"] is (not enforce), why

    for username in (
        "dev",
        "system:serviceaccount:default:replicaset-controller",  # a ServiceAccount anyone can create and name
        "system:serviceaccount:kube-system:replicaset-controller-x",
        "System:serviceaccount:kube-system:replicaset-controller",
        " system:serviceaccount:kube-system:replicaset-controller",
        "system:serviceaccount:kube-system:replication-controller",  # its owner is a kind the webhook is not sent
        "system:serviceaccount:kube-system:generic-garbage-collector",
        "system:serviceaccount:argo-rollouts:argo-rollouts",
        "system:node:worker-1",
        "",
        None,
        ["system:serviceaccount:kube-system:replicaset-controller"],
        {"username": "system:serviceaccount:kube-system:replicaset-controller"},
    ):
        judged(_review(owned, username), f"username {username!r}")
    doc = _review(owned, None)
    doc["request"]["userInfo"] = "system:serviceaccount:kube-system:replicaset-controller"
    judged(doc, "userInfo that is not an object")
    # what the requester can also write: a `groups` entry, an `extra`, a label -- none of it is the identity
    doc = _review(owned, "dev")
    doc["request"]["userInfo"]["groups"] = ["system:serviceaccounts:kube-system", "system:masters"]
    doc["request"]["userInfo"]["extra"] = {"username": [KCM + "replicaset-controller"]}
    judged(doc, "groups and extra")
    # a real controller, and an owner nothing checked
    rs = KCM + "replicaset-controller"
    for obj, why in (
        (_child("Pod", "v1", None), "no owner"),
        (_child("Pod", "v1", "ConfigMap", "v1"), "an owner that is not a workload"),
        (_child("Pod", "v1", "ReplicationController", "v1"), "an owner kind the webhook is never sent"),
        (_child("Pod", "v1", "Rollout", "argoproj.io/v1alpha1"), "a custom resource nobody judged"),
        (_child("Pod", "v1", "ReplicaSet", "example.com/v1"), "a workload kind of another group"),
        (_child("Pod", "v1", "ReplicaSet", controller=False), "an owner that is not the controller"),
        (_child("Pod", "v1", "ReplicaSet", controller="true"), "controller: 'true' is a string"),
        (_child("Pod", "v1", "ReplicaSet", controller=1), "controller: 1 is not true"),
    ):
        judged(_review(obj, rs), why)
    for refs in ({"controller": True}, "ReplicaSet", [None, "x", 7], [[{"controller": True}]]):
        odd = _child("Pod", "v1", None)
        odd["metadata"]["ownerReferences"] = refs
        judged(_review(odd, rs), f"ownerReferences of shape {refs!r}")
    # a kind that was never skipped is not skipped now: a Deployment owned by an operator's custom resource
    judged(_review(_child("Deployment", "apps/v1", "Deployment"), KCM + "deployment-controller"), "a Deployment")


def test_warn_mode_still_says_everything_about_a_forged_owner() -> None:
    """Warn mode cannot deny, so its failure is silence: the forged Pod got no warning at all."""
    cfg = adm.Config.build()
    forged = _answer(_request("r_owned.json"), cfg)
    bare = _answer(_request("r_bad.json"), cfg)
    assert forged["allowed"] is True and forged == bare
    assert any(w.startswith("[KN-S001]") for w in forged["warnings"])


def test_a_debug_container_on_a_managed_pod_is_judged_whoever_asks() -> None:
    """G250's half of this: no owner carries an ephemeral container, so the subresource is never skipped --
    not for a person, and not for a controller identity either."""
    pod = _child("Pod", "v1", "ReplicaSet")
    pod["spec"] = {"containers": [{"name": "web", "image": "nginx"}]}
    debug = copy.deepcopy(pod)
    debug["spec"]["ephemeralContainers"] = [
        {"name": "debugger", "image": "quay.io/evil/t:latest", "securityContext": {"privileged": True}}
    ]
    cfg = adm.Config.build(enforce=["KN-S001"])
    for username in ("dev", KCM + "replicaset-controller"):
        doc = _review(debug, username, operation="UPDATE", oldObject=pod, subResource="ephemeralcontainers")
        assert _answer(doc, cfg)["allowed"] is False, username


def test_an_openshift_namespace_is_reserved_only_on_openshift() -> None:
    """`openshift-anything-i-made-up` was skipped on plain Kubernetes, where nothing reserves the prefix and
    whoever may create a namespace may name it that. On the OpenShift family the platform refuses the name to
    its users, and its operators live there."""
    kubernetes = adm.Config.build(enforce=ENFORCE, platform="kubernetes")
    made_up = _request("r_kubesystem.json")
    assert made_up["request"]["namespace"] == "openshift-anything-i-made-up"
    out = _answer(made_up, kubernetes)
    assert out["allowed"] is False and out["warnings"]
    pod = _child("Pod", "v1", None)
    for ns in ("openshift", "openshift-", "openshift-monitoring", "openshift-x"):
        assert _answer(_review(pod, ns=ns), kubernetes)["allowed"] is False, ns
        for platform in ("openshift", "rosa-classic", "rosa-hcp"):
            cfg = adm.Config.build(enforce=ENFORCE, platform=platform, openshift_reserved=True)
            assert _answer(_review(pod, ns=ns), cfg) == SKIPPED, (platform, ns)
    for platform in ("kubernetes", "openshift"):
        cfg = adm.Config.build(enforce=ENFORCE, platform=platform, openshift_reserved=True)
        for ns in ("kube-system", "kube-public", "kube-node-lease"):
            assert _answer(_review(pod, ns=ns), cfg) == SKIPPED, (platform, ns)
        # exact names and a real prefix, not a substring: none of these is a system namespace anywhere
        for ns in ("kube-system-x", "kube-systems", "my-openshift-x", "openshiftx", "Openshift-x", "kube-", "default"):
            assert _answer(_review(pod, ns=ns), cfg)["allowed"] is False, (platform, ns)
    mine = adm.Config.build(enforce=ENFORCE, platform="kubernetes", excluded=["openshift-x"])
    assert _answer(_review(pod, ns="openshift-x"), mine) == SKIPPED, "the operator may still exclude it by name"


def test_a_platform_that_was_only_declared_reserves_nothing(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """`platform: openshift` is a value, and the chart's default one: a default install on plain Kubernetes
    declared it without anyone choosing it, so the first form of this fix still skipped `openshift-x` there.
    The server cannot find out what it runs on -- it is offline and holds no credential -- so its default is to
    judge, and it skips only when it is TOLD the cluster serves the OpenShift APIs, which the chart reads from
    the cluster at install. Both, or nothing: evidence without the platform is not a reservation either."""
    made_up = _request("r_kubesystem.json")
    pod = _child("Pod", "v1", None)
    for platform in ("openshift", "rosa-classic", "rosa-hcp", "kubernetes"):
        declared = adm.Config.build(enforce=ENFORCE, platform=platform)
        assert declared.openshift_reserved is False, "the default is to judge"
        assert adm.Config(platform=platform).openshift_reserved is False, "however the configuration is built"
        assert _answer(made_up, adm.Config(enforce=frozenset(ENFORCE), platform=platform))["allowed"] is False
        out = _answer(made_up, declared)
        assert out["allowed"] is False and out["warnings"], platform
        for ns in ("openshift", "openshift-x", "openshift-monitoring"):
            assert _answer(_review(pod, ns=ns), declared)["allowed"] is False, (platform, ns)
    evidence_only = adm.Config.build(enforce=ENFORCE, platform="kubernetes", openshift_reserved=True)
    assert _answer(made_up, evidence_only)["allowed"] is False
    both = adm.Config.build(enforce=ENFORCE, platform="openshift", openshift_reserved=True)
    assert _answer(made_up, both) == SKIPPED
    # the command, with the red team's file, under both platform settings and with the chart's statement
    request = str(REQUESTS / "r_kubesystem.json")
    for body, code in (
        ("defaultPlatform: kubernetes\n", 1),
        ("defaultPlatform: openshift\n", 1),
        ("defaultPlatform: openshift\nadmission:\n  openshiftNamespacesReserved: false\n", 1),
        ("defaultPlatform: kubernetes\nadmission:\n  openshiftNamespacesReserved: true\n", 1),
        ("defaultPlatform: openshift\nadmission:\n  openshiftNamespacesReserved: true\n", 0),
    ):
        config = tmp_path / "config.yaml"
        config.write_text(body)
        assert main(["--config", str(config), "admission", "review", "-f", request, "--enforce", "KN-S001"]) == code, (
            body
        )
        assert json.loads(capsys.readouterr().out)["response"]["allowed"] is (code == 0), body


def test_a_deletion_timestamp_on_a_create_does_not_skip() -> None:
    """An object being deleted is skipped so its finalizers can be removed. That is an UPDATE: the API server
    clears `deletionTimestamp` on every create, so a CREATE that carries one is not one it sent."""
    cfg = adm.Config.build(enforce=ENFORCE)
    assert _answer(_request("r_deltime.json"), cfg)["allowed"] is False
    going = _child("Pod", "v1", None)
    going["metadata"]["deletionTimestamp"] = "2026-01-01T00:00:00Z"
    assert _answer(_review(going, operation="UPDATE", oldObject=going), cfg) == SKIPPED


# -- the chart: the same condition, one step earlier -----------------------------------------------------------------


def _match_conditions() -> dict[str, str]:
    """The webhook's `matchConditions` as the template writes them (static text, so it reads without helm)."""
    text = (CHART / "templates" / "admission.yaml").read_text()
    block = text.split("    matchConditions:\n", 1)[1].split("    {{- end }}\n    rules:", 1)[0]
    plain = "\n".join(line for line in block.splitlines() if "{{" not in line)
    return {c["name"]: c["expression"] for c in yaml.safe_load(plain)}


def _sent(expression: str, doc: dict[str, Any]) -> bool:
    """Whether the API server sends this request to the webhook: a matchCondition that is true matches."""
    activation = {
        "request": policy_cel.json_to_cel(doc["request"]),
        "object": policy_cel.json_to_cel(doc["request"]["object"]),
    }
    return bool(policy_cel.evaluate(expression, activation))


def test_the_charts_match_condition_skips_exactly_what_the_server_skips() -> None:
    """The API server evaluates `matchConditions` before it calls the webhook, so a condition looser than the
    server's is the policy and the server's is decoration. Same request, both asked, over the matrix above."""
    conditions = _match_conditions()
    assert "not-owned-by-a-controller" not in conditions, "ownerReferences alone must never exclude a request"
    expression = conditions["not-a-controllers-own-child"]
    assert "request.userInfo.username" in expression
    cfg = adm.Config.build(enforce=ENFORCE)
    cases: list[dict[str, Any]] = [_request(n) for n in ("r_owned.json", "r_owned_cm.json", "r_bad.json")]
    cases.append(_request("r_dep_owned.json"))
    users = [
        "dev",
        "system:kube-controller-manager",
        "system:serviceaccount:default:replicaset-controller",
        KCM + "replication-controller",
        *(KCM + c[4] for c in REAL_CHILDREN),
    ]
    objects = [_child(kind, api, owner, owner_api) for kind, api, owner, owner_api, _ in REAL_CHILDREN]
    objects += [
        _child("Pod", "v1", None),
        _child("Pod", "v1", "ConfigMap", "v1"),
        _child("Pod", "v1", "ReplicationController", "v1"),
        _child("Pod", "v1", "ReplicaSet", "example.com/v1"),
        _child("Pod", "v1", "ReplicaSet", controller=False),
        _child("Deployment", "apps/v1", "Deployment"),
        _child("Job", "batch/v1", "Deployment"),
    ]
    for missing in ("kind", "apiVersion", "controller"):
        partial = _child("Pod", "v1", "ReplicaSet")
        del partial["metadata"]["ownerReferences"][0][missing]
        objects.append(partial)
    cases += [_review(obj, user) for obj in objects for user in users]
    # the subresource is never skipped, and a request with no username is not an error (an error in a
    # matchCondition is a skipped webhook under failurePolicy Ignore, which would be the bypass again)
    cases += [_review(objects[0], user, operation="UPDATE", subResource="ephemeralcontainers") for user in users]
    cases += [_review(objects[0], user, subResource="") for user in users]
    nameless = _review(objects[0], None)
    nameless["request"]["userInfo"] = {"groups": ["system:unauthenticated"]}
    cases.append(nameless)
    sent_some = skipped_some = False
    for doc in cases:
        doc["request"].setdefault("userInfo", {"username": "dev"})
        sent = _sent(expression, doc)
        skipped = _answer(doc, cfg) == SKIPPED and not doc["request"].get("subResource")
        assert sent is (not skipped), (doc["request"]["userInfo"], doc["request"]["object"]["metadata"])
        sent_some, skipped_some = sent_some or sent, skipped_some or skipped
    assert sent_some and skipped_some, "the matrix exercises both answers"
    for name in ("r_owned.json", "r_owned_cm.json"):
        forged = _request(name)
        forged["request"]["userInfo"] = {"username": "dev"}
        assert _sent(expression, forged), f"{name} reaches the webhook"
    # the lists are written twice (CEL in the chart, Python in the server): held equal, by name
    for user in adm.CONTROLLER_USERS:
        assert f'"{user}"' in expression, user
    for word in (*adm.OWNED_KINDS, *adm.CHECKED_OWNERS, *adm.OWNER_API_VERSIONS):
        assert f'"{word}"' in expression, word
    quoted = set(expression.replace("[", " ").replace("]", " ").replace(",", " ").split())
    literals = {w.strip('"') for w in quoted if w.startswith('"') and w.endswith('"')}
    assert literals == (set(adm.CONTROLLER_USERS) | adm.OWNED_KINDS | adm.CHECKED_OWNERS | adm.OWNER_API_VERSIONS), (
        "nothing in the chart's condition that the server does not also require"
    )


def test_the_chart_reserves_openshift_namespaces_only_where_the_platform_does() -> None:
    text = (CHART / "templates" / "admission.yaml").read_text()
    # Two facts, both required: what the operator declared, and what the cluster being installed into serves.
    # The declaration alone is the chart's default value, so it is evidence of nothing (a default install on
    # Kubernetes declared `openshift`); `.Capabilities` is read from the cluster by `helm install` and `upgrade`.
    assert '$declared := has .Values.config.defaultPlatform (list "openshift" "rosa-classic" "rosa-hcp")' in text
    assert '$served := .Capabilities.APIVersions.Has "config.openshift.io/v1"' in text
    assert "{{- $ocp := and $declared $served }}" in text
    assert text.count("$ocp :=") == 1 and text.count("$served :=") == 1 and text.count("$declared :=") == 1
    assert "      openshiftNamespacesReserved: {{ $ocp }}\n" in text, "the server is told, in its config.yaml"
    notes = (CHART / "templates" / "NOTES.txt").read_text()
    assert 'not (.Capabilities.APIVersions.Has "config.openshift.io/v1")' in notes
    assert "config.defaultPlatform" in notes and "openshift-*" in notes
    from kube_noob.catalog import OPENSHIFT_FAMILY

    assert {"openshift", "rosa-classic", "rosa-hcp"} == OPENSHIFT_FAMILY
    lines = text.splitlines()
    at = next(i for i, line in enumerate(lines) if "name: not-an-openshift-namespace" in line)
    assert lines[at - 1].strip() == "{{- if $ocp }}" and lines[at + 2].strip() == "{{- end }}"
    always = text.split("$always := list ", 1)[1].split("}}", 1)[0].replace('"', "").split()
    assert set(always) == adm.SYSTEM_NAMESPACES == {"kube-system", "kube-public", "kube-node-lease"}
    assert '$platformNs := ternary (list "openshift") (list) $ocp' in text
    assert {"openshift"} == adm.OPENSHIFT_NAMESPACES and adm.OPENSHIFT_PREFIXES == ("openshift-",)
    assert _match_conditions()["not-an-openshift-namespace"] == '!request.namespace.startsWith("openshift-")'
