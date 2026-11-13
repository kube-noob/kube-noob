"""The pod specs that are not at `spec.template.spec` (G229).

An operator CRD that carries its own pod spec -- a KServe component, a Ray head or worker group -- used to
produce no findings at all: the readers looked only at the nine ordinary workload paths, found nothing, and every
pod-level rule in the catalogue passed. Not "not evaluated": clean. These tests pin the shape of the fix, so that
the same pod spec scores the same whichever object carries it.
"""

from __future__ import annotations

import copy
import json
import re
from typing import Any

import pytest

from kube_noob import attack_paths as ap
from kube_noob.audit.engine import analyze
from kube_noob.audit.podspec import (
    EMBEDDED_POD_SPEC_GROUPS,
    EMBEDDED_POD_SPEC_PATHS,
    POD_SPEC_PATHS,
    pod_templates,
)
from kube_noob.yamlio import Document

# privileged, root, escalating, host path /, a mutable tag and a mounted token: the loudest pod spec there is
BAD_POD: dict[str, Any] = {
    "serviceAccountName": "runner",
    "containers": [
        {
            "name": "c",
            "image": "model:latest",
            "securityContext": {"privileged": True, "allowPrivilegeEscalation": True, "runAsUser": 0},
            "volumeMounts": [{"name": "h", "mountPath": "/host"}],
        }
    ],
    "volumes": [{"name": "h", "hostPath": {"path": "/"}}],
}
LABELS = {"app": "m"}


def _deployment() -> dict[str, Any]:
    return copy.deepcopy(
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "d", "namespace": "ns"},
            "spec": {
                "replicas": 1,
                "selector": {"matchLabels": LABELS},
                "template": {"metadata": {"labels": LABELS}, "spec": BAD_POD},
            },
        }
    )


def _isvc() -> dict[str, Any]:
    return copy.deepcopy(
        {
            "apiVersion": "serving.kserve.io/v1beta1",
            "kind": "InferenceService",
            "metadata": {"name": "i", "namespace": "ns", "labels": LABELS},
            "spec": {"predictor": BAD_POD},
        }
    )


def _raycluster() -> dict[str, Any]:
    template = {"metadata": {"labels": LABELS}, "spec": BAD_POD}
    return copy.deepcopy(
        {
            "apiVersion": "ray.io/v1",
            "kind": "RayCluster",
            "metadata": {"name": "r", "namespace": "ns"},
            "spec": {
                "headGroupSpec": {"template": template},
                "workerGroupSpecs": [{"groupName": "g0", "template": template}],
            },
        }
    )


def _rule_ids(obj: dict[str, Any]) -> set[str]:
    return {f.rule_id for f in analyze(json.dumps(obj)).findings}


# --- the blind spot itself ---------------------------------------------------------------------------------------


def test_an_inference_service_is_audited_not_passed() -> None:
    """The defect: this returned an empty set, so the predictor counted as clean."""
    found = _rule_ids(_isvc())
    assert found, "an InferenceService predictor produced no findings at all"
    # the pod-level rules that do not depend on labels, replicas or probes
    for rule in ("KN-S001", "KN-S002", "KN-S003", "KN-S006", "KN-S007", "KN-S010", "KN-S012"):
        assert rule in found, f"{rule} did not fire on an inline KServe PodSpec"


def test_every_pod_level_rule_that_fires_on_a_deployment_fires_on_a_ray_cluster() -> None:
    """A RayCluster head template IS a PodTemplateSpec, so nothing about it is inapplicable: the rules that fire
    on the same spec in a Deployment must fire here too, bar the ones scoped to replicated or long-running kinds."""
    kind_scoped = {"KN-C001", "KN-C002", "KN-C007", "KN-N001"}  # probes, replicas, NetworkPolicy selector
    missing = (_rule_ids(_deployment()) - kind_scoped) - _rule_ids(_raycluster())
    assert not missing, f"rules lost when the same pod spec moved into a RayCluster: {sorted(missing)}"


def test_each_component_and_worker_group_is_its_own_pod_spec() -> None:
    isvc = _isvc()
    isvc["spec"]["transformer"] = BAD_POD
    assert [t.component for t in pod_templates(Document(index=0, data=isvc))] == ["predictor", "transformer"]
    isvc["spec"]["predictor"]["workerSpec"] = BAD_POD
    comps = [t.component for t in pod_templates(Document(index=0, data=isvc))]
    assert "predictor/workerSpec" in comps, f"multi-node inference is a second pod spec: {comps}"
    ray = _raycluster()
    ray["spec"]["workerGroupSpecs"].append({"groupName": "g1", "template": {"spec": BAD_POD}})
    assert [t.component for t in pod_templates(Document(index=0, data=ray))] == [
        "headGroupSpec",
        "workerGroupSpecs/0",
        "workerGroupSpecs/1",
    ]


def test_a_findings_path_points_into_the_component_that_carries_it() -> None:
    paths = {f.path for f in analyze(json.dumps(_raycluster())).findings}
    assert any("workerGroupSpecs" in p for p in paths), f"no finding names a worker group: {sorted(paths)[:5]}"
    assert any("headGroupSpec" in p for p in paths), f"no finding names the head: {sorted(paths)[:5]}"


# --- what must NOT happen ---------------------------------------------------------------------------------------


def test_a_same_named_kind_from_another_group_is_not_read() -> None:
    """`RayCluster` in someone else's group is a different object; reading its `spec.headGroupSpec` would be a
    guess about a schema this registry has never seen (G227)."""
    other = _raycluster()
    other["apiVersion"] = "example.com/v1"
    assert pod_templates(Document(index=0, data=other)) == []


def test_a_kind_with_no_api_version_is_read_because_the_live_collectors_drop_it() -> None:
    """API list items carry no apiVersion, and both live collectors set only `kind`. Refusing an absent group
    would restore the blind spot for every `--live` scan -- an unknown is not a contradiction."""
    live = _raycluster()
    del live["apiVersion"]
    assert len(pod_templates(Document(index=0, data=live))) == 2


def test_a_kserve_component_carries_the_labels_the_controller_actually_sets() -> None:
    """The first version of this returned `{}` on the theory that the object's labels are not the pod's. Upstream
    says otherwise: `buildObjectMeta` (predictor.go, read 2026-11-06) sets the pod's labels to the union of the
    ServingRuntime's labels, the object's own, the component's `labels`, and `serving.kserve.io/inferenceservice`
    plus `component`. So the manifest-known set is a SUBSET of the real set, never a different one (G231)."""
    templates = [t for t in pod_templates(Document(index=0, data=_isvc())) if t.component == "predictor"]
    assert len(templates) == 1
    labels = templates[0].labels()
    assert labels["app"] == "m", "the object's own labels are on the pod"
    assert labels["serving.kserve.io/inferenceservice"] == "i"
    assert labels["component"] == "predictor"
    assert templates[0].labels_complete is False, "the ServingRuntime's labels are not in this input"


def test_a_component_labels_block_is_merged_in() -> None:
    isvc = _isvc()
    isvc["spec"]["predictor"]["labels"] = {"tier": "gpu"}
    pt = next(t for t in pod_templates(Document(index=0, data=isvc)) if t.component == "predictor")
    assert pt.labels()["tier"] == "gpu"


def test_a_ray_template_keeps_its_own_labels() -> None:
    templates = pod_templates(Document(index=0, data=_raycluster()))
    assert [t.labels() for t in templates] == [LABELS, LABELS]
    assert all(t.labels_complete is False for t in templates), "KubeRay adds ray.io/* labels this input lacks"


def test_the_two_registries_do_not_overlap() -> None:
    assert not set(POD_SPEC_PATHS) & set(EMBEDDED_POD_SPEC_PATHS)
    assert set(EMBEDDED_POD_SPEC_GROUPS) == set(EMBEDDED_POD_SPEC_PATHS), "every embedded kind needs its group"


@pytest.mark.parametrize("broken", [{"spec": {"predictor": "not-a-mapping"}}, {"spec": []}, {}, {"spec": None}])
def test_malformed_input_yields_no_templates_and_does_not_raise(broken: dict[str, Any]) -> None:
    doc = {"apiVersion": "serving.kserve.io/v1beta1", "kind": "InferenceService", "metadata": {"name": "i"}, **broken}
    assert pod_templates(Document(index=0, data=doc)) == []


def test_a_worker_group_list_that_is_not_a_list_is_skipped() -> None:
    ray = _raycluster()
    ray["spec"]["workerGroupSpecs"] = "nope"
    assert [t.component for t in pod_templates(Document(index=0, data=ray))] == ["headGroupSpec"]


# --- the attack-path scan ---------------------------------------------------------------------------------------


def _sa_and_cluster_admin() -> list[dict[str, Any]]:
    return [
        {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "runner", "namespace": "ns"}},
        {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRole",
            "metadata": {"name": "ca"},
            "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}],
        },
        {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRoleBinding",
            "metadata": {"name": "b"},
            "roleRef": {"kind": "ClusterRole", "name": "ca"},
            "subjects": [{"kind": "ServiceAccount", "name": "runner", "namespace": "ns"}],
        },
    ]


def _service() -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": "s", "namespace": "ns"},
        "spec": {"type": "LoadBalancer", "selector": LABELS, "ports": [{"port": 80}]},
    }


def test_the_scan_reaches_a_ray_head_and_every_worker_group() -> None:
    inv = ap.Inventory.from_documents([_service(), _raycluster(), *_sa_and_cluster_admin()])
    reach = ap.workload_reach(inv)
    assert set(reach) == {"RayCluster/ns/r[headGroupSpec]", "RayCluster/ns/r[workerGroupSpecs/0]"}
    deploy = ap.workload_reach(ap.Inventory.from_documents([_service(), _deployment(), *_sa_and_cluster_admin()]))
    one = deploy["Deployment/ns/d"]
    for r in reach.values():
        assert [c.name for c in r.capabilities] == [c.name for c in one.capabilities]
        assert r.exposure is not None, "the head and each worker group are selected by the Service"
    out = ap.scan(inv, top=50)
    assert out["workloads"] == 1, "one object, even though it carries two pod specs"
    assert (
        out["total"]
        == 2
        * ap.scan(ap.Inventory.from_documents([_service(), _deployment(), *_sa_and_cluster_admin()]), top=50)["total"]
    )


def test_an_unmatchable_component_is_named_as_undetermined_not_left_silent() -> None:
    """A Service whose selector the known labels do not satisfy. The real pod may still carry the label, because
    a ServingRuntime outside this input contributes labels too, so the edge is undetermined -- and saying nothing
    would read as "not exposed", the failure one level up from the one this work began with (G231)."""
    svc = _service()
    svc["spec"]["selector"] = {"runtime": "kserve-sklearn"}  # a ServingRuntime label, not in this input
    inv = ap.Inventory.from_documents([svc, _isvc(), *_sa_and_cluster_admin()])
    reach = ap.workload_reach(inv)
    assert [c.name for c in reach["InferenceService/ns/i[predictor]"].capabilities], "capabilities still scored"
    out = ap.scan(inv, top=50)
    assert any("InferenceService/ns/i[predictor]" in line for line in out["limitations"])
    assert any("No exposure edge could be traced" in line for line in out["limitations"])
    assert any("privileged container" in line for line in out["limitations"]), "say what it can do"


def test_the_scan_reads_every_embedded_kind_it_claims_to() -> None:
    """A kind in the registry that the scan's own inventory rejects would be read by the audit and dropped here."""
    assert set(EMBEDDED_POD_SPEC_PATHS) <= ap.KINDS
    assert set(EMBEDDED_POD_SPEC_PATHS) <= set(ap.LIVE_RESOURCES.values())


def test_every_embedded_kind_is_in_the_read_only_allowlist() -> None:
    """Without this the live scan is refused by the guard before it ever reaches the cluster."""
    from kube_noob.debug.cluster import ALLOWED_RESOURCES

    for resource, kind in ap.LIVE_RESOURCES.items():
        if kind in EMBEDDED_POD_SPEC_PATHS:
            assert resource in ALLOWED_RESOURCES, f"{resource} is scanned but not in the read-only allowlist"
            group = ALLOWED_RESOURCES[resource].group_version.split("/", 1)[0]
            assert group in EMBEDDED_POD_SPEC_GROUPS[kind], f"{resource} is read from a group the reader refuses"


# --- the second pass: what the red team found in the first (G231) ------------------------------------------------


MODEL_FORM: dict[str, Any] = {
    "apiVersion": "serving.kserve.io/v1beta1",
    "kind": "InferenceService",
    "metadata": {"name": "i", "namespace": "ns"},
    "spec": {
        "predictor": {
            "model": {
                "modelFormat": {"name": "sklearn"},
                "storageUri": "s3://b/m",
                "image": "model:latest",
                "securityContext": {"privileged": True, "allowPrivilegeEscalation": True, "runAsUser": 0},
            },
            "volumes": [{"name": "h", "hostPath": {"path": "/"}}],
        }
    },
}


def test_the_model_form_scores_the_same_as_the_containers_form() -> None:
    """`model:` is how a KServe predictor is almost always written -- `containers:` is the exception. Reading only
    `containers` gave this spec 2 findings where the same spec as a list gave 11, and recorded every container
    rule as evaluated-clean on it: the G229 defect one level down, in the form that matters most."""
    as_list = copy.deepcopy(MODEL_FORM)
    model = as_list["spec"]["predictor"].pop("model")
    as_list["spec"]["predictor"]["containers"] = [{"name": "c", **model}]
    assert _rule_ids(MODEL_FORM) == _rule_ids(as_list)
    assert "KN-S001" in _rule_ids(MODEL_FORM), "the privileged model container is a finding"


def test_the_scan_scores_the_model_form_too() -> None:
    """The audit and the scan read containers through different functions, so fixing one left the other passing
    a privileged predictor with no node capability at all."""
    reach = ap.workload_reach(ap.Inventory.from_documents([MODEL_FORM]))
    caps = [c.name for r in reach.values() for c in r.capabilities]
    assert any("privileged" in c for c in caps), caps


@pytest.mark.parametrize("key", ["sklearn", "xgboost", "tensorflow", "pytorch", "triton", "huggingface"])
def test_every_framework_shorthand_is_a_container(key: str) -> None:
    doc = copy.deepcopy(MODEL_FORM)
    doc["spec"]["predictor"][key] = doc["spec"]["predictor"].pop("model")
    assert "KN-S001" in _rule_ids(doc), f"a privileged `{key}:` container was not read"


def test_an_injected_autoscaler_container_is_audited() -> None:
    """KubeRay injects `autoscalerOptions` into the head pod, so a privileged autoscaler is a privileged
    container in that pod."""
    ray = _raycluster()
    ray["spec"]["headGroupSpec"]["template"]["spec"] = {"containers": [{"name": "head", "image": "ray:2"}]}
    ray["spec"]["workerGroupSpecs"] = []
    ray["spec"]["autoscalerOptions"] = {"image": "ray:2", "securityContext": {"privileged": True}}
    assert "KN-S001" in _rule_ids(ray)


def test_a_ray_job_submitter_pod_is_audited() -> None:
    job = {
        "apiVersion": "ray.io/v1",
        "kind": "RayJob",
        "metadata": {"name": "j", "namespace": "ns"},
        "spec": {
            "entrypoint": "python x.py",
            "submitterPodTemplate": {
                "spec": {"containers": [{"name": "s", "image": "ray:2", "securityContext": {"privileged": True}}]}
            },
        },
    }
    assert "KN-S001" in _rule_ids(job)


def test_a_mapping_with_mixed_key_types_does_not_crash_the_audit() -> None:
    """A YAML mapping can hold an int key (`1:`) or a null one (`~:`), and `sorted` then raised TypeError out of
    the audit, the scan and the admission webhook. The contract this file already stated was "no templates and
    does not raise"."""
    import yaml

    doc = {
        "apiVersion": "ray.io/v1",
        "kind": "RayCluster",
        "metadata": {"name": "r", "namespace": "ns"},
        "spec": {"workerGroupSpecs": {1: {"template": {"spec": {}}}, "x": {"template": {"spec": {}}}, None: {}}},
    }
    text = yaml.safe_dump(doc)
    analyze(text)  # must not raise
    ap.scan_manifests(text)  # must not raise


def test_a_correct_network_policy_is_not_called_useless() -> None:
    """`labels() == {}` made KN-V011 and KN-N012 report that a Service has no endpoints and a NetworkPolicy
    protects nothing, about a Service and a policy that both work. A non-match against a known SUBSET of a pod's
    labels proves nothing, so both rules decline instead."""
    isvc = _isvc()
    sel = {"serving.kserve.io/inferenceservice": "i"}
    svc = {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": "s", "namespace": "ns"},
        "spec": {"selector": sel, "ports": [{"port": 80}]},
    }
    np = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": "p", "namespace": "ns"},
        "spec": {"podSelector": {"matchLabels": sel}, "policyTypes": ["Ingress"]},
    }
    report = analyze(json.dumps({"kind": "List", "items": [isvc, svc, np]}))
    fired = {f.rule_id for f in report.findings}
    assert "KN-V011" not in fired and "KN-N012" not in fired


def test_a_selector_that_contradicts_a_known_label_still_fires() -> None:
    """Declining must not become never deciding: a selector asking for a value the pod's KNOWN labels disagree
    with is a real non-match whatever the operator adds."""
    isvc = _isvc()  # metadata.labels = {"app": "m"}
    np = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": "p", "namespace": "ns"},
        "spec": {"podSelector": {"matchLabels": {"app": "typo"}}, "policyTypes": ["Ingress"]},
    }
    fired = {f.rule_id for f in analyze(json.dumps({"kind": "List", "items": [isvc, np]})).findings}
    assert "KN-N012" in fired


def test_a_declining_rule_is_not_recorded_as_evaluated() -> None:
    """The decline has to reach the control summary, or "did not decide" is published as "checked and clean"."""
    isvc = _isvc()
    np = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": "p", "namespace": "ns"},
        "spec": {"podSelector": {"matchLabels": {"runtime": "kserve-sklearn"}}, "policyTypes": ["Ingress"]},
    }
    report = analyze(json.dumps({"kind": "List", "items": [isvc, np]}))
    assert "KN-N012" not in report.evaluated_rules


def test_a_namespace_of_only_serving_workloads_still_needs_a_network_policy() -> None:
    """KN-N001 was scoped to LONG_RUNNING_KINDS, which excluded every serving CRD, so a namespace running only
    KServe or Ray had no finding and the rule was recorded as evaluated-clean on it."""
    for workload in (_isvc(), _raycluster()):
        fired = {f.rule_id for f in analyze(json.dumps(workload), partial_bundle=False).findings}
        assert "KN-N001" in fired, workload["kind"]


def test_a_ray_job_is_not_asked_for_a_network_policy_as_a_server() -> None:
    """A job is not a long-running server; the fix must not over-reach."""
    job = {
        "apiVersion": "ray.io/v1",
        "kind": "RayJob",
        "metadata": {"name": "j", "namespace": "ns"},
        "spec": {
            "rayClusterSpec": {"headGroupSpec": {"template": {"spec": {"containers": [{"name": "c", "image": "x:1"}]}}}}
        },
    }
    fired = {f.rule_id for f in analyze(json.dumps(job), partial_bundle=False).findings}
    assert "KN-N001" not in fired


def test_a_refused_api_group_is_said_out_loud() -> None:
    """Refusing a same-named kind from another group is right (G227); refusing it in silence is the
    absence-read-as-pass this work is about. A Deployment with a made-up group gets KN-V002; this got nothing."""
    other = _raycluster()
    other["apiVersion"] = "example.com/v1"
    report = analyze(json.dumps(other))
    assert not report.findings
    assert any(re.search(r'apiVersion "example\.com/v1".*not audited', a) for a in report.assumptions), (
        report.assumptions
    )
    assert [n["object"] for n in report.not_audited] == ["RayCluster/ns/r"]


def test_the_threat_model_still_sees_an_embedded_workload() -> None:
    """The component ref `Kind/ns/name[component]` broke a lookup keyed on `object_ref`, so `vuln threat`
    reported zero applications for a Ray head the scan had just called internet-reachable."""
    from kube_noob.vuln.threat import model as threat_model

    lb = {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": "s", "namespace": "ns"},
        "spec": {"type": "LoadBalancer", "selector": LABELS, "ports": [{"port": 80}]},
    }
    ray = _raycluster()
    out = threat_model(text=json.dumps({"kind": "List", "items": [lb, ray]}), platform="kubernetes", version="1.35")
    apps = out["applications"]
    assert apps, "a reachable Ray head is an application the threat model must see"
    assert any(a["threats"] for a in apps)


def test_every_reach_carries_the_object_it_came_from() -> None:
    """So the next consumer does not have to parse the key to find the object."""
    inv = ap.Inventory.from_documents([_raycluster(), _deployment()])
    for ref, r in ap.workload_reach(inv).items():
        assert r.object and "[" not in r.object
        assert ref.startswith(r.object)


def test_the_standing_limitations_are_named_so_a_renderer_can_skip_them() -> None:
    """The text renderer prints the per-scan ones only, and it tells them apart by this prefix."""
    out = ap.scan(ap.Inventory.from_documents([_deployment()]), top=5)
    assert out["limitations"][: len(ap.STANDING_LIMITATIONS)] == list(ap.STANDING_LIMITATIONS)


def test_a_plain_pod_without_labels_is_not_told_an_operator_sets_them() -> None:
    """The first predicate was "no labels", which said this about a label-less Pod. It is simply false."""
    pod = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "p", "namespace": "ns"},
        "spec": {"containers": [{"name": "c", "image": "x:1", "securityContext": {"privileged": True}}]},
    }
    out = ap.scan(ap.Inventory.from_documents([pod]), top=5)
    assert len(out["limitations"]) == len(ap.STANDING_LIMITATIONS), out["limitations"]


def test_the_drift_snapshot_watches_the_embedded_kinds() -> None:
    """They are collected live and audited, so leaving them out gave their findings no namespace and no owner."""
    from kube_noob.drift import WATCHED

    assert {"InferenceService", "RayCluster", "RayService", "RayJob"} <= WATCHED


# --- the kinds with no reader at all (G232) ----------------------------------------------------------------------


UNREAD_POD = {"containers": [{"name": "c", "image": "x:latest", "securityContext": {"privileged": True}}]}


@pytest.mark.parametrize(
    ("label", "doc"),
    [
        (
            "Argo Rollout",
            {
                "apiVersion": "argoproj.io/v1alpha1",
                "kind": "Rollout",
                "metadata": {"name": "r", "namespace": "ns"},
                "spec": {"template": {"metadata": {"labels": {"a": "b"}}, "spec": UNREAD_POD}},
            },
        ),
        (
            "Knative Service",
            {
                "apiVersion": "serving.knative.dev/v1",
                "kind": "Service",
                "metadata": {"name": "k", "namespace": "ns"},
                "spec": {"template": {"spec": UNREAD_POD}},
            },
        ),
        (
            "Kubeflow Notebook",
            {
                "apiVersion": "kubeflow.org/v1",
                "kind": "Notebook",
                "metadata": {"name": "n", "namespace": "ns"},
                "spec": {"template": {"spec": UNREAD_POD}},
            },
        ),
        (
            "Seldon",
            {
                "apiVersion": "machinelearning.seldon.io/v1",
                "kind": "SeldonDeployment",
                "metadata": {"name": "s", "namespace": "ns"},
                "spec": {"predictors": [{"componentSpecs": [{"spec": UNREAD_POD}]}]},
            },
        ),
    ],
)
def test_a_pod_spec_in_a_kind_with_no_reader_is_reported_not_passed(label: str, doc: dict[str, Any]) -> None:
    """There are far more workload CRDs than four, and a pod spec inside one with no reader produced no finding,
    no declined rule and no word of any kind -- a privileged container in a document that reported clean. The
    path cannot be guessed, but the shape can be seen, so the gap is named (G232)."""
    report = analyze(json.dumps(doc))
    assert any("no reader" in a for a in report.assumptions), f"{label}: {report.assumptions}"


def test_a_training_job_reports_every_replica_spec_it_could_not_read() -> None:
    doc = {
        "apiVersion": "kubeflow.org/v1",
        "kind": "PyTorchJob",
        "metadata": {"name": "t", "namespace": "ns"},
        "spec": {
            "pytorchReplicaSpecs": {
                "Master": {"template": {"spec": UNREAD_POD}},
                "Worker": {"template": {"spec": UNREAD_POD}},
            }
        },
    }
    note = next(a for a in analyze(json.dumps(doc)).assumptions if "no reader" in a)
    assert note.startswith("2 pod spec(s)"), note


def test_an_object_that_merely_mentions_containers_is_not_accused() -> None:
    """The detector has to be narrow, or it accuses every CRD of hiding pods. A `containers` list whose entries
    have no `image` is not a pod spec, and a ConfigMap whose VALUE is the word is certainly not."""
    for doc in (
        {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": "c", "namespace": "ns"},
            "data": {"x": "containers: lots of them"},
        },
        {
            "apiVersion": "example.com/v1",
            "kind": "Widget",
            "metadata": {"name": "w", "namespace": "ns"},
            "spec": {"containers": ["red", "blue"]},
        },
        {
            "apiVersion": "example.com/v1",
            "kind": "Widget",
            "metadata": {"name": "w", "namespace": "ns"},
            "spec": {"containers": [{"name": "no-image", "size": 3}]},
        },
    ):
        assert not any("no reader" in a for a in analyze(json.dumps(doc)).assumptions), doc


def test_a_kind_the_registries_do_read_is_not_also_flagged() -> None:
    """For the kinds with a reader the registry IS the claim; a second message would say the opposite of it."""
    for doc in (_deployment(), _isvc(), _raycluster()):
        assert not any("no reader" in a for a in analyze(json.dumps(doc)).assumptions), doc["kind"]


def test_the_scan_says_it_dropped_a_workload_crd_rather_than_reporting_none() -> None:
    """`posture scan` filters by kind before anything else, so a file of Argo Rollouts reported 0 workloads and
    0 paths with nothing in notRead -- indistinguishable from a clean cluster."""
    rollout = {
        "apiVersion": "argoproj.io/v1alpha1",
        "kind": "Rollout",
        "metadata": {"name": "r", "namespace": "ns"},
        "spec": {"template": {"metadata": {"labels": {"a": "b"}}, "spec": UNREAD_POD}},
    }
    out = ap.scan(ap.Inventory.from_documents([rollout]), top=5)
    assert out["workloads"] == 0
    assert any("no reader" in n for n in out["notRead"]), out["notRead"]
    quiet = ap.scan(
        ap.Inventory.from_documents(
            [{"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "c", "namespace": "ns"}, "data": {}}]
        ),
        top=5,
    )
    assert quiet["notRead"] == []


def test_the_detector_looks_as_deep_as_the_loader_accepts() -> None:
    """Its first draft capped its own walk at 24 levels while the loader accepts 100, so a pod spec nested deeper
    than that went unmentioned -- the silent miss this detector exists to end, reintroduced inside it."""
    from kube_noob.yamlio import MAX_DEPTH

    node: dict[str, Any] = {"spec": UNREAD_POD}
    for _ in range(MAX_DEPTH - 12):  # inside what the loader permits, far outside the first draft's 24
        node = {"next": node}
    doc = {"apiVersion": "example.com/v1", "kind": "Deep", "metadata": {"name": "d"}, "spec": node}
    assert any("no reader" in a for a in analyze(json.dumps(doc)).assumptions)


def test_a_document_deeper_than_the_loader_allows_is_refused_by_the_loader() -> None:
    from kube_noob.errors import ManifestError

    node: dict[str, Any] = {"end": True}
    for _ in range(400):
        node = {"next": node}
    doc = {"apiVersion": "example.com/v1", "kind": "Deep", "metadata": {"name": "d"}, "spec": node}
    with pytest.raises(ManifestError):
        analyze(json.dumps(doc))


# --- a kind name is unique only inside its group, and a declared exposure is an exposure (G233) -------------------


@pytest.mark.parametrize(
    ("label", "api_version", "kind"),
    [
        ("Knative Service", "serving.knative.dev/v1", "Service"),
        ("Volcano Job", "batch.volcano.sh/v1alpha1", "Job"),
        ("Tekton Task", "tekton.dev/v1", "Task"),
        ("Argo Workflow", "argoproj.io/v1alpha1", "Workflow"),
    ],
)
def test_a_crd_reusing_a_core_kind_name_is_not_called_invalid(label: str, api_version: str, kind: str) -> None:
    """KN-V002 keyed on the kind name alone, and a kind name is unique only within its group: it told a Knative
    user their correct Service "is not served by serving.knative.dev/v1. Use v1" -- as a CRITICAL, which fails a
    gate on a valid manifest. A wrong CRITICAL costs more trust than a missed finding (G233)."""
    doc = {"apiVersion": api_version, "kind": kind, "metadata": {"name": "x", "namespace": "ns"}, "spec": {}}
    fired = [f for f in analyze(json.dumps(doc)).findings if f.rule_id == "KN-V002"]
    assert not fired, f"{label}: {[f.message for f in fired]}"


@pytest.mark.parametrize(
    ("api_version", "kind"),
    [("v1", "Deployment"), ("apps/v1", "Ingress"), ("apps.openshift.io/v1", "Route")],
)
def test_a_built_in_kind_in_the_wrong_group_still_fires(api_version: str, kind: str) -> None:
    """Narrowing the rule must not silence it. The last case is the rule's own documented example."""
    doc = {"apiVersion": api_version, "kind": kind, "metadata": {"name": "x", "namespace": "ns"}, "spec": {}}
    fired = [
        f for f in analyze(json.dumps(doc), platform="openshift", version="4.20").findings if f.rule_id == "KN-V002"
    ]
    assert fired, f"{api_version} {kind} should still be refused"


def _ray_head(**head: Any) -> dict[str, Any]:
    pod = {
        "serviceAccountName": "default",
        "containers": [{"name": "c", "image": "ray:2", "securityContext": {"privileged": True}}],
    }
    return {
        "apiVersion": "ray.io/v1",
        "kind": "RayCluster",
        "metadata": {"name": "r", "namespace": "ns"},
        "spec": {"headGroupSpec": {**head, "template": {"metadata": {"labels": {"app": "ray"}}, "spec": pod}}},
    }


@pytest.mark.parametrize(
    ("head", "expected_weight"),
    [({"serviceType": "LoadBalancer"}, 3), ({"serviceType": "NodePort"}, 2), ({"enableIngress": True}, 3)],
)
def test_an_exposure_the_object_declares_is_an_exposure(head: dict[str, Any], expected_weight: int) -> None:
    """The Service the operator will create is not in the manifest, so nothing matched a selector and the scan
    answered "0 attack paths from 0 exposures" for an internet-facing Ray head running privileged (G233)."""
    out = ap.scan(ap.Inventory.from_documents([_ray_head(**head)]), top=10)
    assert out["total"] >= 1, out["summary"]
    path = out["paths"][0]
    assert path["score"] == expected_weight * 9, path  # privileged container is weight 9
    assert any("serviceType" in st["evidence"] or "enableIngress" in st["evidence"] for st in path["steps"])


def test_a_cluster_ip_head_declares_nothing() -> None:
    out = ap.scan(ap.Inventory.from_documents([_ray_head(serviceType="ClusterIP")]), top=10)
    assert out["total"] == 0, out["summary"]


def test_a_declared_entry_does_not_invent_a_service_step() -> None:
    """The first version reused the selector step, which printed `Service/ns/ --selects--> ...` with the evidence
    "selector {} matches the pod template labels": a Service with no name, and an untrue evidence line."""
    out = ap.scan(ap.Inventory.from_documents([_ray_head(serviceType="LoadBalancer")]), top=10)
    for st in out["paths"][0]["steps"]:
        assert not st["from"].startswith("Service//"), st
        assert st["from"] != "Service/ns/", st
        assert "selector {}" not in st["evidence"], st


# --- de-duplication must not become deletion (G234) --------------------------------------------------------------


def _priv_pod() -> dict[str, Any]:
    return {
        "serviceAccountName": "default",
        "containers": [{"name": "c", "image": "x:1", "securityContext": {"privileged": True}}],
    }


def _dep(name: str, owner: dict[str, Any] | None = None) -> dict[str, Any]:
    d: dict[str, Any] = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": name, "namespace": "ns", "labels": {"app": "m"}},
        "spec": {
            "selector": {"matchLabels": {"app": "m"}},
            "template": {"metadata": {"labels": {"app": "m"}}, "spec": _priv_pod()},
        },
    }
    if owner is not None:
        d["metadata"]["ownerReferences"] = [owner]
    return d


def _lb() -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": "s", "namespace": "ns"},
        "spec": {"type": "LoadBalancer", "selector": {"app": "m"}, "ports": [{"port": 80}]},
    }


def test_a_workload_owned_by_a_crd_is_still_scored() -> None:
    """On a live cluster the Deployment a KServe InferenceService creates is controller-owned BY it, so the scan
    dropped it and a privileged predictor behind a LoadBalancer scored nothing -- in `--live`, which is the
    remedy the scan's own limitation text recommends (G234)."""
    owner = {
        "apiVersion": "serving.kserve.io/v1beta1",
        "kind": "InferenceService",
        "name": "i",
        "uid": "u",
        "controller": True,
    }
    out = ap.scan(ap.Inventory.from_documents([_lb(), _dep("i-predictor", owner)]), top=5)
    assert out["total"] >= 1, out["summary"]


def test_a_deployment_and_its_own_replica_set_are_still_one_workload() -> None:
    """Which is what the ownership filter is for; narrowing it must not treble every path."""
    rs = {
        "apiVersion": "apps/v1",
        "kind": "ReplicaSet",
        "metadata": {
            "name": "d-abc",
            "namespace": "ns",
            "labels": {"app": "m"},
            "ownerReferences": [
                {"apiVersion": "apps/v1", "kind": "Deployment", "name": "d", "uid": "u2", "controller": True}
            ],
        },
        "spec": {
            "selector": {"matchLabels": {"app": "m"}},
            "template": {"metadata": {"labels": {"app": "m"}}, "spec": _priv_pod()},
        },
    }
    out = ap.scan(ap.Inventory.from_documents([_lb(), _dep("d"), rs]), top=5)
    assert out["workloads"] == 1, out
    assert out["total"] == 1, out


def test_an_orphan_replica_set_is_scored_rather_than_dropped() -> None:
    """Dropping on the owner's KIND alone loses every ReplicaSet in a namespace scanned without its Deployments.
    The owner has to actually be in the input for its pods to be considered already accounted for."""
    rs = {
        "apiVersion": "apps/v1",
        "kind": "ReplicaSet",
        "metadata": {
            "name": "d-abc",
            "namespace": "ns",
            "labels": {"app": "m"},
            "ownerReferences": [
                {"apiVersion": "apps/v1", "kind": "Deployment", "name": "d", "uid": "u2", "controller": True}
            ],
        },
        "spec": {
            "selector": {"matchLabels": {"app": "m"}},
            "template": {"metadata": {"labels": {"app": "m"}}, "spec": _priv_pod()},
        },
    }
    out = ap.scan(ap.Inventory.from_documents([_lb(), rs]), top=5)
    assert out["total"] == 1, out["summary"]


# --- fix, and the readers that still saw one template (G238) -----------------------------------------------------


def test_fix_hardens_an_embedded_pod_spec() -> None:
    """`fix` is the one command whose job is to close findings, and it left every AI workload untouched while
    the audit reported findings in it."""
    import yaml

    from kube_noob.audit.fixer import fix_manifests

    res = fix_manifests(yaml.safe_dump(_isvc()), platform="kubernetes", harden=True)
    paths = [str(c.path) for c in res.changes]
    assert any(p.startswith("spec.predictor") for p in paths), paths


def test_fix_writes_into_a_field_shaped_container_not_a_copy_of_it() -> None:
    """`containers()` used to synthesise `{"name": key, **c}` for a `model:` block, which is a COPY: the fixer's
    in-place hardening wrote to a dict the document had never seen and silently did nothing. `ContainerRef`
    carries the real object and the name separately now (G238)."""
    import yaml

    from kube_noob.audit.fixer import fix_manifests

    # A `model:` block the fixer WILL harden. The privileged, `runAsUser: 0` one in MODEL_FORM is deliberately
    # left alone -- a pod-level runAsNonRoot would make the kubelet refuse an explicit root container, and
    # removing `privileged` changes what the workload can do, which needs a person.
    doc = copy.deepcopy(MODEL_FORM)
    doc["spec"]["predictor"]["model"].pop("securityContext")
    res = fix_manifests(yaml.safe_dump(doc), platform="kubernetes", harden=True)
    paths = [str(c.path) for c in res.changes]
    assert any(p.startswith("spec.predictor.model.securityContext") for p in paths), paths
    out = yaml.safe_load(res.yaml())
    assert out["spec"]["predictor"]["model"]["securityContext"], "and it is in the document that comes back"


def test_a_mutable_tag_in_an_embedded_template_is_listed_as_manual_work() -> None:
    import yaml

    from kube_noob.audit.fixer import fix_manifests

    ray = _raycluster()
    res = fix_manifests(yaml.safe_dump(ray), platform="kubernetes", harden=True)
    assert any("pin image" in note for note in res.manual), res.manual


def test_a_probe_on_an_embedded_template_counts_as_a_probe() -> None:
    import yaml

    from kube_noob.build.image import manifests_have_probes

    ray = _raycluster()
    ray["spec"]["headGroupSpec"]["template"]["spec"] = {
        "containers": [{"name": "h", "image": "ray:2", "readinessProbe": {"httpGet": {"port": 8265, "path": "/"}}}]
    }
    assert manifests_have_probes(yaml.safe_dump(ray))


def test_a_container_whose_image_an_operator_supplies_is_not_a_finding() -> None:
    """KServe's own sample has no `image` on the predictor, and the catalogue called that a HIGH (G252).

    `model: {modelFormat: {name: sklearn}, storageUri: ...}` is the canonical form: the ServingRuntime for
    that model format supplies the image. `KN-S012` reported "Container 'model' has no image" at HIGH, and
    since G248 the webhook denied the upstream sample under `enforce: [KN-S012]`. The report records that the
    image was not read instead, because the container IS audited for everything else.
    """
    import yaml

    from kube_noob.audit.engine import analyze
    from kube_noob.audit.podspec import operator_supplied_images
    from kube_noob.yamlio import load_documents

    isvc = yaml.safe_dump(
        {
            "apiVersion": "serving.kserve.io/v1beta1",
            "kind": "InferenceService",
            "metadata": {"name": "sklearn-iris", "namespace": "shop"},
            "spec": {
                "predictor": {
                    "model": {
                        "modelFormat": {"name": "sklearn"},
                        "storageUri": "gs://kfserving-examples/models/sklearn/1.0/model",
                    }
                }
            },
        }
    )
    report = analyze(isvc, platform="kubernetes")
    assert "KN-S012" not in {f.rule_id for f in report.findings}
    assert any("take their image from an operator" in a for a in report.assumptions), report.assumptions
    assert [tuple(p) for p in operator_supplied_images(load_documents(isvc)[0])] == [("spec", "predictor", "model")]
    # A container in a `containers:` list must still carry its own image: that is a real HIGH.
    pod = yaml.safe_dump(
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "p", "namespace": "shop"},
            "spec": {"containers": [{"name": "c"}]},
        }
    )
    plain = analyze(pod, platform="kubernetes")
    assert "KN-S012" in {f.rule_id for f in plain.findings}
    assert not [a for a in plain.assumptions if "take their image from an operator" in a]
    # And one that DOES name an image is measured as any other container is.
    with_image = yaml.safe_dump(
        {
            "apiVersion": "serving.kserve.io/v1beta1",
            "kind": "InferenceService",
            "metadata": {"name": "m", "namespace": "shop"},
            "spec": {"predictor": {"model": {"image": "quay.io/o/m:latest"}}},
        }
    )
    tagged = analyze(with_image, platform="kubernetes")
    assert "KN-S012" in {f.rule_id for f in tagged.findings}
