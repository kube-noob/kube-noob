"""On `--live`, read the CNI from the cluster instead of waiting to be told (roadmap P9).

`--cni` is the caller's claim. With `--live`, kube-noob is already talking to the cluster, and Calico publishes
its own version there: `clusterinformations.crd.projectcalico.org` carries `spec.calicoVersion`, "set
automatically by calico/node" (upstream CRD, projectcalico/calico, libcalico-go/config/crd, retrieved
2026-11-05). Without this read, `policy reach --live` on a Calico 3.32 cluster keeps OVN-Kubernetes semantics and
reports a deny that is not happening -- the defect P7 exists to prevent, surviving on the one path where the
operator cannot read the policies for themselves.

What this must NOT do is make an answer worse. An absent CRD means Calico is not installed and the behaviour is
what it was; a forbidden read says so, and withholds only an answer the admin tier decides (G279).
"""

from __future__ import annotations

from typing import Any

import pytest

from kube_noob.debug.netpol import check_reachability, inventory_from_cluster
from kube_noob.errors import ClusterAccessError

ANP = {
    "apiVersion": "policy.networking.k8s.io/v1alpha1",
    "kind": "AdminNetworkPolicy",
    "metadata": {"name": "guardrail"},
    "spec": {
        "priority": 10,
        "subject": {"namespaces": {"matchLabels": {"tier": "app"}}},
        "ingress": [{"name": "deny-all", "action": "Deny", "from": [{"namespaces": {}}]}],
    },
}
ALLOW_ALL = {
    "apiVersion": "networking.k8s.io/v1",
    "kind": "NetworkPolicy",
    "metadata": {"name": "allow", "namespace": "shop"},
    "spec": {"podSelector": {"matchLabels": {"app": "orders"}}, "policyTypes": ["Ingress"], "ingress": [{}]},
}
WORKLOADS = [
    {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "shop", "labels": {"tier": "app"}}},
    {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "monitoring", "labels": {"tier": "platform"}}},
    {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "orders", "namespace": "shop"},
        "spec": {
            "template": {
                "metadata": {"labels": {"app": "orders"}},
                "spec": {"containers": [{"name": "c", "image": "o:1", "ports": [{"containerPort": 8080}]}]},
            }
        },
    },
    {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "prometheus", "namespace": "monitoring"},
        "spec": {
            "template": {
                "metadata": {"labels": {"app": "prometheus"}},
                "spec": {"containers": [{"name": "c", "image": "p:1"}]},
            }
        },
    },
]

_KINDS = {
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
    "clusterinformations": "ClusterInformation",
}


class Cluster:
    name = "fake"

    def __init__(self, objects: list[dict[str, Any]], forbidden: tuple[str, ...] = ()) -> None:
        self.objects = objects
        self.forbidden = forbidden
        self.calls: list[str] = []

    def get(self, resource: str, name: str | None = None, namespace: str | None = None, **_: Any) -> dict[str, Any]:
        self.calls.append(resource)
        if resource in self.forbidden:
            raise ClusterAccessError(f"{resource} is forbidden: User cannot list {resource} at the cluster scope")
        kind = _KINDS.get(resource)
        if kind is None:
            raise ClusterAccessError(f'the server doesn\'t have a resource type "{resource}"')
        hits = [
            o
            for o in self.objects
            if o["kind"] == kind
            and (name is None or o["metadata"]["name"] == name)
            and (
                kind in {"Namespace", "ClusterInformation"}
                or namespace is None
                or o["metadata"].get("namespace") == namespace
            )
        ]
        if name is not None:
            if not hits:
                raise ClusterAccessError(f"{resource} {name} not found")
            return hits[0]
        return {"items": hits}


def _info(version: str | None, variant: str | None = "Calico") -> dict[str, Any]:
    spec: dict[str, Any] = {"clusterGUID": "abc", "clusterType": "k8s,bgp"}
    if version is not None:
        spec["calicoVersion"] = version
    if variant is not None:
        spec["variant"] = variant
    return {
        "apiVersion": "crd.projectcalico.org/v1",
        "kind": "ClusterInformation",
        "metadata": {"name": "default"},
        "spec": spec,
    }


def _reach(cluster: Cluster, cni: str | None = None) -> dict[str, Any]:
    inv = inventory_from_cluster(cluster, "monitoring/prometheus", "shop/orders", cni)
    return check_reachability(inv, "monitoring/prometheus", "shop/orders", 8080)


def test_the_version_the_cluster_publishes_decides() -> None:
    """The headline: the ANP denies, Calico 3.32 does not enforce it, and nobody had to pass a flag."""
    out = _reach(Cluster([*WORKLOADS, ALLOW_ALL, ANP, _info("v3.32.1")]))
    assert out["verdict"] == "allowed"
    assert [p["policy"] for p in out["inertPolicies"]] == ["AdminNetworkPolicy/guardrail"]
    assert any("read from the cluster" in n for n in out["notes"]), out["notes"]


def test_a_version_that_still_enforces_leaves_the_tier_deciding() -> None:
    out = _reach(Cluster([*WORKLOADS, ALLOW_ALL, ANP, _info("v3.31.0")]))
    assert out["verdict"] == "denied" and out["ingress"]["tier"] == "AdminNetworkPolicy"
    assert "inertPolicies" not in out


def test_a_cluster_without_calico_behaves_exactly_as_before() -> None:
    """An absent CRD is a 404 and means Calico is not installed. It must not add a note or change a verdict."""
    out = _reach(Cluster([*WORKLOADS, ALLOW_ALL, ANP]))
    assert out["verdict"] == "denied" and "inertPolicies" not in out
    assert not any("calico" in n.lower() for n in out.get("notes", []))


def test_a_forbidden_read_says_so_and_withholds_an_answer_the_admin_tier_decides() -> None:
    """A forbidden read of the CNI is not "no Calico" (G279). This used to keep the OVN-Kubernetes assumption and
    answer `denied` from an AdminNetworkPolicy that a Calico 3.32 cluster ignores; the two readings disagree here,
    so the answer is undetermined and says why. Where they agree, the forbidden read changes nothing:
    tests/test_absent_vs_unread.py::test_a_cni_that_could_not_be_read_changes_nothing_where_both_readings_agree."""
    cluster = Cluster([*WORKLOADS, ALLOW_ALL, ANP], forbidden=("clusterinformations",))
    out = _reach(cluster)
    assert out["verdict"] == "undetermined"
    assert out["undeterminedBy"] == ["AdminNetworkPolicy/guardrail"]
    assert any("could not be read" in n and "CNI" in n for n in out["notes"]), out["notes"]


def test_the_flag_wins_over_the_cluster() -> None:
    """A caller who passes --cni knows something the read may not be allowed to see, so the flag is not overridden."""
    out = _reach(Cluster([*WORKLOADS, ALLOW_ALL, ANP, _info("v3.31.0")]), cni="calico:3.32")
    assert out["verdict"] == "allowed" and "inertPolicies" in out


def test_the_cluster_is_not_asked_when_the_flag_already_answered() -> None:
    cluster = Cluster([*WORKLOADS, ALLOW_ALL, ANP, _info("v3.32.1")])
    _reach(cluster, cni="calico:3.31")
    assert "clusterinformations" not in cluster.calls


def test_another_variant_is_not_read_as_open_source_calico() -> None:
    """`variant` declares which Calico is running. Enterprise versions are numbered on their own schedule, so
    mapping one onto the open-source table would be a guess."""
    out = _reach(Cluster([*WORKLOADS, ALLOW_ALL, ANP, _info("v3.32.1", variant="TigeraSecureEnterprise")]))
    assert "inertPolicies" not in out
    assert any("variant" in n.lower() for n in out["notes"]), out["notes"]


def test_an_information_object_without_a_version_is_not_a_version() -> None:
    out = _reach(Cluster([*WORKLOADS, ALLOW_ALL, ANP, _info(None)]))
    assert out["verdict"] == "denied" and "inertPolicies" not in out


@pytest.mark.parametrize("version", ["3", "not-a-version", ""])
def test_a_version_string_that_cannot_be_parsed_is_not_guessed(version: str) -> None:
    out = _reach(Cluster([*WORKLOADS, ALLOW_ALL, ANP, _info(version)]))
    assert "inertPolicies" not in out


def test_the_resource_definition_matches_the_published_crd() -> None:
    """Group, version, plural and scope from projectcalico/calico's own CRD, not from a guess (the G184 lesson)."""
    from kube_noob.debug.cluster import ALLOWED_RESOURCES

    d = ALLOWED_RESOURCES["clusterinformations"]
    assert d.group_version == "crd.projectcalico.org/v1"
    assert d.plural == "clusterinformations"
    assert d.namespaced is False
