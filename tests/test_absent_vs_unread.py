"""A read that failed is not a thing that is absent (G279).

`debug.netpol._tier_absent` matched "not found" anywhere in an error, so an auth plugin missing from PATH, a proxy's
404, "the server could not find the requested resource" with no resource named, or a namespace that does not exist
all read as "this API is not installed". `_cni_from_cluster` then decided there was no Calico, said nothing, and
`policy reach --live` evaluated the admin tier as enforced -- the verdict roadmap P7 and P9 exist to protect. A
response without an `items` key read as an empty list in six more places.

One strict classifier (`debug.cluster.classify_read_failure`) now decides, for every live reader: absence only in
the exact words a backend writes for it (kubectl/oc's "the server doesn't have a resource type" for THIS resource,
pinned to cli-runtime v1.35.0 builder.go; the in-cluster backend's 404 for THIS resource's path), forbidden, or not
read. A response without an `items` list is a failed read (`debug.cluster.list_items`).
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

import pytest

from kube_noob.debug.cluster import classify_read_failure, list_items
from kube_noob.debug.netpol import check_reachability, inventory_from_cluster
from kube_noob.errors import ClusterAccessError

# --------------------------------------------------------------------------------------- the classifier itself

KUBECTL_404 = (
    "kubectl get clusterinformations.crd.projectcalico.org --all-namespaces failed: "
    'error: the server doesn\'t have a resource type "clusterinformations"'
)
AUTH_PLUGIN = "Unable to connect to the server: getting credentials: exec: executable gke-gcloud-auth-plugin not found"
METRICS_DOWN = (
    "E1112 10:00:00.000000   1 memcache.go:265] couldn't get resource list for metrics.k8s.io/v1beta1: "
    "the server is currently unable to handle the request\n"
)


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        (KUBECTL_404, "not-served"),
        # the in-cluster backend's own 404 text, for this resource's own list path
        ("Not found: GET /apis/crd.projectcalico.org/v1/clusterinformations", "not-served"),
        # another group's aggregated API being down says nothing about this one
        (METRICS_DOWN + KUBECTL_404, "not-served"),
        # this group's own discovery failing is why kubectl could not map it: not absence
        (
            "couldn't get resource list for crd.projectcalico.org/v1: the server is currently unable to handle "
            "the request\n" + KUBECTL_404,
            "not-read",
        ),
        ("couldn't get current server API group list: Get ...: dial tcp: i/o timeout\n" + KUBECTL_404, "not-read"),
        # the four shapes the operator-inventory review found reading as "not installed"
        (AUTH_PLUGIN, "not-read"),
        ("Error from server (NotFound): the server could not find the requested resource", "not-read"),
        ('Error from server (NotFound): namespaces "typo" not found', "not-read"),
        ("API error 404 for GET /apis/x: <html>404 page not found</html>", "not-read"),
        # another resource's 404, and another path's
        ('error: the server doesn\'t have a resource type "globalnetworkpolicies"', "not-read"),
        ("Not found: GET /apis/crd.projectcalico.org/v1/globalnetworkpolicies", "not-read"),
        ("Not found: GET /apis/crd.projectcalico.org/v1/clusterinformations/extra", "not-read"),
        # forbidden, in both backends' words, wins over anything else in the message
        (
            'Error from server (Forbidden): clusterinformations.crd.projectcalico.org is forbidden: User "u" '
            'cannot list resource "clusterinformations" in API group "crd.projectcalico.org" at the cluster scope',
            "forbidden",
        ),
        ("Forbidden by RBAC: GET /apis/crd.projectcalico.org/v1/clusterinformations.", "forbidden"),
        (
            "Error from server (Forbidden): clusterinformations.crd.projectcalico.org is forbidden\n" + KUBECTL_404,
            "forbidden",
        ),
        # "forbidden" alone, outside the backend's own line, is not kubectl saying it (a name can be "forbidden")
        ("forbidden\n" + KUBECTL_404, "not-served"),
        ("kubectl timed out after 30.0s", "not-read"),
        ("", "not-read"),
    ],
)
def test_absence_is_recognised_only_in_the_words_a_backend_writes_for_it(message: str, expected: str) -> None:
    assert classify_read_failure("clusterinformations", message) == expected


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ('Error from server (NotFound): deployments.apps "web" not found', "not-found"),
        ("Not found: GET /apis/apps/v1/namespaces/shop/deployments/web", "not-found"),
        ('error: the server doesn\'t have a resource type "deployments"', "not-served"),
        ('Error from server (NotFound): deployments.apps "other" not found', "not-read"),
        ('Error from server (NotFound): namespaces "shop" not found', "not-read"),
        ("Not found: GET /apis/apps/v1/namespaces/shop/deployments/other", "not-read"),
        (AUTH_PLUGIN, "not-read"),
        ('Error from server (Forbidden): deployments.apps "web" is forbidden: User "u" cannot get', "forbidden"),
    ],
)
def test_a_named_object_is_missing_only_when_the_backend_names_it_missing(message: str, expected: str) -> None:
    assert classify_read_failure("deployments", message, name="web") == expected


def test_a_core_object_is_named_without_a_group() -> None:
    assert classify_read_failure("pods", 'Error from server (NotFound): pods "web" not found', name="web") == (
        "not-found"
    )
    assert classify_read_failure("pods", "Not found: GET /api/v1/namespaces/shop/pods/web", name="web") == "not-found"


def test_a_resource_off_the_allowlist_is_never_classified_as_absent() -> None:
    assert classify_read_failure("secrets", 'error: the server doesn\'t have a resource type "secrets"') == "not-read"


@pytest.mark.parametrize("data", [{}, {"kind": "List"}, {"items": None}, {"items": {"a": 1}}, [], None, "x"])
def test_a_response_without_an_items_list_is_a_failed_read_not_zero_objects(data: Any) -> None:
    with pytest.raises(ClusterAccessError, match="no items list"):
        list_items(data, "networkpolicies")
    assert list_items({"items": []}, "networkpolicies") == []


# --------------------------------------------------------------------------------------- policy reach --live

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


def _deployment(name: str, ns: str, app: str, port: int | None = None) -> dict[str, Any]:
    c: dict[str, Any] = {"name": "c", "image": f"{app}:1"}
    if port:
        c["ports"] = [{"containerPort": port}]
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": name, "namespace": ns},
        "spec": {"template": {"metadata": {"labels": {"app": app}}, "spec": {"containers": [c]}}},
    }


WORKLOADS = [
    {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "shop", "labels": {"tier": "app"}}},
    {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "monitoring", "labels": {"tier": "platform"}}},
    _deployment("orders", "shop", "orders", 8080),
    _deployment("prometheus", "monitoring", "prometheus"),
]
_KINDS = {
    "networkpolicies": "NetworkPolicy",
    "namespaces": "Namespace",
    "deployments": "Deployment",
    "adminnetworkpolicies": "AdminNetworkPolicy",
    "baselineadminnetworkpolicies": "BaselineAdminNetworkPolicy",
}


class Cluster:
    """A stub backend that fails in the exact words kubectl writes, and only where told to."""

    name = "fake"

    def __init__(self, objects: list[dict[str, Any]], errors: dict[str, str] | None = None, **raw: Any) -> None:
        self.objects, self.errors, self.raw = objects, errors or {}, raw

    def get(self, resource: str, name: str | None = None, namespace: str | None = None, **_: Any) -> dict[str, Any]:
        if resource in self.errors:
            raise ClusterAccessError(f"kubectl get {resource} failed: {self.errors[resource]}")
        if resource in self.raw:
            return dict(self.raw[resource])
        kind = _KINDS.get(resource)
        if kind is None:
            raise ClusterAccessError(
                f'kubectl get {resource} failed: error: the server doesn\'t have a resource type "{resource}"'
            )
        hits = [
            o
            for o in self.objects
            if o["kind"] == kind
            and (name is None or o["metadata"]["name"] == name)
            and (kind == "Namespace" or namespace is None or o["metadata"].get("namespace") == namespace)
        ]
        if name is not None:
            if not hits:
                qualified = "deployments.apps" if resource == "deployments" else resource
                raise ClusterAccessError(f'Error from server (NotFound): {qualified} "{name}" not found')
            return hits[0]
        return {"items": hits}


def _reach(cluster: Cluster) -> dict[str, Any]:
    inv = inventory_from_cluster(cluster, "monitoring/prometheus", "shop/orders")
    return check_reachability(inv, "monitoring/prometheus", "shop/orders", 8080)


def test_a_cluster_whose_api_says_calico_is_not_served_answers_as_before() -> None:
    """The genuine 404 stays what it was -- no Calico, not a failed read -- and on a cluster that serves
    OVN-Kubernetes' EgressFirewall the AdminNetworkPolicy denies, as before. Without that, "no Calico" no longer
    means "so OVN-Kubernetes" (review D3): the CNI was not identified, which is not the same as not read."""
    out = _reach(Cluster([*WORKLOADS, ALLOW_ALL, ANP], egressfirewalls={"items": []}))
    assert out["verdict"] == "denied" and out["ingress"]["tier"] == "AdminNetworkPolicy"
    assert not any("could not be read" in n for n in out.get("notes", []))
    assert any("OVN-Kubernetes" in n for n in out["notes"])

    unknown = _reach(Cluster([*WORKLOADS, ALLOW_ALL, ANP]))
    assert unknown["verdict"] == "undetermined"
    assert any("CNI was not identified" in n for n in unknown["notes"])
    assert not any("could not be read" in n for n in unknown["notes"])


@pytest.mark.parametrize(
    "failure",
    [
        AUTH_PLUGIN,
        "Error from server (NotFound): the server could not find the requested resource",
        'Error from server (Forbidden): clusterinformations.crd.projectcalico.org is forbidden: User "u" cannot list',
    ],
)
def test_a_cni_that_could_not_be_read_leaves_an_admin_tier_answer_undetermined(failure: str) -> None:
    """If the read failed, this may be a Calico 3.32 cluster that ignores the AdminNetworkPolicy, or one that
    enforces it. The two readings disagree here (deny vs allow), so neither is the answer."""
    out = _reach(Cluster([*WORKLOADS, ALLOW_ALL, ANP], errors={"clusterinformations": failure}))
    assert out["verdict"] == "undetermined", out
    assert out["undeterminedBy"] == ["AdminNetworkPolicy/guardrail"]
    assert "CNI could not be read" in out["summary"], out["summary"]
    assert any("CNI could not be read" in n for n in out["notes"]), out["notes"]


def test_a_cni_that_could_not_be_read_changes_nothing_where_both_readings_agree() -> None:
    """No admin-tier policy decides this traffic: whatever the CNI is, the answer is the NetworkPolicies' answer."""
    out = _reach(Cluster([*WORKLOADS, ALLOW_ALL], errors={"clusterinformations": AUTH_PLUGIN}))
    assert out["verdict"] == "allowed", out
    assert any("CNI could not be read" in n for n in out["notes"]), out["notes"]


def test_a_cni_read_that_returned_no_items_list_is_not_a_cluster_without_calico() -> None:
    out = _reach(Cluster([*WORKLOADS, ALLOW_ALL, ANP], clusterinformations={"kind": "List"}))
    assert out["verdict"] == "undetermined", out
    assert "no items list" in " ".join(out["notes"])


@pytest.mark.parametrize(
    "failure", [AUTH_PLUGIN, "Error from server (NotFound): the server could not find the requested resource"]
)
def test_an_admin_tier_that_could_not_be_read_is_not_an_admin_tier_that_is_not_installed(failure: str) -> None:
    """Before: "AdminNetworkPolicy is not installed on this cluster, or could not be read; the answer is
    NetworkPolicy only" -- and an allowed verdict. An unread tier can deny before any NetworkPolicy runs."""
    out = _reach(Cluster([*WORKLOADS, ALLOW_ALL], errors={"adminnetworkpolicies": failure}))
    assert out["verdict"] == "undetermined", out
    assert "AdminNetworkPolicy" in out["undeterminedBy"]
    assert not any("AdminNetworkPolicy is not installed" in n for n in out["notes"]), out["notes"]


def test_an_admin_tier_the_cluster_does_not_serve_is_named_as_not_served() -> None:
    out = _reach(
        Cluster(
            [*WORKLOADS, ALLOW_ALL],
            errors={
                "adminnetworkpolicies": KUBECTL_404.replace(
                    "clusterinformations.crd.projectcalico.org", "adminnetworkpolicies.policy.networking.k8s.io"
                ).replace('"clusterinformations"', '"adminnetworkpolicies"')
            },
        )
    )
    assert out["verdict"] == "allowed", out
    assert any(
        "AdminNetworkPolicy is not installed on this cluster (its API is not served)" in n for n in out["notes"]
    ), out["notes"]


def test_an_admin_tier_response_without_an_items_list_is_not_an_empty_tier() -> None:
    out = _reach(Cluster([*WORKLOADS, ALLOW_ALL], adminnetworkpolicies={"kind": "AdminNetworkPolicyList"}))
    assert out["verdict"] == "undetermined", out
    assert "AdminNetworkPolicy" in out["undeterminedBy"]


def test_a_networkpolicy_read_without_an_items_list_is_not_a_namespace_without_policies() -> None:
    """Zero NetworkPolicies in a namespace means everything is allowed, so this one decided a verdict."""
    out = _reach(Cluster([*WORKLOADS], networkpolicies={"kind": "NetworkPolicyList"}))
    assert out["verdict"] == "undetermined", out
    assert any(ref.startswith("NetworkPolicy") for ref in out["undeterminedBy"]), out


def test_a_workload_that_could_not_be_read_is_not_reported_as_absent_from_the_manifests() -> None:
    """Every workload read forbidden used to end in "is not in the manifests; known workloads: none"."""
    forbidden = 'Error from server (Forbidden): deployments.apps "orders" is forbidden: User "u" cannot get'
    errors = dict.fromkeys(("deployments", "statefulsets", "daemonsets", "pods"), forbidden)
    with pytest.raises(ClusterAccessError, match="could not read monitoring/prometheus: deployments: "):
        inventory_from_cluster(Cluster(WORKLOADS, errors=errors), "monitoring/prometheus", "shop/orders")


def test_a_workload_whose_first_kind_could_not_be_read_is_not_answered_from_another_kind() -> None:
    """`shop/orders` names a Deployment first. When Deployments cannot be read and a Pod of that name can, the
    object asked about is not established: answering about the Pod (the first version of G279 did, with a note
    under an exit-0 verdict) is answering a different question. The error says how to ask for the Pod."""
    pod = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "orders", "namespace": "shop", "labels": {"app": "orders"}},
        "spec": {"containers": [{"name": "c", "image": "o:1", "ports": [{"containerPort": 8080}]}]},
    }
    forbidden = 'Error from server (Forbidden): deployments.apps "orders" is forbidden: User "u" cannot get'
    cluster = Cluster([*WORKLOADS, ALLOW_ALL, pod], errors={"deployments": forbidden})
    _KINDS["pods"] = "Pod"
    try:
        with pytest.raises(ClusterAccessError, match="name the kind"):
            inventory_from_cluster(cluster, "shop/orders", "shop/orders")
        inv = inventory_from_cluster(cluster, "shop/pod/orders", "shop/pod/orders")
    finally:
        del _KINDS["pods"]
    assert inv.resolve("shop/pod/orders").ref == "pod/orders"


# -------------------------------------------------------------------- the same through a real kubectl process


def _stub_kubectl(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, script: str) -> Any:
    from kube_noob.debug.backends import KubectlBackend

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    kubectl = bin_dir / "kubectl"
    kubectl.write_text('#!/bin/sh\nres="$2"\n' + script)
    kubectl.chmod(kubectl.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    return KubectlBackend("kubectl", None, 5)


def _list_case(res: str, body: dict[str, Any]) -> str:
    """A shell case arm answering ``kubectl get RES [--namespace NS] --output json`` with ``body``; a namespaced
    list answers with only the items in the namespace asked for, as the API server does (review D9)."""
    items = body["items"]
    if not any((i.get("metadata") or {}).get("namespace") for i in items):
        return f"  {res})\n    echo '{json.dumps(body)}'; exit 0;;\n"
    arms = ""
    for ns in sorted({i["metadata"]["namespace"] for i in items}):
        mine = {**body, "items": [i for i in items if i["metadata"]["namespace"] == ns]}
        arms += f"      {ns}) echo '{json.dumps(mine)}'; exit 0;;\n"
    empty = json.dumps({**body, "items": []})
    return f"  {res})\n    case \"$4\" in\n{arms}      *) echo '{empty}'; exit 0;;\n    esac;;\n"


def _kubectl_script(clusterinformations: str) -> str:
    lists = {
        "networkpolicies.networking.k8s.io": {"kind": "List", "items": [ALLOW_ALL]},
        "adminnetworkpolicies.policy.networking.k8s.io": {"kind": "List", "items": [ANP]},
        "baselineadminnetworkpolicies.policy.networking.k8s.io": {"kind": "List", "items": []},
        "egressfirewalls.k8s.ovn.org": {"kind": "List", "items": []},  # an OVN-Kubernetes cluster (review D3)
    }
    cases = [_list_case(res, body) for res, body in lists.items()]
    cases.append('  deployments.apps)\n    case "$3" in\n')
    for d in WORKLOADS[2:]:
        cases.append(f"      {d['metadata']['name']}) echo '{json.dumps(d)}'; exit 0;;\n")
    cases.append("    esac;;\n")
    cases.append('  namespaces)\n    case "$3" in\n')
    for n in WORKLOADS[:2]:
        cases.append(f"      {n['metadata']['name']}) echo '{json.dumps(n)}'; exit 0;;\n")
    cases.append("    esac;;\n")
    cases.append(f"  clusterinformations.crd.projectcalico.org)\n    {clusterinformations};;\n")
    plural = "${res%%.*}"
    tail = f'  *)\n    echo "error: the server doesn\'t have a resource type \\"{plural}\\"" >&2; exit 1;;\n'
    return 'case "$res" in\n' + "".join(cases) + tail + "esac\n"


def test_through_kubectl_an_auth_plugin_not_found_is_not_a_cluster_without_calico(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = _stub_kubectl(tmp_path, monkeypatch, _kubectl_script(f"echo '{AUTH_PLUGIN}' >&2; exit 1"))
    out = _reach(backend)
    assert out["verdict"] == "undetermined", out
    assert "gke-gcloud-auth-plugin" in " ".join(out["notes"])

    absent = _stub_kubectl(
        tmp_path,
        monkeypatch,
        _kubectl_script('echo "error: the server doesn\'t have a resource type \\"clusterinformations\\"" >&2; exit 1'),
    )
    assert _reach(absent)["verdict"] == "denied"


def test_through_kubectl_the_error_line_survives_a_long_discovery_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """kubectl prints a memcache warning per failed aggregated API before its own error. The message kept the
    first 800 characters, so on a cluster whose metrics API was down the "doesn't have a resource type" line was
    cut off -- and a genuine absence could no longer be recognised."""
    warning = METRICS_DOWN.strip()
    noisy = "; ".join(f"echo '{warning}' >&2" for _ in range(6))
    script = _kubectl_script(
        noisy + '; echo "error: the server doesn\'t have a resource type \\"clusterinformations\\"" >&2; exit 1'
    )
    backend = _stub_kubectl(tmp_path, monkeypatch, script)
    assert _reach(backend)["verdict"] == "denied"


# --------------------------------------------------------------------------------------- the other live readers


def test_cluster_info_does_not_call_an_unreadable_cluster_kubernetes() -> None:
    from kube_noob.debug.cluster import cluster_info

    class Backend:
        name = "fake"

        def __init__(self, failure: str) -> None:
            self.failure = failure

        def version(self) -> dict[str, Any]:
            return {"serverVersion": {"major": "1", "minor": "31", "gitVersion": "v1.31.4"}}

        def get(self, resource: str, **_: Any) -> dict[str, Any]:
            raise ClusterAccessError(self.failure)

    forbidden = cluster_info(
        Backend('Error from server (Forbidden): clusterversions.config.openshift.io "version" is forbidden')
    )
    assert forbidden["platform"] is None and forbidden["openshift"] is None
    assert "could not be read" in forbidden["platformNotRead"]
    absent = cluster_info(Backend('error: the server doesn\'t have a resource type "clusterversions"'))
    assert absent["platform"] == "kubernetes" and "platformNotRead" not in absent


def test_a_watch_snapshot_without_an_items_list_is_an_error_not_an_empty_namespace() -> None:
    from kube_noob.config import load_settings
    from kube_noob.watch import RESOURCES, Watcher

    class Backend:
        name = "fake"

        def get(self, resource: str, **_: Any) -> dict[str, Any]:
            return {"kind": "List"}

    snap, errors = Watcher(load_settings(), Backend(), ["shop"]).snapshot("shop")
    assert all(v == [] for v in snap.values())
    assert len(errors) == len(RESOURCES) and all("no items list" in e for e in errors)


def test_drift_and_attack_paths_name_a_response_without_items_as_not_read() -> None:
    from kube_noob import attack_paths, drift

    class Backend:
        name = "fake"

        def get(self, resource: str, **_: Any) -> dict[str, Any]:
            return {"kind": "List"}

    objects, not_read = drift.collect_live(Backend(), ["shop"])
    assert objects == [] and not_read and all("no items list" in n for n in not_read)
    inv = attack_paths.collect_live(Backend(), ["shop"])
    assert inv.not_read and all("no items list" in n for n in inv.not_read)


def test_the_admission_lookups_record_a_response_without_items_as_a_failed_read() -> None:
    from kube_noob.admission import Lookups

    class Backend:
        name = "fake"

        def get(self, resource: str, **_: Any) -> dict[str, Any]:
            return {"kind": "List"}

    ctx = Lookups(Backend(), sleep=lambda _s: None)
    ctx("shop")
    ctx.refresh()
    assert ctx.errors and all("ClusterAccessError" in e for e in ctx.errors), ctx.errors


def test_a_diagnosis_does_not_read_a_missing_event_list_as_no_events() -> None:
    from kube_noob.debug.diagnose import collect_evidence

    class Backend:
        name = "fake"

        def get(self, resource: str, name: str | None = None, **_: Any) -> dict[str, Any]:
            if resource == "pods" and name:
                return {"kind": "Pod", "metadata": {"name": name}, "status": {}}
            return {"kind": "EventList"}

        def logs(self, *_: Any) -> str:
            return ""

    with pytest.raises(ClusterAccessError, match="no items list"):
        collect_evidence(Backend(), "shop", "pod", "web")


def test_the_unread_cni_reason_reaches_the_text_view_the_json_and_the_mcp_result(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """G221: a not-determined reason that only one surface carries is a caveat nobody reads."""
    from kube_noob.cli import main
    from kube_noob.config import load_settings
    from kube_noob.toolkit import Toolkit, TrafficIn

    cluster = Cluster([*WORKLOADS, ALLOW_ALL, ANP], errors={"clusterinformations": AUTH_PLUGIN})
    monkeypatch.setattr("kube_noob.toolkit.get_backend", lambda _settings: cluster)
    kit = Toolkit(load_settings(overrides={"cluster": {"enabled": True}}))
    mcp = kit.cluster_check_traffic(TrafficIn(source="monitoring/prometheus", destination="shop/orders", port=8080))
    assert mcp["verdict"] == "undetermined" and "CNI could not be read" in mcp["summary"]
    argv = ["--cluster-enabled", "policy", "reach", "--from", "monitoring/prometheus", "--to", "shop/orders"]
    argv += ["--port", "8080", "--live"]
    rc_text = main(argv)
    text = capsys.readouterr().out
    assert text.startswith("UNDETERMINED") and "CNI could not be read" in text and "gke-gcloud-auth-plugin" in text
    rc_json = main([*argv, "--format", "json"])
    out = json.loads(capsys.readouterr().out)
    assert rc_text == rc_json and out["verdict"] == "undetermined"
    assert out["undeterminedBy"] == ["AdminNetworkPolicy/guardrail"] and "CNI could not be read" in out["summary"]
