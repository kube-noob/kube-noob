"""G279 under an adversarial review: eleven more ways a live read that did not happen still produced a verdict.

Five of them were a wrong ALLOWED with exit 0 from `policy reach --live` -- the worst output this product can give,
because a CI gate reads the exit code and never the note beneath it. The rule every test here holds: where anything
a selector or a tier needs was not read, the verdict is `undetermined`, and the reason names what was not read.
"""

from __future__ import annotations

import copy
import io
import json
import os
import stat
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any

import pytest

from kube_noob.debug.cluster import classify_read_failure, list_items
from kube_noob.debug.netpol import check_reachability, inventory_from_cluster
from kube_noob.errors import ClusterAccessError

# ------------------------------------------------------------------------------------------------- the cluster stub


def _dep(name: str, ns: str, app: str, port: int | None = None) -> dict[str, Any]:
    c: dict[str, Any] = {"name": "c", "image": f"{app}:1"}
    if port:
        c["ports"] = [{"containerPort": port}]
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": name, "namespace": ns},
        "spec": {"template": {"metadata": {"labels": {"app": app}}, "spec": {"containers": [c]}}},
    }


NS = [
    {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "shop", "labels": {"tier": "app"}}},
    {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "monitoring", "labels": {"tier": "platform"}}},
]
WL = [_dep("orders", "shop", "orders", 8080), _dep("prometheus", "monitoring", "prometheus")]
ALLOW_ALL = {
    "apiVersion": "networking.k8s.io/v1",
    "kind": "NetworkPolicy",
    "metadata": {"name": "allow", "namespace": "shop"},
    "spec": {"podSelector": {"matchLabels": {"app": "orders"}}, "policyTypes": ["Ingress"], "ingress": [{}]},
}
ANP_DENY = {
    "apiVersion": "policy.networking.k8s.io/v1alpha1",
    "kind": "AdminNetworkPolicy",
    "metadata": {"name": "guardrail"},
    "spec": {
        "priority": 10,
        "subject": {"namespaces": {"matchLabels": {"tier": "app"}}},
        "ingress": [{"name": "deny-all", "action": "Deny", "from": [{"namespaces": {}}]}],
    },
}
ANP_ALLOW = {
    "apiVersion": "policy.networking.k8s.io/v1alpha1",
    "kind": "AdminNetworkPolicy",
    "metadata": {"name": "let-in"},
    "spec": {
        "priority": 10,
        "subject": {"namespaces": {}},
        "ingress": [{"name": "a", "action": "Allow", "from": [{"namespaces": {}}]}],
    },
}
CNP_BASE_DENY = {
    "apiVersion": "policy.networking.k8s.io/v1alpha2",
    "kind": "ClusterNetworkPolicy",
    "metadata": {"name": "base-deny"},
    "spec": {
        "tier": "Baseline",
        "priority": 5,
        "subject": {"namespaces": {}},
        "ingress": [{"name": "d", "action": "Deny", "from": [{"namespaces": {}}]}],
    },
}
CNP_ADMIN_ACCEPT = {
    "apiVersion": "policy.networking.k8s.io/v1alpha2",
    "kind": "ClusterNetworkPolicy",
    "metadata": {"name": "adm-allow"},
    "spec": {
        "tier": "Admin",
        "priority": 5,
        "subject": {"namespaces": {}},
        "ingress": [{"name": "a", "action": "Accept", "from": [{"namespaces": {}}]}],
    },
}
CALICO_INFO = {
    "apiVersion": "crd.projectcalico.org/v1",
    "kind": "ClusterInformation",
    "metadata": {"name": "default"},
    "spec": {"calicoVersion": "v3.31.0", "variant": "Calico"},
}
KINDS = {
    "networkpolicies": "NetworkPolicy",
    "namespaces": "Namespace",
    "deployments": "Deployment",
    "statefulsets": "StatefulSet",
    "daemonsets": "DaemonSet",
    "pods": "Pod",
}
QUALIFIED = {"deployments": "deployments.apps", "statefulsets": "statefulsets.apps", "daemonsets": "daemonsets.apps"}
FORBIDDEN = 'kubectl get R failed: Error from server (Forbidden): R is forbidden: User "u" cannot list resource'
TIMEOUT = "kubectl timed out after 30.0s"


def _not_served(resource: str) -> str:
    return f'kubectl get {resource} failed: error: the server doesn\'t have a resource type "{resource}"'


class Cluster:
    """`behave` maps a resource, or (resource, name-or-namespace), to an error string, an exception, or a body."""

    name = "fake"

    def __init__(
        self,
        objects: list[dict[str, Any]],
        behave: dict[Any, Any] | None = None,
        lists: dict[str, list[Any]] | None = None,
    ) -> None:
        self.objects, self.behave, self.lists = objects, behave or {}, lists or {}

    def version(self) -> dict[str, Any]:
        return {"serverVersion": {"major": "1", "minor": "31", "gitVersion": "v1.31.4"}}

    def get(self, resource: str, name: str | None = None, namespace: str | None = None, **_: Any) -> dict[str, Any]:
        b = None
        for key in ((resource, name), (resource, namespace), resource):
            if key in self.behave:
                b = self.behave[key]
                break
        if isinstance(b, BaseException):
            raise b
        if isinstance(b, str):
            raise ClusterAccessError(b)
        if b is not None:
            return copy.deepcopy(b)  # type: ignore[no-any-return]
        if resource in self.lists and name is None:
            return {"items": copy.deepcopy(self.lists[resource])}
        kind = KINDS.get(resource)
        if kind is None:
            raise ClusterAccessError(_not_served(resource))
        hits = [
            o
            for o in self.objects
            if o["kind"] == kind
            and (name is None or o["metadata"]["name"] == name)
            and (kind == "Namespace" or namespace is None or o["metadata"].get("namespace") == namespace)
        ]
        if name is not None:
            if not hits:
                q = QUALIFIED.get(resource, resource)
                raise ClusterAccessError(f'Error from server (NotFound): {q} "{name}" not found')
            return copy.deepcopy(hits[0])
        return {"items": copy.deepcopy(hits)}


def _reach(cluster: Any, src: str = "monitoring/prometheus", dst: str = "shop/orders") -> dict[str, Any]:
    return check_reachability(inventory_from_cluster(cluster, src, dst), src, dst, 8080)


def _cli(cluster: Any, monkeypatch: pytest.MonkeyPatch, *extra: str) -> tuple[int, str]:
    from kube_noob.cli import main

    monkeypatch.setattr("kube_noob.toolkit.get_backend", lambda _s: cluster)
    out, err = io.StringIO(), io.StringIO()
    argv = ["--cluster-enabled", "policy", "reach", "--from", "monitoring/prometheus", "--to", "shop/orders"]
    with redirect_stdout(out), redirect_stderr(err):
        rc = main([*argv, "--port", "8080", "--live", *extra])
    return rc, out.getvalue() + err.getvalue()


# ------------------------------------------------------------------- 1: namespace labels a selector needed, unread

NS_FAILURES = [
    pytest.param(FORBIDDEN.replace("R", "namespaces"), id="forbidden"),
    pytest.param(TIMEOUT, id="timeout"),
    pytest.param({}, id="empty-body"),
    pytest.param({"kind": "Status", "apiVersion": "v1", "status": "Failure", "code": 403}, id="status-body"),
    pytest.param({"kind": "Namespace", "metadata": {"name": "elsewhere"}}, id="another-namespace"),
    pytest.param(json.JSONDecodeError("Expecting value", "<html>", 0), id="not-json"),
]


@pytest.mark.parametrize("failure", NS_FAILURES)
def test_an_admin_policy_whose_subject_needs_unread_namespace_labels_is_not_an_allow(failure: Any) -> None:
    """Stub A: the AdminNetworkPolicy selects namespaces labelled tier=app and denies. With the labels unread
    the subject matched nothing, and the NetworkPolicy allow was reported as ALLOWED with exit 0."""
    out = _reach(Cluster([*NS, *WL, ALLOW_ALL], {"namespaces": failure}, {"adminnetworkpolicies": [ANP_DENY]}))
    assert out["verdict"] == "undetermined", out
    assert any("namespace" in ref and "labels" in ref for ref in out["undeterminedBy"]), out["undeterminedBy"]


@pytest.mark.parametrize("failure", NS_FAILURES)
def test_a_namespace_selector_on_unread_labels_is_not_an_allow(failure: Any) -> None:
    """Stub B: allow only from namespaces WITHOUT restricted; the source namespace has restricted=true."""
    ns = copy.deepcopy(NS)
    ns[1]["metadata"]["labels"]["restricted"] = "true"
    pol = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": "unrestricted-only", "namespace": "shop"},
        "spec": {
            "podSelector": {},
            "policyTypes": ["Ingress"],
            "ingress": [
                {
                    "from": [
                        {"namespaceSelector": {"matchExpressions": [{"key": "restricted", "operator": "DoesNotExist"}]}}
                    ]
                }
            ],
        },
    }
    assert _reach(Cluster([*ns, *WL, pol]))["verdict"] == "denied"  # the truth, when the labels are read
    out = _reach(Cluster([*ns, *WL, pol], {"namespaces": failure}))
    assert out["verdict"] == "undetermined", out


def test_unread_namespace_labels_do_not_withhold_an_answer_no_selector_reads() -> None:
    """Only a selector that reads labels needs them: a podSelector-only answer stays an answer, with the note."""
    out = _reach(Cluster([*NS, *WL, ALLOW_ALL], {"namespaces": FORBIDDEN.replace("R", "namespaces")}))
    assert out["verdict"] == "allowed", out
    assert any("could not read namespace" in n for n in out["notes"]), out["notes"]


def test_unread_namespace_labels_are_not_needed_for_the_name_label() -> None:
    """kubernetes.io/metadata.name is the namespace's name, so a selector on it alone needs no read."""
    pol = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": "from-monitoring", "namespace": "shop"},
        "spec": {
            "podSelector": {},
            "policyTypes": ["Ingress"],
            "ingress": [
                {"from": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "monitoring"}}}]}
            ],
        },
    }
    out = _reach(Cluster([*NS, *WL, pol], {"namespaces": TIMEOUT}))
    assert out["verdict"] == "allowed", out


# --------------------------------------------------------------- 2: the discovery warning that the cut threw away


def _stub_kubectl(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, overrides: dict[str, str]) -> Any:
    from kube_noob.debug.backends import KubectlBackend

    lists = {
        "networkpolicies.networking.k8s.io": {"kind": "List", "items": [ALLOW_ALL]},
        "adminnetworkpolicies.policy.networking.k8s.io": {"kind": "List", "items": [ANP_DENY]},
        "baselineadminnetworkpolicies.policy.networking.k8s.io": {"kind": "List", "items": []},
    }
    cases = [f"  {res})\n    {body};;\n" for res, body in overrides.items()]
    cases += [
        f"  {res})\n    echo '{json.dumps(body)}'; exit 0;;\n" for res, body in lists.items() if res not in overrides
    ]
    cases.append('  deployments.apps)\n    case "$3" in\n')
    cases += [f"      {d['metadata']['name']}) echo '{json.dumps(d)}'; exit 0;;\n" for d in WL]
    cases.append("    esac;;\n")
    cases.append('  namespaces)\n    case "$3" in\n')
    cases += [f"      {n['metadata']['name']}) echo '{json.dumps(n)}'; exit 0;;\n" for n in NS]
    cases.append("    esac;;\n")
    tail = '  *)\n    echo "error: the server doesn\'t have a resource type \\"${res%%.*}\\"" >&2; exit 1;;\n'
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    kubectl = bin_dir / "kubectl"
    kubectl.write_text('#!/bin/sh\nres="$2"\ncase "$res" in\n' + "".join(cases) + tail + "esac\n")
    kubectl.chmod(kubectl.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    return KubectlBackend("kubectl", None, 5)


def _warn(group: str) -> str:
    line = (
        f"E1112 10:00:00.000000   1 memcache.go:287] couldn't get resource list for {group}: "
        "the server is currently unable to handle the request"
    )
    return f'echo "{line}" >&2'


_SEVEN = "; ".join(_warn(f"g{i}.example.com/v1") for i in range(7))


def test_a_tiers_own_discovery_failure_after_seven_others_is_still_seen(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The deciding warning came last, past the 800 characters the message kept: "not installed", ALLOWED."""
    absent = 'echo "error: the server doesn\'t have a resource type \\"adminnetworkpolicies\\"" >&2; exit 1'
    own = _warn("policy.networking.k8s.io/v1alpha1")
    backend = _stub_kubectl(
        tmp_path, monkeypatch, {"adminnetworkpolicies.policy.networking.k8s.io": f"{_SEVEN}; {own}; {absent}"}
    )
    out = _reach(backend)
    assert out["verdict"] == "undetermined", out
    assert "AdminNetworkPolicy" in out["undeterminedBy"]
    assert not any("AdminNetworkPolicy is not installed" in n for n in out["notes"])


def test_the_cnis_own_discovery_failure_after_seven_others_is_still_seen(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    absent = 'echo "error: the server doesn\'t have a resource type \\"clusterinformations\\"" >&2; exit 1'
    backend = _stub_kubectl(
        tmp_path,
        monkeypatch,
        {"clusterinformations.crd.projectcalico.org": f"{_SEVEN}; {_warn('crd.projectcalico.org/v1')}; {absent}"},
    )
    out = _reach(backend)
    assert out["verdict"] == "undetermined", out
    assert any("CNI could not be read" in n for n in out["notes"])


def test_other_groups_failing_still_leave_a_genuine_absence_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    absent = 'echo "error: the server doesn\'t have a resource type \\"clusterinformations\\"" >&2; exit 1'
    backend = _stub_kubectl(tmp_path, monkeypatch, {"clusterinformations.crd.projectcalico.org": f"{_SEVEN}; {absent}"})
    assert _reach(backend)["verdict"] == "denied"


def test_the_full_stderr_is_redacted_where_it_is_kept(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    leak = 'echo "error: bad --token=abcdef1234567890 Authorization: Bearer eyJhbGciOi.xxx.yyy" >&2; exit 1'
    backend = _stub_kubectl(tmp_path, monkeypatch, {"adminnetworkpolicies.policy.networking.k8s.io": leak})
    with pytest.raises(ClusterAccessError) as exc:
        backend.get("adminnetworkpolicies")
    kept = str(exc.value) + str(getattr(exc.value, "stderr", ""))
    assert "abcdef1234567890" not in kept and "eyJhbGciOi.xxx.yyy" not in kept


# -------------------------------------------------------------- 3: every enforcement reading a CNI could have


@pytest.mark.parametrize(
    ("lists", "netpols"),
    [
        # Calico 3.32 ignores the AdminNetworkPolicy and enforces the ClusterNetworkPolicy: denied there
        pytest.param(
            {"adminnetworkpolicies": [ANP_ALLOW], "clusternetworkpolicies": [CNP_BASE_DENY]},
            [],
            id="anp-allow-cnp-deny",
        ),
        # OVN-Kubernetes enforces the AdminNetworkPolicy and not the v1alpha2 kind: denied there
        pytest.param(
            {"adminnetworkpolicies": [ANP_DENY], "clusternetworkpolicies": [CNP_ADMIN_ACCEPT]}, [ALLOW_ALL], id="mirror"
        ),
    ],
)
def test_an_unread_cni_compares_every_enforcement_reading_not_only_all_and_none(
    lists: dict[str, list[Any]], netpols: list[Any]
) -> None:
    out = _reach(
        Cluster([*NS, *WL, *netpols], {"clusterinformations": FORBIDDEN.replace("R", "clusterinformations")}, lists)
    )
    assert out["verdict"] == "undetermined", out
    assert not any("Both readings" in n for n in out["notes"]), out["notes"]


def test_readings_that_all_agree_still_answer() -> None:
    lists = {"adminnetworkpolicies": [ANP_ALLOW], "clusternetworkpolicies": [CNP_ADMIN_ACCEPT]}
    out = _reach(Cluster([*NS, *WL, ALLOW_ALL], {"clusterinformations": TIMEOUT}, lists))
    assert out["verdict"] == "allowed", out
    assert any("every reading" in n.lower() for n in out["notes"]), out["notes"]


# ---------------------------------------------------------------- 4: the object asked about is the one answered


POD_ORDERS = {
    "apiVersion": "v1",
    "kind": "Pod",
    "metadata": {"name": "orders", "namespace": "shop", "labels": {"app": "something-else"}},
    "spec": {"containers": [{"name": "c", "image": "o:1", "ports": [{"containerPort": 8080}]}]},
}
DENY_ORDERS = {
    "apiVersion": "networking.k8s.io/v1",
    "kind": "NetworkPolicy",
    "metadata": {"name": "deny-orders", "namespace": "shop"},
    "spec": {"podSelector": {"matchLabels": {"app": "orders"}}, "policyTypes": ["Ingress"]},
}


@pytest.mark.parametrize(
    "failure",
    [
        pytest.param(TIMEOUT, id="timeout"),
        pytest.param(FORBIDDEN.replace("R", "deployments"), id="forbidden"),
        pytest.param({}, id="empty-body"),
        pytest.param({"kind": "Status", "code": 404}, id="status-body"),
        pytest.param(json.JSONDecodeError("Expecting value", "x", 0), id="not-json"),
    ],
)
def test_a_higher_ranked_kind_that_could_not_be_read_does_not_hand_the_answer_to_another_kind(failure: Any) -> None:
    """The Deployment shop/orders is isolated; a stray Pod of the same name is not. With Deployments unreadable
    the answer used to be ALLOWED about shop/pod/orders, exit 0."""
    with pytest.raises(ClusterAccessError, match="deployments"):
        inventory_from_cluster(
            Cluster([*NS, *WL, DENY_ORDERS, POD_ORDERS], {("deployments", "orders"): failure}),
            "monitoring/prometheus",
            "shop/orders",
        )


def test_a_kind_named_explicitly_is_read_and_answered_whatever_another_kind_does() -> None:
    cluster = Cluster([*NS, *WL, DENY_ORDERS, POD_ORDERS], {("deployments", "orders"): TIMEOUT})
    out = _reach(cluster, dst="shop/pod/orders")
    assert out["verdict"] == "allowed" and out["destination"] == "shop/pod/orders"


# ------------------------------------------------------------------ 5: a list of things that are not objects


@pytest.mark.parametrize("items", [[None, "x"], [1], [[]], [ALLOW_ALL, None]])
def test_items_that_are_not_objects_make_the_read_failed(items: list[Any]) -> None:
    with pytest.raises(ClusterAccessError, match="not objects"):
        list_items({"items": items}, "networkpolicies")


@pytest.mark.parametrize("resource", ["networkpolicies", "adminnetworkpolicies", "clusternetworkpolicies"])
def test_a_policy_read_holding_non_objects_is_not_zero_policies(resource: str) -> None:
    out = _reach(Cluster([*NS, *WL, ALLOW_ALL], {resource: {"items": [None, "x"]}}))
    assert out["verdict"] == "undetermined", out


def test_a_cni_read_holding_non_objects_is_not_a_cluster_without_calico() -> None:
    out = _reach(
        Cluster(
            [*NS, *WL, ALLOW_ALL], {"clusterinformations": {"items": [None, "x"]}}, {"adminnetworkpolicies": [ANP_DENY]}
        )
    )
    assert out["verdict"] == "undetermined", out
    assert any("CNI could not be read" in n for n in out["notes"]), out["notes"]


def test_the_other_live_readers_treat_non_objects_as_a_failed_read() -> None:
    from kube_noob import attack_paths, drift
    from kube_noob.config import load_settings
    from kube_noob.watch import Watcher

    class Backend:
        name = "fake"

        def get(self, resource: str, **_: Any) -> dict[str, Any]:
            return {"items": [None, "x"]}

    _objects, not_read = drift.collect_live(Backend(), ["shop"])
    assert not_read and all("not objects" in n for n in not_read)
    assert all("not objects" in n for n in attack_paths.collect_live(Backend(), ["shop"]).not_read)
    _snap, errors = Watcher(load_settings(), Backend(), ["shop"]).snapshot("shop")
    assert errors and all("not objects" in e for e in errors)


# ------------------------------------------------------------- 6: Calico installed, version unknown, is unknown


@pytest.mark.parametrize(
    "info",
    [
        pytest.param([], id="served-but-empty"),
        pytest.param([{**CALICO_INFO, "spec": {"variant": "Calico"}}], id="no-version"),
        pytest.param([{**CALICO_INFO, "spec": {"calicoVersion": "not-a-version"}}], id="unparsable"),
        pytest.param(
            [{**CALICO_INFO, "spec": {"calicoVersion": "v3.32.1", "variant": "TigeraSecureEnterprise"}}],
            id="other-variant",
        ),
    ],
)
def test_calico_of_an_unknown_version_withholds_an_answer_the_admin_tier_decides(info: list[Any]) -> None:
    out = _reach(
        Cluster([*NS, *WL, ALLOW_ALL], lists={"clusterinformations": info, "adminnetworkpolicies": [ANP_DENY]})
    )
    assert out["verdict"] == "undetermined", out
    assert out["undeterminedBy"] == ["AdminNetworkPolicy/guardrail"]
    assert any("calico" in n.lower() for n in out["notes"]), out["notes"]


def test_calico_with_a_version_still_decides() -> None:
    out = _reach(
        Cluster([*NS, *WL, ALLOW_ALL], lists={"clusterinformations": [CALICO_INFO], "adminnetworkpolicies": [ANP_DENY]})
    )
    assert out["verdict"] == "denied", out


# ------------------------------------------------------------------- 7: patterns anchored to the backend's text


@pytest.mark.parametrize(
    ("resource", "message", "name", "expected"),
    [
        # a workload literally named "forbidden": the echoed argv must not decide
        (
            "deployments",
            (
                "kubectl get deployments.apps forbidden failed: Error from server (NotFound): deployments.apps "
                '"forbidden" not found'
            ),
            "forbidden",
            "not-found",
        ),
        (
            "deployments",
            (
                "kubectl get deployments.apps my-forbidden-app failed: Error from server (NotFound): "
                'deployments.apps "my-forbidden-app" not found'
            ),
            "my-forbidden-app",
            "not-found",
        ),
        # the in-cluster path echoes the namespace
        ("deployments", "Not found: GET /apis/apps/v1/namespaces/forbidden-zone/deployments/web", "web", "not-found"),
        # a 500 body that happens to hold kubectl's words is a server error, not an absence
        (
            "adminnetworkpolicies",
            (
                "API error 500 for GET /apis/policy.networking.k8s.io/v1alpha1/adminnetworkpolicies: error: the "
                'server doesn\'t have a resource type "adminnetworkpolicies"'
            ),
            None,
            "not-read",
        ),
        (
            "adminnetworkpolicies",
            (
                "kubectl get adminnetworkpolicies.policy.networking.k8s.io failed: Error from server (Forbidden): "
                'adminnetworkpolicies.policy.networking.k8s.io is forbidden: User "u" cannot list'
            ),
            None,
            "forbidden",
        ),
        (
            "adminnetworkpolicies",
            (
                "kubectl get adminnetworkpolicies.policy.networking.k8s.io failed: error: the server doesn't have a "
                'resource type "adminnetworkpolicies"'
            ),
            None,
            "not-served",
        ),
        (
            "adminnetworkpolicies",
            (
                "kubectl get adminnetworkpolicies.policy.networking.k8s.io failed: warning: the server doesn\\'t have "
                'a resource type "adminnetworkpolicies" was printed by a plugin'
            ),
            None,
            "not-read",
        ),
    ],
)
def test_the_classifier_reads_the_backends_own_line_and_never_an_echoed_name(
    resource: str, message: str, name: str | None, expected: str
) -> None:
    assert classify_read_failure(resource, message, name=name) == expected


def test_the_in_cluster_backend_carries_the_http_status() -> None:
    from kube_noob.debug.backends import InClusterReadError

    for status, body, name, expected in [
        (404, "404 page not found", None, "not-served"),
        (404, "404 page not found", "version", "not-served"),
        (
            404,
            json.dumps({"kind": "Status", "reason": "NotFound", "details": {"name": "version"}}),
            "version",
            "not-found",
        ),
        (403, "{}", None, "forbidden"),
        (500, 'error: the server doesn\'t have a resource type "clusterversions"', None, "not-read"),
        (401, "Unauthorized", None, "not-read"),
    ]:
        exc = InClusterReadError("GET /apis/config.openshift.io/v1/clusterversions", status=status, body=body)
        assert classify_read_failure("clusterversions", exc, name=name) == expected, (status, body, name)


# ---------------------------------------------------------- 8: groups an aggregated API server answers for


def test_no_aggregated_group_is_ever_classified_as_not_served() -> None:
    """With aggregated discovery, client-go caches a failed group-version silently and the REST mapper drops the
    partial error (client-go v1.35.0 discovery/cached/memory/memcache.go, restmapper/discovery.go), so kubectl's
    bare "doesn't have a resource type" can mean "that API server is down". No group served by an aggregated API
    server may be read as absent."""
    from kube_noob.debug.cluster import AGGREGATED_GROUPS, ALLOWED_RESOURCES

    assert {"route.openshift.io", "apps.openshift.io"} <= AGGREGATED_GROUPS
    for plural, rdef in ALLOWED_RESOURCES.items():
        group = rdef.group_version.split("/")[0] if "/" in rdef.group_version else ""
        if group in AGGREGATED_GROUPS:
            msg = f'kubectl get {plural}.{group} failed: error: the server doesn\'t have a resource type "{plural}"'
            assert classify_read_failure(plural, msg) == "not-read", plural


def test_every_resource_whose_absence_is_acted_on_is_a_crd_group() -> None:
    from kube_noob.debug.cluster import AGGREGATED_GROUPS, ALLOWED_RESOURCES

    consumed = {
        "clusterinformations",
        "clusternetworkpolicies",
        "ciliumclusterwidenetworkpolicies",
        "globalnetworkpolicies",
        "adminnetworkpolicies",
        "baselineadminnetworkpolicies",
        "clusterversions",
        "clusterserviceversions",
        "subscriptions",
    }
    for plural in consumed:
        assert ALLOWED_RESOURCES[plural].group_version.split("/")[0] not in AGGREGATED_GROUPS, plural


# ----------------------------------------------------------------------- 9: an unread platform, everywhere


CV_FORBIDDEN = (
    'Error from server (Forbidden): clusterversions.config.openshift.io "version" is forbidden: User "u" cannot get'
)


@pytest.mark.parametrize(
    "cv",
    [
        pytest.param(CV_FORBIDDEN, id="forbidden"),
        pytest.param(TIMEOUT, id="timeout"),
        pytest.param({}, id="empty-body"),
        pytest.param({"kind": "Status", "code": 403}, id="status-body"),
        pytest.param({"items": []}, id="a-list"),
        pytest.param(
            'Error from server (NotFound): clusterversions.config.openshift.io "version" not found', id="object-missing"
        ),
        pytest.param(json.JSONDecodeError("Expecting value", "x", 0), id="not-json"),
    ],
)
def test_a_cluster_version_that_was_not_read_is_not_kubernetes(cv: Any) -> None:
    from kube_noob.debug.cluster import cluster_info

    info = cluster_info(Cluster([], {"clusterversions": cv}))
    assert info["platform"] is None and info["openshift"] is None
    assert "could not be read" in info["platformNotRead"]


def test_an_unserved_cluster_version_is_kubernetes() -> None:
    from kube_noob.debug.cluster import cluster_info

    info = cluster_info(Cluster([], {"clusterversions": _not_served("clusterversions")}))
    assert info["platform"] == "kubernetes" and "platformNotRead" not in info


def test_debug_and_policy_reach_carry_the_unread_platform(monkeypatch: pytest.MonkeyPatch) -> None:
    from kube_noob.config import load_settings
    from kube_noob.debug.diagnose import bundle_markdown, debug_workload
    from kube_noob.toolkit import Toolkit, TrafficIn

    pod = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "web", "namespace": "shop"},
        "spec": {"containers": [{"name": "c", "image": "x"}]},
        "status": {"phase": "Running"},
    }

    class Backend(Cluster):
        def logs(self, *_: Any) -> str:
            return ""

    cluster = Backend([*NS, *WL, ALLOW_ALL, pod], {"clusterversions": CV_FORBIDDEN}, {"events": []})
    result = debug_workload(cluster, "shop", "pod", "web")
    assert "could not be read" in result["cluster"]["platformNotRead"]
    assert "ClusterVersion could not be read" in bundle_markdown(result)
    monkeypatch.setattr("kube_noob.toolkit.get_backend", lambda _s: cluster)
    kit = Toolkit(load_settings(overrides={"cluster": {"enabled": True}}))
    out = kit.cluster_check_traffic(TrafficIn(source="monitoring/prometheus", destination="shop/orders", port=8080))
    assert any("ClusterVersion could not be read" in n for n in out["notes"]), out.get("notes")


# ------------------------------------------------------------------- 10: admission lookups keep what they had


def test_a_failed_admission_refresh_keeps_the_last_good_objects_and_marks_them_stale() -> None:
    from kube_noob.admission import CONTEXT_RESOURCES, Lookups

    class Backend:
        name = "fake"
        bad = False

        def get(self, resource: str, namespace: str | None = None, **_: Any) -> dict[str, Any]:
            if self.bad and resource != "storageclasses":
                return {"kind": "List"}
            return {"items": [{"metadata": {"name": f"{resource}-1", "namespace": namespace}}]}

    b = Backend()
    lookups = Lookups(b, sleep=lambda _s: None)
    lookups("shop")
    lookups.refresh()
    good = sorted(o["kind"] for o in lookups("shop"))
    assert len(good) == len(CONTEXT_RESOURCES) + 1
    b.bad = True
    lookups.refresh()
    assert sorted(o["kind"] for o in lookups("shop")) == good
    assert set(lookups.stale("shop")) == set(CONTEXT_RESOURCES)


# -------------------------------------------------------------- 11: a body that is not JSON, bytes not UTF-8


def test_a_backend_answer_that_is_not_json_is_a_failed_read_naming_the_resource(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = _stub_kubectl(
        tmp_path, monkeypatch, {"adminnetworkpolicies.policy.networking.k8s.io": "echo '<html>502</html>'; exit 0"}
    )
    with pytest.raises(ClusterAccessError, match="adminnetworkpolicies"):
        backend.get("adminnetworkpolicies")
    out = _reach(backend)
    assert out["verdict"] == "undetermined" and "AdminNetworkPolicy" in out["undeterminedBy"]


@pytest.mark.parametrize(
    "script",
    [
        "printf 'error: \\377\\376 bad\\n' >&2; exit 1",
        'printf \'{"items": [], "x": "\\377"}\'; exit 0',
    ],
)
def test_bytes_that_are_not_utf8_are_a_failed_read_not_a_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, script: str
) -> None:
    backend = _stub_kubectl(tmp_path, monkeypatch, {"adminnetworkpolicies.policy.networking.k8s.io": script})
    # a failed read naming the resource is the right answer; a UnicodeDecodeError, or an answer read from bytes
    # that are not UTF-8, is not
    with pytest.raises(ClusterAccessError, match="adminnetworkpolicies"):
        backend.get("adminnetworkpolicies")


def test_a_stub_backend_raising_a_decode_error_reaches_the_cli_as_undetermined(monkeypatch: pytest.MonkeyPatch) -> None:
    cluster = Cluster([*NS, *WL, ALLOW_ALL], {"adminnetworkpolicies": json.JSONDecodeError("Expecting value", "<", 0)})
    rc, text = _cli(cluster, monkeypatch)
    assert rc == 1 and text.startswith("UNDETERMINED") and "AdminNetworkPolicy" in text


# -------------------------------------------------- a NetworkPolicy read that fails outright: one more namespace


@pytest.mark.parametrize("failure", [FORBIDDEN.replace("R", "networkpolicies"), TIMEOUT])
def test_a_networkpolicy_read_that_failed_is_undetermined_naming_the_namespace(
    failure: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Before: exit 4 and a bare error, while a missing `items` was `undetermined` exit 1. A namespace-scoped
    token reads one namespace and not the other; naming the one it could not read is the useful answer."""
    cluster = Cluster([*NS, *WL, ALLOW_ALL], {("networkpolicies", "monitoring"): failure})
    out = _reach(cluster)
    assert out["verdict"] == "undetermined", out
    assert "NetworkPolicy in namespace monitoring" in out["undeterminedBy"]
    rc, text = _cli(cluster, monkeypatch, "--format", "json")
    assert rc == 1 and json.loads(text)["verdict"] == "undetermined"


def test_a_plain_cluster_with_every_crd_absent_is_still_allowed() -> None:
    assert _reach(Cluster([*NS, *WL, ALLOW_ALL]))["verdict"] == "allowed"
