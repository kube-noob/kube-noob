"""POL2 (R3.2): attack paths from an exposure to what a compromised pod could do; read-only, never Secrets."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from kube_noob import attack_paths as ap
from kube_noob import toolkit as tk
from kube_noob.cli import main
from kube_noob.config import load_settings
from kube_noob.debug.cluster import resolve_resource
from kube_noob.errors import ClusterAccessError

SEEDED = Path(__file__).parent / "fixtures" / "posture" / "seeded.yaml"
PLANTED = (
    "internet -> Route/shop/web -> Service/shop/web -> Deployment/shop/web -> ServiceAccount/shop/web-sa -> "
    "read Secrets (credentials, tokens of other ServiceAccounts) (shop)"
)


def _scan(docs: list[dict[str, Any]], top: int = 20) -> dict[str, Any]:
    return ap.scan(ap.Inventory.from_documents(docs), top=top)


def _exposed(name: str, ns: str = "shop", **pod: Any) -> list[dict[str, Any]]:
    """A Route -> Service -> Deployment chain whose pod spec carries ``pod``."""
    spec = {"containers": [{"name": name, "image": "registry.example.com/x:1"}], **pod}
    return [
        {
            "apiVersion": "route.openshift.io/v1",
            "kind": "Route",
            "metadata": {"name": name, "namespace": ns},
            "spec": {"to": {"kind": "Service", "name": name}},
        },
        {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": name, "namespace": ns},
            "spec": {"selector": {"app": name}, "ports": [{"port": 80}]},
        },
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": name, "namespace": ns},
            "spec": {
                "selector": {"matchLabels": {"app": name}},
                "template": {"metadata": {"labels": {"app": name}}, "spec": spec},
            },
        },
    ]


def _role(kind: str, name: str, rules: list[dict[str, Any]], ns: str = "shop") -> dict[str, Any]:
    meta: dict[str, Any] = {"name": name}
    if kind == "Role":
        meta["namespace"] = ns
    return {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": kind, "metadata": meta, "rules": rules}


def _binding(
    kind: str, name: str, role_kind: str, role: str, subjects: list[dict[str, Any]], ns: str = "shop"
) -> dict[str, Any]:
    meta: dict[str, Any] = {"name": name}
    if kind == "RoleBinding":
        meta["namespace"] = ns
    return {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": kind,
        "metadata": meta,
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": role_kind, "name": role},
        "subjects": subjects,
    }


SA = {"kind": "ServiceAccount", "name": "app-sa", "namespace": "shop"}


# --- R3.2 acceptance on the seeded bundle (the same objects CI applies to kind) -----------------------------------


def test_the_planted_path_ranks_first_and_decoys_rank_lower_or_not_at_all() -> None:
    out = ap.scan_manifests(SEEDED.read_text(encoding="utf-8"))
    first = out["paths"][0]
    assert first["summary"] == PLANTED
    assert first["score"] == 18 and first["exposure"]["weight"] == 3 and first["blastRadius"]["weight"] == 6
    assert [s["edge"] for s in first["steps"]] == [
        "exposed by",
        "routes to",
        "selects",
        "uses token of",
        "is allowed to",
    ]
    assert "RoleBinding/shop/web-secrets" in first["steps"][-1]["evidence"]
    assert "Role/shop/secret-reader rules[0]" in first["fix"][0]
    scores = [p["score"] for p in out["paths"]]
    assert scores == sorted(scores, reverse=True) and scores[1] < 18
    summaries = " ".join(p["summary"] for p in out["paths"])
    assert "Deployment/shop/api" not in summaries, "automountServiceAccountToken: false breaks the token step"
    assert "batch" not in summaries, "an unexposed cluster-admin is not an attack path from an exposure"
    assert "Deployment/shop/docs" not in summaries, "view grants nothing an attacker can use"
    assert out["total"] == 5 and out["entries"] == 5
    assert out["secretsIgnored"] == 1
    assert "hunter2" not in json.dumps(out)


# --- what a pod can do -------------------------------------------------------------------------------------------


def test_node_access_scores_by_what_the_host_gives() -> None:
    docs = _exposed(
        "agent",
        automountServiceAccountToken=False,
        hostPID=True,
        volumes=[
            {"name": "sock", "hostPath": {"path": "/var/run/containerd/containerd.sock"}},
            {"name": "logs", "hostPath": {"path": "/var/log/app"}},
        ],
    )
    docs[2]["spec"]["template"]["spec"]["containers"][0]["securityContext"] = {
        "privileged": True,
        "capabilities": {"add": ["CAP_SYS_ADMIN"]},
    }
    out = _scan(docs)
    got = {(p["blastRadius"]["capability"], p["score"]) for p in out["paths"]}
    assert ("privileged container: full access to the node", 27) in got
    assert ("host path /var/run/containerd/containerd.sock: node takeover", 27) in got
    assert ("host path /var/log/app", 21) in got
    assert ("host namespace hostPID", 24) in got
    assert ("near-root capabilities ['SYS_ADMIN']", 21) in got
    assert all(p["steps"][-1]["to"] == "node" for p in out["paths"])


def test_rbac_capabilities_and_their_scope() -> None:
    docs = _exposed("app", serviceAccountName="app-sa") + [
        _role("ClusterRole", "reader", [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["list"]}]),
        _binding("ClusterRoleBinding", "reader", "ClusterRole", "reader", [SA]),
        _role(
            "Role", "esc", [{"apiGroups": ["rbac.authorization.k8s.io"], "resources": ["roles"], "verbs": ["escalate"]}]
        ),
        _binding("RoleBinding", "esc", "Role", "esc", [SA]),
        _role("ClusterRole", "proxy", [{"apiGroups": [""], "resources": ["nodes/proxy"], "verbs": ["get"]}]),
        _binding("ClusterRoleBinding", "proxy", "ClusterRole", "proxy", [SA]),
        _role(
            "Role",
            "named",
            [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"], "resourceNames": ["tls"]}],
            ns="other",
        ),
        _binding("RoleBinding", "named", "Role", "named", [SA], ns="other"),
    ]
    out = _scan(docs)
    caps = {(p["blastRadius"]["capability"], p["blastRadius"]["scope"]): p["score"] for p in out["paths"]}
    assert caps[("read Secrets (credentials, tokens of other ServiceAccounts)", "cluster")] == 24
    assert caps[("escalate, bind or impersonate", "namespace shop")] == 18
    assert caps[("kubelet API through nodes/proxy", "cluster")] == 24
    assert (
        caps[("read Secrets (credentials, tokens of other ServiceAccounts) (named objects only)", "namespace other")]
        == 12
    )
    assert out["paths"][0]["blastRadius"]["scope"] == "cluster"


def test_cluster_admin_and_subjects_by_group_and_user() -> None:
    for subject in (
        {"kind": "Group", "name": "system:serviceaccounts:shop"},
        {"kind": "Group", "name": "system:serviceaccounts"},
        {"kind": "User", "name": "system:serviceaccount:shop:app-sa"},
        SA,
    ):
        docs = _exposed("app", serviceAccountName="app-sa") + [
            _binding("ClusterRoleBinding", "ca", "ClusterRole", "cluster-admin", [subject])
        ]
        top = _scan(docs)["paths"][0]
        assert top["blastRadius"]["capability"] == "full control" and top["score"] == 30, subject
    other = _exposed("app", serviceAccountName="app-sa") + [
        _binding(
            "ClusterRoleBinding",
            "ca",
            "ClusterRole",
            "cluster-admin",
            [{"kind": "ServiceAccount", "name": "app-sa", "namespace": "elsewhere"}],
        )
    ]
    assert _scan(other)["paths"] == []


def test_tokens_follow_pod_then_serviceaccount_automount() -> None:
    sa_off = {
        "apiVersion": "v1",
        "kind": "ServiceAccount",
        "metadata": {"name": "app-sa", "namespace": "shop"},
        "automountServiceAccountToken": False,
    }
    grant = [_binding("RoleBinding", "edit", "ClusterRole", "edit", [SA])]
    assert _scan(_exposed("app", serviceAccountName="app-sa") + [sa_off] + grant)["paths"] == []
    forced = _exposed("app", serviceAccountName="app-sa", automountServiceAccountToken=True) + [sa_off] + grant
    assert _scan(forced)["paths"], "the pod's own true wins over the ServiceAccount's false"


def test_openshift_scc_plus_create_workloads_runs_privileged_pods() -> None:
    scc = {
        "apiVersion": "security.openshift.io/v1",
        "kind": "SecurityContextConstraints",
        "metadata": {"name": "custom-priv"},
        "allowPrivilegedContainer": True,
        "users": ["system:serviceaccount:shop:app-sa"],
    }
    create = [
        _role("Role", "deployer", [{"apiGroups": ["apps"], "resources": ["deployments"], "verbs": ["create"]}]),
        _binding("RoleBinding", "deployer", "Role", "deployer", [SA]),
    ]
    out = _scan(_exposed("app", serviceAccountName="app-sa") + [scc] + create)
    top = out["paths"][0]
    assert top["blastRadius"]["capability"] == "run privileged pods (SCC custom-priv + create workloads)"
    assert top["score"] == 27
    use_only = [
        _role(
            "ClusterRole",
            "use-priv",
            [
                {
                    "apiGroups": ["security.openshift.io"],
                    "resources": ["securitycontextconstraints"],
                    "verbs": ["use"],
                    "resourceNames": ["privileged"],
                }
            ],
        ),
        _binding("RoleBinding", "use-priv", "ClusterRole", "use-priv", [SA]),
    ]
    no_create = _scan(_exposed("app", serviceAccountName="app-sa") + use_only)
    assert not any("privileged pods" in p["blastRadius"]["capability"] for p in no_create["paths"])
    both = _scan(_exposed("app", serviceAccountName="app-sa") + use_only + create)
    assert both["paths"][0]["blastRadius"]["capability"] == "run privileged pods (SCC privileged + create workloads)"


def test_aggregated_cluster_role_in_a_bundle_and_unknown_roles() -> None:
    agg = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": {"name": "agg"},
        "aggregationRule": {"clusterRoleSelectors": [{"matchLabels": {"team": "x"}}]},
        "rules": [],
    }
    part = _role("ClusterRole", "part", [{"apiGroups": [""], "resources": ["pods/exec"], "verbs": ["create"]}])
    part["metadata"]["labels"] = {"team": "x"}
    docs = _exposed("app", serviceAccountName="app-sa") + [
        agg,
        part,
        _binding("RoleBinding", "agg", "ClusterRole", "agg", [SA]),
        _binding("RoleBinding", "ghost", "ClusterRole", "ghost", [SA]),
    ]
    out = _scan(docs)
    assert out["paths"][0]["blastRadius"]["capability"] == "exec into pods"
    assert any("ClusterRole/ghost" in n for n in out["notRead"])


def test_entries_ingress_loadbalancer_nodeport_and_owned_objects() -> None:
    base = _exposed("app", hostNetwork=True, automountServiceAccountToken=False)
    _route, svc, deploy = base
    ing = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "Ingress",
        "metadata": {"name": "app", "namespace": "shop"},
        "spec": {"defaultBackend": {"service": {"name": "app", "port": {"number": 80}}}},
    }
    lb = {
        **svc,
        "metadata": {"name": "app-lb", "namespace": "shop"},
        "spec": {**svc["spec"], "type": "LoadBalancer", "loadBalancerSourceRanges": ["203.0.113.0/24"]},
    }
    np = {**svc, "metadata": {"name": "app-np", "namespace": "shop"}, "spec": {**svc["spec"], "type": "NodePort"}}
    owned_rs = {
        "apiVersion": "apps/v1",
        "kind": "ReplicaSet",
        "metadata": {
            "name": "app-1",
            "namespace": "shop",
            "ownerReferences": [{"kind": "Deployment", "name": "app", "controller": True}],
        },
        "spec": deploy["spec"],
    }
    out = _scan([svc, deploy, ing, lb, np, owned_rs])
    kinds = sorted((p["exposure"]["kind"], p["score"]) for p in out["paths"])
    assert kinds == [
        ("internet (Ingress)", 18),
        ("node network (NodePort)", 12),
        ("restricted internet (load balancer source ranges)", 12),
    ]
    assert out["workloads"] == 1


def test_ties_rank_fewer_steps_first_and_bounds() -> None:
    out = ap.scan_manifests(SEEDED.read_text(encoding="utf-8"), top=1)
    assert len(out["paths"]) == 1 and out["total"] == 5
    with pytest.raises(ap.ScanError):
        ap.scan(ap.Inventory(), top=0)
    inv = ap.Inventory()
    with pytest.MonkeyPatch.context() as m:
        m.setattr(ap, "MAX_OBJECTS", 3)
        with pytest.raises(ap.ScanError, match="more than 3"):
            for d in _exposed("a") + _exposed("b"):
                inv.add(d)


# --- live: read-only, never Secrets -------------------------------------------------------------------------------


class FakeBackend:
    name = "fake"

    def __init__(self, docs: list[dict[str, Any]], forbidden: set[str] = frozenset()) -> None:  # type: ignore[assignment]
        self.calls: list[tuple[str, str | None]] = []
        self.by_plural: dict[str, list[dict[str, Any]]] = {}
        kinds = {v: k for k, v in ap.LIVE_RESOURCES.items()}
        for d in docs:
            plural = kinds.get(d.get("kind", ""))
            if plural:
                item = {k: v for k, v in d.items() if k not in {"kind", "apiVersion"}}  # API lists drop item kinds
                self.by_plural.setdefault(plural, []).append(item)
        self.forbidden = forbidden

    def get(self, resource: str, name: str | None = None, namespace: str | None = None, **_: Any) -> dict[str, Any]:
        resolve_resource(resource)  # the real allowlist: refuses secrets
        self.calls.append((resource, namespace))
        if resource in self.forbidden:
            raise ClusterAccessError(f"{resource} is forbidden")
        items = [
            i
            for i in self.by_plural.get(resource, [])
            if namespace is None or (i.get("metadata") or {}).get("namespace") == namespace
        ]
        return {"kind": "List", "items": items}


def test_live_scan_reads_the_allowlist_only_and_reports_what_it_could_not_read() -> None:
    docs = [d for d in yaml.safe_load_all(SEEDED.read_text(encoding="utf-8")) if d]
    backend = FakeBackend(docs, forbidden={"securitycontextconstraints"})
    out = ap.scan(ap.collect_live(backend, []))
    assert out["paths"][0]["summary"] == PLANTED
    assert {r for r, _ in backend.calls} == set(ap.LIVE_RESOURCES)
    assert not any("secret" in r for r, _ in backend.calls)
    assert any(n.startswith("securitycontextconstraints") for n in out["notRead"])
    scoped = FakeBackend(docs)
    ap.collect_live(scoped, ["shop", "ops"])
    assert (
        ("clusterroles", None) in scoped.calls
        and ("roles", "shop") in scoped.calls
        and ("roles", "ops") in scoped.calls
    )
    assert ("roles", None) not in scoped.calls


def test_the_allowlist_reads_rbac_and_still_refuses_secrets() -> None:
    for r in ("roles", "rolebinding", "clusterrole", "clusterrolebindings", "dc"):
        assert resolve_resource(r)[0] in ap.LIVE_RESOURCES
    with pytest.raises(ClusterAccessError, match="not permitted"):
        resolve_resource("secrets")
    chart = (Path(__file__).parent.parent / "deploy" / "helm" / "kube-noob" / "templates" / "rbac.yaml").read_text()
    assert "secrets" not in chart.replace("Secrets stay out", "").lower().replace("no secrets, ever", "")


# --- CLI and MCP -------------------------------------------------------------------------------------------------


def test_cli_text_json_and_the_ci_gate(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["posture", "scan", "-f", str(SEEDED), "--top", "2"]) == 0
    text = capsys.readouterr().out
    assert text.startswith("5 attack paths from 5 exposures") and "#1  score 18" in text and "#3" not in text
    assert "hunter2" not in text and "1 Secret object(s) in the input were ignored, unread." in text
    assert main(["--format", "json", "posture", "scan", "-f", str(SEEDED)]) == 0
    assert json.loads(capsys.readouterr().out)["paths"][0]["summary"] == PLANTED
    assert main(["posture", "scan", "-f", str(SEEDED), "--fail-above", "17"]) == 1
    capsys.readouterr()
    assert main(["posture", "scan", "-f", str(SEEDED), "--fail-above", "18"]) == 0
    capsys.readouterr()
    for argv in (
        ["posture", "scan"],
        ["posture", "scan", "--live"],
        ["posture", "scan", "-f", str(SEEDED), "-n", "x"],
        ["posture", "scan", "-f", str(SEEDED), "--top", "0"],
    ):
        assert main(argv) != 0
        capsys.readouterr()


def test_mcp_tools() -> None:
    kit = tk.Toolkit(load_settings())
    names = {s.name for s in kit.specs()}
    assert "posture_scan" in names and "cluster_posture_scan" not in names
    out = kit.posture_scan(tk.PostureScanIn(manifests=SEEDED.read_text(encoding="utf-8"), top=3))
    assert out["paths"][0]["summary"] == PLANTED and len(out["paths"]) == 3
    live = tk.Toolkit(load_settings(overrides={"cluster": {"enabled": True}}))
    assert "cluster_posture_scan" in {s.name for s in live.specs()}
    with pytest.raises(ValueError):
        tk.ClusterPostureIn(namespaces=["Bad NS"])
