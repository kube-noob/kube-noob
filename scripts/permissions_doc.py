#!/usr/bin/env python3
"""Write docs/permissions.md from the code, never by hand: which Kubernetes API resources each live capability
reads, and what the Helm chart's read-only Role and ClusterRole grant for them.

The matrix is recorded, not written: every live capability (the `cluster_*` MCP tools and the `--live` commands
behind the same functions, the drift snapshot, the admission webhook's context reads) is run against a recording
backend over a small fixture cluster, and the rows are the resources it asked for -- group, plural, verb. `cluster_get`
is the one capability whose reads are not a recording: it reads whichever allowlisted resource it is asked for, so
its row is the allowlist (``kube_noob.debug.cluster.ALLOWED_RESOURCES``) itself. The chart's grants are read from
the templates by the same static reader scripts/safety_contract.py uses, so helm is not needed.

Both directions are held by tests/test_permissions_doc.py: a grant the code never reads is a finding, and so is a
read the chart does not grant. Secrets are on neither side (G293).

Usage:
  python scripts/permissions_doc.py           write docs/permissions.md
  python scripts/permissions_doc.py --check   exit 1 if the committed document differs from the code (CI, check.sh)
"""

from __future__ import annotations

import argparse
import copy
import re
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "permissions.md"
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from kube_noob.debug.cluster import ALLOWED_RESOURCES, ResourceDef  # noqa: E402
from kube_noob.errors import ClusterAccessError  # noqa: E402

Grant = tuple[str, str]  # (api group, plural or plural/subresource)

NS = "shop"


def _group(d: ResourceDef) -> str:
    return d.group_version.split("/", 1)[0] if "/" in d.group_version else ""


KINDS = {
    "namespaces": "Namespace",
    "deployments": "Deployment",
    "replicasets": "ReplicaSet",
    "pods": "Pod",
    "statefulsets": "StatefulSet",
    "daemonsets": "DaemonSet",
    "jobs": "Job",
    "cronjobs": "CronJob",
    "services": "Service",
    "routes": "Route",
    "serviceaccounts": "ServiceAccount",
    "roles": "Role",
    "rolebindings": "RoleBinding",
    "clusterroles": "ClusterRole",
    "clusterrolebindings": "ClusterRoleBinding",
    "networkpolicies": "NetworkPolicy",
    "events": "Event",
    "clusterserviceversions": "ClusterServiceVersion",
    "subscriptions": "Subscription",
    "clusterversions": "ClusterVersion",
}


def _kind(plural: str) -> str:
    """The kind of a plural the fixture holds; for the rest a name the list check accepts (``_names_kind``)."""
    if plural in KINDS:
        return KINDS[plural]
    return (plural[:-3] + "y" if plural.endswith("ies") else plural[:-1]).capitalize()


def _obj(plural: str, name: str, namespace: str | None, **body: Any) -> dict[str, Any]:
    d = ALLOWED_RESOURCES[plural]
    meta: dict[str, Any] = {"name": name, "uid": f"uid-{plural}-{name}", "labels": {"app": name}}
    if d.namespaced and namespace:
        meta["namespace"] = namespace
    return {"apiVersion": d.group_version, "kind": _kind(plural), "metadata": meta, **body}


def _podspec(sa: str = "web") -> dict[str, Any]:
    return {
        "serviceAccountName": sa,
        "containers": [
            {"name": "app", "image": "quay.io/acme/web:1.0", "ports": [{"containerPort": 8080}]},
            {"name": "sidecar", "image": "quay.io/acme/sidecar:1.0"},
        ],
    }


class FixtureCluster:
    """A small cluster: one namespace with a crashing, image-pulling Deployment behind a Service and a Route, the
    RBAC that binds its ServiceAccount, a NetworkPolicy, an OLM operator, and an OpenShift ClusterVersion. Every
    allowlisted resource lists (empty when nothing above is of that kind); a name that is not here is NotFound in
    kubectl's words."""

    name = "fixture"

    def __init__(self) -> None:
        # One container crash-loops (so the watch and the debugger read its previous log) and one is stuck pulling
        # (so the debugger reads the ServiceAccount's pull-secret names): both reads are recorded (G293, review).
        pod_status = {
            "phase": "Running",
            "containerStatuses": [
                {
                    "name": "app",
                    "ready": False,
                    "restartCount": 7,
                    "state": {"waiting": {"reason": "CrashLoopBackOff", "message": "back-off 5m0s restarting"}},
                    "lastState": {"terminated": {"reason": "Error", "exitCode": 1}},
                },
                {
                    "name": "sidecar",
                    "ready": False,
                    "restartCount": 0,
                    "state": {"waiting": {"reason": "ImagePullBackOff", "message": "Back-off pulling image"}},
                },
            ],
        }
        tmpl = {"metadata": {"labels": {"app": "web"}}, "spec": _podspec()}
        sel = {"matchLabels": {"app": "web"}}
        self.objects: list[dict[str, Any]] = [
            _obj("namespaces", NS, None, metadata_labels={"team": "shop"}),
            _obj("deployments", "web", NS, spec={"replicas": 1, "selector": sel, "template": tmpl}),
            _obj("replicasets", "web-6d4", NS, spec={"replicas": 1, "selector": sel, "template": tmpl},
                 metadata_labels={"app": "web"}),
            _obj("pods", "web-6d4-x1", NS, spec=_podspec(), status=pod_status, metadata_labels={"app": "web"}),
            _obj("statefulsets", "db", NS, spec={"replicas": 1, "selector": sel, "template": tmpl}),
            _obj("daemonsets", "agent", NS, spec={"selector": sel, "template": tmpl}),
            _obj("jobs", "migrate", NS, spec={"selector": sel, "template": tmpl}),
            _obj("cronjobs", "nightly", NS, spec={"jobTemplate": {"spec": {"template": tmpl}}}),
            _obj("services", "web", NS, spec={"selector": {"app": "web"}, "ports": [{"port": 80, "targetPort": 8080}]}),
            _obj("routes", "web", NS, spec={"to": {"kind": "Service", "name": "web"}, "port": {"targetPort": 8080}}),
            _obj("serviceaccounts", "web", NS, imagePullSecrets=[{"name": "quay-pull"}]),
            _obj("roles", "web", NS, rules=[{"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list"]}]),
            _obj(
                "rolebindings",
                "web",
                NS,
                roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "web"},
                subjects=[{"kind": "ServiceAccount", "name": "web", "namespace": NS}],
            ),
            _obj("clusterroles", "view-pods", None, rules=[{"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}]),  # noqa: E501
            _obj(
                "clusterrolebindings",
                "web-view",
                None,
                roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "view-pods"},
                subjects=[{"kind": "ServiceAccount", "name": "web", "namespace": NS}],
            ),
            _obj("networkpolicies", "default-deny", NS, spec={"podSelector": {}, "policyTypes": ["Ingress"]}),
            _obj("events", "web-6d4-x1.1", NS, reason="BackOff", message="Back-off restarting failed container",
                 involvedObject={"kind": "Pod", "name": "web-6d4-x1", "namespace": NS}, type="Warning",
                 lastTimestamp="2026-11-12T00:00:00Z", count=7),
            _obj("clusterserviceversions", "shop-operator.v1.0.0", NS, spec={"displayName": "Shop", "version": "1.0.0"},
                 status={"phase": "Succeeded"}),
            _obj("subscriptions", "shop-operator", NS, spec={"channel": "stable", "name": "shop-operator",
                 "source": "community-operators", "sourceNamespace": "openshift-marketplace"},
                 status={"installedCSV": "shop-operator.v1.0.0"}),
            _obj("clusterversions", "version", None, status={"desired": {"version": "4.20.3"}}),
        ]  # fmt: skip
        for o in self.objects:
            if "metadata_labels" in o:
                o["metadata"]["labels"] = o.pop("metadata_labels")

    def get(
        self,
        resource: str,
        name: str | None = None,
        namespace: str | None = None,
        selector: str | None = None,
        field_selector: str | None = None,
    ) -> dict[str, Any]:
        from kube_noob.debug.cluster import resolve_resource

        plural, d = resolve_resource(resource)
        hits = [o for o in self.objects if o["kind"] == _kind(plural) and o["apiVersion"] == d.group_version]
        if d.namespaced and namespace:
            hits = [o for o in hits if o["metadata"].get("namespace") == namespace]
        if selector:
            want = dict(part.split("=", 1) for part in selector.split(",") if "=" in part)
            hits = [o for o in hits if all(o["metadata"].get("labels", {}).get(k) == v for k, v in want.items())]
        if name:
            hits = [o for o in hits if o["metadata"]["name"] == name]
            if not hits:
                qualified = plural if d.group_version == "v1" else f"{plural}.{_group(d)}"
                raise ClusterAccessError(f'Error from server (NotFound): {qualified} "{name}" not found')
            return copy.deepcopy(hits[0])
        return {"apiVersion": "v1", "kind": f"{_kind(plural)}List", "metadata": {}, "items": copy.deepcopy(hits)}

    def logs(self, namespace: str, pod: str, container: str | None, tail: int, previous: bool) -> str:
        return "panic: cannot connect to db:5432: connection refused\n"

    def version(self) -> dict[str, Any]:
        return {"serverVersion": {"major": "1", "minor": "33", "gitVersion": "v1.33.2"}}


class RecordingBackend:
    """Answers from the fixture and records every read: (group, plural[/subresource], verb) and the endpoints
    that are not resources (``/version``)."""

    name = "recording"

    def __init__(self) -> None:
        self.fixture = FixtureCluster()
        self.reads: set[Grant] = set()
        self.verbs: set[tuple[str, str, str]] = set()
        self.endpoints: set[str] = set()

    def get(self, resource: str, name: str | None = None, namespace: str | None = None, **kw: Any) -> dict[str, Any]:
        from kube_noob.debug.cluster import resolve_resource

        plural, d = resolve_resource(resource)
        self.reads.add((_group(d), plural))
        self.verbs.add((_group(d), plural, "get" if name else "list"))
        return self.fixture.get(resource, name=name, namespace=namespace, **kw)

    def logs(self, namespace: str, pod: str, container: str | None, tail: int, previous: bool) -> str:
        self.reads.add(("", "pods/log"))
        self.verbs.add(("", "pods/log", "get"))
        return self.fixture.logs(namespace, pod, container, tail, previous)

    def version(self) -> dict[str, Any]:
        self.endpoints.add("/version")
        return self.fixture.version()


@dataclass
class Row:
    capability: str  # "CLI command / MCP tool"
    what: str
    reads: set[Grant] = field(default_factory=set)
    verbs: set[tuple[str, str, str]] = field(default_factory=set)
    endpoints: set[str] = field(default_factory=set)
    recorded: bool = True


def _settings(data_dir: Path) -> Any:
    from kube_noob.config import load_settings

    # The ledger and the learning file live in the scratch directory: a recording must never touch the user's data
    # directory, and a poll against a ledger that already holds the incident would skip the log read (review).
    return load_settings(overrides={"dataDir": str(data_dir), "cluster": {"enabled": True}})


def _run_posture_scan(b: RecordingBackend, _: Path) -> Any:
    from kube_noob import attack_paths

    return attack_paths.scan(attack_paths.collect_live(b, [NS]), top=5)


def _run_posture_reach(b: RecordingBackend, _: Path) -> Any:
    from kube_noob import attack_paths, blast_radius

    inv = attack_paths.collect_live(b, [NS])
    return blast_radius.reach_result(inv, "deployment/web", NS, live=True, namespaces_read=[NS])


def _run_operator_inventory(b: RecordingBackend, _: Path) -> Any:
    from kube_noob import operators

    return operators.inventory(operators.collect_live(b, [NS]), top=5)


def _run_operator_known_issues(b: RecordingBackend, data_dir: Path) -> Any:
    from kube_noob import operator_issues, operators

    collected = operators.collect_live(b, [NS])
    release = operator_issues.live_release(b)
    return operator_issues.assess(
        collected, release=release, surface="mcp", top=5, issues_per_package=3, data_dir=data_dir
    )


def _run_check_traffic(b: RecordingBackend, _: Path) -> Any:
    from kube_noob.debug.netpol import check_reachability, inventory_from_cluster

    out = []
    for src, dst, cni in ((f"{NS}/web", f"{NS}/db", None), (f"{NS}/pod/web-6d4-x1", f"{NS}/db", "calico:3.32")):
        inv = inventory_from_cluster(b, src, dst, cni)
        out.append(check_reachability(inv, src, dst, 5432))
    return out


def _run_check_namespace(b: RecordingBackend, data_dir: Path) -> Any:
    from kube_noob.watch import Watcher

    return Watcher(_settings(data_dir), b, [NS]).poll()


def _run_debug(b: RecordingBackend, data_dir: Path) -> Any:
    from kube_noob.debug.diagnose import debug_workload

    targets = (("deployment", "web"), ("statefulset", "db"), ("daemonset", "agent"), ("job", "migrate"))
    targets += (("pod", "web-6d4-x1"),)
    return [debug_workload(b, NS, kind, name, None, 50, data_dir) for kind, name in targets]


def _run_version(b: RecordingBackend, _: Path) -> Any:
    from kube_noob.debug.cluster import cluster_info

    return cluster_info(b)


def _run_drift(b: RecordingBackend, _: Path) -> Any:
    from kube_noob import drift

    objects, not_read = drift.collect_live(b, [NS])
    return drift.snapshot(objects, source="live", platform="openshift", not_read=not_read)


def _run_admission(b: RecordingBackend, _: Path) -> Any:
    from kube_noob.admission import Lookups

    lookups = Lookups(b, sleep=lambda _s: None)
    lookups(NS)
    lookups.refresh()
    return {"unread": lookups.unread(NS), "stale": lookups.stale(NS), "errors": lookups.errors}


RUNNERS: list[tuple[str, str, Any]] = [
    (
        "`posture scan --live` / `cluster_posture_scan`",
        "attack paths: every workload, its pods, what fronts them and the RBAC their ServiceAccounts hold",
        _run_posture_scan,
    ),
    (
        "`posture reach --live` / `cluster_posture_reach`",
        "one workload's blast radius, from the same inventory as the scan",
        _run_posture_reach,
    ),
    (
        "`operators inventory --live` / `cluster_operator_inventory`",
        "OLM operators installed, at what version, from which catalog and channel",
        _run_operator_inventory,
    ),
    (
        "`operators known-issues --live` / `cluster_operator_known_issues`",
        "the inventory above, plus the ClusterVersion named `version` for the release",
        _run_operator_known_issues,
    ),
    (
        "`policy reach --live` / `cluster_check_traffic`",
        "the two endpoints' workloads and pods, their namespaces' labels, NetworkPolicies, the cluster-scoped tiers "
        "and the CNI's own version object",
        _run_check_traffic,
    ),
    (
        "`watch`, `incidents` / `cluster_check_namespace`",
        "a namespace's pods, events and owners, and the previous log of a container that keeps crashing",
        _run_check_namespace,
    ),
    (
        "`debug`, `bundle` / `cluster_debug`",
        "one workload by kind and name, its pods, their events, the ServiceAccount of a pod stuck pulling (pull secret "
        "names only, never the Secret), and container logs",
        _run_debug,
    ),
    ("`doctor` (with cluster access) / `cluster_version`", "the API server's version", _run_version),
    (
        "`posture snapshot --live`, `posture diff`, the drift schedule",
        "a snapshot of the workloads, their fronts and RBAC, plus the context objects drift is scored on",
        _run_drift,
    ),
    (
        "admission webhook (`serve` with `admission.enabled`)",
        "the context cross-object rules need, per namespace the webhook has seen, and the cluster's StorageClasses",
        _run_admission,
    ),
]


#: Allowlisted (and granted by the chart) resources that no capability other than `cluster_get` reads. Named here
#: so the document's section and tests/test_permissions_doc.py fail the day the set drifts in either direction:
#: a capability that starts reading one of these, or one that stops reading something else (G293, review).
CLUSTER_GET_ONLY: frozenset[Grant] = frozenset(
    {
        ("", "endpoints"),
        ("", "limitranges"),
        ("", "nodes"),
        ("", "persistentvolumes"),
        ("", "resourcequotas"),
        ("config.openshift.io", "apiservers"),
        ("config.openshift.io", "clusteroperators"),
        ("platform.stackrox.io", "centrals"),
        ("platform.stackrox.io", "securedclusters"),
    }
)


def recorded_union(rows: list[Row]) -> set[Grant]:
    """Everything the recorded capabilities read, `cluster_get` (the allowlist itself) left out."""
    return set().union(*(r.reads for r in rows if r.recorded))


def matrix() -> list[Row]:
    rows: list[Row] = []
    with tempfile.TemporaryDirectory() as tmp:
        data_dir = Path(tmp)
        for capability, what, run in RUNNERS:
            b = RecordingBackend()
            run(b, data_dir)
            rows.append(Row(capability, what, set(b.reads), set(b.verbs), set(b.endpoints)))
    allow = {(_group(d), d.plural) for d in ALLOWED_RESOURCES.values()}
    rows.append(
        Row(
            "`cluster_get`",
            "any one resource on the read-only allowlist, by name or as a list, with a label selector; never Secrets "
            "(refused before any backend is touched)",
            allow,
            {(g, p, v) for g, p in allow for v in ("get", "list")},
            set(),
            recorded=False,
        )
    )
    return rows


def code_grants() -> tuple[set[Grant], set[Grant]]:
    """What the chart must grant: cluster scope is the allowlist; namespace scope is its namespaced part. Both
    carry ``pods/log``, which the backends read through the log subresource."""
    cluster = {(_group(d), d.plural) for d in ALLOWED_RESOURCES.values()} | {("", "pods/log")}
    namespaced = {(_group(d), d.plural) for d in ALLOWED_RESOURCES.values() if d.namespaced} | {("", "pods/log")}
    return cluster, namespaced


def _read_rules() -> list[Any]:
    import safety_contract as sc

    return [r for r in sc.chart_rules() if r.template == "rbac.yaml" and r.role.endswith("-read")]


def chart_grants() -> tuple[set[Grant], set[Grant]]:
    cluster: set[Grant] = set()
    namespaced: set[Grant] = set()
    for r in _read_rules():
        target = cluster if r.kind == "ClusterRole" else namespaced
        for g in r.api_groups:
            for res in r.resources:
                target.add((g, res))
    return cluster, namespaced


def chart_verbs() -> set[tuple[str, ...]]:
    return {tuple(r.verbs) for r in _read_rules()}


def _cell(reads: set[Grant], verbs: set[tuple[str, str, str]]) -> str:
    by_group: dict[str, list[str]] = {}
    for g, p in sorted(reads):
        vs = sorted({v for gg, pp, v in verbs if (gg, pp) == (g, p)})
        by_group.setdefault(g, []).append(f"`{p}` ({', '.join(vs)})" if vs else f"`{p}`")
    return "; ".join(f"**{g or 'core'}**: {', '.join(items)}" for g, items in sorted(by_group.items())) or "—"


def render() -> str:
    rows = matrix()
    code_cluster, code_ns = code_grants()
    chart_cluster, chart_ns = chart_grants()
    union = recorded_union(rows)
    only_get = sorted(code_cluster - union - {("", "pods/log")})
    if set(only_get) != set(CLUSTER_GET_ONLY):
        extra, gone = sorted(set(only_get) - CLUSTER_GET_ONLY), sorted(CLUSTER_GET_ONLY - set(only_get))
        raise SystemExit(
            f"CLUSTER_GET_ONLY drifted from what the capabilities read: now read by nothing {extra}, now read by a "
            f"capability {gone}; fix the set and the document together"
        )
    reaches = sorted(
        str(p.relative_to(ROOT / "src"))
        for p in (ROOT / "src" / "kube_noob").rglob("*.py")
        if re.search(r"\bget_backend\(", p.read_text(encoding="utf-8")) and p.name != "cluster.py"
    )
    lines = [
        "# What kube-noob reads from a cluster, and what the chart grants",
        "",
        "<!-- Generated by scripts/permissions_doc.py from the code; do not edit. `--check` holds it in CI. -->",
        "",
        "Live cluster access is off until `cluster.enabled: true` (the chart's `config.clusterEnabled`). When on, "
        "every read goes through one backend (`kube_noob.debug.cluster`, with `kubectl`/`oc` and the operator's "
        f"kubeconfig, or the pod's ServiceAccount token) that allows {len(ALLOWED_RESOURCES)} resources, verbs "
        "`get` and `list` and the `pods/log` subresource, and nothing else: no `watch`, no `exec`, no write, and "
        "Secrets are refused before a request is built. The table below was **recorded**, not written: each "
        "capability was run against a recording backend over a fixture cluster (one namespace with a crashing "
        "Deployment behind a Service and a Route, its RBAC, a NetworkPolicy, an OLM operator, a ClusterVersion) and "
        "the row lists exactly the resources it asked for and with which verb. A read the fixture does not provoke "
        "is not listed. A forbidden read is reported by the capability that asked, naming the resource -- in its "
        "`notRead`, `errors`, `unread` or evidence list and in its text view -- never as an empty namespace or a "
        "silent None; `tests/test_permissions_doc.py` forbids every recorded read of every row, one at a time, and "
        "holds that.",
        "",
        "## Per capability",
        "",
        "| Capability (CLI / MCP tool) | Reads | API group: resource (verbs) |",
        "|---|---|---|",
    ]
    for r in rows:
        extra = f"; endpoint {', '.join(f'`{e}`' for e in sorted(r.endpoints))}" if r.endpoints else ""
        lines.append(f"| {r.capability} | {r.what} | {_cell(r.reads, r.verbs)}{extra} |")
    lines += [
        "",
        "`cluster_get` is the one row that is the allowlist rather than a recording: it reads whichever allowlisted "
        "resource it is asked for. Every other command (`audit`, `gate`, `alerts`, `must-gather analyze`, "
        "`operators inventory` from files, ...) reads no cluster at all: `get_backend` is called only from "
        + ", ".join(f"`{m}`" for m in reaches)
        + ".",
        "",
        "## What the chart grants",
        "",
        "`deploy/helm/kube-noob/templates/rbac.yaml` renders one read-only Role per namespace (`rbac.scope: "
        "namespace`, the default: the release namespace plus `rbac.namespaces`) or one ClusterRole (`rbac.scope: "
        "cluster`), for the ServiceAccount the chart creates, with verbs `get` and `list` only. Read statically "
        "from the template (no `helm`), the grants are:",
        "",
        f"- ClusterRole: {len(chart_cluster)} resources = the allowlist ({len(code_cluster) - 1}) plus `pods/log`"
        + (" -- **identical to what the code can read**." if chart_cluster == code_cluster else " -- **DIFFERS**: "
           f"chart-only {sorted(chart_cluster - code_cluster)}, code-only {sorted(code_cluster - chart_cluster)}."),
        f"- Role (namespace scope): {len(chart_ns)} resources = the namespaced part of the allowlist "
        f"({len(code_ns) - 1}) plus `pods/log`"
        + (" -- **identical**." if chart_ns == code_ns else " -- **DIFFERS**: "
           f"chart-only {sorted(chart_ns - code_ns)}, code-only {sorted(code_ns - chart_ns)}."),
        "- Secrets: in neither, and `tests/test_permissions_doc.py` fails if `secrets` ever appears in a read rule.",
        "",
        "Under the namespace-scoped Role, a capability that asks for a cluster-scoped object (a Namespace's labels, "
        "ClusterRoles, the network policy tiers, StorageClasses, the ClusterVersion) gets a 403 and reports that "
        "read as not read; it never answers as if the object were absent.",
        "",
        "## Allowlisted, but read only through `cluster_get`",
        "",
        "These resources are on the allowlist and in the chart, and no recorded capability above asks for them. "
        "An operator who does not use `cluster_get` can leave them out of a hand-written Role:",
        "",
    ]  # fmt: skip
    lines += [f"- `{p}` ({g or 'core'})" for g, p in only_get] or ["- none"]
    lines += [
        "",
        "## Narrowing",
        "",
        "To grant one capability only, copy its row into a Role (namespaced resources) or ClusterRole "
        "(cluster-scoped ones) with `verbs: [get, list]`. The capability then reports every read it could not make, "
        "by resource name, in its result and its text view, and nothing it could not read counts as clean: the "
        "attack-path scan's headline reads `not determined: N resource list(s) not read (...)` before its counts.",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true", help="exit 1 if the document is stale")
    ap.add_argument("--doc", type=Path, default=OUT, help=argparse.SUPPRESS)
    a = ap.parse_args(argv)
    text = render() + "\n"
    shown = a.doc.relative_to(ROOT) if a.doc.is_relative_to(ROOT) else a.doc
    if a.check:
        current = a.doc.read_text(encoding="utf-8") if a.doc.is_file() else ""
        if current != text:
            print(f"{shown} is stale; run: python scripts/permissions_doc.py", file=sys.stderr)
            return 1
        print(f"{shown} is current")
        return 0
    a.doc.write_text(text, encoding="utf-8")
    print(f"wrote {a.doc}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
