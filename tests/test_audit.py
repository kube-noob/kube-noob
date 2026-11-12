from __future__ import annotations

import pytest

from kube_noob.audit.engine import analyze, explain_rule, list_rules
from kube_noob.audit.fixer import fix_manifests
from kube_noob.audit.model import Severity
from kube_noob.audit.rules import RULES, image_tag
from tests.conftest import fixture_text

BAD = fixture_text("bad-bundle.yaml")


def ids(report) -> set[str]:  # type: ignore[no-untyped-def]
    return {f.rule_id for f in report.findings}


def test_bad_bundle_kubernetes_findings() -> None:
    r = analyze(BAD, "kubernetes")
    expected = {
        "KN-V002",
        "KN-V003",
        "KN-V004",
        "KN-V005",
        "KN-V007",
        "KN-V011",
        "KN-V015",
        "KN-S001",
        "KN-S005",
        "KN-S009",
        "KN-S010",
        "KN-S012",
        "KN-S013",
        "KN-S015",
        "KN-S016",
        "KN-S018",
        "KN-ST001",
        "KN-N002",
        "KN-N004",
        "KN-N006",
        "KN-C006",
        "KN-C001",
    }
    missing = expected - ids(r)
    assert not missing, missing
    assert r.max_severity() is Severity.CRITICAL
    assert r.score() == 0.0
    sock = [f for f in r.findings if f.rule_id == "KN-S010"]
    assert sock and sock[0].severity is Severity.CRITICAL
    typo = [f for f in r.findings if f.rule_id == "KN-V007" and "imagePullPolice" in f.message]
    assert typo and typo[0].line == 20


def test_openshift_specific_rules() -> None:
    r = analyze(BAD, "openshift", "4.22")
    assert "KN-S004" in ids(r)  # fixed runAsUser vs restricted-v2
    assert "KN-V003" not in ids(r)  # Route group exists on OpenShift (wrong version is V002)
    r2 = analyze(
        "apiVersion: machineconfiguration.openshift.io/v1\nkind: MachineConfig\nmetadata: {name: x}\n", "rosa-hcp"
    )
    assert "KN-V017" in ids(r2)


def test_rwx_on_rosa_without_class() -> None:
    y = (
        "apiVersion: v1\nkind: PersistentVolumeClaim\nmetadata: {name: d, namespace: a}\nspec:\n"
        "  accessModes: [ReadWriteMany]\n  resources: {requests: {storage: 1Gi}}\n"
    )
    assert "KN-ST001" in ids(analyze(y, "rosa-hcp"))
    assert "KN-ST001" not in ids(analyze(y, "kubernetes"))


def test_rbd_block_rwx_allowed() -> None:
    y = (
        "apiVersion: v1\nkind: PersistentVolumeClaim\nmetadata: {name: d, namespace: a}\nspec:\n"
        "  accessModes: [ReadWriteMany]\n  volumeMode: Block\n  storageClassName: ocs-storagecluster-ceph-rbd\n"
        "  resources: {requests: {storage: 1Gi}}\n"
    )
    assert "KN-ST001" not in ids(analyze(y, "openshift"))


def test_red_team_scenarios_present() -> None:
    r = analyze(BAD, "kubernetes")
    scen = {s.scenario_id: s for s in r.scenarios}
    for sid in (
        "RT-NODE-CRASH",
        "RT-EXPOSURE",
        "RT-PRIVESC",
        "RT-UPGRADE-BLOCK",
        "RT-SECRET-LEAK",
        "RT-RWX-SPLIT-BRAIN",
        "RT-SUPPLY-CHAIN",
    ):
        assert scen[sid].verdict == "exposed", sid


def test_every_rule_has_metadata_and_is_explainable() -> None:
    assert len(RULES) >= 45
    for rid in RULES:
        info = explain_rule(rid)
        assert info["remediation"] and info["description"]
    assert {r["ruleId"] for r in list_rules()} == set(RULES)
    with pytest.raises(KeyError):
        explain_rule("KN-X999")


@pytest.mark.parametrize(
    ("image", "tag", "digest"),
    [
        ("nginx", None, False),
        ("nginx:latest", "latest", False),
        ("registry:5000/app", None, False),
        ("registry:5000/app:1.2", "1.2", False),
        ("quay.io/a/b@sha256:" + "a" * 64, None, True),
    ],
)
def test_image_tag_parsing(image: str, tag: str | None, digest: bool) -> None:
    assert image_tag(image) == (tag, digest)


def test_fixer_resolves_blockers() -> None:
    res = fix_manifests(BAD, platform="rosa-hcp", k8s_version="1.35")
    changed = {c.rule_id for c in res.changes}
    assert {"KN-V002", "KN-V005", "KN-N002", "KN-C009", "KN-ST001", "KN-V015", "KN-N006", "KN-S004"} <= changed
    after = analyze(res.yaml(), "rosa-hcp")
    assert not {"KN-V002", "KN-V005", "KN-N002", "KN-C009", "KN-ST001", "KN-V015", "KN-N006"} & ids(after)
    assert any("privileged" in m for m in res.manual)


def test_fixer_ingress_migration() -> None:
    y = (
        "apiVersion: networking.k8s.io/v1beta1\nkind: Ingress\nmetadata: {name: s, namespace: s}\nspec:\n"
        "  rules:\n  - host: s.example.com\n    http:\n      paths:\n      - path: /\n"
        "        backend: {serviceName: s, servicePort: 80}\n"
    )
    res = fix_manifests(y, harden=False)
    out = analyze(res.yaml(), "kubernetes", "1.35")
    assert "KN-V005" not in ids(out) and "KN-V007" not in ids(out)
    path = res.documents[0]["spec"]["rules"][0]["http"]["paths"][0]
    assert path["backend"] == {"service": {"name": "s", "port": {"number": 80}}}
    assert path["pathType"] == "ImplementationSpecific"


def test_crd_schema_validation() -> None:
    bad_route = "apiVersion: route.openshift.io/v1\nkind: Route\nmetadata: {name: r}\nspec: {too: {name: s}}\n"
    assert "KN-V007" in ids(analyze(bad_route, "openshift"))
    good_fw = (
        "apiVersion: k8s.ovn.org/v1\nkind: EgressFirewall\nmetadata: {name: default, namespace: a}\nspec:\n"
        "  egress:\n  - {type: Allow, to: {dnsName: example.com}}\n  - {type: Deny, to: {cidrSelector: 0.0.0.0/0}}\n"
    )
    assert not ids(analyze(good_fw, "openshift")) & {"KN-V007", "KN-V015", "KN-N006"}
    sc = "apiVersion: platform.stackrox.io/v1alpha1\nkind: SecuredCluster\nmetadata: {name: s}\nspec: {clusterNam: x}\n"
    assert "KN-V007" in ids(analyze(sc, "openshift"))


def test_legacy_bundle_migrates_to_current_apis() -> None:
    legacy = fixture_text("legacy-bundle.yaml")
    before = analyze(legacy, "kubernetes", "1.35")
    assert sum(1 for f in before.findings if f.rule_id == "KN-V005") == 7
    res = fix_manifests(legacy, platform="kubernetes", k8s_version="1.35")
    after = analyze(res.yaml(), "kubernetes", "1.35")
    blocking = {f.rule_id for f in after.findings if f.severity >= Severity.HIGH}
    assert not blocking, blocking
    assert not {"KN-V005", "KN-V007", "KN-V010", "KN-C009"} & ids(after)
    hpa = next(d for d in res.documents if d["kind"] == "HorizontalPodAutoscaler")
    assert hpa["spec"]["metrics"][0]["resource"]["target"] == {"type": "Utilization", "averageUtilization": 70}


_S010_CRITICAL = [
    "/",
    "/etc",
    "/etc/",
    "//etc",
    "/etc/../etc",
    "/proc",
    "/var/lib/kubelet",
    "/var/lib/kubelet/",
    "/etc/kubernetes",
    "/etc/kubernetes/pki",
    "/etc/kubernetes/./admin.conf",
    "/var/lib/kubelet/pki",
    "/var/lib/kubelet/pods",
    "/var/lib/kubelet/pods/abc/volumes",
    "/var/run/docker.sock",
    "/run/containerd/containerd.sock",
    "/var/run/crio/crio.sock",
    "/run/podman/podman.sock",
    "/var/run/dockershim.sock",
    "/var/run/cri-dockerd.sock",
    "/root",
    "/root/.ssh",
    "/var/lib/etcd",
    "/var/lib/etcd/member",
    # Fourth review: a directory holding a critical path or a runtime socket is critical too, and /proc/1/root is /.
    "/var/run",
    "/run",
    "/run/containerd",
    "/var/lib",
    "/var",
    "/proc/1/root",
]
#: What every cluster mounts and what gives no node: kube-proxy, CNI plugins, CA bundles, the time zone, the
#: machine id, kubelet plugin registration (the third review: a subtree rule made `gate --fail-on critical` fail on
#: nearly every cluster).
_S010_HIGH = [
    "/run/xtables.lock",
    "/var/run/calico",
    "/var/run/cilium",
    "/run/flannel",
    "/etc/cni/net.d",
    "/etc/localtime",
    "/etc/ssl/certs",
    "/etc/pki/ca-trust/extracted/pem",
    "/etc/machine-id",
    "/proc/sys/net",
    "/var/lib/kubelet/device-plugins",
    "/var/lib/kubelet/plugins_registry",
    "/var/run/secrets",
    "/lib/modules",
    "/var/log",
    "/ETC",
    "etc",
    "/var/lib/containerd",
]


@pytest.mark.parametrize(("path", "critical"), [(p, True) for p in _S010_CRITICAL] + [(p, False) for p in _S010_HIGH])
def test_kn_s010_is_critical_for_credential_and_api_paths_only(path: str, critical: bool) -> None:
    """Third review: KN-S010 escalated every path under /etc, /run, /var/run, /proc and /root to critical, which made
    kube-proxy's xtables lock, CNI state and CA bundles fail `gate --fail-on critical`. Critical is the node's
    credentials and API: the existing set, /etc/kubernetes and /var/lib/kubelet/{pki,pods} and below, /root and
    /var/lib/etcd and below, and a runtime socket anywhere -- after `//`, a trailing `/` and `.`/`..` resolve."""
    from kube_noob.audit.rules import takes_over_node

    doc = (
        "apiVersion: apps/v1\nkind: DaemonSet\nmetadata: {name: d, namespace: kube-system}\nspec:\n"
        "  selector: {matchLabels: {app: d}}\n  template:\n    metadata: {labels: {app: d}}\n    spec:\n"
        f"      volumes: [{{name: h, hostPath: {{path: {path!r}}}}}]\n"
        "      containers: [{name: c, image: quay.io/acme/x:1.0.0, volumeMounts: [{name: h, mountPath: /h}]}]\n"
    )
    found = [f for f in analyze(doc, "kubernetes").findings if f.rule_id == "KN-S010"]
    assert len(found) == 1
    assert found[0].severity is (Severity.CRITICAL if critical else Severity.HIGH), path
    assert takes_over_node(path) is critical, path
    text = str(explain_rule("KN-S010"))
    assert "/etc/kubernetes" in text and "/var/lib/etcd" in text


def test_fixer_flips_explicit_privilege_escalation_on_openshift_only() -> None:
    from kube_noob.audit.fixer import fix_manifests

    src = (
        "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: api, namespace: shop}\nspec:\n"
        "  selector: {matchLabels: {app: api}}\n  template:\n    metadata: {labels: {app: api}}\n    spec:\n"
        "      containers:\n        - name: api\n          image: quay.io/acme/api:1.0.0\n"
        "          securityContext: {allowPrivilegeEscalation: true}\n"
    )
    ocp = fix_manifests(src, platform="openshift", k8s_version="1.35")
    assert "allowPrivilegeEscalation: false" in ocp.yaml()
    k8s = fix_manifests(src, platform="kubernetes", k8s_version="1.35")
    assert "allowPrivilegeEscalation: true" in k8s.yaml()
    assert any("allowPrivilegeEscalation: true" in m for m in k8s.manual)
