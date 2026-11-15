"""The fourth review of KN-S037..KN-S041 (G272): the insecure port against source, configuration objects read,
evidence inside scripts, and list kinds unwrapped.

Every reproducer is tried alone and beside a clean neighbour: never clean at rule level.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
import yaml

from kube_noob.audit.engine import analyze
from kube_noob.audit.model import Report, Severity


def _pod(
    command: Any = None,
    args: Any = None,
    image: str = "img:1",
    env: list[dict[str, Any]] | None = None,
    name: str = "w",
    extra: dict[str, Any] | None = None,
) -> str:
    c: dict[str, Any] = {"name": "c", "image": image}
    if command is not None:
        c["command"] = command
    if args is not None:
        c["args"] = args
    if env is not None:
        c["env"] = env
    c.update(extra or {})
    doc = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": name, "namespace": "kube-system"},
        "spec": {"containers": [c]},
    }
    return yaml.safe_dump(doc, sort_keys=False)


def _r(text: str, platform: str = "kubernetes", version: str | None = None) -> Report:
    return analyze(text, platform, version)


def _hits(report: Report, rid: str) -> list[Any]:
    return [f for f in report.findings if f.rule_id == rid]


def _clean(report: Report, rid: str) -> bool:
    return rid in report.evaluated_rules and not _hits(report, rid)


def _declined(report: Report, rid: str) -> bool:
    return rid not in report.evaluated_rules and any(
        a.startswith(f"{rid} was not evaluated") for a in report.assumptions
    )


KAS, ETCD = "KN-S038", "KN-S039"
GEN = "docker.io/library/alpine:3.20"
BASE = ["kube-apiserver", "--authorization-mode=Node,RBAC", "--anonymous-auth=false", "--etcd-servers=https://e:2379"]
GOOD_KAS = _pod(BASE, name="good")
TLS = [
    "--listen-client-urls=https://10.0.0.1:2379",
    "--advertise-client-urls=https://10.0.0.1:2379",
    "--client-cert-auth=true",
    "--trusted-ca-file=/ca",
    "--cert-file=/c",
    "--key-file=/k",
    "--listen-peer-urls=https://10.0.0.1:2380",
    "--initial-advertise-peer-urls=https://10.0.0.1:2380",
    "--peer-client-cert-auth=true",
    "--peer-trusted-ca-file=/pca",
    "--peer-cert-file=/pc",
    "--peer-key-file=/pk",
]
GOOD_ETCD = _pod(["etcd", *TLS], name="good")
BADA = "--etcd-servers=https://e:2379 --authorization-mode=AlwaysAllow"
BADE = "--listen-client-urls=http://0.0.0.0:2379 --advertise-client-urls=http://10.0.0.1:2379"


def _never_clean(text: str, rid: str, version: str | None = None, platform: str = "kubernetes") -> None:
    good = GOOD_KAS if rid == KAS else GOOD_ETCD
    for bundle in (text, good + "---\n" + text):
        report = _r(bundle, platform, version)
        assert not _clean(report, rid), bundle
        assert _declined(report, rid) or _hits(report, rid), bundle


# --- D1. the insecure port, as each release reads it ----------------------------------------------------------------
# v1.19.0 deprecated_insecure_serving.go: --insecure-bind-address and --address are one variable, --insecure-port and
# --port another; kube-apiserver's defaults are 127.0.0.1 and 8080 (pkg/kubeapiserver/options/serving.go).
# v1.20.0..v1.23.0 server.go checkNonZeroInsecurePort refuses any non-zero port; v1.24.0 removed the flags.


@pytest.mark.parametrize(
    "flags",
    [
        ["--address=0.0.0.0"],
        ["--insecure-bind-address=0.0.0.0"],
        ["--insecure-bind-address=0.0.0.0", "--port=8080"],
        ["--address=0.0.0.0", "--insecure-port=0x1f90"],
        ["--insecure-port=0", "--address=0.0.0.0", "--port=8080"],
    ],
)
def test_the_insecure_port_on_a_network_address_up_to_1_19_is_critical(flags: list[str]) -> None:
    for version in ("1.19", "1.16"):
        hits = _hits(_r(_pod([*BASE, *flags]), version=version), KAS)
        assert [h.severity for h in hits] == [Severity.CRITICAL], (flags, version)


@pytest.mark.parametrize(
    "flags",
    [
        ["--insecure-port=8080"],
        ["--insecure-port=8080", "--insecure-bind-address=127.0.0.1"],
        ["--address=0.0.0.0", "--port=0"],
        ["--insecure-port=8080", "--insecure-bind-address=0.0.0.0", "--port=0"],
    ],
)
def test_a_loopback_or_disabled_insecure_port_up_to_1_19_is_clean(flags: list[str]) -> None:
    assert _clean(_r(_pod([*BASE, *flags]), version="1.19"), KAS)


@pytest.mark.parametrize("flags", [["--insecure-port=08080", "--address=0.0.0.0"], ["--address=not-an-ip"]])
def test_an_insecure_value_pflag_refuses_declines(flags: list[str]) -> None:
    _never_clean(_pod([*BASE, *flags]), KAS, version="1.19")


@pytest.mark.parametrize("version", ["1.20", "1.21", "1.23"])
def test_a_non_zero_insecure_port_from_1_20_to_1_23_declines_because_the_server_refuses_it(version: str) -> None:
    for flags in (["--insecure-port=8080", "--insecure-bind-address=0.0.0.0"], ["--port=8080"]):
        _never_clean(_pod([*BASE, *flags]), KAS, version=version)
        line = next(a for a in _r(_pod([*BASE, *flags]), version=version).assumptions if a.startswith(KAS))
        assert "refuses" in line and "1.20" in line
    # the address alone has no effect from 1.20, and port 0 is allowed: read as usual
    assert _clean(_r(_pod([*BASE, "--address=0.0.0.0", "--insecure-port=0"]), version=version), KAS)


@pytest.mark.parametrize("version", ["1.24", "1.33", None])
def test_any_insecure_flag_from_1_24_or_on_an_assumed_version_declines(version: str | None) -> None:
    for flag in ("--insecure-port=0", "--port=8080", "--address=0.0.0.0", "--insecure-bind-address=127.0.0.1"):
        _never_clean(_pod([*BASE, flag]), KAS, version=version)


# --- D2. configuration objects that write the flags: read where decisive, named where not ------------------------

_CAPI_KCP = """apiVersion: controlplane.cluster.x-k8s.io/v1beta1
kind: KubeadmControlPlane
metadata: {name: cp, namespace: default}
spec:
  kubeadmConfigSpec:
    clusterConfiguration:
      apiServer:
        extraArgs:
          authorization-mode: AlwaysAllow
"""
_CAPI_KCPT = """apiVersion: controlplane.cluster.x-k8s.io/v1beta1
kind: KubeadmControlPlaneTemplate
metadata: {name: cp, namespace: default}
spec:
  template:
    spec:
      kubeadmConfigSpec:
        clusterConfiguration:
          apiServer:
            extraArgs:
            - {name: authorization-mode, value: "Node,AlwaysAllow"}
"""
_CAPI_KC = """apiVersion: bootstrap.cluster.x-k8s.io/v1beta1
kind: KubeadmConfig
metadata: {name: c, namespace: default}
spec:
  clusterConfiguration:
    apiServer:
      extraArgs: {authorization_mode: AlwaysAllow}
"""
_CAPI_KCT = """apiVersion: bootstrap.cluster.x-k8s.io/v1beta1
kind: KubeadmConfigTemplate
metadata: {name: c, namespace: default}
spec:
  template:
    spec:
      clusterConfiguration:
        apiServer:
          extraArgs: {authorization-mode: AlwaysAllow}
"""
_KIND = """apiVersion: kind.x-k8s.io/v1alpha4
kind: Cluster
kubeadmConfigPatches:
- |
  kind: ClusterConfiguration
  apiServer:
    extraArgs:
      authorization-mode: AlwaysAllow
nodes:
- role: control-plane
"""
_K0S = """apiVersion: k0s.k0sproject.io/v1beta1
kind: ClusterConfig
metadata: {name: k0s, namespace: kube-system}
spec:
  api:
    extraArgs:
      authorization-mode: AlwaysAllow
"""
_CM = """apiVersion: v1
kind: ConfigMap
metadata: {name: kubeadm-config, namespace: kube-system}
data:
  ClusterConfiguration: |
    apiVersion: kubeadm.k8s.io/v1beta3
    kind: ClusterConfiguration
    apiServer:
      extraArgs:
        authorization-mode: AlwaysAllow
"""
_RANCHER = """apiVersion: provisioning.cattle.io/v1
kind: Cluster
metadata: {name: c, namespace: fleet-default}
spec:
  rkeConfig:
    machineGlobalConfig:
      kube-apiserver-arg: [authorization-mode=AlwaysAllow]
"""
_CC4 = """apiVersion: kubeadm.k8s.io/v1beta4
kind: ClusterConfiguration
apiServer:
  extraArgs:
  - {name: authorization-mode, value: Node,RBAC}
  - {name: authorization-mode, value: AlwaysAllow}
"""


@pytest.mark.parametrize("text", [_CAPI_KCP, _CAPI_KCPT, _CAPI_KC, _CAPI_KCT, _KIND, _K0S, _CM, _RANCHER, _CC4])
def test_a_configuration_object_that_sets_always_allow_is_a_finding(text: str) -> None:
    for bundle in (text, GOOD_KAS + "---\n" + text):
        hits = _hits(_r(bundle), KAS)
        assert [h.severity for h in hits] == [Severity.CRITICAL], bundle
        assert "AlwaysAllow" in hits[0].message


@pytest.mark.parametrize(
    "text",
    [
        _CAPI_KCP.replace("authorization-mode: AlwaysAllow", "authorization-mode: Node,RBAC"),
        _K0S.replace("AlwaysAllow", "Node,RBAC"),
        _CM.replace("AlwaysAllow", "Node,RBAC"),
        _RANCHER.replace("AlwaysAllow", "Node,RBAC"),
        _KIND.replace("AlwaysAllow", "Node,RBAC"),
    ],
)
def test_a_configuration_object_that_does_not_decide_on_its_own_is_named_as_not_read(text: str) -> None:
    _never_clean(text, KAS)
    report = _r(text)
    assert report.as_dict()["declined"][KAS]["entries"]


def test_an_explicit_anonymous_true_in_a_configuration_object_is_a_finding_and_the_rest_declines() -> None:
    text = _CAPI_KCP.replace("authorization-mode: AlwaysAllow", "anonymous-auth: 'true'")
    report = _r(text)
    assert [h.severity for h in _hits(report, KAS)] == [Severity.MEDIUM]
    assert report.as_dict()["controlSummary"]["partlyEvaluatedRules"] == [KAS]


def test_kubeadm_etcd_extra_args_on_a_network_plaintext_url_are_a_finding() -> None:
    text = (
        "apiVersion: kubeadm.k8s.io/v1beta3\nkind: ClusterConfiguration\netcd:\n  local:\n    extraArgs:\n"
        "      listen-client-urls: http://0.0.0.0:2379\n"
    )
    for bundle in (text, GOOD_ETCD + "---\n" + text):
        assert [h.severity for h in _hits(_r(bundle), ETCD)] == [Severity.CRITICAL]


def test_an_unparseable_embedded_configuration_declines() -> None:
    _never_clean(_CM.replace("    apiVersion: kubeadm.k8s.io/v1beta3", "    apiVersion: [unclosed"), KAS)


def test_a_configmap_of_another_name_is_not_a_kubeadm_config() -> None:
    report = _r(_CM.replace("kubeadm-config", "something-else"))
    assert not any(a.startswith(KAS) for a in report.assumptions)


# --- D3. evidence inside scripts and env ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("rid", "text"),
    [
        (KAS, _pod(["sh", "-c", "exec /opt/k8s/kube-apiserver " + BADA], image=GEN)),  # A27
        (
            KAS,
            _pod(
                ["sh", "-c", "exec ${KAS_BIN} " + BADA],
                image=GEN,
                env=[{"name": "KAS_BIN", "valueFrom": {"configMapKeyRef": {"name": "c", "key": "bin"}}}],
            ),
        ),  # A28
        (KAS, _pod(["/bin/busybox", "sh", "-c", "/opt/k/kube-apiserver " + BADA], image="busybox:1.36")),  # A29
        (
            KAS,
            _pod(["$(BIN)"], ["--secure-port=6443"], image=GEN, env=[{"name": "BIN", "value": "/opt/kube-apiserver"}]),
        ),
        (KAS, _pod(["sh", "-c", 'exec "$BIN" --authorization-mode=AlwaysAllow'], image="myreg/x:1")),  # q1e
        (KAS, _pod(["sh", "-c", "k''ube-apiserver " + BADA.split()[1]], image=GEN)),
        (ETCD, _pod(["sh", "-c", "exec /opt/etcd/etcd " + BADE], image=GEN)),  # E2
        (
            ETCD,
            _pod(
                ["/opt/start"],
                image="myreg/kv:1",
                extra={"envFrom": [{"prefix": "ETCD_", "configMapRef": {"name": "e"}}]},
            ),
        ),  # E3
        (ETCD, _pod(["sh", "-c", 'exec "et"cd'], image=GEN)),
        (ETCD, _pod(["sh", "-c", "\\etcd"], image=GEN)),
    ],
)
def test_evidence_inside_scripts_and_env_is_found(rid: str, text: str) -> None:
    _never_clean(text, rid)


@pytest.mark.parametrize(
    "command",
    [
        ["tar", "czf", "/b/x.tgz", "/var/lib/etcd"],
        ["sh", "-c", "tar czf /b/x.tgz /var/lib/etcd"],
        ["sh", "-c", "cp -r /var/lib/etcd /backup && echo done"],
    ],
)
def test_a_data_directory_in_argument_position_is_still_not_etcd(command: list[str]) -> None:
    assert _clean(_r(GOOD_ETCD + "---\n" + _pod(command, image="busybox:1.36")), ETCD)


# --- D4. hyperkube images by component ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "image",
    [
        "k8s.gcr.io/hyperkube-amd64:v1.15.0",
        "docker.io/openshift/origin-hyperkube:v3.11",
        "registry.redhat.io/ose-hyperkube:v4",
    ],
)
def test_a_hyperkube_image_by_component_is_apiserver_evidence(image: str) -> None:
    _never_clean(_pod(None, ["apiserver", "--secure-port=6443"], image=image), KAS)


# --- D5. no utility that can run another program is "safe", and quoting does not hide a name --------------------


@pytest.mark.parametrize(
    "script",
    [
        "tar -xf /b.tar --to-command='/usr/local/bin/e''tcd'",
        "sort --compress-program=/usr/local/bin/e?cd /x",
        "find /usr/local/bin -name x -exec rm {} +",
        "etcdctl snapshot save /b/s.db && find /b -mtime +7 -delete",
    ],
)
def test_an_etcd_image_script_with_a_utility_that_can_run_programs_declines(script: str) -> None:
    _never_clean(_pod(["sh", "-c", script], image="registry.k8s.io/etcd:3.5.15-0"), ETCD)


# --- list kinds, PodTemplate, the gate HTML, KSI truncation, Windows -------------------------------------------------

_KAS_POD_ITEM = {
    "apiVersion": "v1",
    "kind": "Pod",
    "metadata": {"name": "w", "namespace": "kube-system"},
    "spec": {"containers": [{"name": "a", "image": "x", "command": ["kube-apiserver", *BADA.split()]}]},
}


@pytest.mark.parametrize("kind", ["PodList", "DeploymentList", "List"])
def test_a_typed_list_is_unwrapped(kind: str) -> None:
    item = _KAS_POD_ITEM
    if kind == "DeploymentList":
        item = {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "w", "namespace": "kube-system"},
            "spec": {
                "selector": {"matchLabels": {"a": "b"}},
                "template": {"metadata": {"labels": {"a": "b"}}, "spec": item["spec"]},
            },
        }
    text = yaml.safe_dump({"apiVersion": "v1", "kind": kind, "items": [item]}, sort_keys=False)
    for bundle in (text, GOOD_KAS + "---\n" + text):
        assert [h.severity for h in _hits(_r(bundle), KAS)] == [Severity.CRITICAL]


@pytest.mark.parametrize(
    "text",
    [
        "apiVersion: v1\nkind: PodList\nitems: {not: a list}\n",
        "apiVersion: v1\nkind: PodList\nitems:\n- 7\n- metadata: {name: w, namespace: kube-system}\n"
        "  spec: {containers: []}\n",
    ],
)
def test_a_list_kind_whose_items_cannot_all_be_read_declines(text: str) -> None:
    _never_clean(text, KAS)
    _never_clean(text, ETCD)


def test_a_typed_list_item_without_a_kind_takes_the_lists_kind() -> None:
    """The API server's own list responses carry no kind on items; kubectl adds one. Both are the same pods."""
    item = {k: v for k, v in _KAS_POD_ITEM.items() if k not in {"kind", "apiVersion"}}
    text = yaml.safe_dump({"apiVersion": "v1", "kind": "PodList", "items": [item]}, sort_keys=False)
    report = _r(text)
    assert report.resources == ["Pod/kube-system/w"]
    assert [h.severity for h in _hits(report, KAS)] == [Severity.CRITICAL]


def test_a_pod_template_is_audited() -> None:
    text = yaml.safe_dump(
        {
            "apiVersion": "v1",
            "kind": "PodTemplate",
            "metadata": {"name": "w", "namespace": "kube-system"},
            "template": {"metadata": {"labels": {"a": "b"}}, "spec": _KAS_POD_ITEM["spec"]},
        },
        sort_keys=False,
    )
    for bundle in (text, GOOD_KAS + "---\n" + text):
        assert [h.severity for h in _hits(_r(bundle), KAS)] == [Severity.CRITICAL]


def test_the_gate_html_names_not_evaluated_and_partly_evaluated_rules() -> None:
    from kube_noob import gate
    from kube_noob.report_html import render

    bundle = _pod(["kube-apiserver", "--authorization-mode=AlwaysAllow"], name="a") + "---\n"
    bundle += _pod(["sh", "-c", "kube-apiserver"], name="b")
    page = render(gate.run([gate.Source("b.yaml", bundle)], fail_on="never"))
    assert "partly evaluated: KN-S038" in page and "not evaluated: " in page


def test_the_ksi_row_says_how_many_partly_evaluated_rules_it_withheld() -> None:
    from kube_noob.audit import fedramp
    from kube_noob.audit.controls import RULE_CONTROLS

    every = sorted(RULE_CONTROLS)
    rows = fedramp.summary(every, evaluated_rule_ids=[])["indicators"]
    long = [r for r in rows if r.get("rulesBehind", 0) > fedramp.MAX_NAMED_RULES]
    assert long
    for row in long:
        assert len(row["partlyEvaluatedRules"]) == fedramp.MAX_NAMED_RULES
        assert row["morePartlyEvaluated"] == row["rulesBehind"] - fedramp.MAX_NAMED_RULES


@pytest.mark.parametrize(
    "command",
    [
        ["cmd", "/c", "kube-apiserver.exe " + BADA],
        ["C:\\k\\kube-apiserver.exe", "--secure-port=6443"],
        ["powershell", "-Command", "& C:\\k\\kube-apiserver.exe --secure-port=6443"],
    ],
)
def test_a_windows_launch_of_the_apiserver_declines(command: list[str]) -> None:
    _never_clean(_pod(command, image="mcr.microsoft.com/windows/nanoserver:ltsc2022"), KAS)


def test_json_is_unchanged_for_a_bundle_with_no_control_plane() -> None:
    report = _r(_pod(["nginx"], image="nginx:1"))
    assert json.dumps(report.as_dict()["controlSummary"]["partlyEvaluatedRules"]) == "[]"
