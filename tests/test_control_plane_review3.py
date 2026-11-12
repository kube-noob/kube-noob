"""The third adversarial review of KN-S037..KN-S041 (G272): recognition made fail-safe, and partial verdicts named.

Three rounds found launch shapes that were silently "not a server", so beside one clean API server or etcd the
rule read clean. The structural answer: a container is "not this server" only when nothing points at the binary
-- no image, no flag, no ETCD_* variable, no mention in argv, args, env or a script -- or when it is positively
something else (etcdctl, `k3s agent`, a backup script made only of etcdctl and coreutils). Every other shape is
read or declined. And a rule that declined on any object is never clean at rule level: with no finding it is in
`notEvaluatedRules`, with one it is in `partlyEvaluatedRules`, and the `declined` map says how many objects it did
read in full.
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
    env_from: bool = False,
) -> str:
    c: dict[str, Any] = {"name": "c", "image": image}
    if command is not None:
        c["command"] = command
    if args is not None:
        c["args"] = args
    if env is not None:
        c["env"] = env
    if env_from:
        c["envFrom"] = [{"configMapRef": {"name": "x"}}]
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


def _quiet(report: Report, rid: str) -> bool:
    return rid not in report.evaluated_rules and not any(a.startswith(rid) for a in report.assumptions)


KAS = "KN-S038"
ETCD = "KN-S039"
AA = "--authorization-mode=AlwaysAllow"
KAS_IMAGE = "registry.k8s.io/kube-apiserver:v1.34.0"
ETCD_IMAGE = "registry.k8s.io/etcd:3.5.15-0"
GOOD_KAS = _pod(["kube-apiserver", "--authorization-mode=Node,RBAC", "--anonymous-auth=false"], name="good")
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
PLAIN_ENV = [{"name": "ETCD_LISTEN_CLIENT_URLS", "value": "http://0.0.0.0:2379"}]


def _never_clean(text: str, rid: str, good: str, platform: str = "kubernetes", version: str | None = None) -> None:
    """The structural property: alone and beside a clean neighbour, the rule is never clean at rule level."""
    for bundle in (text, good + "---\n" + text):
        report = _r(bundle, platform, version)
        assert not _clean(report, rid), bundle
        if bundle is not text:
            assert _declined(report, rid) or _hits(report, rid), bundle


# --- S. a rule that declined on any object is never clean; a partly evaluated rule is named ---------------------


def test_a_rule_with_a_finding_and_a_decline_is_partly_evaluated_everywhere() -> None:
    from kube_noob.audit.controls import summary
    from kube_noob.audit.fedramp import summary as ksi

    bundle = _pod(["kube-apiserver", AA], name="a") + "---\n" + _pod(["sh", "-c", "kube-apiserver"], name="b")
    report = _r(bundle)
    out = report.as_dict()
    cs = out["controlSummary"]
    assert cs["partlyEvaluatedRules"] == ["KN-S038"] and "KN-S038" not in cs["notEvaluatedRules"]
    assert next(c for c in cs["controls"] if c["id"] == "AC-3")["findings"] >= 1
    assert out["declined"]["KN-S038"]["decided"] == 1
    assert "1 other object" in next(a for a in report.assumptions if a.startswith("KN-S038"))
    direct = summary([f.rule_id for f in report.findings], None, report.evaluated_rules, report.fired_rules)
    assert direct["partlyEvaluatedRules"] == ["KN-S038"]
    rows = ksi([f.rule_id for f in report.findings], evaluated_rule_ids=report.evaluated_rules)["indicators"]
    assert any("KN-S038" in r.get("partlyEvaluatedRules", []) for r in rows)


def test_a_rule_clean_on_one_object_and_declined_on_another_is_not_clean_and_says_both() -> None:
    report = _r(GOOD_KAS + "---\n" + _pod(["sh", "-c", "kube-apiserver"], name="b"))
    out = report.as_dict()
    assert not _clean(report, KAS) and "KN-S038" in out["controlSummary"]["notEvaluatedRules"]
    assert out["declined"]["KN-S038"]["decided"] == 1


def test_the_text_view_and_the_gate_name_partly_evaluated_rules(tmp_path: Any, capsys: Any) -> None:
    from kube_noob import gate
    from kube_noob.cli import main

    bundle = _pod(["kube-apiserver", AA], name="a") + "---\n" + _pod(["sh", "-c", "kube-apiserver"], name="b")
    path = tmp_path / "b.yaml"
    path.write_text(bundle, encoding="utf-8")
    main(["audit", "-f", str(path), "--fail-on", "never"])
    out = capsys.readouterr().out
    assert any(ln.strip().startswith("partly evaluated: KN-S038") for ln in out.splitlines()), out
    md = gate.markdown(gate.run([gate.Source("b.yaml", bundle)], fail_on="never"))
    assert "partly evaluated: KN-S038" in md.split("### Not evaluated in full", 1)[1]


# --- 1. `command: []` runs the image's entrypoint, like no command at all ----------------------------------------


@pytest.mark.parametrize(
    ("rid", "text", "good"),
    [
        (KAS, _pod([], [AA], image="myreg/custom-api:1"), GOOD_KAS),
        (KAS, _pod([], ["--etcd-servers=https://e:2379", AA], image="myreg/api:1"), GOOD_KAS),
        (ETCD, _pod([], ["--listen-client-urls=http://0.0.0.0:2379"], image="myreg/kv:1"), GOOD_ETCD),
        (ETCD, _pod([], None, image="myreg/kv:1", env=PLAIN_ENV), GOOD_ETCD),
    ],
)
def test_an_empty_command_list_takes_the_image_entrypoint_branch(rid: str, text: str, good: str) -> None:
    _never_clean(text, rid, good)
    line = next(a for a in _r(text).assumptions if a.startswith(rid))
    assert "entrypoint" in line and "refuses" not in line


# --- 2. a binary path at the end of a script, and ETCD_* env as evidence -----------------------------------------


@pytest.mark.parametrize(
    "script",
    [
        "exec /usr/local/bin/etcd",
        "/usr/local/bin/etcd",
        "mkdir -p /d && /usr/local/bin/etcd",
        "/usr/local/bin/etcd\n",
        "true; /usr/local/bin/etcd;",
        "if true; then /usr/local/bin/etcd; fi",
    ],
)
def test_a_script_that_runs_etcd_by_path_at_its_end_declines(script: str) -> None:
    _never_clean(_pod(["/bin/sh", "-c", script], image="myreg/kv:1", env=PLAIN_ENV), ETCD, GOOD_ETCD)
    _never_clean(_pod(["/bin/sh", "-c", script], image="myreg/kv:1"), ETCD, GOOD_ETCD)


@pytest.mark.parametrize(
    "script",
    [
        "exec /usr/local/bin/kube-apiserver",
        "/usr/local/bin/kube-apiserver;",
        "/usr/local/bin/kube-apiserver\n",
        "exec ${KAS:-kube-apiserver}",
        'exec /bin/kube-apiserver"$@"',
    ],
)
def test_a_script_that_runs_the_apiserver_by_path_at_its_end_declines(script: str) -> None:
    _never_clean(_pod(["sh", "-c", script], image="myreg/x:1"), KAS, GOOD_KAS)


@pytest.mark.parametrize("command", [["/opt/start.sh"], ["tini", "--", "/opt/start.sh"], ["/app/run"]])
def test_etcd_variables_are_evidence_for_an_unread_entrypoint(command: list[str]) -> None:
    _never_clean(_pod(command, image="myreg/kv:1", env=PLAIN_ENV), ETCD, GOOD_ETCD)


# --- 3. k3s, rke2 and k0s: the subcommand after global flags, through launchers, and read when it says ----------


@pytest.mark.parametrize(
    "command",
    [
        ["k3s", "--debug", "server"],
        ["k3s", "--data-dir", "/data", "server"],
        ["env", "FOO=1", "k3s", "server"],
        ["busybox", "env", "k3s", "server"],
        ["/sbin/tini", "--", "k3s", "server"],
        ["sh", "-c", "exec k3s server"],
        ["k3s", "--unknown-global", "x", "server"],
    ],
)
def test_an_embedding_server_is_found_after_global_flags_and_launchers(command: list[str]) -> None:
    _never_clean(_pod(command, image="myreg/k8s:1"), KAS, GOOD_KAS)


@pytest.mark.parametrize(
    "command",
    [
        ["k3s", "server", "--kube-apiserver-arg=authorization-mode=AlwaysAllow"],
        ["k3s", "server", "--kube-apiserver-arg", "authorization_mode=Node,AlwaysAllow"],
        ["env", "A=1", "k3s", "--debug", "server", "--kube-apiserver-arg=authorization-mode=AlwaysAllow"],
        ["rke2", "server", "--kube-apiserver-arg=authorization-mode=AlwaysAllow"],
    ],
)
def test_an_embedded_always_allow_is_read_as_a_finding(command: list[str]) -> None:
    hits = _hits(_r(_pod(command, image="rancher/k3s:v1.30.1-k3s1")), KAS)
    assert [h.severity for h in hits] == [Severity.CRITICAL] and "AlwaysAllow" in hits[0].message


def test_an_embedded_server_through_a_script_is_declined_not_skipped() -> None:
    text = _pod(["sh", "-c", "exec k3s server --kube-apiserver-arg=authorization-mode=AlwaysAllow"], image="x:1")
    _never_clean(text, KAS, GOOD_KAS)


def test_a_k3s_image_is_not_called_the_apiservers_image() -> None:
    line = next(a for a in _r(_pod(["/opt/run.sh"], image="rancher/k3s:v1.30.1-k3s1")).assumptions if "KN-S038" in a)
    assert "kube-apiserver's" not in line and "k3s" in line


@pytest.mark.parametrize("command", [["k3s", "agent"], ["k3s", "--debug", "agent"], ["k3s", "kubectl", "get", "po"]])
def test_an_embedding_binary_with_another_subcommand_is_positively_not_a_server(command: list[str]) -> None:
    assert _quiet(_r(_pod(command, image="rancher/k3s:v1.30.1-k3s1")), KAS)


# --- 4. a path that merely ends in /etcd is not etcd; an etcdctl-only script on the etcd image is not either ---


@pytest.mark.parametrize(
    ("command", "image"),
    [
        (["tar", "czf", "/b/x.tgz", "/var/lib/etcd"], "busybox:1.36"),
        (["cp", "-r", "/var/lib/etcd", "/backup"], "busybox:1.36"),
        (["restic", "backup", "/var/lib/etcd"], "restic/restic:0.16"),
        (["/velero", "backup", "--path=/var/lib/etcd"], "velero/velero:v1.13"),
        (["/opt/run.sh", "--data-dir=/var/lib/etcd"], "myreg/x:1"),
        (["etcdutl", "snapshot", "restore", "/b/s.db", "--data-dir", "/var/lib/etcd"], ETCD_IMAGE),
        (["etcdctl", "snapshot", "save", "/b"], ETCD_IMAGE),
        (
            [
                "/bin/sh",
                "-c",
                "ETCDCTL_API=3 etcdctl --endpoints=https://127.0.0.1:2379 --cacert=/etc/kubernetes/pki/etcd/ca.crt "
                "snapshot save /backup/etcd-$(date +%F).db",
            ],
            ETCD_IMAGE,
        ),
        (["sh", "-c", "until etcdctl endpoint health; do sleep 1; done"], "quay.io/coreos/etcd:v3.5.9"),
    ],
)
def test_what_is_positively_not_etcd_is_not_recognised(command: list[str], image: str) -> None:
    report = _r(_pod(command, image=image))
    assert _quiet(report, ETCD), report.assumptions
    assert _clean(_r(GOOD_ETCD + "---\n" + _pod(command, image=image)), ETCD)


@pytest.mark.parametrize(
    "script",
    [
        "etcdctl snapshot save /b && /opt/other.sh",
        'etcdctl endpoint health; exec "$@"',
        ". /env; etcdctl member list",
        'eval "$CMD"',
        "for f in a; do etcdctl get $f; done",
    ],
)
def test_an_etcd_image_script_that_runs_anything_else_declines(script: str) -> None:
    _never_clean(_pod(["sh", "-c", script], image=ETCD_IMAGE), ETCD, GOOD_ETCD)


@pytest.mark.parametrize(
    "command",
    [
        ["/opt/bitnami/scripts/etcd/snapshot.sh"],
        ["/opt/bitnami/scripts/etcd/entrypoint.sh", "/opt/bitnami/scripts/etcd/preupgrade.sh"],
    ],
)
def test_a_script_file_on_the_etcd_image_declines(command: list[str]) -> None:
    _never_clean(_pod(command, image="docker.io/bitnami/etcd:3.5.9"), ETCD, GOOD_ETCD)


# --- 5. ABAC and Webhook decide from a file not in the input -----------------------------------------------------


@pytest.mark.parametrize(
    "flags",
    [
        ["--authorization-mode=Node,ABAC,RBAC", "--authorization-policy-file=/p"],
        ["--authorization-mode=Node,Webhook,RBAC", "--authorization-webhook-config-file=/w"],
    ],
)
def test_abac_or_webhook_declines_the_authorizer_and_still_reads_anonymous(flags: list[str]) -> None:
    report = _r(_pod(["kube-apiserver", *flags]))
    assert _declined(report, KAS)
    assert [h.severity for h in _hits(report, KAS)] == [Severity.MEDIUM]  # anonymous default still read
    assert not _hits(_r(_pod(["kube-apiserver", *flags, "--anonymous-auth=false"])), KAS)
    assert not _clean(_r(GOOD_KAS + "---\n" + _pod(["kube-apiserver", *flags, "--anonymous-auth=false"])), KAS)


# --- 6. an empty --config-file falls through to ETCD_CONFIG_FILE --------------------------------------------------


@pytest.mark.parametrize("flag", ["--config-file=", "-config-file="])
def test_an_empty_config_file_flag_falls_through_to_the_variable(flag: str) -> None:
    text = _pod(["etcd", flag, *TLS], env=[{"name": "ETCD_CONFIG_FILE", "value": "/etc/etcd/etcd.yaml"}])
    _never_clean(text, ETCD, GOOD_ETCD)
    assert any("config" in a for a in _r(text).assumptions if a.startswith(ETCD))


def test_an_empty_config_file_with_no_variable_is_read() -> None:
    assert _clean(_r(_pod(["etcd", "--config-file=", *TLS])), ETCD)


# --- 7. the gate's Assumptions section holds only the assumed version --------------------------------------------


def test_the_gate_assumptions_section_is_an_allowlist() -> None:
    from kube_noob import gate

    ray = (
        "apiVersion: example.com/v1\nkind: RayCluster\nmetadata: {name: r, namespace: ml}\nspec:\n  headGroupSpec:\n"
        "    template:\n      spec:\n        containers:\n        - {name: h, image: rayproject/ray:2.9}\n"
    )
    crd = "apiVersion: example.com/v1\nkind: Widget\nmetadata: {name: w, namespace: shop}\n"
    report = gate.run([gate.Source("a.yaml", ray + "---\n" + crd)], fail_on="never")
    md = gate.markdown(report)
    head, _, rest = md.partition("### Not evaluated in full")
    assumptions = head.split("### Assumptions", 1)[1] if "### Assumptions" in head else ""
    items = [ln for ln in assumptions.splitlines() if ln.startswith("- ")]
    assert items and all(
        ln.startswith(("- No Kubernetes version given", "- No OpenShift version given")) for ln in items
    )
    others = [a for a in report["assumptions"] if not a.startswith("No ")]
    assert others and len([ln for ln in rest.splitlines() if ln.startswith("- ")]) >= len(others)


# --- 8. --insecure-port: a CRITICAL finding before 1.24, a decline after ------------------------------------------


def test_the_insecure_port_on_a_network_address_up_to_1_19_is_critical() -> None:
    """Corrected by the fourth review: 1.20-1.23 REFUSE a non-zero insecure port (checkNonZeroInsecurePort), so
    the finding is for a stated 1.19 or older; tests/test_control_plane_review4.py holds the whole version table."""
    argv = ["kube-apiserver", "--authorization-mode=Node,RBAC", "--anonymous-auth=false"]
    text = _pod([*argv, "--insecure-port=8080", "--insecure-bind-address=0.0.0.0"])
    hits = _hits(_r(text, version="1.19"), KAS)
    assert [h.severity for h in hits] == [Severity.CRITICAL] and "insecure port" in hits[0].message
    assert not _hits(_r(_pod([*argv, "--insecure-port=0", "--insecure-bind-address=0.0.0.0"]), version="1.19"), KAS)
    assert _clean(_r(_pod([*argv, "--insecure-port=8080"]), version="1.19"), KAS)  # bound to 127.0.0.1
    assert _declined(_r(text, version="1.22"), KAS)


@pytest.mark.parametrize("version", ["1.24", "1.33", None])
def test_the_insecure_port_on_a_release_that_removed_it_declines(version: str | None) -> None:
    argv = ["kube-apiserver", "--authorization-mode=Node,RBAC", "--anonymous-auth=false", "--insecure-port=8080"]
    _never_clean(_pod([*argv, "--insecure-bind-address=0.0.0.0"]), KAS, GOOD_KAS, version=version)
    line = next(a for a in _r(_pod(argv), version=version).assumptions if a.startswith(KAS))
    assert "1.24" in line


# --- 9. image names: a dash-separated component, not a substring ---------------------------------------------------


@pytest.mark.parametrize(
    ("rid", "image", "good"),
    [
        (ETCD, "k8s.gcr.io/etcd-amd64:3.2.24", GOOD_ETCD),
        (ETCD, "rancher/hardened-etcd:v3.5.13-k3s1", GOOD_ETCD),
        (ETCD, "rancher/mirrored-coreos-etcd:v3.5.9", GOOD_ETCD),
        (KAS, "k8s.gcr.io/kube-apiserver-amd64:v1.15.0", GOOD_KAS),
        (KAS, "k8s.gcr.io/hyperkube:v1.18.0", GOOD_KAS),
        (KAS, "rancher/hardened-kubernetes:v1.30.1-rke2r1", GOOD_KAS),
    ],
)
def test_an_image_whose_name_has_the_binary_as_a_component_is_evidence(rid: str, image: str, good: str) -> None:
    _never_clean(_pod(None, ["--name=m", "--data-dir=/var/lib/etcd"], image=image), rid, good)
    _never_clean(_pod(None, ["--config-file=/etc/etcd/c.yaml"], image=image), rid, good)


@pytest.mark.parametrize("image", ["quay.io/coreos/etcd-operator:v0.9.4", "bitnami/etcd-exporter:1", "etcdctl:1"])
def test_an_image_that_only_contains_the_name_is_not(image: str) -> None:
    assert _quiet(_r(_pod(["/app/run", "--x=1"], image=image)), ETCD)


def test_config_file_is_etcd_evidence_for_a_script_entrypoint_only() -> None:
    _never_clean(_pod(["/opt/run.sh"], ["--config-file=/etc/etcd.conf"], image="myreg/kv:1"), ETCD, GOOD_ETCD)
    assert _quiet(_r(_pod(["/app/server", "--config-file=/etc/app.yaml"])), ETCD)


# --- 10. etcd 3.6: its booleans, and --enable-v2 which it refuses --------------------------------------------------


@pytest.mark.parametrize(
    "flag",
    [
        "--discovery-insecure-skip-tls-verify",
        "--discovery-insecure-transport",
        "--enable-distributed-tracing",
        "--memory-mlock",
        "--peer-skip-client-san-verification",
        "-v",
    ],
)
def test_an_etcd_3_6_boolean_given_bare_does_not_decline(flag: str) -> None:
    assert _clean(_r(_pod(["etcd", flag, *TLS], image="registry.k8s.io/etcd:3.6.4-0")), ETCD)


@pytest.mark.parametrize("image", ["registry.k8s.io/etcd:3.6.4-0", "myreg/etcd:latest", "img:1"])
def test_enable_v2_declines_unless_the_image_says_3_5_or_older(image: str) -> None:
    _never_clean(_pod(["etcd", "--enable-v2", *TLS], image=image), ETCD, GOOD_ETCD)
    assert _clean(_r(_pod(["etcd", "--enable-v2", *TLS], image="registry.k8s.io/etcd:3.5.15-0")), ETCD)


# --- 11. kubeadm and operator configuration objects are said to be unread -------------------------------------------

_CC4 = (
    "apiVersion: kubeadm.k8s.io/v1beta4\nkind: ClusterConfiguration\nkubernetesVersion: v1.34.0\napiServer:\n"
    "  extraArgs:\n  - {name: authorization-mode, value: AlwaysAllow}\n"
)
_CC3 = (
    "apiVersion: kubeadm.k8s.io/v1beta3\nkind: ClusterConfiguration\napiServer:\n  extraArgs:\n"
    "    authorization-mode: AlwaysAllow\netcd:\n  local:\n    extraArgs:\n      listen-client-urls: http://0.0.0.0:2379\n"
)
_KAS_CR = (
    "apiVersion: operator.openshift.io/v1\nkind: KubeAPIServer\nmetadata: {name: cluster}\nspec:\n"
    "  unsupportedConfigOverrides:\n    apiServerArguments:\n      authorization-mode: [AlwaysAllow]\n"
)


@pytest.mark.parametrize(("text", "rid"), [(_CC4, KAS), (_CC3, KAS), (_CC3, ETCD)])
def test_a_kubeadm_cluster_configuration_is_named_as_unread(text: str, rid: str) -> None:
    """Since the fourth review the decisive settings are READ (AlwaysAllow, a plaintext URL: findings); a
    ClusterConfiguration that sets nothing decisive is still named as not read."""
    assert [h.severity for h in _hits(_r(text), rid)] == [Severity.CRITICAL]
    assert not _clean(_r(text + "---\n" + (GOOD_KAS if rid == KAS else GOOD_ETCD)), rid)
    quiet = text.replace("AlwaysAllow", "Node,RBAC").replace("http://0.0.0.0:2379", "https://10.0.0.1:2379")
    report = _r(quiet)
    assert _declined(report, rid) and "ClusterConfiguration" in json.dumps(report.as_dict()["declined"][rid])


@pytest.mark.parametrize("platform", ["openshift", "kubernetes"])
def test_an_openshift_kubeapiserver_resource_is_named_as_unread(platform: str) -> None:
    report = _r(_KAS_CR, platform, "4.20" if platform == "openshift" else None)
    assert _declined(report, KAS) and "KubeAPIServer" in json.dumps(report.as_dict()["declined"][KAS])


# --- the rest of the third review's reproducers: never clean, alone or beside a clean neighbour --------------------


@pytest.mark.parametrize(
    "text",
    [
        _pod(None, ["--secure-port=6443", "--etcd-prefix=/r"], image="k8s.gcr.io/kube-apiserver-amd64:v1.15.0"),
        _pod(None, ["kube-apiserver", "--secure-port=6443"], image="k8s.gcr.io/hyperkube:v1.18.0"),
        _pod(None, ["kube-apiserver"], image="k8s.gcr.io/hyperkube:v1.18.0"),
        _pod(None, ["apiserver", "--secure-port=6443"], image="k8s.gcr.io/hyperkube:v1.18.0"),
        _pod(["sh", "-c", "exec /usr/local/bin/kube-apiserver\t--authorization-mode=AlwaysAllow"], image="x:1"),
        _pod(["nsenter", "-t", "1", "-m", "--", "/usr/bin/kube-apiserver"], image="x:1"),
        _pod(["chroot", "/host", "kube-apiserver"], image="x:1"),
    ],
)
def test_the_apiserver_reproducers_are_never_clean(text: str) -> None:
    _never_clean(text, KAS, GOOD_KAS)


@pytest.mark.parametrize(
    "text",
    [
        _pod([], ["--listen-client-urls=http://0.0.0.0:2379"], image="myreg/kv:1"),
        _pod(["/opt/run.sh"], ["--config-file=/etc/etcd.conf"], image="myreg/kvstore:1"),
        _pod(["etcd", *TLS], env_from=True),
        _pod(["etcd", "--config-file=", *TLS], env=[{"name": "ETCD_CONFIG_FILE", "value": "/e.yaml"}]),
    ],
)
def test_the_etcd_reproducers_are_never_clean(text: str) -> None:
    _never_clean(text, ETCD, GOOD_ETCD)
