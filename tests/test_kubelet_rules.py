"""KN-S042..KN-S045: the kubelet's authentication, authorization, node hardening and serving TLS (G302).

The kubelet is the component a cluster has most copies of and the one nothing in this catalogue read. It is
configured in five shapes a real fleet uses -- a `KubeletConfiguration` object, the same object inside a kubeadm
bundle, a static pod or DaemonSet whose command is the kubelet, OpenShift's `KubeletConfig` CR, and a
`MachineConfig` whose embedded ignition carries `kubelet.conf` -- and the shape decides which upstream defaults
apply to a setting nobody stated. Each rule is held three ways: it fires on the bad shape, it is silent on the
good one, and where it cannot decide it DECLINES with a reason rather than reading as clean.

The two default tables are the point. `cmd/kubelet/app/options/options.go` `applyLegacyDefaults` gives the
COMMAND LINE `--anonymous-auth=true`, `--authorization-mode=AlwaysAllow` and `--read-only-port=10255`;
`pkg/kubelet/apis/config/v1beta1/defaults.go` gives a `KubeletConfiguration` FILE `anonymous.enabled: false`,
`authorization.mode: Webhook` and `readOnlyPort: 0`. A reader that used one table for both would report a
finding on a file that is safe, or pass a command line that is not.
"""

from __future__ import annotations

import base64
import gzip
import json
from typing import Any
from urllib.parse import quote

import pytest
import yaml

from kube_noob.audit.engine import analyze
from kube_noob.audit.model import Report, Severity

KUBELET_RULES = ("KN-S042", "KN-S043", "KN-S044", "KN-S045")


def _report(text: str, platform: str = "kubernetes", version: str | None = None) -> Report:
    return analyze(text, platform, version)


def _hits(report: Report, rule_id: str) -> list[Any]:
    return [f for f in report.findings if f.rule_id == rule_id]


def _declined(report: Report, rule_id: str) -> bool:
    said = any(a.startswith(f"{rule_id} was not evaluated") for a in report.assumptions)
    return rule_id not in report.evaluated_rules and said


def _clean(report: Report, rule_id: str) -> bool:
    return rule_id in report.evaluated_rules and not _hits(report, rule_id)


def _not_evaluated(report: Report, rule_id: str) -> bool:
    """A rule with no subject in the input: out of the evaluated list and silent, never clean.

    It declines QUIETLY, as `KN-S037` does with no APIService: there is nothing to name, so there is no reason
    to print. What makes the absent subject say its own name in the report is G281's `absent_subjects`, which is
    not on this branch.
    """
    return rule_id not in report.evaluated_rules and not _hits(report, rule_id)


def _why(report: Report, rule_id: str) -> str:
    return " ".join(a for a in report.assumptions if a.startswith(f"{rule_id} was not evaluated"))


# --- the five shapes a fleet actually produces ------------------------------------------------------


def _argv(*flags: str, kind: str = "Pod", name: str = "kubelet") -> str:
    container: dict[str, Any] = {
        "name": name,
        "image": "registry.k8s.io/kubelet:v1.35.0",
        "command": ["kubelet", *flags],
    }
    spec = {"hostNetwork": True, "containers": [container]}
    if kind == "DaemonSet":
        doc = {
            "apiVersion": "apps/v1",
            "kind": "DaemonSet",
            "metadata": {"name": name, "namespace": "kube-system"},
            "spec": {
                "selector": {"matchLabels": {"app": name}},
                "template": {"metadata": {"labels": {"app": name}}, "spec": spec},
            },
        }
    else:
        doc = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "namespace": "kube-system"}, "spec": spec}
    return yaml.safe_dump(doc, sort_keys=False)


def _config(**fields: Any) -> str:
    doc = {"apiVersion": "kubelet.config.k8s.io/v1beta1", "kind": "KubeletConfiguration", **fields}
    return yaml.safe_dump(doc, sort_keys=False)


def _kubeadm_bundle(**fields: Any) -> str:
    init = {
        "apiVersion": "kubeadm.k8s.io/v1beta4",
        "kind": "InitConfiguration",
        "metadata": {"name": "config"},
        "nodeRegistration": {"criSocket": "unix:///run/containerd/containerd.sock"},
    }
    return yaml.safe_dump(init, sort_keys=False) + "---\n" + _config(**fields)


def _kubeletconfig_cr(**fields: Any) -> str:
    doc = {
        "apiVersion": "machineconfiguration.openshift.io/v1",
        "kind": "KubeletConfig",
        "metadata": {"name": "set-kubelet-config"},
        "spec": {
            "machineConfigPoolSelector": {
                "matchLabels": {"pools.operator.machineconfiguration.openshift.io/worker": ""}
            },
            "kubeletConfig": dict(fields),
        },
    }
    return yaml.safe_dump(doc, sort_keys=False)


def _machineconfig(source: str, path: str = "/etc/kubernetes/kubelet.conf", **file_fields: Any) -> str:
    doc = {
        "apiVersion": "machineconfiguration.openshift.io/v1",
        "kind": "MachineConfig",
        "metadata": {"name": "99-worker-kubelet", "labels": {"machineconfiguration.openshift.io/role": "worker"}},
        "spec": {
            "config": {
                "ignition": {"version": "3.4.0"},
                "storage": {"files": [{"path": path, "mode": 420, "contents": {"source": source, **file_fields}}]},
            }
        },
    }
    return yaml.safe_dump(doc, sort_keys=False)


def _data_url(text: str, *, gzipped: bool = False) -> str:
    raw = text.encode("utf-8")
    if gzipped:
        return "data:;base64," + base64.b64encode(gzip.compress(raw)).decode("ascii")
    return "data:," + quote(text, safe="")


def _ignition_kubelet(**fields: Any) -> str:
    return _machineconfig(
        _data_url(json.dumps({"kind": "KubeletConfiguration", "apiVersion": "kubelet.config.k8s.io/v1beta1", **fields}))
    )


# =====================================================================================================
# A rule whose subject is absent is not evaluated, never clean (class 14)
# =====================================================================================================


@pytest.mark.parametrize("rule_id", KUBELET_RULES)
def test_a_bundle_with_no_kubelet_in_it_does_not_make_the_kubelet_rules_clean(rule_id: str) -> None:
    report = _report(yaml.safe_dump({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "c"}, "data": {}}))
    assert _not_evaluated(report, rule_id)


@pytest.mark.parametrize("rule_id", KUBELET_RULES)
def test_a_kubeletconfig_of_another_group_is_not_the_openshift_one(rule_id: str) -> None:
    """class 3: a `KubeletConfig` in somebody else's group is a different kind, not a subject."""
    doc = yaml.safe_dump(
        {
            "apiVersion": "example.com/v1",
            "kind": "KubeletConfig",
            "metadata": {"name": "k"},
            "spec": {"kubeletConfig": {"readOnlyPort": 10255}},
        }
    )
    assert _not_evaluated(_report(doc), rule_id)


# =====================================================================================================
# KN-S042: the kubelet accepts requests it does not authenticate
# =====================================================================================================


def test_a_kubelet_command_line_that_does_not_set_anonymous_auth_gets_the_legacy_default_true() -> None:
    report = _report(
        _argv("--authorization-mode=Webhook", "--client-ca-file=/etc/kubernetes/ca.crt", "--read-only-port=0")
    )
    hits = _hits(report, "KN-S042")
    assert len(hits) == 1
    assert "--anonymous-auth" in hits[0].message
    assert "true" in hits[0].message


def test_a_kubeletconfiguration_file_that_does_not_set_anonymous_auth_is_not_a_finding() -> None:
    """A file is never read with the COMMAND LINE's `true`: the two tables are opposite here (class 4, class 21)."""
    report = _report(
        _config(authorization={"mode": "Webhook"}, authentication={"x509": {"clientCAFile": "/etc/ca.crt"}})
    )
    assert not _hits(report, "KN-S042")


def test_a_kubeletconfiguration_file_that_turns_anonymous_auth_on_is_a_finding() -> None:
    report = _report(_config(authentication={"anonymous": {"enabled": True}, "x509": {"clientCAFile": "/etc/ca.crt"}}))
    hits = _hits(report, "KN-S042")
    assert any("anonymous" in f.message for f in hits)


def test_a_kubelet_command_line_with_anonymous_auth_true_and_no_client_ca_is_two_findings() -> None:
    report = _report(_argv("--anonymous-auth=true", "--authorization-mode=Webhook", "--read-only-port=0"))
    messages = " ".join(f.message for f in _hits(report, "KN-S042"))
    assert "--anonymous-auth" in messages
    assert "--client-ca-file" in messages


def test_the_read_only_port_is_a_finding_when_it_is_not_zero_and_clean_when_it_is() -> None:
    bad = _report(
        _argv("--read-only-port=10255", "--anonymous-auth=false", "--authorization-mode=Webhook", "--client-ca-file=/c")
    )
    assert any("10255" in f.message for f in _hits(bad, "KN-S042"))
    good = _report(
        _argv("--read-only-port=0", "--anonymous-auth=false", "--authorization-mode=Webhook", "--client-ca-file=/c")
    )
    assert _clean(good, "KN-S042")  # a command line is read WHOLE, so a clean one can be called clean


def test_a_command_line_that_does_not_set_the_read_only_port_gets_10255_and_a_file_gets_zero() -> None:
    argv = _report(_argv("--anonymous-auth=false", "--authorization-mode=Webhook", "--client-ca-file=/c"))
    assert any("10255" in f.message for f in _hits(argv, "KN-S042"))
    cfg = _report(_config(authorization={"mode": "Webhook"}, authentication={"x509": {"clientCAFile": "/c"}}))
    assert not any("10255" in f.message for f in _hits(cfg, "KN-S042"))


def test_a_read_only_port_that_is_not_a_number_is_declined_not_read_as_zero() -> None:
    report = _report(
        _config(readOnlyPort="ten", authorization={"mode": "Webhook"}, authentication={"x509": {"clientCAFile": "/c"}})
    )
    assert _declined(report, "KN-S042")
    assert "readOnlyPort" in _why(report, "KN-S042")


def test_an_anonymous_auth_value_that_is_not_a_boolean_is_declined() -> None:
    report = _report(_argv("--anonymous-auth=yesplease", "--authorization-mode=Webhook"))
    assert _declined(report, "KN-S042")


# =====================================================================================================
# KN-S043: the kubelet authorizes every request
# =====================================================================================================


def test_always_allow_on_the_kubelet_command_line_is_critical() -> None:
    report = _report(
        _argv("--authorization-mode=AlwaysAllow", "--anonymous-auth=false", "--client-ca-file=/c", "--read-only-port=0")
    )
    hits = _hits(report, "KN-S043")
    assert len(hits) == 1
    assert hits[0].severity is Severity.CRITICAL


def test_a_kubelet_command_line_with_no_authorization_mode_gets_always_allow() -> None:
    report = _report(_argv("--anonymous-auth=false", "--client-ca-file=/c", "--read-only-port=0"))
    assert any("AlwaysAllow" in f.message for f in _hits(report, "KN-S043"))


def test_a_kubeletconfiguration_file_with_no_authorization_mode_is_declined_not_clean() -> None:
    """The v1beta1 default is Webhook, but a flag wins over the file and the command line is not in the input."""
    report = _report(_config(authentication={"x509": {"clientCAFile": "/c"}}))
    assert _declined(report, "KN-S043")
    assert "command line" in _why(report, "KN-S043")


def test_always_allow_in_a_kubeletconfiguration_file_is_still_a_finding() -> None:
    assert _hits(_report(_config(authorization={"mode": "AlwaysAllow"})), "KN-S043")


def test_an_authorization_mode_the_kubelet_does_not_accept_is_declined_not_read() -> None:
    report = _report(_config(authorization={"mode": "RBAC"}))
    assert _declined(report, "KN-S043")


# =====================================================================================================
# KN-S044: node hardening the kubelet does by default, turned off
# =====================================================================================================


def test_protect_kernel_defaults_false_is_a_finding_and_true_is_clean() -> None:
    bad = _report(
        _config(
            protectKernelDefaults=False,
            makeIPTablesUtilChains=True,
            streamingConnectionIdleTimeout="4h",
            eventRecordQPS=50,
        )
    )
    assert any("protectKernelDefaults" in f.message for f in _hits(bad, "KN-S044"))
    good = _report(
        _config(
            protectKernelDefaults=True,
            makeIPTablesUtilChains=True,
            streamingConnectionIdleTimeout="4h",
            eventRecordQPS=50,
        )
    )
    assert _clean(good, "KN-S044")


def test_make_iptables_util_chains_false_is_a_finding() -> None:
    report = _report(
        _config(
            protectKernelDefaults=True,
            makeIPTablesUtilChains=False,
            streamingConnectionIdleTimeout="4h",
            eventRecordQPS=50,
        )
    )
    assert any("makeIPTablesUtilChains" in f.message for f in _hits(report, "KN-S044"))


def test_a_zero_streaming_connection_idle_timeout_is_a_finding() -> None:
    report = _report(
        _config(
            protectKernelDefaults=True,
            makeIPTablesUtilChains=True,
            streamingConnectionIdleTimeout="0",
            eventRecordQPS=50,
        )
    )
    assert any("streamingConnectionIdleTimeout" in f.message for f in _hits(report, "KN-S044"))


def test_a_zero_event_qps_is_an_unbounded_event_rate_and_a_finding() -> None:
    report = _report(
        _config(
            protectKernelDefaults=True,
            makeIPTablesUtilChains=True,
            streamingConnectionIdleTimeout="4h",
            eventRecordQPS=0,
        )
    )
    assert any("eventRecordQPS" in f.message for f in _hits(report, "KN-S044"))


def test_an_absent_protect_kernel_defaults_is_false_in_both_shapes() -> None:
    """Its default is the zero value in both tables, so this one does not differ between them (class 21)."""
    argv = _report(_argv("--make-iptables-util-chains=true"))
    assert any("--protect-kernel-defaults" in f.message for f in _hits(argv, "KN-S044"))
    # A FILE is read for what it states and declines what it does not, because the command line that would
    # override it is not in the input: silence there is not "false", it is not read.
    cfg = _report(_config(makeIPTablesUtilChains=True))
    assert not _hits(cfg, "KN-S044")
    assert "protectKernelDefaults" in _why(cfg, "KN-S044")


def test_a_duration_the_kubelet_does_not_parse_is_declined_not_read_as_zero() -> None:
    report = _report(
        _config(
            streamingConnectionIdleTimeout="soon",
            protectKernelDefaults=True,
            makeIPTablesUtilChains=True,
            eventRecordQPS=50,
        )
    )
    assert _declined(report, "KN-S044")


# =====================================================================================================
# KN-S045: the kubelet's serving certificate and its cipher suites
# =====================================================================================================


def test_an_insecure_cipher_suite_is_a_finding_and_a_preferred_one_is_not() -> None:
    bad = _report(
        _config(tlsCipherSuites=["TLS_RSA_WITH_3DES_EDE_CBC_SHA"], serverTLSBootstrap=True, rotateCertificates=True)
    )
    assert any("TLS_RSA_WITH_3DES_EDE_CBC_SHA" in f.message for f in _hits(bad, "KN-S045"))
    good = _report(
        _config(
            tlsCipherSuites=["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"], serverTLSBootstrap=True, rotateCertificates=True
        )
    )
    assert _clean(good, "KN-S045")


def test_a_cipher_suite_name_kubernetes_does_not_accept_is_declined_not_called_weak() -> None:
    report = _report(_config(tlsCipherSuites=["TLS_MADE_UP_SUITE"], serverTLSBootstrap=True, rotateCertificates=True))
    assert _declined(report, "KN-S045")


def test_no_certificate_rotation_is_a_finding_in_both_directions() -> None:
    report = _report(
        _config(serverTLSBootstrap=False, rotateCertificates=False, tlsCipherSuites=["TLS_AES_128_GCM_SHA256"])
    )
    messages = " ".join(f.message for f in _hits(report, "KN-S045"))
    assert "serverTLSBootstrap" in messages
    assert "rotateCertificates" in messages


def test_the_rotate_kubelet_server_certificate_gate_turned_off_is_a_finding() -> None:
    report = _report(
        _config(
            serverTLSBootstrap=True,
            rotateCertificates=True,
            featureGates={"RotateKubeletServerCertificate": False},
            tlsCipherSuites=["TLS_AES_128_GCM_SHA256"],
        )
    )
    assert any("RotateKubeletServerCertificate" in f.message for f in _hits(report, "KN-S045"))


def test_the_rotation_flags_are_read_from_the_command_line_too() -> None:
    report = _report(_argv("--rotate-certificates=false", "--rotate-server-certificates=false"))
    messages = " ".join(f.message for f in _hits(report, "KN-S045"))
    assert "--rotate-certificates" in messages
    assert "--rotate-server-certificates" in messages


# =====================================================================================================
# Every shape, for one setting, so no shape is read by one rule and skipped by the rest (class 25)
# =====================================================================================================


@pytest.mark.parametrize(
    "text",
    [
        pytest.param(_config(readOnlyPort=10255), id="KubeletConfiguration"),
        pytest.param(_kubeadm_bundle(readOnlyPort=10255), id="kubeadm-bundle"),
        pytest.param(_argv("--read-only-port=10255"), id="static-pod"),
        pytest.param(_argv("--read-only-port=10255", kind="DaemonSet"), id="daemonset"),
        pytest.param(_kubeletconfig_cr(readOnlyPort=10255), id="openshift-KubeletConfig"),
        pytest.param(_ignition_kubelet(readOnlyPort=10255), id="machineconfig-ignition"),
    ],
)
def test_every_shape_a_fleet_produces_is_read_for_the_read_only_port(text: str) -> None:
    report = _report(text, platform="openshift" if "machineconfiguration" in text else "kubernetes")
    assert any("10255" in f.message for f in _hits(report, "KN-S042")), _why(report, "KN-S042")


def test_a_gzipped_ignition_file_is_read_like_a_plain_one() -> None:
    body = json.dumps(
        {"kind": "KubeletConfiguration", "apiVersion": "kubelet.config.k8s.io/v1beta1", "readOnlyPort": 10255}
    )
    text = _machineconfig(_data_url(body, gzipped=True), compression="gzip")
    report = _report(text, platform="openshift")
    assert any("10255" in f.message for f in _hits(report, "KN-S042")), _why(report, "KN-S042")


def test_an_ignition_file_kube_noob_cannot_decode_is_declined_and_named() -> None:
    text = _machineconfig("https://example.invalid/kubelet.conf")
    report = _report(text, platform="openshift")
    assert _declined(report, "KN-S042")
    assert "ignition" in _why(report, "KN-S042")


def test_an_ignition_compression_kube_noob_does_not_know_is_declined_not_read_as_plain() -> None:
    body = json.dumps(
        {"kind": "KubeletConfiguration", "apiVersion": "kubelet.config.k8s.io/v1beta1", "readOnlyPort": 0}
    )
    text = _machineconfig(_data_url(body), compression="zstd")
    report = _report(text, platform="openshift")
    assert _declined(report, "KN-S042")


def test_a_machineconfig_whose_files_carry_no_kubelet_conf_is_not_a_kubelet_subject() -> None:
    text = _machineconfig(_data_url("x"), path="/etc/chrony.conf")
    assert _not_evaluated(_report(text, platform="openshift"), "KN-S042")


# =====================================================================================================
# What the shape does not state is declined, never defaulted from a file that is not here
# =====================================================================================================


def test_a_command_line_with_a_config_file_declines_every_setting_it_does_not_state() -> None:
    report = _report(_argv("--config=/var/lib/kubelet/config.yaml", "--read-only-port=0"))
    assert _declined(report, "KN-S043")
    assert "--config" in _why(report, "KN-S043")


def test_a_config_file_flag_does_not_hide_the_flags_that_are_there() -> None:
    """class 24: a declined half must not swallow the half that was read."""
    report = _report(_argv("--config=/var/lib/kubelet/config.yaml", "--read-only-port=10255"))
    assert any("10255" in f.message for f in _hits(report, "KN-S042"))


def test_a_kubeletconfiguration_file_declines_the_command_line_it_cannot_see() -> None:
    report = _report(_config(readOnlyPort=0))
    assert _declined(report, "KN-S043")
    assert "command line" in _why(report, "KN-S043")


def test_the_two_default_tables_disagree_where_upstream_disagrees() -> None:
    """The asymmetry this module exists for, asserted against the tables themselves (class 8)."""
    from kube_noob.audit.kubelet import ARGV_DEFAULTS, FILE_DEFAULTS

    assert ARGV_DEFAULTS == {"anonymousAuth": True, "authorizationMode": "AlwaysAllow", "readOnlyPort": 10255}
    assert FILE_DEFAULTS == {"anonymousAuth": False, "authorizationMode": "Webhook", "readOnlyPort": 0}
    assert set(ARGV_DEFAULTS) == set(FILE_DEFAULTS)
    assert all(ARGV_DEFAULTS[k] != FILE_DEFAULTS[k] for k in ARGV_DEFAULTS)


def test_a_kubelet_the_launch_reader_cannot_follow_is_declined_with_the_reason() -> None:
    doc = yaml.safe_dump(
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "kubelet", "namespace": "kube-system"},
            "spec": {
                "containers": [
                    {
                        "name": "kubelet",
                        "image": "registry.k8s.io/kubelet:v1.35.0",
                        "command": ["/bin/sh", "-c", "exec kubelet --read-only-port=0"],
                    }
                ]
            },
        }
    )
    report = _report(doc)
    assert _declined(report, "KN-S042")


def test_a_shuffled_bundle_reports_the_same_findings() -> None:
    """class 5: the order documents arrive in does not change the answer."""
    a = _config(readOnlyPort=10255)
    b = _kubeletconfig_cr(readOnlyPort=10255)
    one = _report(a + "---\n" + b, platform="openshift")
    two = _report(b + "---\n" + a, platform="openshift")
    assert sorted(f.message for f in _hits(one, "KN-S042")) == sorted(f.message for f in _hits(two, "KN-S042"))


# =====================================================================================================
# Decline reasons carry no input text (G281's rule)
# =====================================================================================================


@pytest.mark.parametrize("rule_id", KUBELET_RULES)
def test_no_decline_reason_repeats_text_from_the_input(rule_id: str) -> None:
    marker = "ZZmarkerZZ"
    text = _config(
        authorization={"mode": marker},
        streamingConnectionIdleTimeout=marker,
        tlsCipherSuites=[marker],
        readOnlyPort=marker,
    )
    report = _report(text)
    assert marker not in _why(report, rule_id)
