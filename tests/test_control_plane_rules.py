"""KN-S037..KN-S041: the control plane and the trust boundaries around it (G272).

Five settings that decide whether the cluster's own components verify, authenticate and encrypt: the aggregator's
TLS to an extension API server, the kube-apiserver's anonymous and authorizer flags, etcd's listeners and client
certificates, OpenShift's encryption at rest, and OpenShift's LDAP identity provider. Each rule is held three
ways: it fires on the bad shape, it is silent on the good one, and on a shape it cannot decide it DECLINES --
the rule is kept out of the evaluated list and says why -- rather than reading as clean.
"""

from __future__ import annotations

from typing import Any

import pytest
import yaml

from kube_noob.audit import controls
from kube_noob.audit.engine import analyze
from kube_noob.audit.model import Report, Severity


def _report(text: str, platform: str = "kubernetes", version: str | None = None) -> Report:
    return analyze(text, platform, version)


def _hits(report: Report, rule_id: str) -> list[Any]:
    return [f for f in report.findings if f.rule_id == rule_id]


def _declined(report: Report, rule_id: str) -> bool:
    """Not evaluated, and the report says why: never in the evaluated list, never silent."""
    said = any(a.startswith(f"{rule_id} was not evaluated") for a in report.assumptions)
    return rule_id not in report.evaluated_rules and said


def _clean(report: Report, rule_id: str) -> bool:
    return rule_id in report.evaluated_rules and not _hits(report, rule_id)


def _pod(name: str, command: list[str], env: list[dict[str, Any]] | None = None, kind: str = "Pod") -> str:
    container: dict[str, Any] = {"name": name, "image": f"registry.k8s.io/{name}:v1.35.0", "command": command}
    if env is not None:
        container["env"] = env
    doc = {
        "apiVersion": "v1",
        "kind": kind,
        "metadata": {"name": name, "namespace": "kube-system"},
        "spec": {"hostNetwork": True, "containers": [container]},
    }
    return yaml.safe_dump(doc, sort_keys=False)


# =====================================================================================================
# KN-S037: an APIService that does not verify its extension API server
# =====================================================================================================


def _apiservice(spec: dict[str, Any]) -> str:
    doc = {
        "apiVersion": "apiregistration.k8s.io/v1",
        "kind": "APIService",
        "metadata": {"name": "v1beta1.metrics.k8s.io"},
        "spec": {
            "group": "metrics.k8s.io",
            "version": "v1beta1",
            "groupPriorityMinimum": 100,
            "versionPriority": 100,
            **spec,
        },
    }
    return yaml.safe_dump(doc, sort_keys=False)


SERVICE = {"service": {"name": "metrics-server", "namespace": "kube-system"}}


def test_an_apiservice_that_skips_tls_verification_is_reported() -> None:
    report = _report(_apiservice({**SERVICE, "insecureSkipTLSVerify": True}))
    hit = _hits(report, "KN-S037")
    assert len(hit) == 1
    assert hit[0].path == "spec.insecureSkipTLSVerify"
    assert "kube-system/metrics-server" in hit[0].message


def test_an_apiservice_without_a_ca_bundle_is_not_a_finding() -> None:
    """caBundle is optional: unset means the API server's system trust roots, and service-CA injection fills it on
    OpenShift. Absent is not insecure."""
    assert _clean(_report(_apiservice(dict(SERVICE))), "KN-S037")
    assert _clean(_report(_apiservice({**SERVICE, "insecureSkipTLSVerify": False})), "KN-S037")


def test_a_local_apiservice_is_out_of_scope_even_with_the_flag() -> None:
    """No service means the group is served by the API server itself: there is no remote end to verify."""
    assert _clean(_report(_apiservice({"insecureSkipTLSVerify": True})), "KN-S037")


def test_an_apiservice_flag_that_is_not_a_boolean_declines() -> None:
    report = _report(_apiservice({**SERVICE, "insecureSkipTLSVerify": "yes"}))
    assert not _hits(report, "KN-S037")
    assert _declined(report, "KN-S037")


def test_an_apiservice_in_another_group_is_not_read() -> None:
    text = _apiservice({**SERVICE, "insecureSkipTLSVerify": True}).replace(
        "apiregistration.k8s.io/v1", "apiregistration.example.com/v1"
    )
    assert not _hits(_report(text), "KN-S037")


# =====================================================================================================
# KN-S038: kube-apiserver with anonymous auth or an always-allow authorizer
# =====================================================================================================

KUBEADM_APISERVER = [
    "kube-apiserver",
    "--advertise-address=10.0.0.10",
    "--authorization-mode=Node,RBAC",
    "--anonymous-auth=false",
    "--client-ca-file=/etc/kubernetes/pki/ca.crt",
]


def _apiserver(*flags: str, base: tuple[str, ...] = ("--advertise-address=10.0.0.10",)) -> str:
    return _pod("kube-apiserver", ["kube-apiserver", *base, *flags])


def test_an_always_allow_authorizer_is_critical() -> None:
    report = _report(_apiserver("--authorization-mode=Node,AlwaysAllow,RBAC", "--anonymous-auth=false"))
    hit = _hits(report, "KN-S038")
    assert len(hit) == 1 and hit[0].severity == Severity.CRITICAL
    assert "AlwaysAllow" in hit[0].message
    assert hit[0].path == "spec.containers[0].command[2]"


def test_an_absent_authorization_mode_is_always_allow_and_says_so() -> None:
    """Upstream completes an empty --authorization-mode to AlwaysAllow when --authorization-config is not given."""
    report = _report(_apiserver("--anonymous-auth=false"))
    hit = _hits(report, "KN-S038")
    assert len(hit) == 1 and hit[0].severity == Severity.CRITICAL
    assert "not set" in hit[0].message and "AlwaysAllow" in hit[0].message


def test_an_empty_authorization_mode_is_the_same_as_none() -> None:
    hit = _hits(_report(_apiserver("--authorization-mode=", "--anonymous-auth=false")), "KN-S038")
    assert len(hit) == 1 and hit[0].severity == Severity.CRITICAL
    assert "to nothing" in hit[0].message and hit[0].path == "spec.containers[0].command[2]"


def test_explicit_anonymous_auth_is_reported() -> None:
    report = _report(_apiserver("--authorization-mode=Node,RBAC", "--anonymous-auth=true"))
    hit = _hits(report, "KN-S038")
    assert len(hit) == 1 and hit[0].severity == Severity.MEDIUM
    assert "system:anonymous" in hit[0].message


def test_an_absent_anonymous_flag_takes_the_upstream_default_and_names_it() -> None:
    report = _report(_apiserver("--authorization-mode=Node,RBAC"), version="1.33")
    hit = _hits(report, "KN-S038")
    assert len(hit) == 1
    assert "default" in hit[0].message and "true" in hit[0].message
    assert "v1.6.0" in hit[0].message


def test_a_bare_boolean_flag_means_true() -> None:
    assert _hits(_report(_apiserver("--authorization-mode=Node,RBAC", "--anonymous-auth")), "KN-S038")


def test_the_last_occurrence_of_a_flag_wins() -> None:
    report = _report(_apiserver("--anonymous-auth=true", "--authorization-mode=Node,RBAC", "--anonymous-auth=false"))
    assert _clean(report, "KN-S038")


def test_a_kubeadm_apiserver_is_clean() -> None:
    assert _clean(_report(_pod("kube-apiserver", KUBEADM_APISERVER)), "KN-S038")


def test_always_allow_turns_anonymous_off_so_only_the_authorizer_is_reported() -> None:
    """ApplyAuthorization resets anonymous to false when AlwaysAllow is in the modes: one finding, not two."""
    hit = _hits(_report(_apiserver("--authorization-mode=AlwaysAllow", "--anonymous-auth=true")), "KN-S038")
    assert len(hit) == 1 and "AlwaysAllow" in hit[0].message


def test_an_authorization_config_file_declines_the_authorizer_half() -> None:
    report = _report(_apiserver("--authorization-config=/etc/kubernetes/authz.yaml", "--anonymous-auth=false"))
    assert not _hits(report, "KN-S038")
    assert _declined(report, "KN-S038")
    assert any("--authorization-config" in a for a in report.assumptions)


def test_an_authentication_config_file_declines_the_anonymous_half_when_the_flag_is_absent() -> None:
    report = _report(_apiserver("--authorization-mode=Node,RBAC", "--authentication-config=/etc/kubernetes/authn.yaml"))
    assert not _hits(report, "KN-S038")
    assert _declined(report, "KN-S038")


def test_an_explicit_anonymous_flag_is_still_read_beside_an_authentication_config() -> None:
    """Upstream refuses to start when both configure anonymous, and otherwise the flag applies: true is never safe."""
    report = _report(
        _apiserver("--authorization-mode=Node,RBAC", "--authentication-config=/a.yaml", "--anonymous-auth=true")
    )
    assert _hits(report, "KN-S038")


def test_an_expanded_variable_declines() -> None:
    report = _report(_apiserver("--authorization-mode=$(AUTHZ)", "--anonymous-auth=false"))
    assert not _hits(report, "KN-S038")
    assert _declined(report, "KN-S038")


def test_an_unreadable_boolean_declines() -> None:
    report = _report(_apiserver("--authorization-mode=Node,RBAC", "--anonymous-auth=maybe"))
    assert _declined(report, "KN-S038")


def test_a_shell_wrapped_apiserver_declines_rather_than_passing() -> None:
    script = "exec kube-apiserver --authorization-mode=AlwaysAllow"
    report = _report(_pod("kube-apiserver", ["/bin/sh", "-ec", script]))
    assert not _hits(report, "KN-S038")
    assert _declined(report, "KN-S038")


def test_recognition_is_by_the_binary_not_by_a_name_or_label() -> None:
    """A container NAMED kube-apiserver that runs something else is not an API server, and one that is not named
    so but runs the binary is."""
    assert not _hits(_report(_pod("kube-apiserver", ["/usr/bin/proxy", "--anonymous-auth=true"])), "KN-S038")
    assert _hits(_report(_pod("cp", ["/usr/local/bin/kube-apiserver", "--authorization-mode=AlwaysAllow"])), "KN-S038")
    assert _hits(_report(_pod("cp", ["hyperkube", "kube-apiserver", "--authorization-mode=AlwaysAllow"])), "KN-S038")
    assert not _hits(_report(_pod("x", ["kube-apiserver-proxy", "--authorization-mode=AlwaysAllow"])), "KN-S038")


@pytest.mark.parametrize("platform", ["openshift", "rosa-classic", "rosa-hcp"])
def test_an_apiserver_on_openshift_declines_with_the_reason(platform: str) -> None:
    report = _report(_apiserver("--authorization-mode=AlwaysAllow"), platform, "4.20")
    assert not _hits(report, "KN-S038")
    assert _declined(report, "KN-S038")
    assert any("operator-managed" in a for a in report.assumptions)


# =====================================================================================================
# KN-S039: etcd serving clients or peers in plaintext
# =====================================================================================================

KUBEADM_ETCD = [
    "etcd",
    "--advertise-client-urls=https://10.0.0.10:2379",
    "--cert-file=/etc/kubernetes/pki/etcd/server.crt",
    "--client-cert-auth=true",
    "--initial-advertise-peer-urls=https://10.0.0.10:2380",
    "--listen-client-urls=https://127.0.0.1:2379,https://10.0.0.10:2379",
    "--listen-peer-urls=https://10.0.0.10:2380",
    "--peer-client-cert-auth=true",
]


def _etcd(*flags: str, env: list[dict[str, Any]] | None = None) -> str:
    return _pod("etcd", ["etcd", *flags], env)


def test_a_kubeadm_etcd_is_clean() -> None:
    assert _clean(_report(_pod("etcd", KUBEADM_ETCD)), "KN-S039")


def test_etcd_defaults_are_loopback_and_not_a_finding() -> None:
    assert _clean(_report(_etcd("--name=solo")), "KN-S039")


def test_plaintext_client_listener_on_a_network_address_is_critical() -> None:
    report = _report(_etcd("--listen-client-urls=http://0.0.0.0:2379", "--advertise-client-urls=http://10.0.0.10:2379"))
    hit = _hits(report, "KN-S039")
    assert {f.severity for f in hit} == {Severity.CRITICAL}
    assert len(hit) == 2
    assert any("http://0.0.0.0:2379" in f.message for f in hit)


def test_loopback_http_is_not_a_finding() -> None:
    report = _report(
        _etcd(
            "--listen-client-urls=http://127.0.0.1:2379,http://localhost:2379,http://[::1]:2379",
            "--advertise-client-urls=http://127.0.0.1:2379",
        )
    )
    assert _clean(report, "KN-S039")


def test_plaintext_peers_are_reported() -> None:
    hit = _hits(_report(_etcd("--listen-peer-urls=http://10.0.0.10:2380")), "KN-S039")
    assert len(hit) == 1 and hit[0].severity == Severity.HIGH


def test_explicitly_disabled_client_certificates_on_a_network_listener_are_reported() -> None:
    hit = _hits(
        _report(
            _etcd(
                "--listen-client-urls=https://10.0.0.10:2379",
                "--advertise-client-urls=https://10.0.0.10:2379",
                "--client-cert-auth=false",
            )
        ),
        "KN-S039",
    )
    assert len(hit) == 1 and "client-cert-auth" in hit[0].message


def test_absent_client_certificates_take_the_default_false_and_say_so() -> None:
    hit = _hits(
        _report(_etcd("--listen-client-urls=https://10.0.0.10:2379", "--advertise-client-urls=https://10.0.0.10:2379")),
        "KN-S039",
    )
    assert len(hit) == 1 and "default" in hit[0].message


def test_go_flag_single_dash_spelling_is_read() -> None:
    assert _hits(_report(_etcd("-listen-client-urls", "http://10.0.0.10:2379")), "KN-S039")


def test_an_etcd_environment_variable_sets_a_flag_the_command_line_did_not() -> None:
    env = [{"name": "ETCD_LISTEN_CLIENT_URLS", "value": "http://10.0.0.10:2379"}]
    hit = _hits(_report(_etcd("--name=a", env=env)), "KN-S039")
    assert hit and hit[0].path == "spec.containers[0].env[0].value"


def test_a_command_line_flag_shadows_the_environment() -> None:
    env = [{"name": "ETCD_LISTEN_CLIENT_URLS", "value": "http://10.0.0.10:2379"}]
    assert _clean(_report(_etcd("--listen-client-urls=http://127.0.0.1:2379", env=env)), "KN-S039")


@pytest.mark.parametrize(
    ("flags", "env"),
    [
        (("--config-file=/etc/etcd/etcd.conf.yml",), None),
        (("--name=a",), [{"name": "ETCD_CONFIG_FILE", "value": "/etc/etcd.yml"}]),
        (("--name=a",), [{"name": "ETCD_LISTEN_CLIENT_URLS", "valueFrom": {"fieldRef": {"fieldPath": "x"}}}]),
        (("--listen-client-urls=http://$(POD_IP):2379",), None),
        (("--listen-client-urls=gopher://10.0.0.10:2379",), None),
        (("--client-cert-auth=sometimes", "--listen-client-urls=https://10.0.0.10:2379"), None),
    ],
)
def test_what_the_manifest_cannot_say_declines(flags: tuple[str, ...], env: list[dict[str, Any]] | None) -> None:
    report = _report(_etcd(*flags, env=env))
    assert not _hits(report, "KN-S039")
    assert _declined(report, "KN-S039")


def test_env_from_on_an_etcd_container_declines() -> None:
    text = _etcd("--name=a").replace("    command:", "    envFrom:\n    - configMapRef: {name: etcd}\n    command:")
    assert "envFrom" in text
    assert _declined(_report(text), "KN-S039")


def test_a_shell_wrapped_etcd_declines() -> None:
    script = "set -e\nexec nice -n -19 etcd --listen-client-urls=http://0.0.0.0:2379"
    assert _declined(_report(_pod("etcd", ["/bin/bash", "-c", script])), "KN-S039")


def test_a_script_that_only_mentions_the_data_directory_is_not_etcd() -> None:
    report = _report(_pod("backup", ["/bin/sh", "-c", "tar czf /backup/x.tgz /var/lib/etcd"]))
    assert _clean(report, "KN-S039")


# =====================================================================================================
# KN-S040: OpenShift encryption at rest
# =====================================================================================================


def _cluster_apiserver(spec: dict[str, Any] | None) -> str:
    doc: dict[str, Any] = {"apiVersion": "config.openshift.io/v1", "kind": "APIServer", "metadata": {"name": "cluster"}}
    if spec is not None:
        doc["spec"] = spec
    return yaml.safe_dump(doc, sort_keys=False)


@pytest.mark.parametrize(
    "spec", [None, {}, {"encryption": {}}, {"encryption": {"type": ""}}, {"encryption": {"type": "identity"}}]
)
def test_encryption_absent_or_identity_is_reported(spec: dict[str, Any] | None) -> None:
    hit = _hits(_report(_cluster_apiserver(spec), "openshift", "4.20"), "KN-S040")
    assert len(hit) == 1
    assert "Secrets" in hit[0].message


@pytest.mark.parametrize("kind", ["aescbc", "aesgcm", "KMS"])
def test_an_encryption_type_openshift_defines_is_clean(kind: str) -> None:
    assert _clean(_report(_cluster_apiserver({"encryption": {"type": kind}}), "openshift", "4.20"), "KN-S040")


def test_an_unrecognised_encryption_type_declines() -> None:
    report = _report(_cluster_apiserver({"encryption": {"type": "aes-gcm-siv"}}), "openshift", "4.20")
    assert not _hits(report, "KN-S040")
    assert _declined(report, "KN-S040")


@pytest.mark.parametrize("platform", ["openshift", "rosa-classic", "rosa-hcp"])
def test_a_bundle_without_the_singletons_declines_quietly_on_openshift(platform: str) -> None:
    """Not collected is not clean: both rules stay out of the evaluated list and are named as not evaluated. The
    reason is not repeated on every application audit, exactly as KN-S035 declines (the singleton always exists,
    so its absence means nobody passed it)."""
    report = _report("apiVersion: v1\nkind: ConfigMap\nmetadata: {name: x, namespace: y}\n", platform, "4.20")
    for rid in ("KN-S040", "KN-S041"):
        assert rid not in report.evaluated_rules
        assert not any(a.startswith(rid) for a in report.assumptions)
    summary = {c["id"]: c for c in report.as_dict()["controlSummary"]["controls"]}
    assert summary["SC-28(1)"]["notEvaluated"] == 1 and summary["SC-28(1)"]["clean"] == 0


def test_several_apiservers_none_named_cluster_decline() -> None:
    first = _cluster_apiserver({}).replace("name: cluster", "name: a")
    second = _cluster_apiserver({}).replace("name: cluster", "name: b")
    report = _report(first + "---\n" + second, "openshift", "4.20")
    assert not _hits(report, "KN-S040")
    assert _declined(report, "KN-S040")


def test_a_hosted_control_plane_declines_whatever_the_object_says() -> None:
    report = _report(_cluster_apiserver({"encryption": {"type": "identity"}}), "rosa-hcp", "4.20")
    assert not _hits(report, "KN-S040")
    assert _declined(report, "KN-S040")
    assert any("secretEncryption" in a for a in report.assumptions)


def test_encryption_reads_the_same_object_as_the_audit_rule() -> None:
    """KN-S035 and KN-S040 answer about one object, so they must agree about which object that is: an APIServer in
    a foreign group is neither rule's, and both decline it the same way."""
    text = _cluster_apiserver({"encryption": {"type": "identity"}, "audit": {"profile": "None"}})
    report = _report(text, "openshift", "4.20")
    assert _hits(report, "KN-S035") and _hits(report, "KN-S040")
    foreign = _report(text.replace("config.openshift.io/v1", "x.io/v1"), "openshift", "4.20")
    for rid in ("KN-S035", "KN-S040"):
        assert not _hits(foreign, rid) and rid not in foreign.evaluated_rules


# =====================================================================================================
# KN-S041: an OpenShift identity provider that does not use TLS
# =====================================================================================================


def _oauth(providers: list[dict[str, Any]]) -> str:
    doc = {
        "apiVersion": "config.openshift.io/v1",
        "kind": "OAuth",
        "metadata": {"name": "cluster"},
        "spec": {"identityProviders": providers},
    }
    return yaml.safe_dump(doc, sort_keys=False)


def _ldap(url: str, insecure: object) -> dict[str, Any]:
    return {
        "name": "corp",
        "type": "LDAP",
        "mappingMethod": "claim",
        "ldap": {"url": url, "insecure": insecure, "attributes": {"id": ["dn"]}},
    }


def test_an_insecure_ldap_provider_over_ldap_scheme_is_reported() -> None:
    hit = _hits(
        _report(_oauth([_ldap("ldap://ldap.example.com/ou=users,dc=example,dc=com?uid", True)]), "openshift", "4.20"),
        "KN-S041",
    )
    assert len(hit) == 1
    assert hit[0].path == "spec.identityProviders[0].ldap.insecure"
    assert "corp" in hit[0].message


def test_ldap_without_insecure_is_upgraded_with_starttls_and_is_clean() -> None:
    assert _clean(
        _report(_oauth([_ldap("ldap://ldap.example.com/ou=users?uid", False)]), "openshift", "4.20"), "KN-S041"
    )


def test_ldaps_always_uses_tls_even_with_insecure_set() -> None:
    assert _clean(
        _report(_oauth([_ldap("ldaps://ldap.example.com/ou=users?uid", True)]), "openshift", "4.20"), "KN-S041"
    )


def test_a_provider_with_no_insecure_switch_and_no_ca_is_not_a_finding() -> None:
    """A missing `ca` means the system roots, which is verification, not its absence."""
    github = {
        "name": "gh",
        "type": "GitHub",
        "github": {"clientID": "x", "clientSecret": {"name": "gh"}, "organizations": ["acme"]},
    }
    htpasswd = {"name": "local", "type": "HTPasswd", "htpasswd": {"fileData": {"name": "htpass"}}}
    assert _clean(_report(_oauth([github, htpasswd]), "openshift", "4.20"), "KN-S041")


def test_an_unrecognised_provider_type_declines() -> None:
    report = _report(_oauth([{"name": "x", "type": "SAML", "saml": {}}]), "openshift", "4.20")
    assert not _hits(report, "KN-S041")
    assert _declined(report, "KN-S041")


@pytest.mark.parametrize("insecure", ["true", 1, None])
def test_an_unreadable_insecure_value_or_url_declines(insecure: object) -> None:
    provider = _ldap("ldap://ldap.example.com/?uid", insecure)
    if insecure is None:
        provider["ldap"]["url"] = 7
        provider["ldap"]["insecure"] = True
    report = _report(_oauth([provider]), "openshift", "4.20")
    assert not _hits(report, "KN-S041")
    assert _declined(report, "KN-S041")


def test_an_identity_provider_on_a_hosted_control_plane_declines() -> None:
    report = _report(_oauth([_ldap("ldap://ldap.example.com/?uid", True)]), "rosa-hcp", "4.20")
    assert not _hits(report, "KN-S041")
    assert _declined(report, "KN-S041")
    assert any("spec.configuration.oauth" in a for a in report.assumptions)


def test_the_oauth_rule_does_not_run_off_openshift() -> None:
    assert not _hits(_report(_oauth([_ldap("ldap://x/?uid", True)])), "KN-S041")


# =====================================================================================================
# Coverage: a declined rule flows through every view as not evaluated, never as clean
# =====================================================================================================


def test_a_declined_rule_is_not_evaluated_in_the_control_summary_and_the_oscal_exclusions() -> None:
    from kube_noob import oscal

    report = _report(_cluster_apiserver({"encryption": {"type": "aes-gcm-siv"}}), "openshift", "4.20")
    summary = {c["id"]: c for c in report.as_dict()["controlSummary"]["controls"]}
    assert controls.RULE_CONTROLS["KN-S040"] == ("SC-28", "SC-28(1)")
    # SC-28(1) rests on this rule alone, so declining it leaves the control unreviewed: not clean, not a finding.
    assert summary["SC-28(1)"] == {
        "id": "SC-28(1)",
        "title": controls.TITLES["SC-28(1)"],
        "findings": 0,
        "clean": 0,
        "notEvaluated": 1,
    }
    document = oscal.assessment_results(report.as_dict())
    selection = document["assessment-results"]["results"][0]["reviewed-controls"]["control-selections"][0]
    excluded = {c["control-id"] for c in selection["exclude-controls"]}
    included = {c["control-id"] for c in selection.get("include-controls", [])}
    assert "sc-28.1" in excluded and "sc-28.1" not in included


def test_the_ksi_projection_counts_a_declined_rule_as_not_evaluated() -> None:
    from kube_noob.audit import fedramp

    report = _report(_cluster_apiserver({"encryption": {"type": "aes-gcm-siv"}}), "openshift", "4.20")
    view = fedramp.summary(
        [f.rule_id for f in report.findings], None, sorted(report.evaluated_rules), sorted(report.fired_rules)
    )
    rows = {r["id"]: r for r in view["indicators"]}
    assert "KN-S040" in rows["KSI-SVC-SIN"].get("notEvaluatedRules", [])


def test_every_new_rule_has_controls_and_a_fixture() -> None:
    from pathlib import Path

    for rid in ("KN-S037", "KN-S038", "KN-S039", "KN-S040", "KN-S041"):
        assert controls.RULE_CONTROLS[rid], rid
        assert (Path(__file__).parent / "fixtures" / "rules" / f"{rid}.yaml").is_file(), rid


def test_the_output_is_deterministic() -> None:
    text = "\n---\n".join(
        [
            _apiserver("--authorization-config=/a.yaml"),
            _etcd("--config-file=/b.yaml"),
            _apiservice({**SERVICE, "insecureSkipTLSVerify": True}),
        ]
    )
    first = _report(text).as_dict()
    assert first == _report(text).as_dict()
    notes = [a for a in first["assumptions"] if " was not evaluated" in a]
    assert notes == sorted(notes)


# =====================================================================================================
# Every surface carries the reason: text, JSON, SARIF and the MCP result (compact or not)
# =====================================================================================================


def test_the_reason_reaches_sarif_the_text_view_and_the_mcp_result(
    tmp_path: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    import json

    from kube_noob.audit.compact import expand_report
    from kube_noob.cli import main
    from kube_noob.config import Settings
    from kube_noob.toolkit import AuditIn, Toolkit

    text = (
        _apiserver("--authorization-config=/etc/kubernetes/authz.yaml")
        + "---\n"
        + _apiserver("--authorization-mode=Node,RBAC").replace(
            "name: kube-apiserver\n  namespace", "name: kube-apiserver-b\n  namespace"
        )
    )
    path = tmp_path / "cp.yaml"
    path.write_text(text, encoding="utf-8")
    main(["audit", "-f", str(path), "--format", "sarif", "--fail-on", "never"])
    sarif = json.loads(capsys.readouterr().out)
    notes = [n["message"]["text"] for n in sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"]]
    assert any(n.startswith("KN-S038 was not evaluated") and "--authorization-config" in n for n in notes)
    main(["audit", "-f", str(path), "--fail-on", "never"])
    assert "KN-S038 was not evaluated" in capsys.readouterr().out
    kit = Toolkit(Settings())
    flat = kit.audit(AuditIn(manifests=text))
    assert any(a.startswith("KN-S038 was not evaluated") for a in flat["assumptions"])
    # A CRITICAL rule whose findings here are MEDIUM: the compact view hoists what the findings share and expands
    # back to the flat report exactly.
    compact = kit.audit(AuditIn(manifests=text, compact=True))
    assert expand_report(compact)["findings"] == flat["findings"]
    # The declined container still reports the half it CAN decide: anonymous by default, on both.
    assert [f["severity"] for f in flat["findings"] if f["ruleId"] == "KN-S038"] == ["medium", "medium"]


def test_hostile_argv_is_bounded_and_never_crashes() -> None:
    """Twenty thousand tokens, a dangling value flag, non-string tokens and URLs that do not parse."""
    import time

    noise = [f"--x{i}" for i in range(20_000)]
    start = time.monotonic()
    report = _report(_apiserver(*noise, "--authorization-mode"))
    assert time.monotonic() - start < 5
    assert _declined(report, "KN-S038")  # a dangling --authorization-mode: kube-apiserver would not start
    weird = _pod("kube-apiserver", ["kube-apiserver"]).replace("- kube-apiserver", "- kube-apiserver\n      - 7")
    assert not _hits(_report(weird), "KN-S038")  # a non-string token: not a command line kube-noob can read
    unreadable = _pod("kube-apiserver", ["kube-apiserver"]).replace(
        "    command:", "    args: [--authorization-mode=AlwaysAllow, 7]\n    command:"
    )
    assert "args:" in unreadable
    assert _declined(_report(unreadable), "KN-S038")
    report = _report(_etcd("--listen-client-urls=http://[::1:2379,https://[bad"))
    assert not _hits(report, "KN-S039") and _declined(report, "KN-S039")
