"""KN-S046: whether an admission webhook's CA bundle is a certificate the API server could actually use (G303).

A `clientConfig.caBundle` that is present but unusable is worse than an absent one, because the manifest looks
configured: the API server cannot build a trust pool from it, every call to the webhook fails, and the check the
cluster believes it has is not running. `KN-S030` already reports `failurePolicy: Ignore`, which decides what
happens then, and this rule does not repeat it.

The X.509 reading is the standard library only -- `base64`, `ssl.PEM_cert_to_DER_cert`,
`ssl.SSLContext.load_verify_locations` and `ssl.cert_time_to_seconds` -- because `cryptography` is an INDIRECT
dependency of this project (via `pyjwt`, via `mcp`) and making it a direct one is the owner's decision. The one
limit that buys is named rather than hidden: OpenSSL hands back only the certificates it would store as trust
anchors, so a leaf certificate in a bundle is reported as a certificate whose validity window was not read,
never as a bundle holding none.

The certificates below are fixed fixtures with fixed windows (2018-2020 expired, 2020-2099 valid, 2090-2099 not
yet valid), so the verdicts do not drift with the clock the way a certificate minted at test time would.
"""

from __future__ import annotations

import base64
from typing import Any

import pytest
import yaml

from kube_noob.audit.engine import analyze
from kube_noob.audit.model import Report, Severity

VALID_CA = """-----BEGIN CERTIFICATE-----
MIIBUDCB96ADAgECAhQSjA8+/DfxtfYwOfCcByEoiDTkjTAKBggqhkjOPQQDAjAd
MRswGQYDVQQDDBJrdWJlLW5vb2IgdmFsaWQgY2EwIBcNMjAwMTAxMDAwMDAwWhgP
MjA5OTAxMDEwMDAwMDBaMB0xGzAZBgNVBAMMEmt1YmUtbm9vYiB2YWxpZCBjYTBZ
MBMGByqGSM49AgEGCCqGSM49AwEHA0IABGctKVW8MxfjHFOV4AYm7FZg5LS1EzYV
Taz0oEvk8IZkFxTxxMueaNYgblsu2aQA79IQNmsAetruTZZRtSDp4iGjEzARMA8G
A1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIgNxptj68KHXfhOy6xqRd7
eyb1YRPewHWtbnZp4ry7Wu8CIQCMTdnuNumC4AH9FXvyCWe6yvI5o/7e1cHP9ddJ
TszVEg==
-----END CERTIFICATE-----
"""
EXPIRED_CA = """-----BEGIN CERTIFICATE-----
MIIBUjCB+aADAgECAhRR4k4mMwvSRXEZ3x0s2nEk3/dOWTAKBggqhkjOPQQDAjAf
MR0wGwYDVQQDDBRrdWJlLW5vb2IgZXhwaXJlZCBjYTAeFw0xODAxMDEwMDAwMDBa
Fw0yMDAxMDEwMDAwMDBaMB8xHTAbBgNVBAMMFGt1YmUtbm9vYiBleHBpcmVkIGNh
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgatPQkn6CMxK27kEZcpL0OC36KnR
T0BzRykmUDb/FkO/BGrq6UqcM5+kRrbU4XkXahpity0Dd+jzJxh/Z+w2rKMTMBEw
DwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiEAstzHYwTOre3hdTgh
ceCDQyKzaemCA+IJ4rBiAU8nnYYCIE/kg9dEzuMZ36x2lExOorF8a0BzmQkT4acR
vlX1Q2Pt
-----END CERTIFICATE-----
"""
FUTURE_CA = """-----BEGIN CERTIFICATE-----
MIIBVTCB+6ADAgECAhRhBvwxXkQVooa3GSI4eXRVUHvp/zAKBggqhkjOPQQDAjAe
MRwwGgYDVQQDDBNrdWJlLW5vb2IgZnV0dXJlIGNhMCIYDzIwOTAwMTAxMDAwMDAw
WhgPMjA5OTAxMDEwMDAwMDBaMB4xHDAaBgNVBAMME2t1YmUtbm9vYiBmdXR1cmUg
Y2EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATYkzxIUrnMFqZ02VGO11WdJiJV
9ud2BMoVaB1qPkaKvH76tBdE1u9Obls0T7tO4BQiITyGlXZx23p44EXf1m5noxMw
ETAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0kAMEYCIQDhN/p+QuRQjsFE
rQNwDzprBNnXNY/4PkBRnxQ59IWe2QIhANpe9+wDWHPW1NzIIiSiulQfW3VDEyOM
x9akvyJ5k5vP
-----END CERTIFICATE-----
"""
LEAF_CERT = """-----BEGIN CERTIFICATE-----
MIIBRjCB7KADAgECAhR+usMTCnnj2qVYuRMtXzE+kbHPvjAKBggqhkjOPQQDAjAZ
MRcwFQYDVQQDDA5rdWJlLW5vb2IgbGVhZjAgFw0yMDAxMDEwMDAwMDBaGA8yMDk5
MDEwMTAwMDAwMFowGTEXMBUGA1UEAwwOa3ViZS1ub29iIGxlYWYwWTATBgcqhkjO
PQIBBggqhkjOPQMBBwNCAATocfD3XsJg7fkr/I6Mtr9JKGnquHaBtK17Uk2Ji+FS
1YT/bu3g90spbIT1CdJnaua8gyPumiu598mLdGKhaxeloxAwDjAMBgNVHRMBAf8E
AjAAMAoGCCqGSM49BAMCA0kAMEYCIQC/aNnKQuoKcwcsNqrDPtyiBU9u5X93gWop
Wm3YIguAsQIhALX81DebLmooobRrxQ70eD2ufH5FJNzGsBFLtc8w8TZD
-----END CERTIFICATE-----
"""


def _b64(pem: str) -> str:
    return base64.b64encode(pem.encode("ascii")).decode("ascii")


def _report(text: str, platform: str = "kubernetes") -> Report:
    return analyze(text, platform, None)


def _hits(report: Report, rule_id: str = "KN-S046") -> list[Any]:
    return [f for f in report.findings if f.rule_id == rule_id]


def _declined(report: Report, rule_id: str = "KN-S046") -> bool:
    said = any(a.startswith(f"{rule_id} was not evaluated") for a in report.assumptions)
    return rule_id not in report.evaluated_rules and said


def _clean(report: Report, rule_id: str = "KN-S046") -> bool:
    return rule_id in report.evaluated_rules and not _hits(report, rule_id)


def _why(report: Report, rule_id: str = "KN-S046") -> str:
    return " ".join(a for a in report.assumptions if a.startswith(f"{rule_id} was not evaluated"))


def _webhook(
    client_config: dict[str, Any] | None,
    kind: str = "ValidatingWebhookConfiguration",
    annotations: dict[str, str] | None = None,
    **hook: Any,
) -> str:
    entry: dict[str, Any] = {
        "name": "deny.example.com",
        "admissionReviewVersions": ["v1"],
        "sideEffects": "None",
        "rules": [{"apiGroups": [""], "apiVersions": ["v1"], "operations": ["CREATE"], "resources": ["pods"]}],
        **hook,
    }
    if client_config is not None:
        entry["clientConfig"] = client_config
    doc: dict[str, Any] = {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": kind,
        "metadata": {"name": "deny-example"},
        "webhooks": [entry],
    }
    if annotations:
        doc["metadata"]["annotations"] = annotations
    return yaml.safe_dump(doc, sort_keys=False)


SERVICE = {"service": {"name": "webhook", "namespace": "example", "path": "/validate", "port": 443}}


# =====================================================================================================
# A rule whose subject is absent is not evaluated, never clean (class 14)
# =====================================================================================================


def test_a_bundle_with_no_webhook_configuration_in_it_is_not_clean() -> None:
    report = _report(yaml.safe_dump({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "c"}}))
    assert "KN-S046" not in report.evaluated_rules
    assert not _hits(report)


def test_a_webhook_configuration_of_another_group_is_a_different_kind() -> None:
    text = _webhook({**SERVICE, "caBundle": _b64(EXPIRED_CA)}).replace(
        "admissionregistration.k8s.io/v1", "admissionregistration.example.com/v1"
    )
    assert "KN-S046" not in _report(text).evaluated_rules


# =====================================================================================================
# The bundle is there and the API server can use it
# =====================================================================================================


def test_a_valid_ca_bundle_is_clean() -> None:
    assert _clean(_report(_webhook({**SERVICE, "caBundle": _b64(VALID_CA)})))


def test_a_valid_ca_bundle_is_clean_on_a_mutating_configuration_too() -> None:
    """class 21: the other wrapper, tested in the same change."""
    text = _webhook({**SERVICE, "caBundle": _b64(VALID_CA)}, kind="MutatingWebhookConfiguration")
    assert _clean(_report(text))


# =====================================================================================================
# The bundle is there and the API server cannot use it
# =====================================================================================================


@pytest.mark.parametrize(
    ("value", "says"),
    [
        pytest.param("", "empty", id="empty-string"),
        pytest.param("not base64 at all!!", "base64", id="not-base64"),
        pytest.param(base64.b64encode(b"hello").decode(), "PEM", id="base64-but-not-pem"),
        pytest.param(
            base64.b64encode(b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n").decode(),
            "PEM",
            id="a-private-key",
        ),
        pytest.param(
            base64.b64encode(b"-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n").decode(),
            "DER",
            id="pem-framed-but-not-der",
        ),
    ],
)
def test_a_ca_bundle_the_api_server_cannot_decode_is_a_finding_that_says_which_way(value: str, says: str) -> None:
    hits = _hits(_report(_webhook({**SERVICE, "caBundle": value})))
    assert len(hits) == 1
    assert says in hits[0].message
    assert hits[0].severity >= Severity.HIGH


def test_a_ca_bundle_that_is_not_a_string_is_a_finding_and_never_a_python_repr() -> None:
    text = _webhook({**SERVICE, "caBundle": ["a", "b"]})
    hits = _hits(_report(text))
    assert len(hits) == 1
    assert "['a', 'b']" not in hits[0].message


def test_an_expired_ca_bundle_is_a_finding() -> None:
    hits = _hits(_report(_webhook({**SERVICE, "caBundle": _b64(EXPIRED_CA)})))
    assert any("expired" in f.message for f in hits)


def test_a_ca_bundle_that_is_not_yet_valid_is_a_finding() -> None:
    hits = _hits(_report(_webhook({**SERVICE, "caBundle": _b64(FUTURE_CA)})))
    assert any("not valid until" in f.message for f in hits)


def test_one_expired_certificate_beside_a_valid_one_is_still_reported() -> None:
    """class 2 and class 15: the good half of a bundle does not hide the bad half."""
    hits = _hits(_report(_webhook({**SERVICE, "caBundle": _b64(VALID_CA + EXPIRED_CA)})))
    assert any("expired" in f.message for f in hits)


# =====================================================================================================
# The standard library's one limit, named rather than hidden
# =====================================================================================================


def test_a_leaf_certificate_in_the_bundle_is_declined_and_not_called_an_empty_bundle() -> None:
    report = _report(_webhook({**SERVICE, "caBundle": _b64(LEAF_CERT)}))
    assert _declined(report)
    assert "validity window" in _why(report)
    assert not any("no certificate" in f.message for f in _hits(report))


def test_a_leaf_beside_a_valid_ca_declines_the_leaf_and_still_reads_the_ca() -> None:
    """class 24: a declined half must not swallow the half that WAS read."""
    report = _report(_webhook({**SERVICE, "caBundle": _b64(EXPIRED_CA + LEAF_CERT)}))
    assert any("expired" in f.message for f in _hits(report))
    assert "validity window" in _why(report)


# =====================================================================================================
# An absent bundle: what it means depends on where the webhook is
# =====================================================================================================


def test_a_service_backed_webhook_with_no_ca_bundle_is_a_finding() -> None:
    hits = _hits(_report(_webhook(dict(SERVICE))))
    assert len(hits) == 1
    assert "system trust" in hits[0].message


def test_a_url_webhook_with_no_ca_bundle_is_not_a_finding() -> None:
    """A webhook at a public URL may legitimately have a publicly trusted certificate."""
    assert _clean(_report(_webhook({"url": "https://admission.example.com/validate"})))


OPENSHIFT_INJECTOR = {"service.beta.openshift.io/inject-cabundle": "true"}
CERT_MANAGER_INJECTOR = {"cert-manager.io/inject-ca-from": "example/webhook-cert"}


def _certificate(namespace: str = "example", name: str = "webhook-cert") -> str:
    return yaml.safe_dump(
        {
            "apiVersion": "cert-manager.io/v1",
            "kind": "Certificate",
            "metadata": {"name": name, "namespace": namespace},
            "spec": {"secretName": name + "-tls", "issuerRef": {"name": "ca-issuer", "kind": "Issuer"}},
        },
        sort_keys=False,
    )


def test_the_openshift_service_ca_annotation_is_clean_on_the_openshift_family() -> None:
    """It is the configuration OpenShift's own documentation asks for, and KN-S037's remediation asks for it too:
    the operator fills the bundle and keeps it filled, so this is an answer and not an absence (G306)."""
    for platform in ("openshift", "rosa-classic", "rosa-hcp"):
        report = _report(_webhook(dict(SERVICE), annotations=OPENSHIFT_INJECTOR), platform=platform)
        assert _clean(report), (platform, _why(report), [f.message for f in _hits(report)])


def test_the_openshift_service_ca_annotation_is_declined_where_nothing_honours_it() -> None:
    """Off the OpenShift family no operator reads it, and the manifest is probably destined for one, so the rule
    names --platform openshift as every other rule about an OpenShift object does -- it does not report."""
    report = _report(_webhook(dict(SERVICE), annotations=OPENSHIFT_INJECTOR))
    assert not _hits(report)
    assert _declined(report)
    assert "--platform openshift" in _why(report)


def test_the_cert_manager_annotation_is_clean_when_the_certificate_it_names_is_in_the_input() -> None:
    text = _webhook(dict(SERVICE), annotations=CERT_MANAGER_INJECTOR) + "---\n" + _certificate()
    assert _clean(_report(text))


@pytest.mark.parametrize(
    "certificate",
    [
        pytest.param(None, id="no-certificate"),
        pytest.param(_certificate(name="other-cert"), id="another-name"),
        pytest.param(_certificate(namespace="other"), id="another-namespace"),
        pytest.param(_certificate().replace("cert-manager.io/v1", "example.com/v1"), id="another-group"),
    ],
)
def test_the_cert_manager_annotation_is_declined_when_that_certificate_is_not_here(certificate: str | None) -> None:
    """class 3 and class 21: the Certificate is matched on group, namespace AND name, so a near miss is a miss."""
    text = _webhook(dict(SERVICE), annotations=CERT_MANAGER_INJECTOR)
    if certificate:
        text += "---\n" + certificate
    report = _report(text)
    assert not _hits(report)
    assert _declined(report)
    assert "not in the input" in _why(report)


@pytest.mark.parametrize("annotation", ["cert-manager.io/inject-ca-from-secret", "cert-manager.io/inject-apiserver-ca"])
def test_an_injector_that_reads_a_secret_or_the_api_servers_ca_is_declined(annotation: str) -> None:
    """kube-noob never reads Secrets and has no node to read, so neither source can be checked."""
    report = _report(_webhook(dict(SERVICE), annotations={annotation: "true"}))
    assert not _hits(report)
    assert _declined(report)


def test_an_injected_bundle_is_not_reported_even_when_the_value_in_the_manifest_is_expired() -> None:
    """class 21: the neighbouring input -- an injector annotation beside a bundle, not instead of one. The
    controller replaces whatever is written there, so a stale certificate in the manifest decides nothing."""
    report = _report(
        _webhook({**SERVICE, "caBundle": _b64(EXPIRED_CA)}, annotations=OPENSHIFT_INJECTOR), platform="openshift"
    )
    assert not _hits(report)
    assert _clean(report)


# =====================================================================================================
# Shapes the API server itself refuses, declined rather than guessed
# =====================================================================================================


def test_a_webhook_entry_with_no_client_config_is_declined() -> None:
    report = _report(_webhook(None))
    assert _declined(report)


def test_a_client_config_that_is_not_a_mapping_is_declined() -> None:
    doc = yaml.safe_dump(
        {
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingWebhookConfiguration",
            "metadata": {"name": "w"},
            "webhooks": [{"name": "a.example.com", "clientConfig": "service"}],
        }
    )
    assert _declined(_report(doc))


def test_webhooks_that_are_not_a_list_are_declined_not_read_as_none() -> None:
    doc = yaml.safe_dump(
        {
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingWebhookConfiguration",
            "metadata": {"name": "w"},
            "webhooks": {"name": "a.example.com"},
        }
    )
    assert _declined(_report(doc))


def test_the_failure_policy_rule_is_not_repeated_here() -> None:
    """KN-S030 owns `failurePolicy: Ignore`; this rule must not report it a second time (class 9)."""
    text = _webhook({**SERVICE, "caBundle": _b64(VALID_CA)}, failurePolicy="Ignore")
    report = _report(text)
    assert [f.rule_id for f in report.findings if f.rule_id in ("KN-S030", "KN-S046")] == ["KN-S030"]


# =====================================================================================================
# No input text in a decline reason (G281's rule)
# =====================================================================================================


def test_no_decline_reason_repeats_text_from_the_input() -> None:
    marker = "ZZmarkerZZ"
    text = _webhook({**SERVICE, "caBundle": marker}, annotations={"cert-manager.io/inject-ca-from": marker})
    assert marker not in _why(_report(text))
