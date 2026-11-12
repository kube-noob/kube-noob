"""The second adversarial review of KN-S037..KN-S041 (G272): the neighbours of the first fifteen fixes.

Every test here is a shape that read as clean, as a finding it was not, or as a line the report did not write. The
rule throughout: where the manifest does not say, the rule DECLINES with the reason, never clean. Each fixed shape
is tried beside one clean API server or etcd too, because a decline that only shows when the shape is alone is a
clean result for the bundle a reviewer actually passes.
"""

from __future__ import annotations

import json
from pathlib import Path
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
    name: str = "x",
) -> str:
    c: dict[str, Any] = {"name": "c", "image": image}
    if command is not None:
        c["command"] = command
    if args is not None:
        c["args"] = args
    if env is not None:
        c["env"] = env
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


def _declined(report: Report, rid: str) -> bool:
    return rid not in report.evaluated_rules and any(
        a.startswith(f"{rid} was not evaluated") for a in report.assumptions
    )


def _quiet(report: Report, rid: str) -> bool:
    return rid not in report.evaluated_rules and not any(a.startswith(rid) for a in report.assumptions)


def _clean(report: Report, rid: str) -> bool:
    return rid in report.evaluated_rules and not _hits(report, rid)


AA = "--authorization-mode=AlwaysAllow"
KAS_IMAGE = "registry.k8s.io/kube-apiserver:v1.34.0"
ETCD_IMAGE = "quay.io/coreos/etcd:v3.5.17"
CLEAN_KAS = _pod(["kube-apiserver", "--authorization-mode=Node,RBAC", "--anonymous-auth=false"], name="good")
TLS = [
    "--listen-client-urls=https://10.0.0.1:2379",
    "--advertise-client-urls=https://10.0.0.1:2379",
    "--cert-file=/c",
    "--key-file=/k",
    "--client-cert-auth=true",
    "--trusted-ca-file=/ca",
    "--listen-peer-urls=https://10.0.0.1:2380",
    "--initial-advertise-peer-urls=https://10.0.0.1:2380",
    "--peer-cert-file=/pc",
    "--peer-key-file=/pk",
    "--peer-client-cert-auth=true",
    "--peer-trusted-ca-file=/ca",
]
CLEAN_ETCD = _pod(["etcd", *TLS], name="good")


def test_the_clean_baselines_are_clean() -> None:
    assert _clean(_r(CLEAN_KAS), "KN-S038")
    assert _clean(_r(CLEAN_ETCD), "KN-S039")


# --- 1. etcd --auto-tls without certificate files drops client-certificate checking ------------------------------
# embed/config.go ClientSelfCert/PeerSelfCert (release-3.5): with auto TLS on and no cert and key file, the
# TLSInfo is REPLACED by transport.SelfCert's, which sets neither ClientCertAuth nor TrustedCAFile, so
# TLSInfo.ServerConfig leaves ClientAuth at tls.NoClientCert (client/pkg/transport/listener.go).

_CLIENT_ONLY = [
    "--listen-client-urls=https://10.0.0.1:2379",
    "--advertise-client-urls=https://10.0.0.1:2379",
    "--client-cert-auth=true",
    "--trusted-ca-file=/ca",
]
_PEER_ONLY = [
    "--listen-client-urls=https://127.0.0.1:2379",
    "--advertise-client-urls=https://127.0.0.1:2379",
    "--listen-peer-urls=https://10.0.0.1:2380",
    "--initial-advertise-peer-urls=https://10.0.0.1:2380",
    "--peer-client-cert-auth=true",
    "--peer-trusted-ca-file=/ca",
]


@pytest.mark.parametrize(
    ("argv", "env"),
    [
        (["etcd", "--auto-tls=true", *_CLIENT_ONLY], None),
        (["etcd", "--auto-tls", *_CLIENT_ONLY], None),
        (["etcd", *_CLIENT_ONLY, "-auto-tls"], None),
        (["etcd", *_CLIENT_ONLY], [{"name": "ETCD_AUTO_TLS", "value": "true"}]),
    ],
)
def test_etcd_auto_tls_without_certificate_files_accepts_any_client(
    argv: list[str], env: list[dict[str, Any]] | None
) -> None:
    hits = _hits(_r(_pod(argv, env=env)), "KN-S039")
    assert [h.severity for h in hits] == [Severity.CRITICAL]
    assert "auto-tls" in hits[0].message and "client-cert-auth" in hits[0].message


@pytest.mark.parametrize(
    ("argv", "env"),
    [
        (["etcd", "--peer-auto-tls=true", *_PEER_ONLY], None),
        (["etcd", "--peer-auto-tls", *_PEER_ONLY], None),
        (["etcd", *_PEER_ONLY], [{"name": "ETCD_PEER_AUTO_TLS", "value": "1"}]),
    ],
)
def test_etcd_peer_auto_tls_without_certificate_files_accepts_any_peer(
    argv: list[str], env: list[dict[str, Any]] | None
) -> None:
    hits = _hits(_r(_pod(argv, env=env)), "KN-S039")
    assert [h.severity for h in hits] == [Severity.HIGH]
    assert "peer-auto-tls" in hits[0].message


def test_auto_tls_beside_certificate_files_is_ignored_by_etcd_and_reads_clean() -> None:
    """The neighbour: etcd logs "ignoring client auto TLS since certs given" and keeps the configured TLSInfo."""
    assert _clean(_r(_pod(["etcd", "--auto-tls", "--peer-auto-tls", *TLS])), "KN-S039")
    assert _clean(_r(_pod(["etcd", "--auto-tls=false", *_CLIENT_ONLY, "--cert-file=/c", "--key-file=/k"])), "KN-S039")


def test_auto_tls_on_a_loopback_listener_is_not_a_finding() -> None:
    report = _r(_pod(["etcd", "--auto-tls", "--listen-client-urls=https://127.0.0.1:2379"]))
    assert _clean(report, "KN-S039")


def test_an_auto_tls_value_that_is_not_a_boolean_declines() -> None:
    report = _r(_pod(["etcd", *_CLIENT_ONLY], env=[{"name": "ETCD_AUTO_TLS", "value": "yes"}]))
    assert _declined(report, "KN-S039") and not _hits(report, "KN-S039")


# --- 2. a readable command kube-noob does not recognise, with evidence it starts the binary, declines -----------

_KAS_SHAPES = [
    ("s6-svscan, apiserver image", _pod(["s6-svscan", "/etc/s6"], image=KAS_IMAGE, name="w")),
    ("/pause, apiserver image and flags", _pod(["/pause"], [AA], image=KAS_IMAGE, name="w")),
    ("/pause, apiserver flags only", _pod(["/pause"], [AA], name="w")),
    ("busybox sh -c", _pod(["busybox", "sh", "-c", "kube-apiserver " + AA], name="w")),
    ("/bin/busybox ash -c", _pod(["/bin/busybox", "ash", "-c", "exec kube-apiserver " + AA], name="w")),
    (
        "python3 -c execvp",
        _pod(["python3", "-c", "import os;os.execvp('kube-apiserver',['kube-apiserver','" + AA + "'])"], name="w"),
    ),
    ("script file, apiserver image and flags", _pod(["/scripts/start.sh"], [AA], image=KAS_IMAGE, name="w")),
    ("script file, apiserver flags", _pod(["/scripts/start.sh"], [AA], name="w")),
    ("sh <file>, apiserver image", _pod(["sh", "/scripts/start.sh"], image=KAS_IMAGE, name="w")),
    ("env sh -c", _pod(["env", "sh", "-c", "kube-apiserver " + AA], name="w")),
    (
        "env with assignments and flags",
        _pod(["/usr/bin/env", "-i", "A=1", "sh", "-c", "kube-apiserver " + AA], name="w"),
    ),
    ("env -u NAME", _pod(["env", "-u", "HOME", "/bin/bash", "-c", "exec kube-apiserver " + AA], name="w")),
    ("mksh -c", _pod(["/bin/mksh", "-c", "kube-apiserver " + AA], name="w")),
    ("tini then sh -c", _pod(["tini", "--", "sh", "-c", "kube-apiserver " + AA], name="w")),
    ("underscore hint flag", _pod(["/scripts/start.sh"], ["--authorization_mode=AlwaysAllow"], name="w")),
]


@pytest.mark.parametrize(("label", "text"), _KAS_SHAPES, ids=[s[0] for s in _KAS_SHAPES])
def test_an_unread_entrypoint_with_apiserver_evidence_declines_alone_and_beside_a_clean_one(
    label: str, text: str
) -> None:
    alone = _r(text)
    assert _declined(alone, "KN-S038") and not _hits(alone, "KN-S038"), label
    mixed = _r(CLEAN_KAS + "---\n" + text)
    assert _declined(mixed, "KN-S038") and not _clean(mixed, "KN-S038"), label
    assert any("Pod/kube-system/w" in a for a in mixed.assumptions if a.startswith("KN-S038")), label


_ETCD_SHAPES = [
    ("busybox sh -c", _pod(["busybox", "sh", "-c", "exec etcd --listen-client-urls=http://0.0.0.0:2379"], name="w")),
    ("script file, etcd image", _pod(["/scripts/etcd.sh"], image=ETCD_IMAGE, name="w")),
    ("python execvp", _pod(["python3", "-c", "import os;os.execvp('etcd',['etcd'])"], name="w")),
    ("s6-svscan, etcd image", _pod(["s6-svscan", "/etc/s6"], image=ETCD_IMAGE, name="w")),
    ("/pause, etcd flags", _pod(["/pause"], ["--listen-client-urls=http://0.0.0.0:2379"], name="w")),
    ("sh <file>, etcd image", _pod(["sh", "/scripts/etcd.sh"], image=ETCD_IMAGE, name="w")),
    ("env FOO=1 sh -c", _pod(["env", "FOO=1", "sh", "-c", "etcd --listen-client-urls=http://0.0.0.0:2379"], name="w")),
]


@pytest.mark.parametrize(("label", "text"), _ETCD_SHAPES, ids=[s[0] for s in _ETCD_SHAPES])
def test_an_unread_entrypoint_with_etcd_evidence_declines_alone_and_beside_a_clean_one(label: str, text: str) -> None:
    alone = _r(text)
    assert _declined(alone, "KN-S039") and not _hits(alone, "KN-S039"), label
    mixed = _r(CLEAN_ETCD + "---\n" + text)
    assert _declined(mixed, "KN-S039") and not _clean(mixed, "KN-S039"), label


@pytest.mark.parametrize(
    ("rid", "text"),
    [
        ("KN-S038", _pod(["nginx", "-g", "daemon off;"])),
        ("KN-S038", _pod(["sh", "-c", "echo hello"])),
        ("KN-S038", _pod(["busybox", "wget", "-O-", "http://x"])),
        ("KN-S038", _pod(["sh", "/app/run.sh"])),
        ("KN-S038", _pod(["k3s", "agent"], image="rancher/k3s:v1.30.0-k3s1")),
        ("KN-S039", _pod(["etcdctl", "snapshot", "save", "/var/lib/etcd/s.db"], image=ETCD_IMAGE)),
        ("KN-S039", _pod(["/app/server", "--config-file=/etc/app.yaml", "--cert-file=/c", "--key-file=/k"])),
        ("KN-S039", _pod(["sh", "-c", "tar czf /b/x.tgz /var/lib/etcd"])),
    ],
)
def test_a_command_with_no_evidence_of_the_binary_is_not_recognised(rid: str, text: str) -> None:
    """The neighbour the other way: declining every app container would bury the decline that matters."""
    assert _quiet(_r(text), rid)


# --- 3. kube-apiserver normalises `_` to `-` in flag names; etcd does not ----------------------------------------
# component-base/cli/run.go sets cliflag.WordSepNormalizeFunc on the cobra command (cli/flag/flags.go), so
# --authorization_mode IS --authorization-mode. pflag's StringSlice appends every occurrence after the first.


def test_an_underscored_authorization_mode_appends_always_allow() -> None:
    hits = _hits(
        _r(
            _pod(
                [
                    "kube-apiserver",
                    "--authorization-mode=Node,RBAC",
                    "--authorization_mode=AlwaysAllow",
                    "--anonymous-auth=false",
                ]
            )
        ),
        "KN-S038",
    )
    assert [h.severity for h in hits] == [Severity.CRITICAL] and "AlwaysAllow" in hits[0].message


def test_an_underscored_anonymous_auth_given_last_wins() -> None:
    hits = _hits(
        _r(
            _pod(
                ["kube-apiserver", "--authorization-mode=Node,RBAC", "--anonymous-auth=false", "--anonymous_auth=true"]
            )
        ),
        "KN-S038",
    )
    assert [h.severity for h in hits] == [Severity.MEDIUM]


def test_an_underscored_authorization_config_is_not_read_as_no_authorizer() -> None:
    report = _r(_pod(["kube-apiserver", "--authorization_config=/etc/k/authz.yaml", "--anonymous-auth=false"]))
    assert not [h for h in _hits(report, "KN-S038") if h.severity is Severity.CRITICAL]
    assert _declined(report, "KN-S038")


def test_an_underscored_authentication_config_declines_like_the_dash_form() -> None:
    report = _r(_pod(["kube-apiserver", "--authorization-mode=Node,RBAC", "--authentication_config=/x"]))
    assert _declined(report, "KN-S038") and not _hits(report, "KN-S038")


def test_etcd_does_not_normalise_underscores() -> None:
    """Go's flag package has no normaliser: --listen_client_urls is not --listen-client-urls."""
    report = _r(_pod(["etcd", *TLS, "--listen_client_urls=http://0.0.0.0:2379"]))
    assert not _hits(report, "KN-S039") and _declined(report, "KN-S039")


# --- 4. --version and --help count only where the parser would read them as flags --------------------------------


@pytest.mark.parametrize(
    "argv",
    [
        ["kube-apiserver", "--etcd-prefix", "--version", AA],
        ["kube-apiserver", "--authorization-mode", "AlwaysAllow", "--audit-log-path", "-h"],
    ],
)
def test_a_swallowed_version_or_help_is_not_read_as_one(argv: list[str]) -> None:
    for text in (_pod(argv, name="w"), CLEAN_KAS + "---\n" + _pod(argv, name="w")):
        report = _r(text)
        assert not _clean(report, "KN-S038") and not _quiet(report, "KN-S038")


def test_a_swallowed_etcd_version_is_not_read_as_one() -> None:
    argv = ["etcd", "--name", "--version", "--listen-client-urls=http://0.0.0.0:2379"]
    for text in (_pod(argv, name="w"), CLEAN_ETCD + "---\n" + _pod(argv, name="w")):
        report = _r(text)
        assert not _clean(report, "KN-S039") and not _quiet(report, "KN-S039")


@pytest.mark.parametrize(
    "argv",
    [
        ["kube-apiserver", "--version=false", AA],
        ["kube-apiserver", "--help=false", AA],
        ["kube-apiserver", "--version=raw", "--version=false", AA],
        ["kube-apiserver", "--version=v1.33.0", AA],
    ],
)
def test_a_version_or_help_flag_set_false_is_still_a_server(argv: list[str]) -> None:
    assert [h.severity for h in _hits(_r(_pod(argv)), "KN-S038")] == [Severity.CRITICAL]


@pytest.mark.parametrize(
    "argv",
    [["kube-apiserver", "--version=raw"], ["kube-apiserver", AA, "--version"], ["kube-apiserver", "-h", AA]],
)
def test_a_version_or_help_at_a_real_flag_position_is_not_a_server(argv: list[str]) -> None:
    assert _quiet(_r(_pod(argv)), "KN-S038")


def test_an_etcd_version_false_is_a_server_and_an_unparseable_one_declines() -> None:
    assert _hits(_r(_pod(["etcd", "--version=false", "--listen-client-urls=http://0.0.0.0:2379"])), "KN-S039")
    assert _declined(_r(_pod(["etcd", "--version=maybe", "--listen-client-urls=http://0.0.0.0:2379"])), "KN-S039")


# --- 7. authorization combinations the API server refuses decline --------------------------------------------------


@pytest.mark.parametrize(
    "flags",
    [
        ["--authorization-mode=Webhook"],
        ["--authorization-mode=Node,ABAC"],
        ["--authorization-mode=RBAC,RBAC"],
        ["--authorization-mode=Node", "--authorization-mode=Node"],
        ["--authorization-config=/x", "--authorization-mode=Node,RBAC"],
        ["--authorization-config=/x", "--authorization-mode="],
        ["--authorization-config=/x", "--authorization-webhook-version=v1"],
        ["--authorization-mode=Node,RBAC", "--authorization-policy-file=/p"],
        ["--authorization-mode=Node,RBAC", "--authorization-webhook-config-file=/w"],
        ["--authorization-policy-file=/p"],
    ],
)
def test_an_authorization_combination_the_api_server_refuses_declines(flags: list[str]) -> None:
    report = _r(_pod(["kube-apiserver", *flags]))
    assert _declined(report, "KN-S038") and not _hits(report, "KN-S038")
    assert any("refuses" in a for a in report.assumptions if a.startswith("KN-S038"))


@pytest.mark.parametrize(
    "flags",
    [
        ["--authorization-mode=Node,Webhook", "--authorization-webhook-config-file=/w"],
        ["--authorization-mode=ABAC,RBAC", "--authorization-policy-file=/p"],
    ],
)
def test_the_accepted_neighbours_of_a_refused_combination_are_read(flags: list[str]) -> None:
    assert _clean(_r(_pod(["kube-apiserver", *flags, "--anonymous-auth=false"])), "KN-S038")


# --- 8. a known boolean given bare is true, not a possible swallow --------------------------------------------------


@pytest.mark.parametrize("flag", ["--allow-privileged", "--profiling", "--enable-aggregator-routing", "-h=false"])
def test_a_bare_apiserver_boolean_does_not_decline(flag: str) -> None:
    report = _r(_pod(["kube-apiserver", flag, "--authorization-mode=Node,RBAC", "--anonymous-auth=false"]))
    assert _clean(report, "KN-S038")


@pytest.mark.parametrize(
    "flag", ["--experimental-initial-corrupt-check", "--enable-v2", "-strict-reconfig-check", "--enable-pprof"]
)
def test_a_bare_etcd_boolean_does_not_decline(flag: str) -> None:
    assert _clean(_r(_pod(["etcd", flag, *TLS])), "KN-S039")


def test_an_unknown_bare_flag_before_a_flag_still_declines() -> None:
    assert _declined(_r(_pod(["kube-apiserver", "--not-a-flag", "--authorization-mode=Node,RBAC"])), "KN-S038")
    assert _declined(_r(_pod(["etcd", "--not-a-flag", *TLS])), "KN-S039")


def test_a_bad_flag_syntax_declines() -> None:
    report = _r(_pod(["kube-apiserver", "---authorization-mode=AlwaysAllow", "--authorization-mode=Node,RBAC"]))
    assert _declined(report, "KN-S038")


# --- 9. wording, and the claims documents make --------------------------------------------------------------------


def test_a_rule_with_a_finding_on_one_object_and_a_decline_on_another_says_both() -> None:
    """docs/use-cases.md: the finding is reported and counted under its controls, and the decline is stated; the
    rule is not in notEvaluatedRules because it did reach a verdict -- a finding."""
    report = _r(_pod(["kube-apiserver", AA], name="a") + "---\n" + _pod(["sh", "-c", "kube-apiserver"], name="b"))
    assert _hits(report, "KN-S038") and _declined(report, "KN-S038")
    out = report.as_dict()
    assert "KN-S038" in out["declined"]
    assert "KN-S038" not in out["controlSummary"]["notEvaluatedRules"]
    ac3 = next(c for c in out["controlSummary"]["controls"] if c["id"] == "AC-3")
    assert ac3["findings"] >= 1


def test_ldap_insecure_given_as_a_string_says_so() -> None:
    text = (
        "apiVersion: config.openshift.io/v1\nkind: OAuth\nmetadata: {name: cluster}\nspec:\n  identityProviders:\n"
        "  - name: l\n    type: LDAP\n    ldap: {url: 'ldap://d/x', insecure: 'true'}\n"
    )
    line = next(a for a in _r(text, "openshift", "4.20").assumptions if a.startswith("KN-S041"))
    assert "no readable ldap.url" not in line and "insecure" in line and "not a boolean" in line


@pytest.mark.parametrize("kms", ["kms: {}", "kms: null", ""])
def test_kms_encryption_without_a_kms_configuration_declines(kms: str) -> None:
    spec = "{type: KMS" + (", " + kms if kms else "") + "}"
    text = "apiVersion: config.openshift.io/v1\nkind: APIServer\nmetadata: {name: cluster}\nspec:\n"
    text += f"  encryption: {spec}\n"
    report = _r(text, "openshift", "4.20")
    assert _declined(report, "KN-S040") and not _hits(report, "KN-S040")


def test_kms_encryption_with_a_kms_configuration_is_clean() -> None:
    text = (
        "apiVersion: config.openshift.io/v1\nkind: APIServer\nmetadata: {name: cluster}\nspec:\n"
        "  encryption:\n    type: KMS\n    kms:\n      type: AWS\n"
        "      aws: {keyARN: 'arn:aws:kms:us-east-1:1:key/x', region: us-east-1}\n"
    )
    assert _clean(_r(text, "openshift", "4.20"), "KN-S040")


def test_the_gate_summary_keeps_assumptions_apart_from_what_was_not_evaluated() -> None:
    from kube_noob import gate

    report = gate.run([gate.Source("cp.yaml", _pod(["sh", "-c", "exec kube-apiserver"]))], fail_on="never")
    md = gate.markdown(report)
    head, _, rest = md.partition("### Not evaluated in full")
    assert rest, md
    not_evaluated = rest.split("\n### ", 1)[0]
    assert "KN-S038 was not evaluated" in not_evaluated and "assumed" not in not_evaluated
    assert "### Assumptions" in head and "assumed 1.35" in head.split("### Assumptions", 1)[1]


def test_an_exception_on_a_declined_object_is_not_called_stale(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from kube_noob.cli import main

    bundle = tmp_path / "b.yaml"
    bundle.write_text(_pod(["sh", "-c", "exec kube-apiserver --x"], name="b"), encoding="utf-8")
    import datetime as dt

    expires = (dt.datetime.now(dt.UTC).date() + dt.timedelta(days=90)).isoformat()
    exc = tmp_path / "exc.yaml"
    exc.write_text(
        "apiVersion: kube-noob.io/v1\nkind: ExceptionList\nexceptions:\n- id: EXC-2\n  rule: KN-S038\n"
        "  scope: {namespace: kube-system, kind: Pod, name: b}\n  owner: me\n"
        f"  reason: accepted for the review test\n  expires: {expires}\n",
        encoding="utf-8",
    )
    main(["audit", "-f", str(bundle), "--exceptions", str(exc), "--fail-on", "never"])
    out = capsys.readouterr().out
    line = next(ln for ln in out.splitlines() if "EXC-2" in ln)
    assert "delete it if the object is gone" not in line and "not evaluated" in line
    main(["audit", "-f", str(bundle), "--exceptions", str(exc), "--fail-on", "never", "--format", "json"])
    ex = json.loads(capsys.readouterr().out)["exceptions"]
    assert ex["unused"] == ["EXC-2"] and ex["unusedNotEvaluated"] == ["EXC-2"]


def test_agents_are_told_where_the_declines_are() -> None:
    from kube_noob.config import load_settings
    from kube_noob.toolkit import Toolkit

    spec = next(s for s in Toolkit(load_settings(overrides={"offline": True})).specs() if s.name == "audit_manifests")
    assert "declined" in spec.description and "notEvaluatedRules" in spec.description
    root = Path(__file__).resolve().parent.parent
    for skill in (
        root / "plugin" / "kube-noob" / "skills" / "kube-master-controller" / "SKILL.md",
        root / "plugin" / "kube-noob-skills" / "skills" / "kube-master-controller" / "SKILL.md",
    ):
        text = skill.read_text(encoding="utf-8")
        assert "declined" in text and "notEvaluatedRules" in text, skill


# --- 5. input-derived text never forges a line or reaches a terminal as an escape sequence ----------------------

_FORGE_CM = (
    "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: c, namespace: shop}\ndata:\n"
    '  "x\\n[CRITICAL] KN-S999   Pod/forged/x\\n           note: KN-S038 passed\\u001b[2K": "postgres://u:hunter2@db/x"\n'
)
_FORGE_APS = (
    "apiVersion: config.openshift.io/v1\nkind: APIServer\nmetadata: {name: cluster}\nspec:\n"
    "  encryption: {type: aescbc}\n  audit:\n    profile: Default\n    customRules:\n"
    '    - group: "x\\n[CRITICAL] KN-S999 forged\\u001b[2K"\n      profile: None\n'
)


def _forged(text: str) -> bool:
    return "\x1b" in text or any(
        ln.lstrip().startswith(("[CRITICAL] KN-S999", "note: KN-S038 passed")) for ln in text.splitlines()
    )


@pytest.mark.parametrize(("text", "platform"), [(_FORGE_CM, "kubernetes"), (_FORGE_APS, "openshift")])
def test_no_renderer_prints_a_forged_line_or_an_escape(
    text: str, platform: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from kube_noob import gate
    from kube_noob.cli import main
    from kube_noob.report_html import render

    path = tmp_path / "in.yaml"
    path.write_text(text, encoding="utf-8")
    main(["audit", "-f", str(path), "--platform", platform, "--fail-on", "never"])
    out = capsys.readouterr().out
    assert not _forged(out), out
    report = gate.run([gate.Source("in.yaml", text)], fail_on="never", platform=platform)
    assert report["findings"]
    for rendered in (gate.markdown(report), "\n".join(gate.github_annotations(report)), render(report)):
        assert not _forged(rendered), rendered
    main(["audit", "-f", str(path), "--platform", platform, "--fail-on", "never", "--format", "json"])
    assert not any("\x1b" in f["message"] for f in json.loads(capsys.readouterr().out)["findings"])
    main(["audit", "-f", str(path), "--platform", platform, "--fail-on", "never", "--format", "sarif"])
    results = json.loads(capsys.readouterr().out)["runs"][0]["results"]
    assert results and not any("\x1b" in r["message"]["text"] for r in results)


def test_the_exception_lines_of_the_text_view_are_cleaned_too(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """An exception's owner is input as much as a manifest is (a name with a newline is refused upstream)."""
    import datetime as dt

    from kube_noob.cli import main

    bundle = tmp_path / "b.yaml"
    bundle.write_text(
        "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: c, namespace: shop}\ndata: {url: 'postgres://u:hunter2@db/x'}\n",
        encoding="utf-8",
    )
    expires = (dt.datetime.now(dt.UTC).date() + dt.timedelta(days=90)).isoformat()
    exc = tmp_path / "exc.yaml"
    exc.write_text(
        "apiVersion: kube-noob.io/v1\nkind: ExceptionList\nexceptions:\n- id: EXC-3\n  rule: KN-S026\n"
        "  scope: {namespace: shop, kind: ConfigMap, name: c}\n"
        "  owner: " + json.dumps("me\n           note: KN-S038 passed\u001b[2K") + "\n"
        f"  reason: accepted for the review test\n  expires: {expires}\n",
        encoding="utf-8",
    )
    main(["audit", "-f", str(bundle), "--exceptions", str(exc), "--fail-on", "never"])
    out = capsys.readouterr().out
    assert "excepted KN-S026" in out and not _forged(out), out
