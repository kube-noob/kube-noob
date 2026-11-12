"""The adversarial review of KN-S037..KN-S041 (G272): fifteen shapes the first tests did not try.

Every test here is a shape that read as clean, as a finding it was not, or as a decline nobody could see. The rule
throughout: where the manifest does not say, the rule DECLINES with the reason, and the decline is visible in text,
JSON, SARIF, the gate, OSCAL and KSI -- never clean.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from kube_noob.audit.engine import analyze
from kube_noob.audit.model import Report, Severity

FIXTURES = Path(__file__).parent / "fixtures"
APP = (
    "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: web, namespace: shop}\nspec:\n"
    "  selector: {matchLabels: {app: web}}\n  template:\n    metadata: {labels: {app: web}}\n    spec:\n"
    "      containers:\n      - name: web\n        image: quay.io/acme/web@sha256:" + "0" * 64 + "\n"
)


def _pod(
    command: Any = None,
    args: Any = None,
    image: str = "img:1",
    env: list[dict[str, Any]] | None = None,
    name: str = "x",
    container: str = "c",
    env_from: bool = False,
) -> str:
    c: dict[str, Any] = {"name": container, "image": image}
    if command is not None:
        c["command"] = command
    if args is not None:
        c["args"] = args
    if env is not None:
        c["env"] = env
    if env_from:
        c["envFrom"] = [{"configMapRef": {"name": "etcd"}}]
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
    """Not evaluated, and no sentence about it (nothing of its kind was in the input)."""
    return rid not in report.evaluated_rules and not any(a.startswith(rid) for a in report.assumptions)


def _clean(report: Report, rid: str) -> bool:
    return rid in report.evaluated_rules and not _hits(report, rid)


# --- 1. unrecognised launch shapes decline, they are not clean --------------------------------------------------


AA = "--authorization-mode=AlwaysAllow"


@pytest.mark.parametrize(
    ("label", "text"),
    [
        ("no command, image says kube-apiserver", _pod(None, [AA], image="registry.k8s.io/kube-apiserver:v1.34.0")),
        ("no command, args carry an apiserver flag", _pod(None, [AA], image="quay.io/me/cp:1")),
        ("go-runner", _pod(["/go-runner", "--log-file=/l", "/usr/local/bin/kube-apiserver", AA])),
        ("tini", _pod(["tini", "--", "kube-apiserver", AA])),
        ("env", _pod(["/usr/bin/env", "kube-apiserver", AA])),
        ("hyperkube alias", _pod(["/hyperkube", "apiserver", AA])),
        ("k3s", _pod(["k3s", "server", "--kube-apiserver-arg=authorization-mode=AlwaysAllow"])),
        ("rke2", _pod(["rke2", "server", "--kube-apiserver-arg=authorization-mode=AlwaysAllow"])),
        ("non-string in command", _pod(["kube-apiserver", AA, 6443])),
        ("command is a string", _pod("kube-apiserver --authorization-mode=AlwaysAllow")),
    ],
)
def test_an_apiserver_launched_in_a_shape_not_read_declines_rather_than_reading_clean(label: str, text: str) -> None:
    report = _r(text)
    assert not _hits(report, "KN-S038"), label
    assert _declined(report, "KN-S038"), label


@pytest.mark.parametrize(
    ("label", "text"),
    [
        (
            "no command, etcd image",
            _pod(None, ["--listen-client-urls=http://0.0.0.0:2379"], image="quay.io/coreos/etcd:v3.5.0"),
        ),
        (
            "env only, no command",
            _pod(
                None,
                None,
                image="bitnami/etcd:3.5",
                env=[{"name": "ETCD_LISTEN_CLIENT_URLS", "value": "http://0.0.0.0:2379"}],
            ),
        ),
        ("tini", _pod(["tini", "--", "etcd", "--listen-client-urls=http://0.0.0.0:2379"])),
        ("etcd subcommand", _pod(["etcd", "gateway", "start", "--listen-addr=0.0.0.0:2379"])),
    ],
)
def test_an_etcd_launched_in_a_shape_not_read_declines(label: str, text: str) -> None:
    report = _r(text)
    assert not _hits(report, "KN-S039"), label
    assert _declined(report, "KN-S039"), label


def test_a_container_that_does_not_run_the_binary_is_not_recognised() -> None:
    report = _r(_pod(["nginx", "-g", "daemon off;"], name="kube-apiserver", container="kube-apiserver"))
    assert not any(a.startswith("KN-S038") for a in report.assumptions)


# --- 2. every shell wrapper declines, including OpenShift's real etcd static pod -------------------------------


@pytest.mark.parametrize(
    "script",
    [
        "exec kube-apiserver \\\n  --authorization-mode=AlwaysAllow",
        'exec kube-apiserver "$@"',
        "kube-apiserver $FLAGS",
        "exec /usr/local/bin/kube-apiserver --authorization-mode=AlwaysAllow",
    ],
)
def test_a_shell_script_that_runs_the_apiserver_declines(script: str) -> None:
    report = _r(_pod(["/bin/sh", "-c", script, "--", AA]))
    assert _declined(report, "KN-S038") and not _hits(report, "KN-S038")


@pytest.mark.parametrize("platform", ["kubernetes", "openshift"])
def test_openshifts_own_etcd_static_pod_declines_on_both_platforms(platform: str) -> None:
    # The operator renders `${COMPUTED_ENV_VARS}` into extra env entries before writing the pod; a line of its own
    # in the template, it is dropped here so the YAML parses. Everything else is the upstream file as shipped.
    raw = (FIXTURES / "control-plane" / "openshift-etcd-pod.yaml").read_text(encoding="utf-8")
    text = "\n".join(ln for ln in raw.splitlines() if ln.strip() != "${COMPUTED_ENV_VARS}")
    report = _r(text, platform, "4.18" if platform == "openshift" else None)
    assert _declined(report, "KN-S039") and not _hits(report, "KN-S039")


def test_a_script_that_only_names_the_data_directory_is_not_etcd() -> None:
    report = _r(_pod(["/bin/sh", "-c", "tar czf /backup/x.tgz /var/lib/etcd"]))
    assert not any(a.startswith("KN-S039") for a in report.assumptions)
    assert not any(a.startswith("KN-S039") for a in _r(_pod(["/bin/sh", "-c", "etcdctl member list"])).assumptions)


# --- 3. a trusted CA turns client certificates on ---------------------------------------------------------------


def test_a_trusted_ca_without_client_cert_auth_still_requires_certificates() -> None:
    report = _r(
        _pod(
            [
                "etcd",
                "--listen-client-urls=https://10.0.0.1:2379",
                "--advertise-client-urls=https://10.0.0.1:2379",
                "--cert-file=/c",
                "--key-file=/k",
                "--trusted-ca-file=/ca",
                "--listen-peer-urls=https://10.0.0.1:2380",
                "--initial-advertise-peer-urls=https://10.0.0.1:2380",
                "--peer-trusted-ca-file=/ca",
            ]
        )
    )
    assert _clean(report, "KN-S039")


def test_a_trusted_ca_from_the_environment_counts_too() -> None:
    report = _r(
        _pod(
            ["etcd", "--listen-client-urls=https://10.0.0.1:2379", "--advertise-client-urls=https://10.0.0.1:2379"],
            env=[{"name": "ETCD_TRUSTED_CA_FILE", "value": "/ca"}],
        )
    )
    assert _clean(report, "KN-S039")


# --- 4. the OpenShift-only rules are not clean on plain Kubernetes ----------------------------------------------


def test_off_openshift_the_openshift_rules_are_not_evaluated_and_sc_28_1_is_not_satisfied() -> None:
    from kube_noob import oscal

    report = _r(APP)
    for rid in ("KN-S035", "KN-S040", "KN-S041"):
        assert _quiet(report, rid), rid
    summary = {c["id"]: c for c in report.as_dict()["controlSummary"]["controls"]}
    assert summary["SC-28(1)"]["clean"] == 0 and summary["SC-28(1)"]["notEvaluated"] == 1
    assert summary["AU-2"]["clean"] == 0
    doc = oscal.assessment_results(report.as_dict())
    findings = doc["assessment-results"]["results"][0].get("findings", [])
    assert not [f for f in findings if f["target"]["target-id"] == "sc-28.1_obj"]


@pytest.mark.parametrize(
    ("rid", "text"),
    [
        (
            "KN-S040",
            "apiVersion: config.openshift.io/v1\nkind: APIServer\nmetadata: {name: cluster}\n"
            "spec: {encryption: {type: identity}}\n",
        ),
        (
            "KN-S035",
            "apiVersion: config.openshift.io/v1\nkind: APIServer\nmetadata: {name: cluster}\n"
            "spec: {audit: {profile: None}}\n",
        ),
        (
            "KN-S041",
            "apiVersion: config.openshift.io/v1\nkind: OAuth\nmetadata: {name: cluster}\nspec:\n  identityProviders:\n"
            "  - {name: l, type: LDAP, ldap: {url: 'ldap://d/x', insecure: true}}\n",
        ),
    ],
)
def test_an_openshift_object_audited_without_the_platform_declines_and_says_which_flag(rid: str, text: str) -> None:
    report = _r(text)
    assert _declined(report, rid)
    assert any(a.startswith(rid) and "--platform openshift" in a for a in report.assumptions)


def test_the_ksi_view_does_not_count_the_openshift_rules_clean_on_kubernetes() -> None:
    from kube_noob.audit import fedramp

    report = _r(APP)
    view = fedramp.summary(
        [f.rule_id for f in report.findings], None, sorted(report.evaluated_rules), sorted(report.fired_rules)
    )
    row = {r["id"]: r for r in view["indicators"]}["KSI-SVC-SIN"]
    assert "KN-S040" in row.get("notEvaluatedRules", [])


# --- 5. no control-plane object in the input is not clean -------------------------------------------------------


def test_an_application_bundle_does_not_make_the_control_plane_rules_clean() -> None:
    report = _r(APP)
    for rid in ("KN-S037", "KN-S038", "KN-S039"):
        assert _quiet(report, rid), rid
    summary = {c["id"]: c for c in report.as_dict()["controlSummary"]["controls"]}
    assert "KN-S038" in report.as_dict()["controlSummary"]["notEvaluatedRules"]
    assert summary["AC-14"]["notEvaluated"] >= 1


# --- 6. the gate carries the decline in every format ------------------------------------------------------------


def test_the_gate_carries_the_decline_reason_into_json_sarif_markdown_and_html(tmp_path: Path) -> None:
    from kube_noob import gate
    from kube_noob.report_html import render

    text = _pod(["/bin/sh", "-c", "exec kube-apiserver --authorization-mode=AlwaysAllow"], name="kube-apiserver")
    report = gate.run([gate.Source("cp.yaml", text)], fail_on="critical")
    assert any(a.startswith("KN-S038 was not evaluated") for a in report["assumptions"])
    sarif = gate.sarif_of_gate(report)
    notes = [n["message"]["text"] for n in sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"]]
    assert any("KN-S038" in n and "shell script" in n for n in notes)
    md = gate.markdown(report)
    assert "KN-S038" in md and "shell script" in md
    page = render(report)
    assert "KN-S038" in page and "shell script" in page


# --- 7. a quiet decline is visible in text and SARIF ------------------------------------------------------------


def test_a_quiet_decline_is_named_in_the_text_view_and_the_sarif(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from kube_noob.cli import main

    path = tmp_path / "app.yaml"
    path.write_text(APP, encoding="utf-8")
    main(["audit", "-f", str(path), "--platform", "openshift", "--version", "4.20", "--fail-on", "never"])
    out = capsys.readouterr().out
    line = next(ln for ln in out.splitlines() if ln.strip().startswith("not evaluated:"))
    assert "KN-S040" in line and "KN-S041" in line and len(line) < 400
    main(
        [
            "audit",
            "-f",
            str(path),
            "--platform",
            "openshift",
            "--version",
            "4.20",
            "--format",
            "sarif",
            "--fail-on",
            "never",
        ]
    )
    sarif = json.loads(capsys.readouterr().out)
    notes = [n["message"]["text"] for n in sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"]]
    assert any("KN-S040" in n for n in notes)


# --- 8. $(VAR) anywhere in argv declines -------------------------------------------------------------------------


@pytest.mark.parametrize(
    "argv",
    [
        ["kube-apiserver", "$(EXTRA)"],
        ["kube-apiserver", "--authorization-mode=Node,RBAC", "--anonymous-auth=false", "$(EXTRA)"],
        ["kube-apiserver", "--$(F)=AlwaysAllow", "--authorization-mode=Node,RBAC", "--anonymous-auth=false"],
    ],
)
def test_a_variable_anywhere_in_the_apiserver_argv_declines(argv: list[str]) -> None:
    report = _r(_pod(argv))
    assert _declined(report, "KN-S038") and not _hits(report, "KN-S038")


def test_a_variable_anywhere_in_the_etcd_argv_declines() -> None:
    report = _r(_pod(["etcd", "--listen-client-urls=https://127.0.0.1:2379", "$(MORE)"]))
    assert _declined(report, "KN-S039")


# --- 9. a value flag that may swallow the next flag declines ----------------------------------------------------


@pytest.mark.parametrize(
    ("rid", "argv", "env"),
    [
        (
            "KN-S038",
            ["kube-apiserver", "--authorization-mode=Node,RBAC", "--etcd-prefix", "--anonymous-auth=false"],
            None,
        ),
        (
            "KN-S038",
            ["kube-apiserver", "--anonymous-auth=false", "--audit-log-path", "--authorization-mode=AlwaysAllow"],
            None,
        ),
        ("KN-S039", ["etcd", "--name", "--listen-client-urls=http://0.0.0.0:2379"], None),
        (
            "KN-S039",
            ["etcd", "--data-dir", "--listen-client-urls=https://127.0.0.1:2379"],
            [{"name": "ETCD_LISTEN_CLIENT_URLS", "value": "http://0.0.0.0:2379"}],
        ),
    ],
)
def test_an_unknown_flag_followed_by_a_flag_declines_in_both_directions(
    rid: str, argv: list[str], env: list[dict[str, Any]] | None
) -> None:
    report = _r(_pod(argv, env=env))
    assert _declined(report, rid) and not _hits(report, rid)


# --- 10. --version and --help are not servers ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "argv", [["kube-apiserver", "--version"], ["kube-apiserver", "--help"], ["kube-apiserver", "-h"]]
)
def test_a_version_or_help_invocation_is_not_a_server(argv: list[str]) -> None:
    report = _r(_pod(argv))
    assert not _hits(report, "KN-S038") and _quiet(report, "KN-S038")
    assert _quiet(_r(_pod(["etcd", "--version"])), "KN-S039")


# --- 11. a decided finding survives an unrelated undecidable flag -----------------------------------------------


def test_a_decided_plaintext_listener_is_kept_beside_an_undecidable_one() -> None:
    report = _r(_pod(["etcd", "--listen-client-urls=http://0.0.0.0:2379", "--listen-peer-urls=ftp://x"]))
    assert [f.severity for f in _hits(report, "KN-S039")] == [Severity.CRITICAL]
    assert _declined(report, "KN-S039")


def test_the_initial_advertise_peer_urls_are_read() -> None:
    hit = _hits(_r(_pod(["etcd", "--initial-advertise-peer-urls=http://10.0.0.1:2380"])), "KN-S039")
    assert len(hit) == 1 and hit[0].severity == Severity.HIGH and "peers" in hit[0].message


# --- 12. only the object named `cluster` is the singleton --------------------------------------------------------


def _aps(spec: str, name: str = "cluster") -> str:
    return f"apiVersion: config.openshift.io/v1\nkind: APIServer\nmetadata: {{name: {name}}}\n{spec}\n"


def test_a_lone_apiserver_not_named_cluster_declines() -> None:
    report = _r(_aps("spec: {encryption: {type: aescbc}, audit: {profile: Default}}", "other"), "openshift", "4.20")
    for rid in ("KN-S035", "KN-S040"):
        assert _declined(report, rid), rid
        assert any(a.startswith(rid) and "named 'cluster'" in a for a in report.assumptions)


def test_two_objects_named_cluster_decline_as_duplicates() -> None:
    text = _aps("spec: {encryption: {type: aescbc}}") + "---\n" + _aps("spec: {encryption: {type: identity}}")
    report = _r(text, "openshift", "4.20")
    assert _declined(report, "KN-S040") and not _hits(report, "KN-S040")
    assert any(a.startswith("KN-S040") and "2 objects named 'cluster'" in a for a in report.assumptions)


# --- 13. hostile argv is quoted, stripped and capped ------------------------------------------------------------


def test_hostile_argv_cannot_forge_output_lines_or_flood_it() -> None:
    evil = "AlwaysAllow,\n  [CRITICAL] KN-X999 forged \x1b[2K\x1b[1A\u202eevil\u200b" + "A" * 100_000
    report = _r(
        _pod(["kube-apiserver", f"--authorization-mode={evil}", "--anonymous-auth=false"], container="c\nnote: passed")
        + "---\n"
        + _pod(
            ["etcd", f"--listen-client-urls=http://10.0.0.1:2379/\n  note: all clear\x1b[31m{'B' * 100_000}"], name="y"
        )
    )
    texts = [f.message for f in report.findings if f.rule_id in {"KN-S038", "KN-S039"}] + report.assumptions
    assert texts
    for t in texts:
        assert "\n" not in t and "\x1b" not in t and "\u202e" not in t and "\u200b" not in t
        assert len(t) < 1500, len(t)


# --- 14. every declined object is named somewhere --------------------------------------------------------------


def test_five_declined_containers_are_all_named_in_text_and_json() -> None:
    docs = [_pod(["/bin/sh", "-c", "exec kube-apiserver --x"], name=f"cp{i}") for i in range(5)]
    report = _r("---\n".join(docs))
    line = next(a for a in report.assumptions if a.startswith("KN-S038"))
    for i in range(5):
        assert f"Pod/kube-system/cp{i}" in line
    declined = report.as_dict()["declined"]["KN-S038"]
    assert {e["resource"] for e in declined["entries"]} == {f"Pod/kube-system/cp{i}" for i in range(5)}
    assert declined["withheld"] == 0


def test_the_declined_map_is_bounded_with_a_withheld_count() -> None:
    docs = [_pod(["/bin/sh", "-c", "exec kube-apiserver --x"], name=f"cp{i:03d}") for i in range(60)]
    report = _r("---\n".join(docs))
    declined = report.as_dict()["declined"]["KN-S038"]
    assert len(declined["entries"]) <= 50 and declined["withheld"] == 60 - len(declined["entries"])
    line = next(a for a in report.assumptions if a.startswith("KN-S038"))
    assert "not named" in line and len(line) < 4000


def test_the_text_view_keeps_every_finding_on_its_own_lines_whatever_the_manifest_says(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A container NAME is the user's text too, and other rules print it: a newline in it forged a report line."""
    from kube_noob.cli import main

    path = tmp_path / "h.yaml"
    path.write_text(
        _pod(
            ["kube-apiserver", "--authorization-mode=AlwaysAllow,\n  note: all clear\x1b[2K" + "A" * 50_000],
            container="c\nnote: KN-S038 passed",
        ),
        encoding="utf-8",
    )
    main(["audit", "-f", str(path), "--fail-on", "never"])
    out = capsys.readouterr().out
    lines = out.splitlines()
    assert not any(ln.startswith(("note:", "  note: all clear", "  note: KN-S038 passed")) for ln in lines)
    assert "\x1b" not in out and max(len(ln) for ln in lines) <= 2200


def test_the_controls_line_names_only_controls_with_findings(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from kube_noob.cli import main

    path = tmp_path / "app.yaml"
    path.write_text(APP, encoding="utf-8")
    main(["audit", "-f", str(path), "--platform", "openshift", "--version", "4.20", "--fail-on", "never"])
    line = next((ln for ln in capsys.readouterr().out.splitlines() if ln.startswith("NIST SP 800-53")), "")
    assert "(0)" not in line and "SC-28(1)" not in line


@pytest.mark.parametrize(
    ("text", "why"),
    [
        (_aps("spec: {audit: {profile: Default}}", "other"), "none of them is the singleton named 'cluster'"),
        (
            _aps("spec: {audit: {profile: Default}}") + "---\n" + _aps("spec: {audit: {profile: None}}"),
            "2 APIServer objects named 'cluster'",
        ),
    ],
)
def test_detection_coverage_reads_only_the_object_named_cluster(text: str, why: str) -> None:
    """The coverage projection trusted a lone APIServer of any name: the same shape KN-S035 and KN-S040 decline."""
    cov = _r(text, "openshift", "4.20").detection_coverage
    assert cov is not None and why in cov["undecided"]
    assert set(cov) == {"from", "undecided", "controls", "source", "cannotSay"}, "a verdict was drawn anyway"


def test_the_apiservice_policy_is_generated_only_for_the_engine_that_would_run_it() -> None:
    """Kyverno's default resourceFilters exclude APIService, so its policy was installed and checked nothing: the
    kind-cluster acceptance caught the bad fixture admitted. VAP only, and the Kyverno skip says why."""
    from kube_noob.generate import policies as pol

    kyverno = pol.generate(engines=("kyverno",), rules=["KN-S037"], mode="enforce")
    assert not kyverno.documents
    assert [s["ruleId"] for s in kyverno.skipped] == ["KN-S037"]
    assert "[APIService,*,*]" in kyverno.skipped[0]["reason"] and kyverno.skipped[0]["reason"].startswith("kyverno:")
    vap = pol.generate(engines=("vap",), rules=["KN-S037"], mode="enforce")
    assert vap.documents and not vap.skipped
