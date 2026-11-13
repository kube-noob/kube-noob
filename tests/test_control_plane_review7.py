"""The seventh review of KN-S037..KN-S041 (G272): undetermined is exit 1, and the neighbours of round six.

Every input under tests/fixtures/control-plane/review7/ is a reviewer's reproducer, copied as found (`q<n>-` says
which question it came from). Each test asserts the finding text, its line and the object it names, never just
that something fired.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from kube_noob.audit.engine import analyze, refuse_if_not_manifests
from kube_noob.audit.model import Report, Severity
from kube_noob.errors import ConfigError
from kube_noob.yamlio import load_documents

FX = Path(__file__).parent / "fixtures" / "control-plane" / "review7"
FX6 = Path(__file__).parent / "fixtures" / "control-plane" / "review6"
KAS, ETCD = "KN-S038", "KN-S039"


def _r(name: str, version: str | None = "1.30") -> Report:
    return analyze((FX / name).read_text(encoding="utf-8"), "kubernetes", version)


def _t(text: str, version: str | None = "1.30", **kw: Any) -> Report:
    return analyze(text, "kubernetes", version, **kw)


def _hits(report: Report, rid: str) -> list[Any]:
    return [f for f in report.findings if f.rule_id == rid]


def _declined(report: Report, rid: str) -> str:
    return next((a for a in report.assumptions if a.startswith(f"{rid} was not evaluated")), "")


def _gate(path: Path, **kw: Any) -> dict[str, Any]:
    from kube_noob import gate as g

    return g.run(g.collect([str(path)], lambda p: Path(p).read_text(encoding="utf-8")), **kw)


def _cli(args: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str, str]:
    from kube_noob.cli import main

    code = main(args)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


# --- A: undetermined is exit 1, in every output ---


def test_an_undetermined_audit_exits_1_whatever_fail_on_says(capsys: pytest.CaptureFixture[str]) -> None:
    src = FX6 / "q2-declined.yaml"
    report = analyze(src.read_text(encoding="utf-8"), "kubernetes", "1.30")
    assert report.undetermined() == "1 rule not evaluated in full: KN-S038"
    for flags in ([], ["--fail-on", "never"], ["--fail-on", "critical"], ["--min-severity", "critical"]):
        code, out, _ = _cli(["audit", "-f", str(src), *flags], capsys)
        assert code == 1, flags
        assert "score=not determined (1 rule not evaluated in full)" in out.splitlines()[0]
    code, out, _ = _cli(["audit", "-f", str(src), "--format", "json", "--fail-on", "never"], capsys)
    rep = json.loads(out)
    assert code == 1 and rep["summary"]["score"] is None
    assert rep["summary"]["scoreWithheld"] == "1 rule not evaluated in full: KN-S038"


def test_the_gate_is_incomplete_not_passed_on_an_undetermined_audit(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from kube_noob import gate as g

    src = FX6 / "q2-declined.yaml"
    report = _gate(src, platform="kubernetes", version="1.30", fail_on="never")
    assert report["passed"] is False and report["incomplete"] is True
    assert report["undetermined"] == "1 rule not evaluated in full: KN-S038"
    assert any("undetermined" in f for f in report["failures"])
    md = g.markdown(report)
    assert md.startswith("## kube-noob gate incomplete") and "1 rule not evaluated in full: KN-S038" in md
    sarif = g.sarif_of_gate(report)
    run = sarif["runs"][0]
    assert run["invocations"][0]["properties"]["incomplete"] is True
    notes = [r for r in run["results"] if r.get("ruleId") == "kube-noob/undetermined"]
    assert len(notes) == 1 and "KN-S038" in notes[0]["message"]["text"]
    from kube_noob import report_html

    page = report_html.render(report)
    assert "gate incomplete" in page.lower() and "gate passed" not in page.lower()
    summary = tmp_path / "s.md"
    code, _, _ = _cli(["gate", "-f", str(src), "--fail-on", "never", "--summary", str(summary)], capsys)
    assert code == 1 and summary.read_text(encoding="utf-8").startswith("## kube-noob gate incomplete")


def test_the_mcp_tools_carry_the_undetermined_state() -> None:
    from kube_noob.config import load_settings
    from kube_noob.toolkit import AuditIn, FixIn, Toolkit

    text = (FX6 / "q1-32-podlist-item-kind-int.yaml").read_text(encoding="utf-8")
    kit = Toolkit(load_settings(overrides={"offline": True}))
    out = kit.audit(AuditIn(manifests=text))
    assert out["summary"]["score"] is None
    assert out["notAudited"] == [
        {"object": "<kind not a string>/q", "kind": "pod spec", "why": "in a kind kube-noob has no reader for"}
    ]
    assert out["summary"]["scoreWithheld"].startswith("2 rules not evaluated in full and 1 pod spec not audited")
    fixed = kit.fix(FixIn(manifests=text))
    assert fixed["after"]["score"] is None and fixed["after"]["scoreWithheld"]


def test_not_evaluated_names_the_stage_not_requested_and_the_declined_rules() -> None:
    from kube_noob.audit.model import Stage

    text = (FX6 / "q2-declined.yaml").read_text(encoding="utf-8")
    full = _t(text)
    assert full.not_evaluated[KAS] == "declined on 1 object"
    assert full.as_dict()["notEvaluated"] == {KAS: "declined on 1 object"}
    validate_only = analyze(text, "kubernetes", "1.30", stages={Stage.VALIDATE})
    assert validate_only.not_evaluated["KN-S001"] == "stage not requested"
    assert validate_only.undetermined() is None  # a stage the caller did not ask for is not an unread object


@pytest.mark.parametrize(
    "spec", [{"forbidRules": ["KN-S038"]}, {"schemaValid": True}, {"maxSeverity": "high"}, {"minScore": 80}]
)
def test_every_eval_check_that_reads_findings_is_not_evaluated_on_an_undetermined_report(spec: dict[str, Any]) -> None:
    from kube_noob.evals.checks import evaluate

    ev = evaluate((FX6 / "q2-declined.yaml").read_text(encoding="utf-8"), {**spec, "version": "1.30"})
    checks = [o for o in ev.outcomes if o.name != "parse"]
    assert checks and all(
        not o.passed and o.detail.startswith("not evaluated: ") and "KN-S038" in o.detail for o in checks
    )
    assert ev.passed is False


# --- 1: a List whose only items are empty typed lists ---


@pytest.mark.parametrize("fixture", ["q3-10-nested-empty-podlist.yaml", "q3-11-nested-two-empty.yaml"])
def test_a_list_of_empty_typed_lists_is_nothing_to_audit_not_a_pass(
    fixture: str, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, err = _cli(["audit", "-f", str(FX / fixture)], capsys)
    assert code == 2 and "held no items, so there is nothing to audit" in err and "score=100" not in out
    with pytest.raises(ConfigError, match="held no items"):
        refuse_if_not_manifests(load_documents((FX / fixture).read_text(encoding="utf-8")))


def test_an_empty_wrapper_is_not_a_resource() -> None:
    report = _r("q3-02-empty-podlist-beside-deployment.yaml")
    assert "PodList" not in " ".join(report.resources) and not _hits(report, "KN-V001")
    report = _t("apiVersion: v1\nkind: List\nitems: []\nitems: []\n")
    assert report.resources == [] and [f.line for f in _hits(report, "KN-V018")] == [4]


# --- 2 / 9: `items` twice where one occurrence is not a sequence; `fix` refuses what the API server refuses ---


@pytest.mark.parametrize(
    ("fixture", "dup_line", "what"),
    [
        ("q1-01-second-items-map.yaml", 15, "a mapping"),
        ("q1-02-second-items-string.yaml", 15, "a string"),
        ("q1-03-first-items-map.yaml", 4, "a mapping"),
    ],
)
def test_items_twice_with_a_non_sequence_occurrence_keeps_every_pod_and_names_the_refused_one(
    fixture: str, dup_line: int, what: str
) -> None:
    report = _r(fixture)
    assert report.resources == ["Pod/shop/priv"], report.resources
    s001 = _hits(report, "KN-S001")
    assert [(f.resource, f.line) for f in s001] == [("Pod/shop/priv", 14 if dup_line == 15 else 15)]
    v018 = _hits(report, "KN-V018")
    assert [(f.resource, f.line) for f in v018] == [("List/<wrapper>", dup_line)]
    assert (
        f"occurrence on line {dup_line}" in v018[0].message
        and f"is {what}, not a list, and was not read" in v018[0].message
    )
    assert not _hits(report, "KN-V001"), "metadata.name is not a wrapper field"
    assert "is a list whose items are not a list" not in _declined(report, KAS)


def test_a_wrapper_whose_items_is_a_mapping_gets_no_metadata_name_finding() -> None:
    report = _r("q3-04-list-items-map.yaml")
    assert not _hits(report, "KN-V001")
    line = _declined(report, KAS)
    assert line.startswith("KN-S038 was not evaluated in full, so it is not counted as clean: List/<unnamed> is a list")
    assert "whose items are not a list" in line


@pytest.mark.parametrize("fixture", ["q1-01-second-items-map.yaml", "q1-03-first-items-map.yaml"])
def test_fix_refuses_to_write_a_wrapper_that_merged_or_lost_an_items_occurrence(
    fixture: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "out.yaml"
    code, stdout, err = _cli(["fix", "-f", str(FX / fixture), "-o", str(out)], capsys)
    assert code == 1 and not out.exists() and stdout == ""
    assert (
        "List has the key 'items' twice" in err
        and "the API server refuses this file" in err
        and "fix the duplicate first" in err
    )


def test_fix_refuses_a_document_the_api_server_refuses_for_a_duplicate_key(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from kube_noob.audit.fixer import FixRefused, fix_manifests

    text = (FX6 / "q1-08-dup-items.yaml").read_text(encoding="utf-8")
    with pytest.raises(FixRefused, match="List has the key 'items' twice \\(second occurrence on line 15\\)"):
        fix_manifests(text)
    inner = (
        "apiVersion: v1\nkind: Pod\nmetadata: {name: p, namespace: s}\nmetadata: {name: q, namespace: s}\n"
        "spec: {containers: [{name: c, image: x}]}\n"
    )
    with pytest.raises(FixRefused, match="Pod/s/q has the key 'metadata' twice \\(second occurrence on line 4\\)"):
        fix_manifests(inner)
    out = tmp_path / "out.yaml"
    code, _, err = _cli(["fix", "-f", str(FX6 / "q1-08-dup-items.yaml"), "-o", str(out)], capsys)
    assert code == 1 and not out.exists() and "second occurrence on line 15" in err


def test_fix_format_json_prints_json(capsys: pytest.CaptureFixture[str]) -> None:
    code, _, err = _cli(
        ["fix", "-f", str(FX6 / "q3-01-b4-value-with-eq.yaml"), "--format", "json", "-o", "/dev/null"], capsys
    )
    assert code == 0
    summary = json.loads(err)
    assert set(summary) == {"changes", "manualFollowUps", "after"}


# --- 4 / 5 / 13: one reader and one decision block for the k3s argv and the Rancher config ---

#: One `--kube-apiserver-arg` value, and what KN-S038 says for it in BOTH readers: (value, severities, text).
_K3S_TABLE = [
    ("authorization-mode=AlwaysAllow", [Severity.CRITICAL], "AlwaysAllow"),
    ("--authorization-mode=AlwaysAllow", [Severity.CRITICAL], "AlwaysAllow"),
    ("authorization-mode-=AlwaysAllow", [Severity.CRITICAL], "AlwaysAllow"),
    ("authorization-mode+=AlwaysAllow", [Severity.CRITICAL], "AlwaysAllow"),
    ("anonymous-auth=true", [Severity.MEDIUM], "--anonymous-auth=true"),
    ("anonymous-auth=TRUE", [Severity.MEDIUM], "--anonymous-auth=true"),
    ("anonymous-auth", [Severity.MEDIUM], "--anonymous-auth=true"),
    ("anonymous-auth=false", [], ""),
    ("authorization-mode+=Node", [], ""),
]


def _k3s_pod(values: list[str]) -> str:
    return yaml.safe_dump(
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "k3s", "namespace": "kube-system"},
            "spec": {
                "containers": [
                    {
                        "name": "k3s",
                        "image": "rancher/k3s:v1.31.0-k3s1",
                        "command": ["k3s", "server", *[f"--kube-apiserver-arg={v}" for v in values]],
                    }
                ]
            },
        },
        sort_keys=False,
    )


def _rancher(values: list[str]) -> str:
    return (
        "apiVersion: provisioning.cattle.io/v1\nkind: Cluster\nmetadata: {name: c, namespace: fleet-default}\n"
        "spec:\n  kubernetesVersion: v1.31.0+rke2r1\n  rkeConfig:\n    machineGlobalConfig:\n"
        "      kube-apiserver-arg:\n" + "".join(f"      - {json.dumps(v)}\n" for v in values)
    )


@pytest.mark.parametrize(("value", "severities", "text"), _K3S_TABLE)
def test_the_k3s_argv_and_the_rancher_config_give_one_answer_for_one_argument(
    value: str, severities: list[Severity], text: str
) -> None:
    for label, report in (
        ("argv", _t(_k3s_pod([value]), version="1.31")),
        ("rancher", _t(_rancher([value]), version="1.31")),
    ):
        hits = _hits(report, KAS)
        assert [h.severity for h in hits] == severities, (label, value, [h.message for h in hits])
        assert all(text in h.message for h in hits), (label, value)
        if not severities:
            line = _declined(report, KAS)
            assert line and "own defaults" in line and "no such flag" not in line, (label, value, line)


def test_the_rancher_reader_sorts_the_keys_as_get_args_does() -> None:
    # k3s pkg/util/args.go GetArgs: keys are the cleaned RAW names (`anonymous_auth` and `anonymous-auth` are
    # two keys), slices.Sort(keys), then pflag folds `_` and keeps the last: `--anonymous-auth=false
    # --anonymous_auth=true` is true, whatever the YAML order.
    for fixture in ("q5-27-rancher-anon-underscore-first.yaml", "q5-26-rancher-anon-underscore-last.yaml"):
        hits = _hits(_r(fixture, version="1.31"), KAS)
        assert [(h.severity, h.resource) for h in hits] == [(Severity.MEDIUM, "Cluster/fleet-default/c")], fixture
        assert "--anonymous-auth=true" in hits[0].message
    hits = _hits(_t(_k3s_pod(["anonymous_auth=true", "anonymous-auth=false"]), version="1.31"), KAS)
    assert [h.severity for h in hits] == [Severity.MEDIUM]
    assert not _hits(_t(_k3s_pod(["anonymous-auth=true", "anonymous-auth=false"]), version="1.31"), KAS)


@pytest.mark.parametrize(
    ("fixture", "flag"),
    [("q5-09-anon-true.yaml", "true"), ("q5-06-bare-anon.yaml", "true"), ("q5-08-anon-TRUE.yaml", "TRUE")],
)
def test_the_k3s_argv_reports_an_explicit_anonymous_auth(fixture: str, flag: str) -> None:
    hits = _hits(_r(fixture, version="1.31"), KAS)
    assert [(h.severity, h.resource, h.line) for h in hits] == [(Severity.MEDIUM, "Pod/kube-system/k3s", 13)], fixture
    assert "--anonymous-auth=true" in hits[0].message and "k3s server" in hits[0].message


def test_a_padded_rancher_argument_is_a_flag_pflag_refuses() -> None:
    report = _r("q5-24-rancher-padded.yaml", version="1.31")
    assert not _hits(report, KAS)
    line = _declined(report, KAS)
    assert "'authorization-mode' with whitespace in its name" in line and "no such flag" in line
    assert "does not start" in line


@pytest.mark.parametrize("fixture", ["q5-03-comma.yaml", "q5-20-rancher-comma.yaml"])
def test_a_comma_value_is_one_argument_whose_second_mode_the_api_server_refuses(fixture: str) -> None:
    report = _r(fixture, version="1.31")
    assert not _hits(report, KAS)
    line = _declined(report, KAS)
    assert "'anonymous-auth=true'" in line and "does not accept" in line and "refuses to start" in line


# --- 6: kubeadm 1.36 keeps the override order ---


def test_kubeadm_1_36_keeps_the_written_order_where_1_35_sorts() -> None:
    # cmd/kubeadm/app/util/arguments.go on master (fetched 2026-11-13): ArgumentsToCommand sorts the BASE only and
    # appends the overrides that carry no mergeMethod in their written order; at v1.31.0..v1.35.0 every pair is
    # sorted by (name, value).
    text = (FX6 / "q3-10b-b4-underscore-false-dash-true.yaml").read_text(encoding="utf-8")
    assert not _hits(_t(text, version="1.35"), KAS)  # --anonymous-auth=true --anonymous_auth=false: false
    mirror = (FX6 / "q3-10-b4-name-underscore-and-dash.yaml").read_text(encoding="utf-8")
    assert [h.severity for h in _hits(_t(mirror, version="1.35"), KAS)] == [Severity.MEDIUM]
    assert [h.severity for h in _hits(_t(text, version="1.36"), KAS)] == [Severity.MEDIUM]  # written order: true last
    assert not _hits(_t(mirror, version="1.36"), KAS)
    merged = text.replace(
        '  - name: anonymous-auth\n    value: "true"\n',
        '  - name: anonymous-auth\n    value: "true"\n    mergeMethod: append\n',
    )
    report = _t(merged, version="1.36")
    assert not _hits(report, KAS)
    assert "mergeMethod" in _declined(report, KAS) and "kubeadm's own default" in _declined(report, KAS)
    report = _t(merged, version="1.35")
    assert not _hits(report, KAS) and "mergeMethod" in _declined(report, KAS) and "refuses" in _declined(report, KAS)


# --- 7: `items: null` is an empty list ---


@pytest.mark.parametrize("fixture", ["q3-03-list-items-null.yaml", "q3-05-list-items-bare.yaml"])
def test_a_null_items_is_an_empty_list(fixture: str, capsys: pytest.CaptureFixture[str]) -> None:
    code, out, err = _cli(["audit", "-f", str(FX / fixture)], capsys)
    assert code == 2 and "held no items, so there is nothing to audit" in err and "KN-V001" not in out


# --- 10: a nested wrapper's record names the wrapper that has the duplicate ---


def test_a_nested_wrapper_record_names_the_wrapper_that_holds_the_duplicate() -> None:
    report = _r("q1-05-nested-inner-dup-items-outer-dup-kind.yaml")
    assert sorted(report.resources) == ["Pod/shop/priv", "Pod/shop/second"]
    v018 = sorted(((f.resource, f.line, f.message) for f in _hits(report, "KN-V018")), key=lambda x: x[1])
    assert [(r, line) for r, line, _ in v018] == [("List/<wrapper>", 3), ("PodList/<wrapper>", 19)]
    assert v018[0][2].startswith(
        "Duplicate key 'kind' in the List that holds this PodList (second occurrence on line 3)"
    )
    assert v018[1][2].startswith(
        "Duplicate key 'items' in the PodList that holds this object (second occurrence on line 19)"
    )


# --- 11: the HTML report splits what was assumed from what was not evaluated ---


def test_the_html_report_does_not_label_a_declined_rule_as_assumed() -> None:
    from kube_noob import report_html

    report = _gate(FX6 / "q1-32-podlist-item-kind-int.yaml", platform="kubernetes", version="1.30", fail_on="never")
    page = report_html.render(report)
    assert "Assumed." not in page.split("KN-S038 was not evaluated in full")[0][-200:]
    assert "Not evaluated in full" in page
    assumed = analyze(
        (FX6 / "q1-32-podlist-item-kind-int.yaml").read_text(encoding="utf-8"), "kubernetes", None
    ).as_dict()
    page = report_html.render(assumed)
    assert page.count("Assumed") == 1 and "No Kubernetes version given" in page


# --- 12: kubeadm v1beta4 entries kubeadm cannot decode ---


def test_a_non_string_name_a_missing_value_and_a_duplicate_value_key_decline() -> None:
    report = _r("q4-10-b4-name-int.yaml")
    assert [h.severity for h in _hits(report, KAS)] == [Severity.CRITICAL]  # the AlwaysAllow entry still decides
    line = _declined(report, KAS)
    assert "extraArgs[0].name is '7', not a string, which kubeadm's decoder refuses" in line
    report = _r("q4-09-b4-value-missing.yaml")
    assert not _hits(report, KAS), "pflag refuses the empty boolean before any authorizer runs"
    assert "--anonymous-auth=''" in _declined(report, KAS) and "not a boolean" in _declined(report, KAS)
    report = _r("q4-14-b4-dup-name-key-in-entry.yaml")
    assert not _hits(report, KAS)
    assert "extraArgs[0] has the key 'value' twice" in _declined(report, KAS) and "refuses" in _declined(report, KAS)
    assert [(f.line, f.resource) for f in _hits(report, "KN-V018")] == [(7, "ClusterConfiguration/<unnamed>")]


# --- 14: Rancher selectors and Cluster API lists ---


@pytest.mark.parametrize("fixture", ["q7-05-selector-cp-role.yaml", "q7-02-selector-matchexpressions.yaml"])
def test_a_selector_naming_the_control_plane_role_is_read(fixture: str) -> None:
    hits = _hits(_r(fixture, version="1.31"), KAS)
    assert [(h.severity, h.resource) for h in hits] == [(Severity.CRITICAL, "Cluster/fleet-default/c")]


def test_a_selector_is_printed_as_yaml_not_a_python_repr_and_a_scalar_entry_is_named() -> None:
    line = _declined(_r("q7-08-selector-unknown-key.yaml", version="1.31"), KAS)
    assert "{'" not in line and "machineLabelSelector '{" in line
    report = _r("q7-09-selector-entry-scalar.yaml", version="1.31")
    assert [h.severity for h in _hits(report, KAS)] == [Severity.CRITICAL]
    assert "machineSelectorConfig[0] is not a mapping (7)" in _declined(report, KAS)


def test_an_empty_files_list_is_nothing_to_read() -> None:
    line = _declined(_r("q7-24-kcp-files-empty-list.yaml"), KAS)
    assert "files" not in line and "preKubeadmCommands" not in line


# --- 15: no Python reprs in the tool's own words ---


@pytest.mark.parametrize(
    ("fixture", "ref"),
    [
        ("q2-10-item-kind-Pod.yaml", "<kind not a string>/shop/q"),
        ("q2-10-item-kind-empty.yaml", "<kind not a string>/shop/q"),
        ("q2-20-standalone-kind-null.yaml", "<no kind>/shop/q"),
    ],
)
def test_a_non_string_or_null_kind_is_named_with_a_fixed_phrase(fixture: str, ref: str) -> None:
    report = _r(fixture)
    assert report.resources == [ref]
    assert report.not_audited == [{"object": ref, "kind": "pod spec", "why": "in a kind kube-noob has no reader for"}]
    text = "\n".join([*report.assumptions, report.undetermined() or "", *(f.message for f in report.findings)])
    assert "['Pod']" not in text and "None/" not in text and "{}/" not in text


def test_a_null_item_is_named_as_null() -> None:
    report = _r("q3-07-list-items-one-null.yaml")
    assert [(f.resource, f.line, f.message) for f in _hits(report, "KN-V001")] == [
        ("doc[0]", 4, "Document is not a mapping; it cannot be a Kubernetes object.")
    ]
    assert "document 1 (line 4) is not a mapping (null)" in _declined(report, KAS)


# --- 16: $(VAR) expansion as the kubelet does it ---


def test_an_escaped_dollar_is_a_literal_and_a_literal_env_value_is_expanded() -> None:
    # third_party/forked/golang/expansion/expand.go at v1.31.0: `$$` is one `$`; `$(NAME)` maps through the
    # container's env; an unmapped name stays as written.
    report = _r("q6-33-authz-escaped-dollar.yaml")
    assert not _hits(report, KAS)
    line = _declined(report, KAS)
    assert "'$(MODE)'" in line and "does not accept" in line and "$(VAR) expansion" not in line
    hits = _hits(_r("q6-30-anon-env-expansion.yaml"), KAS)
    assert [(h.severity, h.line) for h in hits] == [(Severity.MEDIUM, 18)] and "--anonymous-auth=true" in hits[
        0
    ].message
    hits = _hits(_r("q6-31-authz-env-expansion.yaml"), KAS)
    assert [(h.severity, h.line) for h in hits] == [(Severity.CRITICAL, 16)] and "AlwaysAllow" in hits[0].message
    line = _declined(_r("q6-32-authz-env-undefined.yaml"), KAS)
    assert "env MODE has no literal value in this container" in line


def test_a_value_from_or_env_from_is_not_expanded() -> None:
    text = (FX / "q6-30-anon-env-expansion.yaml").read_text(encoding="utf-8")
    from_ref = text.replace('      value: "true"', "      valueFrom: {configMapKeyRef: {name: c, key: k}}")
    line = _declined(_t(from_ref), KAS)
    assert not _hits(_t(from_ref), KAS) and "env ANON has no literal value in this container" in line
    chained = text.replace('      value: "true"', '      value: "$(OTHER)"')
    assert "env ANON has no literal value in this container" in _declined(_t(chained), KAS)


# --- 17: a typed-list item of another kind inherits nothing ---


def test_an_item_of_another_kind_in_a_typed_list_inherits_no_api_version() -> None:
    report = _r("q2-13-podlist-item-deployment-no-apiversion.yaml")
    assert not _hits(report, "KN-V002")
    v001 = _hits(report, "KN-V001")
    assert [(f.line, f.message) for f in v001] == [(4, "Missing required field(s): apiVersion.")]
    assert report.resources == ["Deployment/shop/q"]


# --- 19: the operators inventory reads a wrapper's duplicate key ---


def test_the_operators_inventory_names_a_wrappers_duplicate_key(capsys: pytest.CaptureFixture[str]) -> None:
    _, out, _ = _cli(["operators", "inventory", "-f", str(FX / "opdir3"), "--format", "json"], capsys)
    rep = json.loads(out)
    assert rep["verdict"] == "partial" and rep["complete"] is False
    assert any("subscriptions.yaml" in c and "'items' twice" in c and "line 4" in c for c in rep["caveats"]), rep[
        "caveats"
    ]


# --- the sixth round's tests, sharpened (reviewer item 9) ---


def test_a_sequence_item_names_each_pod_by_document_and_line() -> None:
    report = analyze((FX6 / "q1-20-list-item-list-of-pods.yaml").read_text(encoding="utf-8"), "kubernetes", "1.30")
    line = next(a for a in report.assumptions if "NOT audited" in a)
    assert line.startswith(
        "2 pod spec(s) are in kinds kube-noob has no reader for, so their containers were NOT audited: "
        "document 1 (line 4) at spec path 0.spec, document 1 (line 4) at spec path 1.spec."
    )
    assert (
        report.not_audited
        == [{"object": "document 1 (line 4)", "kind": "pod spec", "why": "in a kind kube-noob has no reader for"}] * 2
    )


def test_a_wrapper_whose_last_kind_is_not_a_list_names_the_privileged_pod() -> None:
    text = (
        (FX6 / "q1-08c-dup-kind-wrapper.yaml")
        .read_text(encoding="utf-8")
        .replace("kind: ConfigMap\nkind: List\n", "kind: List\nkind: ConfigMap\n")
    )
    report = _t(text)
    assert report.not_audited == [
        {"object": "ConfigMap/<unnamed>", "kind": "pod spec", "why": "in a kind kube-noob has no reader for"}
    ]
    assert "ConfigMap/<unnamed> at spec path items.0.spec" in next(a for a in report.assumptions if "NOT audited" in a)
    assert [(f.resource, f.line) for f in _hits(report, "KN-V018")] == [("ConfigMap/<unnamed>", 3)]
