"""The sixth review of KN-S037..KN-S041 (G272): a number beside an unread object, and the neighbours of round five.

Every input under tests/fixtures/control-plane/review6/ is a reviewer's reproducer, copied as found. Each test
names the finding it holds (F1..F16 in that review) and the behaviour, never the function.
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

FX = Path(__file__).parent / "fixtures" / "control-plane" / "review6"
KAS, ETCD = "KN-S038", "KN-S039"


def _r(name: str, version: str | None = "1.30") -> Report:
    return analyze((FX / name).read_text(encoding="utf-8"), "kubernetes", version)


def _t(text: str, version: str | None = "1.30", **kw: Any) -> Report:
    return analyze(text, "kubernetes", version, **kw)


def _hits(report: Report, rid: str) -> list[Any]:
    return [f for f in report.findings if f.rule_id == rid]


def _declined(report: Report, rid: str) -> str:
    return next((a for a in report.assumptions if a.startswith(f"{rid} was not evaluated")), "")


def _cli(args: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str, str]:
    from kube_noob.cli import main

    code = main(args)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


# --- F1 / F2: the score is withheld whenever anything was not audited; a non-string kind is a finding ---


@pytest.mark.parametrize(
    "fixture",
    ["q1-32-podlist-item-kind-int.yaml", "q1-31-top-kind-mapping.yaml", "q1-28-list-item-kind-nonstring.yaml"],
)
def test_an_object_whose_kind_is_not_a_string_is_a_high_finding_and_never_scores_100(
    fixture: str, capsys: pytest.CaptureFixture[str]
) -> None:
    report = _r(fixture)
    v001 = _hits(report, "KN-V001")
    assert v001 and all("kind" in f.message and "not a string" in f.message for f in v001), report.findings
    assert report.score_withheld() is not None and report.as_dict()["summary"]["score"] is None
    code, out, _ = _cli(["audit", "-f", str(FX / fixture)], capsys)
    assert code == 1 and "score=not determined" in out.splitlines()[0]


def test_a_non_string_api_version_is_a_finding_too() -> None:
    text = "apiVersion: [v1]\nkind: Pod\nmetadata: {name: p}\nspec: {containers: [{name: c, image: x}]}\n"
    v001 = _hits(_t(text), "KN-V001")
    assert v001 and "apiVersion" in v001[0].message and "not a string" in v001[0].message


@pytest.mark.parametrize(
    "fixture",
    [
        "q1-06-items-under-spec.yaml",
        "q1-17-kind-list-lowercase.yaml",
        "q1-26-kind-nonstring.yaml",
        "q1-32-podlist-item-kind-int.yaml",
    ],
)
def test_the_score_is_withheld_and_the_control_plane_rules_decline_where_a_pod_spec_was_not_read(
    fixture: str, capsys: pytest.CaptureFixture[str]
) -> None:
    report = _r(fixture)
    out = report.as_dict()
    assert any("NOT audited" in a for a in report.assumptions)
    assert out["summary"]["score"] is None and "not audited" in out["summary"]["scoreWithheld"]
    for rid in (KAS, ETCD):
        line = _declined(report, rid)
        assert "no reader" in line, (rid, report.assumptions)
    code, text, _ = _cli(["audit", "-f", str(FX / fixture)], capsys)
    assert code == 1 and "score=not determined" in text.splitlines()[0]


def test_an_operator_supplied_image_and_a_refused_group_withhold_the_score_too() -> None:
    kserve = """apiVersion: serving.kserve.io/v1beta1
kind: InferenceService
metadata: {name: m, namespace: ml}
spec:
  predictor:
    model:
      modelFormat: {name: sklearn}
      storageUri: gs://b/m
"""
    out = _t(kserve).as_dict()
    assert any("take their image from an operator" in a for a in out["assumptions"])
    assert out["summary"]["score"] is None and "not read" in out["summary"]["scoreWithheld"]
    foreign = "apiVersion: other.io/v1\nkind: RayCluster\nmetadata: {name: r, namespace: ml}\nspec: {}\n"
    out = _t(foreign).as_dict()
    assert any("not where kube-noob knows" in a for a in out["assumptions"])
    assert out["summary"]["score"] is None


def test_the_withheld_reason_names_rules_and_unread_objects_together() -> None:
    text = (
        (FX / "q2-declined.yaml").read_text(encoding="utf-8")
        + "---\n"
        + (FX / "q1-32-podlist-item-kind-int.yaml").read_text(encoding="utf-8")
    )
    withheld = _t(text).score_withheld()
    assert withheld is not None
    head = withheld.partition(":")[0]
    assert "rule" in head and "not audited" in head and KAS in withheld


@pytest.mark.parametrize("fixture", ["q1-44-podlist-item-kind-null.yaml", "q1-45-podlist-item-kind-empty.yaml"])
def test_a_null_or_empty_kind_on_a_typed_list_item_takes_the_lists_kind(fixture: str) -> None:
    report = _r(fixture)
    assert report.resources == ["Pod/shop/q"]
    assert _hits(report, "KN-S001") and not _hits(report, "KN-V001")


def test_fix_and_the_gate_carry_the_withheld_score(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from kube_noob.config import load_settings
    from kube_noob.toolkit import FixIn, Toolkit

    src = FX / "q1-32-podlist-item-kind-int.yaml"
    kit = Toolkit(load_settings(overrides={"offline": True}))
    after = kit.fix(FixIn(manifests=src.read_text(encoding="utf-8")))["after"]
    assert after["score"] is None and "not audited" in after["scoreWithheld"]
    summary = tmp_path / "s.md"
    code, _, _ = _cli(["gate", "-f", str(src), "--summary", str(summary)], capsys)
    assert code == 1
    assert "Not evaluated in full" in summary.read_text(encoding="utf-8")


# --- F3: the wrapper's own duplicate keys ---


@pytest.mark.parametrize(
    ("fixture", "second_line"),
    [("q1-08-dup-items.yaml", 15), ("q1-08b-dup-items-rev.yaml", 4)],
)
def test_a_list_wrapper_with_items_twice_audits_every_item_and_reports_the_duplicate(
    fixture: str, second_line: int, capsys: pytest.CaptureFixture[str]
) -> None:
    report = _r(fixture)
    v018 = _hits(report, "KN-V018")
    assert [f.line for f in v018] == [second_line] and "items" in v018[0].message, report.findings
    assert _hits(report, "KN-S001"), "the privileged Pod under the first `items` must still be audited"
    code, _, err = _cli(["audit", "-f", str(FX / fixture)], capsys)
    assert code == 1 and "no document has both apiVersion and kind" not in err


def test_a_duplicate_kind_or_api_version_on_the_wrapper_is_reported_with_the_wrappers_line() -> None:
    report = _r("q1-08c-dup-kind-wrapper.yaml")
    v018 = _hits(report, "KN-V018")
    assert [f.line for f in v018] == [3] and "kind" in v018[0].message
    assert _hits(report, "KN-S001")
    text = (FX / "q1-08c-dup-kind-wrapper.yaml").read_text(encoding="utf-8")
    both = text.replace("apiVersion: v1\n", "apiVersion: v1\napiVersion: v1\n", 1)
    report = _t(both)
    assert sorted(f.line for f in _hits(report, "KN-V018")) == [2, 4]


def test_three_items_keys_and_a_typed_wrapper_keep_every_pod() -> None:
    pod = load_documents((FX / "q1-08-dup-items.yaml").read_text(encoding="utf-8"))[0].data
    one = yaml.safe_dump([pod], sort_keys=False)
    two = yaml.safe_dump([dict(pod, metadata={"name": "second", "namespace": "shop"})], sort_keys=False)
    text = "apiVersion: v1\nkind: PodList\nitems:\n" + one + "items: []\nitems:\n" + two
    report = _t(text)
    assert sorted(report.resources) == ["Pod/shop/priv", "Pod/shop/second"]
    assert len(_hits(report, "KN-S001")) == 2
    assert sorted(f.line for f in _hits(report, "KN-V018")) == [15, 16]
    docs = load_documents(text)
    assert [d.line_for(("metadata", "name")) for d in docs] == [7, 20]


def test_a_nested_wrapper_with_items_twice_keeps_every_pod_too() -> None:
    inner = (FX / "q1-08-dup-items.yaml").read_text(encoding="utf-8").replace("kind: List", "kind: PodList")
    text = "apiVersion: v1\nkind: List\nitems:\n- " + inner.replace("\n", "\n  ").rstrip() + "\n"
    report = _t(text)
    assert report.resources == ["Pod/shop/priv"] and _hits(report, "KN-S001")
    v018 = _hits(report, "KN-V018")
    assert [f.line for f in v018] == [18] and "PodList" in v018[0].message
    docs = load_documents(text)
    assert docs[0].line_for(("spec", "containers", 0, "securityContext", "privileged")) == 17


def test_a_duplicate_inside_the_second_items_keeps_its_own_line() -> None:
    pod = load_documents((FX / "q1-08-dup-items.yaml").read_text(encoding="utf-8"))[0].data
    first = yaml.safe_dump([pod], sort_keys=False)
    second = yaml.safe_dump([dict(pod, metadata={"name": "second", "namespace": "shop"})], sort_keys=False)
    second = second.replace("    name: second\n", "    name: second\n    name: second\n")  # a duplicate in item 2
    text = "apiVersion: v1\nkind: List\nitems:\n" + first + "items:\n" + second
    report = _t(text)
    dups = sorted((f.resource, f.line) for f in _hits(report, "KN-V018"))
    assert dups == [("List/<wrapper>", 15), ("Pod/shop/second", 20)], dups


def test_an_empty_list_wrapper_with_a_duplicate_key_still_reports_it(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    text = "apiVersion: v1\nkind: List\nitems: []\nitems: []\n"
    report = _t(text)
    assert [f.line for f in _hits(report, "KN-V018")] == [4] and not _hits(report, "KN-V001")
    path = tmp_path / "dup.yaml"
    path.write_text(text, encoding="utf-8")
    code, _, err = _cli(["audit", "-f", str(path)], capsys)
    assert code == 1, err


def test_a_wrapper_whose_last_kind_is_not_a_list_names_the_pods_it_hides() -> None:
    text = (
        (FX / "q1-08c-dup-kind-wrapper.yaml")
        .read_text(encoding="utf-8")
        .replace("kind: ConfigMap\nkind: List\n", "kind: List\nkind: ConfigMap\n")
    )
    report = _t(text)
    assert _hits(report, "KN-V018") and any("NOT audited" in a for a in report.assumptions)
    assert report.as_dict()["summary"]["score"] is None


# --- F4: a sequence inside `items` ---


@pytest.mark.parametrize(
    ("fixture", "unread"),
    [("q1-20-list-item-list-of-pods.yaml", 2), ("q1-01-list-nested-list-item.yaml", 1)],
)
def test_a_sequence_item_names_the_pods_inside_it_as_unread_and_exits_1(
    fixture: str, unread: int, capsys: pytest.CaptureFixture[str]
) -> None:
    report = _r(fixture)
    line = next(a for a in report.assumptions if "NOT audited" in a)
    assert line.startswith(f"{unread} pod spec(s)") and "document" in line and "spec path" in line
    assert _declined(report, KAS) and _declined(report, ETCD)
    assert report.as_dict()["summary"]["score"] is None
    code, _, err = _cli(["audit", "-f", str(FX / fixture)], capsys)
    assert code == 1 and "no document has both apiVersion and kind" not in err


# --- F5: an empty list is nothing to audit, in either spelling ---


def test_an_empty_list_and_an_empty_typed_list_refuse_alike_with_a_true_message(
    capsys: pytest.CaptureFixture[str],
) -> None:
    results = {}
    for fixture in ("q1-11-list-empty.yaml", "q1-12-podlist-empty.yaml"):
        code, out, err = _cli(["audit", "-f", str(FX / fixture)], capsys)
        results[fixture] = (code, err.replace("PodList", "List"))
        assert code == 2 and "KN-V001" not in out and "no document has both" not in err, (fixture, err)
        assert "held no items" in err
    assert len(set(results.values())) == 1


def test_an_empty_typed_list_beside_a_pod_gets_no_finding_of_its_own() -> None:
    text = (
        (FX / "q1-12-podlist-empty.yaml").read_text(encoding="utf-8")
        + "---\n"
        + (FX / "q1-08-dup-items.yaml")
        .read_text(encoding="utf-8")
        .split("items: []")[0]
        .replace("kind: List\nitems:\n- ", "kind: Pod\n")
        .replace("\n  ", "\n")
    )
    report = _t(text)
    assert not _hits(report, "KN-V001") and not _hits(report, "KN-V007"), report.findings
    assert _hits(report, "KN-S001")


# --- F6: the eval grader reads the withheld state ---


def test_the_eval_grader_fails_min_score_on_a_withheld_score() -> None:
    from kube_noob.evals.checks import evaluate

    text = (FX / "q2-declined.yaml").read_text(encoding="utf-8")
    ev = evaluate(text, {"minScore": 80, "platform": "kubernetes", "version": "1.30"})
    outcome = next(o for o in ev.outcomes if o.name.startswith("posture score"))
    assert outcome.passed is False and "not evaluated in full" in outcome.detail and ev.passed is False


# --- F7: kubeadm sorts the raw name; pflag folds `_` after ---


def test_kubeadm_v1beta4_sorts_the_raw_name_before_pflag_folds_underscores() -> None:
    # cmd/kubeadm/app/util/arguments.go ArgumentsToCommand, identical at v1.31.0..v1.35.0: sort.Slice on the raw
    # Name then Value, so `anonymous-auth` < `anonymous_auth`; kube-apiserver's WordSepNormalizeFunc then makes
    # them one flag and the LAST value wins.
    assert not _hits(
        _r("q3-10b-b4-underscore-false-dash-true.yaml"), KAS
    )  # --anonymous-auth=true --anonymous_auth=false
    assert [h.severity for h in _hits(_r("q3-10-b4-name-underscore-and-dash.yaml"), KAS)] == [Severity.MEDIUM]


def test_kubeadm_v1beta3_map_keys_are_sorted_the_same_way() -> None:
    # The v1beta3 map is converted to the same Arg list before ArgumentsToCommand sorts it.
    assert [h.severity for h in _hits(_r("q3-11-b3-dup-underscore-dash.yaml"), KAS)] == [Severity.MEDIUM]


def test_the_v1beta4_order_is_pinned_for_1_35() -> None:
    text = (FX / "q3-10b-b4-underscore-false-dash-true.yaml").read_text(encoding="utf-8")
    assert not _hits(_t(text, version="1.35"), KAS)


# --- F8: a kubeadm apiVersion kube-noob does not read ---


@pytest.mark.parametrize("fixture", ["q3-16-unknown-apiversion-list.yaml", "q3-17-unknown-apiversion-map.yaml"])
def test_an_unknown_kubeadm_api_version_declines_rather_than_reading_by_shape(fixture: str) -> None:
    report = _r(fixture)
    assert not _hits(report, KAS)
    line = _declined(report, KAS)
    assert "is not one kube-noob reads" in line and ("v1beta5" in line or "v1alpha3" in line)


# --- F9: a kubeadm configuration file is not an API object ---


def test_a_kubeadm_cluster_configuration_gets_no_metadata_name_finding() -> None:
    report = _r("q3-01-b4-value-with-eq.yaml")
    assert not _hits(report, "KN-V001"), report.findings
    assert not _hits(report, KAS)
    for kind in ("InitConfiguration", "JoinConfiguration"):
        assert not _hits(_t(f"apiVersion: kubeadm.k8s.io/v1beta4\nkind: {kind}\n"), "KN-V001")
    # The same kind in another group is somebody else's object and still needs a name.
    assert _hits(_t("apiVersion: other.io/v1\nkind: ClusterConfiguration\n"), "KN-V001")


# --- F10: a bare YAML boolean kubeadm's decoder refuses ---


@pytest.mark.parametrize("fixture", ["q3-08-b4-value-bool-bare.yaml", "q3-09-b3-value-bool-bare.yaml"])
def test_a_bare_boolean_value_in_a_kubeadm_configuration_declines(fixture: str) -> None:
    report = _r(fixture)
    assert not _hits(report, KAS)
    line = _declined(report, KAS)
    assert "not a string" in line and "refuses" in line


# --- F11 / F12: k3s's `--` prefix and `-=` suffix ---


def test_the_k3s_argv_reads_a_double_dash_inside_the_value_and_the_prepend_suffix() -> None:
    assert [h.severity for h in _hits(_r("q4-01-k3s-arg-doubledash-inside.yaml"), KAS)] == [Severity.CRITICAL]
    assert [h.severity for h in _hits(_r("q4-02-k3s-arg-minus-suffix-prepend.yaml"), KAS)] == [Severity.CRITICAL]
    text = (
        (FX / "q4-02-k3s-arg-minus-suffix-prepend.yaml")
        .read_text(encoding="utf-8")
        .replace("authorization-mode-=AlwaysAllow", "authorization-mode+=Node")
    )
    assert not _hits(_t(text), KAS)


def test_the_rancher_config_reads_the_same_k3s_syntax() -> None:
    assert [h.severity for h in _hits(_r("q4r-03-global-list-doubledash.yaml"), KAS)] == [Severity.CRITICAL]
    assert [h.severity for h in _hits(_r("q4r-04-global-list-minus-suffix.yaml"), KAS)] == [Severity.CRITICAL]
    text = (
        (FX / "q4r-04-global-list-minus-suffix.yaml")
        .read_text(encoding="utf-8")
        .replace("authorization-mode-=AlwaysAllow", "authorization-mode+=Node")
    )
    assert not _hits(_t(text), KAS)


def test_a_bare_k3s_key_is_the_flag_set_true() -> None:
    # k3s pkg/util/args.go GetArgs: no `=` means value "true".
    text = (
        (FX / "q4r-04-global-list-minus-suffix.yaml")
        .read_text(encoding="utf-8")
        .replace("authorization-mode-=AlwaysAllow", "anonymous-auth")
    )
    assert [h.severity for h in _hits(_t(text), KAS)] == [Severity.MEDIUM]


# --- F13: pflag trims an IP value ---


def test_a_leading_space_in_an_insecure_address_is_trimmed_as_pflag_does() -> None:
    report = _r("q4-16-insecure-addr-space-1.19.yaml", version="1.19")
    hits = [h for h in _hits(report, KAS) if h.severity == Severity.CRITICAL]
    assert len(hits) == 1 and "insecure port" in hits[0].message and "'0.0.0.0'" in hits[0].message
    assert "pflag refuses" not in _declined(report, KAS)


# --- F14: a flag kube-apiserver does not define ---


@pytest.mark.parametrize("fixture", ["q4-39-flag-trailing-dash-name.yaml", "q4-41-flag-name-digits-only.yaml"])
def test_a_flag_name_no_server_defines_declines_the_container_rather_than_reporting_defaults(fixture: str) -> None:
    report = _r(fixture)
    assert not _hits(report, KAS)
    line = _declined(report, KAS)
    assert "no such flag" in line and "not start" in line


# --- F15: Cluster API scripts and files that may rewrite the manifest ---


def test_cluster_api_files_and_kubeadm_commands_are_named_as_unread() -> None:
    line = _declined(_r("q3-31-kubeadmconfig-files.yaml"), KAS)
    assert "files" in line and "not read" in line
    line = _declined(_r("q3-30-kcp-prekubeadm-sed.yaml"), KAS)
    assert "postKubeadmCommands" in line and "may rewrite" in line


# --- F16: a Rancher selector given as a mapping, and an empty selector ---


def test_a_rancher_selector_config_given_as_a_mapping_is_read_as_one_selector() -> None:
    assert [h.severity for h in _hits(_r("q4r-12-selector-list-not-list.yaml"), KAS)] == [Severity.CRITICAL]


def test_an_empty_match_labels_selector_selects_every_machine_like_an_empty_selector() -> None:
    assert [h.severity for h in _hits(_r("q4r-06-selector-matchlabels-empty.yaml"), KAS)] == [Severity.CRITICAL]
    assert [h.severity for h in _hits(_r("q4r-05-selector-empty-map.yaml"), KAS)] == [Severity.CRITICAL]


# --- what round six verified clean stays so ---


def test_a_sequence_item_alone_is_not_refused_as_no_manifest() -> None:
    docs = load_documents((FX / "q1-20-list-item-list-of-pods.yaml").read_text(encoding="utf-8"))
    refuse_if_not_manifests(docs)  # the wrapper had apiVersion and kind; what it held is the audit's to report


def test_a_values_file_is_still_refused() -> None:
    with pytest.raises(ConfigError):
        refuse_if_not_manifests("replicaCount: 1\nimage: {repository: x}\n")


def test_declines_are_not_hidden_by_the_filter_flags(capsys: pytest.CaptureFixture[str]) -> None:
    for flags in (["--fail-on", "never"], ["--min-severity", "critical"], ["--compact"]):
        _, out, _ = _cli(
            ["audit", "-f", str(FX / "q1-32-podlist-item-kind-int.yaml"), "--format", "json", *flags], capsys
        )
        rep = json.loads(out)
        if flags == ["--compact"]:
            from kube_noob.audit.compact import expand_report

            rep = expand_report(rep)
        assert rep["summary"]["score"] is None and rep["summary"]["scoreWithheld"], flags
