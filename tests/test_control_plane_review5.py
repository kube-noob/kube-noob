"""The fifth review of KN-S037..KN-S041 (G272): list opening is a shared path, and it regressed every rule.

`yamlio._flatten_lists` left a whole list unopened when any item was not a mapping, so a privileged Pod beside a
trailing null item went unaudited and exit 0 where main gave exit 1; and it rescanned the line map once per item.
Every list whose `items` is a list is now opened, a non-mapping item is its own document (KN-V001 reports it), the
document cap applies after opening for every command alike, and the line map is split in one pass.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from kube_noob.audit.engine import analyze
from kube_noob.audit.model import Report, Severity
from kube_noob.yamlio import MAX_DOCUMENTS, load_documents

KAS, ETCD = "KN-S038", "KN-S039"
PRIV = {
    "apiVersion": "v1",
    "kind": "Pod",
    "metadata": {"name": "priv", "namespace": "shop"},
    "spec": {"containers": [{"name": "c", "image": "nginx:1.27", "securityContext": {"privileged": True}}]},
}
KAS_POD = {
    "apiVersion": "v1",
    "kind": "Pod",
    "metadata": {"name": "kube-apiserver", "namespace": "kube-system"},
    "spec": {
        "containers": [
            {
                "name": "kube-apiserver",
                "image": "registry.k8s.io/kube-apiserver:v1.30.0",
                "command": ["kube-apiserver", "--etcd-servers=https://e:2379", "--authorization-mode=AlwaysAllow"],
            }
        ]
    },
}


def _r(text: str, platform: str = "kubernetes", version: str | None = None) -> Report:
    return analyze(text, platform, version)


def _hits(report: Report, rid: str) -> list[Any]:
    return [f for f in report.findings if f.rule_id == rid]


def _statuses(report: Report) -> dict[str, str]:
    """Every rule's status: finding, clean, declined or quiet -- the whole answer, not two rules of it."""
    from kube_noob.audit.rules import RULES

    out = {}
    fired = {f.rule_id for f in report.findings}
    for rid in RULES:
        if rid in fired:
            out[rid] = "finding"
        elif rid in report.evaluated_rules:
            out[rid] = "clean"
        elif any(a.startswith(f"{rid} was not evaluated") for a in report.assumptions):
            out[rid] = "declined"
        else:
            out[rid] = "quiet"
    return out


def _list(kind: str, items: list[Any], api_version: str = "v1") -> str:
    return yaml.safe_dump({"apiVersion": api_version, "kind": kind, "items": items}, sort_keys=False)


# --- 1. every list whose items is a list is opened; a non-mapping item is its own document ---


@pytest.mark.parametrize(
    ("label", "text"),
    [
        ("L04 List with a string item", _list("List", [PRIV, "not an object"])),
        ("null item", _list("List", [PRIV, None])),
        ("L05 PodList with a number item", _list("PodList", [KAS_POD, 42])),
        (
            "L06 PodList inside a List",
            _list("List", [{"apiVersion": "v1", "kind": "PodList", "items": [PRIV, KAS_POD]}]),
        ),
    ],
)
def test_a_list_with_a_non_mapping_item_is_still_opened_and_every_rule_answers(label: str, text: str) -> None:
    report = _r(text)
    statuses = _statuses(report)
    decisive = "KN-S001" if "privileged" in text else KAS  # the privileged container, or AlwaysAllow
    assert statuses[decisive] == "finding", label
    stray = any(not isinstance(i, dict) for i in yaml.safe_load(text)["items"])
    assert statuses["KN-V001"] == ("finding" if stray else "clean"), label  # the item that is not an object
    # The same bundle without the stray item: every OTHER rule reaches the same verdict, so the stray item changed
    # nothing but its own line (the control-plane rules decline on it: it may be a pod they cannot read).
    clean_items = [i for i in yaml.safe_load(text)["items"] if isinstance(i, dict)]
    reference = _statuses(_r(_list("List", clean_items)))
    for rid, status in statuses.items():
        if rid in {"KN-V001", KAS, ETCD}:
            continue
        assert status == reference[rid], (label, rid, status, reference[rid])


def test_the_control_plane_rules_decline_a_document_that_is_not_a_mapping() -> None:
    report = _r(_list("List", [KAS_POD, "not an object"]))
    assert [h.severity for h in _hits(report, KAS)] == [Severity.CRITICAL]
    assert KAS not in report.evaluated_rules and any(
        a.startswith(f"{KAS} was not evaluated") for a in report.assumptions
    )
    assert any("not a mapping" in a for a in report.assumptions if a.startswith(ETCD))


def test_a_nested_list_is_opened_all_the_way_down() -> None:
    inner = {"apiVersion": "v1", "kind": "PodList", "items": [PRIV, KAS_POD]}
    report = _r(_list("List", [{"apiVersion": "v1", "kind": "List", "items": [inner]}]))
    assert sorted(report.resources) == ["Pod/kube-system/kube-apiserver", "Pod/shop/priv"]
    assert _hits(report, "KN-S001") and _hits(report, KAS)
    assert not any("not all mappings" in a for a in report.assumptions)


def test_a_list_whose_items_is_not_a_list_still_declines_the_control_plane_rules() -> None:
    text = "apiVersion: v1\nkind: PodList\nitems: {a: b}\n"
    report = _r(text)
    for rid in (KAS, ETCD):
        assert any(a.startswith(f"{rid} was not evaluated") for a in report.assumptions)


@pytest.mark.parametrize(
    "fixture", ["L04-list-one-nonmapping-item.yaml", "L05-podlist-one-nonmapping-item.yaml", "L06-list-in-list.yaml"]
)
def test_the_reviewers_fixtures_exit_as_main_does(
    fixture: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from kube_noob.cli import main

    source = Path("/tmp/rt-cp5/fx/lists") / fixture
    if not source.exists():
        pytest.skip("reviewer fixtures are not on this machine")
    assert main(["audit", "-f", str(source), "--fail-on", "critical"]) == 1
    capsys.readouterr()


# --- 2. one pass over the line map, and the document cap after opening, for every command ---


class _CountingLines(dict):  # type: ignore[type-arg]
    """A line map that counts how many keys were looked at, so a per-item rescan shows as n_items * len."""

    visits = 0

    def items(self):  # type: ignore[override]
        for kv in super().items():
            type(self).visits += 1
            yield kv


def test_opening_a_list_reads_the_line_map_once() -> None:
    from kube_noob.yamlio import _flatten_lists

    n = 900
    docs = load_documents(
        _list("PodList", [dict(PRIV, metadata={"name": f"p{i}", "namespace": "shop"}) for i in range(n)])
    )
    assert len(docs) == n
    # Open the unflattened document with a counting line map: one visit per key, never per key per item.
    whole = yaml.safe_load(_list("PodList", [PRIV] * n))
    from kube_noob.yamlio import Document

    lines = _CountingLines({("items", i, "metadata", "name"): i + 3 for i in range(n)})
    lines[("kind",)] = 2
    _CountingLines.visits = 0
    out = _flatten_lists([Document(index=0, data=whole, lines=lines)])
    assert len(out) == n and _CountingLines.visits == len(lines)


@pytest.mark.parametrize("command", [["audit"], ["gate"], ["ksi"], ["fix"]])
def test_a_typed_list_past_the_document_cap_is_refused_alike_by_every_command(
    command: list[str], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from kube_noob.cli import main

    path = tmp_path / "big.yaml"
    path.write_text(
        _list(
            "PodList", [dict(PRIV, metadata={"name": f"p{i}", "namespace": "shop"}) for i in range(MAX_DOCUMENTS + 1)]
        )
    )
    code = main([*command, "-f", str(path)])
    err = capsys.readouterr().err
    assert code == 4 and f"More than {MAX_DOCUMENTS} YAML documents" in err, (command, code, err)


def test_the_mcp_audit_refuses_a_list_past_the_cap_rather_than_returning_a_giant_result() -> None:
    from kube_noob.config import load_settings
    from kube_noob.errors import ManifestError
    from kube_noob.toolkit import AuditIn, Toolkit

    text = _list(
        "PodList", [dict(PRIV, metadata={"name": f"p{i}", "namespace": "shop"}) for i in range(MAX_DOCUMENTS + 1)]
    )
    with pytest.raises(ManifestError):
        Toolkit(load_settings(overrides={"offline": True})).audit(AuditIn(manifests=text))


# --- 3. kubeadm v1beta4 repeats a name: sorted by (name, value), then the last wins ---

_CC4 = "apiVersion: kubeadm.k8s.io/v1beta4\nkind: ClusterConfiguration\napiServer:\n  extraArgs:\n"


def test_kubeadm_v1beta4_duplicate_anonymous_auth_is_sorted_before_last_wins() -> None:
    # cmd/kubeadm/app/util/arguments.go v1.31.0 ArgumentsToCommand sorts by (name, value): "false" < "true", so
    # kubeadm writes --anonymous-auth=false --anonymous-auth=true and pflag keeps true.
    text = (
        _CC4
        + '  - {name: anonymous-auth, value: "true"}\n  - {name: anonymous-auth, value: "false"}\n'
        + "  - {name: authorization-mode, value: Node,RBAC}\n"
    )
    assert [h.severity for h in _hits(_r(text), KAS)] == [Severity.MEDIUM]
    swapped = (
        _CC4
        + '  - {name: anonymous-auth, value: "false"}\n  - {name: anonymous-auth, value: "true"}\n'
        + "  - {name: authorization-mode, value: Node,RBAC}\n"
    )
    assert [h.severity for h in _hits(_r(swapped), KAS)] == [Severity.MEDIUM]


# --- 4. Rancher machine selectors, and the `+=` append suffix ---

_RANCHER = """apiVersion: provisioning.cattle.io/v1
kind: Cluster
metadata: {name: c, namespace: fleet-default}
spec:
  rkeConfig:
    machineSelectorConfig:
    - machineLabelSelector: {matchLabels: {role: worker}}
      config:
        kube-apiserver-arg: [authorization-mode=AlwaysAllow]
"""


def test_a_rancher_selector_config_declines_naming_the_selector_and_is_never_a_finding() -> None:
    report = _r(_RANCHER)
    assert not _hits(report, KAS)
    line = next(a for a in report.assumptions if a.startswith(KAS))
    assert "machineLabelSelector" in line and "role" in line


@pytest.mark.parametrize(
    "text",
    [
        _RANCHER.replace(
            "    - machineLabelSelector: {matchLabels: {role: worker}}\n      config:", "    - config:"
        ).replace("authorization-mode=AlwaysAllow", "authorization-mode+=AlwaysAllow"),
        "apiVersion: provisioning.cattle.io/v1\nkind: Cluster\nmetadata: {name: c, namespace: fleet-default}\nspec:\n"
        "  rkeConfig:\n    machineGlobalConfig:\n"
        "      kube-apiserver-arg: [authorization-mode=Node,RBAC, authorization-mode+=AlwaysAllow]\n",
    ],
)
def test_the_append_suffix_is_a_second_authorization_mode_flag(text: str) -> None:
    assert [h.severity for h in _hits(_r(text), KAS)] == [Severity.CRITICAL]


def test_the_append_suffix_on_the_k3s_argv_is_read_too() -> None:
    text = yaml.safe_dump(
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "k3s", "namespace": "kube-system"},
            "spec": {
                "containers": [
                    {
                        "name": "c",
                        "image": "rancher/k3s:v1.30.4-k3s1",
                        "command": [
                            "k3s",
                            "server",
                            "--kube-apiserver-arg=authorization-mode=Node,RBAC",
                            "--kube-apiserver-arg=authorization-mode+=AlwaysAllow",
                        ],
                    }
                ]
            },
        }
    )
    assert [h.severity for h in _hits(_r(text), KAS)] == [Severity.CRITICAL]


# --- 5. the insecure port's range and zones ---

_BASE = ["kube-apiserver", "--authorization-mode=Node,RBAC", "--anonymous-auth=false", "--etcd-servers=https://e:2379"]


def _pod(command: list[str]) -> str:
    return yaml.safe_dump(
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "w", "namespace": "kube-system"},
            "spec": {"containers": [{"name": "c", "image": "x", "command": command}]},
        },
        sort_keys=False,
    )


@pytest.mark.parametrize(
    "flags",
    [
        ["--insecure-port=70000", "--insecure-bind-address=0.0.0.0"],
        ["--insecure-port=-1", "--insecure-bind-address=0.0.0.0"],
        ["--insecure-bind-address=fe80::1%eth0"],
    ],
)
def test_an_insecure_port_out_of_range_or_a_zoned_address_declines(flags: list[str]) -> None:
    report = _r(_pod([*_BASE, *flags]), version="1.19")
    assert not _hits(report, KAS)
    line = next(a for a in report.assumptions if a.startswith(KAS))
    assert "refuses" in line


def test_an_insecure_port_at_the_edges_of_the_range_is_read() -> None:
    assert _hits(_r(_pod([*_BASE, "--insecure-port=65535", "--address=::"]), version="1.19"), KAS)
    assert not _hits(_r(_pod([*_BASE, "--insecure-port=0", "--address=::"]), version="1.19"), KAS)


# --- 6. the kubeadm form must match its apiVersion ---


@pytest.mark.parametrize(
    "text",
    [
        "apiVersion: kubeadm.k8s.io/v1beta3\nkind: ClusterConfiguration\napiServer:\n  extraArgs:\n"
        "  - {name: authorization-mode, value: AlwaysAllow}\n",
        "apiVersion: kubeadm.k8s.io/v1beta4\nkind: ClusterConfiguration\napiServer:\n  extraArgs:\n"
        "    authorization-mode: AlwaysAllow\n",
    ],
)
def test_a_kubeadm_form_that_does_not_match_its_api_version_declines(text: str) -> None:
    report = _r(text)
    assert not _hits(report, KAS)
    line = next(a for a in report.assumptions if a.startswith(KAS))
    assert "v1beta" in line and "decode" in line


# --- 7. what a config object skipped is named ---


def test_a_declined_config_object_names_the_files_and_env_it_skipped() -> None:
    text = """apiVersion: controlplane.cluster.x-k8s.io/v1beta1
kind: KubeadmControlPlane
metadata: {name: cp, namespace: default}
spec:
  kubeadmConfigSpec:
    files:
    - {path: /etc/kubernetes/authz.yaml, content: "x"}
    clusterConfiguration:
      apiServer:
        extraArgs: {authorization-mode: Node,RBAC}
        extraEnvs:
        - {name: X, value: y}
"""
    line = next(a for a in _r(text).assumptions if a.startswith(KAS))
    assert "files" in line and "extraEnvs" in line


# --- 8. a flag name pflag refuses ---


@pytest.mark.parametrize(
    "flag",
    [
        "--Authorization-Mode=AlwaysAllow",
        "--Anonymous-Auth=true",
        "--authorization.mode=AlwaysAllow",
        "--etcd-servers=x,--anonymous-auth=true",
    ],
)
def test_a_flag_name_with_a_character_pflag_refuses_declines(flag: str) -> None:
    if flag.startswith("--etcd-servers"):
        pytest.skip("a value is not a flag name")
    report = _r(_pod([*_BASE, flag]))
    assert not _hits(report, KAS)
    line = next(a for a in report.assumptions if a.startswith(KAS))
    assert "no such flag" in line and "does not start" in line


# --- 9. parity: morePartlyEvaluated is printed where moreNotEvaluated is ---


def test_more_partly_evaluated_is_printed_in_the_ksi_text_and_html() -> None:
    from kube_noob import report_html
    from kube_noob.cli import _ksi_markdown

    row = {
        "id": "KSI-X",
        "family": "X",
        "name": "x",
        "title": "x",
        "controls": [],
        "evidenced": True,
        "rulesFired": [],
        "variesByClass": [],
        "optionalFor": [],
        "rulesBehind": 20,
        "findings": 1,
        "clean": 0,
        "notEvaluated": 0,
        "partlyEvaluatedRules": [f"KN-S{i:03d}" for i in range(12)],
        "morePartlyEvaluated": 7,
        "evidence": {"shows": "x", "doesNotShow": "y", "rulesNamed": []},
    }
    out = {
        "indicators": [row],
        "audited": True,
        "note": "",
        "dataset": {
            "name": "d",
            "version": "1",
            "lastUpdated": "2026-01-01",
            "sha256": "0",
            "url": "",
            "retrieved": "",
        },
        "unmappedControls": [],
        "applicability": "",
        "sharedControlCaveat": "",
    }
    text = _ksi_markdown(out, True)
    assert "partly evaluated:" in text and "and 7 more" in text
    page = report_html.render(out)
    assert "partly evaluated" in page.lower() and "and 7 more" in page


# --- 10. the headline score is withheld while any rule declined on an object ---


def test_the_score_is_not_a_number_while_a_rule_declined_on_an_object(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`score=100.0` printed above "KN-S038 was not evaluated in full" is a number beside an unread rule."""
    from kube_noob.audit.compact import expand_report
    from kube_noob.cli import main
    from kube_noob.config import load_settings
    from kube_noob.toolkit import AuditIn, Toolkit

    text = _pod(["sh", "-c", "exec kube-apiserver"])
    report = _r(text)
    out = report.as_dict()
    assert out["declined"] and out["summary"]["score"] is None
    assert "KN-S038" in out["summary"]["scoreWithheld"] and "not evaluated in full" in out["summary"]["scoreWithheld"]
    assert isinstance(report.score(), float)  # the number itself still exists for the eval grader, by name
    path = tmp_path / "b.yaml"
    path.write_text(text, encoding="utf-8")
    main(["audit", "-f", str(path), "--fail-on", "never"])
    head = capsys.readouterr().out.splitlines()[0]
    assert "score=not determined (1 rule not evaluated in full)" in head and "score=100" not in head
    kit = Toolkit(load_settings(overrides={"offline": True}))
    flat = kit.audit(AuditIn(manifests=text))
    assert flat["summary"]["score"] is None
    assert expand_report(kit.audit(AuditIn(manifests=text, compact=True))) == flat


def test_the_score_stays_a_number_when_only_a_partial_bundle_guard_declined() -> None:
    """A partial bundle's quiet declines (no NetworkPolicy here to judge) are not a rule declining on an object."""
    text = _pod(["nginx"])
    report = analyze(text, "kubernetes", None, partial_bundle=True)
    out = report.as_dict()
    assert "declined" not in out and isinstance(out["summary"]["score"], float)
    assert "scoreWithheld" not in out["summary"]


def test_a_partly_evaluated_rule_withholds_the_score_too() -> None:
    text = (
        _pod(["kube-apiserver", "--authorization-mode=AlwaysAllow"])
        + "---\n"
        + _pod(["sh", "-c", "kube-apiserver"]).replace("name: w", "name: b")
    )
    out = _r(text).as_dict()
    assert out["controlSummary"]["partlyEvaluatedRules"] == [KAS] and out["summary"]["score"] is None
