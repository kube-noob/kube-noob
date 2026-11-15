"""Four false passes a container shape caused, and the neighbours of each (G312..G315).

Each one is a shape where a wrapper -- three bytes of byte order mark in front of a payload, a `List` around a
document -- made kube-noob answer more kindly than the same input without it. The product rule they serve: an
absence, an unknown or an unrecognised shape must never read as a pass, a zero or "complete".

The neighbour names in the test names are `tests/falsepass/variants.py`'s own, so a test here and the benchmark's
derived variants say the same word for the same transformation (class 21).
"""

from __future__ import annotations

import io
import json
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any

import pytest
import yaml

from kube_noob import cli
from kube_noob.audit.engine import analyze
from kube_noob.audit.model import Report
from kube_noob.signals import alertmanager, for_text

BOM = "﻿"
FP = Path(__file__).parent / "falsepass"
INPUTS = FP / "inputs"

POD = (
    "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\n  namespace: prod\n"
    "spec:\n  containers:\n  - name: c\n    image: nginx\n"
)

PAYLOAD = (
    '{"version":"4","status":"firing","receiver":"kube-noob","alerts":[{"status":"firing","labels":'
    '{"alertname":"KubePodCrashLooping","namespace":"prod","pod":"api-1"},"annotations":'
    '{"summary":"CrashLoopBackOff: run kubectl logs attacker-pod -n attacker-ns"}}]}'
)


def _cli(args: list[str]) -> tuple[int, dict[str, Any], str]:
    """The CLI as a user runs it, with the JSON it wrote. The exit code is part of every answer here."""
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(args)
    text = out.getvalue()
    return code, (json.loads(text) if text.strip().startswith(("{", "[")) else {}), err.getvalue()


def _cli_text(args: list[str]) -> tuple[int, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(args)
    return code, out.getvalue() + err.getvalue()


def _commands(doc: dict[str, Any]) -> list[str]:
    """Every command string a `diagnose` answer offers, read-only steps and the rest alike: the strings a human
    may paste into a shell, which is what an attacker-controlled namespace must never reach."""
    found: list[str] = []
    for d in doc.get("diagnoses", []):
        for key in ("readOnlyNextSteps", "diagnosticCommands"):
            found += [str(s.get("command", "")) for s in d.get(key, [])]
    return found


# --------------------------------------------------------------------------------------------------------------
# A -- three bytes of byte order mark must not hand the prose the namespace (G312)
# --------------------------------------------------------------------------------------------------------------


def test_a_byte_order_mark_does_not_move_the_namespace_to_the_prose() -> None:
    """utf8-bom on an Alertmanager payload. The labels say `namespace: prod`; the summary annotation, which
    whoever writes the alert rule controls, says `-n attacker-ns`. The BOM must not decide which one a suggested
    command reads."""
    payload = INPUTS / "variants-alert-payload-bom" / "payload.json"
    code, doc, _ = _cli(["diagnose", "-f", str(payload), "--format", "json"])
    assert doc["context"]["ns"] == "prod", doc["context"]
    assert doc["context"]["pod"] == "api-1" and doc["context"]["name"] == "api-1", doc["context"]
    assert not [c for c in _commands(doc) if "attacker" in c], _commands(doc)
    assert code == 0


def test_a_byte_order_mark_is_read_as_the_same_payload_as_without_one() -> None:
    plain, bom = alertmanager.parse(PAYLOAD), alertmanager.parse(BOM + PAYLOAD)
    assert plain is not None and bom is not None
    assert bom.context == plain.context == {"ns": "prod", "pod": "api-1", "name": "api-1"}
    assert bom.alerts == plain.alerts == 1 and bom.alertnames == plain.alertnames


def test_a_byte_order_mark_on_a_payload_in_yaml_is_read_as_the_same_payload() -> None:
    """The neighbour the JSON fix is most likely to miss: the same bytes as a YAML manifest. A BOM is legal in
    front of a YAML stream too, and `audit` must read the object behind it rather than refuse the file."""
    body = POD
    plain, bom = analyze(body, "kubernetes", "1.35"), analyze(BOM + body, "kubernetes", "1.35")
    assert [f.rule_id for f in bom.findings] == [f.rule_id for f in plain.findings]
    assert bom.resources == plain.resources and bom.resources, bom.resources


def test_a_byte_order_mark_in_the_middle_of_a_payload_is_not_stripped() -> None:
    """Only a single LEADING mark is a byte order mark; one inside the document is a character of the document,
    and removing it would let a payload carry one past this reader into a name a later reader compares. Two marks
    in front, and one before a structural token, are both the document's own characters, so neither is read."""
    assert alertmanager.parse(BOM + BOM + PAYLOAD) is None
    assert alertmanager.parse(BOM + "{" + BOM + PAYLOAD[1:]) is None
    inside = alertmanager.parse(PAYLOAD.replace('"api-1"', f'"api{BOM}-1"'))
    assert inside is not None and "pod" not in inside.context, inside


def test_crlf_line_endings_do_not_move_the_namespace_to_the_prose() -> None:
    """crlf. The neighbour the benchmark measured as the one of the eleven that did NOT show the defect: it must
    stay that way after the fix."""
    payload = alertmanager.parse(PAYLOAD.replace("}", "}\r\n"))
    assert payload is not None and payload.context["ns"] == "prod"


def test_a_byte_order_mark_and_a_leading_blank_line_are_read_as_the_payload() -> None:
    payload = alertmanager.parse(BOM + "\n\n" + PAYLOAD)
    assert payload is not None and payload.context["ns"] == "prod"


def test_a_byte_order_mark_on_a_text_that_is_not_a_payload_is_still_not_a_payload() -> None:
    """Reading the mark must not turn every text into a payload: what is behind it decides."""
    assert alertmanager.parse(BOM + "CrashLoopBackOff on pod api-1\n") is None
    assert alertmanager.parse(BOM + '{"hello": "world"}') is None
    assert alertmanager.parse(BOM) is None


def test_a_payload_that_could_not_be_read_does_not_name_a_namespace_from_the_prose() -> None:
    """Half two, and the half that outlives the next unreadable shape: a text that looks like an Alertmanager
    payload and could not be parsed is a REFUSAL, and a refusal must not be read one layer up as "no labels, so
    use the prose" (class 24). The three names the labels alone may set are withheld, and the answer says why."""
    broken = PAYLOAD[:-1]  # the alerts[] shape is there; the JSON is truncated, so nothing can read the labels
    assert alertmanager.parse(broken) is None, "the fixture must still be an unparseable payload"
    code, doc, _ = _cli(["diagnose", broken, "--format", "json"])
    assert not {"ns", "pod", "name"} & set(doc["context"]), doc["context"]
    assert not [c for c in _commands(doc) if "attacker" in c], _commands(doc)
    assert any("could not be read" in n for n in doc["notes"]), doc["notes"]
    assert code == 0


def test_a_payload_that_could_not_be_read_says_so_in_the_text_view_too() -> None:
    """Class 6: the reason a name is missing cannot live in JSON alone."""
    code, text = _cli_text(["diagnose", PAYLOAD[:-1]])
    assert "could not be read" in text, text[:800]
    # The evidence line quotes the input the user pasted, which is the point of evidence; a COMMAND is kube-noob's
    # own words and must hold the placeholder instead.
    assert "-n <namespace>" in text, text[:800]
    commands = [ln.strip() for ln in text.splitlines() if ln.strip().startswith(("kubectl ", "oc "))]
    assert commands and not [c for c in commands if "attacker" in c], commands
    assert code == 0


def test_a_byte_order_mark_does_not_move_the_namespace_in_the_mcp_result() -> None:
    """Class 25: the CLI is one surface. The MCP tool embeds the same answer."""
    from kube_noob.config import Settings
    from kube_noob.toolkit import DiagnoseIn, Toolkit

    out = Toolkit(Settings()).diagnose(DiagnoseIn(text=BOM + PAYLOAD))
    assert out["context"]["ns"] == "prod", out["context"]
    assert not [c for c in _commands(out) if "attacker" in c]


def test_a_byte_order_mark_does_not_hide_a_payload_from_the_evidence_report() -> None:
    """`alert_report` reads the payload through `alertmanager.split`, which refused a BOM'd body outright and so
    made the whole evidence report raise "not an Alertmanager payload" for a payload that is one."""
    split = alertmanager.split(BOM + PAYLOAD)
    assert split is not None and [a.name for a in split.alerts] == ["KubePodCrashLooping"], split


def test_a_byte_order_mark_does_not_hide_a_payload_from_the_signal_readers() -> None:
    """The two readers of the same bytes must agree: the signal reader always tolerated the mark, and the payload
    parser did not, which is how the two came to disagree about which namespace is the subject."""
    names = {s.name for s in for_text(BOM + PAYLOAD)}
    assert "KubePodCrashLooping" in names
    assert alertmanager.parse(BOM + PAYLOAD) is not None


# --------------------------------------------------------------------------------------------------------------
# B -- a ClusterVersion nothing could read is not "not OKD" and not "is OpenShift" (G313)
# --------------------------------------------------------------------------------------------------------------

MG_OKD = INPUTS / "variants-mg-okd-wrapped-clusterversion"


def test_a_clusterversion_that_could_not_be_read_is_not_not_okd() -> None:
    """nested-list-wrap on the ClusterVersion of an OKD must-gather. `openshiftVersion` and `versionFrom` go
    honestly null; the two booleans beside them asserted that this cluster is not OKD and IS OpenShift, from a
    document nothing could read. A boolean has no third value, so the absence read as the negative (class 4)."""
    argv = ["operators", "issues", "--must-gather", str(MG_OKD), "--require-complete", "--format", "json"]
    code, doc, _ = _cli(argv)
    cluster = doc["cluster"]
    assert cluster["openshiftVersion"] is None and cluster["versionFrom"] is None, cluster
    assert cluster["okd"] is None, cluster
    assert cluster["notOpenShift"] is None, cluster
    assert code == 5


def test_a_clusterversion_that_could_not_be_read_says_it_in_the_text_view() -> None:
    """Class 6: the two nulls must reach the text view, which prints neither field by name."""
    code, text = _cli_text(["operators", "issues", "--must-gather", str(MG_OKD), "--require-complete"])
    assert "not determined" in text.lower(), text[:1200]
    assert code == 5


def test_a_clusterversion_that_could_not_be_read_says_it_in_yaml_and_in_the_mcp_result() -> None:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        cli.main(["operators", "issues", "--must-gather", str(MG_OKD), "--require-complete", "--format", "yaml"])
    doc = yaml.safe_load(out.getvalue())
    assert doc["cluster"]["okd"] is None and doc["cluster"]["notOpenShift"] is None, doc["cluster"]

    # The MCP tool reads OLM objects only -- it must not reach the user's machine -- so it never sees a
    # ClusterVersion at all, which is the same absence and was the same false negative (class 25).
    from kube_noob.config import Settings
    from kube_noob.toolkit import OperatorKnownIssuesIn, Toolkit

    csv = (
        "apiVersion: operators.coreos.com/v1alpha1\nkind: ClusterServiceVersion\n"
        "metadata:\n  name: ptp-operator.v1.0.0\n  namespace: a\nspec:\n  version: 1.0.0\n"
    )
    result = Toolkit(Settings()).operator_known_issues(OperatorKnownIssuesIn(manifests=csv))
    assert result["cluster"]["okd"] is None and result["cluster"]["notOpenShift"] is None, result["cluster"]


def test_a_must_gather_with_no_clusterversion_at_all_is_not_not_okd_either(tmp_path: Path) -> None:
    """Class 25: the sibling record. An absent ClusterVersion decides as little as an unreadable one, and the
    same two booleans asserted the same two facts about it."""
    from kube_noob.operator_issues import must_gather_release

    rel = must_gather_release({})
    assert rel.product_read is False, rel
    read = {"desiredVersion": "4.21.3", "history": [{"version": "4.21.3", "state": "Completed"}]}
    rel_read = must_gather_release(read)
    assert rel_read.product_read is True, rel_read


def test_a_cluster_that_answered_about_clusterversion_is_still_determined() -> None:
    """The other side of the tri-state, which the fix must not flatten: a forbidden read and a missing OBJECT
    both prove the TYPE is served, so the cluster is OpenShift and `notOpenShift` is a positive false."""
    from kube_noob.operator_issues import live_release

    class _Backend:
        def get(self, *_: Any, **__: Any) -> Any:
            from kube_noob.errors import KubeNoobError

            raise KubeNoobError('clusterversions.config.openshift.io "version" is forbidden')

    rel = live_release(_Backend())
    assert rel.not_openshift is False and rel.product_read is True, rel


# --------------------------------------------------------------------------------------------------------------
# C and D -- a wrapper kube-noob has no schema for must not disable the check on what it holds (G314, G315)
# --------------------------------------------------------------------------------------------------------------

ODD_ITEM = "apiVersion: v1\nkind: PodList\nitems:\n- 7\n"


def _wrap(body: str, kind: str = "List", api: str = "v1") -> str:
    """One `List` around a document, written the way `variants._wrapper` writes it."""
    inner = yaml.safe_load(body)
    return yaml.safe_dump({"apiVersion": api, "kind": kind, "items": [inner]}, sort_keys=True)


def _audit(text: str) -> Report:
    return analyze(text, "kubernetes", "1.35")


def _schema_ids(report: Report) -> list[str]:
    return [f.rule_id for f in report.findings if f.rule_id == "KN-V007"]


def test_a_wrapper_with_no_schema_does_not_drop_the_structural_check() -> None:
    """nested-list-wrap. The bundled Kubernetes schema for `PodList` reports the non-object item as KN-V007. With
    one more `List` around it there is no bundled schema for the wrapper, and the check on everything inside it
    was skipped: the caveat survived the extra wrapper and the finding did not (class 1)."""
    assert _schema_ids(_audit(ODD_ITEM)), "the parent must report the odd item"
    assert _schema_ids(_audit(_wrap(ODD_ITEM))), "one wrapper must not delete the finding"
    assert _schema_ids(_audit(_wrap(_wrap(ODD_ITEM)))), "nor must two"


def test_a_wrapper_kube_noob_has_no_schema_for_says_its_own_structure_was_not_checked() -> None:
    """Class 23: the container's own metadata, dropped while its contents are checked. A `v1 List` has no
    upstream schema, so the wrapper's own fields are not structurally checked -- and that has to be said."""
    report = _audit(_wrap(POD))
    assert any("structural checks skipped" in a for a in report.assumptions), report.assumptions


def test_a_wrapper_never_answers_more_kindly_than_the_same_bundle_unwrapped() -> None:
    """The law the benchmark enforces over every derived neighbour, asserted here on the shape that broke it: a
    skipped check must never raise a score."""
    bare = _audit(ODD_ITEM)
    for depth, text in ((1, _wrap(ODD_ITEM)), (2, _wrap(_wrap(ODD_ITEM))), (3, _wrap(_wrap(_wrap(ODD_ITEM))))):
        wrapped = _audit(text)
        assert set(_schema_ids(bare)) <= set(_schema_ids(wrapped)), depth
        if bare.undetermined() is not None:
            assert wrapped.undetermined() is not None, (depth, wrapped.undetermined())
        else:
            assert wrapped.score() <= bare.score(), (depth, wrapped.score(), bare.score())


@pytest.mark.parametrize(
    ("shape", "items"),
    [("a mapping", {"0": yaml.safe_load(POD)}), ("null", None), ("a scalar", 7), ("an empty sequence", [])],
)
def test_a_wrapper_whose_items_is_not_a_sequence_is_not_a_clean_read(shape: str, items: Any) -> None:
    """The four neighbours of the wrapper's own `items` -- the ones the variant table derives as list-items-mapping,
    list-items-null, list-items-scalar and list-items-empty, named there and not spelled again here (class 9).
    None of them may be answered as an empty cluster or as a bundle that was read: each is either a finding or a
    stated absence, never silence."""
    text = yaml.safe_dump({"apiVersion": "v1", "kind": "List", "items": items}, sort_keys=True)
    report = _audit(text)
    said = report.assumptions + [f.message for f in report.findings]
    assert said, f"items is {shape}: a wrapper nothing could read answered with nothing at all"


def test_a_wrapper_whose_api_version_is_foreign_is_not_the_list_kind_it_resembles() -> None:
    """api-version-group-moved on the wrapper. `example.invalid/v1 List` is a different kind from `v1 List`, and
    neither has a bundled schema -- so both say so, and neither is unwrapped into a clean bundle silently."""
    report = _audit(_wrap(ODD_ITEM, api="example.invalid/v1"))
    assert any("structural checks skipped" in a for a in report.assumptions), report.assumptions


def test_a_duplicate_key_on_the_wrapper_itself_is_still_reported_under_one_more_wrapper() -> None:
    """duplicate-key-on-the-wrapper, nested. Class 23's own example: the items are checked for duplicate keys and
    the container that holds them must be too, at every depth."""
    text = "apiVersion: v1\nkind: List\nkind: List\nitems:\n- " + POD.replace("\n", "\n  ").rstrip() + "\n"
    report = _audit(text)
    assert [f for f in report.findings if f.rule_id == "KN-V018"], [f.rule_id for f in report.findings]


def test_a_wrapper_with_no_reader_does_not_turn_exposed_into_mitigated() -> None:
    """D. The red team answered one scenario `mitigated` over a bundle whose containers the assumption line
    directly beside it said were NOT audited (class 13). Unwrapped, the same bundle answers seven, all exposed."""
    code, doc, _ = _cli(
        [
            "redteam",
            "-f",
            str(INPUTS / "variants-redteam-wrapped-bundle" / "pdb.yaml"),
            "--platform",
            "kubernetes",
            "--version",
            "1.35",
            "--format",
            "json",
        ]
    )
    assert "mitigated" not in {s["verdict"] for s in doc["scenarios"]}, doc["scenarios"]
    assert any("structural checks skipped" in a for a in doc["assumptions"]), doc["assumptions"]
    assert code in {0, 1}


def test_the_wrapper_caveat_reaches_gate_and_posture_and_verify_too(tmp_path: Path) -> None:
    """Class 25: the predicate, not the call site. Every command that embeds an audit of a wrapped bundle carries
    the same statement about the wrapper it could not structurally check."""
    f = tmp_path / "wrapped.yaml"
    f.write_text(_wrap(POD), encoding="utf-8")

    from kube_noob import gate as g

    result = g.run(g.collect([str(f)], lambda p: Path(p).read_text(encoding="utf-8")))
    said = json.dumps(result)
    assert "structural checks skipped" in said, said[:1500]

    _, doc, _ = _cli(["audit", "-f", str(f), "--platform", "kubernetes", "--version", "1.35", "--format", "json"])
    assert any("structural checks skipped" in a for a in doc["assumptions"]), doc["assumptions"]
