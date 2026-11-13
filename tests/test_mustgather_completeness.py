"""`must-gather analyze` completeness is the fold of every leg that reported itself (G285).

`--require-complete` exited 0 on the shipped sample while the same output said "operator inventory: partial --
Subscriptions were not read", "operator known issues: partial -- incomplete: the inventory is partial", "searched no
release" and "skipped 1: nested archive (not opened)". `Analysis.completeness()` folded the eight analysers and the
unreadable files only; the legs the `operators` merge added were printed and never reached the exit code.
"""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path
from typing import Any

import pytest

from kube_noob.cli import main
from kube_noob.mustgather import analyse, completeness, ingest, sample
from kube_noob.mustgather import report as mg_report

IMAGE = sample.IMAGE
TOP = sample.TOP
ETCD_LOGS = f"{IMAGE}/namespaces/openshift-etcd/pods/etcd-master-0/etcd/etcd/logs"
# A ClusterVersion with no update in progress, so the release-note legs have a release to search.
SETTLED_CV = sample.FILES[f"{IMAGE}/cluster-scoped-resources/config.openshift.io/clusterversions/version.yaml"]
assert "4.20.4" in SETTLED_CV
OLM_NS = f"{IMAGE}/namespaces/openshift-operator-lifecycle-manager"
EMPTY_LIST = json.dumps({"apiVersion": "v1", "kind": "List", "items": []})


def _tar(path: Path, files: dict[str, str | bytes]) -> Path:
    with tarfile.open(path, "w:gz") as tf:
        for rel in sorted(files):
            data = files[rel].encode() if isinstance(files[rel], str) else files[rel]
            info = tarfile.TarInfo(f"{TOP}/{rel}")
            info.size = len(data)
            info.mtime = 1_793_181_600
            info.mode = 0o644
            tf.addfile(info, io.BytesIO(data))
    return path


def _files(**changes: str | bytes | None) -> dict[str, str | bytes]:
    out: dict[str, str | bytes] = {**sample.FILES, **sample.NESTED}
    for rel, data in changes.items():
        if data is None:
            out.pop(rel, None)
        else:
            out[rel] = data
    return out


def _report(bundle: ingest.Bundle) -> dict[str, Any]:
    return mg_report.build(bundle, analyse.analyse(bundle))


def _legs(rep: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {leg["leg"]: leg for leg in rep["completeness"]["legs"]}


def _settled(**extra: str | bytes | None) -> dict[str, str | bytes]:
    """The sample with its update completed and Subscriptions present: every leg has what it needs."""
    cv = SETTLED_CV.replace(
        "  - state: Partial\n    version: 4.20.4\n    startedTime: '2026-10-28T08:00:00Z'\n",
        "  - state: Completed\n    version: 4.20.4\n    completionTime: '2026-10-28T09:00:00Z'\n",
    )
    assert "Partial" not in cv
    subs = json.dumps(
        {
            "apiVersion": "v1",
            "kind": "List",
            "items": [
                {
                    "apiVersion": "operators.coreos.com/v1alpha1",
                    "kind": "Subscription",
                    "metadata": {"name": "rhacs-operator", "namespace": "rhacs-operator"},
                    "spec": {
                        "name": "rhacs-operator",
                        "channel": "stable",
                        "source": "redhat-operators",
                        "sourceNamespace": "openshift-marketplace",
                        "installPlanApproval": "Automatic",
                    },
                    "status": {"installedCSV": "rhacs-operator.v4.6.0", "currentCSV": "rhacs-operator.v4.6.0"},
                }
            ],
        }
    )
    settled: dict[str, str | bytes | None] = {
        f"{IMAGE}/cluster-scoped-resources/config.openshift.io/clusterversions/version.yaml": cv,
        f"{IMAGE}/namespaces/rhacs-operator/operators.coreos.com/subscriptions.yaml": subs,
        f"{IMAGE}/namespaces/shop/operators.coreos.com/subscriptions.yaml": EMPTY_LIST,
        f"{IMAGE}/namespaces/openshift-operator-lifecycle-manager/operators.coreos.com/subscriptions.yaml": EMPTY_LIST,
    }
    return _files(**{**settled, **extra})


# -- the shipped sample ------------------------------------------------------------------------------------------


def test_require_complete_exits_5_when_the_operator_inventory_is_partial(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    tgz = sample.write(tmp_path)
    assert main(["must-gather", "analyze", str(tgz), "--require-complete"]) == 5
    out = capsys.readouterr()
    assert "operator inventory" in out.err and "Subscriptions were not read" in out.err
    # the text view says which legs, in the line that already existed
    line = next(x for x in out.out.splitlines() if x.startswith("evidence is partial"))
    assert "operator inventory" in line and "operator known issues" in line and "--require-complete exits 5" in line
    # without the flag nothing but the new fields changes: the exit code stays 0
    assert main(["must-gather", "analyze", str(tgz)]) == 0


def test_the_legs_of_the_shipped_sample(tmp_path: Path) -> None:
    rep = _report(ingest.open_bundle(sample.write(tmp_path)))
    c = rep["completeness"]
    legs = _legs(rep)
    assert c["complete"] is False
    assert legs["analysers"]["state"] == "complete" and legs["files"]["state"] == "complete"
    assert legs["operator inventory"]["state"] == "partial" and "Subscriptions" in legs["operator inventory"]["why"]
    assert legs["operator known issues"]["state"] == "partial"
    assert "updating to 4.20.4" in legs["operator known issues"]["why"]
    # the nested audit-log archive is under a directory no analyser reads: a noted skip, not a gap
    assert legs["skipped files"]["state"] == "not-applicable" and "audit_logs" in legs["skipped files"]["why"]
    assert "no analyser reads" in legs["skipped files"]["why"]
    # Secret data is never read by design; the leg says so instead of counting it as missing
    assert legs["secrets"]["state"] == "not-applicable" and "never read" in legs["secrets"]["why"]
    assert c["partialLegs"] == ["operator inventory", "operator known issues"]
    # the keys the analyser-level fold always had are still there, unchanged in meaning
    assert c["analysersRead"] == c["analysersExpected"] == 8 and c["unreadableFiles"] == 0 and c["notCollected"] == []
    # every leg is named every time, so a consumer can key on them
    assert [leg["leg"] for leg in c["legs"]] == list(completeness.LEGS)
    assert all(leg["state"] in completeness.STATES for leg in c["legs"])


def test_an_update_in_progress_that_searched_no_release_is_a_partial_leg(tmp_path: Path) -> None:
    rep = _report(ingest.open_bundle(_tar(tmp_path / "s.tgz", _settled())))
    assert rep["completeness"]["complete"] is True, rep["completeness"]
    updating = _report(ingest.open_bundle(sample.write(tmp_path / "u")))
    leg = _legs(updating)["operator known issues"]
    assert leg["state"] == "partial" and "updating to 4.20.4" in leg["why"]


def test_a_settled_sample_with_subscriptions_is_complete_and_exits_0(tmp_path: Path) -> None:
    tgz = _tar(tmp_path / "settled.tgz", _settled())
    rep = _report(ingest.open_bundle(tgz))
    assert rep["completeness"]["complete"] is True and rep["completeness"]["partialLegs"] == []
    assert {leg["state"] for leg in rep["completeness"]["legs"]} <= {"complete", "not-applicable"}
    assert main(["must-gather", "analyze", str(tgz), "--require-complete"]) == 0


# -- nested archives -----------------------------------------------------------------------------------------------


def test_a_nested_archive_not_opened_makes_the_run_partial(tmp_path: Path) -> None:
    """A rotated etcd log shipped as .gz sits where the etcd analyser reads; not opening it is a gap."""
    rotated = {f"{ETCD_LOGS}/rotated/0.log.20261028-080000.gz": b"\x1f\x8b\x08\x00"}
    rep = _report(ingest.open_bundle(_tar(tmp_path / "n.tgz", _settled(**rotated))))
    leg = _legs(rep)["skipped files"]
    assert leg["state"] == "partial" and "nested archive" in leg["why"] and "openshift-etcd" in leg["why"]
    assert rep["completeness"]["complete"] is False
    assert main(["must-gather", "analyze", str(tmp_path / "n.tgz"), "--require-complete"]) == 5


def test_a_nested_archive_outside_every_analyser_directory_is_a_noted_skip(tmp_path: Path) -> None:
    rep = _report(ingest.open_bundle(_tar(tmp_path / "s.tgz", _settled())))
    leg = _legs(rep)["skipped files"]
    assert leg["state"] == "not-applicable" and "1 nested archive" in leg["why"]
    assert rep["completeness"]["complete"] is True


@pytest.mark.parametrize(
    "rel",
    [
        f"{IMAGE}/namespaces/shop/pods/web-7d9f/web/web/logs/rotated/0.log.gz",
        f"{IMAGE}/namespaces/shop/core/events.yaml.gz",
        f"{IMAGE}/cluster-scoped-resources/core/nodes/nodes.tar",
        f"{IMAGE}/namespaces/shop/operators.coreos.com/clusterserviceversions.tgz",
    ],
)
def test_an_archive_under_any_directory_an_analyser_reads_is_a_gap(tmp_path: Path, rel: str) -> None:
    rep = _report(ingest.open_bundle(_tar(tmp_path / "a.tgz", _settled(**{rel: b"\x1f\x8b\x08\x00"}))))
    assert _legs(rep)["skipped files"]["state"] == "partial"


def test_a_link_in_an_analyser_directory_is_a_gap_too(tmp_path: Path) -> None:
    """Every skip reason but Secrets follows the same rule: in a directory an analyser reads, it is a gap."""
    tgz = _tar(tmp_path / "l.tgz", _settled())
    with tarfile.open(tmp_path / "l2.tgz", "w:gz") as tf, tarfile.open(tgz) as src:
        for m in src.getmembers():
            tf.addfile(m, src.extractfile(m))
        link = tarfile.TarInfo(f"{TOP}/{IMAGE}/cluster-scoped-resources/core/nodes/other.yaml")
        link.type = tarfile.SYMTYPE
        link.linkname = "master-0.yaml"
        tf.addfile(link)
    rep = _report(ingest.open_bundle(tmp_path / "l2.tgz"))
    leg = _legs(rep)["skipped files"]
    assert leg["state"] == "partial" and "link" in leg["why"]


# -- the inventory with no OLM layout --------------------------------------------------------------------------------


def test_a_must_gather_with_no_olm_layout_is_not_determined_and_named_as_such(tmp_path: Path) -> None:
    """A must-gather cannot show that OLM is absent (a filtered gather omits it), so the inventory module already
    answers not-determined, never zero operators (G270); the leg carries that, as partial with the reason."""
    files = _settled(
        **{
            f"{IMAGE}/namespaces/shop/operators.coreos.com/subscriptions.yaml": None,
            f"{IMAGE}/namespaces/rhacs-operator/operators.coreos.com/subscriptions.yaml": None,
            f"{IMAGE}/namespaces/shop/operators.coreos.com/clusterserviceversions/rhacs-operator.v4.6.0.yaml": None,
            f"{IMAGE}/namespaces/openshift-operator-lifecycle-manager/operators.coreos.com/subscriptions.yaml": None,
            f"{OLM_NS}/operators.coreos.com/clusterserviceversions.yaml": None,
        }
    )
    rep = _report(ingest.open_bundle(_tar(tmp_path / "noolm.tgz", files)))
    leg = _legs(rep)["operator inventory"]
    assert leg["state"] == "partial" and "not determined" in leg["why"] and "not in this must-gather" in leg["why"]
    assert rep["completeness"]["complete"] is False


def test_olm_files_that_hold_no_operator_are_complete_with_zero_not_partial(tmp_path: Path) -> None:
    files = _settled(
        **{
            f"{IMAGE}/namespaces/rhacs-operator/operators.coreos.com/subscriptions.yaml": None,
            f"{IMAGE}/namespaces/shop/operators.coreos.com/clusterserviceversions/rhacs-operator.v4.6.0.yaml": None,
            f"{IMAGE}/namespaces/shop/operators.coreos.com/clusterserviceversions.yaml": EMPTY_LIST,
            f"{OLM_NS}/operators.coreos.com/clusterserviceversions.yaml": EMPTY_LIST,
        }
    )
    rep = _report(ingest.open_bundle(_tar(tmp_path / "zero.tgz", files)))
    legs = _legs(rep)
    assert legs["operator inventory"]["state"] == "complete" and "0 operators" in legs["operator inventory"]["why"]
    assert legs["operator known issues"]["state"] == "complete"


# -- every surface agrees -----------------------------------------------------------------------------------------


def test_the_text_view_the_json_and_the_report_json_agree_on_legs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    tgz = sample.write(tmp_path)
    out_dir = tmp_path / "rep"
    code = main(["--format", "json", "must-gather", "analyze", str(tgz), "--report", str(out_dir)])
    assert code == 0  # --report without --require-complete: the fields are there and the exit code is unchanged
    shown = json.loads(capsys.readouterr().out)["completeness"]
    written = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))["completeness"]
    assert shown == written and shown["complete"] is False and shown["legs"]
    assert main(["must-gather", "analyze", str(tgz)]) == 0
    text = capsys.readouterr().out
    line = next(x for x in text.splitlines() if x.startswith("evidence is partial"))
    for name in shown["partialLegs"]:
        assert name in line
    # report.md names the same partial legs in its "What was read" section
    md = (out_dir / "report.md").read_text(encoding="utf-8")
    section = md.split("## What was read", 1)[1]
    assert "partial" in section and all(name in section for name in shown["partialLegs"])


def test_the_mcp_result_carries_the_legs(tmp_path: Path) -> None:
    from kube_noob import toolkit as tk
    from kube_noob.config import Settings

    tgz = sample.write(tmp_path)
    settings = Settings()
    settings.must_gather.enabled = True
    settings.must_gather.allowed_dir = tmp_path
    kit = tk.Toolkit(settings)
    out = kit.analyze_must_gather(tk.MustGatherIn(path=str(tgz)))
    assert out["completeness"]["complete"] is False
    assert [leg["leg"] for leg in out["completeness"]["legs"]] == list(completeness.LEGS)
    assert out["completeness"]["partialLegs"] == ["operator inventory", "operator known issues"]


def test_fail_on_never_does_not_outrank_require_complete(tmp_path: Path) -> None:
    tgz = sample.write(tmp_path)
    assert main(["must-gather", "analyze", str(tgz), "--fail-on", "never", "--require-complete"]) == 5


def test_a_directory_and_its_archive_fold_the_same_legs(tmp_path: Path) -> None:
    tgz = sample.write(tmp_path)
    as_dir = _report(ingest.open_bundle(tmp_path / TOP))["completeness"]
    as_tar = _report(ingest.open_bundle(tgz))["completeness"]
    assert as_dir["complete"] is as_tar["complete"] is False and as_dir["partialLegs"] == as_tar["partialLegs"]
    # the one difference is the archive's top directory in the example path of the skipped audit log
    strip = [{**leg, "why": leg["why"].replace(f"{TOP}/", "")} for leg in as_tar["legs"]]
    assert as_dir["legs"] == strip


def test_the_analyser_legs_still_count(tmp_path: Path) -> None:
    """The fold must keep what it already caught: a missing analyser and an unreadable file."""
    files = _settled(
        **{
            f"{IMAGE}/cluster-scoped-resources/core/nodes/master-0.yaml": "kind: Node\nmetadata: {name: [\n",
            f"{IMAGE}/cluster-scoped-resources/core/nodes/worker-1.yaml": None,
            f"{IMAGE}/cluster-scoped-resources/machineconfiguration.openshift.io/machineconfigpools/worker.yaml": None,
        }
    )
    rep = _report(ingest.open_bundle(_tar(tmp_path / "b.tgz", files)))
    legs = _legs(rep)
    assert legs["analysers"]["state"] == "partial" and "machineconfigpools" in legs["analysers"]["why"]
    assert legs["files"]["state"] == "partial" and "1 file" in legs["files"]["why"]
    assert rep["completeness"]["partialLegs"][:2] == ["analysers", "files"]
