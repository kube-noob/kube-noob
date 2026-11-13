"""G277: a version the known-issue index does not hold is "not determined", never "no known issue".

`kube-noob known-issues 'etcd leader changed' --version 4.16.20` exited 0 with `"matches": []` and a note naming
the releases the index holds. Nothing machine-readable said 4.16 was outside them, so a pipeline or a model reading
the result concluded "not a known bug" -- a verdict earned by absence, the defect class P6 fixed for the API tables.
Every surface that consults the index with a version now carries the same three-valued statement.
"""

from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from kube_noob import known_issues
from kube_noob import toolkit as tk
from kube_noob.cli import main
from kube_noob.config import load_settings

ETCD = "etcd leader changed"


def _kit() -> tk.Toolkit:
    return tk.Toolkit(load_settings())


def _releases() -> list[str]:
    return list(known_issues.get_index().knowledge()["openshiftReleases"])


def test_the_index_still_holds_the_releases_these_tests_assume() -> None:
    # The tests below pick a version below, inside and above the index. If the bundled snapshot moves, they must
    # move with it rather than pass for the wrong reason.
    assert _releases() == ["4.20", "4.21", "4.22"]


def test_a_version_older_than_the_index_is_not_determined_rather_than_no_known_issue() -> None:
    out = _kit().known_issues(tk.KnownIssuesIn(text=ETCD, version="4.16.20"))
    assert out["matches"] == []
    cov = out["versionCoverage"]
    assert cov["status"] == "not-determined" and cov["version"] == "4.16.20"
    assert "4.16" in cov["why"] and "4.20, 4.21, 4.22" in cov["why"] and "NOT DETERMINED" in cov["why"]


def test_a_version_newer_than_the_index_is_not_determined_even_with_matches() -> None:
    # Issues still open in an older release can be listed for a newer one, but that release's own notes were not
    # read: a list is not the whole answer.
    out = _kit().known_issues(tk.KnownIssuesIn(text=ETCD, version="4.23.1"))
    assert out["versionCoverage"]["status"] == "not-determined"
    assert "4.23" in out["versionCoverage"]["why"]


def test_a_version_inside_the_index_with_no_match_stays_a_determined_no_match() -> None:
    out = _kit().known_issues(tk.KnownIssuesIn(text=ETCD, version="4.21.3"))
    assert out["matches"] == [] and out["note"].startswith("No reported issue in the OpenShift release notes")
    assert out["versionCoverage"]["status"] == "determined"


def test_no_version_says_the_answer_is_not_narrowed_by_version() -> None:
    out = _kit().known_issues(tk.KnownIssuesIn(text=ETCD))
    assert out["matches"]  # OCPBUGS-73881, fixed in 4.21.1: listed because nothing says the cluster has the fix
    cov = out["versionCoverage"]
    assert cov["status"] == "not-narrowed" and "version" not in cov
    assert "not narrowed by version" in cov["why"]


def test_text_that_is_not_a_version_is_not_narrowed_and_says_so() -> None:
    # A pre-release (4.21.0-rc.1) is a version now (see test_first_run_review.py); words are not.
    cov = known_issues.match(ETCD, "openshift", "latest")["versionCoverage"]
    assert cov["status"] == "not-narrowed" and cov["version"] == "latest"
    assert known_issues.coverage_line(cov, listed=False) == cov["why"]


def test_a_version_from_a_label_is_shown_on_one_line_and_visibly() -> None:
    cov = known_issues.match(ETCD, "openshift", "4.16.20\nKnown issues determined\u202e")["versionCoverage"]
    assert cov["status"] == "not-narrowed" and "\n" not in cov["why"] and "\u202e" not in cov["why"]


def test_a_blank_version_is_not_narrowed_rather_than_matched_against_nothing() -> None:
    cov = known_issues.match(ETCD, "openshift", "   ")["versionCoverage"]
    assert cov["status"] == "not-narrowed" and "version" not in cov


def test_an_empty_index_determines_nothing() -> None:
    cov = known_issues.version_coverage("4.21.3", [], None)
    assert cov["status"] == "not-determined" and "no release" in cov["why"]


def test_a_plain_kubernetes_question_carries_no_coverage_because_the_index_was_not_consulted() -> None:
    out = known_issues.match(ETCD, "kubernetes", "1.33")
    assert "versionCoverage" not in out and "does not apply" in out["note"]


def test_the_coverage_is_deterministic() -> None:
    a = known_issues.match(ETCD, "openshift", "4.16.20")
    b = known_issues.match(ETCD, "openshift", "4.16.20")
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


@pytest.mark.parametrize("fmt", ["json", "yaml"])
def test_the_cli_machine_formats_carry_the_statement(fmt: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["known-issues", ETCD, "--version", "4.16.20", "--format", fmt]) == 0
    out = capsys.readouterr().out
    assert "not-determined" in out and "versionCoverage" in out


def test_the_text_view_says_not_determined_and_keeps_exit_0(capsys: pytest.CaptureFixture[str]) -> None:
    # known-issues has no --require-complete and exit 5 means unreadable evidence, not an index ceiling (AGENTS.md:
    # never add a meaning to a code), so the statement is in the output and the exit code is unchanged, as P6 did.
    assert main(["known-issues", ETCD, "--version", "4.16.20"]) == 0
    out = capsys.readouterr().out
    assert "NOT DETERMINED for OpenShift 4.16.20" in out


def test_the_text_view_says_not_narrowed_when_no_version_is_given(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["known-issues", ETCD]) == 0
    assert "not narrowed by version" in capsys.readouterr().out


def test_the_mcp_tool_result_carries_the_statement() -> None:
    from kube_noob import tool_runner

    kit = _kit()
    spec = next(s for s in kit.specs() if s.name == "known_issues")
    out = tool_runner.call(spec, {"text": ETCD, "version": "4.16.20"}, "test")
    assert out["versionCoverage"]["status"] == "not-determined"


def test_diagnose_carries_the_statement_next_to_its_empty_list() -> None:
    out = _kit().diagnose(tk.DiagnoseIn(text=ETCD, platform="openshift", version="4.16.20"))
    assert out["knownIssues"] == [] and out["knownIssuesCoverage"]["status"] == "not-determined"


def test_diagnose_of_text_that_never_reached_the_index_says_nothing_about_coverage() -> None:
    # Plain Kubernetes text is not matched against OpenShift release notes at all; there is no coverage to state.
    out = _kit().diagnose(tk.DiagnoseIn(text="Back-off restarting failed container api in pod api-1"))
    assert "knownIssuesCoverage" not in out


def test_build_diagnose_carries_the_statement() -> None:
    log = "STEP 1/3: FROM registry.redhat.io/ubi9\nerror: build error: etcd leader changed\n"
    out = _kit().build_diagnose(tk.BuildDiagnoseIn(log=log, platform="openshift", version="4.16.20"))
    assert out["knownIssuesCoverage"]["status"] == "not-determined"


def test_insight_carries_the_statement_in_json_and_text(capsys: pytest.CaptureFixture[str]) -> None:
    out = _kit().insight(tk.InsightIn(text=ETCD, platform="openshift", version="4.16.20"))
    assert out["knownIssuesCoverage"]["status"] == "not-determined"
    assert main(["insight", ETCD, "--platform", "openshift", "--version", "4.16.20"]) == 0
    assert "NOT DETERMINED for OpenShift 4.16.20" in capsys.readouterr().out


def test_the_incident_watch_carries_the_statement(tmp_path: Path) -> None:
    from kube_noob.incidents import Observation
    from kube_noob.watch import Watcher

    w = Watcher(load_settings(), backend=None, namespaces=["openshift-etcd"], platform="openshift")
    w.version = "4.16.20"
    obs = Observation(namespace="openshift-etcd", workload="etcd", signal="LeaderChanged", evidence=[ETCD])
    out = w.analyse(obs, {}, datetime(2026, 11, 11, tzinfo=UTC))
    assert out["knownIssuesCoverage"]["status"] == "not-determined"


def _mustgather_at(tmp_path: Path, version: str) -> Path:
    from kube_noob.mustgather import sample

    sample.write(tmp_path)
    root = tmp_path / sample.TOP
    for f in root.rglob("*"):
        if f.is_file() and not f.name.endswith(".gz"):
            data = f.read_bytes()
            if b"4.20.3" in data:
                f.write_bytes(data.replace(b"4.20.4", b"4.16.21").replace(b"4.20.3", version.encode()))
    (tmp_path / "must-gather.tar.gz").unlink()
    return root


def test_the_must_gather_report_carries_the_statement_for_the_detected_version(tmp_path: Path) -> None:
    from kube_noob.mustgather import analyse, ingest, report

    b = ingest.open_bundle(_mustgather_at(tmp_path / "mg", "4.16.20"))
    r = report.build(b, analyse.analyse(b), data_dir=tmp_path / "data")
    assert r["cluster"]["version"] == "4.16.20"
    assert r["knownIssues"] == [] and r["knownIssuesCoverage"]["status"] == "not-determined"
    md = report.markdown(r)
    assert "NOT DETERMINED for OpenShift 4.16.20" in md and "None of the findings matches a known issue" not in md
    assert "NOT DETERMINED for OpenShift 4.16.20" in report.case_draft(r)


def test_the_must_gather_report_for_an_indexed_version_is_unchanged(tmp_path: Path) -> None:
    from kube_noob.mustgather import analyse, ingest, report, sample

    b = ingest.open_bundle(sample.write(tmp_path / "mg"))
    r = report.build(b, analyse.analyse(b), data_dir=tmp_path / "data")
    assert r["knownIssuesCoverage"]["status"] == "determined"
    assert "NOT DETERMINED" not in report.markdown(r)


def test_must_gather_analyze_text_and_exit_code(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = _mustgather_at(tmp_path / "mg", "4.16.20")
    archive = shutil.make_archive(str(tmp_path / "mg416"), "gztar", root_dir=root.parent, base_dir=root.name)
    assert main(["must-gather", "analyze", archive, "--require-complete"]) in {0, 5}
    out = capsys.readouterr().out
    assert "NOT DETERMINED for OpenShift 4.16.20" in out


def test_the_gate_names_the_lookup_it_could_not_make() -> None:
    from kube_noob import gate

    cm = gate.Source("cm.yaml", "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: c, namespace: shop}\n")
    rep: dict[str, Any] = gate.run([cm], platform="openshift", version="4.16")
    assert rep["knownIssues"] == [] and rep["knownIssuesCoverage"]["status"] == "not-determined"
    assert any("reported issues" in n and "4.16" in n for n in rep["notRun"])
    inside = gate.run([cm], platform="openshift", version="4.20")
    assert inside["knownIssuesCoverage"]["status"] == "determined"
    assert not any("reported issues" in n for n in inside["notRun"])
    assert "knownIssuesCoverage" not in gate.run([cm], platform="kubernetes", version="1.33")


def test_the_live_diagnostic_bundle_carries_the_statement() -> None:
    from kube_noob.debug.diagnose import bundle_markdown

    cov = known_issues.match(ETCD, "openshift", "4.16.20")["versionCoverage"]
    result = {"target": "deployment/shop/api", "backend": "t", "knownIssues": [], "knownIssuesCoverage": cov}
    md = bundle_markdown(result)
    assert "NOT DETERMINED for OpenShift 4.16.20" in md
