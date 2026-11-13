"""`gate` says when the reported-issues check did not run (G284).

`gate` on OpenShift reported `knownIssues: []` -- which every pipeline reads as none -- when it had no version to
search, when the release was one the bundled index does not cover, and when the platform was not OpenShift at all.
The three cases and a real search that matched nothing were the same bytes. `known-issues` and `operators issues`
already say "not determined" with a verdict beside the list; the gate, the surface a pipeline acts on, said nothing.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kube_noob import gate
from kube_noob.cli import main
from kube_noob.known_issues import get_index

ROOT = Path(__file__).resolve().parents[1]
GOOD = ROOT / "tests" / "fixtures" / "gate" / "good"
CM = gate.Source("cm.yaml", "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: c, namespace: shop}\n")
# A kind no release note names, so a looked-up release matches nothing and the list is a real zero.
QUIET = gate.Source("q.yaml", "apiVersion: v1\nkind: Zzqwxv\nmetadata: {name: q, namespace: shop}\n")


def _releases() -> list[str]:
    return list(get_index(None).knowledge()["openshiftReleases"])


def _not_run_about_issues(rep: dict) -> list[str]:  # type: ignore[type-arg]
    return [n for n in rep["notRun"] if n.startswith("reported issues")]


def test_gate_on_openshift_without_a_version_says_known_issues_were_not_evaluated() -> None:
    rep = gate.run([CM], platform="openshift", version=None)
    assert rep["knownIssues"] == []
    assert rep["knownIssuesVerdict"] == "not-evaluated"
    assert "--version" in rep["knownIssuesNote"]
    (line,) = _not_run_about_issues(rep)
    assert "--version" in line and "not searched" in line
    # the pipeline-facing contract is unchanged: a not-evaluated check is a caveat, not a failure
    assert rep["passed"] and rep["failures"] == []


# 4.23 is in the catalog (admission policies generate for it) and not in the release-note index: the two tables
# are not the same table, and the gate must read the one it searched. A version the catalog refuses outright
# ("4", "3.11", "4.9") never reaches this check: it is refused, which is not a pass either.
@pytest.mark.parametrize("version", ["4.14", "4.12.5", "4.23", "4.19", "v4.20", "4.20-rc.1"])
def test_gate_on_a_release_outside_the_index_is_not_evaluated_not_none(version: str) -> None:
    rep = gate.run([CM], platform="openshift", version=version)
    assert rep["knownIssues"] == []
    assert rep["knownIssuesVerdict"] == "not-evaluated"
    note = rep["knownIssuesNote"]
    assert version in note and all(r in note for r in _releases()) and "as of" in note
    assert _not_run_about_issues(rep) == [f"reported issues: {note}"]


def test_the_same_manifests_on_an_indexed_and_an_unindexed_release_do_not_read_the_same() -> None:
    inside = gate.run([CM], platform="openshift", version="4.20")
    outside = gate.run([CM], platform="openshift", version="4.14")
    assert inside["knownIssuesVerdict"] == "looked-up" and inside["knownIssues"]
    assert outside["knownIssuesVerdict"] == "not-evaluated"
    assert inside["notRun"] != outside["notRun"]


def test_gate_on_kubernetes_is_not_applicable_not_none() -> None:
    platform = "kubernetes"
    rep = gate.run([CM], platform=platform, version="1.33")
    assert rep["knownIssues"] == []
    assert rep["knownIssuesVerdict"] == "not-applicable"
    assert "OpenShift" in rep["knownIssuesNote"]
    # the question does not arise, so it is not a check that was skipped
    assert _not_run_about_issues(rep) == []
    assert gate.run([CM], platform=platform, version=None)["knownIssuesVerdict"] == "not-applicable"


def test_a_looked_up_release_with_zero_matches_is_looked_up_with_an_empty_list() -> None:
    rep = gate.run([QUIET], platform="openshift", version="4.20")
    assert rep["knownIssues"] == []
    assert rep["knownIssuesVerdict"] == "looked-up"
    assert "4.20" in rep["knownIssuesNote"] and "as of" in rep["knownIssuesNote"]
    assert _not_run_about_issues(rep) == []
    md = gate.markdown(rep)
    assert "no open reported issue" in md.lower() and "4.20" in md


@pytest.mark.parametrize("platform", ["rosa-hcp", "rosa-classic"])
def test_every_openshift_family_platform_looks_the_release_up(platform: str) -> None:
    rep = gate.run([CM], platform=platform, version="4.20")
    assert rep["knownIssuesVerdict"] == "looked-up" and rep["knownIssues"]
    assert gate.run([CM], platform=platform, version=None)["knownIssuesVerdict"] == "not-evaluated"


@pytest.mark.parametrize("version", ["4.20.0.1", "4.20.3", "4.22"])
def test_a_patch_or_build_suffix_still_resolves_to_its_minor(version: str) -> None:
    assert gate.run([CM], platform="openshift", version=version)["knownIssuesVerdict"] == "looked-up"


def test_a_looked_up_result_is_byte_for_byte_what_it_was() -> None:
    rep = gate.run([CM], platform="openshift", version="4.20")
    assert rep["knownIssues"] == gate._known({"ConfigMap"}, "openshift", "4.20", None)[0]
    assert len(rep["knownIssues"]) <= 20 and all("ConfigMap" in k["kinds"] for k in rep["knownIssues"])


def test_the_not_run_section_names_the_reason_in_markdown_and_sarif(tmp_path: Path) -> None:
    rep = gate.run([CM], platform="openshift", version="4.14")
    md = gate.markdown(rep)
    not_run = md.split("### Not run", 1)[1]
    assert "reported issues" in not_run and "4.14" in not_run
    doc = gate.sarif(rep)
    inv = doc["runs"][0]["invocations"][0]
    assert inv["executionSuccessful"] is True
    notes = inv["toolExecutionNotifications"]
    issue_notes = [n for n in notes if "reported issues" in n["message"]["text"]]
    assert len(issue_notes) == 1 and issue_notes[0]["level"] == "warning"
    assert "4.14" in issue_notes[0]["message"]["text"]
    # every other not-run leg travels too: the SARIF alone must say what the run did not do
    texts = [n["message"]["text"] for n in notes]
    assert len(texts) == len(rep["notRun"]) and all(any(t.endswith(n) for t in texts) for n in rep["notRun"])
    # and the same document on a looked-up release carries no such note
    clean = gate.sarif(gate.run([CM], platform="openshift", version="4.20"))
    clean_notes = clean["runs"][0]["invocations"][0]["toolExecutionNotifications"]
    assert all("reported issues" not in n["message"]["text"] for n in clean_notes)


def test_the_cli_carries_the_verdict_in_json_in_the_summary_and_in_the_sarif_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sarif = tmp_path / "out.sarif"
    summary = tmp_path / "summary.md"
    args = ["--format", "json", "gate", "-f", str(GOOD), "--platform", "openshift", "--fail-on", "never"]
    args += ["--sarif", str(sarif), "--summary", str(summary)]
    assert main([*args, "--version", "4.14"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["knownIssuesVerdict"] == "not-evaluated" and "4.14" in out["knownIssuesNote"]
    assert any("4.14" in n for n in out["notRun"])
    assert "reported issues" in summary.read_text(encoding="utf-8").split("### Not run", 1)[1]
    notes = json.loads(sarif.read_text(encoding="utf-8"))["runs"][0]["invocations"][0]["toolExecutionNotifications"]
    assert any("4.14" in n["message"]["text"] for n in notes)
    # the text view is the Markdown summary
    assert main([*args[2:], "--version", "4.14"]) == 0
    text = capsys.readouterr().out
    assert "reported issues" in text.split("### Not run", 1)[1] and "4.14" in text
