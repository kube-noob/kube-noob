"""`gate --require-evaluated RULE_ID`: a rule the pipeline relies on must have run, or the gate is incomplete (G290).

`kube-noob gate -f examples/netpol-admin-tiers.yaml --fail-on high` exits 0 while the control record counts KN-N014
as not evaluated (no `--cni`): the AdminNetworkPolicy tier the pipeline relies on was never checked, and the exit
code read as clean. With `--require-evaluated KN-N014` the gate exits 5 (evidence incomplete) and says, in the rule's
own words, why the rule could not decide. Exit 1 keeps its meaning (findings at or above --fail-on, and a rule that
fired has been evaluated) and exit 2 names an unknown rule id.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kube_noob import gate
from kube_noob.cli import main

ROOT = Path(__file__).resolve().parents[1]
TIERS = ROOT / "examples" / "netpol-admin-tiers.yaml"
GOOD = ROOT / "tests" / "fixtures" / "gate" / "good"


def _read(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def _run(**kw: object) -> dict:  # type: ignore[type-arg]
    return gate.run(gate.collect([str(TIERS)], _read), platform="openshift", version="4.20", **kw)  # type: ignore[arg-type]


def _required(rep: dict) -> dict[str, dict]:  # type: ignore[type-arg]
    return {r["rule"]: r for r in rep["requiredEvaluated"]}


def test_a_required_rule_that_could_not_decide_is_incomplete_in_the_rules_own_words() -> None:
    rep = _run(require_evaluated=["KN-N014"])
    row = _required(rep)["KN-N014"]
    assert row["evaluated"] is False and "--cni" in row["why"]
    assert rep["incompleteEvaluation"] == ["KN-N014"]
    # not a finding and not a failure: `passed` keeps its meaning
    assert rep["passed"] is True


def test_with_the_cni_named_the_rule_is_evaluated_and_the_gate_is_complete() -> None:
    rep = _run(require_evaluated=["KN-N014"], cni="ovn-kubernetes")
    row = _required(rep)["KN-N014"]
    assert row["evaluated"] is True and rep["incompleteEvaluation"] == []


def test_a_rule_that_fired_counts_as_evaluated_and_the_findings_win() -> None:
    rep = _run(require_evaluated=["KN-N014"], cni="calico:3.32", fail_on="high")
    row = _required(rep)["KN-N014"]
    assert row["evaluated"] is True and row["fired"] >= 1 and "fired" in row["why"]
    assert rep["incompleteEvaluation"] == [] and not rep["passed"]
    assert any(f["ruleId"] == "KN-N014" for f in rep["findings"])


def test_an_excepted_rule_was_still_evaluated(tmp_path: Path) -> None:
    exceptions = json.dumps(
        {
            "apiVersion": "kube-noob.io/v1",
            "kind": "ExceptionList",
            "exceptions": [
                {
                    "id": "EXC-1",
                    "rule": "KN-N002",
                    "scope": {"namespace": "shop", "kind": "Route", "name": "legacy"},
                    "owner": "web-team",
                    "reason": "TLS ends at the external load balancer in front of the router",
                    "expires": "2027-06-30",
                }
            ],
        }
    )
    bad = ROOT / "tests" / "fixtures" / "gate" / "bad"
    rep = gate.run(
        gate.collect([str(bad)], _read),
        platform="openshift",
        version="4.20",
        exceptions=exceptions,
        require_evaluated=["KN-N002"],
    )
    row = _required(rep)["KN-N002"]
    assert row["evaluated"] is True and row["excepted"] >= 1 and "excepted" in row["why"]
    assert rep["incompleteEvaluation"] == []


def test_a_rule_declined_for_a_missing_policy_says_so() -> None:
    """KN-S036 declines when no registry allow-list is configured; the reason is the rule's, not a hand-written one."""
    rep = _run(require_evaluated=["KN-S036"])
    row = _required(rep)["KN-S036"]
    assert row["evaluated"] is False and "registr" in row["why"]
    assert rep["incompleteEvaluation"] == ["KN-S036"]


def test_a_rule_whose_subject_is_absent_is_evaluated_and_clean_today() -> None:
    """On main a rule with nothing of its kind in the input runs and finds nothing; the gate reports exactly what
    the audit records, so this reads `evaluated` until the audit itself says otherwise (G281)."""
    rep = _run(require_evaluated=["KN-V017"])
    row = _required(rep)["KN-V017"]
    assert row["evaluated"] is True and row["fired"] == 0


def test_no_manifests_means_nothing_was_evaluated(tmp_path: Path) -> None:
    cf = ROOT / "tests" / "fixtures" / "containerfile" / "KN-B005.bad.Containerfile"
    rep = gate.run([], containerfiles=[("Containerfile", _read(str(cf)))], require_evaluated=["KN-N014"])
    row = _required(rep)["KN-N014"]
    assert row["evaluated"] is False and "no manifests" in row["why"]
    assert rep["incompleteEvaluation"] == ["KN-N014"]


def test_the_markdown_and_the_sarif_carry_the_line() -> None:
    rep = _run(require_evaluated=["KN-N014", "KN-S001"])
    md = gate.markdown(rep)
    assert "INCOMPLETE KN-N014 -- " in md and "--cni" in md
    assert "evaluated KN-S001" in md
    doc = gate.sarif(rep)
    inv = doc["runs"][0]["invocations"][0]
    assert inv["properties"]["requiredEvaluated"] == rep["requiredEvaluated"]
    notes = [n for n in inv["toolExecutionNotifications"] if "KN-N014" in n["message"]["text"]]
    assert len(notes) == 1 and notes[0]["level"] == "error"
    assert inv["executionSuccessful"] is True


def test_without_the_flag_nothing_changes() -> None:
    rep = _run()
    assert "requiredEvaluated" not in rep and "incompleteEvaluation" not in rep
    assert "Required" not in gate.markdown(rep)


def test_cli_exit_codes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    base = ["gate", "-f", str(TIERS), "--platform", "openshift", "--version", "4.20", "--fail-on", "high"]
    assert main([*base]) == 0
    capsys.readouterr()
    assert main([*base, "--require-evaluated", "KN-N014"]) == 5
    out = capsys.readouterr()
    line = next(x for x in out.err.splitlines() if x.startswith("INCOMPLETE KN-N014 -- "))
    assert "--cni" in line
    assert "INCOMPLETE KN-N014 -- " in out.out
    assert main([*base, "--require-evaluated", "KN-N014", "--cni", "ovn-kubernetes"]) == 0
    capsys.readouterr()
    assert main([*base, "--require-evaluated", "KN-N014", "--cni", "calico:3.32"]) == 1
    assert "KN-N014" in capsys.readouterr().out
    assert main([*base, "--require-evaluated", "KN-N014", "--require-evaluated", "KN-S001"]) == 5
    capsys.readouterr()
    assert main([*base, "--require-evaluated", "KN-X999"]) == 2
    assert "KN-X999" in capsys.readouterr().err


def test_json_output_carries_the_record(capsys: pytest.CaptureFixture[str]) -> None:
    args = ["--format", "json", "gate", "-f", str(TIERS), "--platform", "openshift", "--version", "4.20"]
    assert main([*args, "--require-evaluated", "KN-N014", "--fail-on", "never"]) == 5
    out = json.loads(capsys.readouterr().out)
    assert out["requiredEvaluated"] == [
        {"rule": "KN-N014", "evaluated": False, "fired": 0, "excepted": 0, "why": out["requiredEvaluated"][0]["why"]}
    ]
    assert "--cni" in out["requiredEvaluated"][0]["why"] and out["incompleteEvaluation"] == ["KN-N014"]


def test_a_sarif_file_with_the_flag_still_validates(tmp_path: Path) -> None:
    out = tmp_path / "g.sarif"
    main(
        [
            "gate",
            "-f",
            str(TIERS),
            "--platform",
            "openshift",
            "--require-evaluated",
            "KN-N014",
            "--sarif",
            str(out),
            "--quiet",
        ]
    )
    doc = json.loads(out.read_text(encoding="utf-8"))
    inv = doc["runs"][0]["invocations"][0]
    assert isinstance(inv["properties"]["requiredEvaluated"], list) and inv["executionSuccessful"] is True
