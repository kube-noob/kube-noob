"""`fix` reports its after-verdict under the assumptions the audit used (G286).

`fix -f examples/exercise-answer.yaml -o out.yaml` printed `after: score 79.0, medium 4` while `audit -f out.yaml`
printed `score=84.0 medium=3`: `Toolkit.fix` ran `analyze` as a whole-namespace audit with info findings counted,
while the CLI's `audit -f one-file` audits a partial bundle from low upwards, so KN-N001 ("no NetworkPolicy for the
namespace in this bundle") sat in the after-verdict and the fix looked worse than it was. `after` carried a summary
and nothing else: no assumptions, no before, no delta. One verdict, computed twice two ways (class 9 and 13).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from kube_noob import toolkit as tk
from kube_noob.cli import main
from kube_noob.config import Settings

ROOT = Path(__file__).resolve().parents[1]
EXERCISE = ROOT / "examples" / "exercise-answer.yaml"
INSECURE = ROOT / "examples" / "insecure-deployment.yaml"
COMPARED = ("score", "counts", "maxSeverity")


def _audit(text: str, **kw: Any) -> dict[str, Any]:
    return tk.Toolkit(Settings()).audit(tk.AuditIn(manifests=text, **kw))


def _fix(text: str, **kw: Any) -> dict[str, Any]:
    return tk.Toolkit(Settings()).fix(tk.FixIn(manifests=text, **kw))


def _same_verdict(view: dict[str, Any], audit: dict[str, Any]) -> None:
    for key in COMPARED:
        assert view[key] == audit["summary"][key], key
    assert view["assumptions"] == audit["assumptions"]
    assert view["controlSummary"] == audit["controlSummary"]


def _summary(err: str) -> dict[str, Any]:
    """The YAML block the CLI prints on stderr after the fixed manifests: from its first key on."""
    lines = err.splitlines()
    start = next(i for i, x in enumerate(lines) if x.startswith("changes:"))
    return yaml.safe_load("\n".join(lines[start:]))


def _cli_fix(tmp_path: Path, capsys: pytest.CaptureFixture[str], *args: str) -> tuple[Path, dict[str, Any]]:
    out = tmp_path / "out.yaml"
    assert main(["fix", *args, "-o", str(out)]) == 0
    return out, _summary(capsys.readouterr().err)


def _cli_audit(path: Path, capsys: pytest.CaptureFixture[str], *args: str) -> dict[str, Any]:
    main(["--format", "json", "audit", "-f", str(path), *args])
    return json.loads(capsys.readouterr().out)


# -- the toolkit -----------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("partial", [True, False])
def test_fix_after_equals_audit_on_the_fixed_bytes_for_a_single_file(partial: bool) -> None:
    text = EXERCISE.read_text(encoding="utf-8")
    res = _fix(text, partial_bundle=partial)
    _same_verdict(res["after"], _audit(res["manifests"], partial_bundle=partial))
    _same_verdict(res["before"], _audit(text, partial_bundle=partial))
    assert res["after"]["score"] >= res["before"]["score"]


def test_fix_in_takes_partial_bundle_with_the_audits_default() -> None:
    assert tk.FixIn.model_fields["partial_bundle"].default is tk.AuditIn.model_fields["partial_bundle"].default


def test_the_delta_lists_fixed_open_and_introduced_rules() -> None:
    text = INSECURE.read_text(encoding="utf-8")
    res = _fix(text, partial_bundle=True)
    before = {f["ruleId"] for f in _audit(text, partial_bundle=True)["findings"]}
    after = {f["ruleId"] for f in _audit(res["manifests"], partial_bundle=True)["findings"]}
    delta = res["delta"]
    assert delta["fixed"] == sorted(before - after) and delta["fixed"]
    assert delta["open"] == sorted(before & after)
    assert delta["introduced"] == sorted(after - before)
    assert delta["findingsBefore"] == len(_audit(text, partial_bundle=True)["findings"])
    assert delta["findingsAfter"] == len(_audit(res["manifests"], partial_bundle=True)["findings"])
    # under matching assumptions, a rule that fires only on a whole-namespace audit cannot appear as introduced
    assert "KN-N001" not in delta["introduced"]


def test_after_carries_assumptions_and_the_control_summary() -> None:
    res = _fix(EXERCISE.read_text(encoding="utf-8"), partial_bundle=True)
    for view in (res["before"], res["after"]):
        assert any("part of a namespace" in a for a in view["assumptions"])
        assert "controls" in view["controlSummary"]
    assert set(res) >= {"manifests", "changes", "manualFollowUps", "before", "after", "delta"}


def test_the_existing_fields_are_where_they_were() -> None:
    res = _fix(INSECURE.read_text(encoding="utf-8"))
    # `after` was the summary itself and callers read `after.score`: those keys stay at the top, joined by the rest
    assert {"counts", "maxSeverity", "score", "assumptions", "controlSummary"} == set(res["after"])
    assert res["after"]["score"] == _audit(res["manifests"])["summary"]["score"]
    assert isinstance(res["changes"], list) and isinstance(res["manualFollowUps"], list)


@pytest.mark.parametrize(("platform", "version"), [("openshift", "4.20"), ("rosa-hcp", "4.22"), ("kubernetes", "1.33")])
def test_platform_and_version_travel_into_both_verdicts(platform: str, version: str) -> None:
    text = INSECURE.read_text(encoding="utf-8")
    res = _fix(text, platform=platform, version=version, partial_bundle=True)
    _same_verdict(res["after"], _audit(res["manifests"], platform=platform, version=version, partial_bundle=True))
    _same_verdict(res["before"], _audit(text, platform=platform, version=version, partial_bundle=True))


def test_no_harden_is_audited_the_same_way() -> None:
    text = INSECURE.read_text(encoding="utf-8")
    res = _fix(text, harden=False, partial_bundle=True)
    _same_verdict(res["after"], _audit(res["manifests"], partial_bundle=True))


def test_a_file_with_two_documents() -> None:
    text = INSECURE.read_text(encoding="utf-8").rstrip() + "\n---\n" + EXERCISE.read_text(encoding="utf-8")
    res = _fix(text, partial_bundle=True)
    _same_verdict(res["after"], _audit(res["manifests"], partial_bundle=True))
    assert res["delta"]["fixed"]


def test_a_document_the_fixer_cannot_read_stays_in_the_after_assumptions() -> None:
    """The fixer passes a document it cannot read through unchanged and says so; the after-audit on those bytes has
    to carry the same unreadable-document note the audit would, not lose it in the delta."""
    text = INSECURE.read_text(encoding="utf-8").rstrip() + "\n---\n- not\n- an object\n"
    res = _fix(text, partial_bundle=True)
    assert "- not\n- an object" in res["manifests"], "the fixer passes a document it cannot read through"
    after_audit = _audit(res["manifests"], partial_bundle=True)
    _same_verdict(res["after"], after_audit)
    # the audit's verdict on those bytes is what the reader gets; nothing about the document vanished in between
    assert res["delta"]["findingsAfter"] == len(after_audit["findings"])


# -- the CLI ----------------------------------------------------------------------------------------------------


def test_the_cli_after_line_equals_audit_on_the_written_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out, summary = _cli_fix(tmp_path, capsys, "-f", str(EXERCISE))
    audit = _cli_audit(out, capsys)
    for key in COMPARED:
        assert summary["after"][key] == audit["summary"][key], key
    assert summary["after"]["assumptions"] == audit["assumptions"]
    before = _cli_audit(EXERCISE, capsys)
    for key in COMPARED:
        assert summary["before"][key] == before["summary"][key], key
    assert summary["delta"]["fixed"]


def test_the_cli_prints_before_and_after_on_one_line(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "out.yaml"
    assert main(["fix", "-f", str(EXERCISE), "-o", str(out)]) == 0
    err = capsys.readouterr().err
    line = next(x for x in err.splitlines() if x.startswith("before score="))
    assert "-> after score=" in line and "fixed" in line


def test_a_directory_is_audited_whole_in_fix_as_in_audit(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    d = tmp_path / "ns"
    d.mkdir()
    (d / "a.yaml").write_text(INSECURE.read_text(encoding="utf-8"), encoding="utf-8")
    (d / "b.yaml").write_text(EXERCISE.read_text(encoding="utf-8"), encoding="utf-8")
    out, summary = _cli_fix(tmp_path, capsys, "-f", str(d))
    assert not any("part of a namespace" in a for a in summary["before"]["assumptions"])
    before = _cli_audit(d, capsys)
    for key in COMPARED:
        assert summary["before"][key] == before["summary"][key], key
    # the written stream is one file: audited as one file it is partial, and `after` was computed whole, so the
    # comparison that holds is against a whole-namespace audit of the same bytes
    whole = _audit(out.read_text(encoding="utf-8"), partial_bundle=False)
    for key in COMPARED:
        assert summary["after"][key] == whole["summary"][key], key


def test_stdin_is_partial_in_fix_as_in_audit(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: Any
) -> None:
    import io

    text = EXERCISE.read_text(encoding="utf-8")
    monkeypatch.setattr("sys.stdin", io.StringIO(text))
    out = tmp_path / "out.yaml"
    assert main(["fix", "-f", "-", "-o", str(out)]) == 0
    summary = _summary(capsys.readouterr().err)
    assert any("part of a namespace" in a for a in summary["after"]["assumptions"])
    for key in COMPARED:
        assert summary["after"][key] == _audit(out.read_text(encoding="utf-8"), partial_bundle=True)["summary"][key]


def test_platform_flags_reach_the_cli_verdicts(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out, summary = _cli_fix(tmp_path, capsys, "-f", str(INSECURE), "--platform", "openshift", "--version", "4.20")
    audit = _cli_audit(out, capsys, "--platform", "openshift", "--version", "4.20")
    for key in COMPARED:
        assert summary["after"][key] == audit["summary"][key], key
    assert summary["after"]["assumptions"] == audit["assumptions"]


def test_the_mcp_fix_tool_agrees_with_the_mcp_audit_tool() -> None:
    kit = tk.Toolkit(Settings())
    text = INSECURE.read_text(encoding="utf-8")
    spec = next(s for s in kit.specs() if s.name == "fix_manifests")
    assert "partial_bundle" in spec.model.model_fields
    res = spec.fn(spec.model(manifests=text, partial_bundle=True))
    audit = kit.audit(tk.AuditIn(manifests=res["manifests"], partial_bundle=True))
    _same_verdict(res["after"], audit)
    assert "before" in res and "delta" in res
