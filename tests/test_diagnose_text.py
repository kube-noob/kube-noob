"""G277: `diagnose` has a text view, and `insight` says what it recognises when it recognises nothing.

`kube-noob diagnose -f examples/events-scc.txt` printed about 216 lines of YAML (with `exitCodes: {}` and an opaque
signal hash), `--format text` changed nothing, and only `kube-noob demo diagnose` showed the ten-line view a person
can act on. Every sibling (`policy reach`, `policy explain`, `known-issues`, `insight`, `must-gather analyze`)
defaults to text and keeps JSON and YAML behind `--format`. The text view must carry every caveat the structured
output carries (G221): what was not determined, notes, and steps that need approval labelled as such.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from kube_noob import demo
from kube_noob import toolkit as tk
from kube_noob.cli import main
from kube_noob.config import load_settings
from kube_noob.debug import diagnose as dx

EXAMPLES = demo.examples_dir()


def _run(argv: list[str], capsys: pytest.CaptureFixture[str]) -> str:
    assert main(argv) == 0
    return capsys.readouterr().out


def _structured(text: str, **kw: Any) -> dict[str, Any]:
    return tk.Toolkit(load_settings()).diagnose(tk.DiagnoseIn(text=text, **kw))


def test_diagnose_prints_a_text_view_by_default(capsys: pytest.CaptureFixture[str]) -> None:
    out = _run(["diagnose", "-f", str(EXAMPLES / "events-scc.txt")], capsys)
    first = out.splitlines()[0]
    assert first.startswith("DBG-SCC") and "SecurityContextConstraints" in first
    assert "approach:" not in out and "exitCodes" not in out and "a43fdded647d" not in out
    assert len(out.splitlines()) < 60
    assert out == _run(["diagnose", "-f", str(EXAMPLES / "events-scc.txt"), "--format", "text"], capsys)


@pytest.mark.parametrize("fmt", ["json", "yaml"])
def test_the_machine_formats_are_the_structured_result_unchanged(fmt: str, capsys: pytest.CaptureFixture[str]) -> None:
    text = (EXAMPLES / "events-scc.txt").read_text(encoding="utf-8")
    out = _run(["diagnose", "-f", str(EXAMPLES / "events-scc.txt"), "--format", fmt], capsys)
    expected = _structured(text)
    if fmt == "json":
        assert out == json.dumps(expected, indent=2, default=str) + "\n"
    else:
        assert out == yaml.safe_dump(expected, sort_keys=False, width=120, allow_unicode=True)


def test_every_step_that_needs_approval_is_labelled_as_such(capsys: pytest.CaptureFixture[str]) -> None:
    out = _run(["diagnose", "-f", str(EXAMPLES / "events-scc.txt")], capsys)
    structured = _structured((EXAMPLES / "events-scc.txt").read_text(encoding="utf-8"))
    top = structured["diagnoses"][0]
    shown = [c["change"] for c in top["proposedChanges"] if c["change"][:60] in out]
    assert shown, "no proposed change of the top diagnosis is shown"
    for change in shown:
        line = next(n for n, x in enumerate(out.splitlines()) if change[:60] in x)
        above = out.splitlines()[:line]
        assert any("needs approval" in x for x in above[-6:]), change
    for step in top["readOnlyNextSteps"]:
        assert step.get("command", step.get("instruction", "")) in out
    for d in structured["policyDenials"]:
        assert d["engineName"] in out and "fix (needs approval)" in out


def test_commands_that_run_in_a_container_are_labelled_as_needing_approval(
    capsys: pytest.CaptureFixture[str],
) -> None:
    out = _run(["diagnose", "HEALTH_WARN 1 osds down; OSD_DOWN 1 osds down"], capsys)
    structured = _structured("HEALTH_WARN 1 osds down; OSD_DOWN 1 osds down")
    lines = out.splitlines()
    for c in structured["cephHealth"]["diagnosticCommands"]:
        at = next(n for n, x in enumerate(lines) if c["command"] in x)
        assert "needs approval" in lines[at - 1], (c["command"], lines[at - 1])
    assert structured["cephHealth"]["note"] in out


def test_the_text_view_carries_what_was_not_determined(capsys: pytest.CaptureFixture[str]) -> None:
    out = _run(["diagnose", "etcd leader changed", "--platform", "openshift", "--version", "4.16.20"], capsys)
    assert "NOT DETERMINED for OpenShift 4.16.20" in out


def test_the_text_view_carries_the_notes(capsys: pytest.CaptureFixture[str]) -> None:
    text = "the thing is slow sometimes and we do not know why"
    structured = _structured(text)
    assert structured["notes"], "the fixture no longer produces a note"
    out = _run(["diagnose", text], capsys)
    assert all(n in out for n in structured["notes"])


def test_the_text_view_carries_memory_notes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    cfg = tmp_path / "kn.yaml"
    cfg.write_text(f"memory:\n  paths: [{tmp_path / 'no-such-repo'}]\n", encoding="utf-8")
    out = _run(["--config", str(cfg), "diagnose", "-f", str(EXAMPLES / "events-crashloop.txt")], capsys)
    assert "no-such-repo" in out


def test_the_text_view_says_where_the_version_came_from(capsys: pytest.CaptureFixture[str]) -> None:
    out = _run(["diagnose", "-f", str(EXAMPLES / "alertmanager-etcd.json")], capsys)
    assert "4.21.0" in out and "openshift_version" in out
    assert "OCPBUGS-73881" in out


def test_every_field_of_the_structured_result_has_a_decision_in_the_text_view() -> None:
    # A new field in the structured result must be rendered or consciously left out, not lost by default: the
    # renderer names both sets, and this fails until a new key is put in one of them.
    handled = dx.TEXT_RENDERED | set(dx.TEXT_OMITTED)
    for name in ("events-scc.txt", "events-crashloop.txt", "alertmanager-etcd.json"):
        assert set(_structured((EXAMPLES / name).read_text(encoding="utf-8"))) <= handled, name
    assert set(_structured("HEALTH_WARN 1 osds down; OSD_DOWN 1 osds down")) <= handled
    assert set(_structured("etcd leader changed", platform="openshift", version="4.16.20")) <= handled
    assert all(why for why in dx.TEXT_OMITTED.values())


def test_the_text_view_is_deterministic(capsys: pytest.CaptureFixture[str]) -> None:
    a = _run(["diagnose", "-f", str(EXAMPLES / "events-crashloop.txt")], capsys)
    b = _run(["diagnose", "-f", str(EXAMPLES / "events-crashloop.txt")], capsys)
    assert a == b


def test_the_text_view_drops_terminal_escapes_from_pasted_text(capsys: pytest.CaptureFixture[str]) -> None:
    out = _run(["diagnose", "Back-off restarting failed container \x1b]0;pwned\x07 api in pod api-1"], capsys)
    assert "\x1b" not in out and "\x07" not in out


# -- insight, when nothing is recognised -----------------------------------------------------------------------


def test_insight_names_what_it_recognises_when_it_recognises_nothing(capsys: pytest.CaptureFixture[str]) -> None:
    from kube_noob import insight

    out = _run(["insight", "paste anything"], capsys)
    assert "input: unknown (nothing recognised)" in out
    for kind in insight.KINDS:
        assert kind in out, kind
    assert "kube-noob insight -f examples/events-scc.txt" in out
    assert "kube-noob examples copy examples" in out


def test_every_kind_the_router_knows_has_a_description() -> None:
    from kube_noob import insight

    assert set(insight.KIND_DESCRIPTIONS) == set(insight.KINDS)
    assert all(insight.KIND_DESCRIPTIONS[k] for k in insight.KINDS)


def test_the_example_the_hint_shows_is_recognised() -> None:
    from kube_noob import insight

    assert insight.UNRECOGNISED_EXAMPLE in {p.name for p in EXAMPLES.iterdir()}
    kinds = insight.recognise((EXAMPLES / insight.UNRECOGNISED_EXAMPLE).read_text(encoding="utf-8"))
    assert kinds, "the example the hint offers is itself not recognised"


def test_insight_prints_no_hint_when_something_was_recognised(capsys: pytest.CaptureFixture[str]) -> None:
    out = _run(["insight", "-f", str(EXAMPLES / "events-scc.txt")], capsys)
    assert "kube-noob recognises" not in out
