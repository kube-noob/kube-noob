"""Gate findings as GitHub annotations, which is where a developer actually looks (roadmap N12).

`gate --sarif` has always written SARIF, and `action.yml` has always run the gate, but nothing turned a finding
into an annotation -- so a finding landed in a log somebody had to go looking for. The constraint that shapes
this is GitHub's own: "10 warning annotations, 10 error annotations, and 10 notice annotations per step" and "50
annotations per job" (actions/toolkit, docs/problem-matchers.md, retrieved 2026-11-05). Emitting one per finding
would therefore drop the rest SILENTLY, and a developer who sees ten annotations and assumes that is all of them
has been misled by the tool -- the same defect as a count that stops being true.

So the last annotation of each kind is spent saying how many were not shown.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from kube_noob import gate

ROOT = Path(__file__).resolve().parents[1]


def _finding(
    rule: str,
    severity: str,
    uri: str | None = "k8s/deploy.yaml",
    line: int | None = 7,
    fails: bool = True,
) -> dict[str, Any]:
    """`fails` is what `gate.run` marks on a finding it actually failed on.

    Set explicitly here rather than derived from the severity, because that derivation was the defect: the gate
    fails on a vulnerability only when it is fixable or known exploited, and on a code finding only when an image
    ships the file, so severity alone annotated passing findings as errors.
    """
    return {
        "failsGate": fails,
        "ruleId": rule,
        "severity": severity,
        "title": f"{rule} title",
        "message": f"{rule} says something is wrong",
        "remediation": "do the thing",
        "resource": "Deployment/shop/web",
        "uri": uri,
        "line": line,
        "path": "spec.template.spec",
    }


def _report(findings: list[dict[str, Any]], fail_on: str = "high", failures: list[str] | None = None) -> dict[str, Any]:
    return {
        "findings": findings,
        "failOn": fail_on,
        "passed": False,
        "failures": [] if failures is None else failures,
    }


def test_a_finding_at_or_above_the_threshold_is_an_error_annotation() -> None:
    lines = gate.github_annotations(_report([_finding("KN-S001", "critical")]))
    assert len(lines) == 1
    assert lines[0].startswith("::error ")
    assert "file=k8s/deploy.yaml" in lines[0] and "line=7" in lines[0]
    assert "KN-S001" in lines[0]


def test_a_finding_below_the_threshold_is_a_warning() -> None:
    lines = gate.github_annotations(_report([_finding("KN-C001", "low", fails=False)]))
    assert lines[0].startswith("::warning ")


def test_the_message_is_one_line_and_escaped() -> None:
    """A newline or a comma in a workflow command ends the annotation early, so the message must survive it."""
    bad = _finding("KN-S002", "high")
    bad["message"] = "first line\nsecond line, with a comma: and a colon%"
    line = gate.github_annotations(_report([bad]))[0]
    assert "\n" not in line
    assert "%0A" in line and "%25" in line
    # The shape is `::<level> <properties>::<message>`, so two `::` are correct and the properties must hold no
    # comma or colon pair of their own -- those end the property list.
    head, _, message = line.partition("::")[2].partition("::")
    assert head.startswith("error ") and "," in head
    assert "%0A" in message and ":" in message, "a colon in the MESSAGE is harmless and stays readable"


def test_a_finding_with_no_file_still_annotates() -> None:
    """A Containerfile finding or a scanner finding may have no manifest line. Dropping it would hide it."""
    line = gate.github_annotations(_report([_finding("KN-S003", "high", uri=None, line=None)]))[0]
    assert line.startswith("::error ") and "file=" not in line


def test_the_last_annotation_says_how_many_were_not_shown() -> None:
    """GitHub drops the eleventh silently. A tool that lets it is telling a developer there are ten problems."""
    findings = [_finding(f"KN-S{i:03d}", "critical") for i in range(25)]
    lines = gate.github_annotations(_report(findings))
    assert len(lines) == gate.MAX_ANNOTATIONS_PER_TYPE
    assert all(line.startswith("::error ") for line in lines)
    assert "16 more" in lines[-1] and "SARIF" in lines[-1]


def test_both_kinds_are_capped_independently() -> None:
    findings = [_finding(f"KN-S{i:03d}", "critical") for i in range(12)]
    findings += [_finding(f"KN-C{i:03d}", "low", fails=False) for i in range(12)]
    lines = gate.github_annotations(_report(findings))
    errors = [x for x in lines if x.startswith("::error ")]
    warnings = [x for x in lines if x.startswith("::warning ")]
    assert len(errors) == len(warnings) == gate.MAX_ANNOTATIONS_PER_TYPE
    assert "3 more" in errors[-1] and "3 more" in warnings[-1]


def test_nothing_is_emitted_for_a_clean_report() -> None:
    assert gate.github_annotations({"findings": [], "failOn": "high", "passed": True, "failures": []}) == []


def test_the_worst_findings_come_first() -> None:
    lines = gate.github_annotations(_report([_finding("KN-A", "high"), _finding("KN-B", "critical")]))
    assert "KN-B" in lines[0] and "KN-A" in lines[1]


def test_never_as_a_threshold_makes_every_finding_a_warning() -> None:
    """`--fail-on never` means nothing fails, so the gate marks nothing and nothing is an error."""
    lines = gate.github_annotations(_report([_finding("KN-S001", "critical", fails=False)], fail_on="never"))
    assert lines[0].startswith("::warning ")


def test_the_total_stays_under_githubs_per_job_cap() -> None:
    findings = [_finding(f"KN-S{i:03d}", "critical") for i in range(40)]
    findings += [_finding(f"KN-C{i:03d}", "low", fails=False) for i in range(40)]
    assert len(gate.github_annotations(_report(findings))) <= 50


def test_the_cli_prints_them_and_keeps_the_exit_code() -> None:
    from kube_noob.cli import main

    fixtures = str(ROOT / "tests" / "fixtures" / "gate" / "bad")
    assert main(["gate", "-f", fixtures, "--platform", "kubernetes", "--fail-on", "high", "--github-annotations"]) == 1


def test_the_action_emits_them() -> None:
    """A feature the action does not call is a feature a user of the action does not have."""
    action = (ROOT / "action.yml").read_text(encoding="utf-8")
    # The action's shell is scripts/ci/gate.sh (G291): the input reaches it as KN_ANNOTATIONS, which adds the flag.
    assert "KN_ANNOTATIONS: ${{ inputs.annotations }}" in action
    assert 'sh "$GITHUB_ACTION_PATH/scripts/ci/gate.sh"' in action
    script = (ROOT / "scripts" / "ci" / "gate.sh").read_text(encoding="utf-8")
    assert '[ "$KN_ANNOTATIONS" != "false" ]; then set -- "$@" --github-annotations' in script
    assert re.search(r"annotations:\n\s+description:", action), "the behaviour is documented as an input"


def test_the_documented_limit_is_the_one_in_the_code() -> None:
    """If GitHub changes the cap, the number lives in one place and this test names where it came from."""
    assert gate.MAX_ANNOTATIONS_PER_TYPE == 10
    assert "problem-matchers" in (gate.github_annotations.__doc__ or "")


def test_a_json_report_is_unchanged_by_the_flag(capsys: pytest.CaptureFixture[str]) -> None:
    """Annotations go to stdout as workflow commands; the report must stay machine-readable beside them."""
    from kube_noob.cli import main

    fixtures = str(ROOT / "tests" / "fixtures" / "gate" / "bad")
    assert main(["--format", "json", "gate", "-f", fixtures, "--platform", "kubernetes", "--github-annotations"]) == 1
    out = capsys.readouterr().out
    body = "\n".join(line for line in out.splitlines() if not line.startswith("::"))
    assert json.loads(body)["findings"], "the JSON report survives beside the annotations"


# -- a red team on the above found these ------------------------------------------------------------------------


def test_a_finding_the_gate_did_not_fail_on_is_not_an_error() -> None:
    """The headline defect. An unfixable critical CVE with no KEV entry is at or above the floor and does NOT
    fail the gate, so annotating it as an error put a red cross on a step that passed."""
    report = _report([_finding("CVE-2099-0001", "critical", uri="trivy.json", line=None, fails=False)])
    report["passed"] = True
    lines = gate.github_annotations(report)
    assert lines[0].startswith("::warning ")


def test_the_reason_a_gate_failed_with_no_findings_is_annotated() -> None:
    """An expired exception list, a Containerfile that would not parse, an unreadable SARIF file: the step was
    red and the pull request said nothing at all."""
    lines = gate.github_annotations(_report([], failures=["the exception list has expired or refused entries"]))
    assert len(lines) == 1
    assert lines[0].startswith("::error title=kube-noob gate::")
    assert "expired" in lines[0]


def test_the_reasons_come_before_the_findings() -> None:
    report = _report([_finding("KN-S001", "critical")], failures=["3 finding(s) at high or above"])
    lines = gate.github_annotations(report)
    assert "kube-noob gate" in lines[0] and "KN-S001" in lines[1]


def test_the_reasons_and_the_findings_share_the_one_error_budget() -> None:
    """GitHub counts ten errors per step whoever wrote them, so the reasons cannot push the findings over."""
    report = _report(
        [_finding(f"KN-S{i:03d}", "critical") for i in range(20)],
        failures=[f"reason {i}" for i in range(4)],
    )
    lines = gate.github_annotations(report)
    assert len([x for x in lines if x.startswith("::error ")]) == gate.MAX_ANNOTATIONS_PER_TYPE


def test_a_property_value_ending_in_a_colon_does_not_eat_the_separator() -> None:
    """`title=x:` plus `::` is three colons, and the runner ends the properties at the first two: the title lost
    its colon and the message gained one. Every colon in a property is escaped now."""
    f = _finding("KN-X", "critical", uri="path:")
    f["title"] = "ends with colon:"
    line = gate.github_annotations(_report([f]))[0]
    props = line.partition("::")[2].partition("::")[0]
    assert ":" not in props and "%3A" in props


def test_an_annotation_is_not_anchored_to_a_path_no_checkout_has() -> None:
    """Reading from stdin gives every finding the uri "-", and `file=-` asks GitHub to anchor the annotation to
    a file named "-". The runner drops it from the diff or puts it somewhere meaningless, which is worse than a
    repository-level annotation: the finding looks reported and is not. Recorded by a red team on 2026-11-05 as
    unverified, reproduced on 2026-11-06 while cutting 0.8.0 (G224)."""
    from pathlib import Path

    from kube_noob import gate

    root = Path(__file__).resolve().parents[1]
    report = gate.run([gate.Source("-", (root / "examples/insecure-deployment.yaml").read_text())], fail_on="high")
    lines = gate.github_annotations(report)
    assert lines, "the findings still produce annotations"
    assert not [line for line in lines if "file=-" in line]
    reported = {f["ruleId"] for f in report["findings"] if any(f["ruleId"] in line for line in lines)}
    assert reported, "the findings are still reported, just not anchored"
    real = gate.run(
        [gate.Source("deploy/web.yaml", (root / "examples/insecure-deployment.yaml").read_text())],
        fail_on="high",
    )
    assert any("file=deploy/web.yaml" in line for line in gate.github_annotations(real))
