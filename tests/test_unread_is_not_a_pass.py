"""A file nothing could be read from, and an object no rule read, are evidence the run does not have.

Three defects, one sentence: something was in the input, was not read, and an output said "fine" anyway.

G340. `gate` exits 5 for a file it could not read, and its REPORT said `passed: true`. `incomplete` was
`"undetermined" in coverage or bool(blocking)`; `blocking` is the files the walk declined to open (G325), and a file
it could not parse was in neither. So the Markdown summary read "## kube-noob gate passed" without naming the
file and nothing was annotated on the pull request. The exit code being right is why nobody read the report.

G341. Two renderers that DID mention the file lost its name: they read `u["path"]` and a gate report's rows carry
`file`. The page printed "File not read." beside an empty name (and its `<span>` as text); the OSCAL remark said
"could not be read and were skipped: ?.".

G342. `red_team` answered `mitigated` on `evidence: []` for a privileged Deployment the audit had refused for its
apiVersion, and dropped three scenarios that are `exposed` for the same object under `apps/v1`.

Each control comes first in its section, because each of these fixes has a muted-alert twin: a gate that is
incomplete on every repository, or a red team that can never say `mitigated`, is turned off by its readers.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from kube_noob import gate, oscal, report_html
from kube_noob import toolkit as tk
from kube_noob.audit.engine import analyze
from kube_noob.cli import main
from kube_noob.gate import NOT_READ_RULE
from kube_noob.toolkit import Toolkit

BROKEN = "broken.yaml"
#: Bytes YAML will not parse: the file was never opened as a manifest, so nothing in it was audited.
UNPARSEABLE = "apiVersion: v1\nkind: Pod\nmetadata: {name: [unclosed\n"

PRIVILEGED = """\
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: prod}
spec:
  replicas: 1
  selector: {matchLabels: {app: web}}
  template:
    metadata: {labels: {app: web}}
    spec:
      containers:
      - name: web
        image: registry.example.com/web:1
        securityContext: {privileged: true}
"""
#: The same object under a group the API server never serves `Deployment` under: no rule reads it.
REFUSED = PRIVILEGED.replace("apps/v1", "apps.k8s.io/v1")

HARDENED_POD = """\
apiVersion: v1
kind: Pod
metadata: {name: ok, namespace: prod, labels: {app: ok}}
spec:
  automountServiceAccountToken: false
  serviceAccountName: ok
  securityContext: {runAsNonRoot: true, seccompProfile: {type: RuntimeDefault}}
  containers:
  - name: c
    image: registry.example.com/c@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    resources: {requests: {cpu: 10m, memory: 16Mi}, limits: {memory: 32Mi, cpu: 100m}}
    securityContext:
      privileged: false
      runAsNonRoot: true
      runAsUser: 1001
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities: {drop: [ALL]}
      seccompProfile: {type: RuntimeDefault}
    livenessProbe: {httpGet: {path: /healthz, port: 8080}}
    readinessProbe: {httpGet: {path: /ready, port: 8080}}
"""
DNS_POLICY = """\
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: default-deny, namespace: prod}
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
  egress:
  - ports:
    - {protocol: UDP, port: 53}
    - {protocol: TCP, port: 53}
"""
#: What `gate -f .` meets in every repository: YAML that is read, understood, and is no Kubernetes object.
WORKFLOW = "name: ci\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n    - run: make test\n"


def _dir(root: Path, **files: str) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (root / name.replace("_yaml", ".yaml")).write_text(text, encoding="utf-8")
    return root


def _report(root: Path) -> dict[str, Any]:
    """The report as `gate -f DIR` builds it: `collect` over a real directory, so the rows are the product's."""
    return gate.run(gate.collect([str(root)], read=lambda _: ""), fail_on="never")


@pytest.fixture
def clean(tmp_path: Path) -> Path:
    return _dir(tmp_path / "clean", pod_yaml=HARDENED_POD, netpol_yaml=DNS_POLICY, ci_yaml=WORKFLOW)


@pytest.fixture
def unread(tmp_path: Path) -> Path:
    """Nothing to report AND a file missing: every finding list is empty, so a renderer that derives its output
    from findings alone emits the one output its reader takes for a clean run."""
    return _dir(tmp_path / "unread", pod_yaml=HARDENED_POD, netpol_yaml=DNS_POLICY, broken_yaml=UNPARSEABLE)


# -- G340: the gate's own predicate ----------------------------------------------------------------------------


def test_a_directory_every_file_of_which_was_read_still_passes(clean: Path) -> None:
    """The control, first. A workflow file beside the manifests is read and understood and is no manifest: it is
    `skipped`, not `unreadable`, and a gate that called that incomplete would be red on every repository."""
    report = _report(clean)
    assert [s["file"].rsplit("/", 1)[-1] for s in report["skipped"]] == ["ci.yaml"]
    assert report["unreadable"] == []
    assert report["passed"] is True
    assert report["incomplete"] is False
    assert report["failures"] == []
    assert gate.verdict_word(report) == "passed"
    assert gate.incomplete_reason(report) == ""
    assert gate.markdown(report).startswith("## kube-noob gate passed")
    assert gate.github_annotations(report) == []
    assert "properties" not in gate.sarif_of_gate(report)["runs"][0]["invocations"][0]
    assert "The gate passed." in report_html.render(report)


def test_a_gate_that_could_not_read_a_file_is_incomplete_and_not_passed(unread: Path) -> None:
    """The regression: `passed: true`, `incomplete: false`, on a run the command itself exits 5 for."""
    report = _report(unread)
    assert [u["file"].rsplit("/", 1)[-1] for u in report["unreadable"]] == [BROKEN]
    assert report["findings"] == [], "the fixture has findings, so it proves less than it claims"
    assert report["incomplete"] is True
    assert report["passed"] is False
    assert gate.verdict_word(report) == "incomplete"
    assert len(report["failures"]) == 1 and BROKEN in report["failures"][0]


def test_the_summary_a_reviewer_reads_says_incomplete_and_names_the_file(unread: Path) -> None:
    """`## kube-noob gate passed` over an all-zero table was the whole summary."""
    text = gate.markdown(_report(unread))
    assert text.startswith("## kube-noob gate incomplete")
    assert "### Why it is incomplete" in text
    assert "broken.yaml" in text.replace("\\", "")


def test_the_pull_request_is_annotated_with_the_file_that_was_not_read(unread: Path) -> None:
    """With no finding and no failure it annotated nothing at all, so the pull request said nothing."""
    lines = gate.github_annotations(_report(unread))
    assert len(lines) == 1
    assert lines[0].startswith("::error title=kube-noob gate::") and BROKEN in lines[0]


def test_the_page_and_the_uploaded_file_state_the_reason_and_not_an_empty_one(unread: Path) -> None:
    """Two readers of the reason. The masthead read `undetermined`, which a file-level gap does not set, and
    the SARIF invocation set `properties.incomplete` for an unread object and not for an unread file."""
    report = _report(unread)
    page = report_html.render(report)
    assert "Gate incomplete." in page
    assert "The gate is incomplete: 1 file(s) could not be read" in page
    assert "incomplete: None" not in page and "incomplete: ," not in page
    run = gate.sarif_of_gate(report)["runs"][0]
    props = run["invocations"][0]["properties"]
    assert props["incomplete"] is True and BROKEN in props["undetermined"]
    assert {r["ruleId"] for r in run["results"]} >= {NOT_READ_RULE, "kube-noob/undetermined"}
    assert NOT_READ_RULE in [i["check_name"] for i in gate.codequality(report)]


def test_the_exit_code_is_five_and_the_report_beside_it_agrees(
    unread: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """At the command, where the report and the exit code are written by the same run and disagreed."""
    assert main(["gate", "-f", str(unread), "--fail-on", "never", "--format", "json"]) == 5
    out = json.loads(capsys.readouterr().out)
    assert (out["passed"], out["incomplete"]) == (False, True)


def test_skip_unreadable_keeps_its_exit_code_and_does_not_buy_the_word_passed(
    unread: Path, clean: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`--skip-unreadable` is documented to gate the files that were read (G126), and still does: 0 here, and 1
    when one of them has a finding at `--fail-on`. What it decides is the exit code. The report is written for a
    reviewer who did not pass the flag, so it still says incomplete and still names the file."""
    assert main(["gate", "-f", str(unread), "--skip-unreadable", "--format", "json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert (out["passed"], out["incomplete"]) == (False, True)
    assert BROKEN in out["failures"][0]
    with_finding = _dir(tmp_path / "bad", deployment_yaml=PRIVILEGED, broken_yaml=UNPARSEABLE)
    assert main(["gate", "-f", str(with_finding), "--skip-unreadable", "--fail-on", "high", "--format", "json"]) == 1
    capsys.readouterr()
    # ... and the flag changes nothing where every file was read.
    assert main(["gate", "-f", str(clean), "--skip-unreadable", "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["passed"] is True


# -- G341: the file's name ---------------------------------------------------------------------------------------


def test_one_reader_takes_the_name_from_either_command_s_rows() -> None:
    """A gate report's rows carry `file`, an audit report's carry `path`. Both first, because the fix for one
    must not be the regression for the other: `audit --oscal` and `audit --html` hand over `path` rows."""
    assert gate.unread_rows({"unreadable": [{"file": "a.yaml", "why": "x"}]}) == [{"path": "a.yaml", "why": "x"}]
    assert gate.unread_rows({"unreadable": [{"path": "b.yaml", "why": "y"}]}) == [{"path": "b.yaml", "why": "y"}]
    assert gate.unread_rows({}) == []
    audit_shaped = {"findings": [], "unreadable": [{"path": "dir/b.yaml", "why": "y"}]}
    assert "dir/b.yaml" in report_html.render(audit_shaped)
    remarks = oscal.assessment_results(audit_shaped)["assessment-results"]["results"][0]["remarks"]
    assert "skipped: dir/b.yaml." in remarks


def test_the_page_names_the_file_it_says_was_not_read(unread: Path) -> None:
    """`File not read. <span class="mono"></span>: ...` -- no name, and the span on the page as text, because
    the limit's text is escaped by the loop that renders it."""
    page = report_html.render(_report(unread))
    limit = next(line for line in page.splitlines() if '<span class="kind">File not read.</span>' in line)
    assert f"{BROKEN}</code>: while parsing" in limit
    assert "&lt;span" not in limit


def test_the_assessment_results_name_the_file_they_say_was_skipped(unread: Path) -> None:
    """`gate --oscal` hands this a gate report: "1 input file(s) could not be read and were skipped: ?."."""
    remarks = oscal.assessment_results(_report(unread))["assessment-results"]["results"][0]["remarks"]
    assert "skipped: ?" not in remarks
    assert f"{BROKEN}. This assessment covers only the files that were read." in remarks


# -- G342: red team ----------------------------------------------------------------------------------------------


def _verdicts(text: str) -> dict[str, str]:
    return {s.scenario_id: s.verdict for s in analyze(text, "kubernetes", None).scenarios}


def test_a_scenario_whose_rules_all_ran_can_still_be_called_mitigated() -> None:
    """The control, first. On the same Deployment under `apps/v1` two rules of RT-NODE-CRASH and RT-ZONE-OUTAGE
    did not run because no PersistentVolumeClaim and no StorageClass is in the input. That is this input's scope:
    nothing was there to read. Counting it would leave no bundle on which red team can say `mitigated`."""
    report = analyze(PRIVILEGED, "kubernetes", None)
    assert "no PersistentVolumeClaim in the input" in report.not_evaluated["KN-ST002"]
    verdicts = {s.scenario_id: s.verdict for s in report.scenarios}
    assert verdicts["RT-ZONE-OUTAGE"] == "mitigated"
    assert verdicts["RT-SUPPLY-CHAIN"] == "mitigated"
    assert list(verdicts.values()).count("exposed") == 4


def test_an_input_with_no_pod_spec_still_has_no_scenario_about_pods() -> None:
    """The other control: a Service alone holds no pod spec, read or unread, so the scenarios about pods do not
    apply and are not shown as `undecided` either."""
    service = "apiVersion: v1\nkind: Service\nmetadata: {name: s, namespace: prod}\nspec: {ports: [{port: 80}]}\n"
    assert not {"RT-RESOURCE-STARVATION", "RT-SUPPLY-CHAIN", "RT-NODE-CRASH"} & set(_verdicts(service))


def test_no_scenario_is_mitigated_on_an_object_the_audit_refused() -> None:
    """The regression: RT-NODE-CRASH and RT-ZONE-OUTAGE answered `mitigated` with `evidence: []`."""
    report = analyze(REFUSED, "kubernetes", None)
    assert [r["object"] for r in report.not_audited] == ["Deployment/prod/web"]
    for s in report.scenarios:
        assert s.verdict == "undecided", f"{s.scenario_id} answers {s.verdict} for an object no rule read"
        assert s.evidence and "1 Deployment not audited" in s.evidence[-1], s.scenario_id


def test_refusing_an_object_does_not_remove_the_scenarios_it_was_exposed_to() -> None:
    """Six scenarios under `apps/v1`, three under `apps.k8s.io/v1`: the three that vanished are `exposed` or
    answered for the readable object, and were dropped because "no workload the rules could read" was read as
    "no workload"."""
    assert set(_verdicts(REFUSED)) == set(_verdicts(PRIVILEGED))


def test_the_tool_and_the_command_carry_the_same_answer(
    settings: Any, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The two hops a caller reaches this through: `Toolkit.red_team`, which is the `red_team` MCP tool, and
    `kube-noob redteam`."""
    out = Toolkit(settings).red_team(tk.ManifestsIn(manifests=REFUSED))
    assert "mitigated" not in [s["verdict"] for s in out["scenarios"]]
    assert len(out["scenarios"]) == 6
    path = tmp_path / "refused.yaml"
    path.write_text(REFUSED, encoding="utf-8")
    assert main(["redteam", "-f", str(path), "--format", "json"]) == 0
    printed = json.loads(capsys.readouterr().out)
    assert [s["verdict"] for s in printed["scenarios"]] == ["undecided"] * 6
