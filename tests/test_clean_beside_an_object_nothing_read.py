"""A clean object beside one nothing read, and two renderers that made an affirmative claim from the clean one.

Found by G360's fixtures, not by tripping over it. Once the audit reported a container the reader had not read,
`tests/test_renderer_conformance.py` held every renderer to that report, and two of them still presented it as
clean: OSCAL wrote `satisfied/pass` and `red_team` answered `mitigated`. Neither was losing a NEW reason. Both were
already wrong on 0.10.0, for every reason an object can go unaudited, on an input the matrix did not have:

    a hardened Pod, the NetworkPolicy for it, and a Tekton Task with a privileged `docker:24-dind` step
        gate:      incomplete
        OSCAL:     16 objectives `satisfied/pass`
        red_team:  RT-RESOURCE-STARVATION mitigated, RT-SUPPLY-CHAIN mitigated, both on `evidence: []`

Why the matrix missed it: every fixture that withheld an OBJECT held that object alone. With nothing else in the
input the rules have no subject, record "1 Deployment not audited (...)" as their reason, and both renderers read
that reason correctly. Put one readable object beside it and every rule has a subject, runs, and is clean about
the object it READ. The unread one is then in no rule's record: no rule declined, no subject was missing.

`clean` is a statement about what a rule read. `satisfied` and `mitigated` are statements about the input. The gap
between the two is the report's `notAudited` list, and these two renderers never read it. G343 made exactly this
argument for a FILE that could not be read; this is the same argument for an object.

The control comes first in each section: an emitter that can never say `satisfied`, or a red team that can never
say `mitigated`, is one nobody reads.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from kube_noob import gate, oscal
from kube_noob import toolkit as tk
from kube_noob.audit import engine
from kube_noob.toolkit import Toolkit

NETPOL = """\
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
CLEAN = {"pod.yaml": HARDENED_POD, "netpol.yaml": NETPOL}

#: A kind with no reader (G232, G333).
TEKTON = """\
apiVersion: tekton.dev/v1
kind: Task
metadata: {name: build, namespace: ci}
spec:
  steps:
  - name: build
    image: docker:24-dind
    securityContext: {privileged: true}
"""
#: A kind the rules know, under a group they refuse it in (G281).
REFUSED = """\
apiVersion: apps.k8s.io/v1
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
#: A kind with a reader, and a container where the reader does not look (G360).
MISPLACED = """\
apiVersion: apps.openshift.io/v1
kind: DeploymentConfig
metadata: {name: dc, namespace: prod}
spec:
  replicas: 2
  selector: {app: dc}
  template:
    metadata: {labels: {app: dc}}
    Spec:
      containers:
      - name: c
        image: registry.example.com/c:1
        securityContext: {privileged: true}
"""
#: An object that IS read, with a container whose image is not in the input at all (G252, G272).
OPERATOR_IMAGE = """\
apiVersion: serving.kserve.io/v1beta1
kind: InferenceService
metadata: {name: m, namespace: prod}
spec:
  predictor:
    model: {modelFormat: {name: sklearn}, storageUri: 'gs://bucket/model'}
"""

#: Every reason a `notAudited` row has. The defect was never about one of them: it is about the list.
UNAUDITED = [
    ("a kind with no reader", TEKTON, "Task/ci/build"),
    ("a refused apiVersion", REFUSED, "Deployment/prod/web"),
    ("a container the reader did not read", MISPLACED, "DeploymentConfig/prod/dc"),
    ("an image an operator supplies", OPERATOR_IMAGE, "InferenceService/prod/m"),
]
IDS = [u[0] for u in UNAUDITED]

EXCEPTION = """\
apiVersion: kube-noob.io/v1
kind: ExceptionList
exceptions:
  - id: EXC-TEKTON
    notAudited: {namespace: ci, kind: Task, name: build, apiGroup: tekton.dev}
    owner: team-ci
    reason: Tekton Tasks are reviewed by the pipeline team's own admission policy
    expires: 2027-11-01
"""


def _gate(tmp_path: Path, files: dict[str, str], exceptions: str | None = None) -> dict[str, Any]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (tmp_path / name).write_text(text, encoding="utf-8")
    return gate.run(gate.collect([str(tmp_path)], read=lambda _: ""), fail_on="never", exceptions=exceptions)


def _states(doc: dict[str, Any]) -> list[str]:
    result = doc["assessment-results"]["results"][0]
    return [f["target"]["status"]["state"] for f in result.get("findings") or []]


def _verdicts(text: str) -> dict[str, str]:
    return {s.scenario_id: s.verdict for s in engine.analyze(text).scenarios}


# -- OSCAL ---------------------------------------------------------------------------------------------------------


def test_a_fully_audited_input_still_reports_objectives_satisfied(tmp_path: Path) -> None:
    """The control. `satisfied` must stay reachable, or the document says nothing on every run (G335)."""
    report = _gate(tmp_path, CLEAN)
    assert report["notAudited"] == []
    assert _states(oscal.assessment_results(report)).count("satisfied") >= 10


@pytest.mark.parametrize(("name", "text", "ref"), UNAUDITED, ids=IDS)
def test_no_objective_is_satisfied_beside_an_object_nothing_read(
    name: str, text: str, ref: str, tmp_path: Path
) -> None:
    """The regression: sixteen `satisfied/pass` beside the Tekton Task, thirteen beside the refused Deployment.
    A GRC tool reads `status.state` and not the prose next to it (G335), so the state is what is asserted."""
    report = _gate(tmp_path, {**CLEAN, "other.yaml": text})
    assert ref in [r["object"] for r in report["notAudited"]], name
    assert gate.verdict_word(report) == "incomplete"
    doc = oscal.assessment_results(report)
    assert "satisfied" not in _states(doc), name


def test_no_objective_is_satisfied_beside_a_file_the_walk_did_not_read_as_a_manifest(tmp_path: Path) -> None:
    """Review class 21, the neighbour of G343. That fix counted a file that could not be PARSED; a file the walk
    skipped because its first key is `apiversion` is a file nothing was audited from by the same argument, the
    gate calls the run incomplete for it, and sixteen objectives read `satisfied/pass` beside it."""
    near_miss = TEKTON.replace("apiVersion:", "apiversion:")
    report = _gate(tmp_path, {**CLEAN, "near.yaml": near_miss})
    assert [s["file"] for s in report["skipped"] if s.get("forbidsVerdict")], report["skipped"]
    assert gate.verdict_word(report) == "incomplete"
    doc = oscal.assessment_results(report)
    assert "satisfied" not in _states(doc)
    assert "near.yaml" in doc["assessment-results"]["results"][0]["remarks"]


def test_a_file_that_is_simply_not_a_manifest_withholds_nothing(tmp_path: Path) -> None:
    """The control for the test above: a values file is read, understood, and holds no object. Every repository
    has one, and an emitter that withheld `satisfied` for it would never say the word (G325)."""
    report = _gate(tmp_path, {**CLEAN, "values.yaml": "replicaCount: 2\nimage: {tag: '1.0'}\n"})
    assert not [s for s in report["skipped"] if s.get("forbidsVerdict")]
    assert _states(oscal.assessment_results(report)).count("satisfied") >= 10


def test_the_document_names_the_object_and_says_why_the_controls_are_excluded(tmp_path: Path) -> None:
    """Review class 6. An exclusion listed as "12 clean, 0 not evaluated" with no reason beside it reads as a bug
    in the emitter. The reason is in the result's remarks and beside `exclude-controls`."""
    doc = oscal.assessment_results(_gate(tmp_path, {**CLEAN, "task.yaml": TEKTON}))
    result = doc["assessment-results"]["results"][0]
    assert "1 object(s) in the input were not audited: Task/ci/build (" in result["remarks"]
    selection = result["reviewed-controls"]["control-selections"][0]
    assert "1 object(s) in the input were not audited" in selection["remarks"]
    assert selection.get("exclude-controls"), "the controls were dropped rather than excluded"


def test_an_accepted_exception_gives_the_objectives_back(tmp_path: Path) -> None:
    """A `notAudited` exception is the caller saying "decide without that object", as `--skip-unreadable` says it
    of a file. The row stays listed, the gate's verdict is determined again, and so are the objectives: this
    emitter reads the same predicate the gate does (`open_not_audited`), not a list of its own (class 9)."""
    report = _gate(tmp_path, {**CLEAN, "task.yaml": TEKTON}, exceptions=EXCEPTION)
    assert [r.get("acceptedBy") for r in report["notAudited"]] == ["EXC-TEKTON"]
    assert gate.verdict_word(report) != "incomplete"
    assert "satisfied" in _states(oscal.assessment_results(report))


def test_a_finding_is_still_reported_beside_an_object_nothing_read(tmp_path: Path) -> None:
    """Withholding `satisfied` withholds nothing else: a control with a finding is `not-satisfied`, as before."""
    privileged = REFUSED.replace("apps.k8s.io/v1", "apps/v1")
    doc = oscal.assessment_results(_gate(tmp_path, {"d.yaml": privileged, "task.yaml": TEKTON}))
    states = _states(doc)
    assert "not-satisfied" in states
    assert "satisfied" not in states


# -- red team ------------------------------------------------------------------------------------------------------


def test_a_fully_audited_input_still_has_mitigated_scenarios() -> None:
    """The control: on the clean bundle the scenarios the rules ran clean for are `mitigated`."""
    verdicts = _verdicts(HARDENED_POD + "---\n" + NETPOL)
    assert "mitigated" in verdicts.values(), verdicts


@pytest.mark.parametrize(("name", "text", "ref"), UNAUDITED, ids=IDS)
def test_no_scenario_is_mitigated_beside_an_object_nothing_read(name: str, text: str, ref: str) -> None:
    """The regression: `RT-RESOURCE-STARVATION: mitigated` and `RT-SUPPLY-CHAIN: mitigated` on `evidence: []`
    beside a privileged Tekton step -- and `RT-SUPPLY-CHAIN: mitigated` for an InferenceService whose image is
    not in the input, which is a claim about the supply chain of an image nobody saw."""
    report = engine.analyze(HARDENED_POD + "---\n" + NETPOL + "---\n" + text)
    assert ref in [r["object"] for r in report.not_audited], name
    assert report.scenarios, name
    for s in report.scenarios:
        assert s.verdict != "mitigated", f"{name}: {s.scenario_id} is mitigated on {s.evidence}"
    undecided = [s for s in report.scenarios if s.verdict == "undecided"]
    assert undecided, name
    assert any(ref in e for s in undecided for e in s.evidence), "the scenario does not name the object"


def test_an_exposed_scenario_stays_exposed() -> None:
    """A finding is a finding. Only the affirmative claim is withdrawn."""
    privileged = REFUSED.replace("apps.k8s.io/v1", "apps/v1")
    before = _verdicts(privileged)
    after = _verdicts(privileged + "---\n" + TEKTON)
    exposed = {k for k, v in before.items() if v == "exposed"}
    assert exposed
    assert {k for k, v in after.items() if v == "exposed"} >= exposed


def test_the_mcp_tool_and_the_cli_answer_the_same(settings: Any, tmp_path: Path, capsys: Any) -> None:
    """Both read the audit's scenarios: one fix, two surfaces, and a test that they did not drift (class 25)."""
    from kube_noob.cli import main

    text = HARDENED_POD + "---\n" + NETPOL + "---\n" + TEKTON
    out = dict(Toolkit(settings).red_team(tk.ManifestsIn(manifests=text)))
    assert "mitigated" not in [s["verdict"] for s in out["scenarios"]]
    path = tmp_path / "m.yaml"
    path.write_text(text, encoding="utf-8")
    main(["--format", "json", "redteam", "-f", str(path)])
    printed = json.loads(capsys.readouterr().out)
    assert [s["verdict"] for s in printed["scenarios"]] == [s["verdict"] for s in out["scenarios"]]


def test_the_scenario_line_is_bounded() -> None:
    """Review class 2: a thousand unread objects are one bounded line per scenario, with the count stated."""
    many = "---\n".join(TEKTON.replace("name: build,", f"name: build-{i},") for i in range(40))
    report = engine.analyze(HARDENED_POD + "---\n" + NETPOL + "---\n" + many)
    lines = [e for s in report.scenarios for e in s.evidence if "were not audited" in e]
    assert lines
    for line in lines:
        assert line.startswith("40 object(s) in this input were not audited")
        assert "and 37 more" in line
        assert len(line) < 600
