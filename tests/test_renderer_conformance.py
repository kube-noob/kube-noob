"""One report, every renderer of it, and the same two questions asked of each.

Seven renderers of the same audit report were each found, separately, to drop the half of the answer that says
what was NOT evaluated. `audit --format sarif` put thirty-six coverage statements only in
`toolExecutionNotifications`, which GitHub code scanning does not read (G328). `verify`, `verify_change`,
`insight` and `scripts/ci/gate.sh` answered `allow` and exit 0 for everything the gate called incomplete (G329).
`sarif_of_gate` -- the file the Action uploads -- carried fourteen findings and no coverage result at all while
fifty-two rules reached no verdict, and zero results of any kind for a CRD-only input (G331). `posture_scan`,
`threat_model` and `fedramp_ksi` returned a zero for an object the audit had refused (G330). GitLab code quality
wrote `[]` for an undetermined gate, so the widget said "no issues" (G334). OSCAL reported three control
objectives `satisfied/pass` on a report the gate itself called undetermined (G335). And the admission webhook
admitted a privileged Tekton step with no warning at all (G337).

Each was found by tripping over it, and each fix taught one renderer one lesson. This file is the other approach:
the renderers are enumerated from the source, and the ones this product has are held to a predicate rather than
to a precedent.

The test that matters is not whether an output contains the word "undetermined". It is whether a downstream
consumer can reconstruct the same assessment meaning from every supported format. So each renderer has an adapter
with two functions, each written the way that renderer's REAL consumer reads it:

    carries_withheld   -- does this output state that part of the INPUT reached no verdict?
    presents_as_clean  -- would its real consumer conclude "nothing to see"?

and the conformance assertion is one line: on a report whose verdict is withheld, `carries_withheld` is true AND
`presents_as_clean` is false. `presents_as_clean` is the half that cannot be satisfied by adding a sentence
somewhere -- G328 and G335 both ended with the gap stated in prose a consumer does not parse, beside a field it
does (review class 6), and both would fail here on `presents_as_clean` alone.

A rule with no subject in the input ("no Service in the input") is NOT withheld evidence and is deliberately
outside both predicates: it is this report's scope. Counting it as a gap is what took a clean input from 23
satisfied objectives to 1 in G335's first attempt, and a renderer that reports a coverage gap on every run is one
every reader turns off.

`test_every_renderer_has_an_adapter` is the part that makes renderer EIGHT correct by construction: the renderer
functions and the manifest-taking MCP tools are read out of the source with `ast`, and a new one with no adapter
and no stated exemption fails. A conformance suite that silently skips the next renderer is the defect it exists
to prevent.

Putting the renderers side by side found three defects nobody had tripped over. They are recorded in
`KNOWN_DEFECTS` with the evidence, under G338, and each entry fails the day it is fixed.
"""

from __future__ import annotations

import ast
import contextlib
import io
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import pytest
import yaml

from kube_noob import admission, cli, gate, oscal, report_html
from kube_noob import toolkit as tk
from kube_noob.gate import NOT_AUDITED_RULE, NOT_EVALUATED_RULE, NOT_READ_RULE
from kube_noob.toolkit import Toolkit

#: Absolute, because `tests/conftest.py` chdirs into a tmp_path: a relative source path resolves to nothing.
ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "kube_noob"

#: The file every fixture that withholds a FILE withholds. Named once, because three tests assert a renderer
#: names it and two renderers currently do not.
BROKEN = "broken.yaml"


# -- the inputs ------------------------------------------------------------------------------------------------

#: A default-deny NetworkPolicy that still allows cluster DNS. In the clean bundle because without it KN-N001 or
#: KN-N013 fires, and a "clean" fixture with a finding in it proves nothing about a clean report.
_DNS_POLICY = """\
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

_HARDENED_POD = """\
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

#: A privileged container in a Deployment under the group the rules DO know it under: every rule that applies was
#: evaluated and fourteen of them fired. The control for everything below -- a renderer that says "withheld" here
#: is one that says it on every run.
_PRIVILEGED_DEPLOYMENT = """\
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

#: The same object under a group the API server would never serve `Deployment` under. `refusal` refuses it, so no
#: rule read the privileged container: zero findings, and `undetermined` as the reason. G330, G331, G334, G335 and
#: G337 were all first seen on this shape.
_REFUSED_DEPLOYMENT = _PRIVILEGED_DEPLOYMENT.replace("apps/v1", "apps.k8s.io/v1")

#: Bytes YAML will not parse. The file was never opened as a manifest, so nothing in it was audited and a clean
#: result over the rest of the input says nothing about it (G251, G325).
_UNPARSEABLE = "apiVersion: v1\nkind: Pod\nmetadata: {name: [unclosed\n"

#: A kind no rule reads, carrying a privileged `docker:24-dind` step -- a real privilege escalation in a shape
#: nobody modelled. This is the input G337 was found on.
_TEKTON_TASK = """\
apiVersion: tekton.dev/v1
kind: Task
metadata: {name: build, namespace: ci}
spec:
  steps:
  - name: build
    image: docker:24-dind
    securityContext: {privileged: true}
"""


@dataclass(frozen=True)
class Fixture:
    """One directory of input, and what putting every renderer over it proves.

    A directory and not a string, because two of the seven defects are about files: a file that could not be read
    and a file the directory walk declined to open are evidence the run does not have, and neither can be
    expressed as manifest text. `gate.collect` over a real directory is what the CI gate does, so the
    `unreadable` and `skipped` rows these fixtures produce are the rows the product produces.
    """

    name: str
    proves: str
    files: Mapping[str, str]
    #: True when this input must not be reported on with a verdict. Checked against the report itself in
    #: `test_every_fixture_has_the_shape_it_claims`, never taken on trust: a fixture that quietly stopped being
    #: withheld would turn every conformance assertion below into a vacuous pass, which is how three of the
    #: seven defects survived a green suite.
    withheld: bool
    #: True when what is withheld is a FILE rather than an object. A renderer handed manifest TEXT -- every MCP
    #: tool, and the admission webhook, which is sent one object -- cannot have a file it could not read, so
    #: those adapters have no input for this fixture rather than failing it.
    file_level: bool = False
    #: True when the input itself must be refused (exit 2) rather than reported on.
    refused: bool = False


FIXTURES: tuple[Fixture, ...] = (
    Fixture(
        name="fully-evaluated-and-clean",
        proves="A report with nothing withheld. The other direction: the conformance assertion is one-sided, so "
        "without this fixture a renderer that reported a gap on every run would conform.",
        files={"pod.yaml": _HARDENED_POD, "netpol.yaml": _DNS_POLICY},
        withheld=False,
    ),
    Fixture(
        name="findings-with-complete-evidence",
        proves="Fourteen findings and complete evidence. A renderer must distinguish this from the withheld "
        "fixtures below: exit 1 and exit 5 are not two answers to the same question.",
        files={"deployment.yaml": _PRIVILEGED_DEPLOYMENT},
        withheld=False,
    ),
    Fixture(
        name="object-the-audit-refused",
        proves="The shape G330, G331, G334, G335 and G337 were each found on: a privileged container in a "
        "Deployment under `apps.k8s.io/v1`, which no rule read. Zero findings, and the verdict withheld.",
        files={"deployment.yaml": _REFUSED_DEPLOYMENT},
        withheld=True,
    ),
    Fixture(
        name="unreadable-file",
        proves="A file nothing could be audited from, beside a readable one with findings. The findings are a "
        "floor, not a measurement, and a renderer that reports only them reports a number it cannot support.",
        files={"deployment.yaml": _PRIVILEGED_DEPLOYMENT, BROKEN: _UNPARSEABLE},
        withheld=True,
        file_level=True,
    ),
    Fixture(
        name="kind-no-rule-reads",
        proves="A Tekton Task with a privileged `docker:24-dind` step: a container in a field no pod-spec "
        "detector looked at. It used to reach every renderer in this file as a PASS -- gate `passed`, "
        "`incomplete: false`, zero findings, and the webhook admitting it with no warning -- and this fixture "
        "recorded that, with `withheld=False` and a test asserting the pass so the gap could not be mistaken "
        "for a renderer bug. G333 reads the step as the container it is, so the gate now withholds the verdict "
        "and every adapter in the registry is held to carrying it.",
        files={"task.yaml": _TEKTON_TASK},
        withheld=True,
    ),
    Fixture(
        name="zero-findings-and-incomplete-evidence",
        proves="The exact shape every one of the seven got wrong: nothing to report AND evidence missing. Every "
        "finding list in the report is empty, so a renderer that derives its output from findings alone emits "
        "the one output its consumer reads as a clean scan.",
        files={"pod.yaml": _HARDENED_POD, "netpol.yaml": _DNS_POLICY, BROKEN: _UNPARSEABLE},
        withheld=True,
        file_level=True,
    ),
    Fixture(
        name="empty-input",
        proves="Nothing to audit. The answer is a refusal (exit 2, config/usage), never a report: a clean report "
        "over no input is the same false pass as a clean report over an input nobody read.",
        files={"empty.yaml": "\n"},
        withheld=False,
        refused=True,
    ),
)

BY_NAME = {f.name: f for f in FIXTURES}
_READABLE = tuple(f.name for f in FIXTURES if not f.refused)


def _write(fixture: Fixture, root: Path) -> Path:
    for name, text in fixture.files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


# -- the reports each renderer consumes ------------------------------------------------------------------------


@dataclass(frozen=True)
class Bundle:
    """The reports one fixture produces, each built the way the command that writes it builds it."""

    fixture: Fixture
    root: Path
    gate_report: dict[str, Any]
    audit_report: dict[str, Any]
    manifests: str
    primary: dict[str, Any] | None  # the first object in the input: what the webhook would be sent
    settings: Any


def _bundle(fixture: Fixture, root: Path, settings: Any) -> Bundle:
    gate_report = gate.run(gate.collect([str(root)], read=lambda _: ""), fail_on="never")
    # `audit -f <dir>` reads each file on its own and attaches the ones it could not read, rather than
    # concatenating first: one unreadable file used to decide the outcome for every other file in the directory,
    # and said so against a line of the combined text rather than a path anyone could open (G251). `cli._dir_yaml`
    # is that read, so the audit report here is the one the command prints.
    ok, bad = cli._dir_yaml(root)
    manifests = "\n---\n".join(text for _, text in ok)
    audit_report = dict(Toolkit(settings).audit(tk.AuditIn(manifests=manifests)))
    if bad:
        audit_report["unreadable"] = bad
    docs = [d for d in yaml.safe_load_all(manifests) if isinstance(d, dict) and d.get("kind")]
    return Bundle(fixture, root, gate_report, audit_report, manifests, docs[0] if docs else None, settings)


def _withheld(report: dict[str, Any]) -> bool:
    """Whether this report has evidence it could not get.

    `gate.verdict_word` is THE predicate, and reading it rather than re-deriving it is the lesson of G329: `verify`
    kept a second list of what makes a report incomplete and answered `allow` the day the first list learned a new
    reason (review classes 9 and 21). There was one documented hole in it -- a file the run could not read did not
    make the verdict incomplete -- and this function carried an `unreadable` disjunct to cover it, with a test
    pinning the hole so the disjunct could not outlive it. G340 closed the hole in `gate` itself, so both are
    gone: one predicate, no local second opinion about what incomplete means.
    """
    return gate.verdict_word(report) == "incomplete"


# -- adapters: two questions per renderer, asked the way its real consumer asks them ---------------------------


@dataclass(frozen=True)
class Adapter:
    """How one renderer's output is read by the thing that actually reads it.

    `consumer` names that thing, because it is what decides both predicates: SARIF's consumer is GitHub code
    scanning, which reads `runs[].results` and not `toolExecutionNotifications` (G328); OSCAL's is a GRC tool,
    which reads `status.state` and not the prose beside it (G335).

    `reads` is what this renderer is given. `report` renderers are handed the whole report, so a file that could
    not be read is in their input; `manifests` and `object` renderers are handed text and have no such file to
    report, which is a gap in the surface and not a defect in the renderer.
    """

    consumer: str
    reads: Literal["report", "manifests", "object"]
    render: Callable[[Bundle], Any]
    carries_withheld: Callable[[Any], bool]
    presents_as_clean: Callable[[Any], bool]
    #: How this output names a file: used only by `test_a_file_that_was_not_read_is_named_by_the_renderers`.
    as_text: Callable[[Any], str] = field(default=lambda out: out if isinstance(out, str) else json.dumps(out))


#: The rule ids that say something about the INPUT reached no verdict. `NOT_EVALUATED_RULE` is deliberately not
#: here: it carries "these rules had no subject in the input", which is scope, and a renderer that raised it as a
#: withheld verdict would raise one on every run.
_WITHHELD_RULES = frozenset({NOT_AUDITED_RULE, NOT_READ_RULE, "kube-noob/undetermined"})
#: Every rule id that is not a finding, for `presents_as_clean`: a SARIF run of findings only is what a consumer
#: reads as "this is the complete list".
_NON_FINDING_RULES = _WITHHELD_RULES | {NOT_EVALUATED_RULE}

#: Phrases that state the input reached no verdict, for the renderers whose consumer is a person reading prose.
#: "not evaluated" and "reached no verdict" are absent on purpose, for the reason `_WITHHELD_RULES` gives.
_WITHHELD_PROSE = (
    "not audited",
    "not read",
    "undetermined",
    "not determined",
    "not fully audited",
)


def _says_withheld(text: str) -> bool:
    low = text.lower()
    return any(phrase in low for phrase in _WITHHELD_PROSE)


def _sarif_carries(doc: Any) -> bool:
    return any(r.get("ruleId") in _WITHHELD_RULES for r in doc["runs"][0]["results"])


def _sarif_clean(doc: Any) -> bool:
    """Empty, or findings only. The two ways a SARIF run says "this is everything there was to find"."""
    results = doc["runs"][0]["results"]
    return not results or all(r.get("ruleId") not in _NON_FINDING_RULES for r in results)


def _cq_carries(issues: Any) -> bool:
    return any(i.get("check_name") in _WITHHELD_RULES for i in issues)


def _cq_clean(issues: Any) -> bool:
    """`[]` is how GitLab's Code Quality widget spells "no issues" (G334), and so is a list of findings only."""
    return not issues or not any(i.get("check_name") in _NON_FINDING_RULES for i in issues)


def _markdown_clean(text: str) -> bool:
    """A reviewer skims the masthead. "gate passed" with no section saying what was withheld is a clean result."""
    return text.startswith("## kube-noob gate passed") and not _says_withheld(text)


def _html_carries(page: str) -> bool:
    """Section 1 is "Limits of this examination", but it is also where a rule with no subject is listed, so its
    presence alone is not the signal. These are the limit kinds that are about the input."""
    return (
        "undetermined" in page.lower()
        or '<span class="kind">File not read.</span>' in page
        or '<span class="kind">Nothing audited.</span>' in page
        or "resource(s) refused" in page
        or "resources refused" in page
    )


def _html_clean(page: str) -> bool:
    """A page with no such limit, whose masthead does not say anything reached no verdict, reads as complete."""
    return not _html_carries(page) and "reached no verdict" not in page


def _oscal_states(doc: Any) -> list[str]:
    out = []
    for result in doc["assessment-results"]["results"]:
        for finding in result.get("findings") or []:
            status = (finding.get("target") or {}).get("status") or {}
            out.append(f"{status.get('state')}/{status.get('reason')}")
    return out


def _oscal_carries(doc: Any) -> bool:
    result = doc["assessment-results"]["results"][0]
    return _says_withheld(json.dumps({k: v for k, v in result.items() if k != "findings"})) or "could not be read" in (
        result.get("remarks") or ""
    )


def _oscal_clean(doc: Any) -> bool:
    """`satisfied` is the strongest word this document says, so one of them is what a GRC tool reads as clean, and
    it reads `status.state` and never the description beside it (G335)."""
    return "satisfied/pass" in _oscal_states(doc)


def _review_warnings(response: Any) -> list[str]:
    return [str(w) for w in (response["response"].get("warnings") or [])]


def _admission_clean(response: Any) -> bool:
    """`allowed: true` with no warning is a blank response: `kubectl` prints nothing and the object goes in."""
    return bool(response["response"].get("allowed")) and not _review_warnings(response)


def _text_view(report: dict[str, Any]) -> str:
    """The audit's text view, as `audit --format text` prints it: `_print_report`, then the unreadable files,
    which the command prints on stderr so a partial audit does not look clean on either channel."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        cli._print_report(report)
        for bad in report.get("unreadable") or []:
            print(f"not read: {bad['path']} ({bad['why']})")
    return buf.getvalue()


def _text_clean(text: str) -> bool:
    """A numeric score on the headline and no line naming anything withheld. A number printed beside "was not
    evaluated in full" read as a verdict on what was not read (G272), so the score word is the signal."""
    return "score=not determined" not in text and not _says_withheld(text)


def _json_carries(report: Any) -> bool:
    summary = report.get("summary") or {}
    return bool(
        summary.get("verdict") == "undetermined"
        or report.get("notAudited")
        or report.get("unreadable")
        or report.get("declined")
    )


def _insight_carries(out: Any) -> bool:
    return any(_says_withheld(json.dumps(row)) for row in out.get("skipped") or [])


def _insight_clean(out: Any) -> bool:
    """`{"ran": ["audit"], "findings": [], "skipped": []}` is what a model reads as "audited, nothing found"
    (G329): `ran` beside an empty `findings` and nothing under `skipped`."""
    return "audit" in (out.get("ran") or []) and not out.get("findings") and not out.get("skipped")


def _posture_carries(out: Any) -> bool:
    return bool(out.get("notRead") or out.get("refused"))


def _posture_clean(out: Any) -> bool:
    """A workload count with an empty `notRead` and an empty `refused`: a model reading that tells the user the
    workloads were ranked and nothing was refused (G330)."""
    return not _posture_carries(out)


def _redteam_verdicts(out: Any) -> list[str]:
    return [str(s.get("verdict")) for s in out.get("scenarios") or []]


def _redteam_carries(out: Any) -> bool:
    """`assumptions`, which is where this answer carries the audit's reason. An `undecided` SCENARIO is not the
    signal: a scenario can honestly be undecided for want of its own input -- RT-SUPPLY-CHAIN is undecided with
    no SBOM on a clean bundle -- and reading that as a withheld verdict would make every run carry one."""
    return _says_withheld(json.dumps(out.get("assumptions") or []))


def _redteam_clean(out: Any) -> bool:
    """`mitigated` is an affirmative claim that the scenario is handled. One of them on an object no rule read is
    this product's own defect in a scenario verdict; `undecided` is the word for that case, and the same answer
    already uses it for other scenarios."""
    return "mitigated" in _redteam_verdicts(out)


def _ksi_carries(out: Any) -> bool:
    """The verdict has to be inside a client's truncation window, not at byte 54,945 of 55,269 (G330)."""
    return '"verdict"' in json.dumps(out)[:1024]


#: Every renderer of one report, and how its real consumer reads it. A name here is `<module>.<function>` or
#: `mcp.<tool name>`, which is what `test_every_renderer_has_an_adapter` reads out of the source.
ADAPTERS: dict[str, Adapter] = {
    "gate.sarif_of_audit": Adapter(
        "GitHub code scanning, reading the audit's SARIF",
        "report",
        lambda b: gate.sarif_of_audit(b.audit_report),
        _sarif_carries,
        _sarif_clean,
    ),
    "gate.sarif_of_gate": Adapter(
        "GitHub code scanning, reading the file the Action uploads",
        "report",
        lambda b: gate.sarif_of_gate(b.gate_report),
        _sarif_carries,
        _sarif_clean,
    ),
    "gate.codequality": Adapter(
        "GitLab's Code Quality widget",
        "report",
        lambda b: gate.codequality(b.gate_report),
        _cq_carries,
        _cq_clean,
    ),
    "gate.markdown": Adapter(
        "a reviewer reading the job summary or a merge request note",
        "report",
        lambda b: gate.markdown(b.gate_report),
        _says_withheld,
        _markdown_clean,
    ),
    "gate.github_annotations": Adapter(
        "a developer reading the pull request's annotations",
        "report",
        lambda b: "\n".join(gate.github_annotations(b.gate_report)),
        _says_withheld,
        lambda text: not text.strip(),
    ),
    "oscal.assessment_results": Adapter(
        "a GRC tool reading status.state",
        "report",
        lambda b: oscal.assessment_results(b.gate_report),
        _oscal_carries,
        _oscal_clean,
    ),
    "report_html.render": Adapter(
        "a reviewer or an auditor reading the self-contained page",
        "report",
        lambda b: report_html.render(b.gate_report),
        _html_carries,
        _html_clean,
    ),
    "cli.text": Adapter(
        "somebody reading the audit in a terminal",
        "report",
        lambda b: _text_view(b.audit_report),
        _says_withheld,
        _text_clean,
    ),
    "cli.json": Adapter(
        "a script reading the audit's JSON report",
        "report",
        lambda b: b.audit_report,
        _json_carries,
        lambda report: not _json_carries(report),
    ),
    "admission.review": Adapter(
        "the API server, and kubectl printing the response's warnings",
        "object",
        lambda b: admission.review(
            {
                "apiVersion": "admission.k8s.io/v1",
                "kind": "AdmissionReview",
                "request": {
                    "uid": "1",
                    "namespace": ((b.primary or {}).get("metadata") or {}).get("namespace") or "default",
                    "object": b.primary,
                },
            },
            admission.Config(),
        ),
        lambda response: any(_says_withheld(w) for w in _review_warnings(response)),
        _admission_clean,
    ),
    "mcp.audit_manifests": Adapter(
        "a model answering the user from the tool result",
        "manifests",
        lambda b: dict(Toolkit(b.settings).audit(tk.AuditIn(manifests=b.manifests))),
        _json_carries,
        lambda report: not _json_carries(report),
    ),
    "mcp.validate_manifests": Adapter(
        "a model answering the user from the tool result",
        "manifests",
        lambda b: dict(Toolkit(b.settings).validate(tk.ManifestsIn(manifests=b.manifests))),
        _json_carries,
        lambda report: not _json_carries(report),
    ),
    "mcp.verify_change": Adapter(
        "a coding agent deciding whether to run kubectl apply",
        "manifests",
        lambda b: dict(Toolkit(b.settings).verify_change(tk.VerifyIn(manifests=b.manifests, fail_on="never"))),
        lambda out: out["verdict"] == "not-determined",
        lambda out: out["verdict"] == "allow",
    ),
    "mcp.insight": Adapter(
        "a model, on the tool the server instructions say to start with",
        "manifests",
        lambda b: dict(Toolkit(b.settings).insight(tk.InsightIn(text=b.manifests))),
        _insight_carries,
        _insight_clean,
    ),
    "mcp.posture_scan": Adapter(
        "a model reporting a cluster's posture to the user",
        "manifests",
        lambda b: dict(Toolkit(b.settings).posture_scan(tk.PostureScanIn(manifests=b.manifests))),
        _posture_carries,
        _posture_clean,
    ),
    "mcp.threat_model": Adapter(
        "a model reporting the attack paths it found",
        "manifests",
        lambda b: dict(Toolkit(b.settings).threat_model(tk.ThreatModelIn(manifests=b.manifests))),
        _posture_carries,
        _posture_clean,
    ),
    "mcp.fedramp_ksi": Adapter(
        "a model, or an assessor, reading the KSI crosswalk",
        "manifests",
        lambda b: dict(Toolkit(b.settings).fedramp_ksi(tk.KsiIn(manifests=b.manifests))),
        _ksi_carries,
        lambda out: "verdict" not in out,
    ),
    "mcp.red_team": Adapter(
        "a model reporting which attack scenarios are handled",
        "manifests",
        lambda b: dict(Toolkit(b.settings).red_team(tk.ManifestsIn(manifests=b.manifests))),
        _redteam_carries,
        _redteam_clean,
    ),
}


#: A cell this suite asserts is WRONG today, with the evidence. The marker is `xfail(strict=True)` applied at
#: run time, not `pytest.xfail()`, deliberately: the imperative form short-circuits before the assertions and
#: would keep reporting xfail forever. Applied as a strict marker the assertions still run, so the day a defect
#: is fixed the cell passes, strict turns that into a failure, and the entry has to be deleted. A known defect
#: that quietly becomes a silent pass is how a suite stops being read.
#:
#: Four defects, all found by putting the renderers side by side rather than by tripping over one (G338):
#:
#: 1. `red_team` is the EIGHTH renderer of this report to lose the withheld half of the answer. On the refused
#:    Deployment it answers `RT-NODE-CRASH: mitigated` and `RT-ZONE-OUTAGE: mitigated`, both with `evidence: []`,
#:    while `RT-PRIVESC` in the same answer answers `undecided` and names the two rules that were not evaluated.
#:    The same object under `apps/v1` answers `exposed` for four scenarios -- so the refusal turned four
#:    exposures into silence and left two affirmative claims standing, on empty evidence, in the same answer
#:    where a third scenario demonstrates the word for that case. Review class 21.
#:
#: 2. The gate reports `passed` for a run in which a file could not be read. `incomplete` is
#:    `"undetermined" in coverage or bool(blocking)`, and `blocking` is `skipped` rows that forbid a verdict --
#:    `unreadable` rows are not in it. So `verdict_word` says "passed", `gate.markdown` writes
#:    "## kube-noob gate passed" and does not name the file, and `github_annotations` annotates nothing, while
#:    `unreadable_reason`'s own docstring says both are incomplete evidence. The exit code is right (the command
#:    returns 5), which is why nobody tripped over the report.
#:
#: 3. OSCAL reports control objectives `satisfied/pass` on a run with a file that was never read. The document
#:    says so in `remarks` -- "1 input file(s) could not be read and were skipped" -- which is prose a GRC tool
#:    does not parse while it reads `status.state`. That is G335 exactly: G335 taught this emitter that partial
#:    COVERAGE excludes a control, and an unreadable file is partial evidence by the same argument.
#:
#: 4. The HTML page and the OSCAL document lose the file's NAME. Both read `u["path"]` from the unreadable rows,
#:    and a GATE report's rows carry `file` -- the audit's carry `path`. The page prints "File not read." with an
#:    empty filename and the assessment-results remark says "1 input file(s) could not be read and were skipped:
#:    ?.". That is the key mismatch `test_gate_sarif_coverage.py::
#:    test_an_unreadable_file_keyed_on_file_rather_than_path_still_anchors` was written for, two renderers along.
#: Empty, and that is the point: every entry here was a defect with an expiry date, and G340-G343 are the
#: expiry. A strict xfail that starts passing fails, so this table could not be left behind -- which is the
#: one failure mode a conformance suite has that an ordinary suite does not.
KNOWN_DEFECTS: dict[tuple[str, str], str] = {}


# -- the suite -------------------------------------------------------------------------------------------------


@pytest.fixture
def bundles(tmp_path: Path, settings: Any) -> dict[str, Bundle]:
    """Every fixture's reports, built once. A refused input is absent: it has no report by definition."""
    return {fx.name: _bundle(fx, _write(fx, tmp_path / fx.name), settings) for fx in FIXTURES if not fx.refused}


def _applicable(renderer: str, fixture: Fixture) -> str:
    """Why this renderer has no input for this fixture, or an empty string."""
    if fixture.file_level and ADAPTERS[renderer].reads != "report":
        return (
            "what is withheld here is a FILE, and this renderer is handed manifest text or one object: it has no "
            "file it could not read to report"
        )
    return ""


@pytest.mark.parametrize("renderer", sorted(ADAPTERS))
@pytest.mark.parametrize("fixture", _READABLE)
def test_renderer_conformance(
    request: pytest.FixtureRequest, bundles: dict[str, Bundle], renderer: str, fixture: str
) -> None:
    """The one assertion, over every renderer for every fixture.

    On a report whose verdict is withheld, the output states so AND its consumer cannot read it as clean. Both
    halves: G328 and G335 each ended with the gap stated somewhere the consumer does not look, beside a field it
    does, so `carries_withheld` alone passes a renderer that is still wrong.
    """
    fx = BY_NAME[fixture]
    if why := _applicable(renderer, fx):
        pytest.skip(f"{renderer}: {why}")
    if defect := KNOWN_DEFECTS.get((renderer, fixture)):
        request.node.add_marker(pytest.mark.xfail(strict=True, reason=defect))
    if not fx.withheld:
        # One-sided by design. `test_a_complete_report_is_not_reported_as_withheld` holds the other direction.
        ADAPTERS[renderer].render(bundles[fixture])
        return
    adapter = ADAPTERS[renderer]
    output = adapter.render(bundles[fixture])
    assert adapter.carries_withheld(output), (
        f"{renderer}: the verdict is withheld and this output does not say so, so {adapter.consumer} cannot "
        "reconstruct that part of the input reached no verdict"
    )
    assert not adapter.presents_as_clean(output), (
        f"{renderer}: the verdict is withheld and {adapter.consumer} reads this output as clean"
    )


@pytest.mark.parametrize("renderer", sorted(ADAPTERS))
def test_a_complete_report_is_not_reported_as_withheld(bundles: dict[str, Bundle], renderer: str) -> None:
    """The other direction, on the fixture where nothing was withheld.

    A renderer that reported a coverage gap on every run would satisfy the assertion above and be useless: a
    warning on every output is one every reader turns off, which is the reason `audit --format sarif` says
    nothing on a run that evaluated everything, and the reason a rule whose subject is absent is outside both
    predicates here.
    """
    adapter = ADAPTERS[renderer]
    output = adapter.render(bundles["fully-evaluated-and-clean"])
    assert not adapter.carries_withheld(output), f"{renderer}: nothing was withheld and this output says it was"


@pytest.mark.parametrize("renderer", sorted(r for r, a in ADAPTERS.items() if a.reads == "report"))
@pytest.mark.parametrize("fixture", tuple(f.name for f in FIXTURES if f.file_level))
def test_a_file_that_was_not_read_is_named_by_the_renderers(
    request: pytest.FixtureRequest, bundles: dict[str, Bundle], renderer: str, fixture: str
) -> None:
    """Saying a file was not read without saying WHICH one is not an answer a reader can act on.

    `carries_withheld` is satisfied by a sentence; this is not. It is how the key mismatch in defect 3 above was
    found: the page and the assessment-results document both say a file could not be read, and neither says
    which, because they read `path` from rows that carry `file`.
    """
    if defect := KNOWN_DEFECTS.get((f"{renderer}:names", fixture)):
        request.node.add_marker(pytest.mark.xfail(strict=True, reason=defect))
    adapter = ADAPTERS[renderer]
    text = adapter.as_text(adapter.render(bundles[fixture]))
    assert BROKEN in text, f"{renderer}: the output does not name {BROKEN}, which nothing in it was audited from"


def test_every_fixture_has_the_shape_it_claims(bundles: dict[str, Bundle]) -> None:
    """Without this the suite is vacuous: a fixture that stopped being withheld would satisfy every assertion
    above by never reaching one, which is how three of the seven defects survived a green suite."""
    for name, bundle in bundles.items():
        assert _withheld(bundle.gate_report) == bundle.fixture.withheld, (
            f"{name}: the report says withheld={_withheld(bundle.gate_report)}, the fixture claims "
            f"{bundle.fixture.withheld}"
        )
    assert len([f for f in FIXTURES if f.withheld]) >= 3
    zero = bundles["zero-findings-and-incomplete-evidence"]
    assert not zero.gate_report["findings"], "the fixture that matters most has findings, so it proves less"
    assert not zero.audit_report["findings"]
    assert zero.gate_report["unreadable"], "nothing is withheld here, so this fixture proves nothing"
    refused = bundles["object-the-audit-refused"]
    assert not refused.gate_report["findings"], "the privileged container was read, so the fixture is not refused"
    assert [r["object"] for r in refused.gate_report["notAudited"]] == ["Deployment/prod/web"]


def test_the_empty_input_is_refused_rather_than_reported_clean(tmp_path: Path) -> None:
    """Exit 2, config/usage. A clean report over no input is the same false pass as a clean report over an input
    nobody read, and it is the one a caller is most likely to produce by accident."""
    fx = BY_NAME["empty-input"]
    root = _write(fx, tmp_path / fx.name)
    with pytest.raises(gate.GateError) as err:
        gate.run(gate.collect([str(root)], read=lambda _: ""), fail_on="never")
    assert "nothing to check" in str(err.value) or "Kubernetes manifest" in str(err.value)


def test_two_renderers_of_one_report_state_the_same_gap(bundles: dict[str, Bundle]) -> None:
    """Review class 9. Two renderers of one report must take their numbers from the same list, or a reviewer
    reading the SARIF and a reviewer reading the GitLab widget are told different things about the same run."""
    for name in (f.name for f in FIXTURES if f.withheld):
        report = bundles[name].gate_report
        in_sarif = {
            r["message"]["text"]
            for r in gate.sarif_of_gate(report)["runs"][0]["results"]
            if r["ruleId"] in _WITHHELD_RULES
        }
        in_widget = {i["description"] for i in gate.codequality(report) if i["check_name"] in _WITHHELD_RULES}
        assert bool(in_sarif) == bool(in_widget), f"{name}: one renderer states a gap the other does not"


# -- the guard: renderer eight cannot appear without an adapter ------------------------------------------------

#: A public function in a renderer module, or an MCP tool over manifests, that is not a renderer of an audit
#: verdict, and why. Every entry is a decision somebody made and can be argued with; the point is that it was
#: made, rather than the function being absent from both lists and so from this suite.
NOT_A_VERDICT_VIEW: dict[str, str] = {
    "gate.forbids_verdict": "a predicate over one skip reason, not an output",
    "gate.unreadable_reason": "a predicate over one file's bytes, not an output",
    "gate.not_opened_reason": "a predicate over one file a directory walk left alone, not an output (G351)",
    "gate.verdict_word": "THE predicate every renderer here reads; it has no output of its own",
    "gate.render": "renders a Helm chart to manifests; it runs before the audit and reports no verdict",
    "gate.collect": "reads files into Sources; it reports no verdict",
    "gate.run": "produces the report every adapter above consumes, so it is the subject, not a renderer",
    "gate.sarif": "the shared SARIF emitter; its two callers, sarif_of_audit and sarif_of_gate, are adapted",
    "gate.write": "writes the adapted renderers' output to disk and adds nothing to it",
    "oscal.control_id": "formats one control id",
    "oscal.objective_id": "formats one objective id",
    "oscal.check_import_ap": "validates a command-line argument",
    "admission.review_bytes": "parses the request body and delegates to review, which is adapted",
    "admission.excluded_namespace": "a predicate over one namespace name",
    "admission.app": "the ASGI application; the response it serves is review's, which is adapted",
    "admission.watch_certificate": "reloads the serving certificate",
    # The manifest-taking MCP tools that answer a different question. Each carries the audit's `assumptions`, but
    # none states a verdict over the input, so neither predicate has a meaning for it.
    "mcp.check_network_policy": "answers whether one source reaches one destination, not a verdict over the input",
    "mcp.posture_reach": "as check_network_policy: one source, one destination, one port",
    "mcp.code_report": "reads a SAST tool's SARIF, not the manifest audit",
    "mcp.containerfile_audit": "audits a Containerfile; the manifests say where the image runs",
    "mcp.vuln_report": "reads a scanner report; the manifests say which images are deployed",
    "mcp.compliance_results": "reads a must-gather's ComplianceCheckResults, not this audit",
    "mcp.operator_inventory": "lists the operators in the input",
    "mcp.operator_known_issues": "matches that inventory against the known-issue index",
    # `fix_manifests` is excluded from the two verdict predicates because it states no verdict -- but that is not
    # the same as owing nothing, and reading it that way cost a real defect. G344: the fixer rewrote any
    # `apiVersion` whose `kind` it recognised, so `projectcalico.org/v3 NetworkPolicy`,
    # `serving.knative.dev/v1 Service`, `batch.volcano.sh/v1alpha1 Job` and the Kubernetes documentation's own
    # `stable.example.com/v1 CronJob` came back as built-ins -- four valid manifests turned into broken ones,
    # and through `protocol` (where `apply_fixes` is the default) the broken core Service carried a new HIGH
    # finding of its own. The audit refuses every one of those objects. So the one writer in this matrix
    # contradicted the audit's verdict while sitting outside the matrix that exists to catch exactly that, and
    # an exclusion reason that stops at "not a verdict" is review class 6 one level out: the limit recorded
    # where no reader of this table sees it.
    # The invariant it DOES owe, held by tests/test_fixer_foreign_group.py: it must not edit an object the audit
    # refuses. Any future exclusion here states what the surface still owes, not only what it does not.
    "mcp.fix_manifests": (
        "states no verdict over the input, so neither predicate applies -- but it is the one surface here that "
        "WRITES, and a writer must not edit an object the audit refuses (G344); that invariant is held by "
        "tests/test_fixer_foreign_group.py, not by this matrix"
    ),
    "mcp.run_protocol": "composes validate, audit and red_team; each of those is adapted on its own",
}

#: Adapters for a surface this guard does not enumerate, and why it does not. The CLI's text and JSON views are
#: the two the `audit` command writes; the module has hundreds of print helpers and no one-renderer-per-function
#: shape to read, so these two are named rather than discovered. `mcp.insight` takes `text` rather than
#: `manifests`, so it is outside the mechanical rule below and is named too.
NAMED_NOT_ENUMERATED = frozenset({"cli.text", "cli.json", "mcp.insight"})


def _public_functions(module: str) -> set[str]:
    """Top-level public functions of one source file, read from the source rather than by importing it.

    `ast`, as `tests/test_tool_profiles.py` reads the tool names: a renderer added to the module is in the source
    whether or not anything imports it yet, and a guard that imported the module would also be satisfied by a
    renderer registered somewhere this file does not look.
    """
    tree = ast.parse((SRC / f"{module}.py").read_text(encoding="utf-8"))
    return {
        node.name
        for node in tree.body
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and not node.name.startswith("_")
    }


def _mcp_tools_over_manifests(settings: Any) -> set[str]:
    """Every MCP tool whose input carries `manifests`.

    Mechanical rather than a hand-written list: a new tool that takes manifests is a new renderer of this report
    and appears here on the day it is written, which is the one thing a hand-written list cannot do.
    """
    return {spec.name for spec in Toolkit(settings).specs() if "manifests" in getattr(spec.model, "model_fields", {})}


def test_every_renderer_has_an_adapter(settings: Any) -> None:
    """The reason this file exists rather than an eighth one-renderer test.

    A renderer with no adapter and no stated exemption fails here. It is the only test in the suite that fails
    for something that has not happened yet, and the only one that would have caught renderers two through seven
    before they shipped.
    """
    found = {
        f"{mod}.{name}" for mod in ("gate", "oscal", "admission", "report_html") for name in _public_functions(mod)
    }
    found |= {f"mcp.{name}" for name in _mcp_tools_over_manifests(settings)}
    classified = set(ADAPTERS) | set(NOT_A_VERDICT_VIEW)
    missing = sorted(found - classified)
    assert not missing, (
        "a renderer with no adapter and no stated exemption: add it to ADAPTERS with the two predicates its real "
        f"consumer reads, or to NOT_A_VERDICT_VIEW with the reason it states no verdict -- {missing}"
    )
    # The other direction: an adapter or an exemption for something that is no longer in the source is a stale
    # decision, and a registry nobody prunes is one nobody trusts.
    stale = sorted(classified - found - NAMED_NOT_ENUMERATED)
    assert not stale, f"classified but no longer in the source: {stale}"


def test_the_adapters_cover_the_renderers_the_seven_defects_were_found_in() -> None:
    """Named one by one, so a refactor that drops an adapter is a failure rather than a smaller matrix."""
    for name in (
        "gate.sarif_of_audit",  # G328
        "gate.sarif_of_gate",  # G331
        "gate.codequality",  # G334
        "oscal.assessment_results",  # G335
        "admission.review",  # G337
        "mcp.verify_change",  # G329
        "mcp.insight",  # G329
        "mcp.posture_scan",  # G330
        "mcp.threat_model",  # G330
        "mcp.fedramp_ksi",  # G330
    ):
        assert name in ADAPTERS, f"{name} lost its adapter"
    assert len(ADAPTERS) >= 18
    assert len(FIXTURES) >= 7
