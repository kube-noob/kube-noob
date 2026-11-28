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

The matrix had a blind spot of its own, and it cost two false passes (G363): every fixture that withheld an OBJECT
held that object alone. With one object and no reader for it, no rule has a subject, every rule says so, and a
renderer cannot go wrong. The mixed fixtures below (G364) are the other shape -- clean objects that give every
rule a subject, beside one object nothing read -- in each position and combination a renderer could treat
differently: the unread object first, last, and in the middle of one file; a refused object of the kind the
passing rules read; a refused object that is the only subject a rule could have had; an accepted
`--skip-unreadable` file beside a refusal nobody accepted; and a kind with no reader beside a kind whose reader
missed a container.

What these two predicates do NOT hold, and it is stated here so nobody reads a green matrix as more than it is:
they ask whether an output SAYS part of the input reached no verdict. They do not ask whether a figure in the same
output was computed over a denominator that excludes it -- `clean: 12` on a control, "42 rules evaluated", an
indicator's `clean` count, a snapshot's `evaluatedRules`. On every mixed fixture here those figures are
byte-identical to the clean fixture's. `docs/report-ir.md` records the measurement and why the fix is one
coverage ledger the renderers project, not a ninth and tenth patch to a renderer.

`drift` is the one renderer here that is a DELTA over two snapshots rather than a projection of one report, and
it was outside this matrix while the worst measured lie of the series happened in it (G366). `_drift_pair`
states what "the same fixture" means for a delta and why; `_drift_clean` states the one place the predicates
above do not translate as written and the smallest honest translation of them, because `verdict` is set from the
`notAudited` rows whether or not the join that stops a lost finding reading as `fixed` exists (G374).
"""

from __future__ import annotations

import ast
import contextlib
import copy
import datetime as dt
import io
import json
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import pytest
import yaml

from kube_noob import admission, cli, drift, gate, oscal, report_html
from kube_noob import toolkit as tk
from kube_noob.audit.model import SKIP_UNREADABLE
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

#: A kind kube-noob DOES read, with its containers one capital letter away from where the reader looks:
#: `template.Spec`. The reader finds no pod spec, so no pod-level rule runs and nothing fires on the privileged
#: container. Until G360 the detector returned nothing for a registered kind by its name, and this scored 92.0,
#: gated `passed` and verified `allow`. (An API server prunes or rejects `Spec`, so nothing here would run as
#: written; what was wrong was the stated score.)
_DC_CAPITAL_SPEC = """\
apiVersion: apps.openshift.io/v1
kind: DeploymentConfig
metadata: {name: web, namespace: prod}
spec:
  replicas: 1
  selector: {app: web}
  template:
    metadata: {labels: {app: web}}
    Spec:
      containers:
      - name: web
        image: registry.example.com/web:1
        securityContext: {privileged: true}
"""

#: The other half of the same defect, and the one a per-pod-spec fix would have missed: the reader DID read this
#: object -- `predictor` is audited and produces findings -- and a second container sits under `explainer.alibi`,
#: a key the reader does not read inside a pod spec it does. Findings AND a withheld verdict in one object.
_ISVC_UNREAD_EXPLAINER = """\
apiVersion: serving.kserve.io/v1beta1
kind: InferenceService
metadata: {name: model, namespace: prod}
spec:
  predictor:
    containers:
    - name: kserve-container
      image: registry.example.com/model:1
  explainer:
    alibi:
      image: registry.example.com/alibi:1
      securityContext: {privileged: true}
"""

#: The hardened Pod's own kind under a group the API server does not serve it under. A rule that passes on
#: `Pod/prod/ok` beside it has this kind as its subject and never read this object.
_REFUSED_POD = """\
apiVersion: core.k8s.io/v1
kind: Pod
metadata: {name: debug, namespace: prod}
spec:
  hostPID: true
  containers:
  - name: debug
    image: registry.example.com/debug:1
    securityContext: {privileged: true}
"""

#: The only Service in its input, refused. Every rule whose subject is a Service found nothing because the one
#: object it could have judged is the one it did not read -- which is not "no Service in the input".
_REFUSED_SERVICE = """\
apiVersion: core.k8s.io/v1
kind: Service
metadata: {name: edge, namespace: prod}
spec:
  type: LoadBalancer
  selector: {app: ok}
  ports: [{port: 80, targetPort: 8080}]
"""

#: The same for RBAC, and kept as its own fixture because `posture_scan` files it differently: a refused
#: workload goes under `refused`, a refused binding only under `notRead`.
_REFUSED_BINDING = """\
apiVersion: rbac.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: everyone-admin}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: cluster-admin}
subjects: [{kind: Group, name: "system:authenticated", apiGroup: rbac.authorization.k8s.io}]
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
    #: True when the run is made with `--skip-unreadable`: the caller accepted the files that could not be read,
    #: so those rows are listed with `acceptedBy` and withhold nothing. Whatever ELSE the input withholds still
    #: does, which is the whole point of the one fixture that sets it.
    skip_unreadable: bool = False
    #: Symbolic links to make under the fixture's root, name -> target. A target that leaves the root is written
    #: from `outside`, beside the root, so a fixture can hold the one entry type a directory walk never descends.
    links: Mapping[str, str] = field(default_factory=dict)
    outside: Mapping[str, str] = field(default_factory=dict)
    #: The entry a file-level fixture withholds, which every renderer of a report must NAME.
    names: str = BROKEN


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
        name="link-to-a-directory-the-walk-does-not-follow",
        proves="A clean bundle beside `base -> ../outside`, which holds a privileged Deployment. No walk follows "
        "a link out of the directory it was given, and until G444 none of them said so: zero findings, score "
        "100.0, `passed`, `satisfied`. The entry withheld is neither a file that would not parse nor an object "
        "nothing read, so no fixture above reaches a renderer with it.",
        files={"pod.yaml": _HARDENED_POD, "netpol.yaml": _DNS_POLICY},
        links={"base": "{outside}"},
        outside={"deployment.yaml": _PRIVILEGED_DEPLOYMENT},
        withheld=True,
        file_level=True,
        names="base",
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
        name="reader-kind-whose-pod-spec-went-unread",
        proves="A DeploymentConfig with its containers under `template.Spec`. The kind has a reader, the reader "
        "found no pod spec, and the detector that reports an unread container used to return nothing for a "
        "registered kind without looking. Every renderer got a report with a score in it and no row saying a "
        "container went unread, so every one of them was right about a report that was wrong (G360).",
        files={"dc.yaml": _DC_CAPITAL_SPEC},
        withheld=True,
    ),
    Fixture(
        name="read-object-with-an-unread-container",
        proves="An InferenceService whose `predictor` is audited and whose `explainer.alibi` is not: findings and "
        'a withheld verdict about ONE object. A renderer that treats `notAudited` as "this object produced '
        'nothing" and one that drops the row because the object has findings both fail here and on no other '
        "fixture (G360).",
        files={"isvc.yaml": _ISVC_UNREAD_EXPLAINER},
        withheld=True,
    ),
    Fixture(
        name="clean-objects-beside-one-nothing-read",
        proves="The fixture this matrix did not have, and the reason two renderers passed it while wrong: every "
        "withheld OBJECT above is alone in its input, so the rules had no subject and said so. Here a hardened "
        "Pod gives every pod rule a subject, each runs clean on it, and the privileged Tekton step beside it is "
        "in no rule's record. On 0.10.0 OSCAL reported sixteen objectives `satisfied/pass` and `red_team` "
        "answered `RT-RESOURCE-STARVATION: mitigated` and `RT-SUPPLY-CHAIN: mitigated` on this input, in a run "
        "the gate called incomplete (G363). The Task's file sorts first on purpose: the webhook adapter is sent "
        "the first object, and a renderer handed only the clean Pod has nothing withheld to report.",
        files={"a-task.yaml": _TEKTON_TASK, "pod.yaml": _HARDENED_POD, "netpol.yaml": _DNS_POLICY},
        withheld=True,
    ),
    Fixture(
        name="mixed-unread-object-last",
        proves="The same three objects with the Task's file sorting LAST. Position must not matter and once did "
        "for the webhook adapter, which was sent only the first object in the input: handed the clean "
        "NetworkPolicy it had nothing withheld to report. The adapter is now sent every object, as an API server "
        "sends them (G364).",
        files={"netpol.yaml": _DNS_POLICY, "pod.yaml": _HARDENED_POD, "z-task.yaml": _TEKTON_TASK},
        withheld=True,
    ),
    Fixture(
        name="mixed-unread-object-in-the-middle-of-one-file",
        proves="One file, three documents, the unread one between two clean ones. A renderer that reports per "
        "FILE has one file here and it was read; what is withheld is a document inside it, at a line that is "
        "neither the file's first nor its last.",
        files={"all.yaml": f"{_HARDENED_POD}---\n{_TEKTON_TASK}---\n{_DNS_POLICY}"},
        withheld=True,
    ),
    Fixture(
        name="mixed-refused-object-of-the-kind-the-passing-rules-read",
        proves="A hardened Pod and a privileged, hostPID Pod under `core.k8s.io/v1`. Every pod rule passes -- on "
        "the Pod it read -- and its subject kind is exactly the kind of the object it did not read. No rule is "
        "'not evaluated' here for want of a subject, so a renderer that looks for the gap in the rules' own "
        "reasons finds none.",
        files={"pod.yaml": _HARDENED_POD, "netpol.yaml": _DNS_POLICY, "refused-pod.yaml": _REFUSED_POD},
        withheld=True,
    ),
    Fixture(
        name="mixed-the-only-subject-of-a-rule-was-refused",
        proves="A LoadBalancer Service under `core.k8s.io/v1`, the only Service in the input, beside the clean "
        "Pod. The Service rules found nothing because the one object they could have judged was not read: "
        "their reason must be the refusal, never 'no Service in the input' (class 24).",
        files={"pod.yaml": _HARDENED_POD, "netpol.yaml": _DNS_POLICY, "service.yaml": _REFUSED_SERVICE},
        withheld=True,
    ),
    Fixture(
        name="mixed-the-only-binding-was-refused",
        proves="`cluster-admin` for `system:authenticated` in a ClusterRoleBinding under `rbac.k8s.io/v1`, beside "
        "the clean Pod. The RBAC rules' only subject, refused; and the one refusal `posture_scan` lists under "
        "`notRead` alone, where it lists a refused workload under `refused` as well.",
        files={"pod.yaml": _HARDENED_POD, "netpol.yaml": _DNS_POLICY, "binding.yaml": _REFUSED_BINDING},
        withheld=True,
    ),
    Fixture(
        name="mixed-accepted-unreadable-file-beside-a-refusal-nobody-accepted",
        proves="`--skip-unreadable` accepts the file that could not be parsed; nothing accepts the refused "
        "Deployment beside it. One waiver must not be read as two: a renderer that sees `acceptedBy` on the "
        "unreadable row and concludes the run's gaps were accepted reports clean over a privileged container "
        "no rule read.",
        files={
            "pod.yaml": _HARDENED_POD,
            "netpol.yaml": _DNS_POLICY,
            "deployment.yaml": _REFUSED_DEPLOYMENT,
            BROKEN: _UNPARSEABLE,
        },
        withheld=True,
        skip_unreadable=True,
    ),
    Fixture(
        name="mixed-no-reader-kind-beside-a-reader-that-missed-a-container",
        proves="Both of G360's and G333's shapes in one input, beside the clean Pod: a Tekton Task (no reader) "
        "and a DeploymentConfig with its containers under `template.Spec` (a reader that found no pod spec, and "
        "findings on the rest of the object). Two rows of two different reasons, findings, and a withheld "
        "verdict at once: a renderer that names the first row and stops, or that drops the rows because there "
        "are findings to show, fails here.",
        files={
            "a-task.yaml": _TEKTON_TASK,
            "dc.yaml": _DC_CAPITAL_SPEC,
            "pod.yaml": _HARDENED_POD,
            "netpol.yaml": _DNS_POLICY,
        },
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
    for name, text in fixture.outside.items():
        path = root.parent / f"{root.name}-outside" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    for name, target in fixture.links.items():
        (root / name).symlink_to(target.format(outside=f"../{root.name}-outside"))
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
    #: Every object in the input, in order: what the webhook is sent, one request each. It was the FIRST object
    #: only, which made the webhook's conformance depend on which file sorted first (G364).
    objects: list[dict[str, Any]]
    settings: Any


def _bundle(fixture: Fixture, root: Path, settings: Any) -> Bundle:
    gate_report = gate.run(
        gate.collect([str(root)], read=lambda _: ""), fail_on="never", skip_unreadable=fixture.skip_unreadable
    )
    # `audit -f <dir>` reads each file on its own and attaches the ones it could not read, rather than
    # concatenating first: one unreadable file used to decide the outcome for every other file in the directory,
    # and said so against a line of the combined text rather than a path anyone could open (G251). `cli._dir_yaml`
    # is that read, so the audit report here is the one the command prints.
    ok, bad = cli._dir_yaml(root)
    manifests = "\n---\n".join(text for _, text in ok)
    audit_report = dict(Toolkit(settings).audit(tk.AuditIn(manifests=manifests)))
    if bad:
        # As `audit --skip-unreadable` records them (`cli._audit`): the waiver is on the row, so every reader of
        # the report sees who accepted the gap, and `open_unread` is the one place that decides it withholds none.
        accepted = {"acceptedBy": SKIP_UNREADABLE} if fixture.skip_unreadable else {}
        audit_report["unreadable"] = [{**u, **accepted} for u in bad]
    docs = [d for d in yaml.safe_load_all(manifests) if isinstance(d, dict) and d.get("kind")]
    return Bundle(fixture, root, gate_report, audit_report, manifests, docs, settings)


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
    not be read is in their input; `manifests`, `object` and `snapshots` renderers are handed text, one object or
    two snapshots of objects, and have no such file to report, which is a gap in the surface and not a defect in
    the renderer.
    """

    consumer: str
    reads: Literal["report", "manifests", "object", "snapshots"]
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


def _review(obj: dict[str, Any]) -> Any:
    """The webhook's answer for one object, as `admission.review` gives it to the API server."""
    return admission.review(
        {
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "request": {
                "uid": "1",
                "namespace": (obj.get("metadata") or {}).get("namespace") or "default",
                "object": obj,
            },
        },
        admission.Config(),
    )


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
def _receipt(b: Bundle, command: str) -> Any:
    """The receipt `audit --receipt` or `gate --receipt` writes for this fixture, through the real command.

    Through `cli.main` and not through `receipt.build`, because the fields this adapter reads are filled in by the
    command (`_write_audit_receipt`, `_write_gate_receipt`), and that is where they went wrong: the receipt read
    `summary.scoreWithheld` after G281 retired the name, and recorded exit 1 and the word `failed` for a gate
    that exited 5 and said `incomplete` (G359). Written BESIDE the fixture directory, never inside it: a JSON
    file in the directory being audited is a file the walk has to account for.

    `audit` refuses a directory holding a file it could not read and writes no receipt (exit 5). That refusal is
    this renderer's whole output for such an input, so it is returned as one -- with the stderr that names the
    file -- rather than skipped: "no receipt exists" must not be confused with "a receipt that says clean".
    """
    target = b.root.parent / f"{b.fixture.name}.{command}.receipt.json"
    target.unlink(missing_ok=True)
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main([command, "-f", str(b.root), "--fail-on", "never", "--receipt", str(target)])
    if not target.exists():
        return {"refused": {"exitCode": code, "stderr": err.getvalue()}}
    return json.loads(target.read_text(encoding="utf-8"))


def _receipt_carries(doc: Any) -> bool:
    """`payload.verdict.undetermined`: the reason there is no verdict, in the block `receipt verify` compares and a
    third party reads. Not the scope lists beside it -- a reason that exists only in `scope` while the verdict
    block says exit 0 is the caveat-beside-the-field shape of G328 and G335."""
    if "refused" in doc:
        return doc["refused"]["exitCode"] == 5
    return bool(doc["payload"]["verdict"]["undetermined"])


def _receipt_clean(doc: Any) -> bool:
    """Exit 0 recorded and no reason beside it: what a reader of the verdict block takes for a pass."""
    if "refused" in doc:
        return False
    verdict = doc["payload"]["verdict"]
    return verdict["exitCode"] == 0 and not verdict["undetermined"]


#: The groups the refused fixtures above put a kind under, mapped back to the one an API server serves it
#: under. The fixtures were BUILT by that substitution (`_REFUSED_DEPLOYMENT = _PRIVILEGED_DEPLOYMENT.replace(
#: "apps/v1", "apps.k8s.io/v1")`), so undoing it is how "the same object, back when the rules still read it" is
#: spelled.
_SERVED_GROUP = {
    "apps.k8s.io/v1": "apps/v1",
    "core.k8s.io/v1": "v1",
    "rbac.k8s.io/v1": "rbac.authorization.k8s.io/v1",
}
_DAY_ONE = dt.datetime(2026, 11, 1, tzinfo=dt.UTC)
_DAY_TWO = dt.datetime(2026, 11, 2, tzinfo=dt.UTC)
#: Per fixture, not per cell. Four adapters read the same pair and `bundles` is function-scoped, so without this
#: the matrix would run two full audits per cell for each of them. `taken_at` is explicit and `snapshot` is
#: deterministic over the same objects, which is what makes the cache a cache and not a second answer.
_DRIFT_PAIRS: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {}
_DRIFT_HISTORIES: dict[str, Any] = {}


def _drift_snapshot(objects: list[dict[str, Any]], when: dt.datetime) -> dict[str, Any]:
    """One `posture snapshot` of these objects, as `cli._snapshot_from_args` takes it from `-f`."""
    return drift.snapshot(objects, source="manifests", platform="kubernetes", taken_at=when)


def _drift_pair(b: Bundle) -> tuple[dict[str, Any], dict[str, Any]]:
    """The two snapshots `posture diff` is handed for this fixture -- and what "the same fixture" means here.

    `drift` is the one renderer in this file that is a DELTA over two snapshots rather than a projection of one
    report, so the matrix's "one fixture, one input" has to be given a meaning rather than assumed. Three
    readings were weighed:

    1. `old` readable, `new` withheld -- the evidence disappears;
    2. `old` withheld, `new` readable -- the evidence appears;
    3. both withheld -- nothing moved, and coverage is incomplete throughout.

    (3) translates to every fixture uniformly and holds nothing: with identical snapshots no finding and no
    object moves, so the one guard a delta has -- `_unreadable`, G366's join -- never runs, and an adapter built
    on it passes with that join deleted. (2) is the same for the same reason. (1) is the only pairing in which
    the report has something to LOSE, and the loss is the measured lie: 15 findings reported `fixed`, the
    critical KN-S001 among them, from a one-line `apps/v1` -> `apps.k8s.io/v1` change.

    So `new` is always the fixture exactly as the matrix holds it, and `old` is the state that same input was in
    when the rules still read the object it now withholds. Where the withholding is a GROUP the rules refuse,
    that state is the same object under the group an API server serves it under. Where nothing could ever have
    read it -- a Tekton `Task` has no reader, a `DeploymentConfig` with its containers under `template.Spec` has
    no pod spec to find, an `InferenceService`'s `explainer.alibi` is a field the reader does not read inside a
    pod spec it does -- there is no such state, and the object is absent from `old` instead, so the fixture
    still conforms on the half that is about saying so. One rule, two shapes, and what makes the object
    unreadable decides which -- never the fixture's name, so a fixture added later gets its pairing too.
    """
    if b.fixture.name not in _DRIFT_PAIRS:
        new = _drift_snapshot(b.objects, _DAY_TWO)
        unread = _drift_unread({"notAudited": (new.get("coverage") or {}).get("notAudited") or []})
        before: list[dict[str, Any]] = []
        for obj in b.objects:
            if _label(obj) not in unread:
                before.append(obj)
            elif (served := _SERVED_GROUP.get(str(obj.get("apiVersion")))) is not None:
                before.append({**copy.deepcopy(obj), "apiVersion": served})
        _DRIFT_PAIRS[b.fixture.name] = (_drift_snapshot(before, _DAY_ONE), new)
    return _DRIFT_PAIRS[b.fixture.name]


def _drift_history(b: Bundle) -> Any:
    """The trend `posture report` attaches to what it renders, through the daily job run twice.

    `write_report` is the job: it diffs the snapshot against the newest one kept and writes both the report and
    the snapshot, so writing `old` and then `new` is the folder a trend is read out of. Written under a temp
    directory of its own rather than beside the fixture, for the reason `_receipt` gives: a JSON file in the
    directory being audited is a file the walk has to account for.
    """
    if b.fixture.name not in _DRIFT_HISTORIES:
        old, new = _drift_pair(b)
        state = Path(tempfile.mkdtemp(prefix="g374-")) / "posture"
        drift.write_report(state, old)
        drift.write_report(state, new)
        _DRIFT_HISTORIES[b.fixture.name] = drift.history(state)
    return _DRIFT_HISTORIES[b.fixture.name]


def _drift_unread(report: Mapping[str, Any]) -> set[str]:
    """The objects a drift report says the new snapshot did not read, named as its own rows name them.

    From the report and nothing else, because that is all a consumer has. The join G366 is about is one a reader
    of this document CAN do -- `notAudited` carries `Kind/namespace/name` and a finding's `resource` uses the
    same shape -- and the point is that `diff` must do it for them rather than publish both lists unjoined.
    """
    return {str(r.get("object")) for r in report.get("notAudited") or () if isinstance(r, dict) and r.get("object")}


def _drift_repairs_about_an_unread_object(report: Mapping[str, Any]) -> set[str]:
    """The rows that claim good news about an object this same report says nothing read.

    `fixed` and `removed` are the delta's two affirmative claims. "KN-S001 fixed on Deployment/prod/web" is read
    as "there is nothing to see about that object any more", which is `presents_as_clean` asked of a row instead
    of a document -- the same question, at the granularity a delta answers it.
    """
    unread = _drift_unread(report)
    claimed = {str(f.get("resource")) for f in report["findings"].get("fixed") or ()}
    claimed |= {str(k) for k in report["objects"].get("removed") or ()}
    return claimed & unread


def _drift_carries(report: Mapping[str, Any]) -> bool:
    """`assumptions` is deliberately not here: every run with no `--version` carries one, so reading it would
    make this renderer report a gap on every report it writes."""
    return bool(
        report.get("verdict") == "undetermined"
        or report.get("notAudited")
        or report.get("notRead")
        or report["findings"].get("undetermined")
        or report["objects"].get("undetermined")
    )


def _drift_clean(report: Mapping[str, Any]) -> bool:
    """Where the matrix's predicate does NOT translate as written, and the smallest honest translation.

    `presents_as_clean` asks whether the consumer reads the whole output as "nothing to see". For a delta that
    question is answered by `verdict`, and `diff` sets `verdict: undetermined` from the unaccepted `notAudited`
    rows whether or not G366's `_unreadable` join exists -- so the predicate as written passes a `diff` that
    reports the critical finding as `fixed`, which is coverage that holds nothing. The second disjunct is the
    translation: a row claiming a repair the evidence cannot support is the consumer concluding "nothing to see"
    about that object. Measured with the join reverted, on this matrix's fixtures, in the G374 guidance row.
    """
    return not _drift_carries(report) or bool(_drift_repairs_about_an_unread_object(report))


def _drift_markdown_clean(text: str) -> bool:
    """What an operator reads of the daily report: the headline, and the "N fixed" count in the summary line.

    A `## Fixed findings` table is the prose form of the same affirmative claim `_drift_clean`'s second disjunct
    reads from the JSON. The text cannot do the join itself, and it does not have to: on every withheld fixture
    here the only finding that can leave is one whose object stopped being read, which
    `test_the_delta_never_reports_a_repair_about_an_object_the_new_snapshot_did_not_read` asserts rather than
    leaves to the reader of this docstring.
    """
    return not _says_withheld(text) or "## Fixed findings" in text


def _drift_trend_point(hist: Any) -> dict[str, Any]:
    """The newest point: where a reader of a trend looks for "and today?"."""
    points = [p for p in hist.get("points") or () if isinstance(p, dict)]
    return points[-1] if points else {}


def _trend_carries(hist: Any) -> bool:
    """`complete is not True` covers both `False` (something was not read) and `None` (whether anything was is
    not known), which are two answers and neither of them is "yes"."""
    return _drift_trend_point(hist).get("complete") is not True or bool(hist.get("unplaced"))


def _trend_clean(hist: Any) -> bool:
    """A point a dashboard draws as a complete read. `open: 0` beside `complete: true` is the trend saying the
    day was measured and was quiet, which is what G374 found it saying about a day it could not measure."""
    return _drift_trend_point(hist).get("complete") is True and not hist.get("unplaced")


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
    "receipt.audit": Adapter(
        "a third party handed `audit --receipt`'s document, and `receipt verify` comparing its verdict block",
        "report",
        lambda b: _receipt(b, "audit"),
        _receipt_carries,
        _receipt_clean,
    ),
    "receipt.gate": Adapter(
        "a third party handed `gate --receipt`'s document, and `receipt verify` comparing its verdict block",
        "report",
        lambda b: _receipt(b, "gate"),
        _receipt_carries,
        _receipt_clean,
    ),
    "admission.review": Adapter(
        "the API server, and kubectl printing the response's warnings",
        "object",
        # One request per object, in order: the API server never sends a bundle. `kubectl apply -f dir/` prints
        # the warnings of every response, so the consumer's view of the directory is the list.
        lambda b: [_review(obj) for obj in b.objects],
        lambda responses: any(_says_withheld(w) for r in responses for w in _review_warnings(r)),
        lambda responses: all(_admission_clean(r) for r in responses),
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
    "drift.diff": Adapter(
        "a script or a dashboard reading `posture diff`'s report between two days",
        "snapshots",
        lambda b: drift.diff(*_drift_pair(b)),
        _drift_carries,
        _drift_clean,
    ),
    "drift.markdown": Adapter(
        "an operator reading the daily drift report",
        "snapshots",
        lambda b: drift.markdown(drift.diff(*_drift_pair(b))),
        _says_withheld,
        _drift_markdown_clean,
    ),
    "drift.first_report": Adapter(
        "the same operator on the first day, when there is no earlier snapshot to compare with",
        "snapshots",
        lambda b: drift.first_report(_drift_pair(b)[1]),
        _drift_carries,
        _drift_clean,
    ),
    "drift.history": Adapter(
        "a dashboard drawing open findings over time from the retained reports",
        "snapshots",
        _drift_history,
        _trend_carries,
        _trend_clean,
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
            "what is withheld here is a FILE, and this renderer is handed manifest text, one object or two "
            "snapshots of objects: it has no file it could not read to report"
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
    named = BY_NAME[fixture].names
    assert named in text, f"{renderer}: the output does not name {named}, which nothing in it was audited from"


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
#: The fixtures that hold clean objects AND an object nothing read. Selected by shape, not by name, so a fixture
#: added later with that shape is held to the tests below without anyone remembering to list it.
def _label(obj: dict[str, Any]) -> str:
    """`Kind/namespace/name`, the way the report's `notAudited` rows name an object."""
    ns = obj["metadata"].get("namespace")
    return f"{obj['kind']}/{ns + '/' if ns else ''}{obj['metadata']['name']}"


def _mixed(bundles: dict[str, Bundle]) -> dict[str, Bundle]:
    out: dict[str, Bundle] = {}
    for name, b in bundles.items():
        unread = {str(r.get("object")) for r in b.gate_report.get("notAudited") or []}
        if unread and len(b.objects) > len(unread):
            out[name] = b
    return out


def test_the_matrix_holds_the_mixture_and_not_only_the_object_alone(bundles: dict[str, Bundle]) -> None:
    """The blind spot, as a floor (G364). Every fixture that withheld an object held it alone until G363, so no
    adapter had been asked what it says when a report holds both; OSCAL and `red_team` answered `satisfied` and
    `mitigated`, and passed this file. A matrix that loses its mixed fixtures goes back to proving less than it
    appears to, silently, so their number and their variety are asserted."""
    mixed = _mixed(bundles)
    assert len(mixed) >= 8, sorted(mixed)
    # The clean neighbour is really clean in each: nothing here is a "findings beside a gap" fixture by accident,
    # except the one that says so.
    with_findings = {n for n, b in mixed.items() if b.gate_report["findings"]}
    assert with_findings <= {
        "mixed-no-reader-kind-beside-a-reader-that-missed-a-container",
        "read-object-with-an-unread-container",
    }, with_findings
    # Each position of the unread object, and each reason an object goes unread, is present at least once.
    whys = {str(r["why"]) for b in mixed.values() for r in b.gate_report["notAudited"]}
    assert any("no reader" in w for w in whys), whys
    assert any("does not know" in w for w in whys), whys
    assert any("does not read one" in w or "where kube-noob does not" in w for w in whys), whys
    positions = set()
    for b in mixed.values():
        unread = {str(r.get("object")) for r in b.gate_report["notAudited"]}
        labels = [_label(d) for d in b.objects]
        for i, label in enumerate(labels):
            if label in unread:
                positions.add("first" if i == 0 else "last" if i == len(labels) - 1 else "middle")
    assert positions == {"first", "middle", "last"}, positions


def test_a_rule_whose_only_subject_was_refused_does_not_say_the_kind_is_absent(bundles: dict[str, Bundle]) -> None:
    """Class 24, on the two fixtures built for it. "no Service in the input" about an input that holds a Service
    is an absence standing in for a refusal, in the one field every renderer copies its reasons from."""
    for fixture, kind in (
        ("mixed-the-only-subject-of-a-rule-was-refused", "Service"),
        ("mixed-the-only-binding-was-refused", "ClusterRoleBinding"),
    ):
        for report in (bundles[fixture].gate_report, bundles[fixture].audit_report):
            reasons = [str(why) for why in report["notEvaluated"].values()]
            named = [why for why in reasons if f"1 {kind} not audited" in why]
            assert named, f"{fixture}: no rule gives the refused {kind} as its reason"
            if kind == "Service":
                # A rule that reads Services says the Service was refused, never that there is none.
                assert "no Service in the input" not in reasons, fixture


def test_the_webhook_warns_about_the_object_nothing_read_and_not_about_its_clean_neighbour(
    bundles: dict[str, Bundle],
) -> None:
    """Per object, which the aggregated adapter cannot see: sent a directory one object at a time, the webhook
    must put its warning on the response for the object that was not read. A warning on the clean Pod's response
    instead would satisfy `any(...)` and tell the user the wrong object."""
    for name, b in _mixed(bundles).items():
        unread = {str(r.get("object")) for r in b.gate_report["notAudited"]}
        for obj in b.objects:
            label = _label(obj)
            warned = any(_says_withheld(w) for w in _review_warnings(_review(obj)))
            if label in unread:
                assert warned, f"{name}: {label} was not read and its admission response does not say so"
            elif label == "Pod/prod/ok":
                assert not warned, f"{name}: the hardened Pod is fully audited and its response says it is not"


def test_an_accepted_unreadable_file_does_not_accept_the_refusal_beside_it(bundles: dict[str, Bundle]) -> None:
    """The one fixture run with `--skip-unreadable`. The file is listed with who accepted it and withholds
    nothing; the refused Deployment was accepted by nobody and still withholds the verdict, and the report says
    which is which rather than one sentence covering both."""
    b = bundles["mixed-accepted-unreadable-file-beside-a-refusal-nobody-accepted"]
    assert [u.get("acceptedBy") for u in b.gate_report["unreadable"]] == [SKIP_UNREADABLE]
    assert gate.verdict_word(b.gate_report) == "incomplete"
    assert [r["object"] for r in b.gate_report["notAudited"]] == ["Deployment/prod/web"]
    # The failure the gate states is the refusal, and it does not blame the file somebody accepted.
    assert any("Deployment/prod/web" in f for f in b.gate_report["failures"])
    assert not any(BROKEN in f for f in b.gate_report["failures"]), b.gate_report["failures"]
    # Without the refusal the same waiver gives a verdict: the control that makes the assertion above mean
    # "the refusal withheld it" and not "this flag never yields a verdict".
    clean = bundles["zero-findings-and-incomplete-evidence"]
    waived = gate.run(gate.collect([str(clean.root)], read=lambda _: ""), fail_on="never", skip_unreadable=True)
    assert gate.verdict_word(waived) == "passed"


def test_the_delta_never_reports_a_repair_about_an_object_the_new_snapshot_did_not_read(
    bundles: dict[str, Bundle],
) -> None:
    """Per row, which the document-level predicate cannot see (G366, G374).

    `diff` sets `verdict: undetermined` from the `notAudited` rows alone, so a report that lists the critical
    finding under `fixed` still carries the withheld half and still fails `presents_as_clean` nowhere. The
    invariant is the join: a finding moves to `fixed`, and an object to `removed`, only when the new snapshot
    read it. Everything else is carried under `undetermined` rather than dropped -- a guard that silently lost
    the rows would satisfy the first assertion here.

    The last two assertions are what stop this from being vacuous. At least three fixtures must actually have
    LOST a finding under the pairing `_drift_pair` builds, or the guard had nothing to refuse; and every finding
    that left must be one whose object stopped being read, which is what lets `_drift_markdown_clean` read a
    `## Fixed findings` heading as the prose form of the same claim.
    """
    lost = 0
    for name, b in bundles.items():
        if not b.fixture.withheld or b.fixture.file_level:
            continue
        old, new = _drift_pair(b)
        report = drift.diff(old, new)
        unread = _drift_unread(report)
        assert unread, f"{name}: the pairing withholds nothing, so this fixture proves nothing here"
        assert not _drift_repairs_about_an_unread_object(report), (
            f"{name}: the report claims a repair about an object it says nothing read -- "
            f"{sorted(_drift_repairs_about_an_unread_object(report))}"
        )
        open_before = {f["id"] for f in old["findings"] if not f.get("excepted")}
        open_now = {f["id"] for f in new["findings"] if not f.get("excepted")}
        accounted = len(report["findings"]["fixed"]) + len(report["findings"].get("undetermined") or [])
        assert accounted == len(open_before - open_now), f"{name}: a finding is in neither list"
        if open_before - open_now:
            lost += 1
            assert report["findings"]["fixed"] == [], f"{name}: {report['findings']['fixed']}"
            assert {str(f["resource"]) for f in report["findings"]["undetermined"]} <= unread, name
    assert lost >= 3, lost


def test_a_real_fix_is_still_a_fix_in_the_matrix_too(bundles: dict[str, Bundle]) -> None:
    """The negative control, and the reason the test above is a join and not a blanket refusal.

    Without it a `diff` that called nothing `fixed` ever would pass everything here, and the gate an operator
    reads every morning would stop being able to report remediation -- which is how it gets turned off. The
    privileged Deployment of `findings-with-complete-evidence` is read in both snapshots and is no longer
    privileged in the second: that is remediation, and it has to keep reading as remediation.
    """
    b = bundles["findings-with-complete-evidence"]
    old, _ = _drift_pair(b)
    hardened = copy.deepcopy(b.objects)
    for obj in hardened:
        for container in obj["spec"]["template"]["spec"]["containers"]:
            container.pop("securityContext", None)
    report = drift.diff(old, _drift_snapshot(hardened, _DAY_TWO))
    assert "KN-S001" in {f["ruleId"] for f in report["findings"]["fixed"]}, report["findings"]
    assert not report["findings"].get("undetermined"), report["findings"]
    assert report.get("verdict") != "undetermined", report.get("verdictReason")


def test_the_trend_does_not_draw_an_undetermined_day_as_a_complete_read(bundles: dict[str, Bundle]) -> None:
    """The defect adding the adapter found (G374).

    `history`'s `complete` was read off `notRead` alone -- the resources a CLUSTER refused. An object the RULES
    refused puts nothing there and leaves the report's own `verdict` undetermined, so on
    `mixed-refused-object-of-the-kind-the-passing-rules-read` the series read `open: 10 -> 0, complete: true` on
    both days: the lie G366 took out of `findings.fixed`, redrawn one surface over (review class 25). The
    clean fixture holds the other direction, so the flag does not simply become False everywhere.
    """
    for name, b in bundles.items():
        if b.fixture.file_level:
            continue
        point = _drift_trend_point(_drift_history(b))
        assert point, name
        if b.fixture.withheld:
            assert point["complete"] is False, f"{name}: the trend draws an undetermined day as complete"
        else:
            assert point["complete"] is True, f"{name}: nothing was withheld and the trend says otherwise"


NOT_A_VERDICT_VIEW: dict[str, str] = {
    "gate.forbids_verdict": "a predicate over one skip reason, not an output",
    "gate.unreadable_reason": "a predicate over one file's bytes, not an output",
    "gate.not_opened_reason": "a predicate over one file a directory walk left alone, not an output (G351)",
    "gate.verdict_word": "THE predicate every renderer here reads; it has no output of its own",
    "gate.render": "renders a Helm chart to manifests; it runs before the audit and reports no verdict",
    "gate.collect": "reads files into Sources; it reports no verdict",
    "gate.walk": "lists the files under a directory and the entries no walk goes into; it reports no verdict (G444)",
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
    # The text here used to read "as check_network_policy: one source, one destination, one port", which is the
    # question the tool ABOVE asks and not this one: `posture_reach` is `blast_radius.reach_result`, the reach of
    # one workload the caller names. The exemption is still right -- it states no verdict over the input -- and
    # an exemption that describes a different renderer is one no reader can check, which is the whole value of
    # the table (G374).
    # Adapted first, and that was wrong. The walk does state a verdict -- `complete`, `broken`, `stopped` -- but
    # over ONE named path, not over the input, and the two predicates here are about the input's coverage. On the
    # `fully-evaluated-and-clean` fixture, which carries no Ingress, no Service and no NetworkPolicy, the walk
    # stops because that path is genuinely not knowable from those objects: `carries_withheld` read true and
    # `test_a_complete_report_is_not_reported_as_withheld` failed, correctly. "Nothing was withheld about the
    # input" and "this path is not walkable here" are different claims, so neither predicate has a meaning for
    # it -- the same reason `posture_reach` below is exempt.
    "mcp.learn_mechanism": (
        "the verdict on ONE path the caller names -- a request reaching a Pod, a node going dark -- hop by hop, "
        "and not a verdict over the input: a bundle carrying none of a path's objects makes that path unknowable "
        "without anything being withheld about the bundle. What it owes instead: the hops after a stop are NOT "
        "in `steps`, so the absence has to be counted rather than noticed, held by "
        "tests/test_the_walk_an_agent_can_run.py "
        "(test_a_stopped_walk_says_stopped_and_names_the_hop pins `declared == len(steps) + notReached`), and "
        "the command and the tool are compared whole so one path cannot have two answers "
        "(test_the_command_and_the_tool_give_the_same_answer). The command's `--format html` page "
        "(learn/mechanism_html.py, G402) is a view of this same walk and is exempt for the same reason; what it "
        "owes is held by tests/test_a_walk_you_can_watch.py: it embeds the walk `--format json` prints, exits "
        "with the walk's code, draws every declared hop, and shows nothing that was not judged as passing"
    ),
    "mcp.posture_reach": (
        "the blast radius of ONE workload the caller names -- its ServiceAccount, the bindings that name it, "
        "what those allow, the Secrets it may read by RBAC and the node it can escape to -- not a verdict over "
        "the input. What it owes instead: a leg the manifests do not carry is a `notDetermined` leg and never an "
        "empty one, held by tests/test_blast_radius.py "
        "(test_a_bound_role_missing_from_the_input_is_not_determined_not_an_empty_list, "
        "test_require_complete_exits_5_when_a_leg_is_not_determined)"
    ),
    "mcp.code_report": "reads a SAST tool's SARIF, not the manifest audit",
    "mcp.containerfile_audit": "audits a Containerfile; the manifests say where the image runs",
    "mcp.vuln_report": "reads a scanner report; the manifests say which images are deployed",
    "mcp.compliance_results": "reads a must-gather's ComplianceCheckResults, not this audit",
    "mcp.operator_inventory": "lists the operators in the input",
    # `verify_receipt` takes manifests and states no verdict over them: its three answers are about whether a
    # RECEIPT's verdict was reproduced, and `identical` for a receipt that records `undetermined` means "still
    # undetermined", not "clean". The receipt DOCUMENT is the verdict view, and it is adapted above
    # (`receipt.audit`, `receipt.gate`). What this tool still owes, held by tests/test_receipts.py: it never
    # answers `identical` for something it could not check (no manifests, a digest that differs, another
    # kube-noob), and it recomputes the verdict by the same functions the command used rather than its own
    # (`test_the_mcp_verifier_reproduces_an_undetermined_receipt`, G359).
    "mcp.verify_receipt": (
        "answers whether a receipt's recorded verdict is reproduced (identical / differs / cannot-be-checked), "
        "not a verdict over the input; the receipt document itself is adapted as receipt.audit and receipt.gate"
    ),
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
    # `drift` was outside this guard until G374: the module was not enumerated, so `posture diff` -- where the
    # worst measured lie of the series lived (G366: 15 findings reported `fixed`, the critical KN-S001 among
    # them, when their object merely stopped being read) -- had no adapter and no stated exemption, and the
    # defect was found by hand. Its four verdict views are adapted above; these are the rest.
    "drift.snapshot": "records the hashes, findings and coverage the reports above are built from: the subject",
    "drift.normalise": "strips status and server-set metadata from one object before it is hashed",
    "drift.watched": "filters the objects a snapshot TRACKS; the audit behind it reads every object it was given",
    "drift.load": "reads a snapshot file and bounds its size; it reports no verdict",
    "drift.collect_live": "reads the cluster read-only and returns what it could not read, which snapshot records",
    "drift.write_report": (
        "writes diff's report, markdown's text and the snapshot to the state folder and adds nothing to them "
        "but the trend, which is adapted as drift.history"
    ),
    "drift.latest_report": "reads the newest retained report back with the trend attached; both are adapted",
}

#: Adapters for a surface this guard does not enumerate, and why it does not. The CLI's text and JSON views are
#: the two the `audit` command writes; the module has hundreds of print helpers and no one-renderer-per-function
#: shape to read, so these two are named rather than discovered. `mcp.insight` takes `text` rather than
#: `manifests`, so it is outside the mechanical rule below and is named too. The two receipts are documents the
#: `audit` and `gate` commands write from private helpers in `cli.py` (`receipt.py` holds no command and its
#: public functions are parts, not a renderer), so they are named for the same reason the CLI views are.
NAMED_NOT_ENUMERATED = frozenset({"cli.text", "cli.json", "mcp.insight", "receipt.audit", "receipt.gate"})


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
        f"{mod}.{name}"
        for mod in ("gate", "oscal", "admission", "report_html", "drift")
        for name in _public_functions(mod)
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
    assert {"receipt.audit", "receipt.gate"} <= set(ADAPTERS), "a receipt is a view of the verdict (G359)"
    # `posture diff` is a view of the verdict too, and it was the one renderer this matrix could not see while
    # G366 happened in it. An exemption here would have to say what a delta cannot be handed; there is no such
    # thing, so there is no exemption (G374).
    assert {"drift.diff", "drift.markdown", "drift.first_report", "drift.history"} <= set(ADAPTERS), (
        "a drift report is a view of the verdict (G366, G374)"
    )
    assert len(ADAPTERS) >= 24
    assert len(FIXTURES) >= 17
