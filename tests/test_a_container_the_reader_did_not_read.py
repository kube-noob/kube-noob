"""A container in a kind kube-noob DOES read, at a place its reader does not look.

`unread_pod_specs` is the safety net under the kind registries: a container-shaped mapping in a kind with no reader
withholds the verdict. For a kind the registries name it returned nothing at all, by kind -- "for those kinds the
registry is the claim". The claim was never checked against what the reader actually read, and three of the kinds
the registries name have no bundled schema to catch the difference (`DeploymentConfig`, `InferenceService`, the
KubeRay kinds). So, measured with the CLI on 0.10.0:

  * `DeploymentConfig` with a privileged container under `template.Spec` -- capital S, not the `template.spec` the
    reader walks -- scored 92.0 to 96.0, gated `passed`, verified `allow`
  * `InferenceService` with a privileged `spec.explainer.alibi` scored 79.0, `passed`, `allow`
  * `RayCluster` and `InferenceService` with a pod spec at a path the registry does not list scored 80.0,
    `passed`, `allow`

What this was NOT: a deployable bypass. In all three a current API server rejects or prunes the field (it is not
in the kind's schema), so the container would not run as written. The defect is the stated score and the pass --
a number printed over a container no rule looked at -- and the tests below hold that and no more.

The fix is in the predicate and not at a call site (review class 25): the walk now runs over every kind, and what
it prunes is what `containers()` yielded -- per container, not per pod spec, because `explainer.alibi` sits INSIDE
a pod spec the registry claims and pruning by pod-spec path hid it. Core kinds were never the gap (KN-V007's strict
schema fails them), and they go through the same walk anyway: a reader's claim does not depend on which validator
happens to run beside it.

The control comes first in each section: a gate that is incomplete on every repository is one nobody reads.
"""

from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Any

import pytest
import yaml

from kube_noob import admission, gate
from kube_noob import toolkit as tk
from kube_noob.audit import engine
from kube_noob.audit.podspec import (
    EMBEDDED_CONTAINER_KEYS,
    EMBEDDED_POD_SPEC_PATHS,
    INJECTED_CONTAINERS,
    POD_SPEC_PATHS,
    containers,
    pod_templates,
    unread_pod_specs,
)
from kube_noob.audit.rules import UNREAD_CONTAINERS, UNREAD_POD_SPECS, WORKLOAD_KINDS
from kube_noob.cli import main
from kube_noob.toolkit import Toolkit
from kube_noob.yamlio import load_documents

IMG = "registry.example.com/app@sha256:" + "0" * 64
PRIV = f"{{name: c, image: '{IMG}', securityContext: {{privileged: true}}}}"
PLAIN = f"{{name: a, image: '{IMG}'}}"

DC = """\
apiVersion: apps.openshift.io/v1
kind: DeploymentConfig
metadata: {name: dc, namespace: app}
spec:
  replicas: 1
  selector: {app: dc}
  template:
    metadata: {labels: {app: dc}}
"""
ISVC = """\
apiVersion: serving.kserve.io/v1beta1
kind: InferenceService
metadata: {name: m, namespace: app}
spec:
"""
PREDICTOR = f"  predictor:\n    containers: [{PLAIN}]\n"
RAY = """\
apiVersion: ray.io/v1
kind: RayCluster
metadata: {name: r, namespace: app}
spec:
"""
HEAD = f"  headGroupSpec:\n    template:\n      spec:\n        containers: [{PLAIN}]\n"
DEPLOYMENT = """\
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: app}
spec:
  replicas: 1
  selector: {matchLabels: {app: web}}
  template:
    metadata: {labels: {app: web}}
"""

#: The three shapes in the report, as the red-team pass measured them.
DC_CAPITAL_SPEC = DC + f"    Spec:\n      containers: [{PRIV}]\n"
ISVC_ALIBI = ISVC + PREDICTOR + f"  explainer:\n    alibi: {PRIV}\n"
RAY_UNLISTED = RAY + HEAD + f"  extraGroupSpec:\n    template:\n      spec:\n        containers: [{PRIV}]\n"
ISVC_UNLISTED = ISVC + PREDICTOR + f"  router:\n    containers: [{PRIV}]\n"

REPORTED: list[tuple[str, str, str, str]] = [
    ("DeploymentConfig template.Spec", DC_CAPITAL_SPEC, "DeploymentConfig/app/dc", "spec.template.Spec.containers"),
    ("InferenceService explainer.alibi", ISVC_ALIBI, "InferenceService/app/m", "spec.explainer.alibi"),
    ("RayCluster unlisted path", RAY_UNLISTED, "RayCluster/app/r", "spec.extraGroupSpec.template.spec.containers"),
    ("InferenceService unlisted path", ISVC_UNLISTED, "InferenceService/app/m", "spec.router.containers"),
]

#: Review class 21: the shape next to each one in the report, none of them one of the three reproducers. Measured
#: on 0.10.0: the first fifteen gated `passed`. The last is a core kind, which KN-V007's strict schema was already
#: failing; it is here because the reader's claim does not depend on which validator runs beside it.
NEIGHBOURS: list[tuple[str, str, str, str]] = [
    (
        "DeploymentConfig spec.Containers",
        DC + f"    spec:\n      Containers: [{PRIV}]\n",
        "DeploymentConfig/app/dc",
        "spec.template.spec.Containers",
    ),
    (
        "DeploymentConfig containers as a mapping",
        DC + f"    spec:\n      containers: {{c: {PRIV}}}\n",
        "DeploymentConfig/app/dc",
        "spec.template.spec.containers",
    ),
    (
        "DeploymentConfig a container under a made-up key beside read ones",
        DC + f"    spec:\n      containers: [{PLAIN}]\n      sidecar: {PRIV}\n",
        "DeploymentConfig/app/dc",
        "spec.template.spec.sidecar",
    ),
    (
        "DeploymentConfig spec.Template",
        DC.replace("  template:", "  Template:") + f"    spec:\n      containers: [{PRIV}]\n",
        "DeploymentConfig/app/dc",
        "spec.Template.spec.containers",
    ),
    (
        # A recognised container key at an unread place withholds on the NAME as well as on the shape: an entry
        # with no `image` is one the reader would have read (and reported as having none) had it been where the
        # reader looks.
        "DeploymentConfig template.Spec, the container declares no image",
        DC + "    Spec:\n      containers: [{name: c, securityContext: {privileged: true}}]\n",
        "DeploymentConfig/app/dc",
        "spec.template.Spec.containers",
    ),
    (
        # A real field, and a real container: the custom deployer pod runs this image, and no rule reads it.
        "DeploymentConfig strategy.customParams",
        DC
        + f"    spec:\n      containers: [{PLAIN}]\n  strategy: {{type: Custom, customParams: {{image: '{IMG}'}}}}\n",
        "DeploymentConfig/app/dc",
        "spec.strategy.customParams",
    ),
    (
        "InferenceService spec.Predictor",
        ISVC + f"  Predictor:\n    containers: [{PRIV}]\n",
        "InferenceService/app/m",
        "spec.Predictor.containers",
    ),
    (
        "InferenceService a model under spec.Predictor",
        ISVC + PREDICTOR + f"  Predictor:\n    model: {PRIV}\n",
        "InferenceService/app/m",
        "spec.Predictor.model",
    ),
    (
        "InferenceService predictor.Model",
        ISVC + f"  predictor:\n    Model: {PRIV}\n",
        "InferenceService/app/m",
        "spec.predictor.Model",
    ),
    (
        "InferenceService art with no image under spec.Explainer",
        ISVC + PREDICTOR + "  Explainer:\n    art: {securityContext: {privileged: true}}\n",
        "InferenceService/app/m",
        "spec.Explainer.art",
    ),
    (
        "InferenceService predictor.containers as a mapping",
        ISVC + f"  predictor:\n    containers: {{c: {PRIV}}}\n",
        "InferenceService/app/m",
        "spec.predictor.containers",
    ),
    (
        "InferenceService predictor as a list",
        ISVC + f"  predictor:\n  - containers: [{PRIV}]\n",
        "InferenceService/app/m",
        "spec.predictor.0.containers",
    ),
    (
        "RayCluster template.Spec",
        RAY + f"  headGroupSpec:\n    template:\n      Spec:\n        containers: [{PRIV}]\n",
        "RayCluster/app/r",
        "spec.headGroupSpec.template.Spec.containers",
    ),
    (
        "RayCluster workerGroupSpecs as a mapping",
        RAY + HEAD + f"  workerGroupSpecs:\n    template:\n      spec:\n        containers: [{PRIV}]\n",
        "RayCluster/app/r",
        "spec.workerGroupSpecs.template.spec.containers",
    ),
    (
        # The reader joins the autoscaler to the head pod. With no head pod to join, nothing read it.
        "RayCluster autoscalerOptions with no head group",
        RAY + f"  autoscalerOptions: {{image: '{IMG}', securityContext: {{privileged: true}}}}\n",
        "RayCluster/app/r",
        "spec.autoscalerOptions",
    ),
    (
        "CronJob jobTemplate.Spec",
        "apiVersion: batch/v1\nkind: CronJob\nmetadata: {name: cj, namespace: app}\nspec:\n  schedule: '0 0 * * *'\n"
        f"  jobTemplate:\n    Spec:\n      template:\n        spec:\n          containers: [{PRIV}]\n",
        "CronJob/app/cj",
        "spec.jobTemplate.Spec.template.spec.containers",
    ),
]

#: Valid objects, every one of which a reader reads in full -- and the fields in them that look like a container
#: and are not one. A fix that accused any of these would turn every OpenShift, KServe or KubeRay repository
#: undetermined, which is a worse outcome than the gap it closes.
VALID: list[tuple[str, str]] = [
    ("DeploymentConfig", DC + f"    spec:\n      containers: [{PRIV}]\n"),
    (
        # `rbd.image` names a block device image. It is a mapping with a string `image` and it is storage.
        "DeploymentConfig with an RBD volume",
        DC
        + f"    spec:\n      containers: [{PLAIN}]\n      volumes: [{{name: v, rbd: {{image: foo, monitors: [a]}}}}]\n",
    ),
    (
        "Deployment with init and ephemeral containers",
        DEPLOYMENT
        + f"    spec:\n      containers: [{PLAIN}]\n      initContainers: [{PLAIN}]\n"
        + f"      ephemeralContainers: [{PLAIN}]\n",
    ),
    (
        # What `kubectl get pod -o yaml` and a must-gather carry: the status repeats every container's image.
        "Pod read back from a cluster",
        "apiVersion: v1\nkind: Pod\nmetadata: {name: p, namespace: app}\n"
        f"spec:\n  containers: [{PLAIN}]\n  initContainers: [{PLAIN}]\n"
        f"status:\n  containerStatuses: [{{name: a, image: '{IMG}', imageID: x, ready: true, restartCount: 0}}]\n"
        f"  initContainerStatuses: [{{name: a, image: '{IMG}', imageID: x, ready: true, restartCount: 0}}]\n",
    ),
    (
        "CronJob",
        "apiVersion: batch/v1\nkind: CronJob\nmetadata: {name: cj, namespace: app}\nspec:\n  schedule: '0 0 * * *'\n"
        f"  jobTemplate:\n    spec:\n      template:\n        spec:\n          restartPolicy: Never\n"
        f"          containers: [{PLAIN}]\n",
    ),
    (
        "PodTemplate",
        "apiVersion: v1\nkind: PodTemplate\nmetadata: {name: t, namespace: app}\ntemplate:\n  spec:\n"
        f"    containers: [{PLAIN}]\n",
    ),
    (
        "InferenceService, every component",
        ISVC
        + f"  predictor:\n    model: {{modelFormat: {{name: sklearn}}, image: '{IMG}'}}\n"
        + f"    initContainers: [{PLAIN}]\n"
        + f"    workerSpec:\n      containers: [{PLAIN}]\n"
        + f"  transformer:\n    containers: [{PLAIN}]\n"
        + f"  explainer:\n    art: {{image: '{IMG}'}}\n",
    ),
    ("InferenceService, a framework shorthand", ISVC + f"  predictor:\n    sklearn: {{image: '{IMG}'}}\n"),
    (
        "RayCluster with the autoscaler and two worker groups",
        RAY
        + HEAD
        + f"  autoscalerOptions: {{image: '{IMG}'}}\n"
        + f"  workerGroupSpecs:\n  - groupName: a\n    template:\n      spec:\n        containers: [{PLAIN}]\n"
        + f"  - groupName: b\n    template:\n      spec:\n        containers: [{PLAIN}]\n",
    ),
    (
        "RayService",
        "apiVersion: ray.io/v1\nkind: RayService\nmetadata: {name: s, namespace: app}\nspec:\n  rayClusterConfig:\n"
        f"    autoscalerOptions: {{image: '{IMG}'}}\n"
        f"    headGroupSpec:\n      template:\n        spec:\n          containers: [{PLAIN}]\n",
    ),
    (
        # A RayJob that submits to a cluster somebody else declared carries no pod spec at all, and that is valid.
        "RayJob selecting an existing cluster",
        "apiVersion: ray.io/v1\nkind: RayJob\nmetadata: {name: j, namespace: app}\nspec:\n"
        "  entrypoint: python x.py\n  clusterSelector: {ray.io/cluster: r}\n",
    ),
    (
        "RayJob with a submitter",
        "apiVersion: ray.io/v1\nkind: RayJob\nmetadata: {name: j, namespace: app}\nspec:\n  entrypoint: python x.py\n"
        f"  submitterPodTemplate:\n    spec:\n      containers: [{PLAIN}]\n"
        f"  rayClusterSpec:\n    headGroupSpec:\n      template:\n        spec:\n          containers: [{PLAIN}]\n",
    ),
]


def _rows(text: str, **kw: Any) -> list[tuple[str, str]]:
    rep = engine.analyze(text, **kw)
    return [(str(r["object"]), str(r["why"])) for r in rep.as_dict()["notAudited"]]


def _paths(text: str) -> list[str]:
    (doc,) = load_documents(text)
    return [".".join(str(p) for p in path) for path in unread_pod_specs(doc)]


# -- the predicate -------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(("name", "text"), VALID, ids=[v[0] for v in VALID])
def test_an_object_the_reader_read_in_full_is_not_accused(name: str, text: str) -> None:
    """The control, and the direction that decides whether this is usable rather than noise."""
    assert _paths(text) == [], name
    assert UNREAD_CONTAINERS not in [why for _, why in _rows(text)], name


@pytest.mark.parametrize(("name", "text", "ref", "where"), REPORTED, ids=[r[0] for r in REPORTED])
def test_a_container_the_reader_did_not_read_withholds_the_verdict(name: str, text: str, ref: str, where: str) -> None:
    """The regression: the three shapes in the report (the third on both kinds it was measured on). Each one
    printed a score, gated `passed` and verified `allow`."""
    assert _paths(text) == [where], name
    assert (ref, UNREAD_CONTAINERS) in _rows(text), name
    rep = engine.analyze(text)
    assert rep.undetermined(), name
    assert rep.as_dict()["summary"]["score"] is None, "a number is still printed over a container no rule read"


@pytest.mark.parametrize(("name", "text", "ref", "where"), NEIGHBOURS, ids=[n[0] for n in NEIGHBOURS])
def test_the_shape_next_to_the_reported_one_withholds_it_too(name: str, text: str, ref: str, where: str) -> None:
    """Review class 21. A guard for `Spec`, `alibi` and "an unlisted path" would have passed every row here."""
    assert _paths(text) == [where], name
    assert (ref, UNREAD_CONTAINERS) in _rows(text), name
    assert engine.analyze(text).undetermined(), name


def test_what_is_pruned_is_the_container_the_reader_read_not_the_pod_spec_around_it() -> None:
    """The reason the first attempt at this stopped. `spec.explainer` is a pod spec the registry claims, so
    pruning by pod-spec path prunes `alibi` with it. Per container, the read `art` is pruned and the unread
    `alibi` beside it -- in the same mapping -- is not."""
    text = ISVC + PREDICTOR + f"  explainer:\n    art: {{image: '{IMG}'}}\n    alibi: {PRIV}\n"
    (doc,) = load_documents(text)
    read = {c.path for pt in pod_templates(doc) for c in containers(pt)}
    assert ("spec", "explainer", "art") in read
    assert ("spec", "explainer") in {pt.path for pt in pod_templates(doc)}
    assert _paths(text) == ["spec.explainer.alibi"]


def test_the_part_the_reader_did_read_is_still_audited() -> None:
    """Withholding the verdict does not withhold the findings. A privileged predictor beside an unread explainer
    is reported as privileged; what is missing is the score, not the evidence."""
    text = ISVC + f"  predictor:\n    containers: [{PRIV}]\n" + f"  explainer:\n    alibi: {PRIV}\n"
    rep = engine.analyze(text)
    privileged = [f for f in rep.findings if f.rule_id == "KN-S002"]
    assert [f.resource for f in privileged] == ["InferenceService/app/m"]
    assert "predictor" in privileged[0].path
    assert ("InferenceService/app/m", UNREAD_CONTAINERS) in _rows(text)


def test_the_report_says_where_the_container_is_and_does_not_overstate_it() -> None:
    """The path, so a reader can fix the manifest -- and the mitigating fact, so nobody reads this as a bypass:
    a field the kind's schema does not define is pruned or rejected by the API server and runs nothing."""
    notes = [a for a in engine.analyze(ISVC_ALIBI).assumptions if "spec.explainer.alibi" in a]
    assert len(notes) == 1, notes
    assert "InferenceService/app/m at spec.explainer.alibi" in notes[0]
    assert "were NOT audited" in notes[0]
    assert "prunes or rejects" in notes[0]
    assert "no reader for" not in notes[0], "the kind HAS a reader; saying otherwise sends the reader the wrong way"


def test_a_kind_with_a_reader_is_never_said_to_have_none() -> None:
    """Two reasons for two facts (review class 9 the other way round: one phrase for both would be false for one).
    A Tekton Task has no reader. A DeploymentConfig has one, and it did not look where the container is."""
    tekton = (
        "apiVersion: tekton.dev/v1\nkind: Task\nmetadata: {name: b, namespace: ci}\nspec:\n"
        "  steps: [{name: s, image: 'docker:24'}]\n"
    )
    assert _rows(tekton) == [("Task/ci/b", UNREAD_POD_SPECS)]
    assert _rows(DC_CAPITAL_SPEC, platform="openshift", version="4.20") == [
        ("DeploymentConfig/app/dc", UNREAD_CONTAINERS)
    ]
    assert UNREAD_CONTAINERS != UNREAD_POD_SPECS


def test_a_workload_whose_only_pod_spec_went_unread_is_not_called_absent() -> None:
    """Review class 24. With `template.Spec` the reader finds no pod spec, and every pod-spec rule used to record
    "no pod spec in the input (no Pod, Deployment, ... DeploymentConfig ...)" beside a DeploymentConfig."""
    rep = engine.analyze(DC_CAPITAL_SPEC, platform="openshift", version="4.20")
    why = rep.as_dict()["notEvaluated"]["KN-S002"]
    assert why == f"1 DeploymentConfig not audited ({UNREAD_CONTAINERS})"
    assert not [w for w in rep.as_dict()["notEvaluated"].values() if "no pod spec in the input" in w]


def test_every_kind_with_a_reader_goes_through_the_walk() -> None:
    """Review class 25, structurally: the old guard returned `[]` for a kind by NAME. Every kind either registry
    names is built here with its pod spec moved to a place its reader does not look, and each must be reported.
    A kind added to a registry tomorrow is in this loop on the day it is added."""
    assert set(WORKLOAD_KINDS) == set(POD_SPEC_PATHS) | set(EMBEDDED_POD_SPEC_PATHS)
    group = {"DeploymentConfig": "apps.openshift.io/v1", "InferenceService": "serving.kserve.io/v1beta1"}
    for kind in WORKLOAD_KINDS:
        api = group.get(kind) or ("ray.io/v1" if kind.startswith("Ray") else "v1")
        obj = {
            "apiVersion": api,
            "kind": kind,
            "metadata": {"name": "x", "namespace": "app"},
            "spec": {"somewhereElse": {"containers": [{"name": "c", "image": IMG}]}},
        }
        (doc,) = load_documents(yaml.safe_dump(obj))
        assert unread_pod_specs(doc) == [("spec", "somewhereElse", "containers")], kind


def test_every_container_key_a_registry_names_is_one_the_walk_knows() -> None:
    """A container key added to a registry is read at the path the registry gives it and reported everywhere else.
    Built from the registries, so the two cannot drift (review class 9)."""
    names = {k for keys in EMBEDDED_CONTAINER_KEYS.values() for k in keys}
    names |= {str(where[-1]) for pairs in INJECTED_CONTAINERS.values() for where, _ in pairs}
    for key in sorted(names):
        text = ISVC + PREDICTOR + f"  elsewhere:\n    {key}: {{securityContext: {{privileged: true}}}}\n"
        assert _paths(text) == [f"spec.elsewhere.{key}"], key


def test_the_same_input_gives_the_same_answer_in_any_key_order() -> None:
    """Review class 5. The paths are sorted, and a mapping's key order is not part of the answer."""
    obj = yaml.safe_load(
        ISVC + PREDICTOR + f"  router:\n    containers: [{PRIV}]\n  explainer:\n    alibi: {PRIV}\n    zeta: {PRIV}\n"
    )
    first = _paths(yaml.safe_dump(obj, sort_keys=True))
    assert first == ["spec.explainer.alibi", "spec.explainer.zeta", "spec.router.containers"]
    rng = random.Random(7)
    for _ in range(5):
        spec = list(obj["spec"].items())
        rng.shuffle(spec)
        shuffled = {**obj, "spec": dict(spec)}
        assert _paths(yaml.safe_dump(shuffled, sort_keys=False)) == first


def test_a_mapping_key_that_is_not_a_string_does_not_crash_the_walk() -> None:
    """Review class 16: `1:` and `~:` are legal YAML keys, and a `sorted` over mixed key types raises TypeError."""
    text = ISVC + PREDICTOR + f"  1: {{containers: [{PRIV}]}}\n  ~: {{x: 1}}\n"
    assert _paths(text) == ["spec.1.containers"]


def test_two_unread_pod_specs_under_keys_of_different_types_do_not_crash_the_old_walk() -> None:
    """Found while rewriting this function, in the half that was already there: the walk for a kind with NO reader
    ended in a plain `sorted` over paths, and two hits under an int key and a string key at the same depth raised
    `TypeError: '<' not supported between instances of 'int' and 'str'` out of the detector."""
    text = (
        "apiVersion: fleet.acme.io/v1\nkind: WidgetFleet\nmetadata: {name: f, namespace: app}\nspec:\n"
        f"  1: {{containers: [{PLAIN}]}}\n  b: {{containers: [{PLAIN}]}}\n"
    )
    assert _paths(text) == ["spec.1", "spec.b"]
    assert _rows(text) == [("WidgetFleet/app/f", UNREAD_POD_SPECS)]


def test_list_indices_are_ordered_as_numbers() -> None:
    """The order a plain sort gave wherever it could give one, kept: index 2 before index 10."""
    items = "".join(f"  - {{containers: [{PLAIN}]}}\n" for _ in range(11))
    text = "apiVersion: fleet.acme.io/v1\nkind: WidgetFleet\nmetadata: {name: f, namespace: app}\nspec:\n" + items
    assert _paths(text) == [f"spec.{i}" for i in range(11)]


def test_a_container_past_the_two_hundredth_item_of_a_list_is_still_seen() -> None:
    """G362, review class 2: the walk for a kind with no reader read `node[:200]` of every list. An Argo Workflow
    whose 201st template runs a privileged `docker:24-dind` scored 100.0 with nothing under `notAudited` -- and
    unlike the shapes above, that container runs. The control is the same Workflow one template shorter."""
    head = (
        "apiVersion: argoproj.io/v1alpha1\nkind: Workflow\nmetadata: {name: wf, namespace: ci}\nspec:\n  templates:\n"
    )
    last = "  - name: last\n    container: {image: 'docker:24-dind', securityContext: {privileged: true}}\n"
    for filler in (199, 200, 450):
        text = head + "".join(f"  - name: t{i}\n    dag: {{tasks: []}}\n" for i in range(filler)) + last
        assert _paths(text) == [f"spec.templates.{filler}"], filler
        report = engine.analyze(text)
        assert report.undetermined(), filler
        assert report.as_dict()["summary"]["score"] is None, filler
    runs_nothing = head + "".join(f"  - name: t{i}\n    dag: {{tasks: []}}\n" for i in range(450))
    assert _paths(runs_nothing) == []


def test_a_key_in_the_path_cannot_forge_a_line_of_the_report(settings: Any) -> None:
    """Review class 7. The path is made of the document's own keys, and a key may hold a newline, an escape
    sequence or a bidi override. It is cleaned where the sentence is built, so the JSON carries no raw one."""
    obj = yaml.safe_load(ISVC + PREDICTOR)
    obj["spec"]["ev\u202eil\nFORGED: row\x1b[31m"] = {"containers": [{"name": "c", "image": IMG}]}
    report = engine.analyze(yaml.safe_dump(obj))
    (note,) = [a for a in report.assumptions if "were NOT audited" in a]
    for raw in ("\u202e", "\n", "\x1b"):
        assert raw not in note, repr(note)
    assert "FORGED" in note, "the key was dropped rather than shown cleaned"
    out = dict(Toolkit(settings).posture_scan(tk.PostureScanIn(manifests=yaml.safe_dump(obj))))
    for entry in out["notRead"]:
        for raw in ("\u202e", "\n", "\x1b"):
            assert raw not in entry, repr(entry)


# -- the commands, as a user runs them -----------------------------------------------------------------------------


def _write(tmp_path: Path, text: str) -> str:
    path = tmp_path / "m.yaml"
    path.write_text(text, encoding="utf-8")
    return str(path)


CLI_CASES = [
    ("DeploymentConfig template.Spec", DC_CAPITAL_SPEC, ["--platform", "openshift", "--version", "4.20"]),
    ("InferenceService explainer.alibi", ISVC_ALIBI, []),
    ("RayCluster unlisted path", RAY_UNLISTED, []),
    ("InferenceService unlisted path", ISVC_UNLISTED, []),
]


@pytest.mark.parametrize(("name", "text", "platform"), CLI_CASES, ids=[c[0] for c in CLI_CASES])
def test_audit_prints_no_score_and_exits_1(
    name: str, text: str, platform: list[str], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(["--format", "json", "audit", "-f", _write(tmp_path, text), *platform])
    report = json.loads(capsys.readouterr().out)
    assert code == 1, name
    assert report["summary"]["score"] is None
    assert report["summary"]["verdict"] == "undetermined"
    assert [r["why"] for r in report["notAudited"]] == [UNREAD_CONTAINERS]


@pytest.mark.parametrize(("name", "text", "platform"), CLI_CASES, ids=[c[0] for c in CLI_CASES])
def test_audit_text_view_says_it_and_prints_no_number(
    name: str, text: str, platform: list[str], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Review class 6: the caveat is in the view a person reads, not only in the JSON."""
    code = main(["audit", "-f", _write(tmp_path, text), *platform])
    out = capsys.readouterr().out
    assert code == 1, name
    assert "score=not determined" in out
    assert UNREAD_CONTAINERS in out


@pytest.mark.parametrize(("name", "text", "platform"), CLI_CASES, ids=[c[0] for c in CLI_CASES])
def test_gate_does_not_pass(
    name: str, text: str, platform: list[str], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(["--format", "json", "gate", "-f", _write(tmp_path, text), *platform])
    report = json.loads(capsys.readouterr().out)
    assert code == 1, name
    assert report["passed"] is False
    assert gate.verdict_word(report) == "incomplete"
    assert any(UNREAD_CONTAINERS in f for f in report["failures"]), report["failures"]


@pytest.mark.parametrize(("name", "text", "platform"), CLI_CASES, ids=[c[0] for c in CLI_CASES])
def test_verify_does_not_allow(
    name: str, text: str, platform: list[str], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(["--format", "json", "verify", "-f", _write(tmp_path, text), *platform])
    result = json.loads(capsys.readouterr().out)
    assert result["verdict"] == "not-determined", name
    assert code == 5
    said = json.dumps(result)
    assert "no audit rule reads" in said
    assert "no reader for" not in said, "the kind has a reader; the sentence for a kind without one is false here"


def test_verify_reads_the_file_the_gate_does_not_open(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """`verify`'s own detector exists for the documents the gate never saw -- a `.json` file in a directory -- and
    it calls the predicate directly, so it has to learn the reason from the predicate and not from a gate row."""
    (tmp_path / "k8s").mkdir()
    (doc,) = list(yaml.safe_load_all(ISVC_ALIBI))
    (tmp_path / "k8s" / "isvc.json").write_text(json.dumps(doc), encoding="utf-8")
    code = main(["--format", "json", "verify", "-f", str(tmp_path / "k8s")])
    result = json.loads(capsys.readouterr().out)
    assert result["verdict"] == "not-determined"
    assert code == 5
    assert "InferenceService/app/m" in json.dumps(result)


def test_an_exception_accepts_the_row_in_the_gate_and_in_verify(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Review class 9. The documented remedy for an object nobody will fix is a `notAudited` exception, and it has
    to work at both hops or the tool's own advice fails at the one that runs before an action."""
    manifest = _write(tmp_path, ISVC + f"  predictor:\n    containers: [{PLAIN}]\n  explainer:\n    alibi: {PLAIN}\n")
    exceptions = tmp_path / "exceptions.yaml"
    exceptions.write_text(
        "apiVersion: kube-noob.io/v1\nkind: ExceptionList\nexceptions:\n  - id: EXC-ALIBI\n"
        "    notAudited: {namespace: app, kind: InferenceService, name: m, apiGroup: serving.kserve.io}\n"
        "    owner: ml-platform\n    reason: the explainer field is pruned by the API server\n"
        "    expires: 2027-11-01\n",
        encoding="utf-8",
    )
    main(["--format", "json", "gate", "-f", manifest, "--exceptions", str(exceptions), "--fail-on", "never"])
    report = json.loads(capsys.readouterr().out)
    assert [r.get("acceptedBy") for r in report["notAudited"]] == ["EXC-ALIBI"], report["notAudited"]
    assert gate.verdict_word(report) != "incomplete"
    main(["--format", "json", "verify", "-f", manifest, "--exceptions", str(exceptions), "--fail-on", "never"])
    assert json.loads(capsys.readouterr().out)["verdict"] == "allow"


# -- the surfaces that are handed text or one object ---------------------------------------------------------------


def test_the_webhook_warns_about_a_container_it_did_not_evaluate() -> None:
    """The API server sends one object. A blank `allowed: true` for it is the same pass, one hop later."""
    (obj,) = list(yaml.safe_load_all(ISVC_ALIBI))
    response = admission.review(
        {
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "request": {"uid": "1", "namespace": "app", "object": obj},
        },
        admission.Config(),
    )
    warnings = [str(w) for w in response["response"].get("warnings") or []]
    assert any("not audited" in w.lower() for w in warnings), warnings


def test_posture_and_the_threat_model_do_not_rank_it_as_read(settings: Any) -> None:
    """`posture_scan` has its own reader and its own list of what it ranks. A DeploymentConfig whose pod spec it
    did not find is not a workload with no capabilities."""
    for out in (
        dict(Toolkit(settings).posture_scan(tk.PostureScanIn(manifests=DC_CAPITAL_SPEC))),
        dict(Toolkit(settings).threat_model(tk.ThreatModelIn(manifests=DC_CAPITAL_SPEC))),
    ):
        assert out.get("notRead") or out.get("refused"), sorted(out)
        assert "DeploymentConfig/app/dc" in json.dumps([out.get("notRead"), out.get("refused")])


def test_insight_and_the_protocol_do_not_call_it_ready(settings: Any) -> None:
    out = dict(Toolkit(settings).insight(tk.InsightIn(text=ISVC_ALIBI)))
    assert any("not audited" in json.dumps(row).lower() for row in out.get("skipped") or []), out.get("skipped")
    proto = dict(Toolkit(settings).run_protocol(tk.ProtocolIn(request="review this manifest", manifests=ISVC_ALIBI)))
    assert proto.get("ready") is not True, {k: proto.get(k) for k in ("ready", "verdict")}
