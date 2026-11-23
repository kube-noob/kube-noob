"""A container this product never looked at, in a document it reported as passing.

`unread_pod_specs` is the safety net under the kind registries: there are far more workload CRDs than anyone can
enumerate, so rather than guessing a path it finds the *shape* of a pod spec and reports that the object was not
audited. The verdict is withheld, no finding is invented, and the reader is told the gap exists. That design is
right and it works.

Its shape detector required a `containers` LIST. Three shapes that run containers therefore read as clean:

  * Tekton `Task` -- `spec.steps[]`, and `spec.sidecars[]`
  * Argo `Workflow` -- `spec.templates[].container`, one mapping rather than a list
  * any pod spec carrying only `initContainers`, which has no `containers` key at all

A privileged `docker:24-dind` step in a Tekton Task scored 100.0, exited 0, gated `passed` and verified `allow`.

The discriminator is unchanged and is the whole guard: a mapping is container-shaped only if it declares a string
`image`. Widening which KEY may hold it does not widen what gets accused, and a hit withholds the verdict rather
than making a claim -- so the cost of recognising one shape too many is a stated unknown, and the cost of
recognising one too few is a privileged container reported clean.
"""

from __future__ import annotations

from typing import Any

import pytest

from kube_noob.audit import engine
from kube_noob.audit.podspec import _looks_like_a_pod_spec

TEKTON = """\
apiVersion: tekton.dev/v1
kind: Task
metadata: {name: build, namespace: ci}
spec:
  steps:
  - name: dind
    image: docker:24-dind
    securityContext: {privileged: true}
"""

TEKTON_SIDECAR = """\
apiVersion: tekton.dev/v1
kind: Task
metadata: {name: build, namespace: ci}
spec:
  sidecars:
  - name: registry
    image: registry:2
    securityContext: {privileged: true}
"""

ARGO = """\
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata: {name: wf, namespace: ci}
spec:
  templates:
  - name: main
    container:
      image: alpine:3
      securityContext: {privileged: true}
"""

ONLY_INIT = """\
apiVersion: fleet.acme.io/v1
kind: WidgetFleet
metadata: {name: fleet, namespace: prod}
spec:
  template:
    spec:
      initContainers:
      - name: setup
        image: busybox:1
        securityContext: {privileged: true}
"""

#: The shape that already worked. Here so a run in which nothing is detected fails loudly rather than quietly.
PROPER = """\
apiVersion: fleet.acme.io/v1
kind: WidgetFleet
metadata: {name: fleet, namespace: prod}
spec:
  template:
    spec:
      containers:
      - name: c
        image: busybox:1
"""

RUNS_NOTHING = """\
apiVersion: fleet.acme.io/v1
kind: WidgetFleet
metadata: {name: fleet, namespace: prod}
spec:
  replicas: 3
  strategy: {type: Rolling}
  endpoints: [{name: api, port: 8080}]
"""

KYVERNO = """\
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata: {name: require-labels}
spec:
  rules:
  - name: check
    match: {resources: {kinds: [Pod]}}
    validate: {pattern: {metadata: {labels: {team: "?*"}}}}
"""


def _not_audited(text: str) -> list[str]:
    rep = engine.analyze(text)
    return [str(r.get("object")) for r in (rep.as_dict().get("notAudited") or [])]


@pytest.mark.parametrize(
    ("name", "text", "ref"),
    [
        ("tekton steps", TEKTON, "Task/ci/build"),
        ("tekton sidecars", TEKTON_SIDECAR, "Task/ci/build"),
        ("argo container mapping", ARGO, "Workflow/ci/wf"),
        ("initContainers only", ONLY_INIT, "WidgetFleet/prod/fleet"),
        ("containers list", PROPER, "WidgetFleet/prod/fleet"),
    ],
)
def test_a_container_in_a_kind_with_no_reader_withholds_the_verdict(name: str, text: str, ref: str) -> None:
    """The regression. Each of the first four scored 100.0, exit 0, gate `passed`, verify `allow`."""
    assert _not_audited(text) == [ref], name
    assert engine.analyze(text).undetermined(), name


@pytest.mark.parametrize(("name", "text"), [("runs nothing", RUNS_NOTHING), ("kyverno policy", KYVERNO)])
def test_a_document_that_runs_no_container_is_not_accused(name: str, text: str) -> None:
    """The direction that decides whether this is usable rather than noise.

    A CRD that declares replicas and endpoints, and a Kyverno policy that names `Pod` as a match target, run
    nothing. If either were reported as holding an unread pod spec, every GitOps repository would be undetermined
    and the report would be ignored -- which is a worse outcome than the gap it closes.
    """
    assert _not_audited(text) == [], name
    assert not engine.analyze(text).undetermined(), name


def test_the_image_string_is_the_whole_discriminator() -> None:
    """Widening the key is safe only because this has not moved. A mapping without a string `image` is not a
    container however it is named, and that is what keeps an unrelated CRD from being accused."""
    assert _looks_like_a_pod_spec({"containers": [{"name": "c", "image": "busybox:1"}]})
    assert _looks_like_a_pod_spec({"steps": [{"name": "s", "image": "docker:24"}]})
    assert _looks_like_a_pod_spec({"container": {"image": "alpine:3"}})
    # No image, or an image that is not a string: not a container.
    assert not _looks_like_a_pod_spec({"steps": [{"name": "s", "script": "echo hi"}]})
    assert not _looks_like_a_pod_spec({"containers": [{"name": "c", "image": {"repo": "busybox"}}]})
    assert not _looks_like_a_pod_spec({"container": {"name": "c"}})
    assert not _looks_like_a_pod_spec({"steps": "not-a-list"})
    assert not _looks_like_a_pod_spec({"replicas": 3})


def test_a_kind_the_registries_do_read_is_held_to_what_its_reader_read(settings: Any) -> None:
    """Flipped by G360, deliberately. This test was `test_a_kind_the_registries_do_read_is_unaffected` and asserted
    the opposite of its last line: that `unread_pod_specs` returns nothing for a kind with a reader, on the
    reasoning that "a `steps` list inside a Deployment is far more likely to be a template for something else than
    a pod kube-noob missed, and for those kinds the registry is the claim".

    The claim was never checked, and that is what was wrong with it. The detector returned `[]` for a registered
    kind by its NAME, so a container the reader did not read was reported by nobody: a privileged container under
    `template.Spec` in a DeploymentConfig, `explainer.alibi` in an InferenceService and a pod spec at an unlisted
    path in a RayCluster each printed a score and gated `passed` (tests/test_a_container_the_reader_did_not_read.py
    holds those). A reader's claim is "I read every container in this object", and it is now compared with what
    the reader read.

    The two halves, on the input this test has always used:

    * the Deployment's own container is read, and a kind the registries read is unaffected while that is all it
      holds -- the half of the old assertion that was right, kept;
    * the `steps` entry beside it declares an image and was read by no rule, so the object is reported as not
      audited. For a Deployment that is a second statement beside KN-V007, whose strict schema already refuses
      the unknown field; for a kind with no bundled schema it is the only statement there is.
    """
    read_in_full = """\
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: prod}
spec:
  replicas: 1
  selector: {matchLabels: {app: web}}
  template:
    metadata: {labels: {app: web}}
    spec:
      containers: [{name: web, image: 'registry.example.com/web:1'}]
"""
    assert _not_audited(read_in_full) == []
    assert engine.analyze(read_in_full).findings, "the Deployment's own container was not audited"

    text = read_in_full + "  steps: [{name: oddly, image: 'docker:24'}]\n"
    assert _not_audited(text) == ["Deployment/prod/web"]
    report = engine.analyze(text)
    assert report.undetermined()
    assert "KN-V007" in {f.rule_id for f in report.findings}, "the strict schema stopped refusing the unknown field"
    assert len(report.findings) > 1, "the Deployment's own container was not audited either"


def test_the_same_input_gives_the_same_answer() -> None:
    first = _not_audited(TEKTON)
    assert first == _not_audited(TEKTON) == ["Task/ci/build"]
