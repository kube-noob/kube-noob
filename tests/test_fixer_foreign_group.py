"""The fixer rewrote valid third-party resources into built-in ones, and the audit said the opposite.

`kube-noob fix` corrects an apiVersion when the kind is one this tool knows and the version is not one it is
served under. That is right for a typo. It made no distinction between a wrong VERSION inside a group this tool
serves and somebody else's CRD that happens to share a kind name, so it turned valid manifests into broken ones:

    projectcalico.org/v3 NetworkPolicy  ->  networking.k8s.io/v1   (spec is `selector: app == 'web'`)
    serving.knative.dev/v1 Service      ->  v1
    batch.volcano.sh/v1alpha1 Job       ->  batch/v1
    stable.example.com/v1 CronJob       ->  batch/v1               (the Kubernetes docs' own CRD example)

Through `protocol`, where `apply_fixes` is the default, that silently handed back a broken core Service carrying
a new HIGH finding of its own -- the tool manufacturing the defect it then reported.

The audit already drew this line and the fixer contradicted it: on the same Calico file `audit` says "apiVersion
names a group kube-noob does not know NetworkPolicy under" and withholds the verdict, while the fixer called
that same unknown a typo. Two answers to one question about one object, which is review class 9; and an unknown
read as a thing to correct, which is this product's own rule inverted.

`refusal` is the one predicate, so there is no second list to drift -- narrowed to a group no rule in this tool
reads any kind under, read off the same `SUBJECT_GROUPS` table. `apps.openshift.io/v1 Route` is deliberately on
the other side of that line: `apps.openshift.io` is a group kube-noob serves (`DeploymentConfig` lives there), so
a `Route` under it is a typo in the group of a real OpenShift kind and the rewrite leaves a valid manifest. The
repository's own `bad-bundle.yaml` carries that case and expects it fixed.
"""

from __future__ import annotations

from typing import Any

import pytest

from kube_noob.audit import fixer
from kube_noob.audit.rules import refusal
from kube_noob.yamlio import dump_documents, load_documents

#: Valid resources of other products whose kind name collides with a built-in. Rewriting any of these is wrong.
FOREIGN = {
    "calico": "apiVersion: projectcalico.org/v3\nkind: NetworkPolicy\nmetadata: {name: web, namespace: prod}\n"
    "spec: {selector: \"app == 'web'\", ingress: [{action: Allow}]}\n",
    "knative": "apiVersion: serving.knative.dev/v1\nkind: Service\nmetadata: {name: hello, namespace: prod}\n"
    "spec: {template: {spec: {containers: [{image: 'ghcr.io/example/hello:1'}]}}}\n",
    "volcano": "apiVersion: batch.volcano.sh/v1alpha1\nkind: Job\nmetadata: {name: j, namespace: prod}\n"
    "spec: {minAvailable: 1, tasks: []}\n",
    # The Kubernetes documentation's own CustomResourceDefinition example.
    "docs-crd": "apiVersion: stable.example.com/v1\nkind: CronJob\nmetadata: {name: c, namespace: prod}\n"
    "spec: {cronSpec: '* * * * */5', image: my-awesome-cron-image}\n",
}

#: A wrong version INSIDE a group this tool serves. This is the typo the rewrite exists for and must keep fixing.
TYPOS = {
    "networking.k8s.io/v1beta9 NetworkPolicy": (
        "apiVersion: networking.k8s.io/v1beta9\nkind: NetworkPolicy\nmetadata: {name: p, namespace: prod}\n"
        "spec: {podSelector: {}}\n",
        "networking.k8s.io/v1",
    ),
    "extensions/v1beta1 Ingress": (
        "apiVersion: extensions/v1beta1\nkind: Ingress\nmetadata: {name: i, namespace: prod}\n"
        "spec: {backend: {serviceName: web, servicePort: 80}}\n",
        "networking.k8s.io/v1",
    ),
}


#: A typo in the GROUP of a real kind, inside a group this tool does read other kinds under. `refusal` refuses
#: these too, so they are what narrows the guard: `apps.openshift.io` serves `DeploymentConfig`, so a `Route`
#: under it cannot be somebody's CRD collision, the spec survives the rewrite, and `bad-bundle.yaml` -- the
#: repository's own fixture, asserted by `tests/test_audit.py::test_fixer_resolves_blockers` -- expects it fixed.
GROUP_TYPOS = {
    "apps.openshift.io/v1 Route": (
        "apiVersion: apps.openshift.io/v1\nkind: Route\nmetadata: {name: web, namespace: shop}\n"
        "spec: {to: {kind: Service, name: web}}\n",
        "route.openshift.io/v1",
    ),
}


def _fixed(text: str) -> tuple[str, Any]:
    out = fixer.fix_manifests(text)
    return dump_documents(out.documents), out


@pytest.mark.parametrize("name", sorted(FOREIGN))
def test_a_kind_under_a_group_this_tool_does_not_serve_is_left_alone(name: str) -> None:
    """The regression. Every one of these came back as a built-in, and three of the four are then invalid."""
    text = FOREIGN[name]
    before = str(load_documents(text)[0].data["apiVersion"])
    after_text, result = _fixed(text)
    assert f"apiVersion: {before}" in after_text, f"{name}: the apiVersion was rewritten"
    assert not [c for c in (result.changes or []) if getattr(c, "rule_id", "") == "KN-V002"], name


@pytest.mark.parametrize("name", sorted(FOREIGN))
def test_the_reader_is_told_why_the_rewrite_was_declined(name: str) -> None:
    """Silence would be the other failure: a caller who asked for a fix and got none needs to know the tool
    looked and declined, and on what grounds, with the served apiVersion still named in case they disagree."""
    _, result = _fixed(FOREIGN[name])
    said = [m for m in (result.manual or []) if "was not rewritten" in m]
    assert len(said) == 1, result.manual
    assert "does not know" in said[0]
    assert "no rule in kube-noob reads any kind under" in said[0]
    assert "custom resource that shares a built-in's name" in said[0]


@pytest.mark.parametrize("name", sorted(TYPOS))
def test_a_wrong_version_inside_a_served_group_is_still_fixed(name: str) -> None:
    """The direction that decides whether this is a fix or a lobotomy. These are real typos and the rewrite is
    the feature; a guard that refused them would have removed it."""
    text, want = TYPOS[name]
    after_text, _ = _fixed(text)
    assert f"apiVersion: {want}" in after_text, name


@pytest.mark.parametrize("name", sorted(FOREIGN))
def test_the_fixer_and_the_audit_now_agree(name: str) -> None:
    """Class 9 stated directly: the audit refuses these objects, so the fixer may not treat them as corrigible.
    One predicate, asserted from both sides, so a change to `refusal` moves them together."""
    doc = load_documents(FOREIGN[name])[0]
    assert refusal(doc) is not None, f"{name}: the audit does not refuse it, so this test proves nothing"
    _, result = _fixed(FOREIGN[name])
    assert not [c for c in (result.changes or []) if getattr(c, "rule_id", "") == "KN-V002"]


@pytest.mark.parametrize("name", sorted(TYPOS))
def test_the_audit_does_not_refuse_a_genuine_typo(name: str) -> None:
    """The other half of the same predicate, so the pair cannot silently become vacuous."""
    assert refusal(load_documents(TYPOS[name][0])[0]) is None, name


def test_the_fixed_output_is_still_the_same_document(tmp_path: Any) -> None:
    """A declined rewrite must not drop or reorder anything else: the file comes back as it went in."""
    text = FOREIGN["calico"]
    after_text, _ = _fixed(text)
    before_doc = load_documents(text)[0].data
    after_doc = load_documents(after_text)[0].data
    assert after_doc == before_doc


@pytest.mark.parametrize("name", sorted(GROUP_TYPOS))
def test_a_typo_the_audit_refuses_is_still_fixed_when_the_group_is_one_this_tool_reads(name: str) -> None:
    """The narrowing, asserted from the table rather than from a hand-written list. `refusal` refusing an object
    is not on its own a reason to decline the rewrite; a group no rule reads any kind under is."""
    from kube_noob.audit.rules import SUBJECT_GROUPS
    from kube_noob.catalog import api_group

    served = {g for v in SUBJECT_GROUPS.values() for g in v}
    text, want = GROUP_TYPOS[name]
    assert api_group(str(load_documents(text)[0].data["apiVersion"])) in served, name
    after_text, result = _fixed(text)
    assert f"apiVersion: {want}" in after_text, name
    assert not [m for m in (result.manual or []) if "was not rewritten" in m], name


@pytest.mark.parametrize("name", sorted(FOREIGN))
def test_no_rule_reads_any_kind_under_these_groups(name: str) -> None:
    """The other side of the same table, so the pair cannot both drift in one direction."""
    from kube_noob.audit.rules import SUBJECT_GROUPS
    from kube_noob.catalog import api_group

    served = {g for v in SUBJECT_GROUPS.values() for g in v}
    assert api_group(str(load_documents(FOREIGN[name])[0].data["apiVersion"])) not in served, name
