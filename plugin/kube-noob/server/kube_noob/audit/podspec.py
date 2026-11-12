"""Helpers to locate pod templates and containers inside workload objects."""

from __future__ import annotations

import math
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from kube_noob.yamlio import MAX_DEPTH, Document, PathT, get_path

POD_SPEC_PATHS: dict[str, PathT] = {
    "Pod": ("spec",),
    "Deployment": ("spec", "template", "spec"),
    "StatefulSet": ("spec", "template", "spec"),
    "DaemonSet": ("spec", "template", "spec"),
    "ReplicaSet": ("spec", "template", "spec"),
    "ReplicationController": ("spec", "template", "spec"),
    "Job": ("spec", "template", "spec"),
    "CronJob": ("spec", "jobTemplate", "spec", "template", "spec"),
    "DeploymentConfig": ("spec", "template", "spec"),
    # core/v1 PodTemplate: a pod template on its own, `template.spec` (G272; a must-gather carries them).
    "PodTemplate": ("template", "spec"),
}

#: Kinds that carry one or more pod specs somewhere other than the nine places above, with ``*`` standing for
#: every element of a list (or every value of a mapping). Every path here was read out of the published CRD
#: schema on 2026-11-06, not inferred from a tutorial:
#:
#: * ``serving.kserve.io/v1beta1`` InferenceService -- `predictor`, `transformer` and `explainer` are each a
#:   full PodSpec inline (all of `containers`, `volumes`, `serviceAccountName`, `nodeSelector`, `tolerations`,
#:   `initContainers`, `securityContext`, `hostNetwork`, `hostPID`, `hostIPC`,
#:   `automountServiceAccountToken` appear in the schema), from
#:   config/crd/full/serving.kserve.io_inferenceservices.yaml.
#: * ``ray.io/v1`` and ``v1alpha1`` RayCluster -- `headGroupSpec.template` and each `workerGroupSpecs[].template`
#:   are ordinary PodTemplateSpecs (`metadata` + `spec`), from
#:   helm-chart/kuberay-operator/crds/ray.io_rayclusters.yaml.
#: * RayService wraps the same cluster under `rayClusterConfig`, RayJob under `rayClusterSpec`.
#:
#: Why this exists: without it every pod-level rule in the catalogue returns nothing for these objects. A
#: KServe predictor running privileged, as root, with `hostPath: /` and a mutable tag produced **14 findings
#: as a Deployment and zero as an InferenceService** -- not "not evaluated", clean (G229).
EMBEDDED_POD_SPEC_PATHS: dict[str, tuple[PathT, ...]] = {
    "InferenceService": (
        ("spec", "predictor"),
        ("spec", "predictor", "workerSpec"),
        ("spec", "transformer"),
        ("spec", "explainer"),
        ("spec", "canary", "*", "predictor"),
    ),
    "RayCluster": (
        ("spec", "headGroupSpec", "template", "spec"),
        ("spec", "workerGroupSpecs", "*", "template", "spec"),
    ),
    "RayService": (
        ("spec", "rayClusterConfig", "headGroupSpec", "template", "spec"),
        ("spec", "rayClusterConfig", "workerGroupSpecs", "*", "template", "spec"),
    ),
    "RayJob": (
        ("spec", "rayClusterSpec", "headGroupSpec", "template", "spec"),
        ("spec", "rayClusterSpec", "workerGroupSpecs", "*", "template", "spec"),
        ("spec", "submitterPodTemplate", "spec"),
    ),
}

#: Containers that are a FIELD of a component rather than an entry in its `containers` list, by the pod spec path
#: that holds them. This is the form almost every KServe manifest in the wild uses -- a predictor is written as
#: `model: {modelFormat: ..., storageUri: ...}`, never as `containers: [...]` -- and reading only `containers`
#: left a privileged `model:` container producing 2 findings where the same spec as `containers` produced 11,
#: with every container rule recorded as evaluated-clean on it. Each key below is a full `v1.Container` in the
#: published schema (`image` and `securityContext` among 30+ properties), read from
#: config/crd/full/serving.kserve.io_inferenceservices.yaml on 2026-11-06:
#:
#: * `predictor`: `model`, and the ten framework shorthands it replaced, all still served;
#: * `explainer`: `art`;
#: * `transformer`: none -- it has `containers` only, which is why this registry is keyed by path, not by kind.
#:
#: KubeRay's `autoscalerOptions` is the same shape: a container injected into the head pod.
EMBEDDED_CONTAINER_KEYS: dict[PathT, tuple[str, ...]] = {
    ("spec", "predictor"): (
        "model",
        "huggingface",
        "lightgbm",
        "onnx",
        "paddle",
        "pmml",
        "pytorch",
        "sklearn",
        "tensorflow",
        "triton",
        "xgboost",
    ),
    ("spec", "explainer"): ("art",),
}

#: Containers that live beside a pod spec rather than inside it, as (where the container is, which pod spec it
#: joins). KubeRay injects the autoscaler into the head pod, so a privileged `autoscalerOptions` is a privileged
#: container in that pod and has to be audited as one. Paths from ray.io_ray{clusters,services,jobs}.yaml, v1 and
#: v1alpha1, on 2026-11-06.
INJECTED_CONTAINERS: dict[str, tuple[tuple[PathT, PathT], ...]] = {
    "RayCluster": ((("spec", "autoscalerOptions"), ("spec", "headGroupSpec", "template", "spec")),),
    "RayService": (
        (
            ("spec", "rayClusterConfig", "autoscalerOptions"),
            ("spec", "rayClusterConfig", "headGroupSpec", "template", "spec"),
        ),
    ),
    "RayJob": (
        (
            ("spec", "rayClusterSpec", "autoscalerOptions"),
            ("spec", "rayClusterSpec", "headGroupSpec", "template", "spec"),
        ),
    ),
}

#: Labels the operator puts on the pod, by pod spec path, as a function of the object. These are not a guess: they
#: are written by the controller unconditionally, so they are as true of the running pod as anything in the
#: manifest. KServe's `buildObjectMeta` (pkg/controller/v1beta1/inferenceservice/components/predictor.go, read
#: 2026-11-06) sets the pod's labels to the union of the ServingRuntime's labels, the object's own labels, the
#: component's `labels`, and these two.
KSERVE_COMPONENT_OF: dict[PathT, str] = {
    ("spec", "predictor"): "predictor",
    ("spec", "predictor", "workerSpec"): "predictor",
    ("spec", "transformer"): "transformer",
    ("spec", "explainer"): "explainer",
}

#: The API groups each embedded kind belongs to. A `RayCluster` from some other group is a different object
#: that happens to share a name, and is not read (G227). An object with *no* `apiVersion` is a different case:
#: the live collectors set `kind` from the resource they listed and API list items carry no apiVersion of their
#: own, so a missing group is an unknown, not a contradiction, and the pod specs are read. Refusing it would put
#: the G229 blind spot straight back for every `--live` scan, which is the mistake this registry exists to fix.
EMBEDDED_POD_SPEC_GROUPS: dict[str, frozenset[str]] = {
    "InferenceService": frozenset({"serving.kserve.io"}),
    "RayCluster": frozenset({"ray.io"}),
    "RayService": frozenset({"ray.io"}),
    "RayJob": frozenset({"ray.io"}),
}

LONG_RUNNING_KINDS = frozenset({"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "DeploymentConfig"})

#: Embedded-pod-spec kinds that run a long-lived server, for the rules that ask "is this thing left running and
#: reachable". Deliberately NOT folded into `LONG_RUNNING_KINDS`: the probe and replica rules there would then
#: fire on every InferenceService, and both operators inject their own probes and manage their own replica
#: counts, so those would be false positives. A namespace whose only workloads are these had no NetworkPolicy
#: finding at all, and the rule was recorded as evaluated-clean on it (G231). A RayJob is a job and is excluded.
LONG_RUNNING_EMBEDDED_KINDS = frozenset({"InferenceService", "RayCluster", "RayService"})
REPLICATED_KINDS = frozenset({"Deployment", "StatefulSet", "ReplicaSet", "DeploymentConfig"})


@dataclass
class PodTemplate:
    doc: Document
    spec: dict[str, Any]
    path: PathT
    #: Where this template's own metadata lives, when it has any. `None` means it has none of its own: a KServe
    #: component is a bare PodSpec with no PodTemplateSpec around it, and its labels come from the object plus
    #: what the controller adds (`extra_labels`).
    meta_path: PathT | None = None
    #: Labels the operator puts on this pod on top of whatever the manifest shows (G231).
    extra_labels: dict[str, str] = field(default_factory=dict)
    #: False when `labels()` is a KNOWN SUBSET of the pod's real labels rather than all of them -- an operator
    #: merges in labels from objects that are not in the bundle (a KServe ServingRuntime, KubeRay's own
    #: `ray.io/*` set). The distinction matters in both directions and is why `selector_decides` exists: a
    #: selector satisfied by the subset is satisfied by the whole, so a match is real; a selector the subset
    #: fails might be satisfied by a label we cannot see, so a NON-match proves nothing and must not become a
    #: finding that tells someone their NetworkPolicy protects nothing (G231).
    labels_complete: bool = True

    @property
    def component(self) -> str:
        """Which pod spec this is, for the kinds that carry several: `predictor`, `headGroupSpec`,
        `workerGroupSpecs/0`. Empty for an ordinary workload, which has exactly one and needs no name."""
        if self.doc.kind not in EMBEDDED_POD_SPEC_PATHS:
            return ""
        parts = [str(p) for p in self.path[1:] if p not in ("template", "spec")]
        return "/".join(parts)

    @property
    def template_metadata_path(self) -> PathT | None:
        if self.meta_path is not None:
            return self.meta_path
        return self.path[:-1] + ("metadata",)

    def labels(self) -> dict[str, str]:
        """The labels this pod is known to carry. A subset of the real set when `labels_complete` is False."""
        path = self.template_metadata_path
        out: dict[str, str] = {}
        if path is not None:
            meta = get_path(self.doc.data, path)
            if self.doc.kind == "Pod":
                meta = get_path(self.doc.data, ("metadata",))
            if isinstance(meta, dict) and isinstance(meta.get("labels"), dict):
                out = {str(k): str(v) for k, v in meta["labels"].items()}
        return {**out, **self.extra_labels}


@dataclass
class ContainerRef:
    pod: PodTemplate
    container: dict[str, Any]
    path: PathT
    init: bool
    #: What to call a container that has no `name` of its own. A KServe `model:` block is a container whose name
    #: is the KEY it sits under, and the first version of this synthesised `{"name": key, **c}` -- which is a
    #: COPY, so the fixer's in-place hardening wrote to a dict the document had never seen and silently did
    #: nothing. `container` is always the object as it appears in the document now (G238).
    label: str = ""

    @property
    def name(self) -> str:
        return self.label or str(self.container.get("name", "<unnamed>"))


def operator_supplied_images(doc: Document) -> list[PathT]:
    """The field-shaped containers in this document whose image an operator supplies, not the manifest.

    A KServe predictor written as `model: {modelFormat: {name: sklearn}, storageUri: ...}` -- the canonical
    form, and the one in KServe's own sample -- carries no `image`: the ServingRuntime for that model format
    provides it. KubeRay's `autoscalerOptions` is the same shape. Reporting "this container has no image" on
    those was a HIGH finding on correct manifests, and on the upstream sample (G252), so the rule skips them
    and the report says instead that the image was not read.
    """
    out: list[PathT] = []
    for pt in pod_templates(doc):
        for c in containers(pt):
            if not c.label:
                continue  # an entry in a `containers:` list must carry its own image
            image = c.container.get("image")
            if not isinstance(image, str) or not image.strip():
                out.append(c.path)
    return out


def pod_template(doc: Document) -> PodTemplate | None:
    """The one pod spec of an ordinary workload kind. Kinds that carry several have `pod_templates`."""
    path = POD_SPEC_PATHS.get(doc.kind)
    if path is None:
        return None
    spec = get_path(doc.data, path)
    if not isinstance(spec, dict):
        return None
    return PodTemplate(doc=doc, spec=spec, path=path)


def _expand(data: Any, path: PathT) -> Iterator[PathT]:
    """Every concrete path `path` names, with `*` standing for each index of a list or each key of a mapping."""
    if "*" not in path:
        yield path
        return
    i = path.index("*")
    head, tail = path[:i], path[i + 1 :]
    node = get_path(data, head)
    if isinstance(node, list):
        keys: list[Any] = list(range(len(node)))
    elif isinstance(node, dict):
        # `key=str` because a YAML mapping can hold keys of several types (`1:` is an int, `~:` is None) and
        # `sorted` then raises TypeError, which travelled out of the audit, the scan and the admission webhook
        # as a crash rather than a verdict. The keys themselves are kept; only the ORDER is by their text.
        keys = sorted(node, key=str)
    else:
        return
    for k in keys:
        yield from _expand(data, (*head, k, *tail))


def refused_group(doc: Document) -> str | None:
    """The API group this object declares when that group is not one this reader knows for its kind.

    `None` means the object is read: either the group is right, or there is no group at all (both live
    collectors set only `kind`, and API list items carry no apiVersion, so an absent group is an unknown and not
    a contradiction -- refusing it would restore the G229 blind spot for every `--live` scan).

    Returning the group rather than a bool is what lets the caller SAY so. A `RayCluster` in someone else's group
    produced no findings and no word about why, while a `Deployment` with a made-up group gets KN-V002: the
    refusal was right and refusing in silence is the absence-read-as-pass this work is about (G231).
    """
    groups = EMBEDDED_POD_SPEC_GROUPS.get(doc.kind)
    if groups is None:
        return None
    group = doc.api_version.split("/", 1)[0]
    return group if group and group not in groups else None


def pod_templates(doc: Document) -> list[PodTemplate]:
    """Every pod spec in this object, wherever it lives.

    One for an ordinary workload, several for the kinds in `EMBEDDED_POD_SPEC_PATHS` -- a RayCluster has a head
    and one per worker group, an InferenceService up to three components. Returning a list rather than an
    Optional is the whole point: the previous single-template reader silently found nothing in these kinds, so
    every pod-level rule passed them (G229).
    """
    one = pod_template(doc)
    if one is not None:
        return [one]
    paths = EMBEDDED_POD_SPEC_PATHS.get(doc.kind)
    if paths is None or not isinstance(doc.data, dict):
        return []
    if refused_group(doc) is not None:
        return []  # same kind name, a different API group: a different object (G227)
    out: list[PodTemplate] = []
    for template in paths:
        for path in _expand(doc.data, template):
            spec = get_path(doc.data, path)
            if not isinstance(spec, dict):
                continue
            # A PodTemplateSpec ends in `spec` and has `metadata` beside it. A bare inline PodSpec (a KServe
            # component) has none, and its pod's labels come from the object plus what the controller merges in.
            meta: PathT | None = path[:-1] + ("metadata",) if path[-1] == "spec" else None
            out.append(
                PodTemplate(
                    doc=doc,
                    spec=spec,
                    path=path,
                    meta_path=meta if meta is not None else ("metadata",),
                    extra_labels=_operator_labels(doc, path),
                    # Every one of these kinds has its labels merged by an operator from objects that are not in
                    # the bundle, so what the manifest shows is a subset in all of them (G231).
                    labels_complete=False,
                )
            )
    return out


def _operator_labels(doc: Document, path: PathT) -> dict[str, str]:
    """Labels the controller puts on this pod regardless of the manifest.

    Only the deterministic ones: KServe names the object and the component on every pod it creates, and the
    component's own `labels` block is merged in as well. KubeRay's `ray.io/*` labels are deliberately NOT here --
    their values depend on the group name and the node type in ways the published CRD does not pin down, and a
    guessed label value would be worse than the known subset this returns.
    """
    component = KSERVE_COMPONENT_OF.get(path)
    if component is None or doc.kind != "InferenceService":
        return {}
    out = {"serving.kserve.io/inferenceservice": doc.name, "component": component}
    own = get_path(doc.data, ("spec", component, "labels"))
    if isinstance(own, dict):
        out.update({str(k): str(v) for k, v in own.items()})
    return out


#: Node budget for `unread_pod_specs`. The loader already refuses a document deeper than `MAX_DEPTH` or with more
#: nodes than its own budget, so this walk inherits those bounds and only needs a backstop against pathological
#: breadth. The depth limit is the LOADER's, deliberately: a lower one of its own would have made the detector go
#: quiet on a pod spec nested deeper than it chose to look, which is the silent miss this whole function exists
#: to end -- the first draft set it to 24, four times shallower than a document the loader happily accepts.
_WALK_MAX_NODES = 200_000


def _looks_like_a_pod_spec(node: dict[str, Any]) -> bool:
    """True for a mapping that is a PodSpec in all but name.

    Deliberately narrow: a `containers` list holding at least one mapping with an `image`. That is the shape every
    pod spec has and almost nothing else does, and being narrow is what keeps this from accusing an unrelated CRD
    of hiding pods.
    """
    items = node.get("containers")
    if not isinstance(items, list):
        return False
    return any(isinstance(c, dict) and isinstance(c.get("image"), str) for c in items)


def unread_pod_specs(doc: Document) -> list[PathT]:
    """Every pod-spec-shaped mapping in this object that no reader above would have looked at.

    This is the answer to the question the registries cannot answer: there are far more workload CRDs than four,
    and a pod spec inside a kind with no reader produced no findings, no declined rules and **no word of any
    kind** -- a privileged container in a document that reported clean. Enumerating the CRD universe is not
    possible and guessing a path produces a confident wrong finding, so this does neither: it finds the shape,
    reports that it was not audited, and leaves the verdict to a reader who will be told the gap exists.

    Returns nothing for a kind the registries do read -- there the pod specs are known, and a `containers` list
    somewhere else in such an object is far more likely to be a template for something else than a pod kube-noob
    missed. For those kinds the registry is the claim, and extending it is how a new path gets read.
    """
    if not isinstance(doc.data, dict) or doc.kind in POD_SPEC_PATHS or doc.kind in EMBEDDED_POD_SPEC_PATHS:
        return []
    if refused_group(doc) is not None:
        return []  # already reported as a kind read from the wrong group; one message is enough
    out: list[PathT] = []
    seen = 0
    stack: list[tuple[Any, PathT, int]] = [(doc.data, (), 0)]
    while stack:
        node, path, depth = stack.pop()
        seen += 1
        if seen > _WALK_MAX_NODES or depth > MAX_DEPTH:
            break
        if isinstance(node, dict):
            if _looks_like_a_pod_spec(node):
                out.append(path)
                continue  # its own containers are the finding; no need to walk into them
            for key in sorted(node, key=str):
                stack.append((node[key], (*path, key), depth + 1))
        elif isinstance(node, list):
            for i, item in enumerate(node[:200]):
                stack.append((item, (*path, i), depth + 1))
    return sorted(out)


def containers(pod: PodTemplate, include_init: bool = True, *, ephemeral: bool = True) -> Iterator[ContainerRef]:
    """App containers, then (``include_init``) init containers and, unless ``ephemeral`` is False, ephemeral ones."""
    keys: tuple[str, ...] = ("containers", "initContainers", "ephemeralContainers") if include_init else ("containers",)
    if not ephemeral:
        keys = tuple(k for k in keys if k != "ephemeralContainers")
    for key in keys:
        items = pod.spec.get(key)
        if not isinstance(items, list):
            continue
        for i, c in enumerate(items):
            if isinstance(c, dict):
                yield ContainerRef(pod=pod, container=c, path=(*pod.path, key, i), init=key != "containers")
    # Containers that are a field of the component rather than an entry in a list. `model:` is how a KServe
    # predictor is almost always written, and reading only `containers` passed every container rule on it.
    for key in EMBEDDED_CONTAINER_KEYS.get(pod.path, ()):
        c = pod.spec.get(key)
        if isinstance(c, dict):
            yield ContainerRef(pod=pod, container=c, path=(*pod.path, key), init=False, label=key)
    # Containers the operator injects into this pod from elsewhere in the object (KubeRay's autoscaler).
    for where, joins in INJECTED_CONTAINERS.get(pod.doc.kind, ()):
        if joins != pod.path:
            continue
        c = get_path(pod.doc.data, where)
        if isinstance(c, dict) and ("image" in c or "securityContext" in c):
            yield ContainerRef(pod=pod, container=c, path=where, init=False, label=str(where[-1]))


def replicas(doc: Document) -> int | None:
    if doc.kind not in REPLICATED_KINDS:
        return None
    spec = doc.data.get("spec") if isinstance(doc.data, dict) else None
    if not isinstance(spec, dict):
        return 1
    r = spec.get("replicas", 1)
    return r if isinstance(r, int) else None


def effective_security(pod: PodTemplate, c: ContainerRef, field: str) -> Any:
    """Container securityContext wins over pod securityContext (for fields that exist on both)."""
    csc = c.container.get("securityContext")
    if isinstance(csc, dict) and field in csc:
        return csc[field]
    psc = pod.spec.get("securityContext")
    if isinstance(psc, dict) and field in psc:
        return psc[field]
    return None


def selector_matches(selector: dict[str, Any] | None, labels: dict[str, str]) -> bool:
    """Evaluate a LabelSelector (matchLabels + matchExpressions)."""
    if selector is None:
        return False
    if selector == {}:
        return True
    ml = selector.get("matchLabels") or {}
    if not isinstance(ml, dict):
        return False
    for k, v in ml.items():
        if labels.get(str(k)) != str(v):
            return False
    for expr in selector.get("matchExpressions") or []:
        if not isinstance(expr, dict):
            return False
        key, op, values = str(expr.get("key")), expr.get("operator"), [str(x) for x in expr.get("values") or []]
        if op == "In" and labels.get(key) not in values:
            return False
        if op == "NotIn" and labels.get(key) in values:
            return False
        if op == "Exists" and key not in labels:
            return False
        if op == "DoesNotExist" and key in labels:
            return False
    return True


def selector_decides(selector: dict[str, Any] | None, pod: PodTemplate) -> bool | None:
    """Whether this selector selects this pod: True, False, or None for "cannot tell from this input".

    `selector_matches` answers True or False against a label set taken as complete. For a pod whose labels an
    operator merges from objects outside the bundle, the known set is a subset, and the two answers are not
    equally safe:

    * A positive match on a subset stays a match on the whole, because `matchLabels`, `In` and `Exists` only ever
      require a label to be present -- adding labels cannot break them. So True is returned as True.
    * A `DoesNotExist` or `NotIn` term requires a label to be ABSENT, which an unseen label can falsify. A match
      that depends on one of those is therefore undecided.
    * A non-match is undecided too, unless the contradiction is in a label we can actually see: a selector asking
      for `app=web` fails on the subset and might still match once the operator's labels arrive, but a selector
      asking for `app=web` against a KNOWN `app=api` is a real non-match whatever else is added.

    Returning None rather than False is the whole point. A False here becomes "this policy protects nothing" or
    "this Service has no endpoints" in front of a reader, and saying that about a correct NetworkPolicy because
    an operator sets the label is worse than saying nothing (G231).
    """
    if selector is None:
        return False
    labels = pod.labels()
    matched = selector_matches(selector, labels)
    if pod.labels_complete:
        return matched
    exprs = [e for e in (selector.get("matchExpressions") or []) if isinstance(e, dict)]
    negative = [e for e in exprs if e.get("operator") in {"NotIn", "DoesNotExist"}]
    if matched:
        # A match that rests on a label being absent can be undone by a label we cannot see.
        return None if negative else True
    # A non-match is only certain when a label we can see contradicts the selector.
    for key, value in (selector.get("matchLabels") or {}).items():
        if str(key) in labels and labels[str(key)] != str(value):
            return False
    for e in exprs:
        key, op = str(e.get("key")), e.get("operator")
        values = [str(x) for x in e.get("values") or []]
        if key not in labels:
            continue
        if op == "In" and labels[key] not in values:
            return False
        if op in {"NotIn", "DoesNotExist"}:
            return False  # the key is present, which is what these two forbid
    return None


def _scaled(value: Any, total: int) -> int | None:
    """IntOrString as the disruption controller scales it (percentages round up)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        v = value.strip()
        if v.endswith("%") and v[:-1].isdigit():
            return math.ceil(int(v[:-1]) * total / 100)
        if v.isdigit():
            return int(v)
    return None


def pdb_allows_no_disruption(spec: dict[str, Any], replica_count: int) -> bool:
    """True when a PDB with this spec permits zero voluntary evictions for ``replica_count`` healthy pods."""
    mu = _scaled(spec.get("maxUnavailable"), replica_count)
    if mu is not None:
        return mu <= 0
    ma = _scaled(spec.get("minAvailable"), replica_count)
    return ma is not None and ma >= replica_count
