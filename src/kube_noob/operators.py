"""Installed-operator inventory (E2): which OLM operators are installed, at what version, from which catalog and
channel, with what approval mode, in which namespaces and in what phase -- and, as part of the same answer, what
could not be read. An inventory that could not see the OLM objects says "not determined"; it never says "no
operators", because that is the absence-reads-as-a-pass this project exists to refuse.

Three inputs feed one builder: manifest files (``from_manifests``), a must-gather (``kube_noob.mustgather.operators``,
which the Claude plugin does not ship) and the live cluster through the read-only allowlisted backend
(``collect_live``: ClusterServiceVersions and Subscriptions only, never Secrets).

Every field, label and annotation below was read in the source that defines it (the commit is the citation):

- operator-framework/api e1a542ceb01262523627440bde3a0b3387bdeb16
  - ``pkg/operators/v1alpha1/clusterserviceversion_types.go``: ``spec.version`` (an OperatorVersion, semver),
    ``status.phase`` (Pending, InstallReady, Installing, Succeeded, Failed, Unknown, Replacing, Deleting),
    ``status.reason`` Copied (CSVReasonCopied), ``status.message``.
  - ``pkg/operators/v1alpha1/clusterserviceversion.go``: ``CopiedLabelKey = "olm.copiedFrom"``; ``IsCopied`` is
    true for reason Copied, for that label, or for an ``olm.operatorNamespace`` annotation naming another namespace.
  - ``pkg/operators/v1alpha1/subscription_types.go``: ``spec.name`` (the package), ``spec.source``,
    ``spec.sourceNamespace``, ``spec.channel``, ``spec.installPlanApproval`` (Automatic or Manual; absent means
    Automatic, ``GetInstallPlanApproval``), ``status.installedCSV``, ``status.currentCSV``, ``status.state``,
    ``status.installPlanRef``, conditions InstallPlanPending, InstallPlanFailed, InstallPlanMissing,
    ResolutionFailed, BundleUnpackFailed, CatalogSourcesUnhealthy.
  - ``pkg/operators/v1alpha1/installplan_types.go``: ``spec.clusterServiceVersionNames``, ``spec.approval``,
    ``spec.approved``, ``status.phase`` (Planning, RequiresApproval, Installing, Complete, Failed).
  - ``pkg/operators/v1/operatorgroup_types.go``: annotations ``olm.targetNamespaces`` (``BuildTargetNamespaces``:
    ``status.namespaces`` sorted and joined with commas; the empty namespace means all of them) and
    ``olm.operatorNamespace``; ``spec.targetNamespaces``, ``status.namespaces``.
  - ``crds/operators.coreos.com_{clusterserviceversions,subscriptions}.yaml``: group operators.coreos.com, version
    v1alpha1 (served, storage), scope Namespaced, category ``olm``.
- operator-framework/operator-lifecycle-manager f4ec58f8678b04ca27d953db4eb08ed918ed3b18
  - ``pkg/controller/operators/olm/operatorgroup.go`` ``csvCopyPrototype``: a copy carries the label
    ``olm.copiedFrom=<the source namespace>``, ``status.reason`` Copied, the source's spec and status, and no
    ``olm.targetNamespaces`` annotation.
  - ``pkg/controller/operators/olm/operator.go``: OLM itself lists the originals with the selector
    ``!olm.copiedFrom``, which is what a cluster-wide live read here uses.
  - ``pkg/controller/operators/catalog/subscription/state.go``: an InstallPlan in RequiresApproval shows on its
    Subscription as condition InstallPlanPending with reason RequiresApproval, so a live read that has no
    InstallPlans still sees a Manual approval waiting.
  - ``pkg/controller/registry/resolver/projection/properties.go`` and ``steps.go``: the annotation
    ``operatorframework.io/properties``, JSON ``{"properties": [{"type": ..., "value": ...}]}``.
- operator-framework/operator-registry 3f41ded86df8e755d6a51d70f10cd50a489ef4b9 ``alpha/property/property.go``:
  property type ``olm.package`` with value ``{"packageName", "version"}``.

What reads as an answer, and what does not (G270). The verdict is ``listed`` only when every object the answer
needs was read and nothing was skipped. Any of these makes it ``partial`` (or ``not-determined`` when no
ClusterServiceVersion was read at all), and each is named in ``caveats``: a file that could not be read or was
skipped by the reader; a file in an OLM path that held no usable object of that kind; an item in a typed list that is
not an object of that kind; objects past ``MAX_ITEMS``; an object named like an OLM kind from another API group
(ignored, and a caveat); two objects with one name and different content; a Subscription with no status; a namespace
whose Subscriptions were not read. ``no-olm`` needs a 404 on ``operators.coreos.com`` for both live reads, in the
exact words the backends write for a missing resource type, never just "not found".

Joining: a Subscription names its installed CSV in ``status.installedCSV`` and is joined on that alone, to a CSV
that is an original in its own namespace; a copy never stands in for one. ``currentCSV`` is only ever the upgrade
(or install) in flight. One entry per CSV, however many Subscriptions name it.

Safety: Secret objects in the input are dropped unread; only named fields are read (a Subscription's
``spec.config``, which can carry environment values, never is); every string shown is made printable by
``sanitize.visible`` and redacted; names and versions that are not valid are not shown as names or versions. The
output is bounded and sorted, and evidence names an object and its file rather than a document position, so the
same objects in any order give the same bytes; duplicates that disagree are resolved by content and flagged.
"""

from __future__ import annotations
