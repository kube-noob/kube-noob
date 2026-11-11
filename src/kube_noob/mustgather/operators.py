"""The OLM objects of a must-gather, for the installed-operator inventory (``kube_noob.operators``).

openshift/must-gather 6b4d6857e4ad556d702582d7e739898cf7dfb4ca ``collection-scripts/gather_olm`` runs
``oc adm inspect -A olm``: every resource in the ``olm`` category (ClusterServiceVersions, Subscriptions,
InstallPlans and OperatorGroups among them, per the CRDs in operator-framework/api), written as
``namespaces/<ns>/operators.coreos.com/<resource>.yaml`` lists or ``.../<resource>/<name>.yaml`` objects
(``kube_noob.mustgather.ingest`` cites the layout). Reading goes through the analysers' loader, so the same caps, the
same refusal of aliases and deep nesting, and the same parse budget apply; files ``ingest`` did not keep (Secrets)
are never seen. A resource with no file at all is "not in this must-gather", never zero objects.
"""

from __future__ import annotations

from collections import Counter

from kube_noob import operators as ops
from kube_noob.mustgather.analyse import _SUFFIX, _items, _Loader
from kube_noob.mustgather.ingest import Bundle, classify, root_of

GROUP = "operators.coreos.com"
_KIND = {resource: kind for kind, resource in ops.KIND_TO_RESOURCE.items()}


def _route(path: str) -> tuple[str, str] | None:
    """(resource, namespace from the path) for an OLM resource file."""
    found = root_of(path)
    if found is None or classify(path) != "resource":
        return None
    rest = found[1]
    if rest[0] != "namespaces" or len(rest) not in (4, 5) or rest[2] != GROUP:
        return None
    resource = _SUFFIX.sub("", rest[3]) if len(rest) == 4 else rest[3]
    return (resource, rest[1]) if resource in _KIND else None


def collect(bundle: Bundle) -> ops.Collected:
    c = ops.Collected("must-gather")
    loader = _Loader(bundle)
    files: Counter[str] = Counter()
    failed: Counter[str] = Counter()
    for path in sorted(bundle.files):
        routed = _route(path)
        if routed is None:
            continue
        resource, path_ns = routed
        files[resource] += 1
        before = len(loader.unparsed)
        docs = loader.load(path)
        if len(loader.unparsed) > before or (not docs and bundle.files.get(path)):
            failed[resource] += 1
        for doc in docs:
            for item in _items(doc, _KIND[resource]):
                c.add(item, path, path_ns, kind=_KIND[resource])
    c.unreadable = list(loader.unparsed)
    for resource in ops.RESOURCES:
        n = len(c.objects[resource])
        if not files[resource]:
            c.reads[resource] = ops.SourceRead(
                resource=resource,
                state="not-read",
                reason=f"not in this must-gather (namespaces/<ns>/{GROUP}/{resource})",
            )
        elif failed[resource] == files[resource]:
            c.reads[resource] = ops.SourceRead(
                resource=resource, state="not-read", reason=f"none of its {files[resource]} file(s) could be read"
            )
        elif failed[resource]:
            c.reads[resource] = ops.SourceRead(
                resource=resource,
                state="partial",
                objects=n,
                reason=f"{failed[resource]} of {files[resource]} file(s) could not be read",
            )
        else:
            c.reads[resource] = ops.SourceRead(resource=resource, state="read", objects=n)
    return c
