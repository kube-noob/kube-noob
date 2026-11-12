"""The OLM objects of a must-gather, for the installed-operator inventory (``kube_noob.operators``).

openshift/must-gather 6b4d6857e4ad556d702582d7e739898cf7dfb4ca ``collection-scripts/gather_olm`` runs
``oc adm inspect -A olm``: every resource in the ``olm`` category (ClusterServiceVersions, Subscriptions,
InstallPlans and OperatorGroups among them, per the CRDs in operator-framework/api), written as
``namespaces/<ns>/operators.coreos.com/<resource>.yaml`` lists or ``.../<resource>/<name>.yaml`` objects
(``kube_noob.mustgather.ingest`` cites the layout). Reading goes through the analysers' loader, so the same caps, the
same refusal of aliases and deep nesting, and the same parse budget apply.

A file counts as read only when it yields what its path promises: a list of that kind (an empty one is a read of
zero), or at least one usable object of that kind. Everything else is named in ``unreadable`` and makes the answer
partial: a file the loader refused, an empty file, a file holding an error message or a Status, an object of
another kind, an OLM file ``ingest`` skipped (a link, a file over its size cap), and an OLM file outside the layout
above. A resource with no file at all is "not in this must-gather", never zero objects.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from kube_noob import operators as ops
from kube_noob.mustgather.analyse import _SUFFIX, _Loader
from kube_noob.mustgather.ingest import Bundle, classify, root_of

GROUP = "operators.coreos.com"


def _route(path: str) -> tuple[str, str, bool] | None:
    """(resource, namespace from the path, whether it is a list file) for an OLM file in the layout oc writes."""
    found = root_of(path)
    if found is None or classify(path) != "resource":
        return None
    rest = found[1]
    if rest[0] != "namespaces" or len(rest) not in (4, 5) or rest[2] != GROUP:
        return None
    resource = _SUFFIX.sub("", rest[3]) if len(rest) == 4 else rest[3]
    return (resource, rest[1], len(rest) == 4) if resource in ops.RESOURCE_TO_KIND else None


def _olm_resource(path: str) -> str | None:
    """The OLM resource a path looks like it holds, in any spelling or depth -- for telling a skipped or misplaced
    OLM file from a file that has nothing to do with OLM."""
    found = root_of(path)
    if found is None:
        return None
    rest = found[1]
    if rest[0] != "namespaces" or len(rest) < 4 or rest[2].lower() != GROUP:
        return None
    resource = _SUFFIX.sub("", rest[3].lower())
    return resource if resource in ops.RESOURCE_TO_KIND else None


def _read_file(c: ops.Collected, docs: list[Any], resource: str, path: str, path_ns: str, is_list: bool) -> str:
    """Add what one file holds; returns why it did not count as a read, or "" when it did."""
    kind = ops.RESOURCE_TO_KIND[resource]
    rejected_before = c.rejected[resource]
    kept = 0
    listed = False
    for doc in docs:
        if not isinstance(doc, dict):
            c.rejected[resource] += 1
            continue
        stated = str(doc.get("kind") or "")
        if is_list and stated in (f"{kind}List", "List"):
            items = doc.get("items")
            if not isinstance(items, list):
                c.rejected[resource] += 1
                continue
            listed = True
            for item in items[: ops.MAX_ITEMS]:
                kept += c.add(item, path, path_ns, expect=kind)
            c.overflow(resource, len(items) - ops.MAX_ITEMS)
        else:
            kept += c.add(doc, path, path_ns, expect=kind)
    if not docs:
        return "empty, or holds no YAML document (not read)"
    if c.rejected[resource] > rejected_before and not kept:
        return f"holds no usable {kind} (not read)"
    if not kept and not listed:
        return f"holds no {kind} (not read)"
    return ""


def collect(bundle: Bundle) -> ops.Collected:
    c = ops.Collected("must-gather")
    loader = _Loader(bundle)
    files: Counter[str] = Counter()
    failed: Counter[str] = Counter()
    unreadable: list[dict[str, str]] = []

    def gap(resource: str, path: str, reason: str, counted: bool = False) -> None:
        """A file of ``resource`` that is not a read; ``counted`` when it was already counted as one of its files."""
        failed[resource] += 1
        files[resource] += 0 if counted else 1
        unreadable.append({"path": ops._text(path, 300), "reason": reason})

    for path in sorted(bundle.files):
        routed = _route(path)
        if routed is None:
            looks = _olm_resource(path)
            if looks is not None:
                gap(looks, path, "an OLM file outside the layout oc adm inspect writes (not read)")
            continue
        resource, path_ns, is_list = routed
        files[resource] += 1
        before = len(loader.unparsed)
        docs = loader.load(path)
        if len(loader.unparsed) > before:
            failed[resource] += 1
            unreadable += [{"path": u["path"], "reason": u["reason"]} for u in loader.unparsed[before:]]
            continue
        if not bundle.files.get(path):
            gap(resource, path, "an empty file (not read)", counted=True)
            continue
        why = _read_file(c, [d for d in docs if d is not None], resource, path, path_ns, is_list)
        if why:
            gap(resource, path, why, counted=True)
    for path, reason in sorted(bundle.skipped_paths):
        looks = _olm_resource(path)
        if looks is not None:
            gap(looks, path, f"skipped by the must-gather reader: {reason}")
    if bundle.skipped_unlisted:
        unreadable.append(
            {
                "path": f"<{bundle.skipped_unlisted} more skipped files>",
                "reason": "skipped past the number of paths kept, so whether any held OLM objects is not known",
            }
        )
    c.unreadable = unreadable
    for resource in ops.RESOURCES:
        n = len(c.objects[resource])
        ok = files[resource] - failed[resource]
        gaps = c.rejected[resource] + c.dropped[resource]
        if not files[resource]:
            c.reads[resource] = ops.SourceRead(
                resource=resource,
                state="not-read",
                reason=f"not in this must-gather (namespaces/<ns>/{GROUP}/{resource})",
            )
        elif ok <= 0:
            c.reads[resource] = ops.SourceRead(
                resource=resource, state="not-read", reason=f"none of its {files[resource]} file(s) could be read"
            )
        elif failed[resource] or gaps:
            parts = [f"{failed[resource]} of {files[resource]} file(s) could not be read"] if failed[resource] else []
            if gaps:
                parts.append(f"{gaps} object(s) not usable or past the read cap")
            c.reads[resource] = ops.SourceRead(resource=resource, state="partial", objects=n, reason="; ".join(parts))
        else:
            c.reads[resource] = ops.SourceRead(resource=resource, state="read", objects=n)
    return c
