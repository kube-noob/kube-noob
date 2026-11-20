"""The Compliance Operator objects of a must-gather, for ``kube_noob.compliance_results``.

``oc adm inspect ns/openshift-compliance`` -- what the Compliance Operator's own must-gather image collects -- writes
``namespaces/<ns>/compliance.openshift.io/<resource>.yaml`` lists or ``.../<resource>/<name>.yaml`` objects, the same
layout ``kube_noob.mustgather.ingest`` cites for OLM. Reading goes through the analysers' loader, so the same caps,
the same refusal of aliases and deep nesting, and the same parse budget apply.

A file counts as read only when it yields what its path promises: a list of that kind (an empty one is a read of
zero), or at least one usable object of that kind. Everything else is named in ``unreadable`` and makes the answer
undetermined: a file the loader refused, an empty file, a file holding an error message or a Status, an object of
another kind, a compliance file ``ingest`` skipped (a link, a file over its size cap, a name the Secret rule
refuses), and a compliance file outside the layout above. A resource with no file at all is "not in this
must-gather", never zero objects -- and a must-gather with no compliance directory is never "the operator is not
installed", because a bundle cannot prove that.

The Secret rule is deliberately NOT relaxed here. ``ingest.secret_like`` exempts OLM object files because a
ClusterServiceVersion is named after its operator and one is called ``secrets-store-csi-driver-operator``; a
Compliance Operator object is named after a scan, a profile or a ComplianceAsCode rule (``ocp4-``, ``rhcos4-``), so
no exemption is needed and none is granted. A compliance file the rule does refuse is reported as a skipped file and
makes the answer undetermined, which is what a name this reader will not open should cost.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from kube_noob import compliance_results as cr
from kube_noob.mustgather.analyse import _SUFFIX, _Loader
from kube_noob.mustgather.ingest import Bundle, classify, root_of

GROUP = cr.GROUP


def _route(path: str) -> tuple[str, str, bool] | None:
    """(resource, namespace from the path, whether it is a list file) for a compliance file in the layout oc writes."""
    found = root_of(path)
    if found is None or classify(path) != "resource":
        return None
    rest = found[1]
    if rest[0] != "namespaces" or len(rest) not in (4, 5) or rest[2] != GROUP:
        return None
    resource = _SUFFIX.sub("", rest[3]) if len(rest) == 4 else rest[3]
    return (resource, rest[1], len(rest) == 4) if resource in cr.RESOURCE_TO_KIND else None


def _compliance_resource(path: str) -> str | None:
    """The compliance resource a path looks like it holds, in any spelling or depth -- for telling a skipped or
    misplaced compliance file from a file that has nothing to do with the operator."""
    found = root_of(path)
    if found is None:
        return None
    rest = found[1]
    if rest[0] != "namespaces" or len(rest) < 4 or rest[2].lower() != GROUP:
        return None
    # Any component under the group, not only the one the layout puts the resource in: a file two directories
    # deeper is still a compliance file somebody collected, and the layout check above has already refused it, so
    # looking at rest[3] alone passed it over in silence (review class 21 -- the neighbour of the misplaced file).
    for part in rest[3:]:
        resource = _SUFFIX.sub("", part.lower())
        if resource in cr.RESOURCE_TO_KIND:
            return resource
    return None


def _read_file(c: cr.Collected, docs: list[Any], resource: str, path: str, path_ns: str, is_list: bool) -> str:
    """Add what one file holds; returns why it did not count as a read, or "" when it did."""
    kind = cr.RESOURCE_TO_KIND[resource]
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
            for item in items[: cr.MAX_ITEMS]:
                kept += c.add(item, path, path_ns, expect=kind)
            c.overflow(resource, len(items) - cr.MAX_ITEMS)
        else:
            kept += c.add(doc, path, path_ns, expect=kind)
    if not docs:
        return "empty, or holds no YAML document (not read)"
    if c.rejected[resource] > rejected_before and not kept:
        return f"holds no usable {kind} (not read)"
    if not kept and not listed:
        return f"holds no {kind} (not read)"
    return ""


def collect(bundle: Bundle) -> cr.Collected:
    c = cr.Collected("must-gather")
    loader = _Loader(bundle)
    files: Counter[str] = Counter()
    failed: Counter[str] = Counter()
    unreadable: list[dict[str, str]] = []

    def gap(resource: str, path: str, reason: str, counted: bool = False) -> None:
        failed[resource] += 1
        files[resource] += 0 if counted else 1
        unreadable.append({"path": cr._text(path, 300), "reason": reason})

    for path in sorted(bundle.files):
        routed = _route(path)
        if routed is None:
            looks = _compliance_resource(path)
            if looks is not None:
                gap(looks, path, "a compliance file outside the layout oc adm inspect writes (not read)")
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
        looks = _compliance_resource(path)
        if looks is not None:
            gap(looks, path, f"skipped by the must-gather reader: {reason}")
    if bundle.skipped_unlisted:
        unreadable.append(
            {
                "path": f"<{bundle.skipped_unlisted} more skipped files>",
                "reason": "skipped past the number of paths kept, so whether any held compliance objects is not known",
            }
        )
    c.unreadable = unreadable
    for resource in cr.RESOURCES:
        n = len(c.objects[resource])
        ok = files[resource] - failed[resource]
        gaps = c.rejected[resource] + c.dropped[resource]
        if not files[resource]:
            c.reads[resource] = cr.SourceRead(
                resource=resource,
                state="not-read",
                reason=f"not in this must-gather (namespaces/<ns>/{GROUP}/{resource})",
            )
        elif ok <= 0:
            c.reads[resource] = cr.SourceRead(
                resource=resource, state="not-read", reason=f"none of its {files[resource]} file(s) could be read"
            )
        elif failed[resource] or gaps:
            parts = [f"{failed[resource]} of {files[resource]} file(s) could not be read"] if failed[resource] else []
            if gaps:
                parts.append(f"{gaps} object(s) not usable or past the read cap")
            c.reads[resource] = cr.SourceRead(resource=resource, state="partial", objects=n, reason="; ".join(parts))
        else:
            c.reads[resource] = cr.SourceRead(resource=resource, state="read", objects=n)
    return c
