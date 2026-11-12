"""Blast radius: if THIS workload is compromised, what can it reach? (moat item V3, G273). Read-only, tier R.

Anchored on one workload (``Kind/namespace/name``), it returns what an attacker running code in its pods gets: the
ServiceAccount whose token they hold, the bindings that name that account (directly, or through the groups
``system:serviceaccounts``, ``system:serviceaccounts:<ns>`` and ``system:authenticated``), what each lets it do, the
Secrets it may read by RBAC or reach by creating a pod (by name or by scope -- Secret objects are never read), the
node when a pod spec can escape to it, which namespaces or the whole cluster that covers, and how it is exposed. A
Pod in the input is answered from its own spec, with its owner chain as context, because the Pod is what runs.

It is not a second model. Every edge comes from :mod:`kube_noob.attack_paths` -- the same entries, the same RBAC
reading, the same capabilities, the same document order -- and each carries the evidence line ``posture scan``
prints for that step, plus the object and the field that prove it.

What the input cannot show is part of the answer, never an empty list read as "nothing". Each leg (exposure, token,
rbac, secrets, node) is ``reached``, ``none`` or ``not determined``, and a not-determined cause that the input names
is a node with its reason: a ServiceAccount, Role or aggregated ClusterRole the input does not carry, a stand-in for
a built-in role, a duplicated name, a field that is not the shape the API requires, a bound rule this module does
not classify, a projected token for another audience, a list a live read was refused. A set of files cannot prove
that no other binding or Service exists, so for file input ``none`` is only said of a leg the pod spec itself
decides, and ``complete`` stays false, unless the caller asserts the files are the whole bundle (``whole_bundle``).

The graph is bounded in nodes, edges and bytes. The summary is computed before anything is cut; truncation keeps the
highest-weight capabilities, the node escape and the gaps first and a binding only where something kept needs it,
and the document says how much it withheld. A reference that matches nothing, or more than one object, is an error.

The Mermaid rendering is derived from the JSON graph and nothing else. Every label is escaped: an object name is
input, and a name carrying a quote, a bracket, ``%%`` or a newline could otherwise close a label and add a ``click``
handler or an ``init`` directive to the diagram. Entity codes (``#35;``) are Mermaid's documented escape
(https://mermaid.js.org/syntax/flowchart.html#entity-codes-to-escape-characters, read 2026-11-11).
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from typing import Any

from kube_noob import attack_paths as ap

SCHEMA_ID = "kube-noob/blast-radius"
SCHEMA_VERSION = 1
MAX_NODES = 120
MAX_EDGES = 200
#: The whole document, serialised. An MCP caller holds the result in its context: a cap on nodes alone let 200
#: bindings with 2,300-character names return 1.67 MB (G273).
MAX_BYTES = 96_000
MAX_STRING = 1_000  # any one string in the document; longer ones keep a hash so they stay distinct
MAX_LISTED = 20  # paths and exposures carried along
MAX_NAMED = 10  # unclassified rules named in one reason
MAX_LABEL = 240
_CAP_LIMIT = 10_000

#: Edge kinds, in the order the graph reads from the workload outwards. A fixed vocabulary: the Mermaid renderer
#: refuses any other, so an edge label can never carry input.
EDGE_KINDS: tuple[str, ...] = (
    "uses token of",
    "bound by",
    "grants",
    "can read",
    "escapes through",
    "reaches",
    "not determined",
)
NODE_TYPES: tuple[str, ...] = (
    "workload",
    "undetermined",
    "serviceaccount",
    "binding",
    "capability",
    "scope",
    "secret",
)
LEGS = ("exposure", "token", "rbac", "secrets", "node")
STATUSES = ("reached", "none", "not determined")

_DNS = r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?"
_REF = re.compile(
    r"(?P<kind>[A-Za-z][A-Za-z0-9]{0,62})/(?:(?P<ns>" + _DNS + r")/)?(?P<name>[A-Za-z0-9][A-Za-z0-9._:-]{0,252})"
    r"(?:\[(?P<component>[A-Za-z0-9/_.-]{1,128})\])?\Z"
)
_NAMESPACE = re.compile(_DNS + r"\Z")
_ALIASES = {
    "deploy": "Deployment",
    "po": "Pod",
    "sts": "StatefulSet",
    "ds": "DaemonSet",
    "rs": "ReplicaSet",
    "cj": "CronJob",
    "dc": "DeploymentConfig",
    "isvc": "InferenceService",
}
_PLURAL = {kind: plural for plural, kind in ap.LIVE_RESOURCES.items()}
_EXPOSURE_READS = ("services", "routes", "ingresses")

_EVIDENCE = {
    "type": "object",
    "additionalProperties": False,
    "required": ["object", "field", "text"],
    "properties": {
        "object": {"type": "string"},
        "field": {"type": ["string", "null"]},
        "text": {"type": "string"},
    },
}
_STR_LIST = {"type": "array", "items": {"type": "string"}}
#: The document's JSON Schema. `schemaVersion` changes when a consumer would have to change; fields are added,
#: never renamed.
SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://kube-noob.com/schemas/blast-radius-v1.json",
    "title": "kube-noob blast radius",
    "type": "object",
    "additionalProperties": False,
    "required": [
        "schema",
        "schemaVersion",
        "anchor",
        "summary",
        "complete",
        "completeness",
        "legs",
        "nodes",
        "edges",
        "notDetermined",
        "truncated",
        "exposure",
        "paths",
        "pathsWithheld",
        "notRead",
        "secretsIgnored",
        "limitations",
    ],
    "properties": {
        "schema": {"const": SCHEMA_ID},
        "schemaVersion": {"const": SCHEMA_VERSION},
        "anchor": {
            "type": "object",
            "additionalProperties": False,
            "required": ["query", "object", "resolved", "via", "ownerDiffers"],
            "properties": {
                "query": {"type": "string"},
                "object": {"type": "string"},
                "resolved": {"type": "array", "minItems": 1, "items": {"type": "string"}},
                "via": {"type": "array", "minItems": 1, "items": {"type": "string"}},
                "ownerDiffers": _STR_LIST,
            },
        },
        "summary": {"type": "string"},
        "complete": {"type": "boolean"},
        "completeness": {"type": "string"},
        "legs": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["workload", "leg", "status", "detail"],
                "properties": {
                    "workload": {"type": "string"},
                    "leg": {"enum": list(LEGS)},
                    "status": {"enum": list(STATUSES)},
                    "detail": {"type": "string"},
                },
            },
        },
        "nodes": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["id", "type", "label"],
                "properties": {
                    "id": {"type": "string"},
                    "type": {"enum": list(NODE_TYPES)},
                    "label": {"type": "string"},
                    "scope": {"type": "string"},
                    "weight": {"type": "integer", "minimum": 0, "maximum": 10},
                    "leg": {"enum": list(LEGS)},
                    "reason": {"type": "string"},
                },
                "if": {"properties": {"type": {"const": "undetermined"}}},
                "then": {"required": ["leg", "reason"]},
            },
        },
        "edges": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["id", "from", "to", "kind", "evidence"],
                "properties": {
                    "id": {"type": "string"},
                    "from": {"type": "string"},
                    "to": {"type": "string"},
                    "kind": {"enum": list(EDGE_KINDS)},
                    "evidence": _EVIDENCE,
                },
            },
        },
        "notDetermined": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["id", "leg", "from", "reason", "inGraph"],
                "properties": {
                    "id": {"type": "string"},
                    "leg": {"enum": list(LEGS)},
                    "from": {"type": "string"},
                    "reason": {"type": "string"},
                    "inGraph": {"type": "boolean"},
                },
            },
        },
        "truncated": {
            "oneOf": [
                {"type": "null"},
                {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "nodesWithheld",
                        "edgesWithheld",
                        "notDeterminedWithheld",
                        "stringsClipped",
                        "maxNodes",
                        "maxEdges",
                        "maxBytes",
                    ],
                    "properties": {
                        "nodesWithheld": {"type": "integer", "minimum": 0},
                        "edgesWithheld": {"type": "integer", "minimum": 0},
                        "notDeterminedWithheld": {"type": "integer", "minimum": 0},
                        "stringsClipped": {"type": "integer", "minimum": 0},
                        "maxNodes": {"type": "integer", "minimum": 1},
                        "maxEdges": {"type": "integer", "minimum": 1},
                        "maxBytes": {"type": "integer", "minimum": 1},
                    },
                },
            ]
        },
        "exposure": {"type": "array", "items": {"type": "object"}},
        "paths": {"type": "array", "items": {"type": "object"}},
        "pathsWithheld": {"type": "integer", "minimum": 0},
        "notRead": _STR_LIST,
        "secretsIgnored": {"type": "integer", "minimum": 0},
        "limitations": _STR_LIST,
    },
}

LIMITATIONS: tuple[str, ...] = (
    *ap.STANDING_LIMITATIONS,
    "hostPort is not a node escape: it opens the pod on the node's network, which is an exposure.",
    "Only the escalation rights the Kubernetes RBAC good-practices page names are ranked; any other bound rule "
    "that is not a plain read is reported as not classified.",
)
_FILE_INPUT = (
    "File input: a set of files cannot show the bindings, Services, Routes or Ingresses it leaves out, so "
    "'none' is said only of what the pod spec decides and the answer is not complete. Pass --whole-bundle "
    "(whole_bundle) to assert the files are everything that applies to this workload."
)
_WHOLE_BUNDLE = "File input asserted to be the whole bundle: an absence in it is taken as an answer."
_LIVE = "Live read: what the account could list is the cluster's answer; a refused or limited read is not determined."


class ReachError(ValueError):
    """The anchor names nothing in the input, or more than one object, or the request is out of bounds."""


# --- the anchor ----------------------------------------------------------------------------------------------------


def _workload_kind(kind: str) -> str | None:
    low = kind.lower()
    if low in _ALIASES:
        return _ALIASES[low]
    for k in sorted(ap.WORKLOAD_KINDS):
        if low in {k.lower(), k.lower() + "s"}:
            return k
    return None


def _failed_reads(inv: ap.Inventory, *resources: str) -> list[str]:
    return sorted({n for n in inv.not_read for r in resources if n.startswith((f"{r}:", f"{r} in "))})


def _resolve(
    inv: ap.Inventory, query: str, namespace: str | None, namespaces_read: list[str] | None = None
) -> tuple[dict[str, Any], str, list[str], dict[str, Any] | None, str]:
    """(the object to score, component, its owner chain, its top owner when it is a Pod). Raises ReachError when it
    names nothing or more than one object."""
    if not isinstance(query, str) or len(query) > 512:
        raise ReachError("the workload reference must be Kind/name or Kind/namespace/name, at most 512 characters")
    m = _REF.match(query)
    if m is None:
        raise ReachError(
            f"not a workload reference: {query[:80]!r}. Use Kind/name with a namespace (deployment/web -n shop) or "
            "Kind/namespace/name as posture scan prints it (Deployment/shop/web)"
        )
    if namespace is not None and not _NAMESPACE.match(namespace):
        raise ReachError(f"not a namespace name: {namespace[:80]!r}")
    if m["ns"] and namespace and m["ns"] != namespace:
        raise ReachError(f"{query} names namespace {m['ns']}, and the namespace given is {namespace}")
    ns = m["ns"] or namespace or "default"
    kind = _workload_kind(m["kind"])
    if kind is None:
        raise ReachError(
            f"{m['kind']} is not a workload kind kube-noob reads; name the object that runs the pods "
            f"({', '.join(sorted(ap.WORKLOAD_KINDS))})"
        )
    name = m["name"]
    found = [o for o in inv.of(kind) if ap.object_namespace(o) == ns and ap.object_name(o) == name]
    if not found:
        hint = ""
        refused = _failed_reads(inv, _PLURAL.get(kind, ""))
        if namespaces_read and ns not in namespaces_read:
            hint = f" -- namespace {ns} was not read (read: {', '.join(sorted(namespaces_read))})"
        elif refused:
            # A refused list is not an empty one: say so, rather than "no such object" alone (G273).
            hint = f" -- and that list was not read ({'; '.join(refused[:3])})"
        elif kind == "Pod":
            owners = sorted(
                ap.object_ref(o)
                for o in inv.of(*ap.WORKLOAD_KINDS)
                if ap.object_namespace(o) == ns and o.get("kind") != "Pod" and name.startswith(ap.object_name(o) + "-")
            )
            if owners:
                hint = (
                    f". A Pod's name is its owner's plus a generated suffix and the Pod is not in the input: name "
                    f"the owner ({', '.join(owners[:5])}), or add the Pod to the input"
                )
        else:
            same = sorted(ap.object_name(o) for o in inv.of(kind) if ap.object_namespace(o) == ns)
            if same:
                hint = f" ({kind} objects in {ns}: {', '.join(same[:5])}{' ...' if len(same) > 5 else ''})"
        raise ReachError(f"no {kind} named {name} in namespace {ns} in the input{hint}")
    distinct = {ap.canonical_form(o) for o in found}
    if len(distinct) > 1:
        # The API keeps one object per name; the input carries several, and which one runs is not in it. Picking
        # by sort order answered for a benign Deployment while a privileged one of the same name went unread.
        raise ReachError(
            f"{len(distinct)} different {kind} objects named {ns}/{name} are in the input; which one the cluster "
            "runs is not known. Remove the duplicate, or scan the files separately"
        )
    obj = found[0]
    chain = [ap.object_ref(obj)]
    by_name: dict[tuple[str, str, str], dict[str, dict[str, Any]]] = {}
    for o in inv.of(*ap.WORKLOAD_KINDS):
        oref = (str(o.get("kind")), ap.object_namespace(o), ap.object_name(o))
        by_name.setdefault(oref, {})[ap.canonical_form(o)] = o
    top: dict[str, Any] | None = None
    ambiguous = ""
    cur = obj
    for _ in range(8):
        oref3 = next(
            (
                k
                for r in ap.controller_refs(cur)
                if (k := (str(r.get("kind")), ap.object_namespace(cur), str(r.get("name")))) in by_name
            ),
            None,
        )
        if oref3 is None:
            break
        if len(by_name[oref3]) > 1:
            # The owner is duplicated: which one owns the Pod is not in the input, so there is nothing to compare
            # with and nothing to resolve to.
            ambiguous = (
                f"{len(by_name[oref3])} different {oref3[0]} objects named {oref3[1]}/{oref3[2]} are in the input"
            )
            chain.append(f"{oref3[0]}/{oref3[1]}/{oref3[2]} (ambiguous)")
            break
        owner = next(iter(by_name[oref3].values()))
        if ap.object_ref(owner) in chain:
            break
        cur = owner
        chain.append(ap.object_ref(cur))
        top = cur
    if kind == "Pod":
        # The Pod is what runs: an admission webhook can add a container, a person can edit it, a stale ReplicaSet
        # can differ from its Deployment. Its own spec is scored; the owners are context (G273).
        return obj, m["component"] or "", chain, top, ambiguous
    if ambiguous:
        raise ReachError(
            f"{ambiguous}; which one {ap.object_ref(obj)} belongs to, and so which spec runs, is not known"
        )
    # Any other owned object (a ReplicaSet) is a template: the scan scores its owner, and so does this.
    return cur, m["component"] or "", chain, None, ""


# --- the graph -----------------------------------------------------------------------------------------------------


class _Graph:
    def __init__(self) -> None:
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: dict[str, dict[str, Any]] = {}

    def node(self, node_id: str, kind: str, label: str, **extra: Any) -> str:
        self.nodes.setdefault(node_id, {"id": node_id, "type": kind, "label": label, **extra})
        return node_id

    def edge(self, src: str, kind: str, dst: str, obj: str, fld: str | None, text: str) -> None:
        edge_id = f"{src}|{kind}|{dst}"
        new = {
            "id": edge_id,
            "from": src,
            "to": dst,
            "kind": kind,
            "evidence": {"object": obj, "field": fld, "text": text},
        }
        old = self.edges.get(edge_id)
        # One edge per (from, kind, to); of two proofs, the same one whatever the input order.
        if old is None or json.dumps(new, sort_keys=True) < json.dumps(old, sort_keys=True):
            self.edges[edge_id] = new

    def undetermined(self, src: str, leg: str, about: str, reason: str, obj: str) -> None:
        nid = self.node(
            f"undetermined:{leg}:{about}", "undetermined", f"not determined: {reason}", leg=leg, reason=reason
        )
        self.edge(src, "not determined", nid, obj, None, reason)

    def open_from(self, *sources: str) -> list[dict[str, Any]]:
        src = set(sources)
        return sorted(
            (self.nodes[e["to"]] for e in self.edges.values() if e["from"] in src and e["kind"] == "not determined"),
            key=lambda n: n["id"],
        )


def _scope_node(g: _Graph, scope: str) -> str:
    if scope == "node":
        return g.node("scope:node", "scope", "the node")
    if scope == "cluster":
        return g.node("scope:cluster", "scope", "cluster-wide")
    ns = scope.removeprefix("namespace ")
    return g.node(f"scope:namespace/{ns}", "scope", f"namespace {ns}")


def _cap_label(cap: ap.Capability) -> str:
    target = cap.scope if cap.scope in {"node", "cluster"} else cap.scope.removeprefix("namespace ")
    return f"{cap.name} ({target})"  # as the scan prints the step's target


def _readable_targets(g: _Graph, grant: ap.Grant) -> list[str]:
    names = sorted(ap.strs(grant.rule.get("resourceNames")))
    if grant.cluster:
        if names:
            return [g.node(f"secret:*/{n}", "secret", f"Secret {n} in every namespace") for n in names]
        return [g.node("secrets:cluster", "secret", "every Secret in the cluster")]
    ns = grant.namespace
    if names:
        return [g.node(f"secret:{ns}/{n}", "secret", f"Secret {ns}/{n}") for n in names]
    return [g.node(f"secrets:namespace/{ns}", "secret", f"every Secret in namespace {ns}")]


def _rule_text(grant: ap.Grant) -> str:
    verbs = ",".join(sorted(ap.strs(grant.rule.get("verbs")))) or "-"
    res = ",".join(sorted(ap.strs(grant.rule.get("resources")) | ap.strs(grant.rule.get("nonResourceURLs")))) or "-"
    return f"{grant.role_ref} {grant.rule_at} ({verbs} on {res})"


class _Site:
    """What one pod spec contributes, for the legs and the graph."""

    def __init__(self, ref: str) -> None:
        self.ref = ref
        self.legs: dict[str, tuple[str, str]] = {}

    def leg(self, name: str, status: str, detail: str) -> None:
        self.legs[name] = (status, detail)


def _site_graph(
    g: _Graph,
    inv: ap.Inventory,
    site: Any,
    r: ap.Reach,
    *,
    mode: str,
    namespaces_read: list[str],
) -> _Site:
    out = _Site(r.ref)
    w = g.node(f"workload:{r.ref}", "workload", r.ref)
    loose = mode == "files"  # a set of files cannot prove an absence

    # exposure: how an attacker arrives
    refused = _failed_reads(inv, *_EXPOSURE_READS)
    if r.entries:
        best = sorted(r.entries, key=lambda e: (-e[1].weight, e[0]))[0][1]
        out.leg("exposure", "reached", f"{best.exposure} ({len(r.entries)} exposure(s) in the input)")
    elif refused:
        for note in refused:
            g.undetermined(w, "exposure", note.split(":")[0], f"{note}: exposures through it are not known", r.object)
        out.leg("exposure", "not determined", "; ".join(refused))
    elif r.embedded:
        out.leg(
            "exposure",
            "not determined",
            "an operator creates this pod's Services and merges in its labels, so no exposure edge can be traced "
            "from this input",
        )
    elif loose:
        out.leg(
            "exposure",
            "not determined",
            "no Service, Route or Ingress in these files reaches it; one outside them cannot be ruled out",
        )
    else:
        out.leg("exposure", "none", "no Service, Route or Ingress read reaches it")

    # node: what the pod spec itself gives an attacker on the host
    for cap in r.node:
        c = g.node(f"capability:node:{cap.name}", "capability", _cap_label(cap), scope="node", weight=cap.weight)
        g.edge(w, "escapes through", c, r.object, cap.at or None, cap.evidence)
        g.edge(c, "reaches", _scope_node(g, "node"), r.object, cap.at or None, cap.evidence)
    out.leg(
        "node",
        "reached" if r.node else "none",
        "; ".join(sorted({c.evidence for c in r.node})) if r.node else f"none of: {ap.NODE_CHECKS}",
    )

    spec = site.spec
    named_by = next((f for f in ("serviceAccountName", "serviceAccount") if spec.get(f)), None)
    sa_name = str(spec.get(named_by) if named_by else "default")
    sa_ref = f"ServiceAccount/{r.namespace}/{sa_name}"
    mount = r.mount
    if mount is None:
        base = ".".join(str(k) for k in site.path)
        where = (
            f"{base}.automountServiceAccountToken=false"
            if spec.get("automountServiceAccountToken") is False
            else f"{sa_ref} sets automountServiceAccountToken=false"
        )
        out.leg("token", "none", f"no ServiceAccount token is mounted or projected ({where})")
        out.leg("rbac", "none", "no token, so no API rights through it")
        out.leg("secrets", "none", "no token, so no Secrets reachable through it")
        return out

    sa = g.node(f"sa:{r.namespace}/{sa_name}", "serviceaccount", sa_ref)
    g.edge(w, "uses token of", sa, r.object, mount.at, mount.evidence)
    mount_open = False
    accounts = [
        o for o in inv.of("ServiceAccount") if ap.object_namespace(o) == r.namespace and ap.object_name(o) == sa_name
    ]
    automount_matters = spec.get("automountServiceAccountToken") is not True and "projected" not in mount.at
    if not accounts and automount_matters:
        refused_sa = _failed_reads(inv, "serviceaccounts")
        reason = (
            f"ServiceAccount {r.namespace}/{sa_name} is not in the input: whether it turns off "
            "automountServiceAccountToken is not known, so the token is assumed mounted, as posture scan assumes"
            + (f" ({refused_sa[0]})" if refused_sa else "")
        )
        g.undetermined(w, "token", sa_ref, reason, sa_ref)
        mount_open = True
    flags = {o.get("automountServiceAccountToken") is False for o in accounts}
    if len({ap.canonical_form(o) for o in accounts}) > 1 and len(flags) > 1:
        g.undetermined(
            w,
            "token",
            f"{sa_ref}#duplicates",
            f"{len(accounts)} ServiceAccount objects named {r.namespace}/{sa_name} are in the input and disagree on "
            "automountServiceAccountToken; the token is assumed mounted",
            sa_ref,
        )
        mount_open = True
    if mount.audience:
        g.undetermined(
            w,
            "token",
            f"{sa_ref}#audience",
            f"the projected token asks for audience {mount.audience}: the API server accepts it only if that is one "
            "of its --api-audiences, which the input does not show; its rights are listed as if it does",
            sa_ref,
        )
        mount_open = True
    out.leg("token", "not determined" if mount_open else "reached", f"{sa_ref}: {mount.evidence}")

    grants, gaps = ap.grants_of(inv, r.namespace, sa_name)
    unclassified = ap.unclassified_of(inv, grants)
    bindings: set[str] = set()
    for gap in gaps:
        b = g.node(f"binding:{gap.binding}", "binding", gap.binding)
        bindings.add(b)
        g.edge(sa, "bound by", b, gap.binding, gap.subject_at, gap.subject)
        g.undetermined(b, "rbac", gap.role_ref, gap.reason, gap.role_ref)
    if unclassified:
        named = "; ".join(_rule_text(x) for x in unclassified[:MAX_NAMED])
        more = f" and {len(unclassified) - MAX_NAMED} more" if len(unclassified) > MAX_NAMED else ""
        g.undetermined(
            sa,
            "rbac",
            f"{sa_ref}#unclassified",
            f"{len(unclassified)} bound rule(s) grant rights kube-noob does not classify, so what they allow is not "
            f"known: {named}{more}",
            sa_ref,
        )
    if mode == "live":
        for resource in ("rolebindings", "clusterrolebindings", "roles", "clusterroles"):
            for note in _failed_reads(inv, resource):
                g.undetermined(sa, "rbac", note.split(":")[0], f"{note}: grants through it are not known", sa_ref)
        if namespaces_read:
            g.undetermined(
                sa,
                "rbac",
                "rolebindings-outside",
                f"RoleBindings outside the namespaces read ({', '.join(sorted(namespaces_read))}) were not read: "
                f"grants to {sa_ref} in other namespaces are not known",
                sa_ref,
            )
    elif loose:
        if not inv.of("RoleBinding"):
            g.undetermined(
                sa,
                "rbac",
                "RoleBinding",
                f"no RoleBinding is in the input: what RoleBindings grant {sa_ref}, in any namespace, is not known",
                sa_ref,
            )
        if not inv.of("ClusterRoleBinding"):
            g.undetermined(
                sa,
                "rbac",
                "ClusterRoleBinding",
                f"no ClusterRoleBinding is in the input: cluster-wide grants to {sa_ref}, including through the "
                "groups system:serviceaccounts and system:authenticated, are not known",
                sa_ref,
            )

    def via(grant: ap.Grant) -> str:
        b = g.node(f"binding:{grant.binding}", "binding", grant.binding)
        bindings.add(b)
        g.edge(sa, "bound by", b, grant.binding, grant.subject_at, grant.subject)
        return b

    api = [cap for cap, _ in r.api]
    for cap in api:
        c = g.node(
            f"capability:{cap.scope}:{cap.name}", "capability", _cap_label(cap), scope=cap.scope, weight=cap.weight
        )
        for grant in cap.grants:
            g.edge(via(grant), "grants", c, grant.role_ref, grant.rule_at, cap.evidence)
        first = cap.grants[0] if cap.grants else None
        scope_field = None
        if first is not None and cap.scope != "node":
            scope_field = "kind" if first.cluster else "metadata.namespace"
        g.edge(c, "reaches", _scope_node(g, cap.scope), first.binding if first else sa_ref, scope_field, cap.scope)
    readable = [grant for grant in grants if ap.reads_secrets(grant.rule)]
    for grant in readable:
        b = via(grant)
        for target in _readable_targets(g, grant):
            g.edge(b, "can read", target, grant.role_ref, grant.rule_at, grant.evidence)
    # Rights that reach every Secret of their scope without a read rule: a pod it creates mounts any Secret of the
    # namespace, and escalate, bind or impersonate can take any right there (G273).
    implied = [(cap, grant) for cap in api if cap.implies_reads for grant in cap.grants]
    for cap, grant in implied:
        b = via(grant)
        target = (
            g.node("secrets:cluster", "secret", "every Secret in the cluster")
            if grant.cluster
            else g.node(
                f"secrets:namespace/{grant.namespace}", "secret", f"every Secret in namespace {grant.namespace}"
            )
        )
        g.edge(b, "can read", target, grant.role_ref, grant.rule_at, f"{cap.name}: {grant.evidence}")

    open_rbac = g.open_from(sa, *sorted(bindings))
    rbac_open = bool(open_rbac)
    if rbac_open:
        out.leg("rbac", "not determined", "; ".join(n["reason"] for n in open_rbac))
    elif api:
        out.leg("rbac", "reached", ", ".join(sorted({c.name for c in api})))
    elif loose:
        out.leg(
            "rbac",
            "not determined",
            f"no binding in these files gives {sa_ref} a right kube-noob ranks; one outside them cannot be ruled out",
        )
    else:
        bound = sorted({grant.binding for grant in grants})
        out.leg(
            "rbac",
            "none",
            f"bound by {', '.join(bound)}, to rules that are plain reads"
            if bound
            else f"no binding read names {sa_ref} or a group it is in",
        )
    if readable or implied:
        how = sorted({grant.evidence for grant in readable} | {f"{c.name}: {gr.evidence}" for c, gr in implied})
        out.leg(
            "secrets",
            "reached",
            "; ".join(how) + ("; more may be reachable: the RBAC leg is not determined" if rbac_open else ""),
        )
    else:
        out.leg(
            "secrets",
            "not determined" if rbac_open or loose else "none",
            "the RBAC leg is not determined"
            if rbac_open
            else (
                "no rule in these files reaches a Secret; a binding outside them cannot be ruled out"
                if loose
                else "no rule bound to it reaches a Secret"
            ),
        )
    return out


def _owner_differences(
    inv: ap.Inventory, pod: dict[str, Any], owner: dict[str, Any] | None, pod_reach: list[Any]
) -> list[str]:
    """What about the Pod differs from its owner's template in a way the blast radius depends on."""
    if owner is None:
        return []
    mine = [r for _, r in pod_reach]
    theirs = [r for _, r in ap.reach_of(inv, owner)]
    if not mine or not theirs:
        return []
    a, b = mine[0], theirs[0]
    out = []
    sa_a = a.mount.service_account if a.mount else "(no token)"
    sa_b = b.mount.service_account if b.mount else "(no token)"
    if sa_a != sa_b:
        out.append(f"ServiceAccount token: the Pod {sa_a}, {ap.object_ref(owner)} {sa_b}")
    node_a, node_b = sorted({c.name for c in a.node}), sorted({c.name for c in b.node})
    if node_a != node_b:
        out.append(
            f"node escape: the Pod {', '.join(node_a) or 'none'}; {ap.object_ref(owner)} {', '.join(node_b) or 'none'}"
        )
    if sorted(a.images) != sorted(b.images):
        out.append(
            f"containers: the Pod runs {len(a.images)} image(s), {ap.object_ref(owner)} declares {len(b.images)}"
        )
    return out


def _units(g: _Graph) -> list[list[str]]:
    """The nodes in the order truncation keeps them, as units that travel together: the workloads and accounts;
    each node escape with its scope; then capabilities by weight (each with the bindings that grant it and its
    scope) interleaved with the gaps (each with the binding it hangs from), so neither starves the other; then the
    Secrets with their bindings; then anything left. A binding comes only with something that needs it."""
    by_type: dict[str, list[dict[str, Any]]] = {}
    for n in g.nodes.values():
        by_type.setdefault(n["type"], []).append(n)
    into: dict[str, list[str]] = {}
    for e in g.edges.values():
        into.setdefault(e["to"], []).append(e["from"])
    units: list[list[str]] = [
        [n["id"]] for t in ("workload", "serviceaccount") for n in sorted(by_type.get(t, []), key=lambda n: n["id"])
    ]
    caps = sorted(by_type.get("capability", []), key=lambda n: (-int(n.get("weight", 0)), n["id"]))
    node_caps = [c for c in caps if c.get("scope") == "node"]
    api_caps = [c for c in caps if c.get("scope") != "node"]

    def scope_of(cap: dict[str, Any]) -> list[str]:
        return [e["to"] for e in g.edges.values() if e["from"] == cap["id"] and e["kind"] == "reaches"]

    units += [[c["id"], *scope_of(c)] for c in node_caps]
    cap_units = [[*sorted(into.get(c["id"], [])), c["id"], *scope_of(c)] for c in api_caps]
    gap_units = [
        [*sorted(s for s in into.get(n["id"], []) if g.nodes[s]["type"] == "binding"), n["id"]]
        for n in sorted(by_type.get("undetermined", []), key=lambda n: n["id"])
    ]
    for i in range(max(len(cap_units), len(gap_units))):
        units += [u[i] for u in (cap_units, gap_units) if i < len(u)]
    units += [
        [*sorted(into.get(n["id"], [])), n["id"]] for n in sorted(by_type.get("secret", []), key=lambda n: n["id"])
    ]
    units += [[n["id"]] for n in sorted(g.nodes.values(), key=lambda n: n["id"])]
    return units


def _bounded(g: _Graph, max_nodes: int, max_edges: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int, int]:
    """(nodes, edges, nodes withheld, edges withheld)."""
    kept: list[str] = []
    seen: set[str] = set()
    for unit in _units(g):
        fresh = [n for n in dict.fromkeys(unit) if n not in seen]
        if not fresh:
            continue
        if len(kept) + len(fresh) > max_nodes:
            if len(kept) >= max_nodes:
                break
            continue  # a unit that does not fit whole is skipped; a smaller later one may
        kept += fresh
        seen.update(fresh)
    rank = {t: i for i, t in enumerate(NODE_TYPES)}
    position = {n: i for i, n in enumerate(kept)}
    nodes = sorted((g.nodes[n] for n in kept), key=lambda n: (rank[n["type"]], position[n["id"]]))
    priority = ("uses token of", "escapes through", "not determined", "grants", "bound by", "reaches", "can read")
    order = {k: i for i, k in enumerate(EDGE_KINDS)}
    candidates = [e for e in g.edges.values() if e["from"] in seen and e["to"] in seen]
    candidates.sort(key=lambda e: (priority.index(e["kind"]), position[e["to"]], position[e["from"]]))
    edges = sorted(candidates[:max_edges], key=lambda e: (order[e["kind"]], position[e["from"]], position[e["to"]]))
    return nodes, edges, len(g.nodes) - len(nodes), len(g.edges) - len(edges)


def _clip(value: Any, counter: list[int]) -> Any:
    """Every string in the document cut to MAX_STRING, keeping a hash of the whole so two long strings stay apart."""
    if isinstance(value, str):
        if len(value) <= MAX_STRING:
            return value
        counter[0] += 1
        digest = hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:12]
        return f"{value[: MAX_STRING - 24]}...[sha256:{digest}]"
    if isinstance(value, dict):
        return {k: _clip(v, counter) for k, v in value.items()}
    if isinstance(value, list):
        return [_clip(v, counter) for v in value]
    return value


def reach(
    inv: ap.Inventory,
    workload: str,
    namespace: str | None = None,
    *,
    live: bool = False,
    namespaces_read: list[str] | None = None,
    whole_bundle: bool = False,
    max_nodes: int = MAX_NODES,
    max_edges: int = MAX_EDGES,
    max_bytes: int = MAX_BYTES,
) -> dict[str, Any]:
    """The blast-radius document for one workload. Raises ReachError when the reference matches nothing or more
    than one object."""
    if not (1 <= max_nodes <= _CAP_LIMIT and 1 <= max_edges <= _CAP_LIMIT and 4_000 <= max_bytes <= 50_000_000):
        raise ReachError(f"the node and edge caps must be 1-{_CAP_LIMIT}, the byte cap 4000-50000000")
    inv.canonicalize()
    mode = "live" if live else ("whole" if whole_bundle else "files")
    obj, component, via, owner, ambiguous = _resolve(inv, workload, namespace, list(namespaces_read or []))
    pairs = ap.reach_of(inv, obj)
    if component:
        pairs = [(s, r) for s, r in pairs if s.template.component == component]
        if not pairs:
            names = ", ".join(sorted(s.template.component for s, _ in ap.reach_of(inv, obj)) or ["none"])
            raise ReachError(f"{ap.object_ref(obj)} has no component {component} (components: {names})")
    if not pairs:
        raise ReachError(f"{ap.object_ref(obj)} carries no pod spec kube-noob reads")
    g = _Graph()
    sites = [_site_graph(g, inv, site, r, mode=mode, namespaces_read=list(namespaces_read or [])) for site, r in pairs]
    differs = _owner_differences(inv, obj, owner, pairs) + (
        [f"{ambiguous}, so the owner chain stops below them and the Pod is not compared with either"]
        if ambiguous
        else []
    )

    exposure: list[dict[str, Any]] = []
    paths: list[ap.AttackPath] = []
    for _site, r in pairs:
        for _i, entry, steps in sorted(r.entries, key=lambda e: (-e[1].weight, e[0])):
            exposure.append({"kind": entry.exposure, "weight": entry.weight, "steps": [s.as_dict() for s in steps]})
        paths += r.paths()
    paths.sort(key=lambda p: (-p.score, len(p.steps), p.as_dict(0)["summary"]))

    # The summary is the whole graph's, computed before anything is cut: a truncated document said "reaches no
    # capability" for a privileged cluster-admin pod whose capabilities had been the first thing dropped (G273).
    caps = sorted(
        (n for n in g.nodes.values() if n["type"] == "capability"), key=lambda n: (-int(n.get("weight", 0)), n["label"])
    )
    legs = [
        {"workload": s.ref, "leg": name, "status": s.legs[name][0], "detail": s.legs[name][1]}
        for s in sorted(sites, key=lambda s: s.ref)
        for name in LEGS
        if name in s.legs
    ]
    open_legs = [x for x in legs if x["status"] == "not determined"]
    undetermined_all = sorted((n for n in g.nodes.values() if n["type"] == "undetermined"), key=lambda n: n["id"])
    anchor = ap.object_ref(obj) + (f"[{component}]" if component else "")
    head = (
        f"reaches {len(caps)} capabilit{'y' if len(caps) == 1 else 'ies'} (top: {caps[0]['label']})"
        if caps
        # With a leg open, "none" would be a claim the input cannot support.
        else ("reaches no capability the input shows" if open_legs else "reaches no capability kube-noob ranks")
    )
    reached_from = (
        f"exposed: {exposure[0]['kind']}, top path score {paths[0].score}"
        if exposure and paths
        else (f"exposed: {exposure[0]['kind']}" if exposure else "not reached by any exposure in the input")
    )
    open_note = f"; {len(open_legs)} leg(s) not determined" if open_legs else ""
    differ_note = f"; the Pod differs from its owner ({len(differs)} way(s))" if differs else ""
    completeness = {"files": _FILE_INPUT, "whole": _WHOLE_BUNDLE, "live": _LIVE}[mode]
    limitations = [completeness, *LIMITATIONS]
    if differs:
        limitations.insert(1, "The Pod is scored on its own spec; it differs from its owner: " + "; ".join(differs))

    def build(n_cap: int, e_cap: int, list_cap: int) -> dict[str, Any]:
        nodes, edges, nodes_cut, edges_cut = _bounded(g, n_cap, e_cap)
        kept = {n["id"] for n in nodes}
        sources = {e["to"]: e["from"] for e in g.edges.values() if e["kind"] == "not determined"}
        nd = [
            {
                "id": n["id"],
                "leg": n["leg"],
                "from": sources.get(n["id"], ""),
                "reason": n["reason"],
                "inGraph": n["id"] in kept,
            }
            for n in undetermined_all
        ]
        nd_shown = sorted(nd, key=lambda x: (not x["inGraph"], x["id"]))[:list_cap]
        doc: dict[str, Any] = {
            "schema": SCHEMA_ID,
            "schemaVersion": SCHEMA_VERSION,
            "anchor": {
                "query": workload,
                "object": anchor,
                "resolved": [r.ref for _, r in pairs],
                "via": via,
                "ownerDiffers": differs,
            },
            "summary": "",
            "complete": False,
            "completeness": completeness,
            "legs": legs,
            "nodes": nodes,
            "edges": edges,
            "notDetermined": nd_shown,
            "truncated": None,
            "exposure": exposure[: min(MAX_LISTED, list_cap)],
            "paths": [p.as_dict(i + 1) for i, p in enumerate(paths[: min(MAX_LISTED, list_cap)])],
            "pathsWithheld": max(0, len(paths) - min(MAX_LISTED, list_cap)),
            "notRead": sorted(set(inv.not_read))[: min(50, list_cap)],
            "secretsIgnored": inv.dropped_secrets,
            "limitations": limitations,
        }
        clipped = [0]
        doc = _clip(doc, clipped)
        nd_cut = len(nd) - len(nd_shown)
        if nodes_cut or edges_cut or nd_cut or clipped[0]:
            doc["truncated"] = {
                "nodesWithheld": nodes_cut,
                "edgesWithheld": edges_cut,
                "notDeterminedWithheld": nd_cut,
                "stringsClipped": clipped[0],
                "maxNodes": n_cap,
                "maxEdges": e_cap,
                "maxBytes": max_bytes,
            }
        t = doc["truncated"]
        cut = (
            f"; truncated: {t['nodesWithheld']} node(s), {t['edgesWithheld']} edge(s), "
            f"{t['notDeterminedWithheld']} not-determined reason(s) withheld, {t['stringsClipped']} string(s) clipped"
            if t
            else ""
        )
        doc["summary"] = f"{anchor}: if compromised, {head}; {reached_from}{open_note}{differ_note}{cut}"
        doc["complete"] = mode != "files" and not open_legs and not undetermined_all and t is None
        return doc

    n_cap, e_cap, list_cap = max_nodes, max_edges, max(max_nodes, 50)
    doc = build(n_cap, e_cap, list_cap)
    # Bounded in bytes as well as in count: halve until it fits, and the document says what went.
    while len(json.dumps(doc)) > max_bytes and (n_cap > 4 or list_cap > 4):
        n_cap, e_cap, list_cap = max(4, n_cap // 2), max(4, e_cap // 2), max(4, list_cap // 2)
        doc = build(n_cap, e_cap, list_cap)
    return doc


def reach_result(
    inv: ap.Inventory, workload: str, namespace: str | None = None, *, mermaid: bool = False, **kw: Any
) -> dict[str, Any]:
    """The MCP result: the document, and the diagram when asked for, together within MAX_BYTES. The diagram is
    derived from the document, so the document is the one thing that shrinks."""
    budget = MAX_BYTES
    while True:
        doc = reach(inv, workload, namespace, max_bytes=budget, **kw)
        if not mermaid:
            return doc
        out = {**doc, "mermaid": to_mermaid(doc)}
        if len(json.dumps(out)) <= MAX_BYTES or budget <= 8_000:
            return out
        budget //= 2


def reach_manifests(text: str, workload: str, namespace: str | None = None, **kw: Any) -> dict[str, Any]:
    from kube_noob.yamlio import load_documents

    return reach(ap.Inventory.from_documents(d.data for d in load_documents(text)), workload, namespace, **kw)


# --- renderings ----------------------------------------------------------------------------------------------------

_SAFE = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ./:_-=,()'+*@!?")


def flat(text: Any) -> str:
    """One line: every run of whitespace, newlines included, is one space. A name or path in the input carrying a
    newline otherwise printed a forged row into the text view (G273)."""
    return " ".join(str(text).split())


def mermaid_label(text: str) -> str:
    """An untrusted string made safe inside a quoted Mermaid label: whitespace (newlines included) collapsed,
    control characters replaced, and every character outside a small safe set written as a decimal entity code,
    so a quote, a bracket, a backtick, `%%`, `;`, `<` or `#` can neither end the label nor start a statement."""
    text = flat(text)
    if len(text) > MAX_LABEL:
        text = text[: MAX_LABEL - 3] + "..."
    out = []
    for ch in text:
        if ch in _SAFE:
            out.append(ch)
        elif unicodedata.category(ch).startswith("C"):
            out.append("?")
        else:
            out.append(f"#{ord(ch)};")
    return "".join(out)


def to_mermaid(graph: dict[str, Any]) -> str:
    """A Mermaid `flowchart` of the blast-radius document, derived from its nodes and edges only. Deterministic:
    node ids are positions in the document's own node order. What the document says about its own completeness,
    truncation and limitations is drawn as note nodes, so the diagram alone does not read as the whole answer."""
    ids = {n["id"]: f"n{i}" for i, n in enumerate(graph["nodes"], 1)}
    lines = [
        "flowchart LR",
        f"  %% kube-noob blast radius ({SCHEMA_ID} v{SCHEMA_VERSION}); every label is escaped input",
    ]
    lines += [f'  {ids[n["id"]]}["{mermaid_label(n["label"])}"]' for n in graph["nodes"]]
    for e in graph["edges"]:
        if e["kind"] not in EDGE_KINDS or e["from"] not in ids or e["to"] not in ids:
            continue  # not in this document's vocabulary or its nodes: never drawn
        a, b = ids[e["from"]], ids[e["to"]]
        if e["kind"] == "not determined":
            lines.append(f"  {a} -. not determined .-> {b}")
        else:
            lines.append(f"  {a} -->|{e['kind']}| {b}")
    open_ids = [ids[n["id"]] for n in graph["nodes"] if n["type"] == "undetermined"]
    if open_ids:
        lines.append("  classDef undetermined stroke-dasharray: 5 5")
        lines.append(f"  class {','.join(open_ids)} undetermined")
    notes: list[str] = []
    open_legs = [x for x in graph["legs"] if x["status"] == "not determined"]
    if open_legs:
        notes.append("not determined: " + "; ".join(sorted({f"{x['leg']} ({x['workload']})" for x in open_legs})))
    notes += graph["limitations"]
    t = graph.get("truncated")
    if t:
        notes.append(
            f"truncated: {t['nodesWithheld']} node(s), {t['edgesWithheld']} edge(s) and {t['notDeterminedWithheld']} "
            f"not-determined reason(s) withheld, {t['stringsClipped']} string(s) clipped "
            f"(caps {t['maxNodes']} nodes, {t['maxEdges']} edges, {t['maxBytes']} bytes)"
        )
    for i, note in enumerate(notes):
        lines.append(f'  t{i}["{mermaid_label(note)}"]')
    if notes:
        lines.append("  classDef note stroke-dasharray: 2 2")
        lines.append(f"  class {','.join(f't{i}' for i in range(len(notes)))} note")
    return "\n".join(lines)


def render_text(graph: dict[str, Any]) -> str:
    """The text view. Every string that can come from the input passes through `flat`."""
    labels = {n["id"]: flat(n["label"]) for n in graph["nodes"]}
    out = [flat(graph["summary"])]
    if len(graph["anchor"]["via"]) > 1:
        out.append("  owner chain: " + " -> ".join(flat(x) for x in graph["anchor"]["via"]))
    for d in graph["anchor"]["ownerDiffers"]:
        out.append(f"  the Pod differs from its owner: {flat(d)}")
    workloads = sorted({x["workload"] for x in graph["legs"]})
    for wl in workloads:
        out.append("")
        if len(workloads) > 1:
            out.append(f"  [{flat(wl)}]")
        for row in (x for x in graph["legs"] if x["workload"] == wl):
            out.append(f"  {row['leg']:9} {row['status']:15} {flat(row['detail'])}")
    out.append("")
    for e in graph["edges"]:
        if e["kind"] == "not determined":
            continue
        ev = e["evidence"]
        out.append(f"  {labels[e['from']]} --{e['kind']}--> {labels[e['to']]}")
        where = f"{flat(ev['object'])} {flat(ev['field'])}" if ev["field"] else flat(ev["object"])
        out.append(f"      {flat(ev['text'])}  [{where}]")
    for n in graph["notDetermined"]:
        out.append(f"\nnot determined: {flat(n['reason'])}")
    for p in graph["paths"][:5]:
        out.append(f"\nexposed path #{p['rank']}  score {p['score']}: {flat(p['summary'])}")
    t = graph["truncated"]
    if t:
        out.append(
            f"\ntruncated: {t['nodesWithheld']} node(s), {t['edgesWithheld']} edge(s) and "
            f"{t['notDeterminedWithheld']} not-determined reason(s) withheld, {t['stringsClipped']} string(s) clipped "
            f"(caps {t['maxNodes']} nodes, {t['maxEdges']} edges, {t['maxBytes']} bytes)"
        )
    if graph["notRead"]:
        out.append("\nnot read: " + "; ".join(flat(x) for x in graph["notRead"][:10]))
    ignored = graph["secretsIgnored"]
    if ignored:
        out.append(f"{ignored} Secret object(s) in the input were ignored, unread.")
    out.append("")
    out += [f"limitation: {flat(x)}" for x in graph["limitations"]]
    return "\n".join(out)
