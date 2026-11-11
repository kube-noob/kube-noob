"""Blast radius: if THIS workload is compromised, what can it reach? (moat item V3, G273). Read-only, tier R.

Anchored on one workload (``Kind/namespace/name``, or a Pod resolved to the owner the attack-path scan scores), it
returns what an attacker running code in its pods gets: the ServiceAccount whose token is mounted, the bindings
that name that account (directly, or through the groups ``system:serviceaccounts``, ``system:serviceaccounts:<ns>``
and ``system:authenticated``), what each lets it do, the Secrets it may read by RBAC (by name or by scope -- Secret
objects are never read), the node when a pod spec can escape to it, and which namespaces or the whole cluster that
reach covers.

It is not a second model. Every edge comes from :mod:`kube_noob.attack_paths` -- the same entries, the same RBAC
reading, the same capabilities -- and each carries the evidence line ``posture scan`` prints for that step, plus the
object and the field that prove it.

What the input cannot show is part of the graph, not a gap in it. A ServiceAccount that is not in the input, a bound
Role that is not, an aggregated ClusterRole, a bundle with no RoleBinding or no ClusterRoleBinding at all, and a
live read that failed or was limited to some namespaces each become a ``not determined`` node with the reason,
joined by a ``not determined`` edge -- because an empty list there would read as "this account can do nothing".
The graph is capped (``MAX_NODES``, ``MAX_EDGES``); when the cap is hit the document says how much it withheld, and
what was not determined is kept ahead of what was found. A reference that matches nothing is an error.

The Mermaid rendering is derived from the JSON graph and nothing else. Every label is escaped: an object name is
input, and a name carrying a quote, a bracket, ``%%`` or a newline could otherwise close a label and add a ``click``
handler or an ``init`` directive to the diagram. Entity codes (``#35;``) are Mermaid's documented escape
(https://mermaid.js.org/syntax/flowchart.html#entity-codes-to-escape-characters, read 2026-11-11).
"""

from __future__ import annotations

import json
import re
import unicodedata
from typing import Any

from kube_noob import attack_paths as ap

SCHEMA_ID = "kube-noob/blast-radius"
SCHEMA_VERSION = 1
MAX_NODES = 120
MAX_EDGES = 200
MAX_LISTED = 20  # paths and exposures carried along
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
LEGS = ("token", "rbac", "secrets", "node")
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
            "required": ["query", "object", "resolved", "via"],
            "properties": {
                "query": {"type": "string"},
                "object": {"type": "string"},
                "resolved": {"type": "array", "minItems": 1, "items": {"type": "string"}},
                "via": {"type": "array", "minItems": 1, "items": {"type": "string"}},
            },
        },
        "summary": {"type": "string"},
        "complete": {"type": "boolean"},
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
                "required": ["id", "leg", "from", "reason"],
                "properties": {
                    "id": {"type": "string"},
                    "leg": {"enum": list(LEGS)},
                    "from": {"type": "string"},
                    "reason": {"type": "string"},
                },
            },
        },
        "truncated": {
            "oneOf": [
                {"type": "null"},
                {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["nodesWithheld", "edgesWithheld", "maxNodes", "maxEdges"],
                    "properties": {
                        "nodesWithheld": {"type": "integer", "minimum": 0},
                        "edgesWithheld": {"type": "integer", "minimum": 0},
                        "maxNodes": {"type": "integer", "minimum": 1},
                        "maxEdges": {"type": "integer", "minimum": 1},
                    },
                },
            ]
        },
        "exposure": {"type": "array", "items": {"type": "object"}},
        "paths": {"type": "array", "items": {"type": "object"}},
        "pathsWithheld": {"type": "integer", "minimum": 0},
        "notRead": {"type": "array", "items": {"type": "string"}},
        "secretsIgnored": {"type": "integer", "minimum": 0},
        "limitations": {"type": "array", "items": {"type": "string"}},
    },
}

LIMITATIONS: tuple[str, ...] = (
    *ap.STANDING_LIMITATIONS,
    "Grants are what the input shows. A binding outside it is reported as not determined where its absence can "
    "be seen (no binding of a kind at all, a role it names, a failed or namespace-limited live read); a bundle "
    "that carries some bindings cannot show the ones it leaves out.",
)


class ReachError(ValueError):
    """The anchor names nothing in the input, or the request is out of bounds."""


# --- the anchor ----------------------------------------------------------------------------------------------------


def _workload_kind(kind: str) -> str | None:
    low = kind.lower()
    if low in _ALIASES:
        return _ALIASES[low]
    for k in sorted(ap.WORKLOAD_KINDS):
        if low in {k.lower(), k.lower() + "s"}:
            return k
    return None


def _resolve(inv: ap.Inventory, query: str, namespace: str | None) -> tuple[dict[str, Any], str, list[str]]:
    """(object, component, owner chain) for the anchor. Raises ReachError when it names nothing."""
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
        if kind == "Pod":
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
    obj = found[0]
    via = [ap.object_ref(obj)]
    # Up the controller chain, the way the scan de-duplicates: a Pod's ReplicaSet's Deployment is the workload it
    # scores, when those objects are in the input. An owner that is not in the input is not invented.
    by_key = {(str(o.get("kind")), ap.object_namespace(o), ap.object_name(o)): o for o in inv.of(*ap.WORKLOAD_KINDS)}
    for _ in range(8):
        owner = next(
            (
                by_key[key]
                for r in ap.controller_refs(obj)
                if (key := (str(r.get("kind")), ap.object_namespace(obj), str(r.get("name")))) in by_key
            ),
            None,
        )
        if owner is None or ap.object_ref(owner) in via:
            break
        obj = owner
        via.append(ap.object_ref(obj))
    return obj, m["component"] or "", via


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

    def undetermined(self, src: str, leg: str, key: str, reason: str, obj: str) -> None:
        nid = self.node(
            f"undetermined:{leg}:{key}", "undetermined", f"not determined: {reason}", leg=leg, reason=reason
        )
        self.edge(src, "not determined", nid, obj, None, reason)


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


def _failed_reads(inv: ap.Inventory, *resources: str) -> list[str]:
    return sorted({n for n in inv.not_read for r in resources if n.startswith((f"{r}:", f"{r} in "))})


def _site_graph(
    g: _Graph,
    inv: ap.Inventory,
    site: Any,
    r: ap.Reach,
    *,
    live: bool,
    namespaces_read: list[str],
    legs: list[dict[str, Any]],
) -> None:
    w = g.node(f"workload:{r.ref}", "workload", r.ref)
    base = ".".join(str(k) for k in site.path)

    def leg(name: str, status: str, detail: str) -> None:
        legs.append({"workload": r.ref, "leg": name, "status": status, "detail": detail})

    # node: what the pod spec itself gives an attacker on the host
    for cap in r.node:
        c = g.node(f"capability:node:{cap.name}", "capability", _cap_label(cap), scope="node", weight=cap.weight)
        g.edge(w, "escapes through", c, r.object, cap.at or None, cap.evidence)
        g.edge(c, "reaches", _scope_node(g, "node"), r.object, cap.at or None, cap.evidence)
    leg(
        "node",
        "reached" if r.node else "none",
        "; ".join(sorted({c.evidence for c in r.node}))
        if r.node
        else "no privileged container, hostPath volume, host namespace or near-root capability in the pod spec",
    )

    spec = site.spec
    sa_name = str(spec.get("serviceAccountName") or spec.get("serviceAccount") or "default")
    sa_ref = f"ServiceAccount/{r.namespace}/{sa_name}"
    if not r.mount_evidence:
        where = (
            f"{base}.automountServiceAccountToken=false"
            if spec.get("automountServiceAccountToken") is False
            else f"{sa_ref} sets automountServiceAccountToken=false"
        )
        leg("token", "none", f"no ServiceAccount token is mounted ({where})")
        leg("rbac", "none", "no token, so no API rights through it")
        leg("secrets", "none", "no token, so no Secrets readable through it")
        return

    sa = g.node(f"sa:{r.namespace}/{sa_name}", "serviceaccount", sa_ref)
    sa_field = f"{base}.serviceAccountName" if base else "serviceAccountName"
    g.edge(w, "uses token of", sa, r.object, sa_field, r.mount_evidence)
    present = {(ap.object_namespace(o), ap.object_name(o)) for o in inv.of("ServiceAccount")}
    mount_open = False
    if (r.namespace, sa_name) not in present and spec.get("automountServiceAccountToken") is not True:
        failed = _failed_reads(inv, "serviceaccounts")
        reason = (
            f"ServiceAccount {r.namespace}/{sa_name} is not in the input: whether it turns off "
            "automountServiceAccountToken is not known, so the token is assumed mounted, as posture scan assumes"
            + (f" ({failed[0]})" if failed else "")
        )
        g.undetermined(w, "token", sa_ref, reason, sa_ref)
        mount_open = True
    leg("token", "not determined" if mount_open else "reached", f"{sa_ref}: {r.mount_evidence}")

    grants, gaps = ap.grants_of(inv, r.namespace, sa_name)
    rbac_open = False
    for gap in gaps:
        b = g.node(f"binding:{gap.binding}", "binding", gap.binding)
        g.edge(sa, "bound by", b, gap.binding, gap.subject_at, gap.subject)
        g.undetermined(b, "rbac", gap.role_ref, gap.reason, gap.role_ref)
        rbac_open = True
    if live:
        for resource in ("rolebindings", "clusterrolebindings", "roles", "clusterroles"):
            for note in _failed_reads(inv, resource):
                g.undetermined(sa, "rbac", note.split(":")[0], f"{note}: grants through it are not known", sa_ref)
                rbac_open = True
        if namespaces_read:
            read = ", ".join(sorted(namespaces_read))
            g.undetermined(
                sa,
                "rbac",
                "rolebindings-outside",
                f"RoleBindings outside the namespaces read ({read}) were not read: grants to {sa_ref} in other "
                "namespaces are not known",
                sa_ref,
            )
            rbac_open = True
    else:
        if not inv.of("RoleBinding"):
            g.undetermined(
                sa,
                "rbac",
                "RoleBinding",
                f"no RoleBinding is in the input: what RoleBindings grant {sa_ref}, in any namespace, is not known",
                sa_ref,
            )
            rbac_open = True
        if not inv.of("ClusterRoleBinding"):
            g.undetermined(
                sa,
                "rbac",
                "ClusterRoleBinding",
                f"no ClusterRoleBinding is in the input: cluster-wide grants to {sa_ref}, including through the "
                "groups system:serviceaccounts and system:authenticated, are not known",
                sa_ref,
            )
            rbac_open = True

    def via(grant: ap.Grant) -> str:
        b = g.node(f"binding:{grant.binding}", "binding", grant.binding)
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
    bound = sorted({grant.binding for grant in grants} | {gap.binding for gap in gaps})
    if rbac_open:
        leg("rbac", "not determined", "; ".join(n["reason"] for n in _open(g, sa)))
    elif api:
        leg("rbac", "reached", ", ".join(sorted({c.name for c in api})))
    else:
        leg(
            "rbac",
            "none",
            f"bound by {', '.join(bound)}, to nothing kube-noob ranks"
            if bound
            else f"no binding in the input names {sa_ref} or a group it is in",
        )
    if readable:
        leg(
            "secrets",
            "reached",
            "; ".join(sorted({grant.evidence for grant in readable}))
            + ("; more may be readable: the RBAC leg is not determined" if rbac_open else ""),
        )
    else:
        leg(
            "secrets",
            "not determined" if rbac_open else "none",
            "the RBAC leg is not determined" if rbac_open else "no rule bound to it reads Secrets",
        )


def _open(g: _Graph, src: str) -> list[dict[str, Any]]:
    return sorted(
        (g.nodes[e["to"]] for e in g.edges.values() if e["from"] == src and e["kind"] == "not determined"),
        key=lambda n: n["id"],
    )


def _canonical(inv: ap.Inventory) -> None:
    """Sort every kind's objects, so that which of two equal-weight grants proves a capability, and which of two
    duplicated names wins, does not depend on the order of the documents (same input, same bytes)."""
    inv.objects = {
        k: sorted(v, key=lambda o: json.dumps(o, sort_keys=True, default=str)) for k, v in sorted(inv.objects.items())
    }


def reach(
    inv: ap.Inventory,
    workload: str,
    namespace: str | None = None,
    *,
    live: bool = False,
    namespaces_read: list[str] | None = None,
    max_nodes: int = MAX_NODES,
    max_edges: int = MAX_EDGES,
) -> dict[str, Any]:
    """The blast-radius document for one workload. Raises ReachError when the reference matches nothing."""
    if not (1 <= max_nodes <= _CAP_LIMIT and 1 <= max_edges <= _CAP_LIMIT):
        raise ReachError(f"the node and edge caps must be 1-{_CAP_LIMIT}")
    _canonical(inv)
    obj, component, via = _resolve(inv, workload, namespace)
    pairs = ap.reach_of(inv, obj)
    if component:
        pairs = [(s, r) for s, r in pairs if s.template.component == component]
        if not pairs:
            names = ", ".join(sorted(s.template.component for s, _ in ap.reach_of(inv, obj)) or ["none"])
            raise ReachError(f"{ap.object_ref(obj)} has no component {component} (components: {names})")
    if not pairs:
        raise ReachError(f"{ap.object_ref(obj)} carries no pod spec kube-noob reads")
    g = _Graph()
    legs: list[dict[str, Any]] = []
    for site, r in pairs:
        _site_graph(g, inv, site, r, live=live, namespaces_read=list(namespaces_read or []), legs=legs)

    # exposures and ranked paths through this workload, as the scan prints them
    exposure: list[dict[str, Any]] = []
    paths: list[ap.AttackPath] = []
    for _site, r in pairs:
        for _i, entry, steps in sorted(r.entries, key=lambda e: (-e[1].weight, e[0])):
            exposure.append({"kind": entry.exposure, "weight": entry.weight, "steps": [s.as_dict() for s in steps]})
        paths += r.paths()
    paths.sort(key=lambda p: (-p.score, len(p.steps), p.as_dict(0)["summary"]))
    shown = [p.as_dict(i + 1) for i, p in enumerate(paths[:MAX_LISTED])]

    nodes, edges, truncated = _bounded(g, max_nodes, max_edges)
    undetermined = [n for n in nodes if n["type"] == "undetermined"]
    sources = {e["to"]: e["from"] for e in edges if e["kind"] == "not determined"}
    not_determined = [
        {"id": n["id"], "leg": n["leg"], "from": sources.get(n["id"], ""), "reason": n["reason"]} for n in undetermined
    ]
    caps = sorted((n for n in nodes if n["type"] == "capability"), key=lambda n: (-int(n.get("weight", 0)), n["label"]))
    anchor = ap.object_ref(obj) + (f"[{component}]" if component else "")
    head = (
        f"reaches {len(caps)} capabilit{'y' if len(caps) == 1 else 'ies'} (top: {caps[0]['label']})"
        if caps
        # With a leg open, "none" would be a claim the input cannot support.
        else ("reaches no capability the input shows" if undetermined else "reaches no capability kube-noob ranks")
    )
    reached_from = (
        f"exposed: {exposure[0]['kind']}, top path score {shown[0]['score']}"
        if exposure and shown
        else (f"exposed: {exposure[0]['kind']}" if exposure else "not reached by any exposure in the input")
    )
    open_note = f"; {len(not_determined)} leg(s) not determined" if not_determined else ""
    cut = (
        f"; truncated: {truncated['nodesWithheld']} node(s), {truncated['edgesWithheld']} edge(s) withheld"
        if truncated
        else ""
    )
    return {
        "schema": SCHEMA_ID,
        "schemaVersion": SCHEMA_VERSION,
        "anchor": {"query": workload, "object": anchor, "resolved": [r.ref for _, r in pairs], "via": via},
        "summary": f"{anchor}: if compromised, {head}; {reached_from}{open_note}{cut}",
        "complete": not not_determined and truncated is None,
        "legs": sorted(legs, key=lambda x: (x["workload"], LEGS.index(x["leg"]))),
        "nodes": nodes,
        "edges": edges,
        "notDetermined": not_determined,
        "truncated": truncated,
        "exposure": exposure[:MAX_LISTED],
        "paths": shown,
        "pathsWithheld": max(0, len(paths) - MAX_LISTED),
        "notRead": sorted(set(inv.not_read))[:50],
        "secretsIgnored": inv.dropped_secrets,
        "limitations": list(LIMITATIONS),
    }


def _bounded(
    g: _Graph, max_nodes: int, max_edges: int
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, int] | None]:
    """Nodes in a fixed order -- the workload, then what was NOT determined, then what was found -- cut at the cap;
    edges whose ends survive, the not-determined ones first. Truncation never hides an unknown before a finding."""
    rank = {t: i for i, t in enumerate(NODE_TYPES)}
    ordered = sorted(g.nodes.values(), key=lambda n: (rank[n["type"]], n["id"]))
    nodes = ordered[:max_nodes]
    kept = {n["id"] for n in nodes}
    order = {k: i for i, k in enumerate(EDGE_KINDS)}
    live_edges = [e for e in g.edges.values() if e["from"] in kept and e["to"] in kept]
    live_edges.sort(key=lambda e: (e["kind"] != "not determined", order[e["kind"]], e["from"], e["to"]))
    edges = sorted(live_edges[:max_edges], key=lambda e: (order[e["kind"]], e["from"], e["to"]))
    withheld_nodes, withheld_edges = len(ordered) - len(nodes), len(g.edges) - len(edges)
    truncated = (
        {"nodesWithheld": withheld_nodes, "edgesWithheld": withheld_edges, "maxNodes": max_nodes, "maxEdges": max_edges}
        if withheld_nodes or withheld_edges
        else None
    )
    return nodes, edges, truncated


def reach_manifests(text: str, workload: str, namespace: str | None = None, **kw: Any) -> dict[str, Any]:
    from kube_noob.yamlio import load_documents

    return reach(ap.Inventory.from_documents(d.data for d in load_documents(text)), workload, namespace, **kw)


# --- renderings ----------------------------------------------------------------------------------------------------

_SAFE = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ./:_-=,()'+*@!?")


def mermaid_label(text: str) -> str:
    """An untrusted string made safe inside a quoted Mermaid label: whitespace (newlines included) collapsed,
    control characters replaced, and every character outside a small safe set written as a decimal entity code,
    so a quote, a bracket, a backtick, `%%`, `;`, `<` or `#` can neither end the label nor start a statement."""
    flat = " ".join(str(text).split())
    if len(flat) > MAX_LABEL:
        flat = flat[: MAX_LABEL - 3] + "..."
    out = []
    for ch in flat:
        if ch in _SAFE:
            out.append(ch)
        elif unicodedata.category(ch).startswith("C"):
            out.append("?")
        else:
            out.append(f"#{ord(ch)};")
    return "".join(out)


def to_mermaid(graph: dict[str, Any]) -> str:
    """A Mermaid `flowchart` of the blast-radius document, derived from its nodes and edges only. Deterministic:
    node ids are positions in the document's own node order."""
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
    t = graph.get("truncated")
    if t:
        note = (
            f"truncated: {t['nodesWithheld']} node(s) and {t['edgesWithheld']} edge(s) withheld "
            f"(caps {t['maxNodes']} nodes, {t['maxEdges']} edges)"
        )
        lines.append(f'  t0["{mermaid_label(note)}"]')
        lines.append("  classDef truncated stroke-dasharray: 2 2")
        lines.append("  class t0 truncated")
    return "\n".join(lines)


def render_text(graph: dict[str, Any]) -> str:
    labels = {n["id"]: n["label"] for n in graph["nodes"]}
    out = [graph["summary"]]
    if len(graph["anchor"]["via"]) > 1:
        out.append("  resolved: " + " -> ".join(graph["anchor"]["via"]))
    out.append("")
    for row in graph["legs"]:
        out.append(f"  {row['leg']:8} {row['status']:15} {row['detail']}")
    out.append("")
    for e in graph["edges"]:
        if e["kind"] == "not determined":
            continue
        ev = e["evidence"]
        out.append(f"  {labels[e['from']]} --{e['kind']}--> {labels[e['to']]}")
        where = f"{ev['object']} {ev['field']}" if ev["field"] else ev["object"]
        out.append(f"      {ev['text']}  [{where}]")
    for n in graph["notDetermined"]:
        out.append(f"\nnot determined: {n['reason']}")
    for p in graph["paths"][:5]:
        out.append(f"\nexposed path #{p['rank']}  score {p['score']}: {p['summary']}")
    t = graph["truncated"]
    if t:
        out.append(
            f"\ntruncated: {t['nodesWithheld']} node(s) and {t['edgesWithheld']} edge(s) withheld "
            f"(caps {t['maxNodes']} nodes, {t['maxEdges']} edges)"
        )
    if graph["notRead"]:
        out.append("\nnot read: " + "; ".join(graph["notRead"][:10]))
    ignored = graph["secretsIgnored"]
    if ignored:
        out.append(f"{ignored} Secret object(s) in the input were ignored, unread.")
    return "\n".join(out)
