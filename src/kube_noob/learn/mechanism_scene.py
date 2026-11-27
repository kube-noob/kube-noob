"""Where the things on a mechanism walk stand: the isometric scene and the sequence diagram of one walk.

The player's layout follows KubeLearn's ``src/scene/world.ts``, ``src/components/Stage.tsx`` and
``src/components/SequenceView.tsx`` (kubelearn.joesabbagh.com), Copyright (c) 2026 Joe Sabbagh, MIT License; the
notice is reproduced in ``THIRD_PARTY_NOTICES.md``. Ported from there: the 1000 x 640 world and its ground-to-
screen geometry, the floor plate with its grid and its name lying on it, cables that run along the floor's two
axes and are trimmed at each footprint, the camera box that frames the actors in focus, and the lane-per-actor
sequence diagram. What is kube-noob's own is what stands in the scene and why.

**One hop, one actor, and the actor is the reader's object.** A hop that names an object in `steps[].objects`
stands on a card for that object: the kind's badge, the object's own name, its namespace. Two hops that read the
same object share its card. A hop the rules read without naming an object (a NetworkPolicy the walk only counts)
stands on a card for the kind, and says the walk names no object there.

**A thing no manifest holds is drawn as one.** The visitor's laptop, cluster DNS, the node's own packet path, the
scheduler: a lesson's layout may give a hop with no manifest object one of KubeLearn's external or node actors.
Every such actor, and the worker nodes drawn as scenery, carries ``data-manifest="no"`` -- a dashed outline in
the stylesheet -- and the words "not in any manifest" under its name. None of them is ever given a verdict a
rule did not reach: the state on an actor is the worst state among the hops that stand on it, and scenery has no
hops, so it has no state.

**A lesson this module has no layout for is still drawn.** `LAYOUTS` places the four lessons shipped today by
role: edge actors front right, traffic cards in front of the nodes, workloads behind, policy and RBAC cards in a
row. Any other lesson, a walk whose hops are not the layout's, and a walk drawn with no lesson at all get a plain
isometric row on a plate, in hop order. Nothing here raises on a lesson it has not seen.

This module computes positions and writes markup. It makes no judgement and reads no manifest: every string it
is given was cleaned by :func:`kube_noob.learn.mechanism_html.view`, and is escaped by the `esc` it is passed.
"""

from __future__ import annotations

import math
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from kube_noob.learn import iso as I

WORLD = (1000.0, 640.0)
S = 4.6
ORIGIN = (460.0, 230.0)

Point = tuple[float, float]
Box = tuple[float, float, float, float]

#: The badge on a card, by kind. KubeLearn's codes where it has one; the RBAC kinds are added in its style.
BADGE = {
    "Deployment": "DEP",
    "ReplicaSet": "RS",
    "Service": "SVC",
    "HorizontalPodAutoscaler": "HPA",
    "StatefulSet": "STS",
    "Job": "JOB",
    "CronJob": "CJ",
    "ConfigMap": "CM",
    "Secret": "SEC",
    "Ingress": "ING",
    "PersistentVolumeClaim": "PVC",
    "PersistentVolume": "PV",
    "DaemonSet": "DS",
    "NetworkPolicy": "NP",
    "PodDisruptionBudget": "PDB",
    "ScaledObject": "SO",
    "ResourceQuota": "RQ",
    "LimitRange": "LR",
    "Pod": "POD",
    "ServiceAccount": "SA",
    "Role": "ROLE",
    "ClusterRole": "CR",
    "RoleBinding": "RB",
    "ClusterRoleBinding": "CRB",
    "Namespace": "NS",
    "Route": "RTE",
    "HTTPRoute": "HR",
    "Gateway": "GW",
}

#: The colour family of a card, by kind: a class name this module chose, never text from the input.
TONE = {
    **dict.fromkeys(("Service", "Ingress", "NetworkPolicy", "Route", "HTTPRoute", "Gateway"), "net"),
    **dict.fromkeys(("Deployment",), "api"),
    **dict.fromkeys(("ReplicaSet",), "control"),
    **dict.fromkeys(("StatefulSet", "DaemonSet", "Job", "CronJob", "Pod", "PersistentVolume"), "node"),
    **dict.fromkeys(("ConfigMap", "PersistentVolumeClaim", "LimitRange", "Namespace"), "state"),
    **dict.fromkeys(("Secret", "PodDisruptionBudget", "ResourceQuota"), "drop"),
    **dict.fromkeys(("HorizontalPodAutoscaler", "ScaledObject"), "scale"),
    **dict.fromkeys(("ServiceAccount", "Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding"), "rbac"),
}

#: How each kind of art stands: half its footprint on screen, how far under it the label sits, and what the
#: camera must keep in view around it ([left, top, right, bottom] from its position, label included).
ART: dict[str, tuple[Point, float, Box]] = {
    "card": ((23, 16), 42, (-84, -28, 84, 84)),
    "node": ((37, 37), 58, (-90, -60, 90, 100)),
    "laptop": ((23, 28), 46, (-80, -75, 80, 88)),
    "browser": ((23, 28), 46, (-80, -75, 80, 88)),
    "lb": ((28, 28), 50, (-80, -55, 80, 92)),
    "rack": ((18, 18), 42, (-80, -60, 80, 84)),
    "api": ((23, 23), 48, (-80, -70, 80, 90)),
    "sched": ((20, 20), 38, (-80, -50, 80, 80)),
    "pod": ((20, 20), 46, (-90, -70, 90, 88)),
    "box": ((21, 16), 36, (-80, -40, 80, 78)),
}

#: Worst first: the state an actor shows is the worst among the hops standing on it. Nothing here outranks a
#: break, and a hop nobody judged never outranks one somebody did.
RANK = {"fails": 6, "cannot-judge": 5, "unrecognised": 5, "holds": 3, "not-observable": 2, "not-walked": 1}

NOT_IN_MANIFEST = "not in any manifest"


@dataclass(frozen=True)
class Spot:
    """Where one hop stands, and what is drawn there when the hop has no manifest object."""

    g: Point
    art: str = "card"
    name: str = ""
    word: str = ""
    slots: tuple[str, ...] = ()


@dataclass(frozen=True)
class Layout:
    """One lesson's stage: the plate, the scenery on it, where the path starts, and a spot per hop id."""

    floor: tuple[float, float, float, float]  # x0, x1, y0, y1 in ground units
    steps: dict[str, Spot]
    scenery: tuple[Spot, ...] = ()
    origin: Spot | None = None


_NODES = (36.0, 10.0), (36.0, -26.0)
_PLATE = (12.0, 58.0, -46.0, 38.0)
# The spots, by role. Traffic cards stand in front of the nodes, workloads and policy behind and to the left,
# things outside the cluster front right -- the same arrangement as world.ts RESOURCES.
_TRAFFIC_FAR, _TRAFFIC_NEAR = (44.0, 86.0), (44.0, 57.0)
_WORKLOAD, _POLICY = (0.0, -30.0), (0.0, 6.0)
_EDGE, _EDGE_FRONT = (86.0, -8.0), (86.0, 34.0)

LAYOUTS: dict[str, Layout] = {
    "mech-net-request-to-pod": Layout(
        floor=_PLATE,
        origin=Spot(_EDGE_FRONT, "browser", "Visitor"),
        scenery=(Spot(_NODES[1], "node", "worker node", slots=("other", "v1", "v1")),),
        steps={
            "edge-admits": Spot(_TRAFFIC_FAR),
            "edge-names-a-service-here": Spot(_TRAFFIC_FAR),
            "service-selects-pods": Spot(_TRAFFIC_NEAR),
            "workload-selects-its-own-pods": Spot(_WORKLOAD),
            "policy-admits-the-packet": Spot(_POLICY),
            "pod-reports-ready": Spot(_WORKLOAD),
            "packet-reaches-the-container": Spot(_NODES[0], "node", "Node network", slots=("other", "v1")),
        },
    ),
    "mech-net-pod-calls-a-service": Layout(
        floor=_PLATE,
        origin=Spot(_NODES[0], "node", "Calling pod's node", slots=("v1", "other")),
        steps={
            "namespace-has-a-policy": Spot(_POLICY),
            "egress-keeps-dns": Spot(_POLICY),
            "name-resolves": Spot(_EDGE_FRONT, "rack", "Cluster DNS", word="DNS"),
            "service-selects-pods": Spot(_TRAFFIC_NEAR),
            "workload-selects-its-own-pods": Spot(_WORKLOAD),
            "pod-reports-ready": Spot(_WORKLOAD),
            "clusterip-is-translated": Spot(_NODES[1], "node", "ClusterIP translation", slots=("other", "v1", "v1")),
        },
    ),
    "mech-cp-a-node-goes-dark": Layout(
        floor=_PLATE,
        scenery=(
            Spot(_NODES[0], "node", "worker node", slots=("other", "v1")),
            Spot(_NODES[1], "node", "worker node", slots=("v1", "other", "v1")),
        ),
        steps={
            "more-than-one-replica": Spot(_WORKLOAD),
            "replicas-can-land-apart": Spot(_WORKLOAD),
            "the-budget-lets-one-go": Spot(_POLICY),
            "the-scheduler-places-the-replacement": Spot(_EDGE, "sched", "Scheduler"),
        },
    ),
    "mech-sec-rbac-and-serviceaccounts": Layout(
        floor=_PLATE,
        scenery=(
            Spot(_NODES[0], "node", "worker node", slots=("other", "v1")),
            Spot(_NODES[1], "node", "worker node", slots=("v1", "other", "v1")),
        ),
        steps={
            # The RBAC objects in a row, in the order a request meets them.
            "no-pod-automounts-a-token": Spot((0.0, 42.0)),
            "no-binding-grants-to-everyone": Spot(_POLICY),
            "no-binding-names-cluster-admin": Spot(_POLICY),
            "no-role-uses-a-wildcard": Spot(_WORKLOAD),
            "no-role-carries-an-escalation-grant": Spot(_WORKLOAD),
            "no-long-lived-token-secret": Spot((0.0, -66.0)),
            "the-api-server-authorizes-the-request": Spot((40.0, 66.0), "api", "API server"),
        },
    ),
}

#: The plain row: how far apart along the floor's x axis, how many to a row, how far apart the rows.
_ROW_STEP, _ROW_LEN, _ROW_GAP = 34.0, 5, 40.0


@dataclass
class Actor:
    id: str
    art: str
    g: Point
    name: str
    sub: str
    badge: str = ""
    tone: str = ""
    manifest: bool = True
    word: str = ""
    slots: tuple[str, ...] = ()
    hops: list[int] = field(default_factory=list)
    scenery: bool = False

    @property
    def pos(self) -> Point:
        return to_screen(self.g)

    @property
    def foot(self) -> Point:
        return ART[self.art][0]

    @property
    def label_dy(self) -> float:
        return ART[self.art][1]

    @property
    def box(self) -> Box:
        return ART[self.art][2]


def to_screen(g: Point) -> Point:
    p = I.iso(g[0], g[1], 0, S)
    return (ORIGIN[0] + p[0], ORIGIN[1] + p[1])


def clip(text: str, limit: int) -> str:
    """A label short enough to draw. The whole text is always in the story beside the scene."""
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "\u2026"


def badge_for(kind: str) -> str:
    """The code on a card. A kind this build has no code for gets its capitals; a kind with none gets `?`."""
    known = BADGE.get(kind)
    if known:
        return known
    caps = re.sub(r"[^A-Z0-9]", "", kind)[:4]
    return caps or re.sub(r"[^A-Za-z0-9]", "", kind)[:3].upper() or "?"


def split_object(obj: str) -> tuple[str, str, str]:
    """`Ingress/shop/shop` -> (kind, namespace, name). The namespace is empty when the object states none."""
    parts = obj.split("/")
    if len(parts) == 3:
        return parts[0], parts[1], parts[2]
    if len(parts) == 2:
        return parts[0], "", parts[1]
    return parts[0], "", "/".join(parts[1:])


def _art(a: Actor, esc: Callable[[object], str]) -> str:
    if a.art == "card":
        return I.resource_card(S * 0.85, esc(a.badge))
    if a.art == "node":
        return I.worker_node(S, a.slots or ("other", "other"))
    if a.art in ("laptop", "browser"):
        return I.laptop(S, "browser" if a.art == "browser" else "terminal")
    if a.art == "lb":
        return I.load_balancer(S)
    if a.art == "rack":
        return I.rack(S * 0.85, esc(a.word))
    if a.art == "api":
        return I.api_server(S)
    if a.art == "sched":
        return I.scheduler(S)
    if a.art == "pod":
        return I.pod(S * 0.85)
    return I.chip(S, 9, 7, 3, esc(a.word or "?"))


def _covers(a: Actor) -> Box:
    return (a.g[0] - a.foot[0] / S, a.g[1] - a.foot[1] / S, a.g[0] + a.foot[0] / S, a.g[1] + a.foot[1] / S)


def _ground_route(a: Actor, b: Actor, others: list[Actor]) -> list[Point]:
    """An L along the floor's two axes from a to b: the one that runs under fewer other actors, x first on a tie."""
    p, q = a.g, b.g
    if p[0] == q[0] or p[1] == q[1]:
        return [p, q]
    options = ([p, (q[0], p[1]), q], [p, (p[0], q[1]), q])
    boxes = [_covers(o) for o in others if o.id not in (a.id, b.id)]

    def hits(route: list[Point]) -> int:
        count = 0
        for x0, y0, x1, y1 in boxes:
            for i in range(1, len(route)):
                u, v = route[i - 1], route[i]
                if max(u[0], v[0]) > x0 and min(u[0], v[0]) < x1 and max(u[1], v[1]) > y0 and min(u[1], v[1]) < y1:
                    count += 1
                    break
        return count

    return options[0] if hits(options[0]) <= hits(options[1]) else options[1]


def _screen_route(route: list[Point], a: Actor, b: Actor) -> list[Point]:
    """A ground route as screen points, trimmed so it starts and ends at the edges of the two footprints."""
    out = [to_screen(p) for p in route]
    if len(out) < 2:
        return out

    def trim(end: Point, nxt: Point, g_end: Point, g_next: Point, actor: Actor) -> Point:
        r = actor.foot[0] if g_end[0] != g_next[0] else actor.foot[1]
        length = math.hypot(nxt[0] - end[0], nxt[1] - end[1])
        k = min(r, length * 0.45) / (length or 1.0)
        return (end[0] + (nxt[0] - end[0]) * k, end[1] + (nxt[1] - end[1]) * k)

    n = len(out) - 1
    first = trim(out[0], out[1], route[0], route[1], a)
    last = trim(out[n], out[n - 1], route[n], route[n - 1], b)
    out[0], out[n] = first, last
    return out


def frame(actors: list[Actor], min_width: float, also: list[Point], caption: bool) -> list[float]:
    """The smallest world box that shows these actors, padded and kept at the stage's aspect ratio."""
    xs = [p[0] for p in also]
    ys = [p[1] for p in also]
    for a in actors:
        xs += [a.pos[0] + a.box[0], a.pos[0] + a.box[2]]
        ys += [a.pos[1] + a.box[1], a.pos[1] + a.box[3]]
    if not xs:
        return [0.0, 0.0, WORLD[0], WORLD[1]]
    x0, x1, y0, y1 = min(xs), max(xs), min(ys), max(ys)
    pad = 48.0
    # Room under the actors for the caption and the transport bar, which sit over the bottom of the stage.
    y1 += 110.0 if caption else 56.0
    w = max(x1 - x0 + pad * 2, min_width)
    h = y1 - y0 + pad * 2
    ratio = WORLD[0] / WORLD[1]
    if w / h > ratio:
        h = w / ratio
    else:
        w = h * ratio
    cx, cy = (x0 + x1) / 2, (y0 + y1) / 2
    return [round(cx - w / 2, 1), round(cy - h / 2, 1), round(w, 1), round(h, 1)]


def _d(points: list[Point]) -> str:
    return " ".join(f"{'L' if i else 'M'}{I.num(p[0], 1)} {I.num(p[1], 1)}" for i, p in enumerate(points))


def _floor(rect: tuple[float, float, float, float], text: str, esc: Callable[[object], str]) -> tuple[str, list[Point]]:
    """The plate the scene stands on: a thin slab with a faint grid and its name lying on it."""
    x0, x1, y0, y1 = rect

    def p(x: float, y: float) -> Point:
        return to_screen((x, y))

    def down(q: Point) -> Point:
        return (q[0], q[1] + 6)

    a, b, c, e = p(x0, y0), p(x1, y0), p(x1, y1), p(x0, y1)
    grid: list[str] = []
    x = x0 + 4
    while x < x1:
        grid.append(_d([p(x, y0), p(x, y1)]))
        x += 4
    y = y0 + 4
    while y < y1:
        grid.append(_d([p(x0, y), p(x1, y)]))
        y += 4
    ox, oy = p(x0 + 2, y1 - 2.4)
    c30, half = I.C30 * S, 0.5 * S
    matrix = f"matrix({I.num(c30, 3)} {I.num(half, 3)} {I.num(-c30, 3)} {I.num(half, 3)} {I.num(ox, 1)} {I.num(oy, 1)})"
    markup = (
        '<g class="floor">'
        f'<polygon class="floor-edge" points="{I.pts([e, c, down(c), down(e)])}"/>'
        f'<polygon class="floor-edge" points="{I.pts([c, b, down(b), down(c)])}"/>'
        f'<polygon class="floor-top" points="{I.pts([a, b, c, e])}"/>'
        f'<path class="floor-grid" d="{"".join(grid)}"/>'
        f'<text class="floor-name" transform="{matrix}" font-size="2.1">{esc(text)}</text>'
        "</g>"
    )
    return markup, [down(q) for q in (a, b, c, e)]


def _hop_actor(h: dict[str, Any], spot: Spot | None) -> tuple[str, Actor]:
    """The key two hops share when they stand on the same thing, and the actor for the first of them."""
    g = spot.g if spot else (0.0, 0.0)
    objects: list[str] = h["objects"]
    kinds: list[str] = h["kinds"]
    if objects:
        kind, namespace, name = split_object(objects[0])
        sub = f"namespace {namespace}" if namespace else "no namespace stated"
        if len(objects) > 1:
            sub += f" \u00b7 +{len(objects) - 1} more"
        return "obj:" + objects[0], Actor(
            "", "card", g, clip(f"{kind} {name}", 30), clip(sub, 34), badge_for(kind), TONE.get(kind, "other")
        )
    if kinds:
        kind = kinds[0]
        name = kind if len(kinds) == 1 else f"{kind} (or {len(kinds) - 1} more kinds)"
        return "kind:" + "/".join(kinds), Actor(
            "", "card", g, clip(name, 30), "kind; no object named", badge_for(kind), TONE.get(kind, "other")
        )
    # No object and no kind: nothing a manifest holds. The lesson's layout may say what stands here.
    if spot and spot.art != "card":
        return f"hop:{h['n']}", Actor(
            "", spot.art, g, spot.name or clip(h["title"], 30), NOT_IN_MANIFEST, manifest=False, word=spot.word,
            slots=spot.slots,
        )  # fmt: skip
    return f"hop:{h['n']}", Actor("", "box", g, clip(h["title"], 30), NOT_IN_MANIFEST, manifest=False, word=str(h["n"]))


def _free(g: Point, taken: set[Point]) -> Point:
    """`g`, or the nearest spot behind it that nothing stands on: two different objects never share a spot."""
    while g in taken:
        g = (g[0] - 32.0, g[1])
    return g


def build(
    hops: list[dict[str, Any]], lesson: str, namespaces: list[str], esc: Callable[[object], str]
) -> dict[str, Any]:
    """The scene for one walk. Adds to every hop where it stands and how the event reaches it; returns the
    markup of the stage and of the sequence diagram, and the data the script needs to move between them."""
    layout = LAYOUTS.get(lesson)
    if layout is not None and any(h["id"] not in layout.steps for h in hops):
        layout = None  # not the path this layout was drawn for: the plain row, not a guess

    actors: list[Actor] = []
    by_key: dict[str, Actor] = {}
    taken: set[Point] = set()

    def add(a: Actor) -> Actor:
        a.id = f"a{len(actors)}"
        a.g = _free(a.g, taken)
        taken.add(a.g)
        actors.append(a)
        return a

    origin: Actor | None = None
    if layout is not None:
        for sp in layout.scenery:
            add(Actor("", sp.art, sp.g, sp.name, NOT_IN_MANIFEST, manifest=False, slots=sp.slots, scenery=True))
        if layout.origin is not None:
            sp = layout.origin
            origin = add(
                Actor("", sp.art, sp.g, sp.name, NOT_IN_MANIFEST, manifest=False, word=sp.word, slots=sp.slots,
                      scenery=True)
            )  # fmt: skip

    for h in hops:
        key, fresh = _hop_actor(h, layout.steps[h["id"]] if layout is not None else None)
        actor = by_key.get(key)
        if actor is None:
            if layout is None:
                i = len(by_key)
                col, row = i % _ROW_LEN, i // _ROW_LEN
                fresh.g = (col * _ROW_STEP, row * _ROW_GAP)
            actor = by_key[key] = add(fresh)
        actor.hops.append(h["n"])
        h["actor"] = actor.id

    if layout is not None:
        rect = layout.floor
    elif actors:
        gx, gy = [a.g[0] for a in actors], [a.g[1] for a in actors]
        rect = (min(gx) - 14, max(gx) + 14, min(gy) - 12, max(gy) + 16)
    else:
        rect = _PLATE
    where = f"namespace {namespaces[0]}" if len(namespaces) == 1 else ""
    floor, corners = _floor(rect, clip("cluster" + (f" \u00b7 {where}" if where else ""), 60), esc)

    ids = {a.id: a for a in actors}
    cables: list[str] = []
    prev = origin
    for h in hops:
        here = ids[h["actor"]]
        start = prev or here
        h["from"] = start.id
        route = [] if start.id == here.id else _screen_route(_ground_route(start, here, actors), start, here)
        h["route"] = [[round(p[0], 1), round(p[1], 1)] for p in route]
        h["at"] = [round(here.pos[0], 1), round(here.pos[1] - 20, 1)]
        h["frame"] = frame([start, here], 820.0, [], caption=True)
        h["chip"] = clip(h["title"], 34)
        if route:
            cables.append(f'<path class="cable c-{h["state"]}" id="cab-{h["n"]}" d="{_d(route)}"/>')
        prev = here

    state = {h["n"]: (h["state"], h["glyph"], h["mark"]) for h in hops}
    drawn: list[str] = []
    for a in sorted(actors, key=lambda a: (a.g[0] + a.g[1], a.id)):
        worst = max((state[n] for n in a.hops), key=lambda s: RANK.get(s[0], 5), default=None)
        verdict = worst[0] if worst else "none"
        word = f"{worst[1]} {worst[2]}" if worst else ""
        classes = "actor" + (" res" if a.art == "card" else "") + (f" tone-{a.tone}" if a.tone else "")
        classes += " scenery" if a.scenery else ""
        x, y = a.pos
        drawn.append(
            f'<g class="{classes}" id="act-{a.id}" data-v="{verdict}" data-manifest="{"yes" if a.manifest else "no"}">'
            f'<g transform="translate({I.num(x, 1)} {I.num(y, 1)})">{_art(a, esc)}</g>'
            f'<g class="alabel" transform="translate({I.num(x, 1)} {I.num(y + a.label_dy, 1)})" text-anchor="middle">'
            f'<text class="n">{esc(a.name)}</text><text class="ip" y="16">{esc(a.sub)}</text>'
            f'<text class="st" y="32">{esc(word)}</text></g></g>'
        )

    overview = frame(actors, WORLD[0], corners if layout is not None or actors else [], caption=False)
    view_box = " ".join(I.num(v, 1) for v in overview)
    scene = (
        f'<svg class="iso scene" id="scene" viewBox="{view_box}" preserveAspectRatio="xMidYMid meet" role="img" '
        'aria-label="Isometric diagram of the path. The list of hops beside it says the same in words.">'
        f'<g class="level">{floor}{"".join(cables)}<path class="trail" id="trail" d=""/>{"".join(drawn)}'
        '<g id="dot"><circle class="ring" r="16"/><circle class="ring r2" r="16"/><circle class="core" r="6"/>'
        '<path class="x" d="M-3 -3L3 3M3 -3L-3 3"/><path class="bar" d="M-3 0H3"/>'
        '<g class="mchip" transform="translate(0 -24)"><rect x="-80" y="-11" width="160" height="21" rx="4"/>'
        '<text text-anchor="middle" y="4"></text></g></g>'
        "</g></svg>"
    )

    lanes = ([origin] if origin else []) + [a for a in actors if a.hops]
    return {
        "scene": scene,
        "sequence": _sequence(hops, lanes, esc),
        "data": {
            "frame": overview,
            "actors": [{"id": a.id, "hops": a.hops} for a in actors],
            "layout": lesson if layout is not None else "row",
        },
    }


_GUTTER, _LANE_W, _HEAD_H, _ROW_H = 58.0, 150.0, 44.0, 34.0


def _sequence(hops: list[dict[str, Any]], lanes: list[Actor], esc: Callable[[object], str]) -> str:
    """The walk as a sequence diagram: a lane per actor in hop order, an arrow per hop, its verdict in words."""
    if not lanes:
        return ""
    at = {a.id: _GUTTER + i * _LANE_W + _LANE_W / 2 for i, a in enumerate(lanes)}
    width = _GUTTER + len(lanes) * _LANE_W + 16
    height = _HEAD_H + len(hops) * _ROW_H + 24
    out = [
        f'<svg class="seq-body" id="seq" width="{I.num(width, 0)}" height="{I.num(height, 0)}" '
        f'viewBox="0 0 {I.num(width, 0)} {I.num(height, 0)}" role="img" '
        'aria-label="Sequence diagram of the path. The list of hops beside it says the same in words.">'
    ]
    for a in lanes:
        x = I.num(at[a.id], 1)
        out.append(f'<text class="seq-lane" x="{x}" y="26" text-anchor="middle">{esc(clip(a.name, 22))}</text>')
        out.append(f'<line class="lifeline" x1="{x}" x2="{x}" y1="{I.num(_HEAD_H, 0)}" y2="{I.num(height, 0)}"/>')
    for i, h in enumerate(hops):
        top = _HEAD_H + 8 + i * _ROW_H
        mid = top + _ROW_H / 2 + 6
        x1, x2 = at.get(h["from"], at[h["actor"]]), at[h["actor"]]
        own = x1 == x2
        left = own and x1 > width * 0.6
        span = (x1 - _GUTTER - 16 if left else width - x1 - 40) if own else max(abs(x2 - x1) - 8, 280)
        label = clip(f"{h['glyph']} {h['mark']}: {h['title']}", max(8, int(span / 6.6)))
        half = len(label) * 6.6 / 2
        if own:
            turn = -1 if left else 1
            arrow = (
                f'<path class="seq-arrow" d="M{I.num(x1, 1)} {I.num(mid - 6, 1)} h{26 * turn} v12 h{-24 * turn}"/>'
                f'<path class="seq-head" d="M{I.num(x1 + 2 * turn, 1)} {I.num(mid + 6, 1)} l{7 * turn} -4 v8 z"/>'
            )
            lx, anchor, ly = x1 + 32 * turn, ("end" if left else "start"), mid + 4
        else:
            turn = 1 if x2 > x1 else -1
            arrow = (
                f'<line class="seq-arrow" x1="{I.num(x1, 1)}" x2="{I.num(x2 - 3 * turn, 1)}" '
                f'y1="{I.num(mid, 1)}" y2="{I.num(mid, 1)}"/>'
                f'<path class="seq-head" d="M{I.num(x2, 1)} {I.num(mid, 1)} l{-7 * turn} -4 v8 z"/>'
            )
            lx, anchor, ly = min(max((x1 + x2) / 2, _GUTTER + half), width - 4 - half), "middle", mid - 6
        out.append(
            f'<g class="seq-row s-{h["state"]}" id="seq-{h["n"]}">'
            f'<rect class="seq-hit" x="0" y="{I.num(top, 1)}" width="{I.num(width, 0)}" height="{I.num(_ROW_H, 0)}"/>'
            f'<text class="seq-time" x="8" y="{I.num(mid + 4, 1)}">hop {h["n"]}</text>{arrow}'
            f'<text class="seq-label" x="{I.num(lx, 1)}" y="{I.num(ly, 1)}" text-anchor="{anchor}">{esc(label)}</text>'
            "</g>"
        )
    out.append("</svg>")
    return "".join(out)
