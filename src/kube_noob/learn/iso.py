"""Isometric drawing helpers for the mechanism walk's scene: boxes, cards, nodes and the things around a cluster.

Ported from KubeLearn's ``src/iso/iso.ts`` (kubelearn.joesabbagh.com), Copyright (c) 2026 Joe Sabbagh, MIT License;
the notice is reproduced in ``THIRD_PARTY_NOTICES.md``. The shapes and their proportions are that project's. What
is this module's own: every number is written with a fixed count of decimals and no negative zero, so the same
call is the same bytes on every platform (G402's rule for the page these shapes are drawn on), and every builder
takes only numbers and text this package wrote -- a label out of a manifest is escaped by the caller, never here.

World x runs to the lower right, y to the lower left, z up. Every builder returns SVG markup in screen pixels,
centred on the shape's footprint.
"""

from __future__ import annotations

import math

#: cos(30 degrees), written out: `math.cos` is the platform's libm, and the page must not depend on its last bit.
C30 = 0.8660254037844387

Point = tuple[float, float]


def num(value: float, places: int = 2) -> str:
    """A number as the page writes it: fixed decimals, trailing zeros dropped, and never ``-0``."""
    text = f"{value:.{places}f}"
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return "0" if text in ("-0", "") else text


def iso(x: float, y: float, z: float, s: float) -> Point:
    """Ground (x, y) at height z, as a screen point at scale s."""
    return ((x - y) * C30 * s, (x + y) * 0.5 * s - z * s)


def pts(points: list[Point] | tuple[Point, ...]) -> str:
    return " ".join(f"{num(p[0])},{num(p[1])}" for p in points)


def _mtx(*n: float) -> str:
    return "matrix(" + " ".join(num(v, 3) for v in n) + ")"


def face_y(x: float, y: float, z: float, s: float) -> str:
    """The transform that draws flat units on a box's left face."""
    o = iso(x, y, z, s)
    return _mtx(C30 * s, 0.5 * s, 0, s, o[0], o[1])


def face_x(x: float, y: float, z: float, s: float) -> str:
    """The transform that draws flat units on a box's right face."""
    o = iso(x, y, z, s)
    return _mtx(C30 * s, -0.5 * s, 0, s, o[0], o[1])


def face_top(x: float, y: float, z: float, s: float) -> str:
    """The transform that draws flat units lying on a box's top face."""
    o = iso(x, y, z, s)
    return _mtx(C30 * s, 0.5 * s, -C30 * s, 0.5 * s, o[0], o[1])


def box(x: float, y: float, z: float, w: float, d: float, h: float, s: float, cls: str = "") -> str:
    """A box with its three visible faces: left, right, top."""

    def p(a: float, b: float, c: float) -> Point:
        return iso(a, b, c, s)

    top = [p(x, y, z + h), p(x + w, y, z + h), p(x + w, y + d, z + h), p(x, y + d, z + h)]
    left = [p(x, y + d, z), p(x + w, y + d, z), p(x + w, y + d, z + h), p(x, y + d, z + h)]
    right = [p(x + w, y, z), p(x + w, y + d, z), p(x + w, y + d, z + h), p(x + w, y, z + h)]
    return (
        f'<g class="{cls}"><polygon class="f-l" points="{pts(left)}"/>'
        f'<polygon class="f-r" points="{pts(right)}"/><polygon class="f-t" points="{pts(top)}"/></g>'
    )


def cylinder(z: float, r: float, h: float, s: float) -> str:
    rx, ry = num(1.2247 * r * s), num(0.7071 * r * s)
    yb, yt = num(-z * s), num(-(z + h) * s)
    return (
        f'<g><path class="f-l" d="M-{rx},{yb} A{rx},{ry} 0 0 0 {rx},{yb} L{rx},{yt} A{rx},{ry} 0 0 1 -{rx},{yt} Z"/>'
        f'<ellipse class="f-t" cx="0" cy="{yt}" rx="{rx}" ry="{ry}"/></g>'
    )


def hidden_edges(x: float, y: float, w: float, d: float, h: float, s: float) -> str:
    """The three edges of a glass box that a solid one would hide."""

    def line(a: Point, b: Point) -> str:
        return f'<line class="hid" x1="{num(a[0], 1)}" y1="{num(a[1], 1)}" x2="{num(b[0], 1)}" y2="{num(b[1], 1)}"/>'

    o = iso(x, y, 0, s)
    return line(o, iso(x, y, h, s)) + line(o, iso(x + w, y, 0, s)) + line(o, iso(x, y + d, 0, s))


def arrow(x1: float, y1: float, x2: float, y2: float) -> str:
    """A line with an open arrowhead at its far end, as path data."""
    length = math.hypot(x2 - x1, y2 - y1) or 1.0
    ux, uy = (x2 - x1) / length, (y2 - y1) / length
    k = 1.1

    def head(a: float) -> Point:
        return (x2 - k * (ux * math.cos(a) - uy * math.sin(a)), y2 - k * (uy * math.cos(a) + ux * math.sin(a)))

    h1, h2 = head(0.6), head(-0.6)
    return (
        f"M{num(x1)} {num(y1)} L{num(x2)} {num(y2)} "
        f"M{num(h1[0])} {num(h1[1])} L{num(x2)} {num(y2)} L{num(h2[0])} {num(h2[1])}"
    )


def leds(positions: tuple[float, ...], v: float, accent_index: int = 1) -> str:
    return "".join(
        f'<circle class="led{" b" if i == accent_index else ""}" cx="{num(u)}" cy="{num(v)}" r=".4"/>'
        for i, u in enumerate(positions)
    )


#: What a laptop's screen shows. Text this module wrote: no address, no name out of the reader's input.
_TERMINAL = (
    '<text class="scr" x="1.4" y="2.7" font-size="1.3">&gt;_ kubectl</text>'
    '<text class="scr d" x="1.4" y="4.4" font-size="1.15">apply -f</text>'
)
_BROWSER = (
    '<rect class="bar" x="1.3" y="1.2" width="9.4" height="1.5" rx=".35"/>'
    '<line class="det" x1="1.4" y1="4" x2="8.6" y2="4"/><line class="det" x1="1.4" y1="5.1" x2="9.8" y2="5.1"/>'
    '<line class="det" x1="1.4" y1="6.2" x2="6.4" y2="6.2"/>'
)


def laptop(s: float, screen: str = "terminal") -> str:
    """A laptop. The screen shows a terminal, or a browser for a visitor."""
    g = box(-5, -6, 0, 10, 12, 0.8, s)
    keys = "".join(
        f'<rect x="{num(1.2 + row * 1.1)}" y="{num(1.4 + i * 1.05)}" width=".8" height=".75"/>'
        for row in range(3)
        for i in range(9)
    )
    g += (
        f'<g class="keys" transform="{face_top(-4.4, -6, 0.8, s)}">{keys}'
        '<rect x="5.2" y="4" width="2.6" height="4"/></g>'
    )
    g += box(-5, -6, 0.8, 0.6, 12, 7.8, s)
    g += (
        f'<g transform="{face_x(-4.4, 6, 8.6, s)}"><rect class="display-r" x=".7" y=".7" width="10.6" height="6.4"/>'
        f"{_BROWSER if screen == 'browser' else _TERMINAL}</g>"
    )
    return g


def api_server(s: float) -> str:
    """The API server: a stack of three units."""
    g = ""
    for k in range(3):
        z = k * 2.7
        g += box(-5, -5, z, 10, 10, 2.2, s)
        g += (
            f'<g transform="{face_x(5, 5, z + 2.2, s)}">{leds((1.3, 2.5), 1.1)}'
            '<line class="det" x1="5" y1=".8" x2="8.8" y2=".8"/>'
            '<line class="det" x1="5" y1="1.4" x2="8.8" y2="1.4"/></g>'
        )
        g += f'<g transform="{face_y(-5, 5, z + 2.2, s)}"><line class="det" x1="1" y1="1.1" x2="9" y2="1.1"/></g>'
    g += (
        f'<g transform="{face_top(-5, -5, 7.6, s)}">'
        '<text class="topt" x="5" y="5.9" font-size="2.6" text-anchor="middle">API</text></g>'
    )
    return g


def scheduler(s: float) -> str:
    """The scheduler: a grid of nodes on its top face, one of them picked."""
    g = box(-4.6, -4.6, 0, 9.2, 9.2, 3, s)
    cells = "".join(
        f'<rect class="cell" x="{num(1.4 + (i % 2) * 3.5)}" y="{num(1.4 + (i >> 1) * 3.5)}" width="2.9" height="2.9"/>'
        for i in range(4)
    )
    g += f'<g transform="{face_top(-4.6, -4.6, 3, s)}">{cells}</g>'
    g += (
        f'<g transform="{face_x(4.6, 4.6, 3, s)}">{leds((1.2, 2.4), 1.4)}'
        '<line class="det" x1="4.5" y1="1.1" x2="8" y2="1.1"/><line class="det" x1="4.5" y1="1.8" x2="8" y2="1.8"/></g>'
    )
    g += box(0.3, -3.2, 3, 2.9, 2.9, 2.4, s, "hot")
    return g


def etcd(s: float) -> str:
    g = "".join(cylinder(k * 2.5, 4.4, 1.9, s) for k in range(3))
    g += (
        f'<g transform="{face_top(0, 0, 6.9, s)}">'
        '<text class="topt" x="0" y=".8" font-size="2" text-anchor="middle">etcd</text></g>'
    )
    return g


#: The pod-slot classes a worker node may draw. Anything else is drawn as `other`.
SLOTS = ("other", "v1", "v2", "starting", "terminating")


def worker_node(s: float, slots: tuple[str, ...] = ("other", "other")) -> str:
    """A worker node: a slab with up to four pod cubes standing on it."""
    g = box(-8, -8, 0, 16, 16, 2.4, s)
    g += (
        f'<g transform="{face_x(8, 8, 2.4, s)}">{leds((1.3, 2.6, 3.9), 1.2)}'
        '<line class="det" x1="6" y1=".9" x2="14.5" y2=".9"/><line class="det" x1="6" y1="1.6" x2="14.5" y2="1.6"/></g>'
    )
    spots = ((-6.8, -6.8), (1.3, -6.8), (-6.8, 1.3), (1.3, 1.3))
    for slot, (x, y) in zip(slots[:4], spots, strict=False):
        g += box(x, y, 2.4, 5.5, 5.5, 4.4, s, f"slot slot-{slot if slot in SLOTS else 'other'}")
    return g


def chip(s: float, w: float, d: float, h: float, label: str, cls: str = "") -> str:
    """A labelled box: the generic part. `label` must already be escaped."""
    g = box(-w / 2, -d / 2, 0, w, d, h, s, cls)
    size = min(2.1, (w * 1.45) / max(len(label), 3))
    g += (
        f'<g transform="{face_top(-w / 2, -d / 2, h, s)}"><text class="topt" x="{num(w / 2)}" '
        f'y="{num(d / 2 + size * 0.35)}" font-size="{num(size)}" text-anchor="middle">{label}</text></g>'
    )
    g += f'<g transform="{face_x(w / 2, d / 2, h, s)}">{leds((1, 2), min(h / 2, 1.1), 0)}</g>'
    return g


def resource_card(s: float, badge: str) -> str:
    """A Kubernetes API object drawn as a stacked record card: kind initials on the top face.

    `badge` must already be escaped; it is a code this package chose (ING, SVC), never a string out of a manifest.
    """
    g = box(-6, -4, 0, 12, 8, 1.6, s)
    g += box(-6, -4, 1.6, 12, 8, 1.1, s, "sheet")
    size = 2.7 if len(badge) <= 3 else 2.1
    g += (
        f'<g transform="{face_top(-6, -4, 2.7, s)}"><text class="topt" x="6" y="5.2" font-size="{num(size)}" '
        f'text-anchor="middle">{badge}</text></g>'
    )
    return g


def rack(s: float, label: str) -> str:
    """A server rack with a word on top, for a service the path uses and no manifest shows, like a DNS resolver."""
    g = ""
    for k in range(2):
        z = k * 2.7
        g += box(-4.5, -4.5, z, 9, 9, 2.2, s)
        g += (
            f'<g transform="{face_x(4.5, 4.5, z + 2.2, s)}">{leds((1.2, 2.4), 1.1)}'
            '<line class="det" x1="4.5" y1="1.1" x2="8" y2="1.1"/></g>'
        )
    g += (
        f'<g transform="{face_top(-4.5, -4.5, 4.9, s)}"><text class="topt" x="4.5" y="5.4" font-size="2.3" '
        f'text-anchor="middle">{label}</text></g>'
    )
    return g


def pod(s: float) -> str:
    """A Pod: a glass box around its containers."""
    g = hidden_edges(-5, -5, 10, 10, 9, s)
    g += box(-3.8, -3.8, 0, 2.6, 2.6, 2.6, s)
    g += box(-1.2, -1.2, 0, 5, 5, 6.2, s, "hot")
    g += f'<g transform="{face_y(-1.2, 3.8, 6.2, s)}"><text class="topt" x=".7" y="1.9" font-size="1.4">app</text></g>'
    g += box(-5, -5, 0, 10, 10, 9, s, "glass")
    return g


def load_balancer(s: float) -> str:
    g = box(-6, -6, 0, 12, 12, 2.6, s)
    fan = " ".join((arrow(1.6, 6, 5.2, 6), arrow(5.2, 6, 10.2, 2.4), arrow(5.2, 6, 10.4, 6), arrow(5.2, 6, 10.2, 9.6)))
    g += f'<g class="arrows" transform="{face_top(-6, -6, 2.6, s)}"><path d="{fan}"/></g>'
    g += (
        f'<g transform="{face_x(6, 6, 2.6, s)}">{leds((1.2, 2.4), 1.3)}'
        '<line class="det" x1="5" y1="1.3" x2="10.8" y2="1.3"/></g>'
    )
    return g


def logo(s: float) -> str:
    """The mark in the page header: a cube inside a glass cube."""
    return (
        hidden_edges(-5, -5, 10, 10, 10, s)
        + box(-2.2, -2.2, 0, 4.4, 4.4, 4.4, s, "hot")
        + box(-5, -5, 0, 10, 10, 10, s, "glass")
    )
