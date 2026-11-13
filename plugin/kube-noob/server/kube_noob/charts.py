"""Inline SVG charts for the self-contained HTML report (U3).

The report (U1) is one file a compliance reviewer opens from an email attachment on a laptop with no network, so
a chart here is drawn, not plotted: no script, no stylesheet, no font, no image, no library, nothing the browser
fetches. Every chart is `<svg>` built from integers, which is why the tests can assert the geometry against the
numbers instead of looking at a picture.

Three rules decide what may be drawn.

**A chart may show only what a table on the same page shows.** The picture is a second reading of numbers the
reader can already check line by line, never a new claim and never a smoothed one. So each chart function takes
counts, not findings, and :mod:`kube_noob.report_html` renders the table beside it.

**Colour is never the only carrier.** Every bar is labelled with its name and its count, every stacked chart has
a legend and the per-control table underneath, and every mark carries a `<title>` the browser shows on hover --
the honest substitute for the tooltip layer an interactive chart would have, since this page runs no script. A
reader with no colour vision at all loses nothing but the grouping.

**An absence is never drawn as a zero.** A bar of length zero and a missing bar look identical, so a count that
was withheld is not passed to this module at all: the caller renders the reason instead. The trend is the sharp
case -- a point from a snapshot where resources could not be read is an undercount, and a line through it would
assert a comparison nobody made.

The palettes were checked with the dataviz validator (OKLCH lightness band, chroma floor, colour-vision
separation of adjacent pairs, contrast against the surface) in both light and dark:

* standing buckets, light ``#b02a30,#00908a,#6b5ca5,#2a7d57,#3f6ea8`` and dark
  ``#dc6a73,#0fa39c,#8b7cd0,#239f66,#3f88da`` -- every check passes in both modes;
* the trend's two series, the first and second of those -- every check passes in both modes;
* severity is an ordered state rather than a category, and its name is written next to every bar, so only
  contrast against the surface applies to it; that check passes in both modes.
"""

from __future__ import annotations

import html
from collections.abc import Mapping, Sequence

#: Bars past this are summarised rather than drawn: a chart of 300 bars is not a chart anybody reads, and the
#: table below it carries every row anyway.
MAX_BARS = 20

#: Points past this are dropped from the *left* (the oldest), because a trend is read from its right-hand end.
MAX_POINTS = 60

W = 680
_LABEL_W = 170
_VALUE_W = 48
_ROW_H = 20
_BAR_H = 12
#: A 2px gap of surface between neighbouring fills, so two segments never read as one.
_GAP = 2

CSS = """
figure.kn { margin: .6rem 0 1.3rem; }
figure.kn figcaption { color: var(--dim); font-size: .85rem; margin: 0 0 .35rem; }
svg.kn { display: block; width: 100%; height: auto; max-width: 44rem; }
svg.kn text { fill: var(--fg); font: 11px ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto,
              Helvetica, Arial, sans-serif; }
svg.kn text.lbl { fill: var(--dim); }
svg.kn text.val { font-variant-numeric: tabular-nums; }
svg.kn .axis { stroke: var(--line); stroke-width: 1; fill: none; }
svg.kn .plot { stroke: none; fill: var(--dim); }
svg.kn .ln { fill: none; stroke-width: 2; stroke-linejoin: round; stroke-linecap: round; }
ul.kn-legend { list-style: none; display: flex; flex-wrap: wrap; gap: .1rem 1rem; margin: 0 0 .5rem;
               padding: 0; font-size: .82rem; color: var(--dim); }
ul.kn-legend li { margin: 0; }
.kn-sw { display: inline-block; width: .65rem; height: .65rem; border-radius: 2px; margin-right: .3rem;
         vertical-align: baseline; }
:root { --kn-q0: #b02a30; --kn-q1: #00908a; --kn-q2: #6b5ca5; --kn-q3: #2a7d57; --kn-q4: #3f6ea8;
        --kn-critical: #7d1a18; --kn-high: #b02a30; --kn-medium: #b06a14; --kn-low: #5b6070;
        --kn-info: #767c8a; }
@media (prefers-color-scheme: dark) {
  :root { --kn-q0: #dc6a73; --kn-q1: #0fa39c; --kn-q2: #8b7cd0; --kn-q3: #239f66; --kn-q4: #3f88da;
          --kn-critical: #f58a86; --kn-high: #dc6a73; --kn-medium: #c99433; --kn-low: #9aa0ad;
          --kn-info: #8b90a0; }
}
.kn-q0 { fill: var(--kn-q0); background: var(--kn-q0); }
.kn-q1 { fill: var(--kn-q1); background: var(--kn-q1); }
.kn-q2 { fill: var(--kn-q2); background: var(--kn-q2); }
.kn-q3 { fill: var(--kn-q3); background: var(--kn-q3); }
.kn-q4 { fill: var(--kn-q4); background: var(--kn-q4); }
.kn-s0 { stroke: var(--kn-q0); }
.kn-s1 { stroke: var(--kn-q1); }
svg.kn circle.kn-s0 { fill: var(--kn-q0); stroke: none; }
svg.kn circle.kn-s1 { fill: var(--kn-q1); stroke: none; }
.kn-critical { fill: var(--kn-critical); background: var(--kn-critical); }
.kn-high { fill: var(--kn-high); background: var(--kn-high); }
.kn-medium { fill: var(--kn-medium); background: var(--kn-medium); }
.kn-low { fill: var(--kn-low); background: var(--kn-low); }
.kn-info { fill: var(--kn-info); background: var(--kn-info); }
@media print { svg.kn { max-width: 100%; } }
"""

#: The severity names that have a colour of their own. Anything else is drawn in the neutral fill, which is the
#: right answer for a name this module has never heard of rather than a guess at how bad it is.
SEVERITY_CLASS: Mapping[str, str] = {
    "critical": "kn-critical",
    "high": "kn-high",
    "medium": "kn-medium",
    "low": "kn-low",
    "info": "kn-info",
}


def _esc(value: object) -> str:
    """The only way text enters a chart. Same rule as the page: escape first, interpolate never."""
    return html.escape("" if value is None else str(value), quote=True)


def _clip(text: str, limit: int = 26) -> str:
    """A label short enough for the label column. The full text stays in the mark's ``<title>``."""
    s = str(text)
    return s if len(s) <= limit else s[: limit - 1].rstrip() + "…"


def _scale(value: int, span: int, top: int) -> int:
    """``value`` of ``top`` across ``span`` pixels, as an integer, so the geometry is reproducible and a test
    can assert that twice the count is twice the bar.

    With one floor: a value above zero is never drawn as nothing, because a zero-width bar and a missing bar
    are the same picture. Proportionality therefore holds above that floor and not at it -- a 1 beside a
    10 000 is one pixel either way -- which is the other reason every bar carries its number as text.
    """
    if value <= 0 or top <= 0:
        return 0
    return max(1, value * span // top)


def _open(height: int, *, label: str) -> str:
    return (
        f'<svg class="kn" viewBox="0 0 {W} {height}" role="img" aria-label="{_esc(label)}" '
        f'xmlns="http://www.w3.org/2000/svg">'
    )


def _figure(caption: str, body: list[str], *, legend: list[str] | None = None) -> list[str]:
    out = [f'<figure class="kn"><figcaption>{_esc(caption)}</figcaption>']
    if legend:
        out.append('<ul class="kn-legend">' + "".join(legend) + "</ul>")
    out += body
    out.append("</figure>")
    return out


def _legend(entries: Sequence[tuple[str, str]]) -> list[str]:
    return [f'<li><span class="kn-sw {_esc(cls)}"></span>{_esc(name)}</li>' for name, cls in entries]


def _overflow(shown: int, total: int, noun: str = "row") -> list[str]:
    """What the chart left out, said in the chart. A table of 30 rows beside a chart of 20 is the first rule
    broken quietly: the reader compares the two and finds a different shape with no reason given."""
    if total <= shown:
        return []
    return [f'<p class="note">{total - shown} more {noun}(s) are in the table below, not in the chart.</p>']


def bars(
    rows: Sequence[tuple[str, int]],
    *,
    caption: str,
    classes: Mapping[str, str] | None = None,
    default_class: str = "kn-q0",
) -> list[str]:
    """A horizontal bar per row, longest-first order left to the caller.

    ``rows`` are ``(name, count)``. ``classes`` maps a name to its fill class; a name with no entry is drawn in
    the neutral fill. Returns markup, or nothing at all when there is no row and when every count is zero -- an
    all-zero chart is a row of empty bars, which says less than the sentence the caller writes instead.
    """
    rows = [(str(n), int(c)) for n, c in rows if int(c) >= 0]
    if not rows or not any(c for _, c in rows):
        return []
    shown = rows[:MAX_BARS]
    top = max(c for _, c in shown)
    plot = W - _LABEL_W - _VALUE_W - 8
    height = 2 + _ROW_H * len(shown) + 2
    said = ", ".join(f"{n} {c}" for n, c in shown)
    out = [_open(height, label=f"{caption}: {said}")]
    out.append(f"<title>{_esc(caption)}</title>")
    for i, (name, count) in enumerate(shown):
        y = 2 + i * _ROW_H
        mid = y + _ROW_H // 2
        cls = (classes or {}).get(name, default_class)
        width = _scale(count, plot, top)
        out.append(
            f"<g><title>{_esc(name)}: {_esc(count)}</title>"
            f'<text class="lbl" x="{_LABEL_W - 6}" y="{mid + 4}" text-anchor="end">{_esc(_clip(name))}</text>'
            f'<rect class="{_esc(cls)}" x="{_LABEL_W}" y="{y + (_ROW_H - _BAR_H) // 2}" width="{width}" '
            f'height="{_BAR_H}" rx="2"/>'
            f'<text class="val" x="{_LABEL_W + width + 6}" y="{mid + 4}">{_esc(count)}</text></g>'
        )
    out.append("</svg>")
    return _figure(caption, out) + _overflow(len(shown), len(rows))


def stacked(
    rows: Sequence[tuple[str, Sequence[int]]],
    *,
    series: Sequence[str],
    caption: str,
) -> list[str]:
    """One bar per row, split into ``series`` segments and scaled against the largest row total.

    Rows keep the order given, so the bar and the table below it read the same way down the page. A row whose
    total is zero is drawn as nothing with its total written beside it, because an empty bar and a zero-length
    segment are the same picture and the number removes the question.
    """
    clean = [(str(n), [max(0, int(v)) for v in vals]) for n, vals in rows]
    clean = [(n, vals) for n, vals in clean if len(vals) == len(series)]
    if not clean or not series or len(series) > 5:
        return []
    shown = clean[:MAX_BARS]
    totals = [sum(vals) for _, vals in shown]
    top = max(totals)
    if top <= 0:
        return []
    plot = W - _LABEL_W - _VALUE_W - 8
    height = 2 + _ROW_H * len(shown) + 2
    said = "; ".join(f"{n} " + ", ".join(f"{series[i]} {v}" for i, v in enumerate(vals) if v) for n, vals in shown)
    out = [_open(height, label=f"{caption}: {said}"), f"<title>{_esc(caption)}</title>"]
    for i, (name, vals) in enumerate(shown):
        y = 2 + i * _ROW_H
        mid = y + _ROW_H // 2
        bar_y = y + (_ROW_H - _BAR_H) // 2
        x = _LABEL_W
        parts = [f'<text class="lbl" x="{_LABEL_W - 6}" y="{mid + 4}" text-anchor="end">{_esc(_clip(name))}</text>']
        drawn = [(j, v) for j, v in enumerate(vals) if v > 0]
        # Each segment ends where the RUNNING total ends, rather than at its own scaled width added to the one
        # before it. Scaling each width on its own and adding them up accumulates the one-pixel floor: five
        # segments of 1 against a row of 1 000 pushed the bar four pixels past the plot it is scaled to.
        running = 0
        for pos, (j, value) in enumerate(drawn):
            running += value
            end = min(_LABEL_W + plot, _LABEL_W + _scale(running, plot, top))
            width = max(1, end - x - (_GAP if pos < len(drawn) - 1 else 0))
            width = min(width, _LABEL_W + plot - x)
            parts.append(
                f'<rect class="kn-q{j}" x="{x}" y="{bar_y}" width="{width}" height="{_BAR_H}" rx="2">'
                f"<title>{_esc(name)} — {_esc(series[j])}: {_esc(value)}</title></rect>"
            )
            x = end
        # Beside the bar's end rather than in a column of its own: the total is a direct label on the mark,
        # which is what keeps the chart readable with no colour vision at all.
        parts.append(f'<text class="val" x="{x + 6}" y="{mid + 4}">{_esc(totals[i])}</text>')
        out.append(
            f"<g><title>{_esc(name)}: "
            + _esc(", ".join(f"{series[j]} {v}" for j, v in enumerate(vals)))
            + "</title>"
            + "".join(parts)
            + "</g>"
        )
    out.append("</svg>")
    legend = _legend([(name, f"kn-q{i}") for i, name in enumerate(series)])
    return _figure(caption, out, legend=legend) + _overflow(len(shown), len(clean))


def lines(
    ticks: Sequence[str],
    series: Sequence[tuple[str, Sequence[int]]],
    *,
    caption: str,
) -> list[str]:
    """Up to two series over the same x positions, as a line each with a dot per point.

    ``ticks`` label the x positions and must be the length of every series. The y axis starts at zero and is
    labelled at zero and at the maximum, because a trend drawn from a floor other than zero exaggerates the
    change -- which, on a page about findings, is the one thing a chart here must not do.
    """
    series = [(str(n), [max(0, int(v)) for v in vals]) for n, vals in series]
    n = len(ticks)
    if not n or not series or len(series) > 2 or any(len(vals) != n for _, vals in series):
        return []
    dropped = 0
    if n > MAX_POINTS:  # a trend is read from its right-hand end, so the oldest points go -- and are counted
        keep = slice(n - MAX_POINTS, n)
        dropped = n - MAX_POINTS
        ticks, series, n = list(ticks)[keep], [(s, list(v)[keep]) for s, v in series], MAX_POINTS
    top = max((max(vals) for _, vals in series), default=0)
    axis_top = max(1, top)
    left, right, pad_top, height = 46, 10, 14, 200
    floor = height - 28
    plot_w, plot_h = W - left - right, floor - pad_top

    def x_at(i: int) -> int:
        return left if n == 1 else left + i * plot_w // (n - 1)

    def y_at(v: int) -> int:
        return floor - _scale(v, plot_h, axis_top)

    said = "; ".join(f"{name} from {vals[0]} to {vals[-1]}" for name, vals in series)
    out = [
        _open(height, label=f"{caption}: {said}"),
        f"<title>{_esc(caption)}</title>",
        f'<path class="axis" d="M{left} {pad_top} V{floor} H{W - right}"/>',
        f'<text class="lbl" x="{left - 6}" y="{floor + 4}" text-anchor="end">0</text>',
        # Only when something was measured: an all-zero series under a top tick reading 1 labels the axis with
        # a number nothing in the data reaches.
        *([f'<text class="lbl" x="{left - 6}" y="{pad_top + 4}" text-anchor="end">{_esc(top)}</text>'] if top else []),
    ]
    label_at = {0, n - 1} | ({n // 2} if n >= 5 else set())
    for i in sorted(label_at):
        anchor = "start" if i == 0 else "end" if i == n - 1 else "middle"
        out.append(
            f'<text class="lbl" x="{x_at(i)}" y="{floor + 16}" text-anchor="{anchor}">'
            f"{_esc(_clip(ticks[i], 16))}</text>"
        )
    for s, (name, vals) in enumerate(series):
        points = " ".join(f"{x_at(i)},{y_at(v)}" for i, v in enumerate(vals))
        if n > 1:
            out.append(f'<polyline class="ln kn-s{s}" points="{points}"/>')
        for i, v in enumerate(vals):
            out.append(
                f'<circle class="kn-s{s}" cx="{x_at(i)}" cy="{y_at(v)}" r="{3 if n > 24 else 4}">'
                f"<title>{_esc(ticks[i])} — {_esc(name)}: {_esc(v)}</title></circle>"
            )
    out.append("</svg>")
    legend = _legend([(name, f"kn-q{i}") for i, (name, _) in enumerate(series)])
    return _figure(caption, out, legend=legend) + _overflow(n, n + dropped, "point")
