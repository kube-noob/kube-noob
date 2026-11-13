"""One self-contained HTML page for a gate report, a posture report or the KSI crosswalk (U1).

The audience is a compliance reviewer, and what a reviewer gets from the terminal is text they cannot forward and
JSON they will not read. So: one file, inline styling, no script, no stylesheet, no font, no image, nothing the
browser has to fetch -- openable from an email attachment on a laptop with no network, which is the situation
this tool is used in.

Two rules hold the whole module up.

**Every caveat the text view carries survives into the page, above the findings.** `assumptions`,
`notCheckedBeyond`, an unreadable file, a withheld control standing, `audited: false` -- each one changes what a
count means, and a reader who meets an empty findings table first has already drawn their conclusion. An HTML
report that drops them would be G221 in a third format.

**A chart shows only what a table on the same page shows** (U3). Every chart in :mod:`kube_noob.charts` is a
second reading of counts the reader can check row by row underneath it, and a count that was withheld is not
drawn at all -- an empty bar and a zero-length bar are the same picture, which is G221 again in ink.

**Nothing from a manifest is ever markup.** Resource names, messages, paths and reasons come from someone else's
cluster, and this is the one place in the product where that text becomes a document another person opens. Every
value goes through :func:`_esc`; there is no template interpolation anywhere that does not.
"""

from __future__ import annotations

import datetime as dt
import html
import re
from dataclasses import dataclass
from typing import Any

from kube_noob import charts

#: Rows past this are summarised rather than listed: a 4,000-row table is not a report anybody reads, and the
#: count says how many are missing rather than letting the table end silently.
MAX_ROWS = 300

_CSS = """
:root { color-scheme: light dark; --fg: #15181d; --bg: #fcfcfb; --dim: #5c6370; --line: #d9dce1;
        --warn-bg: #fff6e5; --warn-line: #e0a63a; --bad: #b02a30; --ok: #2a7d57;
        --link: #1d4e7a; --limit: #6b5ca5; --limit-bg: #f5f3f9; --rule-strong: #15181d; }
@media (prefers-color-scheme: dark) {
  :root { --fg: #e9eaec; --bg: #16181c; --dim: #9aa1ae; --line: #2b3038;
          --warn-bg: #2d2516; --warn-line: #b78a2e; --bad: #dc6a73; --ok: #239f66;
          --link: #74b0e4; --limit: #8b7cd0; --limit-bg: #1d1b24; --rule-strong: #c6cad2; }
}
* { box-sizing: border-box; }
body { margin: 0; padding: 2rem 1rem 4rem; color: var(--fg); background: var(--bg);
       font: 15px/1.55 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
main { max-width: 68rem; margin: 0 auto; }
h1 { font-size: 1.6rem; margin: 0 0 .25rem; letter-spacing: -.01em; }
h2 { font-size: 1.15rem; margin: 2.4rem 0 .6rem; padding-bottom: .35rem;
     border-bottom: 2px solid var(--rule-strong); display: flex; align-items: baseline; gap: .6rem; }
h2 .num { color: var(--dim); font-weight: 400; font-size: .85rem;
          font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
a { color: var(--link); }
/* The masthead: the verdict, the three numbers that decide the next action, and what the numbers are true of.
   A reviewer who reads nothing else has to be able to act on this block and quote one line of it. */
.verdict { font-size: 1.45rem; line-height: 1.25; font-weight: 600; letter-spacing: -.012em;
           margin: 1.4rem 0 .5rem; max-width: 34ch; }
.lede { color: var(--dim); margin: 0 0 1.4rem; max-width: 70ch; }
.tiles { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr));
         border-top: 1px solid var(--line); border-bottom: 1px solid var(--line); margin: 0 0 1rem; }
.tiles > div { padding: .85rem 1.2rem; border-right: 1px solid var(--line); }
.tiles > div:last-child { border-right: 0; }
.tiles > div:first-child { padding-left: 0; }
/* The absence tile carries the rule of the whole product, so it is the one with a marked edge. */
.tiles .absence { border-left: 3px solid var(--limit); }
.tiles .big { font-size: 2.1rem; line-height: 1; font-weight: 600; font-variant-numeric: tabular-nums;
              font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
.tiles .big.harm { color: var(--bad); }
.tiles .what { font-weight: 600; margin-top: .45rem; }
.tiles .of { color: var(--dim); font-size: .82rem; }
.prov { display: grid; grid-template-columns: auto 1fr; gap: 0 .9rem; margin: 0 0 1rem;
        font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
        font-size: .76rem; line-height: 1.7; color: var(--dim); }
.prov dt { opacity: .8; }
.prov dd { margin: 0; }
nav.toc { border-top: 1px solid var(--line); padding: .7rem 0 0; margin: 0 0 .6rem;
          display: flex; flex-wrap: wrap; gap: .3rem 1.6rem; font-size: .9rem; }
nav.toc a { text-decoration: none; }
nav.toc a span.n { color: var(--dim); margin-right: .45rem;
                   font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: .8rem; }
nav.toc a span.t { border-bottom: 1px solid var(--line); }
/* A limit is not a warning about the page: it is a finding about the audit, and an auditor has to read it. */
ol.limits { list-style: none; margin: .6rem 0 1rem; padding: 0; }
ol.limits > li { border-top: 1px solid var(--line); border-left: 3px solid var(--limit);
                 padding: .7rem 0 .7rem .9rem; display: grid; grid-template-columns: 1fr 22rem; gap: 1.6rem; }
ol.limits > li:last-child { border-bottom: 1px solid var(--line); }
ol.limits .kind { font-weight: 600; }
ol.limits .so { color: var(--dim); font-size: .88rem; border-left: 1px solid var(--line); padding-left: 1.1rem; }
details.quiet { border: 1px solid var(--line); border-radius: 2px; margin: 1rem 0; }
details.quiet > summary { padding: .55rem .8rem; cursor: pointer; font-weight: 600; font-size: .92rem; }
details.quiet > div { padding: .1rem .8rem .7rem; }
h3 { font-size: .95rem; margin: 1.4rem 0 .3rem; }
p, li { margin: .4rem 0; }
.sub { color: var(--dim); margin: 0 0 1.2rem; font-size: .9rem; }
.caveat { background: var(--warn-bg); border: 1px solid var(--warn-line); border-left-width: 4px;
          border-radius: 3px; padding: .7rem .9rem; margin: .6rem 0; }
.caveat b { display: block; margin-bottom: .2rem; }
table { border-collapse: collapse; width: 100%; margin: .5rem 0 1rem; font-size: .88rem; }
th, td { text-align: left; padding: .35rem .5rem; border-bottom: 1px solid var(--line); vertical-align: top; }
th { color: var(--dim); font-weight: 600; white-space: nowrap; }
td.n, th.n { text-align: right; font-variant-numeric: tabular-nums; white-space: nowrap; }
code, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: .85em; }
td a.mono, th a.mono { white-space: nowrap; }
.sev { font-weight: 600; white-space: nowrap; }
.sev-critical, .sev-high { color: var(--bad); }
.fails { color: var(--bad); font-weight: 600; }
.pass { color: var(--ok); font-weight: 600; }
.note { color: var(--dim); font-size: .85rem; }
.ev { margin: .2rem 0 .8rem; padding-left: .8rem; border-left: 2px solid var(--line); }
.ev dt { color: var(--dim); font-size: .8rem; text-transform: uppercase; letter-spacing: .04em; margin-top: .4rem; }
.ev dd { margin: .1rem 0 0; }
@media print {
  /* The second destination of this page is a PDF in an audit package, so the sheet is designed, not inherited:
     a running identity on every page, headers that repeat, no row split across a break, and -- the one that
     matters for evidence -- everything folded away on screen opened up, so the printout is not a subset. */
  @page { margin: 18mm 16mm 16mm; }
  body { padding: 0; font-size: 10.5pt; }
  main { max-width: none; }
  a { color: inherit; text-decoration: none; }
  h1, h2, h3 { break-after: avoid-page; }
  table { break-inside: auto; font-size: 9.5pt; }
  thead { display: table-header-group; }
  tr, .caveat, ol.limits > li, figure.kn { break-inside: avoid; }
  nav.toc { display: none; }
  .caveat { border-left-width: 3px; }
  details.quiet > summary { list-style: none; }
  details.quiet > div { display: block !important; }
  .printonly { display: block; }
}
.printonly { display: none; }
"""


def _esc(value: Any) -> str:
    """The only way text enters the page. ``quote=True`` so a value is safe in an attribute as well."""
    return html.escape("" if value is None else str(value), quote=True)


def _rich(value: Any) -> str:
    """Escaped text, then the `backticks` the prose is written with turned into code spans.

    Order matters and is the whole safety argument: the value is escaped FIRST, so the only markup that can
    exist by the time this looks for backticks is markup this function wrote. A hostile name containing
    backticks becomes a code span holding escaped text, which is harmless.
    """
    out = _esc(value)
    parts = out.split("`")
    if len(parts) < 3:
        return out
    rebuilt = [parts[0]]
    for i, part in enumerate(parts[1:], start=1):
        rebuilt.append(f"<code>{part}</code>" if i % 2 else part)
    # An unpaired trailing backtick leaves the last fragment unwrapped; splitting on an odd count would have
    # opened a tag with nothing to close it.
    if len(parts) % 2 == 0:
        rebuilt[-1] = parts[-1]
    return "".join(rebuilt)


def _row(cells: list[str], *, numeric: set[int] | None = None, head: bool = False, width: int = 0) -> str:
    """A row. A short row's last cell spans the rest, so a note does not sit under a numeric heading."""
    tag = "th" if head else "td"
    num = numeric or set()
    out = []
    for i, cell in enumerate(cells):
        cls = ' class="n"' if i in num else ""
        span = ""
        if width and i == len(cells) - 1 and len(cells) < width:
            span = f' colspan="{width - len(cells) + 1}"'
            cls = ""
        out.append(f"<{tag}{cls}{span}>{cell}</{tag}>")
    return "<tr>" + "".join(out) + "</tr>"


def _table(headers: list[str], rows: list[list[str]], numeric: set[int] | None = None) -> list[str]:
    if not rows:
        return []
    shown, hidden = rows[:MAX_ROWS], max(0, len(rows) - MAX_ROWS)
    out = ["<table>", "<thead>", _row([_esc(h) for h in headers], numeric=numeric, head=True), "</thead>", "<tbody>"]
    out += [_row(r, numeric=numeric, width=len(headers)) for r in shown]
    out += ["</tbody>", "</table>"]
    if hidden:
        out.append(f'<p class="note">{hidden} more row(s) not listed here; the JSON output carries all of them.</p>')
    return out


#: Worst first, which is the order the findings table is already sorted in. A severity this does not name is
#: listed after these, alphabetically, rather than guessed at a position.
_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")

#: Written where a value is missing, so an empty cell is never read as a zero.
_EM_DASH = "\u2014"


@dataclass(frozen=True)
class Tile:
    """One of the three numbers in the masthead. ``harm`` colours it, ``absence`` marks its edge."""

    value: str
    unit: str
    what: str
    of: str
    harm: bool = False
    absence: bool = False


@dataclass(frozen=True)
class Masthead:
    """The three numbers and the sentence that goes over them, from the same place.

    The sentence belongs to the shape, not to a generic template: a posture report counts findings and rules,
    a KSI crosswalk counts indicators, and a gate counts checks that never ran. One wording over all three
    printed "21 findings are open, and 15 rules reached no verdict" above tiles reading "indicators", and
    pointed at a section 1 that did not list them -- which is the defect G257 is about, in the page that
    introduced G257.
    """

    tiles: list[Tile]
    head: str
    lede: str


def _plural(n: int, one: str, many: str | None = None) -> str:
    return one if n == 1 else (many or one + "s")


def _standing_totals(report: dict[str, Any]) -> dict[str, int] | None:
    standing = report.get("controlStanding")
    rows = (standing or {}).get("controls") if isinstance(standing, dict) else None
    if not isinstance(rows, list) or not rows:
        return None
    keys = ("findings", "excepted", "withheld", "clean", "notEvaluated")
    return {k: sum(int(r.get(k) or 0) for r in rows if isinstance(r, dict)) for k in keys}


def _masthead_of(report: dict[str, Any]) -> Masthead | None:
    """The three numbers and the sentence over them, decided together by which report this is.

    The middle tile is always the absence: how much of this run reached no verdict. Every other scanner
    reports what failed, and a reader who only ever sees that number cannot tell a clean cluster from an
    unexamined one -- so it is a tile beside the findings rather than a column in a table thirty rows long.

    The sentence is built in the same branch as the tiles, because a wording shared across all three shapes
    printed "21 findings are open, and 15 rules reached no verdict" over tiles reading "indicators" and sent
    the reader to a section 1 that did not list them. That is G257's own rule broken in the page that
    introduced G257; each shape now counts the thing its own tiles count, and names only a section it has.
    """
    totals = _standing_totals(report)
    if totals is not None:
        unseen = totals["withheld"] + totals["notEvaluated"]
        # The headline is the FINDING count, not the per-control sum. One finding is evidence about several
        # controls -- KN-S012 is both AC-6 and CM-7 -- so adding the standing column printed 5 where the report
        # said 3, in the largest type on the page, two sections above the table that contradicted it. The
        # standing numbers are rule results counted once per control, and the tiles now say that rather than
        # calling them rules.
        buckets = report.get("findings")
        found = int(buckets.get("open") or 0) if isinstance(buckets, dict) else totals["findings"]
        excepted = int(buckets.get("excepted") or 0) if isinstance(buckets, dict) else totals["excepted"]
        tiles = [
            Tile(
                str(found),
                _plural(found, "finding"),
                "Open findings",
                f"{excepted} excepted" if excepted else "none excepted",
                harm=found > 0,
            ),
            Tile(
                str(unseen),
                "rule results",
                "Withheld or not evaluated",
                "no evidence either way, counted once per control",
                absence=True,
            ),
            Tile(
                str(totals["clean"]),
                "rule results",
                "Evaluated and clean",
                "ran and found nothing, counted once per control",
            ),
        ]
        is_are = "is" if found == 1 else "are"
        if not unseen:
            return Masthead(
                tiles,
                f"{found} {_plural(found, 'finding')} {is_are} open.",
                "Every rule that applies was evaluated, and nothing was withheld.",
            )
        return Masthead(
            tiles,
            f"{found} {_plural(found, 'finding')} {is_are} open, and {unseen} rule "
            f"{_plural(unseen, 'result')} reached no verdict.",
            "A rule result that reached no verdict is not a pass. Section 1 says what each one would have "
            "covered, and every count on this page is bounded by them.",
        )
    counts = report.get("counts")
    if isinstance(counts, dict) and isinstance(report.get("findings"), list):
        total = sum(int(v) for v in counts.values() if isinstance(v, int))
        worst = next((n for n in _SEVERITY_ORDER if int(counts.get(n) or 0) > 0), None)
        not_run = len(report.get("notRun") or []) + len(report.get("skipped") or [])
        tiles = [
            Tile(
                str(total),
                _plural(total, "finding"),
                "Findings",
                f"worst is {worst}" if worst else "none",
                harm=total > 0,
            ),
            Tile(str(not_run), _plural(not_run, "check"), "Not run", "no input was given for them", absence=True),
            Tile(str(int(report.get("excepted") or 0)), "excepted", "Excepted", "accepted, and still listed"),
        ]
        lede = (
            f"{total} {_plural(total, 'finding')} at <code>--fail-on {_esc(report.get('failOn'))}</code> for "
            f"platform <code>{_esc(report.get('platform'))}</code>."
        )
        if not_run:
            lede += (
                f" {not_run} {_plural(not_run, 'check')} never ran because no input was given for "
                f"{'it' if not_run == 1 else 'them'}: that is not a pass, and section 1 says what "
                f"{'it' if not_run == 1 else 'they'} would have covered."
            )
        return Masthead(tiles, "The gate passed." if report.get("passed") else "The gate failed.", lede)
    rows = report.get("indicators")
    if isinstance(rows, list) and rows:
        # A KSI row's `findings` is a COUNT, not a bucket dict -- reading it as one crashed `ksi --html`
        # outright. Guarded by type rather than by `or {}`, because the next shape to arrive here should
        # produce a tile that says nothing rather than an exception or a confident zero.
        def _open(row: dict[str, Any]) -> int:
            got = row.get("findings")
            if isinstance(got, dict):
                got = got.get("open")
            return got if isinstance(got, int) and not isinstance(got, bool) else 0

        bare = sum(1 for r in rows if isinstance(r, dict) and not r.get("evidenced"))
        hit = sum(1 for r in rows if isinstance(r, dict) and _open(r) > 0)
        clean = len(rows) - bare - hit
        tiles = [
            Tile(str(hit), _plural(hit, "indicator"), "With open findings", "evidence against them", harm=hit > 0),
            Tile(
                str(bare), _plural(bare, "indicator"), "No rule behind them", "not a zero, and not a pass", absence=True
            ),
            Tile(str(clean), _plural(clean, "indicator"), "Evidenced and clean", "rules ran, nothing open"),
        ]
        has_have = "has" if hit == 1 else "have"
        head = f"{hit} {_plural(hit, 'indicator')} {has_have} findings against {'it' if hit == 1 else 'them'}"
        if bare:
            # "and 15 indicators no kube-noob rule behind them" elides the verb and reads as a typo in the
            # largest type on the page. The unit is already stated by the clause it hangs off.
            head += f", and {bare} {'has' if bare == 1 else 'have'} no kube-noob rule behind "
            head += "it at all." if bare == 1 else "them at all."
        else:
            head += ", and every indicator has at least one rule behind it."
        lede = (
            "An indicator with no rule behind it is not a zero and not a pass: kube-noob has nothing to say "
            "about it, and the evidence has to come from somewhere else. The crosswalk below lists every "
            "indicator and the rules, if any, that bear on it."
        )
        return Masthead(tiles, head, lede)
    return None


def _provenance(report: dict[str, Any], when: str, version: str) -> list[str]:
    """What the numbers are true of. An evidence document that does not state its own scope cannot be cited."""
    rows: list[tuple[str, str]] = []
    scope = [str(report[k]) for k in ("source", "platform") if report.get(k)]
    if report.get("kubernetesVersion"):
        scope.append(f"kubernetes {report['kubernetesVersion']}")
    files = report.get("files")
    if isinstance(files, list) and files:
        scope.append(f"{len(files)} {_plural(len(files), 'file')}")
    if scope:
        rows.append(("scope", " · ".join(scope)))
    if report.get("to"):
        rows.append(("taken", str(report["to"])))
    rows.append(("by", f"kube-noob {version}" if version else "kube-noob"))
    dataset = (report.get("dataset") or {}).get("version") if isinstance(report.get("dataset"), dict) else None
    if dataset:
        rows.append(("dataset", str(dataset)))
    rows.append(("network", "none used to produce this page, none loaded by it"))
    body = "".join(f"<dt>{_esc(k)}</dt><dd>{_esc(v)}</dd>" for k, v in rows)
    return [f'<dl class="prov">{body}</dl>']


def _masthead(report: dict[str, Any], when: str, version: str) -> list[str]:
    mast = _masthead_of(report)
    if mast is None:
        return _provenance(report, when, version)
    out = [
        f'<p class="verdict">{_esc(mast.head)}</p>',
        f'<p class="lede">{mast.lede}</p>',
        '<div class="tiles">',
    ]
    for t in mast.tiles:
        cls = ' class="absence"' if t.absence else ""
        big = ' class="big harm"' if t.harm else ' class="big"'
        out.append(
            f"<div{cls}><span{big}>{_esc(t.value)}</span> "
            f'<span class="of">{_esc(t.unit)}</span>'
            f'<div class="what">{_esc(t.what)}</div><div class="of">{_esc(t.of)}</div></div>'
        )
    out.append("</div>")
    return out + _provenance(report, when, version)


class Sections:
    """Numbers the sections as they are written, and remembers them for the contents.

    The numbers are the point, not decoration: a reviewer cites "section 1" at a colleague, and an auditor's
    own working paper references them. They are assigned in document order rather than fixed, because which
    sections a page has depends on which report it is.
    """

    def __init__(self) -> None:
        self.entries: list[tuple[str, str, str]] = []

    def head(self, title: str, anchor: str, *, note: str = "") -> str:
        self.entries.append((str(len(self.entries) + 1), title, anchor))
        n = len(self.entries)
        tail = f'<span class="note" style="margin-left:auto">{_esc(note)}</span>' if note else ""
        return f'<h2 id="{_esc(anchor)}"><span class="num">{n}</span>{_esc(title)}{tail}</h2>'

    def toc(self) -> list[str]:
        if len(self.entries) < 2:
            return []
        links = "".join(
            f'<a href="#{_esc(a)}"><span class="n">{_esc(n)}</span><span class="t">{_esc(t)}</span></a>'
            for n, t, a in self.entries
        )
        return [f'<nav class="toc" aria-label="Contents">{links}</nav>']


def _limits(report: dict[str, Any], sec: Sections) -> list[str]:
    """Section 1: everything this run could not establish, ahead of anything it found.

    These were a strip of yellow boxes, which is how a reader learns to skim them. They are not warnings about
    the page -- they are findings about the audit, an auditor is required to read them, and a control nobody
    evaluated is indistinguishable from a clean one in any table that does not say so. So: a numbered section,
    in the document's own voice, each limit beside the one thing that would turn it into a result.
    """
    items: list[tuple[str, str, str]] = []
    if report.get("audited") is False:
        items.append(
            (
                "Nothing audited",
                "This is the crosswalk itself, not a result: no manifests were read, so no row below carries a "
                "finding count.",
                "Audit something and run again; a zero here would read as a pass.",
            )
        )
    for note in report.get("assumptions") or []:
        items.append(("Assumed", str(note), "Give kube-noob what it assumed, and the assumption becomes a result."))
    limit = report.get("notCheckedBeyond")
    if isinstance(limit, dict) and limit.get("why"):
        items.append(("Not checked that far", str(limit["why"]), "Nothing beyond that point is covered either way."))
    for u in report.get("unreadable") or []:
        if isinstance(u, dict):
            items.append(
                (
                    "File not read",
                    f'<span class="mono">{_esc(u.get("path"))}</span>: {_esc(u.get("why"))}',
                    "Every count below is a floor: this is not a complete audit.",
                )
            )
    unread = [str(n) for n in report.get("notRead") or []]
    if unread:
        shown = "; ".join(unread[:MAX_ROWS])
        items.append(
            (
                f"{len(unread)} {_plural(len(unread), 'resource')} refused",
                _esc(shown),
                "Every count below is a floor, not a measurement: kube-noob was not allowed to look.",
            )
        )
    # A check nobody ran is the plainest limit there is, and the masthead counts them in the absence tile --
    # so leaving them out of this section made that tile point at a section that did not mention them.
    for entry in report.get("notRun") or []:
        text = str(entry)
        head, _, why = text.partition(":")
        items.append(("Not run", _esc(head.strip()), _esc(why.strip()) or "No input was given for it."))
    for entry in report.get("skipped") or []:
        if isinstance(entry, dict):
            items.append(("Skipped", _esc(entry.get("what") or entry), _esc(entry.get("why") or "")))
        else:
            items.append(("Skipped", _esc(entry), ""))
    for note in report.get("notes") or []:
        items.append(("Note", str(note), ""))
    if not items:
        return []
    out = [
        sec.head(
            "Limits of this examination",
            "limits",
            note=f"{len(items)} {_plural(len(items), 'limit')} · read before relying on the counts",
        ),
        "<p>Each item is something this run could not establish. None of them is a pass and none is a failure, "
        "and they are stated ahead of the findings because a rule that was never evaluated is indistinguishable "
        "from a clean one in any table that does not say so.</p>",
        '<ol class="limits">',
    ]
    for kind, what, so in items:
        tail = f'<div class="so">{so}</div>' if so else "<div></div>"
        out.append(f'<li><div><span class="kind">{_esc(kind)}.</span> {_rich(what)}</div>{tail}</li>')
    out.append("</ol>")
    return out


_UNSAFE_IN_ID = re.compile(r"[^A-Za-z0-9._-]+")


def _slug(finding: dict[str, Any]) -> str:
    """An anchor for one finding: stable across runs of the same input, and never anything but an id.

    Built from the rule and the resource rather than from a position in the list, because a page where
    `#f-3` means a different finding tomorrow is worse than no anchor at all.
    """
    parts = [str(finding.get("ruleId") or "rule"), str(finding.get("resource") or ""), str(finding.get("uri") or "")]
    return "f-" + _UNSAFE_IN_ID.sub("-", "-".join(p for p in parts if p)).strip("-")[:96]


def _severity_sections(report: dict[str, Any]) -> list[str]:
    """The gate's own `counts`, as a table and a bar per severity. Nothing when every count is zero: a row of
    empty bars says less than the sentence about there being no finding."""
    counts = report.get("counts")
    if not isinstance(counts, dict):
        return []
    rows: list[tuple[str, int]] = []
    for name in _SEVERITY_ORDER:
        if isinstance(counts.get(name), int):
            rows.append((name, int(counts[name])))
    rows += sorted((str(k), int(v)) for k, v in counts.items() if isinstance(v, int) and k not in _SEVERITY_ORDER)
    if not any(c for _, c in rows):
        return []
    drawn = charts.bars(rows, caption="Findings by severity", classes=charts.SEVERITY_CLASS)
    table = _table(["Severity", "Findings"], [[_esc(n), _esc(c)] for n, c in rows], numeric={1})
    return drawn + table


def _trend_sections(report: dict[str, Any], sec: Sections) -> list[str]:
    """Open and excepted findings across the snapshots still kept (U3).

    The table is always rendered; the line only when every point is a complete measurement of the same
    population. Each reason it is withheld is one of the ways a number can be absent rather than zero -- a
    snapshot that was refused a resource reports a floor, a report written before kube-noob recorded
    completeness cannot say, a report that does not say when it was taken cannot be placed, a file that could
    not be read is a point missing from the middle, and two sources in one folder are two populations. Joining
    any of them to its neighbours would publish a change in findings that may only be a change in what
    kube-noob was allowed to see.
    """
    hist = report.get("history")
    if not isinstance(hist, dict):
        return []
    points = [p for p in hist.get("points") or [] if isinstance(p, dict)]
    unplaced = [str(x) for x in hist.get("unplaced") or []]
    if len(points) < 2 and not unplaced:
        return []
    kept = len(points) + len(unplaced)
    out = [sec.head("Open findings over time", "trend", note=f"{kept} snapshots kept")]
    counted = [p for p in points if isinstance(p.get("open"), int) and isinstance(p.get("excepted"), int)]
    partial = [p for p in points if p.get("complete") is False]
    unknown = [p for p in points if p.get("complete") is None]
    undated = [p for p in points if not p.get("at")]
    sources = sorted({str(p["source"]) for p in points if p.get("source")})
    why: list[str] = []
    if partial:
        why.append(
            f"{len(partial)} of the {kept} kept came from a snapshot that could not read every resource, so "
            "their open-finding counts are a floor rather than a measurement"
        )
    if unknown:
        why.append(
            f"{len(unknown)} were written before kube-noob recorded whether a snapshot had read everything, "
            "so whether their counts are complete is not known"
        )
    if undated:
        why.append(f"{len(undated)} do not say when they were taken")
    if len(counted) != len(points):
        why.append(f"{len(points) - len(counted)} do not carry both counts")
    if unplaced:
        why.append(f"{len(unplaced)} could not be read back or were not read ({', '.join(unplaced)})")
    if len(sources) > 1:
        why.append(
            "the series mixes snapshots of different things (" + ", ".join(sources) + "), which are different "
            "populations rather than one population over time"
        )
    if why or len(points) < 2:
        out.append(
            '<div class="caveat"><b>No trend is drawn.</b>'
            + _esc("; ".join(why) or "there is one point, which is not a trend")
            + ". A line through those points would publish a change in findings that may only be a change in "
            "what kube-noob was allowed to see. The counts themselves are below, each marked with whether its "
            "snapshot read every resource.</div>"
        )
    else:
        shown = points[-charts.MAX_POINTS :]
        out += charts.lines(
            [str(p["at"])[:10] for p in shown],
            [
                ("Open", [int(p["open"]) for p in shown]),
                ("Excepted", [int(p["excepted"]) for p in shown]),
            ],
            caption="Open and excepted findings per snapshot",
        )
        out.append(
            '<p class="note">The points are evenly spaced by snapshot, not by date: the dates say which '
            "snapshot each point is, and a gap between two runs is not drawn as a gap.</p>"
        )
        if len(points) > len(shown):
            out.append(
                f'<p class="note">{len(points) - len(shown)} older point(s) are in the table below, not in '
                "the chart.</p>"
            )
    out += _table(
        ["Taken", "Open", "Excepted", "Source", "Read everything"],
        [
            [
                f'<span class="mono">{_esc(p.get("at") or _EM_DASH)}</span>',
                _esc(p["open"]) if isinstance(p.get("open"), int) else _EM_DASH,
                _esc(p["excepted"]) if isinstance(p.get("excepted"), int) else _EM_DASH,
                _esc(p.get("source") or _EM_DASH),
                "yes"
                if p.get("complete") is True
                else f'<span class="fails">{"no" if p.get("complete") is False else "not recorded"}</span>',
            ]
            for p in points
        ],
        numeric={1, 2},
    )
    out.append(
        '<p class="note">"Read everything" is whether the snapshot was refused a resource it asked the cluster '
        "for. It does not cover a kind kube-noob has no reader for: the audit records that as an assumption on "
        "the run itself.</p>"
    )
    if unplaced:
        out.append(
            '<p class="note">Kept files behind a point that could not be made: '
            f'<span class="mono">{_esc(", ".join(unplaced))}</span>.</p>'
        )
    return out


def _caveats(report: dict[str, Any]) -> list[str]:
    """Everything that changes what a count below means. Rendered first, always."""
    out: list[str] = []
    if report.get("audited") is False:
        out.append(
            '<div class="caveat"><b>Nothing was audited.</b>This is the crosswalk itself, not a result: no '
            "manifests were read, so no row below carries a finding count. A zero would read as a pass.</div>"
        )
    for note in report.get("assumptions") or []:
        out.append(f'<div class="caveat"><b>Assumed</b>{_rich(note)}</div>')
    limit = report.get("notCheckedBeyond")
    if limit:
        out.append(f'<div class="caveat"><b>Not checked that far</b>{_rich(limit.get("why"))}</div>')
    unreadable = report.get("unreadable") or []
    if unreadable:
        items = "".join(
            f'<li><span class="mono">{_esc(u.get("path"))}</span>: {_esc(u.get("why"))}</li>' for u in unreadable
        )
        out.append(
            '<div class="caveat"><b>Files that could not be read</b>'
            f"<ul>{items}</ul>This is not a complete audit, so nothing below is a clean result.</div>"
        )
    not_read = report.get("notRead") or []
    if not_read:
        items = "".join(f"<li>{_esc(n)}</li>" for n in not_read)
        out.append(
            '<div class="caveat"><b>Resources that could not be read</b>'
            f"<ul>{items}</ul>This is not a complete read of the cluster, so nothing below is a clean result.</div>"
        )
    for note in report.get("notes") or []:
        out.append(f'<div class="caveat"><b>Note</b>{_rich(note)}</div>')
    return out


def _gate_sections(report: dict[str, Any], sec: Sections) -> list[str]:
    out: list[str] = []
    if report.get("failures"):
        out.append(sec.head("Why the gate failed", "why"))
        out.append("<ul>" + "".join(f"<li>{_esc(f)}</li>" for f in report["failures"]) + "</ul>")
    findings = report.get("findings")
    if isinstance(findings, list):
        out.append(sec.head("Findings", "findings", note=f"{len(findings)} found \u00b7 worst first"))
        if not findings:
            out.append(
                '<p class="note">No finding at or above the configured severity. Read the caveats above before '
                "reading that as a clean result.</p>"
            )
        out += _severity_sections(report)
        out += _table(
            ["Rule", "Severity", "Fails gate", "Resource", "Where", "What"],
            [
                [
                    # Addressable, so a reviewer can send a colleague to ONE line rather than to the page and a
                    # description of where to look. The id is the rule and the resource, which is what a reader
                    # has in hand when they want to point at a row.
                    f'<a id="{_esc(_slug(f))}" href="#{_esc(_slug(f))}" class="mono">{_esc(f.get("ruleId"))}</a>',
                    f'<span class="sev sev-{_esc(str(f.get("severity", "")).lower())}">'
                    f"{_esc(f.get('severity'))}</span>",
                    '<span class="fails">yes</span>' if f.get("failsGate") else "no",
                    _esc(f.get("resource")),
                    f'<span class="mono">{_esc(f.get("uri"))}{":" + str(f["line"]) if f.get("line") else ""}</span>',
                    _esc(f.get("message")),
                ]
                for f in findings
            ],
        )
    if report.get("excepted"):
        out.append(sec.head("Excepted", "excepted", note=f"{len(report['excepted'])} accepted, and still listed"))
        out += _table(
            ["Rule", "Resource", "Exception", "Owner", "Expires"],
            [
                [
                    f'<span class="mono">{_esc(f.get("ruleId"))}</span>',
                    _esc(f.get("resource")),
                    _esc((f.get("exception") or {}).get("id")),
                    _esc((f.get("exception") or {}).get("owner")),
                    _esc((f.get("exception") or {}).get("expires")),
                ]
                for f in report["excepted"]
            ],
        )
    return out


def _posture_findings(report: dict[str, Any], sec: Sections) -> list[str]:
    """A posture report's `findings` is a dict of buckets (new, fixed, still open), not a list."""
    buckets = report.get("findings")
    if not isinstance(buckets, dict):
        return []
    out = [sec.head("What changed", "changed")]
    out += _table(
        ["Bucket", "Findings"],
        [[_esc(name), _esc(len(rows) if isinstance(rows, list) else rows)] for name, rows in buckets.items()],
        numeric={1},
    )
    for name, rows in buckets.items():
        if not isinstance(rows, list) or not rows:
            continue
        out.append(f"<h3>{_esc(name)} ({len(rows)})</h3>")
        out += _table(
            ["Rule", "Severity", "Resource", "Namespace", "Owner"],
            [
                [
                    f'<span class="mono">{_esc(f.get("ruleId"))}</span>',
                    _esc(f.get("severity")),
                    _esc(f.get("resource")),
                    _esc(f.get("namespace")),
                    _esc(f.get("owner")),
                ]
                for f in rows
                if isinstance(f, dict)
            ],
        )
    return out


def _standing_sections(report: dict[str, Any], sec: Sections) -> list[str]:
    out: list[str] = []
    by_control = (report.get("violations") or {}).get("byControl")
    if by_control:
        out.append(sec.head("Open findings by control", "bycontrol"))
        out += charts.bars(
            [(str(c.get("control")), int(c.get("findings") or 0)) for c in by_control if isinstance(c, dict)],
            caption="Most open findings first",
        )
        out += _table(
            ["Control", "Title", "Findings", "Namespaces"],
            [
                [
                    f'<span class="mono">{_esc(c.get("control"))}</span>',
                    _esc(c.get("title")),
                    _esc(c.get("findings")),
                    _esc(", ".join(c.get("namespaces") or []))
                    + (f' <span class="note">+{c["moreNamespaces"]} more</span>' if c.get("moreNamespaces") else ""),
                ]
                for c in by_control
            ],
            numeric={2},
        )
    standing = report.get("controlStanding")
    if standing is None:
        out.append(sec.head("Control standing", "standing"))
        out.append(
            '<div class="caveat"><b>No standing is reported.</b>Some resources could not be read, and a rule '
            "that never ran cannot be counted clean, so standing is withheld entirely rather than published "
            "with a bucket that cannot be trusted.</div>"
        )
        return out
    controls = [c for c in (standing.get("controls") or []) if isinstance(c, dict)]
    buckets = ("findings", "excepted", "withheld", "clean", "notEvaluated")
    # Ranked by consequence, not alphabetically: a control with a finding, an exception, a withheld result or a
    # rule nobody ran is something to act on; one where every rule ran and came back clean is a row to count,
    # not to read. Thirty rows of which eight say anything is the shape that hid `notEvaluated` in the first
    # place, so the silent ones fold away -- and the print stylesheet opens them again, because a PDF in an
    # audit package must not be a subset of the page a colleague opened.
    loud = [c for c in controls if any(int(c.get(b) or 0) for b in buckets if b != "clean")]
    quiet = [c for c in controls if c not in loud]
    counted = sum(int(c.get(b) or 0) for c in controls for b in buckets)
    out.append(
        sec.head(
            "Control standing",
            "standing",
            note=f"{len(controls)} controls \u00b7 {counted} rule results",
        )
    )
    out += charts.stacked(
        [(str(c.get("id")), [int(c.get(b) or 0) for b in buckets]) for c in loud or controls],
        series=["Findings", "Excepted", "Withheld", "Clean", "Not evaluated"],
        caption="Per-control standing, rules counted",
    )

    def rows(group: list[dict[str, Any]]) -> list[list[str]]:
        return [
            [
                f'<a id="c-{_esc(c.get("id"))}" href="#c-{_esc(c.get("id"))}" class="mono">{_esc(c.get("id"))}</a>',
                _esc(c.get("title")),
                _esc(c.get("findings", 0)),
                _esc(c.get("excepted", 0)),
                _esc(c.get("withheld", 0)),
                _esc(c.get("clean", 0)),
                _esc(c.get("notEvaluated", 0)),
            ]
            for c in group
        ]

    headers = ["Control", "Title", "Findings", "Excepted", "Withheld", "Clean", "Not evaluated"]
    if loud:
        out.append(f"<h3>Controls with something to report \u2014 {len(loud)} of {len(controls)}</h3>")
        out += _table(headers, rows(loud), numeric={2, 3, 4, 5, 6})
    if quiet:
        out.append(
            '<details class="quiet"><summary>'
            f"{len(quiet)} {_plural(len(quiet), 'control')} with nothing to report \u2014 every rule evaluated, "
            "every rule clean</summary><div>"
        )
        out += _table(headers, rows(quiet), numeric={2, 3, 4, 5, 6})
        out.append("</div></details>")
        out.append(
            '<p class="note">A control is listed above only when it has a finding, an exception, a withheld '
            "result or a rule that was not evaluated. The folded list is not hidden evidence: it opens itself "
            "when this page is printed, so the PDF carries every control.</p>"
        )
    return out


def _ksi_sections(report: dict[str, Any], sec: Sections) -> list[str]:
    indicators = report.get("indicators")
    if indicators is None:
        return []
    out: list[str] = []
    data = report.get("dataset") or {}
    if data:
        out.append(
            f'<p class="note">{_esc(data.get("name"))} version <code>{_esc(data.get("version"))}</code> '
            f"(updated {_esc(data.get('lastUpdated'))}), retrieved {_esc(data.get('retrieved'))}, sha256 "
            f'<span class="mono">{_esc(data.get("sha256"))}</span>.</p>'
        )
    for key in ("note", "applicability", "sharedControlCaveat"):
        if report.get(key):
            out.append(f'<div class="caveat"><b>Read this first</b>{_rich(report[key])}</div>')
    if report.get("unmappedControls"):
        out.append(
            '<p class="note">Controls kube-noob maps that no indicator cites, so no finding reaches an indicator '
            f"through them: {_esc(', '.join(report['unmappedControls']))}.</p>"
        )
    for miss in report.get("findingsNotMapped") or []:
        out.append(
            f'<div class="caveat"><b>Findings that reach no indicator</b>{_esc(miss.get("findings"))} from '
            f'<span class="mono">{_esc(miss.get("ruleId"))}</span>: {_rich(miss.get("why"))}</div>'
        )
    audited = report.get("audited")
    out.append(sec.head("Indicators", "indicators", note=f"{len(indicators)} in the crosswalk"))
    headers = ["Indicator", "Family", "Name", "kube-noob controls"]
    numeric: set[int] = set()
    if audited:
        headers += ["Findings", "Clean", "Not evaluated", "Withheld"]
        numeric = {4, 5, 6, 7}
    else:
        headers += ["Rules behind it"]
        numeric = {4}
    rows: list[list[str]] = []
    for r in indicators:
        base = [
            f'<span class="mono">{_esc(r.get("id"))}</span>',
            _esc(r.get("family")),
            _esc(r.get("name")),
            _esc(", ".join(r.get("controls") or [])) or "—",
        ]
        if not r.get("evidenced"):
            # One cell spanning the count columns: the note used to sit under the "Findings" heading, which is
            # the one place on this page a reader must not misread.
            base.append(f'<span class="note">{_esc(r.get("why"))}</span>')
        elif audited:
            base += [
                _esc(r.get("findings", 0)),
                _esc(r.get("clean", 0)),
                _esc(r.get("notEvaluated", 0)),
                _esc(r.get("withheld", 0)),
            ]
        else:
            base.append(_esc(r.get("rulesBehind", 0)))
        rows.append(base)
    out += _table(headers, rows, numeric=numeric)
    curated = [r for r in indicators if r.get("evidence")]
    if curated:
        out.append(sec.head("What the evidence shows, and what it does not", "evidence"))
        for r in curated:
            out.append(f'<h3><span class="mono">{_esc(r["id"])}</span> — {_esc(r.get("name"))}</h3>')
            if r.get("warning"):
                out.append(f'<div class="caveat"><b>Warning</b>{_rich(r["warning"])}</div>')
            ev = r["evidence"]
            out.append(
                '<dl class="ev">'
                f"<dt>Shows</dt><dd>{_rich(ev.get('shows'))}</dd>"
                f"<dt>Does not show</dt><dd>{_rich(ev.get('doesNotShow'))}</dd>"
                f'<dt>Rules named</dt><dd><span class="mono">{_esc(", ".join(ev.get("rulesNamed") or []))}</span></dd>'
                "</dl>"
            )
            if r.get("notEvaluatedRules"):
                more = f" and {r['moreNotEvaluated']} more" if r.get("moreNotEvaluated") else ""
                out.append(
                    f'<p class="note">Declined to decide: <span class="mono">'
                    f"{_esc(', '.join(r['notEvaluatedRules']))}</span>{_esc(more)}.</p>"
                )
    return out


def _title(report: dict[str, Any]) -> str:
    if "indicators" in report:
        return "FedRAMP 20x Key Security Indicators"
    if "passed" in report or "failures" in report:
        return "kube-noob gate"
    if "controlStanding" in report or "violations" in report:
        return "kube-noob posture"
    return "kube-noob report"


def render(report: dict[str, Any], *, generated_at: dt.datetime | None = None) -> str:
    """One page for whichever report this is. Unknown shapes still produce a valid page rather than an error.

    The order is the argument (U5). A reviewer opens this to decide something, so the verdict, the three numbers
    that decide it and the scope they are true of come first; then what the run could not establish; then what
    it found. Sections are numbered as they are written so the contents and a reader's citation agree.
    """
    when = (generated_at or dt.datetime.now(dt.UTC)).strftime("%Y-%m-%d %H:%M UTC")
    title = _title(report)
    # kube-noob's version only. The KSI report carries dataset.version (2026.11.02.01), and borrowing it for
    # the byline printed "by kube-noob 2026.11.02.01" -- a false claim about the tool, in the first line of a
    # document written for someone checking claims.
    version = str(report.get("version") or "")
    sec = Sections()
    # Explicit dispatch, because the three reports share key NAMES with different shapes: a gate report's
    # `findings` is a list of findings and a posture report's is a dict of buckets, and rendering one as the
    # other produced a page built from dictionary keys.
    is_gate = "passed" in report or "failOn" in report
    is_posture = "controlStanding" in report or "violations" in report
    body = _limits(report, sec)
    if is_gate:
        body += _gate_sections(report, sec)
    if is_posture:
        body += _posture_findings(report, sec)
        body += _standing_sections(report, sec)
        body += _trend_sections(report, sec)
    body += _ksi_sections(report, sec)
    return "\n".join(
        [
            "<!doctype html>",
            '<html lang="en"><head><meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1">',
            f"<title>{_esc(title)}</title>",
            f"<style>{_CSS}{charts.CSS}</style>",
            "</head><body><main>",
            f"<h1>{_esc(title)}</h1>",
            f'<p class="sub">Generated {_esc(when)} by kube-noob'
            + (f" {_esc(version)}" if version else "")
            + ". No network was used to produce this page, and the page itself loads nothing.</p>",
            *_masthead(report, when, version),
            # Written after the body, because the numbers come from the sections that were actually rendered.
            *sec.toc(),
            *body,
            "</main></body></html>",
            "",
        ]
    )
