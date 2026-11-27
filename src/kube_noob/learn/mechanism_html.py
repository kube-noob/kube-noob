"""One mechanism walk as a lesson player you can watch: an isometric scene, an event that travels it, a story.

`render()` in :mod:`kube_noob.learn.mechanism` is the walk as text and `--format json` is the walk as data. This
is the third view of the SAME dict, for the reader who learns a path by watching it. The page is a port of
KubeLearn's lesson player (kubelearn.joesabbagh.com, Copyright (c) 2026 Joe Sabbagh, MIT License; the notice is in
``THIRD_PARTY_NOTICES.md``), driven by kube-noob's own walk: a stage with the reader's objects standing on a
cluster floor, a marker that flies from one hop's object to the next, a caption strip and a transport bar under
it, a story column with the hop's explanation and its facts, the list of hops, a sequence view of the same path,
and a drawer of the evidence. One KubeLearn "step" is one hop; the lesson overview is the path's verdict. The
drawing lives in :mod:`kube_noob.learn.iso` and :mod:`kube_noob.learn.mechanism_scene`, the stylesheet and the
script in :mod:`kube_noob.learn.mechanism_player`; this module decides what the page says.

Five rules hold the module up. `tests/test_a_walk_you_can_watch.py` and `tests/test_the_walk_like_kubelearn.py`
hold each of them.

**It adds no judgement.** Every verdict on the page is the one `walk()` reached. The only thing computed here is
how to draw it, and the drawing has five states, not two: holds, BROKEN, cannot judge, not observable and not
walked. A value this module does not recognise -- a verdict it has no word for, a path verdict that disagrees with
its own hops -- is drawn as unrecognised, in the colour of a stop, and never as a pass.

**Nothing that was not judged is animated as passing.** The marker is drawn only for a hop a rule read. At a
BROKEN hop it arrives and fails; at a hop that could not be judged it stops short and the page says why; for a
hop no manifest can show, and for a hop after a stop, no marker is drawn at all and the page says that in words.
Each state is a glyph and a word first and a colour second, so a monochrome print and a screen reader get the
same answer, and on this page green is used for one thing only: a rule read the hop and it holds.

**Nothing from a manifest is ever markup.** Object names, finding titles and the walker's own sentences that
quote them all pass through :func:`_text` (one line, invisible characters marked, capped) and :func:`_esc`, in
the HTML and in the SVG text of the scene alike. The walk is also embedded as JSON for the script and for any
program that wants the data back; there `<`, `>`, `&`, U+2028 and U+2029 are written as `\\uXXXX`, so no string
can close the element it sits in. The script puts text on the page with `textContent` only.

**The page fetches nothing and is the same bytes every time.** No URL appears in it -- not a font, not an image,
not an SVG namespace, not the address of the project this player is ported from -- and the Content-Security-
Policy in its head forbids the browser from fetching one even if a name tried. A `://` that arrives inside a
name is written with its colon as a character reference, so the page carries no clickable or auto-linked address
either. There is no timestamp and no randomness: one walk, one page. The output is ASCII, so it is safe to print
to a terminal as well as to redirect to a file.

**The page is the whole walk without the script.** The overview, every hop's verdict, explanation, rules,
objects and findings, the list of hops and the evidence table are in the HTML as written, and the scene is drawn
in its final state. The script only chooses what to show and moves the marker and the camera.
"""

from __future__ import annotations

import html
from typing import Any

from kube_noob import sanitize
from kube_noob.learn import iso, mechanism_scene
from kube_noob.learn.mechanism import CANNOT_JUDGE, FAILS, HOLDS, NOT_OBSERVABLE
from kube_noob.learn.mechanism_player import CSS as _CSS
from kube_noob.learn.mechanism_player import JS as _JS
from kube_noob.learn.mechanism_player import icon as _icon
from kube_noob.yamlio import json_document

#: A hop the lesson declares and the walk never reached, because it stopped first. Not a verdict `walk()` emits --
#: those hops are absent from `steps` and only counted -- so this view gives the absence a name and a card.
NOT_WALKED = "not-walked"
#: A step verdict this build has no word for. Drawn like a stop; never like a pass.
UNRECOGNISED = "unrecognised"

#: The words for each state. Words, not colour: they are in the page's text wherever the state is shown.
MARK = {
    HOLDS: "holds",
    FAILS: "BROKEN",
    CANNOT_JUDGE: "cannot judge",
    NOT_OBSERVABLE: "not observable",
    NOT_WALKED: "not walked",
    UNRECOGNISED: "unrecognised verdict",
}

#: The glyph beside each word: a tick, a cross, a question mark, a dotted circle, a middle dot. Only a hop a rule
#: read and found nothing wrong on gets the tick.
GLYPH = {
    HOLDS: "\u2713",
    FAILS: "\u2717",
    CANNOT_JUDGE: "?",
    NOT_OBSERVABLE: "\u25cc",
    NOT_WALKED: "\u00b7",
    UNRECOGNISED: "?",
}

#: What the list of hops says under a hop nobody judged, beside its word.
_NOTE = {
    NOT_OBSERVABLE: "not checked by any manifest",
    NOT_WALKED: "the walk stopped before this hop",
}

#: The hops a marker is drawn for: the ones a rule read. `cannot-judge` is here because the marker is drawn
#: stopping short of it, which is the picture of what happened.
_DRAWN = (HOLDS, FAILS, CANNOT_JUDGE)

_EXIT_MEANS = {
    0: "at least one hop was judged and every observable hop holds",
    1: "a verdict was reached and it is not a pass",
    5: "no verdict was reached",
}

#: Placeholders drawn for hops the walk counted as not reached when no lesson was passed to name them. Bounded,
#: because the count is read from a dict a caller may have built by hand.
_MAX_PLACEHOLDERS = 64
_MAX_LISTED = 40
#: Progress dots are drawn per hop in every hop's section, so only for a path short enough to read them.
_MAX_DOTS = 24

CSP = "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:"

CREDIT = "Player design ported from KubeLearn by Joe Sabbagh, MIT"


def _text(value: object, cap: int = 240) -> str:
    """One line of text from the walk: white space collapsed, invisible and bidi characters marked, capped.

    The cap is stated when it cuts, so a truncated name does not read as the whole name.
    """
    out = sanitize.one_line("" if value is None else str(value))
    return out if len(out) <= cap else out[: cap - 3].rstrip() + "..."


def _whole(value: object, limit: int = 4000) -> str:
    """A hop's explanation, on one line and not cut: it wraps on the page instead (G411).

    The last clause of a `holds` sentence is where the lesson states what its rule does not read; a cap that fell
    there made the hold read stronger than the lesson wrote it. Only input can be longer than `limit`, and then
    the page says how much was left out.
    """
    out = sanitize.one_line("" if value is None else str(value))
    return out if len(out) <= limit else f"{out[:limit]} (cut: {len(out) - limit} more characters)"


def _esc(value: object) -> str:
    """Escaped for HTML text, for SVG text and for a double-quoted attribute, and ASCII.

    `[` and the colon of `://` are written as character references: the first so no line of the page can be read
    as a CI service message (`##[`), the second so the page carries no address a viewer would auto-link.
    """
    out = html.escape("" if value is None else str(value), quote=True)
    out = out.replace("[", "&#91;").replace("://", "&#58;//")
    return out.encode("ascii", "xmlcharrefreplace").decode("ascii")


def _json(obj: Any) -> str:
    """JSON that is safe inside a `<script>` element: sorted keys, ASCII, and no `<`, `>` or `&` in the bytes.

    `ensure_ascii` already writes U+2028 and U+2029 as escapes; they are replaced again here so the property does
    not rest on that flag. `://` occurs only inside strings (no JSON syntax puts a slash after a colon), so
    escaping its colon changes no structure and the data loads back exactly.
    """
    text = json_document(obj, sort_keys=True, ensure_ascii=True, separators=(",", ":"), default=str)
    for raw, safe in (
        ("<", "\\u003c"),
        (">", "\\u003e"),
        ("&", "\\u0026"),
        ("\u2028", "\\u2028"),
        ("\u2029", "\\u2029"),
        ("://", "\\u003a//"),
    ):
        text = text.replace(raw, safe)
    return text


def _int(value: object) -> int | None:
    """A count as an int, or None when it is not one. `True` is not a count."""
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _strings(value: object) -> list[str]:
    if not isinstance(value, list | tuple):
        return []
    return [_text(v) for v in value]


def _declared(lesson: dict[str, Any] | None, steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The lesson's steps, when they are the path this walk walked: `steps` must be a prefix of them, id by id.

    A lesson that does not match is ignored rather than trusted, so a wrong lesson cannot put names on hops the
    walk never declared.
    """
    raw = (lesson or {}).get("steps")
    if not isinstance(raw, list) or len(raw) < len(steps):
        return []
    declared = [s for s in raw if isinstance(s, dict)]
    if len(declared) != len(raw):
        return []
    for got, want in zip(steps, declared, strict=False):
        if str(got.get("step")) != str(want.get("id")):
            return []
    return declared


def _kinds(step: dict[str, Any] | None) -> list[str]:
    if not step:
        return []
    return _strings(step.get("needs") or step.get("reads") or [])


def _event(state: str, n: int, why: str, broken_before: int | None, stop_at: int | None) -> str:
    """What the event does at this hop, in one sentence. The page prints it, with or without the animation."""
    if state == HOLDS:
        tail = f" The path was already broken at hop {broken_before}." if broken_before else ""
        return f"The event arrives: this hop holds.{tail}"
    if state == FAILS:
        return "The event fails here: this hop is BROKEN. The walk carries on, because a finding is a verdict."
    if state == CANNOT_JUDGE:
        return "The event stops before this hop: it could not be judged. The hops after it were not walked."
    if state == NOT_OBSERVABLE:
        return "No event is drawn: no manifest can show this hop, so it was not checked and is not counted as passing."
    if state == NOT_WALKED:
        where = f"at hop {stop_at}" if stop_at else "earlier"
        return (
            f"No event is drawn: the walk stopped {where}, so this hop was not walked. It is not reported as working."
        )
    return "No event is drawn: this hop carries a verdict this page does not recognise. It is not counted as passing."


def _says(h: dict[str, Any]) -> str:
    """The caption under the scene: what this hop checked and what the walk found there, in a plain sentence."""
    state, head = h["state"], f"{h['title']}: {h['mark']}."
    if state == HOLDS:
        return f"{head} The rules that read this hop found nothing wrong."
    if state == FAILS:
        found = h["findings"]
        if not found:
            return f"{head} {h['why']}"
        first = found[0]
        more = f" And {len(found) - 1} more finding(s)." if len(found) > 1 else ""
        return f"{head} {first['ruleId']} on {first['resource']}: {first['title']}.{more}"
    if state == CANNOT_JUDGE:
        return f"{head} {h['why']}"
    if state == NOT_OBSERVABLE:
        return f"{head} No manifest can show this hop, so it was not checked and is not counted as passing."
    if state == NOT_WALKED:
        return f"{head} The walk stopped before this hop, so it is not reported as working."
    return f"{head} This page does not recognise the verdict on this hop, so it is not counted as passing."


def _evidence(hops: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """What the walk recorded, hop by hop: every finding, and the reason beside every hop no rule could judge."""
    rows: list[dict[str, Any]] = []
    for h in hops:
        for f in h["findings"]:
            rows.append(
                {
                    "hop": h["n"],
                    "state": h["state"],
                    "rule": f["ruleId"],
                    "severity": f["severity"].upper() or "not stated",
                    "object": f["resource"],
                    "message": f["title"],
                }
            )
        if h["state"] in (CANNOT_JUDGE, UNRECOGNISED, NOT_OBSERVABLE):
            rows.append(
                {
                    "hop": h["n"],
                    "state": h["state"],
                    "rule": ", ".join(h["rules"]) or "none",
                    "severity": "not observable" if h["state"] == NOT_OBSERVABLE else "not evaluated",
                    "object": ", ".join(h["objects"][:3]) or "none named by the walk",
                    "message": h["why"],
                }
            )
    return rows


def _model(walked: dict[str, Any], lesson: dict[str, Any] | None) -> tuple[dict[str, Any], dict[str, str]]:
    """The view, and the markup of the stage drawn from it."""
    raw_steps = walked.get("steps")
    steps = [s for s in raw_steps if isinstance(s, dict)] if isinstance(raw_steps, list) else []
    raw_counts = walked.get("counts")
    counts: dict[str, Any] = raw_counts if isinstance(raw_counts, dict) else {}
    declared = _declared(lesson, steps)

    not_reached = _int(counts.get("notReached")) or 0
    after = max(not_reached, len(declared) - len(steps), 0)
    capped = min(after, _MAX_PLACEHOLDERS)

    hops: list[dict[str, Any]] = []
    broken_before: int | None = None
    stop_at: int | None = None
    for i, s in enumerate(steps):
        n = i + 1
        verdict = s.get("verdict")
        state = (
            verdict
            if isinstance(verdict, str) and verdict in (HOLDS, FAILS, CANNOT_JUDGE, NOT_OBSERVABLE)
            else UNRECOGNISED
        )
        objects = _strings(s.get("objects"))
        kinds = _kinds(declared[i] if declared else None)
        if objects:
            label, named = objects[0] + (f" (+{len(objects) - 1} more)" if len(objects) > 1 else ""), True
        elif kinds:
            label, named = " / ".join(kinds), False
        else:
            label, named = _text(s.get("step") or f"hop {n}"), False
        raw_findings = s.get("findings")
        findings = [
            {
                "severity": _text(f.get("severity")),
                "ruleId": _text(f.get("ruleId")),
                "resource": _text(f.get("resource")),
                "title": _text(f.get("title")),
            }
            for f in (raw_findings if isinstance(raw_findings, list) else [])
            if isinstance(f, dict)
        ]
        why = _whole(s.get("why"))
        hops.append(
            {
                "n": n,
                "id": _text(s.get("step") or f"hop {n}"),
                "title": _text(s.get("title") or f"hop {n}"),
                "state": state,
                "mark": MARK[state],
                "glyph": GLYPH[state],
                "why": why,
                "label": label,
                "named": named,
                "objects": objects,
                "kinds": kinds,
                "rules": _strings(s.get("rules")),
                "findings": findings,
                "event": _event(state, n, why, broken_before, stop_at),
            }
        )
        if state == FAILS and broken_before is None:
            broken_before = n
        if state in (CANNOT_JUDGE, UNRECOGNISED) and stop_at is None:
            stop_at = n
    for j in range(capped):
        n = len(steps) + j + 1
        step = declared[n - 1] if declared and n - 1 < len(declared) else None
        kinds = _kinds(step)
        ident = _text(step.get("id")) if step else f"hop {n}"
        hops.append(
            {
                "n": n,
                "id": ident,
                "title": _text(step.get("title")) if step else "A hop the walk did not reach",
                "state": NOT_WALKED,
                "mark": MARK[NOT_WALKED],
                "glyph": GLYPH[NOT_WALKED],
                "why": "The walk stopped before this hop, so nothing read it and nothing is claimed about it.",
                "label": " / ".join(kinds) if kinds else ident,
                "named": False,
                "objects": [],
                "kinds": kinds,
                "rules": _strings(step.get("rules")) if step else [],
                "findings": [],
                "event": _event(NOT_WALKED, n, "", broken_before, stop_at),
            }
        )
    total = len(hops)
    width = max(2, len(str(total)))
    for h in hops:
        prev = hops[h["n"] - 2]["label"] if h["n"] > 1 else "start"
        h["caption"] = f"{h['n']:0{width}d}/{total:0{width}d}  {prev} \u2192 {h['label']}"
        h["says"] = _says(h)

    verdict = walked.get("verdict")
    exit_code = _int(walked.get("exitCode"))
    states = [h["state"] for h in hops]
    judged = sum(1 for s in states if s in (HOLDS, FAILS))
    # The one check this view makes of its input, and it only ever lowers: a `complete` that its own hops do not
    # bear out is not drawn in the colour of a pass. `walk()` never produces one; a hand-built dict can.
    if verdict == "complete":
        # `all()` over no hops is True; `judged > 0` is what refuses that, and the `steps: []` case of
        # test_a_complete_its_own_hops_do_not_bear_out_is_not_drawn_as_a_pass holds it. Recorded in
        # tests/fixtures/empty_verdict_baseline.json for that reason.
        sound = exit_code == 0 and judged > 0 and all(s in (HOLDS, NOT_OBSERVABLE) for s in states)
        tone, word = ("ok", "complete") if sound else ("warn", "unrecognised: the verdict and the hops disagree")
    elif verdict == "broken":
        tone, word = "bad", "BROKEN"
    elif verdict == "stopped":
        tone, word = "warn", "stopped: no verdict reached"
    else:
        tone, word = "warn", "unrecognised verdict"

    # The hop a reader has to act on: the stop, else the first break, else the first hop. The overview links it.
    start = next((h["n"] for h in hops if h["state"] in (CANNOT_JUDGE, UNRECOGNISED)), None)
    start = start or next((h["n"] for h in hops if h["state"] == FAILS), None) or (1 if hops else 0)

    def count(key: str) -> str:
        got = _int(counts.get(key))
        return "not stated" if got is None else str(got)

    lesson_id = _text(walked.get("lesson"))
    namespaces = _strings(walked.get("namespaces"))
    drawn = mechanism_scene.build(hops, lesson_id, namespaces, _esc) if hops else {"scene": "", "sequence": ""}
    view_ = {
        "lesson": lesson_id,
        "title": _text(walked.get("title") or "A mechanism walk"),
        "layer": _text(walked.get("layer")),
        "verdict": _text(verdict),
        "verdictWord": word,
        "tone": tone,
        "reason": _text(walked.get("verdictReason") or "no reason was given for this verdict", 900),
        "exitCode": "not stated" if exit_code is None else str(exit_code),
        "exitMeans": _EXIT_MEANS.get(exit_code if exit_code is not None else -1, "not an exit code this page knows"),
        "counts": {k: count(k) for k in ("declared", "judged", "notObservable", "notReached")},
        "namespaces": namespaces,
        "hiddenHops": after - capped,
        "start": start,
        "hops": hops,
        "evidence": _evidence(hops),
        "scene": drawn.get("data"),
    }
    return view_, {"scene": str(drawn["scene"]), "sequence": str(drawn["sequence"])}


def view(walked: dict[str, Any], lesson: dict[str, Any] | None = None) -> dict[str, Any]:
    """Everything the page shows, as cleaned strings: the model the HTML and the script are both written from."""
    return _model(walked, lesson)[0]


def _code(value: str) -> str:
    """A value that came from the reader's manifests, set apart so it cannot blend into the page's own words."""
    return f'<code class="in">{_esc(value)}</code>'


def _list(values: list[str], *, from_input: bool) -> str:
    shown = values[:_MAX_LISTED]
    parts = [_code(v) if from_input else _esc(v) for v in shown]
    if len(values) > len(shown):
        parts.append(_esc(f"and {len(values) - len(shown)} more not listed here"))
    return ", ".join(parts)


def _glyph(state: str) -> str:
    """The mark in the list of hops. A hop nobody judged gets a hollow ring drawn by the stylesheet, not a tick."""
    if state in (NOT_OBSERVABLE, NOT_WALKED):
        return '<span class="glyph hollow" aria-hidden="true"></span>'
    return f'<span class="glyph" aria-hidden="true">{_esc(GLYPH[state])}</span>'


def _node(h: dict[str, Any]) -> str:
    """One hop in the list: its number, its glyph, its title and its verdict as a word."""
    note = f'<span class="note">{_esc(_NOTE[h["state"]])}</span>' if h["state"] in _NOTE else ""
    return (
        f'<li><a class="node s-{h["state"]}" href="#step-{h["n"]}">'
        f'<span class="num">{h["n"]}</span>{_glyph(h["state"])}'
        f'<span class="lab"><span class="toc-title">{_esc(h["title"])}</span> '
        f'<span class="chip">{_esc(h["mark"])}</span>{note}</span></a></li>'
    )


def _fact(name: str, value: str) -> str:
    return f"<div><dt>{name}</dt><dd>{value}</dd></div>"


def _section(h: dict[str, Any], total: int) -> str:
    """One hop of the story: where it is on the path, what it checks, why it got its verdict, and the facts."""
    state = h["state"]
    if h["objects"]:
        objects = _list(h["objects"], from_input=True)
    elif h["kinds"]:
        objects = f"none named by the walk (the hop reads {_esc(' / '.join(h['kinds']))})"
    else:
        objects = "none named by the walk"
    if h["rules"]:
        rules = _list(h["rules"], from_input=False)
        if state == NOT_WALKED:
            rules += " (the rules it would rest on; none ran)"
    else:
        rules = "none: no rule in this build reads this hop"
    facts = [
        _fact("Object", objects),
        _fact("Rules", rules),
        _fact("Verdict", f'<span class="chip s-{state}">{_esc(h["glyph"])} {_esc(h["mark"])}</span>'),
    ]
    if h["findings"]:
        items = "".join(
            f'<li><span class="sev">{_esc(f["severity"].upper())}</span><span>{_esc(f["ruleId"])}</span> '
            f"{_code(f['resource'])} <span>{_esc(f['title'])}</span></li>"
            for f in h["findings"][:_MAX_LISTED]
        )
        if len(h["findings"]) > _MAX_LISTED:
            more = len(h["findings"]) - _MAX_LISTED
            items += f"<li>{_esc(f'and {more} more findings not listed here')}</li>"
        facts.append(_fact("Findings", f'<ul class="finds">{items}</ul>'))
    elif state == HOLDS:
        facts.append(_fact("Findings", "none from the rules above"))
    elif state == FAILS:
        facts.append(_fact("Findings", "not listed in the walk"))
    else:
        facts.append(_fact("Findings", "none reported; that is not a pass for this hop"))
    dots = ""
    if total <= _MAX_DOTS:
        dots = (
            '<span class="dots" aria-hidden="true">'
            + "".join('<i class="on"></i>' if k < h["n"] else "<i></i>" for k in range(total))
            + "</span>"
        )
    return (
        f'<section class="panel hop s-{state}" id="step-{h["n"]}">'
        f'<div class="kicker-row"><span class="kicker">Hop {h["n"]} of {total}</span>{dots}'
        f'<a class="link-btn" href="#overview">{_icon("back", 12)}Overview</a></div>'
        f'<h2 class="display">{_esc(h["title"])}</h2>'
        f'<p class="sub route">{_esc(h["caption"])}</p>'
        f'<p class="body prose">{_esc(h["why"])}</p>'
        f'<p class="body event">{_esc(h["event"])}</p>'
        f'<dl class="facts">{"".join(facts)}</dl></section>'
    )


def _overview(v: dict[str, Any]) -> list[str]:
    """Step 0 of the player: the path's verdict, what the exit code means, the counts and the walk's reason."""
    hops, counts = v["hops"], v["counts"]
    spaces = v["namespaces"]
    if len(spaces) == 1:
        where = _code(spaces[0]) + " (the namespace judged)"
    elif spaces:
        where = _list(spaces, from_input=True) + " (more than one, so none was judged)"
    else:
        where = "none stated by the walk"
    out = [
        f'<section class="panel t-{v["tone"]}" id="overview" aria-label="Path verdict">',
        '<p class="kicker">' + (f"{_esc(v['layer'])} layer &#183; " if v["layer"] else "") + "mechanism walk</p>",
        '<h2 class="display">',
        f'<span class="word">Path verdict: {_esc(v["verdictWord"])}</span>',
        "</h2>",
        f'<p class="sub">exit code {_esc(v["exitCode"])} ({_esc(v["exitMeans"])})</p>',
        f'<p class="body prose">{_esc(v["reason"])}</p>',
        '<dl class="stats">',
        f"<div><dt>hops declared</dt><dd>{_esc(counts['declared'])}</dd></div>",
        f"<div><dt>judged</dt><dd>{_esc(counts['judged'])}</dd></div>",
        f"<div><dt>not observable</dt><dd>{_esc(counts['notObservable'])}</dd></div>",
        f"<div><dt>not walked</dt><dd>{_esc(counts['notReached'])}</dd></div>",
        "</dl>",
        '<dl class="facts">',
        _fact("Lesson", f"kube-noob learn mechanism {_esc(v['lesson'])}"),
        _fact("Namespace", where),
        "</dl>",
    ]
    if hops:
        out.append(f'<a class="btn primary start" href="#step-1">{_icon("play", 12)}Walk the {len(hops)} hops</a>')
        act = hops[int(v["start"]) - 1]
        if act["state"] not in (HOLDS, NOT_OBSERVABLE):
            out.append(
                f'<a class="jump" href="#step-{act["n"]}">Go to hop {act["n"]}: {_esc(act["mark"])}, '
                "the hop to act on</a>"
            )
    out.append("</section>")
    return out


def _stage(v: dict[str, Any], markup: dict[str, str]) -> list[str]:
    """The left of the player: the scene, the sequence view of it, the caption strip and the transport bar."""
    return [
        f'<section class="stage" id="schem" data-view="cluster" data-start="{int(v["start"])}" aria-label="Diagram">',
        '<div class="canvas">',
        markup["scene"],
        f'<div class="sequence">{markup["sequence"]}</div>',
        '<div class="stage-tools jsonly">',
        '<div class="seg" role="group" aria-label="Diagram view">',
        f'<button type="button" id="v-cluster" aria-pressed="true">{_icon("layers", 14)}Cluster</button>',
        f'<button type="button" id="v-sequence" aria-pressed="false">{_icon("sequence", 14)}Sequence</button>',
        "</div>",
        "</div>",
        '<div class="zoom-ui jsonly">',
        f'<button type="button" class="ibtn" id="zin" aria-label="Zoom in">{_icon("plus", 14)}</button>',
        f'<button type="button" class="ibtn" id="zout" aria-label="Zoom out">{_icon("minus", 14)}</button>',
        f'<button type="button" class="ibtn" id="zreset" aria-label="Reset view" hidden>{_icon("recenter", 14)}'
        "</button>",
        "</div>",
        '<div class="caption" id="capbox" hidden>',
        '<div class="caption-in"><span class="badge" id="capn" aria-hidden="true"></span>'
        '<span><em id="capr"></em><output id="cap" aria-live="polite"></output></span>'
        f'<button type="button" class="caption-next" id="capnext" aria-label="Next">{_icon("right")}</button></div>',
        "</div>",
        '<div class="transport controls" role="group" aria-label="Step through the walk">',
        f'<button type="button" class="ibtn" id="prev" aria-label="Previous hop">{_icon("prev")}</button>',
        f'<button type="button" class="btn primary play" id="next">{_icon("next", 12)}'
        '<span id="nextlabel">Next hop</span></button>',
        f'<button type="button" class="ibtn" id="play" aria-pressed="false" aria-label="Auto-play the hops">'
        f"{_icon('play', 14)}</button>",
        '<button type="button" class="ibtn speed" id="speed" aria-label="Playback speed 1 times. Change speed">'
        "1&#215;</button>",
        f'<button type="button" class="ibtn" id="restart" aria-label="Restart at the overview">{_icon("replay")}'
        "</button>",
        "</div>",
        "</div>",
        "</section>",
    ]


def _flow(v: dict[str, Any]) -> list[str]:
    """The drawer under the stage: the evidence the walk recorded, one row per finding or unjudged hop."""
    rows = v["evidence"]
    out = [
        '<details class="flow" id="flow">',
        f"<summary>{_icon('right', 14).replace('ico i-right', 'ico i-right flow-chevron')}Events "
        f'<span class="count" id="count">{len(rows)} / {len(rows)}</span></summary>',
        '<span class="progress" aria-hidden="true"><i id="bar"></i></span>',
        '<div class="flow-panel">',
    ]
    if rows:
        out.append(
            '<table class="etable"><thead><tr><th scope="col">Hop</th><th scope="col">Rule</th>'
            '<th scope="col">Severity</th><th scope="col">Object</th><th scope="col">What the walk recorded</th>'
            "</tr></thead><tbody>"
        )
        for r in rows[: _MAX_LISTED * 4]:
            out.append(
                f'<tr data-hop="{int(r["hop"])}"><td>{int(r["hop"])}</td><td>{_esc(r["rule"])}</td>'
                f'<td class="sev s-{r["state"]}">{_esc(r["severity"])}</td><td>{_code(r["object"])}</td>'
                f"<td>{_esc(r['message'])}</td></tr>"
            )
        out.append("</tbody></table>")
        if len(rows) > _MAX_LISTED * 4:
            out.append(f'<p class="empty-row">{len(rows) - _MAX_LISTED * 4} more rows are not listed here.</p>')
    else:
        out.append(
            '<p class="empty-row">The walk recorded no finding and no hop it could not judge. That is what this '
            "walk recorded about this path, not a statement about anything it did not read.</p>"
        )
    out += ["</div>", "</details>"]
    return out


_LEGEND = [
    '<details class="legend">',
    "<summary>How to read this page</summary>",
    "<ul>",
    '<li><span class="chip s-holds">&#10003; holds</span> a rule read this hop and found nothing wrong.</li>',
    '<li><span class="chip s-fails">&#10007; BROKEN</span> a rule on this hop produced a finding. The walk carries '
    "on.</li>",
    '<li><span class="chip s-cannot-judge">? cannot judge</span> nothing could answer for this hop. The walk stops '
    "here.</li>",
    '<li><span class="chip s-not-observable">&#9676; not observable</span> no manifest can show this hop. It is '
    "never counted as passing, and what stands there in the diagram is drawn dashed and marked not in any "
    "manifest.</li>",
    '<li><span class="chip s-not-walked">&#183; not walked</span> the walk stopped before this hop. It is never '
    "reported as working.</li>",
    '<li><code class="in">shaded text</code> came from your manifests; everything else is kube-noob speaking.</li>',
    "<li>Green is used for one thing: a hop that holds. The colour of a card that has no verdict yet says what "
    "kind of object it is, and nothing about whether it works.</li>",
    "</ul>",
    "</details>",
]

_SHORTCUTS = [
    '<dialog id="shortcuts" aria-labelledby="keys-title">',
    '<div class="dialog-head"><h2 class="dialog-title" id="keys-title">Keyboard shortcuts</h2>',
    f'<button type="button" class="ibtn ghost" id="keysclose" aria-label="Close">{_icon("close")}</button></div>',
    '<dl class="shortcut-list">',
    "<div><dt><kbd>&#8594;</kbd> <kbd>Space</kbd></dt><dd>Next hop</dd></div>",
    "<div><dt><kbd>&#8592;</kbd></dt><dd>Previous hop</dd></div>",
    "<div><dt><kbd>Home</kbd></dt><dd>Back to the overview</dd></div>",
    "<div><dt><kbd>P</kbd></dt><dd>Auto-play, or stop it</dd></div>",
    "<div><dt><kbd>+</kbd> <kbd>-</kbd></dt><dd>Zoom the diagram</dd></div>",
    "<div><dt><kbd>?</kbd></dt><dd>This list</dd></div>",
    "</dl>",
    "</dialog>",
]


def render_html(walked: dict[str, Any], lesson: dict[str, Any] | None = None) -> str:
    """The walk as one self-contained HTML document. `lesson` names the hops after a stop; without it they are
    drawn as numbered placeholders, and either way each is labelled "not walked"."""
    v, markup = _model(walked, lesson)
    hops = v["hops"]
    title = f"{v['title']} ({v['layer']})" if v["layer"] else v["title"]
    out: list[str] = [
        "<!doctype html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        f'<meta http-equiv="Content-Security-Policy" content="{CSP}">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>{_esc(title)} - kube-noob mechanism walk</title>",
        f"<style>{_CSS}</style>",
        "</head>",
        "<body>",
        '<div class="shell">',
        '<header class="topbar">',
        f'<span class="brand"><svg class="iso brand-mark" viewBox="-19 -32 38 44" aria-hidden="true" '
        f'focusable="false">{iso.logo(2)}</svg><span class="wordmark"><span class="k">kube</span>-noob</span></span>',
        '<span class="topbar-sep" aria-hidden="true">/</span>',
        '<span class="crumb">learn mechanism</span>',
        '<span class="topbar-sep" aria-hidden="true">/</span>',
        f'<h1 class="crumb-here">{_esc(v["title"])}</h1>',
        '<div class="tools jsonly">',
        f'<button type="button" class="ibtn ghost" id="theme" aria-label="Switch theme">{_icon("sun")}{_icon("moon")}'
        "</button>",
        f'<button type="button" class="ibtn ghost" id="keys" aria-label="Keyboard shortcuts">{_icon("keys")}</button>',
        "</div>",
        "</header>",
        '<main class="workspace">',
    ]
    if hops:
        out += _stage(v, markup)
    else:
        out += [
            '<section class="stage" aria-label="Diagram">',
            '<p class="empty-row">This walk lists no hops, so there is nothing to draw and nothing is shown as '
            "working.</p>",
            "</section>",
        ]
    out += ['<aside class="story" id="story" aria-label="The walk, hop by hop">', '<div class="story-body">']
    out += _overview(v)
    out += [_section(h, len(hops)) for h in hops]
    out.append("</div>")
    if hops:
        out += [
            '<nav class="toc" aria-label="Hops">',
            '<ol class="toc-list">',
            *[_node(h) for h in hops],
            "</ol>",
        ]
        if v["hiddenHops"]:
            out.append(
                f'<p class="more">{_esc(v["hiddenHops"])} more hop(s) were not walked and are not drawn here. '
                "They are not reported as working.</p>"
            )
        out.append("</nav>")
    out += _LEGEND
    out += [
        f'<footer class="credit">{CREDIT}. Drawn by kube-noob from your own manifests; this page fetched nothing.'
        "</footer>",
        "</aside>",
    ]
    out += _flow(v)
    out += ["</main>", "</div>"]
    out += _SHORTCUTS
    out += [
        f'<script type="application/json" id="walk-data">{_json({"view": v, "walk": walked})}</script>',
        f"<script>{_JS}</script>",
        "</body>",
        "</html>",
    ]
    return "\n".join(out) + "\n"
