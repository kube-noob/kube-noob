"""One mechanism walk as a page you can watch: a schematic of the hops, an event that travels them, a decoder.

`render()` in :mod:`kube_noob.learn.mechanism` is the walk as text and `--format json` is the walk as data. This
is the third view of the SAME dict, for the reader who learns a path by watching it: the components the lesson's
hops touch drawn in hop order, one event moving hop to hop, and a panel that opens the selected hop -- its
verdict, its rules, the objects it read and the findings on it.

Four rules hold the module up, and `tests/test_a_walk_you_can_watch.py` holds each of them.

**It adds no judgement.** Every verdict on the page is the one `walk()` reached. The only thing computed here is
how to draw it, and the drawing has five states, not two: holds, BROKEN, cannot judge, not observable and not
walked. A value this module does not recognise -- a verdict it has no word for, a path verdict that disagrees with
its own hops -- is drawn as unrecognised, in the colour of a stop, and never as a pass.

**Nothing that was not judged is animated as passing.** The event is drawn only for a hop a rule read. At a
BROKEN hop it arrives and fails; at a hop that could not be judged it stops short and the page says why; for a
hop no manifest can show, and for a hop after a stop, no event is drawn at all and the page says that in words.
Each state is text first and colour second, so a monochrome print and a screen reader get the same answer.

**Nothing from a manifest is ever markup.** Object names, finding titles and the walker's own sentences that
quote them all pass through :func:`_text` (one line, invisible characters marked, capped) and :func:`_esc`. The
walk is also embedded as JSON for the script and for any program that wants the data back; there `<`, `>`, `&`,
U+2028 and U+2029 are written as `\\uXXXX`, so no string can close the element it sits in. The script puts text
on the page with `textContent` only.

**The page fetches nothing and is the same bytes every time.** No URL appears in it -- not a font, not an image,
not an SVG namespace -- and the Content-Security-Policy in its head forbids the browser from fetching one even if
a name tried. A `://` that arrives inside a name is written with its colon as a character reference, so the page
carries no clickable or auto-linked address either. There is no timestamp and no randomness: one walk, one page.
The output is ASCII, so it is safe to print to a terminal as well as to redirect to a file.
"""

from __future__ import annotations

import html
from typing import Any

from kube_noob import sanitize
from kube_noob.learn.mechanism import CANNOT_JUDGE, FAILS, HOLDS, NOT_OBSERVABLE
from kube_noob.yamlio import json_document

#: A hop the lesson declares and the walk never reached, because it stopped first. Not a verdict `walk()` emits --
#: those hops are absent from `steps` and only counted -- so this view gives the absence a name and a box.
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

#: The hops an event is drawn for: the ones a rule read. `cannot-judge` is here because the event is drawn
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

CSP = "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:"


def _text(value: object, cap: int = 240) -> str:
    """One line of text from the walk: white space collapsed, invisible and bidi characters marked, capped.

    The cap is stated when it cuts, so a truncated name does not read as the whole name.
    """
    out = sanitize.one_line("" if value is None else str(value))
    return out if len(out) <= cap else out[: cap - 3].rstrip() + "..."


def _esc(value: object) -> str:
    """Escaped for HTML text and for a double-quoted attribute, and ASCII.

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


def view(walked: dict[str, Any], lesson: dict[str, Any] | None = None) -> dict[str, Any]:
    """Everything the page shows, as cleaned strings: the model the HTML and the script are both written from."""
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
        why = _text(s.get("why"), 600)
        hops.append(
            {
                "n": n,
                "id": _text(s.get("step") or f"hop {n}"),
                "title": _text(s.get("title") or f"hop {n}"),
                "state": state,
                "mark": MARK[state],
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

    verdict = walked.get("verdict")
    exit_code = _int(walked.get("exitCode"))
    states = [h["state"] for h in hops]
    judged = sum(1 for s in states if s in (HOLDS, FAILS))
    # The one check this view makes of its input, and it only ever lowers: a `complete` that its own hops do not
    # bear out is not drawn in the colour of a pass. `walk()` never produces one; a hand-built dict can.
    if verdict == "complete":
        sound = exit_code == 0 and judged > 0 and all(s in (HOLDS, NOT_OBSERVABLE) for s in states)
        tone, word = ("ok", "complete") if sound else ("warn", "unrecognised: the verdict and the hops disagree")
    elif verdict == "broken":
        tone, word = "bad", "BROKEN"
    elif verdict == "stopped":
        tone, word = "warn", "stopped: no verdict reached"
    else:
        tone, word = "warn", "unrecognised verdict"

    # Where the page opens: the hop a reader has to act on. The stop, else the first break, else the first hop.
    start = next((h["n"] for h in hops if h["state"] in (CANNOT_JUDGE, UNRECOGNISED)), None)
    start = start or next((h["n"] for h in hops if h["state"] == FAILS), None) or (1 if hops else 0)

    def count(key: str) -> str:
        got = _int(counts.get(key))
        return "not stated" if got is None else str(got)

    return {
        "lesson": _text(walked.get("lesson")),
        "title": _text(walked.get("title") or "A mechanism walk"),
        "layer": _text(walked.get("layer")),
        "verdict": _text(verdict),
        "verdictWord": word,
        "tone": tone,
        "reason": _text(walked.get("verdictReason") or "no reason was given for this verdict", 900),
        "exitCode": "not stated" if exit_code is None else str(exit_code),
        "exitMeans": _EXIT_MEANS.get(exit_code if exit_code is not None else -1, "not an exit code this page knows"),
        "counts": {k: count(k) for k in ("declared", "judged", "notObservable", "notReached")},
        "hiddenHops": after - capped,
        "start": start,
        "hops": hops,
    }


_CSS = """
:root{color-scheme:light dark;--bg:#f2f5fb;--grid:#dfe6f3;--panel:#ffffff;--line:#b4c2de;--ink:#13203d;
--dim:#4d5c7c;--ok:#0b6f4d;--bad:#b3261e;--warn:#7a4f00;--mute:#5a6684;--evt:#0a5fc2;--in:#eaf0fb}
@media (prefers-color-scheme:dark){:root{--bg:#0a1630;--grid:#11224a;--panel:#0f2044;--line:#2c4379;
--ink:#dce7ff;--dim:#93a7d1;--ok:#5fd6a8;--bad:#ff7b72;--warn:#f3bd55;--mute:#8492b5;--evt:#7fd2ff;--in:#16295a}}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;padding:20px 16px 56px;color:var(--ink);background:var(--bg);
background-image:linear-gradient(var(--grid) 1px,transparent 1px),
linear-gradient(90deg,var(--grid) 1px,transparent 1px);
background-size:24px 24px;font:15px/1.55 ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace}
main{max-width:1040px;margin:0 auto}
h1{font-size:1.7rem;line-height:1.2;margin:0 0 4px;letter-spacing:-.01em}
h2{font-size:1rem;margin:0 0 8px}
p{margin:0 0 8px}
.prose{font-family:system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;font-size:1rem;max-width:68ch}
.dim{color:var(--dim)}
code.in{background:var(--in);padding:0 4px;border-radius:3px;overflow-wrap:anywhere;font:inherit}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:14px 16px;margin-top:16px}
.verdict{display:flex;flex-wrap:wrap;gap:6px 18px;align-items:baseline}
.verdict .word{font-size:1.5rem;font-weight:700;overflow-wrap:anywhere}
.t-ok .word{color:var(--ok)}.t-bad .word{color:var(--bad)}.t-warn .word{color:var(--warn)}
.t-ok{border-left:6px solid var(--ok)}.t-bad{border-left:6px solid var(--bad)}
.t-warn{border-left:6px dashed var(--warn)}
.counts{display:flex;flex-wrap:wrap;gap:6px 22px;margin:10px 0 0;padding:0}
.counts div{display:flex;gap:8px;align-items:baseline}
.counts dt{color:var(--dim)}.counts dd{margin:0;font-weight:700;font-size:1.1rem}
.schem{position:relative;padding:22px 16px 22px 34px}
.nodes{list-style:none;margin:0;padding:0;display:grid;grid-template-columns:repeat(auto-fill,minmax(172px,1fr));gap:36px}
.node{position:relative;z-index:1;display:block;height:100%;min-height:104px;padding:8px 10px;color:inherit;
text-decoration:none;background:var(--panel);border:2px solid var(--line);border-radius:4px;overflow-wrap:anywhere}
.node .num{color:var(--dim)}.node .lab{display:block;font-weight:700;margin:2px 0}
.node .sub{display:block;color:var(--dim);font-size:.8rem}
.chip{display:inline-block;padding:0 7px;border:1.5px solid currentColor;border-radius:3px;
font-weight:700;font-size:.85rem}
.s-holds .chip,.s-holds.chip{color:var(--ok)}
.s-fails .chip,.s-fails.chip{color:var(--bad)}
.s-cannot-judge .chip,.s-cannot-judge.chip,.s-unrecognised .chip,
.s-unrecognised.chip{color:var(--warn);border-style:dashed}
.s-not-observable .chip,.s-not-observable.chip,.s-not-walked .chip,
.s-not-walked.chip{color:var(--mute);border-style:dashed}
.node.s-holds{border-color:var(--ok)}.node.s-fails{border-color:var(--bad);border-width:3px}
.node.s-cannot-judge,.node.s-unrecognised{border-color:var(--warn);border-style:dashed}
.node.s-not-observable{border-style:dashed;border-color:var(--mute);color:var(--mute)}
.node.s-not-walked{border-style:dotted;border-color:var(--mute);color:var(--mute)}
.node.s-not-walked>*{opacity:.5}
.node:focus-visible,button:focus-visible{outline:3px solid var(--evt);outline-offset:3px}
.node.sel{box-shadow:0 0 0 3px var(--evt)}
.node.hit{animation:hit .5s 1}
@keyframes hit{20%{transform:translateX(-5px)}40%{transform:translateX(5px)}
60%{transform:translateX(-3px)}80%{transform:translateX(3px)}}
.wires{display:none;position:absolute;left:0;top:0;width:100%;height:100%;pointer-events:none;overflow:visible}
.wires.over{z-index:2}
.wire{fill:none;stroke:var(--line);stroke-width:2}
.w-holds,.w-fails{stroke:var(--dim)}
.w-cannot-judge,.w-unrecognised{stroke:var(--warn);stroke-dasharray:7 5}
.w-not-observable{stroke:var(--mute);stroke-dasharray:3 6}
.w-not-walked{stroke:var(--mute);stroke-dasharray:1 7;opacity:.45}
#dot{display:none}
#dot circle{fill:var(--evt);stroke:var(--bg);stroke-width:2}
#dot path{display:none;fill:none;stroke-width:3;stroke-linecap:round}
#dot.after circle{fill:var(--bg);stroke:var(--bad);stroke-width:3}
#dot.ok circle{fill:var(--ok)}
#dot.fail circle{fill:var(--bg);stroke:var(--bad);stroke-width:3}#dot.fail .x{display:inline;stroke:var(--bad)}
#dot.halt circle{fill:var(--bg);stroke:var(--warn);stroke-width:3}#dot.halt .bar{display:inline;stroke:var(--warn)}
.controls{display:none;flex-wrap:wrap;gap:8px 10px;align-items:center}
button{font:inherit;color:var(--ink);background:var(--panel);border:1.5px solid var(--line);border-radius:4px;
padding:6px 12px;min-height:40px;cursor:pointer}
button:hover{border-color:var(--evt)}
#cap{flex:1 1 220px;font-weight:700;white-space:pre-wrap;overflow-wrap:anywhere}
.hop h2{white-space:pre-wrap;overflow-wrap:anywhere}
.hop .event{border-left:4px solid var(--line);padding-left:10px}
.hop.s-fails .event{border-color:var(--bad)}.hop.s-cannot-judge .event,
.hop.s-unrecognised .event{border-color:var(--warn)}
.hop.s-holds .event{border-color:var(--ok)}
.dec{margin:10px 0 0;display:grid;grid-template-columns:minmax(84px,max-content) 1fr;gap:4px 14px}
.dec dt{color:var(--dim)}.dec dd{margin:0;overflow-wrap:anywhere}
.finds{list-style:none;margin:0;padding:0}
.finds li{display:flex;flex-wrap:wrap;gap:2px 10px;padding:4px 0;border-top:1px solid var(--line)}
.finds .sev{font-weight:700;color:var(--bad)}
.legend{font-size:.9rem}.legend li{margin:2px 0}
.jsonly{display:none}
.js .wires{display:block}.js #dot.on{display:inline}.js .controls{display:flex}.js .jsonly{display:block}
.js .hop{display:none}.js .hop.sel{display:block}
@media (prefers-reduced-motion:reduce){.node.hit{animation:none}}
@media (max-width:480px){body{padding:14px 12px 40px}h1{font-size:1.35rem}.schem{padding:18px 10px 18px 28px}
.dec{grid-template-columns:1fr}.dec dt{margin-top:6px}}
@media print{.controls{display:none!important}.js .hop{display:block}body{background:none}}
"""

_JS = """
(function(){
"use strict";
var blob=document.getElementById("walk-data");if(!blob)return;
var hops;try{hops=JSON.parse(blob.textContent).view.hops;}catch(e){return;}
var n=hops.length;if(!n)return;
var root=document.documentElement,stage=document.getElementById("schem");
var nodes=stage.querySelectorAll(".node"),wires=stage.querySelectorAll(".wire");
var secs=document.querySelectorAll(".hop"),dot=document.getElementById("dot");
var cap=document.getElementById("cap"),play=document.getElementById("play");
if(nodes.length!==n||wires.length!==n||secs.length!==n)return;
root.classList.add("js");
var still=window.matchMedia?window.matchMedia("(prefers-reduced-motion: reduce)"):{matches:true};
var DRAWN={"holds":1,"fails":1,"cannot-judge":1};
var cur=-1,raf=0,timer=0,playing=false,wantMove=false,paths=[];
function box(e){return{l:e.offsetLeft,t:e.offsetTop,r:e.offsetLeft+e.offsetWidth,b:e.offsetTop+e.offsetHeight,
cx:e.offsetLeft+e.offsetWidth/2,cy:e.offsetTop+e.offsetHeight/2};}
function layout(){
paths=[];
for(var i=0;i<n;i++){
var c=box(nodes[i]),pts;
if(i===0){pts=[[c.l-22,c.cy],[c.l,c.cy]];}
else{var p=box(nodes[i-1]);
if(Math.abs(p.t-c.t)<4&&c.l>=p.r){pts=[[p.r,p.cy],[c.l,c.cy]];}
else{var mid=(p.b+c.t)/2;pts=[[p.cx,p.b],[p.cx,mid],[c.cx,mid],[c.cx,c.t]];}}
paths.push(pts);
wires[i].setAttribute("d","M"+pts.map(function(q){return q[0].toFixed(1)+" "+q[1].toFixed(1);}).join("L"));
}}
function at(pts,f){
var len=[],total=0,i;
for(i=1;i<pts.length;i++){var d=Math.abs(pts[i][0]-pts[i-1][0])+Math.abs(pts[i][1]-pts[i-1][1]);len.push(d);total+=d;}
var want=total*f;
for(i=0;i<len.length;i++){if(want<=len[i]||i===len.length-1){var k=len[i]?Math.min(1,want/len[i]):1;
return[pts[i][0]+(pts[i+1][0]-pts[i][0])*k,pts[i][1]+(pts[i+1][1]-pts[i][1])*k];}want-=len[i];}
return pts[pts.length-1];}
function put(q){dot.setAttribute("transform","translate("+q[0].toFixed(1)+" "+q[1].toFixed(1)+")");}
function brokenBefore(i){for(var k=0;k<i;k++){if(hops[k].state==="fails")return true;}return false;}
function settle(i){
var s=hops[i].state;
dot.setAttribute("class","on "+(s==="fails"?"fail":s==="cannot-judge"?"halt":brokenBefore(i)?"after":"ok"));
put(at(paths[i],s==="cannot-judge"?0.55:1));
if(s==="fails"&&!still.matches){nodes[i].classList.remove("hit");void nodes[i].offsetWidth;
nodes[i].classList.add("hit");}
}
function show(i,move){
if(raf){window.cancelAnimationFrame(raf);raf=0;}
cur=i;
for(var k=0;k<n;k++){
var on=k===i;nodes[k].classList.toggle("sel",on);secs[k].classList.toggle("sel",on);
if(on){nodes[k].setAttribute("aria-current","step");}else{nodes[k].removeAttribute("aria-current");}}
cap.textContent=hops[i].caption;
var s=hops[i].state;
if(!DRAWN[s]){dot.setAttribute("class","");return;}
if(!move||still.matches){settle(i);return;}
var end=s==="cannot-judge"?0.55:1,t0=0;
dot.setAttribute("class","on"+(brokenBefore(i)?" after":""));
put(at(paths[i],0));
function frame(t){if(!t0)t0=t;var f=Math.min(1,(t-t0)/900);put(at(paths[i],f*end));
if(f<1){raf=window.requestAnimationFrame(frame);}else{raf=0;settle(i);}}
raf=window.requestAnimationFrame(frame);
}
function fromHash(){var m=/^#step-(\\d+)$/.exec(window.location.hash);if(!m)return-1;var i=parseInt(m[1],10)-1;
return i>=0&&i<n?i:-1;}
function go(i,move){
if(i<0||i>=n)return;
var h="#step-"+(i+1);
if(window.location.hash===h){show(i,move);return;}
wantMove=move;
try{window.location.hash=h;}catch(e){wantMove=false;show(i,move);}
}
function stop(){playing=false;if(timer){window.clearTimeout(timer);timer=0;}
play.textContent="Play";play.setAttribute("aria-pressed","false");}
function canAdvance(){
if(cur>=n-1)return false;
var s=hops[cur].state;
if(s==="cannot-judge"||s==="unrecognised"||s==="not-walked")return false;
return hops[cur+1].state!=="not-walked";}
function tick(){timer=0;if(!playing)return;if(!canAdvance()){stop();return;}
go(cur+1,true);timer=window.setTimeout(tick,2200);}
function start(){playing=true;play.textContent="Pause";play.setAttribute("aria-pressed","true");
if(!canAdvance()){go(0,true);timer=window.setTimeout(tick,2200);}else{tick();}}
window.addEventListener("hashchange",function(){var i=fromHash();if(i<0)return;
var move=wantMove&&i===cur+1;wantMove=false;show(i,move);});
play.addEventListener("click",function(){if(playing){stop();}else{start();}});
document.getElementById("prev").addEventListener("click",function(){stop();go(cur-1,false);});
document.getElementById("next").addEventListener("click",function(){stop();go(cur+1,true);});
document.addEventListener("keydown",function(e){
if(e.defaultPrevented||e.altKey||e.ctrlKey||e.metaKey)return;
var tag=e.target&&e.target.tagName;
if(e.key==="ArrowLeft"){stop();go(cur-1,false);e.preventDefault();}
else if(e.key==="ArrowRight"){stop();go(cur+1,true);e.preventDefault();}
else if((e.key===" "||e.key==="Spacebar")&&tag!=="BUTTON"&&tag!=="A"){
if(playing){stop();}else{start();}e.preventDefault();}
});
window.addEventListener("resize",function(){layout();if(cur>=0)show(cur,false);});
layout();
var first=fromHash();
if(first<0){first=parseInt(stage.getAttribute("data-start"),10)-1;if(!(first>=0&&first<n))first=0;}
show(first,false);
})();
"""


def _code(value: str) -> str:
    """A value that came from the reader's manifests, set apart so it cannot blend into the page's own words."""
    return f'<code class="in">{_esc(value)}</code>'


def _list(values: list[str], *, from_input: bool) -> str:
    shown = values[:_MAX_LISTED]
    parts = [_code(v) if from_input else _esc(v) for v in shown]
    if len(values) > len(shown):
        parts.append(_esc(f"and {len(values) - len(shown)} more not listed here"))
    return ", ".join(parts)


def _node(h: dict[str, Any]) -> str:
    label = _code(h["label"]) if h["named"] else _esc(h["label"])
    if h["named"]:
        sub = "object in your manifests"
    elif h["kinds"]:
        sub = "kind; the walk names no object here"
    else:
        sub = "no manifest object"
    return (
        f'<li><a class="node s-{h["state"]}" href="#step-{h["n"]}">'
        f'<span class="num">{h["n"]:02d}</span> <span class="chip">{_esc(h["mark"])}</span>'
        f'<span class="lab">{label}</span><span class="sub">{_esc(sub)}</span></a></li>'
    )


def _section(h: dict[str, Any]) -> str:
    rows: list[str] = [f'<dt>verdict</dt><dd><span class="chip s-{h["state"]}">{_esc(h["mark"])}</span></dd>']
    rows.append(f"<dt>hop</dt><dd>{_esc(h['id'])}</dd>")
    if h["rules"]:
        word = "rules it would rest on" if h["state"] == NOT_WALKED else "rules"
        rows.append(f"<dt>{word}</dt><dd>{_list(h['rules'], from_input=False)}</dd>")
    else:
        rows.append("<dt>rules</dt><dd>none: no rule in this build reads this hop</dd>")
    if h["objects"]:
        rows.append(f"<dt>objects</dt><dd>{_list(h['objects'], from_input=True)}</dd>")
    else:
        rows.append("<dt>objects</dt><dd>none named by the walk</dd>")
    if h["findings"]:
        items = "".join(
            f'<li><span class="sev">{_esc(f["severity"].upper())}</span><span>{_esc(f["ruleId"])}</span>'
            f"{_code(f['resource'])}<span>{_esc(f['title'])}</span></li>"
            for f in h["findings"][:_MAX_LISTED]
        )
        if len(h["findings"]) > _MAX_LISTED:
            more = len(h["findings"]) - _MAX_LISTED
            items += f"<li>{_esc(f'and {more} more findings not listed here')}</li>"
        rows.append(f'<dt>findings</dt><dd><ul class="finds">{items}</ul></dd>')
    elif h["state"] == HOLDS:
        rows.append("<dt>findings</dt><dd>none from the rules above</dd>")
    else:
        rows.append(
            "<dt>findings</dt><dd>none reported; that is not a pass for this hop</dd>"
            if h["state"] != FAILS
            else "<dt>findings</dt><dd>not listed in the walk</dd>"
        )
    return (
        f'<section class="panel hop s-{h["state"]}" id="step-{h["n"]}">'
        f"<h2>{_esc(h['caption'])}</h2>"
        f'<p class="prose"><strong>{_esc(h["title"])}.</strong> {_esc(h["why"])}</p>'
        f'<p class="prose event">{_esc(h["event"])}</p>'
        f'<dl class="dec">{"".join(rows)}</dl></section>'
    )


def render_html(walked: dict[str, Any], lesson: dict[str, Any] | None = None) -> str:
    """The walk as one self-contained HTML document. `lesson` names the hops after a stop; without it they are
    drawn as numbered placeholders, and either way each is labelled "not walked"."""
    v = view(walked, lesson)
    hops = v["hops"]
    counts = v["counts"]
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
        "<main>",
        "<header>",
        f"<h1>{_esc(v['title'])}</h1>",
        f'<p class="dim">kube-noob learn mechanism {_esc(v["lesson"])}'
        + (f" ({_esc(v['layer'])} layer)" if v["layer"] else "")
        + ", walked against your own manifests, one hop at a time</p>",
        "</header>",
        f'<section class="panel t-{v["tone"]}" aria-label="Path verdict">',
        '<div class="verdict">',
        f'<span class="word">Path verdict: {_esc(v["verdictWord"])}</span>',
        f"<span>exit code {_esc(v['exitCode'])} ({_esc(v['exitMeans'])})</span>",
        "</div>",
        f'<p class="prose">{_esc(v["reason"])}</p>',
        '<dl class="counts">',
        f"<div><dt>hops declared</dt><dd>{_esc(counts['declared'])}</dd></div>",
        f"<div><dt>judged</dt><dd>{_esc(counts['judged'])}</dd></div>",
        f"<div><dt>not observable</dt><dd>{_esc(counts['notObservable'])}</dd></div>",
        f"<div><dt>not walked</dt><dd>{_esc(counts['notReached'])}</dd></div>",
        "</dl>",
        "</section>",
    ]
    if hops:
        out += [
            f'<section class="panel schem" id="schem" data-start="{int(v["start"])}" aria-label="The path">',
            '<svg class="wires" aria-hidden="true" focusable="false">',
            *[f'<path class="wire w-{h["state"]}" d=""></path>' for h in hops],
            "</svg>",
            '<ol class="nodes">',
            *[_node(h) for h in hops],
            "</ol>",
            # The event is drawn in a layer of its own ABOVE the components, so it is not hidden when it arrives.
            '<svg class="wires over" aria-hidden="true" focusable="false">',
            '<g id="dot"><circle r="7"></circle><path class="x" d="M-3.5 -3.5L3.5 3.5M3.5 -3.5L-3.5 3.5"></path>'
            '<path class="bar" d="M-3.5 0H3.5"></path></g>',
            "</svg>",
            "</section>",
        ]
        if v["hiddenHops"]:
            out.append(
                f'<p class="panel">{_esc(v["hiddenHops"])} more hop(s) were not walked and are not drawn here. '
                "They are not reported as working.</p>"
            )
        out += [
            '<div class="panel controls" role="group" aria-label="Step through the walk">',
            '<button type="button" id="prev">Previous hop</button>',
            '<button type="button" id="play" aria-pressed="false">Play</button>',
            '<button type="button" id="next">Next hop</button>',
            '<output id="cap" aria-live="polite"></output>',
            "</div>",
            *[_section(h) for h in hops],
        ]
    else:
        out.append(
            '<p class="panel">This walk lists no hops, so there is nothing to draw and nothing is shown as working.</p>'
        )
    out += [
        '<section class="panel legend" aria-label="How to read this page">',
        "<h2>How to read this page</h2>",
        "<ul>",
        '<li><span class="chip s-holds">holds</span> a rule read this hop and found nothing wrong.</li>',
        '<li><span class="chip s-fails">BROKEN</span> a rule on this hop produced a finding. The walk carries on.</li>',
        '<li><span class="chip s-cannot-judge">cannot judge</span> nothing could answer for this hop. The walk stops '
        "here.</li>",
        '<li><span class="chip s-not-observable">not observable</span> no manifest can show this hop. It is never '
        "counted as passing.</li>",
        '<li><span class="chip s-not-walked">not walked</span> the walk stopped before this hop. It is never reported '
        "as working.</li>",
        '<li><code class="in">shaded text</code> came from your manifests; everything else is kube-noob speaking.</li>',
        '<li class="jsonly">Left and right arrow keys step through the hops, space plays or pauses, and the address '
        "ends in #step-N so a hop can be linked.</li>",
        "</ul>",
        "</section>",
        "</main>",
        f'<script type="application/json" id="walk-data">{_json({"view": v, "walk": walked})}</script>',
        f"<script>{_JS}</script>",
        "</body>",
        "</html>",
    ]
    return "\n".join(out) + "\n"
