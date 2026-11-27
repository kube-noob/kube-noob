"""The stylesheet, the icons and the script of the mechanism walk's player page.

The player's look and behaviour are a port of KubeLearn's lesson player (kubelearn.joesabbagh.com), Copyright (c)
2026 Joe Sabbagh, MIT License; the notice is reproduced in ``THIRD_PARTY_NOTICES.md``. From ``src/index.css``:
the dark and light tokens, the shell (header, stage, 360px story column, events drawer), `.btn`, `.ibtn`, `.seg`,
the isometric faces, the caption strip, the transport bar, the step list, the facts table and the sequence
diagram's lines. From ``src/components/Icon.tsx``: the icon paths. From ``src/components/Stage.tsx`` and
``src/playback.ts``: a marker (dot and chip) that flies the route with a trail behind it, pulse rings when an
event stays on one actor, dimming of what is out of focus, the camera easing to the box that frames the focus,
and the flight timing (0.2 px/ms, between 0.8 and 3 s). The time a caption is left up is shorter per word than
KubeLearn's, because a hop's caption here is a longer sentence than one of its events.

What is kube-noob's own, and why it differs: there are no web fonts (the page fetches nothing, so the stacks are
the system's); no green is used for a kind of object, because on this page green means one thing -- a rule read
the hop and it holds; and a hop no rule judged is never animated as passing. The marker is drawn only for a hop a
rule read (`DRAWN`), stops short of a hop that could not be judged, and auto-play never advances into a hop that
was not walked.

Everything here is a constant this package wrote. No string from a walk is formatted into the stylesheet or the
script: the script reads the walk from the JSON element and puts text on the page with `textContent` only.
"""

from __future__ import annotations

_DARK = """color-scheme:dark;--bg:#080d1b;--panel:#0c1326;--raised:#121b35;--line:#1f2d55;--line-strong:#2f4378;
--grid:rgba(120,150,230,.07);--text:#d6e0f7;--dim:#98a6c8;--faint:#5f6d92;--accent:#326ce5;--accent-text:#7ea6ff;
--accent-soft:rgba(50,108,229,.18);--on-accent:#fff;--l-api:#6ea8ff;--l-state:#2dd4bf;--l-control:#f5b83d;
--l-node:#a78bfa;--l-scale:#f0abfc;--l-drop:#f87171;--ok:#3ccf8e;--iso-top:#1b2b52;--iso-left:#142245;
--iso-right:#0f1a38;--iso-line:#79a0ff;--iso-detail:#a9c2ff;--display:#0a1633;--iso-hot-top:#26478f;
--iso-hot-left:#1c3878;--iso-hot-right:#152d63;--link:#2a3f72;--floor:rgba(121,160,255,.035);--floor-edge:#0c1326;
--iso-other-top:#232a3c;--iso-other-left:#1b2131;--iso-other-right:#161b29;--iso-other-line:#56607a;
--shadow:0 18px 50px rgba(0,0,0,.5)"""

_LIGHT = """color-scheme:light;--bg:#f3f6fc;--panel:#fff;--raised:#eef2fa;--line:#d3dcee;--line-strong:#b3c2e1;
--grid:rgba(50,90,170,.08);--text:#14203c;--dim:#4f5d7d;--faint:#8391ad;--accent:#326ce5;--accent-text:#2556c4;
--accent-soft:rgba(50,108,229,.11);--on-accent:#fff;--l-api:#2563d9;--l-state:#0b7d71;--l-control:#955500;
--l-node:#6a45d6;--l-scale:#a21caf;--l-drop:#c62f2f;--ok:#15803d;--iso-top:#fff;--iso-left:#e8eefb;
--iso-right:#d9e3f7;--iso-line:#2f5fd0;--iso-detail:#2f5fd0;--display:#e3ebfb;--iso-hot-top:#e1eaff;
--iso-hot-left:#cfdcfc;--iso-hot-right:#bccff8;--link:#b3c2e1;--floor:rgba(47,95,208,.035);--floor-edge:#e6ecf8;
--iso-other-top:#f3f4f7;--iso-other-left:#e6e8ee;--iso-other-right:#d9dce5;--iso-other-line:#98a2b8;
--shadow:0 18px 50px rgba(20,32,60,.18)"""

# Light is the base, dark follows the system unless the reader chose light, and a choice wins either way.
CSS = (
    """
:root{--sans:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
--mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,"Liberation Mono",monospace;
--header-h:52px;--story-w:360px;--radius:6px}
:root{"""
    + _LIGHT
    + """}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){"""
    + _DARK
    + """}}
:root[data-theme="dark"]{"""
    + _DARK
    + """}
*{box-sizing:border-box}
[hidden]{display:none!important}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.55 var(--sans);-webkit-font-smoothing:antialiased}
h1,h2,p,dl,dd,ol,ul{margin:0;padding:0}
ol,ul{list-style:none}
button{font:inherit;color:inherit;cursor:pointer;background:none;border:0;padding:0}
a{color:inherit}
code,kbd{font-family:var(--mono)}
code.in{font-size:.92em;background:var(--raised);border:1px solid var(--line);border-radius:4px;padding:0 4px;
overflow-wrap:anywhere}
kbd{font-size:11px;font-weight:500;padding:0 5px;border:1px solid var(--line-strong);border-radius:4px;
color:var(--dim);background:var(--raised);white-space:nowrap;line-height:18px}
.ico{width:16px;height:16px;fill:none;stroke:currentColor;stroke-width:1.7;stroke-linecap:round;
stroke-linejoin:round;flex:none}
.ico .fill{fill:currentColor}
:focus-visible{outline:2px solid var(--accent-text);outline-offset:2px}
.kicker{font-family:var(--mono);font-size:11px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;
color:var(--accent-text)}
.btn{height:32px;padding:0 14px;border:1px solid var(--line-strong);background:var(--raised);
border-radius:var(--radius);font-size:13px;font-weight:600;display:inline-flex;align-items:center;
justify-content:center;gap:8px;white-space:nowrap;text-decoration:none}
.btn:hover{border-color:var(--accent-text)}
.btn.primary{background:var(--accent);border-color:var(--accent);color:var(--on-accent)}
.ibtn{width:32px;height:32px;border:1px solid var(--line-strong);border-radius:var(--radius);display:inline-flex;
align-items:center;justify-content:center;gap:4px;color:var(--dim);background:var(--panel);flex:none}
.ibtn:hover{color:var(--text);border-color:var(--accent-text)}
.ibtn:disabled{opacity:.4;cursor:default}
.ibtn.ghost{border-color:transparent;background:transparent}
.ibtn.ghost:hover{border-color:transparent;background:var(--raised)}
.ibtn[aria-pressed="true"]{color:var(--accent-text);background:var(--accent-soft)}
.link-btn{display:inline-flex;align-items:center;gap:4px;min-height:24px;font-size:12.5px;color:var(--dim);
padding:2px 6px;border-radius:4px;text-decoration:none}
.link-btn:hover{color:var(--text);background:var(--raised)}
.seg{display:inline-flex;border:1px solid var(--line-strong);border-radius:8px;padding:2px;gap:2px;
background:var(--panel)}
.seg button{height:28px;padding:0 10px;border-radius:6px;font-size:12.5px;font-weight:600;color:var(--dim);
display:inline-flex;align-items:center;justify-content:center;gap:6px}
.seg button:hover{color:var(--text)}
.seg button[aria-pressed="true"]{color:var(--on-accent);background:var(--accent)}
.jsonly,.transport,.caption{display:none}
.js .jsonly,.js .transport{display:flex}
.js .caption:not([hidden]){display:block}

.shell{height:100vh;height:100dvh;display:flex;flex-direction:column}
.topbar{height:var(--header-h);flex:none;display:flex;align-items:center;gap:6px;padding:0 12px 0 16px;
border-bottom:1px solid var(--line)}
.brand{display:flex;align-items:center;gap:8px;flex:none}
.brand-mark{width:26px;height:26px}
.wordmark{font-size:14px;font-weight:600;letter-spacing:-.01em;white-space:nowrap}
.wordmark .k{font-weight:700;color:var(--accent-text)}
.topbar-sep{color:var(--faint);margin:0 2px}
.crumb{height:34px;padding:0 8px;display:inline-flex;align-items:center;gap:8px;font-size:14px;font-weight:600;
color:var(--dim);flex:none}
.crumb-here{font-size:14px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;min-width:0}
.tools{margin-left:auto;align-items:center;gap:2px;flex:none}
:root[data-theme="dark"] .i-moon,:root[data-theme="light"] .i-sun{display:none}
.workspace{flex:1;min-height:0;display:grid;grid-template-columns:minmax(0,1fr) var(--story-w);
grid-template-rows:minmax(0,1fr) auto;grid-template-areas:"stage story" "flow flow"}

.stage{grid-area:stage;position:relative;min-width:0;min-height:0;display:flex;flex-direction:column;overflow:hidden}
.canvas{flex:1;min-height:0;position:relative;
background:radial-gradient(115% 85% at 50% 28%,color-mix(in srgb,var(--panel) 60%,var(--bg)) 0%,var(--bg) 68%)}
.stage-tools{position:absolute;top:12px;left:12px;right:12px;z-index:2;align-items:center;gap:12px;flex-wrap:wrap}
.transport{position:absolute;left:50%;bottom:16px;transform:translateX(-50%);z-index:2;gap:6px;align-items:center;
padding:6px;border:1px solid var(--line-strong);border-radius:14px;
background:color-mix(in srgb,var(--panel) 90%,transparent);box-shadow:var(--shadow)}
.transport .ibtn{width:36px;height:36px;border-color:transparent;background:transparent}
.transport .ibtn:hover:not(:disabled){background:var(--raised);color:var(--text)}
.transport .ibtn[aria-pressed="true"]{color:var(--accent-text);background:var(--accent-soft)}
.transport .speed{width:auto;min-width:36px;padding:0 8px;font-family:var(--mono);font-size:11px;font-weight:600}
.play{min-width:142px;height:36px;border-radius:9px}
.scene{position:absolute;inset:0;width:100%;height:100%}
.stage[data-view="sequence"] .scene,.stage[data-view="sequence"] .zoom-ui{display:none}
.sequence{display:none;position:absolute;inset:56px 0 0;overflow:auto;padding-bottom:150px;
border-top:1px solid var(--line)}
.stage[data-view="sequence"] .sequence{display:block}

.floor .floor-top{fill:var(--floor);stroke:var(--line-strong);stroke-width:1}
.floor .floor-edge{fill:var(--floor-edge);stroke:var(--line-strong);stroke-width:1}
.iso .floor-grid{stroke:var(--grid);stroke-width:1;fill:none}
.floor-name{fill:var(--faint);font-family:var(--mono);font-weight:500}
.iso polygon,.iso path,.iso ellipse{stroke:var(--iso-line);stroke-width:1.15;stroke-linejoin:round}
.f-t{fill:var(--iso-top)}.f-l{fill:var(--iso-left)}.f-r{fill:var(--iso-right)}
.hot .f-t{fill:var(--iso-hot-top)}.hot .f-l{fill:var(--iso-hot-left)}.hot .f-r{fill:var(--iso-hot-right)}
.glass polygon{fill-opacity:.16}
.hid{stroke:var(--iso-line);stroke-width:1;stroke-dasharray:2 3;opacity:.55}
.det{stroke:var(--iso-detail);stroke-width:1;vector-effect:non-scaling-stroke;opacity:.75;fill:none}
.led{fill:var(--iso-detail)}.led.b{fill:var(--accent-text)}
.display-r{fill:var(--display);stroke:var(--iso-line);stroke-width:.8;vector-effect:non-scaling-stroke}
.scr{fill:var(--iso-detail);font-family:var(--mono);font-weight:700}.scr.d{font-weight:500}
.iso .bar,.iso .cell{fill:none;stroke:var(--iso-detail);stroke-width:.8;vector-effect:non-scaling-stroke;opacity:.75}
.keys rect{fill:none;stroke:var(--iso-detail);stroke-width:.7;vector-effect:non-scaling-stroke;opacity:.65}
.topt{fill:var(--iso-detail);font-family:var(--mono);font-weight:800}
.iso .arrows path{fill:none;stroke:var(--iso-detail);stroke-width:1.5;vector-effect:non-scaling-stroke;
stroke-linecap:round}
.iso .slot-other polygon{stroke:var(--iso-other-line)}
.iso .slot-other .f-t{fill:var(--iso-other-top)}.iso .slot-other .f-l{fill:var(--iso-other-left)}
.iso .slot-other .f-r{fill:var(--iso-other-right)}
.iso .slot-v1 polygon{stroke:var(--accent-text)}
.iso .slot-v1 .f-t{fill:var(--iso-hot-top)}.iso .slot-v1 .f-l{fill:var(--iso-hot-left)}
.iso .slot-v1 .f-r{fill:var(--iso-hot-right)}

.actor{--rk:var(--iso-line);transition:opacity .35s}
.actor[data-dim]{opacity:.38}
.res{--rk:var(--l-api)}
.tone-node{--rk:var(--l-node)}.tone-state{--rk:var(--l-state)}.tone-scale,.tone-rbac{--rk:var(--l-scale)}
.actor[data-v="holds"]{--rk:var(--ok)}
.actor[data-v="fails"]{--rk:var(--l-drop)}
.actor[data-v="cannot-judge"],.actor[data-v="unrecognised"]{--rk:var(--l-control)}
.actor[data-v="not-observable"],.actor[data-v="not-walked"]{--rk:var(--dim)}
.res .f-t{fill:color-mix(in srgb,var(--rk) 20%,var(--iso-top))}
.res .f-l{fill:color-mix(in srgb,var(--rk) 14%,var(--iso-left))}
.res .f-r{fill:color-mix(in srgb,var(--rk) 14%,var(--iso-right))}
.res .sheet .f-t{fill:color-mix(in srgb,var(--rk) 34%,var(--iso-top))}
.res .sheet .f-l{fill:color-mix(in srgb,var(--rk) 24%,var(--iso-left))}
.res .sheet .f-r{fill:color-mix(in srgb,var(--rk) 24%,var(--iso-right))}
.res polygon{stroke:color-mix(in srgb,var(--rk) 65%,var(--iso-line))}
.res .topt{fill:color-mix(in srgb,var(--rk) 75%,var(--text))}
.actor[data-v="fails"] polygon{stroke:var(--l-drop);stroke-width:1.6}
.actor[data-v="cannot-judge"] polygon,.actor[data-v="unrecognised"] polygon{stroke:var(--l-control);
stroke-dasharray:6 3}
.actor[data-manifest="no"] polygon,.actor[data-manifest="no"] path,.actor[data-manifest="no"] ellipse,
.actor[data-manifest="no"] rect{stroke-dasharray:4 3}
.actor[data-v="not-walked"]{opacity:.5}
.actor[data-v="not-walked"] polygon{stroke-dasharray:1 4}
.alabel text{paint-order:stroke;stroke:var(--bg);stroke-width:4px;stroke-linejoin:round}
.alabel .n{fill:var(--text);font-family:var(--sans);font-weight:600;font-size:13.5px}
.alabel .ip{fill:var(--dim);font-family:var(--mono);font-size:11.5px}
.alabel .st{fill:var(--dim);font-family:var(--mono);font-size:11.5px;font-weight:700}
.actor[data-on] .alabel .n{fill:var(--accent-text)}
.actor[data-v="holds"] .st{fill:var(--ok)}.actor[data-v="fails"] .st{fill:var(--l-drop)}
.actor[data-v="cannot-judge"] .st,.actor[data-v="unrecognised"] .st{fill:var(--l-control)}
.iso .cable{fill:none;stroke:var(--link);stroke-width:1.5;stroke-linecap:round;transition:stroke .3s}
.iso .cable[data-on]{stroke:color-mix(in srgb,var(--accent-text) 55%,var(--link))}
.iso .c-not-observable,.iso .c-cannot-judge,.iso .c-unrecognised{stroke-dasharray:6 5}
.iso .c-not-walked{stroke-dasharray:1 6;opacity:.6}
.iso .trail{display:none;fill:none;stroke:var(--accent-text);stroke-width:2.2;stroke-linecap:round;
stroke-dasharray:1 1;stroke-dashoffset:1}
.iso .trail.on{display:inline}
.iso .trail.t-holds{stroke:var(--ok)}.iso .trail.t-fails{stroke:var(--l-drop)}
.iso .trail.t-cannot-judge{stroke:var(--l-control)}
#dot{display:none;--c:var(--accent-text)}
#dot.on{display:inline}
#dot.ok{--c:var(--ok)}#dot.fail{--c:var(--l-drop)}#dot.halt{--c:var(--l-control)}
#dot .core{fill:var(--c);stroke:var(--bg);stroke-width:2}
#dot.fail .core,#dot.halt .core{fill:var(--bg);stroke:var(--c);stroke-width:2.5}
#dot.after .core{fill:var(--bg);stroke:var(--l-drop);stroke-width:2.5}
#dot .x,#dot .bar,#dot .ring{display:none;fill:none;stroke:var(--c);stroke-width:2.5;stroke-linecap:round}
#dot.fail .x,#dot.halt .bar{display:inline}
#dot.pulse .ring{display:inline;stroke-width:2;opacity:0;transform-box:fill-box;transform-origin:center;
animation:ring 1.5s ease-out infinite}
#dot.pulse .ring.r2{animation-delay:.75s}
@keyframes ring{from{opacity:.9;transform:scale(.4)}to{opacity:0;transform:scale(1.6)}}
#dot .mchip rect{fill:var(--panel);stroke:var(--c);stroke-width:1}
#dot .mchip text{fill:var(--c);font-family:var(--sans);font-size:12px;font-weight:500}

.s-holds{--c:var(--ok)}.s-fails{--c:var(--l-drop)}.s-cannot-judge,.s-unrecognised{--c:var(--l-control)}
.s-not-observable,.s-not-walked{--c:var(--dim)}
.chip{display:inline-block;padding:0 7px;border:1.5px solid var(--c);border-radius:4px;color:var(--c);
font-family:var(--mono);font-size:11px;font-weight:700;line-height:18px;white-space:nowrap;vertical-align:middle}
.s-cannot-judge .chip,.s-cannot-judge.chip,.s-unrecognised .chip,.s-unrecognised.chip,.s-not-observable .chip,
.s-not-observable.chip,.s-not-walked .chip,.s-not-walked.chip{border-style:dashed}
.caption{position:absolute;left:50%;bottom:70px;width:min(680px,calc(100% - 120px));padding:12px 12px 12px 14px;
border:1px solid var(--line-strong);border-radius:10px;background:color-mix(in srgb,var(--panel) 94%,transparent);
font-size:14px;line-height:1.5;transform:translate(-50%,0);z-index:1}
.caption-in{display:flex;gap:12px;align-items:flex-start}
.caption em{display:block;font-style:normal;font-family:var(--mono);font-size:11.5px;color:var(--dim);
white-space:pre-wrap;overflow-wrap:anywhere}
.caption output{display:block;overflow-wrap:anywhere}
.badge{display:inline-flex;min-width:20px;height:20px;padding:0 4px;border-radius:10px;align-items:center;
justify-content:center;font-family:var(--mono);font-size:10px;font-weight:700;background:var(--c);
color:var(--bg);flex:none;margin-top:2px}
.caption-next{margin:-5px 0 -5px auto;align-self:center;flex:none;width:30px;height:30px;display:inline-flex;
align-items:center;justify-content:center;border-radius:50%;background:var(--accent-soft);color:var(--accent-text)}
.caption-next:hover{background:var(--accent);color:var(--on-accent)}
.zoom-ui{position:absolute;right:12px;bottom:14px;flex-direction:column;gap:4px;z-index:2}
.zoom-ui .ibtn{width:30px;height:30px;background:color-mix(in srgb,var(--panel) 90%,transparent)}

.story{grid-area:story;min-height:0;overflow-y:auto;border-left:1px solid var(--line);display:flex;
flex-direction:column}
.story-body{padding:24px 24px 8px}
.panel{scroll-margin-top:24px}
.panel+.panel{margin-top:28px;padding-top:24px;border-top:1px solid var(--line)}
.js .panel{margin-top:0;padding-top:0;border-top:0}
.js #overview{display:none}.js #overview.sel{display:block}
.js .hop{display:none}.js .hop.sel{display:block}
.t-ok{--c:var(--ok)}.t-bad{--c:var(--l-drop)}.t-warn{--c:var(--l-control)}
#overview>.kicker{border-left:2px solid var(--c);padding-left:10px;letter-spacing:.12em;color:var(--dim)}
.t-warn>.kicker{border-left-style:dashed}
.word{color:var(--c)}
.kicker-row{display:flex;align-items:center;gap:10px}
.dots{display:inline-flex;gap:3px;flex-wrap:wrap}
.dots i{width:5px;height:5px;border-radius:50%;background:var(--line-strong)}
.dots i.on{background:var(--accent-text)}
.kicker-row .link-btn{margin-left:auto;margin-right:-6px}
.display{font-size:22px;font-weight:700;letter-spacing:-.02em;line-height:1.25;margin-top:8px;overflow-wrap:anywhere}
.sub{color:var(--dim);font-size:13.5px;margin:6px 0 14px;overflow-wrap:anywhere}
.route{font-family:var(--mono);font-size:12px;white-space:pre-wrap}
.body{line-height:1.7;font-size:14px;overflow-wrap:anywhere}
.event{margin-top:12px;padding-left:10px;border-left:2px solid var(--c);color:var(--dim)}
.s-cannot-judge .event,.s-unrecognised .event,.s-not-observable .event,.s-not-walked .event{border-left-style:dashed}
.facts{margin-top:18px}
.facts>div{display:grid;grid-template-columns:96px 1fr;gap:12px;padding:10px 0;border-top:1px solid var(--line)}
.facts dt{color:var(--dim);font-family:var(--mono);font-size:10.5px;font-weight:600;letter-spacing:.07em;
text-transform:uppercase;padding-top:3px}
.facts dd{font-family:var(--mono);font-size:12.5px;line-height:1.65;overflow-wrap:anywhere;min-width:0}
.finds li{padding:4px 0}.finds li+li{border-top:1px dashed var(--line)}
.finds .sev{font-weight:700;color:var(--l-drop);margin-right:6px}
.start{margin-top:22px;width:100%;height:40px;font-size:13.5px}
.jump{display:inline-block;margin-top:10px;font-size:13px;color:var(--accent-text)}
.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px;margin-top:18px}
.stats div{display:flex;flex-direction:column-reverse}
.stats dd{font-family:var(--mono);font-size:17px;font-weight:600;font-variant-numeric:tabular-nums;
overflow-wrap:anywhere}
.stats dt{font-size:12px;color:var(--dim)}
.toc{margin-top:auto;padding:16px 24px 8px}
.toc-list{border-top:1px solid var(--line)}
.node{position:relative;display:flex;align-items:flex-start;gap:8px;min-height:44px;padding:10px 0;
border-bottom:1px solid var(--line);font-size:14px;line-height:1.45;color:var(--dim);text-decoration:none}
.node:hover,.node.sel{color:var(--text)}
.node.sel{font-weight:500}
.node::after{content:"";position:absolute;left:0;right:0;bottom:-1px;height:1px;background:var(--accent-text);
transform:scaleX(0);transform-origin:0 50%;transition:transform .3s}
.node:hover::after,.node.sel::after{transform:scaleX(1)}
.num{width:16px;font-family:var(--mono);font-size:12px;font-variant-numeric:tabular-nums;flex:none;padding-top:1px}
.glyph{width:16px;flex:none;text-align:center;font-weight:700;color:var(--c)}
.glyph.hollow::before{content:"";display:inline-block;width:10px;height:10px;border:1.5px dashed var(--c);
border-radius:50%}
.s-not-walked .glyph.hollow::before{border-style:dotted;opacity:.7}
.lab{min-width:0;overflow-wrap:anywhere}
.lab .chip{margin-left:6px}
.note{display:block;font-size:12px;color:var(--dim)}
.s-not-walked .toc-title{opacity:.75}
.more{padding:10px 0;color:var(--dim);font-size:13px}
.legend{padding:8px 24px 8px;font-size:13px;color:var(--dim)}
.legend summary{width:fit-content;min-height:24px;padding:4px 0;cursor:pointer}
.legend summary:hover{color:var(--text)}
.legend li{margin:8px 0}
.credit{padding:8px 24px 24px;font-size:12px;color:var(--dim)}

.flow{grid-area:flow;min-width:0;border-top:1px solid var(--line);position:relative}
.flow summary{list-style:none;height:42px;display:flex;align-items:center;gap:8px;padding:0 14px 0 12px;
font-size:13px;font-weight:600;color:var(--dim);cursor:pointer}
.flow summary::-webkit-details-marker{display:none}
.flow summary:hover,.flow[open] summary{color:var(--text)}
.flow-chevron{transition:transform .15s}
.flow[open] .flow-chevron{transform:rotate(90deg)}
.count{font-family:var(--mono);font-size:11px;font-weight:600;color:var(--dim);background:var(--raised);
border:1px solid var(--line);border-radius:99px;padding:1px 8px;font-variant-numeric:tabular-nums}
.progress{position:absolute;left:0;right:0;top:-1px;height:2px;pointer-events:none}
.progress i{display:block;height:100%;width:100%;background:var(--accent);transition:width .3s}
.flow-panel{max-height:320px;overflow:auto;border-top:1px solid var(--line)}
.etable{width:100%;min-width:680px;border-collapse:collapse;font-family:var(--mono);font-size:12px}
.etable th{position:sticky;top:0;background:var(--bg);text-align:left;font-family:var(--sans);font-size:11px;
font-weight:600;letter-spacing:.07em;text-transform:uppercase;color:var(--dim);padding:7px 10px}
.etable td{padding:6px 10px;border-top:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere}
.etable .sev{font-weight:700;color:var(--c);white-space:nowrap}
.etable tr.cur td{background:var(--accent-soft)}
.empty-row{padding:14px;color:var(--dim)}

.seq-body{display:block;font-family:var(--mono)}
.seq-lane{fill:var(--text);font-size:11px;font-weight:700;letter-spacing:.03em}
.lifeline{stroke:var(--line-strong);stroke-dasharray:3 4}
.seq-hit{fill:transparent}
.seq-row.cur .seq-hit{fill:var(--accent-soft)}
.seq-row.later{opacity:.35}
.seq-time{fill:var(--dim);font-size:10.5px}
.seq-arrow{stroke:var(--c);stroke-width:1.6;fill:none}
.seq-head{fill:var(--c)}
.s-not-observable .seq-arrow,.s-not-walked .seq-arrow,.s-cannot-judge .seq-arrow,
.s-unrecognised .seq-arrow{stroke-dasharray:4 4}
.s-not-observable .seq-head,.s-not-walked .seq-head{fill:none;stroke:var(--c)}
.seq-label{fill:var(--c);font-size:11px;font-weight:600}

dialog{width:min(420px,calc(100vw - 32px));background:var(--panel);color:var(--text);
border:1px solid var(--line-strong);border-radius:12px;box-shadow:var(--shadow);padding:0}
dialog::backdrop{background:rgba(4,8,20,.55)}
.dialog-head{display:flex;justify-content:space-between;align-items:center;padding:10px 10px 10px 16px;
border-bottom:1px solid var(--line)}
.dialog-title{font-size:15px;font-weight:600}
.shortcut-list{padding:6px 16px 10px}
.shortcut-list div{display:grid;grid-template-columns:110px 1fr;padding:7px 0;border-bottom:1px solid var(--line);
align-items:center;font-size:13px}
.shortcut-list div:last-child{border-bottom:0}

@media (max-width:1100px){:root{--story-w:320px}}
@media (max-width:900px){.shell{height:auto}
.workspace{grid-template-columns:minmax(0,1fr);grid-template-rows:none;grid-template-areas:"stage" "story" "flow"}
.stage .canvas{flex:none;height:max(420px,64vh)}
.story{border-left:0;border-top:1px solid var(--line);overflow:visible}
.toc{margin-top:8px}
.caption{width:calc(100% - 24px);bottom:64px;font-size:13px}
.js .zoom-ui{display:none}}
@media (max-width:600px){.wordmark,.brand+.topbar-sep,.crumb,.crumb+.topbar-sep{display:none}}
@media (max-width:480px){.story-body{padding:20px 16px 8px}.toc,.legend,.credit{padding-left:16px;padding-right:16px}
.facts>div{grid-template-columns:1fr;gap:2px}.stats{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media (prefers-reduced-motion:reduce){*,*::before,*::after{animation:none!important;transition:none!important}}
@media print{.transport,.caption,.stage-tools,.zoom-ui,.tools{display:none!important}.shell{height:auto}
.workspace{display:block}.stage .canvas{height:420px}.story{overflow:visible;border-left:0}
.js .hop,.js #overview{display:block}.flow-panel{max-height:none}}
"""
)

#: Icon paths, from KubeLearn's Icon.tsx. Drawn on a 24 x 24 grid, stroked in the current colour.
ICONS = {
    "sun": '<circle cx="12" cy="12" r="4"/><path d="M12 2.5v2M12 19.5v2M2.5 12h2M19.5 12h2M5.3 5.3l1.4 1.4'
    'M17.3 17.3l1.4 1.4M5.3 18.7l1.4-1.4M17.3 6.7l1.4-1.4"/>',
    "moon": '<path d="M20 14.5A8 8 0 1 1 9.5 4a6.5 6.5 0 0 0 10.5 10.5Z"/>',
    "keys": '<rect x="2.5" y="6" width="19" height="12" rx="1.5"/><path d="M6 10h.01M9.5 10h.01M13 10h.01'
    'M16.5 10h.01M8 14h8"/>',
    "play": '<path class="fill" d="M7 5v14l11-7z"/>',
    "back": '<path d="m14.5 6-6 6 6 6"/>',
    "right": '<path d="m9.5 6 6 6-6 6"/>',
    "replay": '<path d="M4.5 12a7.5 7.5 0 1 0 2.2-5.3"/><path d="M4.5 4.5v4h4"/>',
    "close": '<path d="M6 6l12 12M18 6 6 18"/>',
    "layers": '<path d="m12 4 8.5 4.5L12 13 3.5 8.5Zm-8.5 8L12 16.5l8.5-4.5M3.5 15.5 12 20l8.5-4.5"/>',
    "sequence": '<path d="M6 3.5v17M18 3.5v17M6 8h10.5m-2-2 2 2-2 2M18 15H7.5m2-2-2 2 2 2"/>',
    "next": '<path d="m8 6 6 6-6 6M17 6v12"/>',
    "prev": '<path d="m16 6-6 6 6 6M7 6v12"/>',
    "plus": '<path d="M12 5v14M5 12h14"/>',
    "minus": '<path d="M5 12h14"/>',
    "recenter": '<circle cx="12" cy="12" r="6.5"/><path d="M12 2.5V6M12 18v3.5M2.5 12H6M18 12h3.5"/>'
    '<circle class="fill" cx="12" cy="12" r="1.2"/>',
}


def icon(name: str, size: int = 16) -> str:
    return (
        f'<svg class="ico i-{name}" width="{size}" height="{size}" viewBox="0 0 24 24" aria-hidden="true" '
        f'focusable="false">{ICONS[name]}</svg>'
    )


JS = r"""
(function(){
"use strict";
var blob=document.getElementById("walk-data");if(!blob)return;
var V;try{V=JSON.parse(blob.textContent).view;}catch(e){return;}
var hops=V.hops,n=hops.length;if(!n||!V.scene)return;
function $(id){return document.getElementById(id);}
var root=document.documentElement,stage=$("schem"),svg=$("scene"),dot=$("dot"),trail=$("trail");
var secs=document.querySelectorAll(".hop"),nodes=document.querySelectorAll(".toc .node"),over=$("overview");
var story=$("story"),capbox=$("capbox"),capn=$("capn"),capr=$("capr"),cap=$("cap");
var play=$("play"),next=$("next"),prev=$("prev"),nextLabel=$("nextlabel"),speedBtn=$("speed");
if(!stage||!svg||!dot||!trail||!over||!play||!next||!prev||secs.length!==n||nodes.length!==n)return;
root.classList.add("js");
var still=window.matchMedia?window.matchMedia("(prefers-reduced-motion: reduce)"):{matches:true};
var DRAWN={"holds":1,"fails":1,"cannot-judge":1};
var RANK={"fails":6,"cannot-judge":5,"unrecognised":5,"holds":3,"not-observable":2,"not-walked":1};
var cur=-1,raf=0,camRaf=0,timer=0,playing=false,speed=1,box=V.scene.frame.slice();
var chipText=dot.querySelector(".mchip text"),chipRect=dot.querySelector(".mchip rect");
var acts=V.scene.actors.map(function(a){var el=$("act-"+a.id);
return{id:a.id,hops:a.hops,el:el,st:el?el.querySelector(".st"):null};});
var rows=document.querySelectorAll(".etable tr[data-hop]"),count=$("count"),bar=$("bar");

/* What each actor shows: the worst state among the hops on it that the walk has reached so far. A hop that was
   not walked is never reached, so it is shown as not walked from the start. */
function paint(upto){
acts.forEach(function(a){
if(!a.el||!a.hops.length)return;
var best=null;
a.hops.forEach(function(k){var h=hops[k-1];if(!h)return;
if(k-1>upto&&h.state!=="not-walked")return;
if(!best||(RANK[h.state]||5)>(RANK[best.state]||5))best=h;});
a.el.setAttribute("data-v",best?best.state:"pending");
if(a.st)a.st.textContent=best?best.glyph+" "+best.mark:"";
});}
function flag(el,name,on){if(!el)return;if(on){el.setAttribute(name,"");}else{el.removeAttribute(name);}}
function focus(i){
acts.forEach(function(a){var on=i>=0&&(a.id===hops[i].actor||a.id===hops[i].from);
flag(a.el,"data-on",on);flag(a.el,"data-dim",i>=0&&!on);});
for(var k=0;k<n;k++){flag($("cab-"+(k+1)),"data-on",k===i);}
}

function setBox(b){svg.setAttribute("viewBox",b.map(function(v){return v.toFixed(1);}).join(" "));}
function ease(t){return t<0.5?2*t*t:1-Math.pow(-2*t+2,2)/2;}
function camera(to,animate){
if(camRaf){window.cancelAnimationFrame(camRaf);camRaf=0;}
var from=box.slice();
if(!animate||still.matches){box=to.slice();setBox(box);return;}
var t0=0;
function step(t){if(!t0)t0=t;var f=Math.min(1,(t-t0)/900),e=ease(f);
box=from.map(function(v,k){return v+(to[k]-v)*e;});setBox(box);
camRaf=f<1?window.requestAnimationFrame(step):0;}
camRaf=window.requestAnimationFrame(step);
}
function home(){return cur<0?V.scene.frame:hops[cur].frame;}
function zoom(f){var w=box[2]/f,h=box[3]/f;
if(w<160||w>6000)return;
camera([box[0]+(box[2]-w)/2,box[1]+(box[3]-h)/2,w,h],true);flag($("zreset"),"hidden",false);}

function at(pts,f){
var len=[],total=0,i;
for(i=1;i<pts.length;i++){var d=Math.sqrt(Math.pow(pts[i][0]-pts[i-1][0],2)+Math.pow(pts[i][1]-pts[i-1][1],2));
len.push(d);total+=d;}
var want=total*f;
for(i=0;i<len.length;i++){if(want<=len[i]||i===len.length-1){var k=len[i]?Math.min(1,want/len[i]):1;
return[pts[i][0]+(pts[i+1][0]-pts[i][0])*k,pts[i][1]+(pts[i+1][1]-pts[i][1])*k];}want-=len[i];}
return pts[pts.length-1];}
function length(pts){var t=0;for(var i=1;i<pts.length;i++){
t+=Math.sqrt(Math.pow(pts[i][0]-pts[i-1][0],2)+Math.pow(pts[i][1]-pts[i-1][1],2));}return t;}
function path(pts){return pts.map(function(q,i){return(i?"L":"M")+q[0].toFixed(1)+" "+q[1].toFixed(1);}).join(" ");}
function put(q){dot.setAttribute("transform","translate("+q[0].toFixed(1)+" "+q[1].toFixed(1)+")");}
function label(text){
chipText.textContent=text;
var w=160;try{w=chipText.getComputedTextLength()+18;}catch(e){}
chipRect.setAttribute("x",(-w/2).toFixed(1));chipRect.setAttribute("width",w.toFixed(1));}
function brokenBefore(i){for(var k=0;k<i;k++){if(hops[k].state==="fails")return true;}return false;}
function reach(s){return s==="cannot-judge"?0.55:1;}
/* How long the event takes to get there: 0.2 px a millisecond, between 0.8 and 3 seconds. */
function travel(i){var h=hops[i];if(still.matches||!DRAWN[h.state])return 0;
if(h.route.length<2)return 750/speed;
return Math.max(800,Math.min(3000,length(h.route)/0.2))/speed;}
function reading(i){var words=hops[i].says.split(/\s+/).length;return(Math.max(1500,words*220)+800)/speed;}
function settle(i){
var h=hops[i],s=h.state,pts=h.route,inPlace=pts.length<2;
dot.setAttribute("class","on "+(s==="fails"?"fail":s==="cannot-judge"?"halt":brokenBefore(i)?"after":"ok")+
(inPlace&&s==="holds"&&!still.matches?" pulse":""));
put(inPlace?h.at:at(pts,reach(s)));
if(!inPlace){trail.setAttribute("d",path(pts));trail.setAttribute("class","trail on t-"+s);
trail.style.strokeDashoffset=String(1-reach(s));}
paint(i);
}
function fly(i,move){
if(raf){window.cancelAnimationFrame(raf);raf=0;}
trail.setAttribute("class","trail");
var s=hops[i].state,pts=hops[i].route;
if(!DRAWN[s]){dot.setAttribute("class","");return;}
label(hops[i].chip);
if(!move||still.matches||pts.length<2){settle(i);return;}
var end=reach(s),t0=0,ms=travel(i);
dot.setAttribute("class","on"+(brokenBefore(i)?" after":""));
put(at(pts,0));
trail.setAttribute("d",path(pts));trail.setAttribute("class","trail on t-"+s);trail.style.strokeDashoffset="1";
function frame(t){if(!t0)t0=t;var f=Math.min(1,(t-t0)/ms),e=ease(f)*end;put(at(pts,e));
trail.style.strokeDashoffset=String(1-e);
if(f<1){raf=window.requestAnimationFrame(frame);}else{raf=0;settle(i);}}
raf=window.requestAnimationFrame(frame);
}

function canAdvance(){
if(cur>=n-1)return false;
if(cur<0)return hops[0].state!=="not-walked";
var s=hops[cur].state;
if(s==="cannot-judge"||s==="unrecognised"||s==="not-walked")return false;
return hops[cur+1].state!=="not-walked";}
function evidence(){
var shown=0;
for(var k=0;k<rows.length;k++){var hop=parseInt(rows[k].getAttribute("data-hop"),10);
var later=cur>=0&&hop>cur+1;rows[k].hidden=later;rows[k].className=hop===cur+1?"cur":"";if(!later)shown++;}
if(count)count.textContent=shown+" / "+rows.length;
if(bar)bar.style.width=(rows.length?shown/rows.length*100:100)+"%";
for(k=0;k<n;k++){var r=$("seq-"+(k+1));if(r){r.classList.toggle("cur",k===cur);
r.classList.toggle("later",cur>=0&&k>cur);}}
}
function buttons(){
prev.disabled=cur<0;
nextLabel.textContent=cur<0?"Start the walk":canAdvance()?"Next hop":"See the verdict";
play.setAttribute("aria-pressed",playing?"true":"false");
play.setAttribute("aria-label",playing?"Stop auto-play":"Auto-play the hops");
}
function show(i,move){
cur=i;
for(var k=0;k<n;k++){var on=k===i;secs[k].classList.toggle("sel",on);nodes[k].classList.toggle("sel",on);
if(on){nodes[k].setAttribute("aria-current","step");}else{nodes[k].removeAttribute("aria-current");}}
over.classList.toggle("sel",i<0);
if(story)story.scrollTop=0;
evidence();buttons();
flag($("zreset"),"hidden",true);
camera(home(),true);
focus(i);
if(timer){window.clearTimeout(timer);timer=0;}
if(i<0){
if(raf){window.cancelAnimationFrame(raf);raf=0;}
capbox.hidden=true;dot.setAttribute("class","");trail.setAttribute("class","trail");paint(n-1);
if(playing)timer=window.setTimeout(tick,600);
return;}
var h=hops[i],flying=move&&!still.matches&&DRAWN[h.state]&&h.route.length>1;
capbox.hidden=false;capbox.className="caption s-"+h.state;
capn.textContent=String(h.n);capr.textContent=h.caption;cap.textContent=h.says;
paint(flying?i-1:i);
fly(i,move);
if(playing)timer=window.setTimeout(tick,(flying||h.route.length<2?travel(i):0)+reading(i));
}
function parse(hash){if(hash==="#overview")return-1;var m=/^#step-(\d+)$/.exec(hash||"");if(!m)return null;
var i=parseInt(m[1],10)-1;return i>=0&&i<n?i:null;}
function go(i,move){
if(i<-1||i>=n)return;
try{window.history.replaceState(null,"",i<0?"#overview":"#step-"+(i+1));}catch(e){}
show(i,move);
}
function stop(){playing=false;if(timer){window.clearTimeout(timer);timer=0;}buttons();}
function advance(){if(cur<0){go(0,true);}else if(canAdvance()){go(cur+1,true);}else{go(-1,false);}}
function tick(){timer=0;if(!playing)return;if(!canAdvance()){stop();return;}go(cur+1,true);}
function start(){playing=true;buttons();
if(!canAdvance()){go(-1,false);}else{timer=window.setTimeout(tick,cur<0?300:600);}}

window.addEventListener("hashchange",function(){var i=parse(window.location.hash);
if(i===null||i===cur)return;stop();show(i,false);});
document.addEventListener("click",function(e){
var a=e.target&&e.target.closest?e.target.closest("a"):null;if(!a)return;
var i=parse(a.getAttribute("href"));if(i===null)return;
e.preventDefault();stop();go(i,i===cur+1);});
play.addEventListener("click",function(){if(playing){stop();}else{start();}});
prev.addEventListener("click",function(){stop();go(cur-1,false);});
next.addEventListener("click",function(){stop();advance();});
function on(id,fn){var el=$(id);if(el)el.addEventListener("click",fn);}
on("capnext",function(){stop();advance();});
on("restart",function(){stop();go(-1,false);});
on("speed",function(){speed=speed===1?1.5:speed===1.5?2:1;speedBtn.textContent=speed+"\u00d7";
speedBtn.setAttribute("aria-label","Playback speed "+speed+" times. Change speed");});
on("zin",function(){zoom(1.4);});
on("zout",function(){zoom(1/1.4);});
on("zreset",function(){camera(home(),true);flag($("zreset"),"hidden",true);});
function view(name){stage.setAttribute("data-view",name);
$("v-cluster").setAttribute("aria-pressed",name==="cluster"?"true":"false");
$("v-sequence").setAttribute("aria-pressed",name==="sequence"?"true":"false");}
on("v-cluster",function(){view("cluster");});
on("v-sequence",function(){view("sequence");});

var KEY="kube-noob-walk-theme",themeBtn=$("theme");
function theme(t,keep){root.setAttribute("data-theme",t);
if(themeBtn)themeBtn.setAttribute("aria-label","Switch to "+(t==="dark"?"light":"dark")+" theme");
if(keep){try{window.localStorage.setItem(KEY,t);}catch(e){}}}
var chosen=null;try{chosen=window.localStorage.getItem(KEY);}catch(e){}
if(chosen!=="dark"&&chosen!=="light"){
chosen=window.matchMedia&&window.matchMedia("(prefers-color-scheme: dark)").matches?"dark":"light";}
theme(chosen,false);
on("theme",function(){theme(root.getAttribute("data-theme")==="dark"?"light":"dark",true);});

var dlg=$("shortcuts");
function keys(){if(!dlg)return;if(dlg.showModal){if(!dlg.open)dlg.showModal();}else{dlg.setAttribute("open","");}}
on("keys",keys);
on("keysclose",function(){if(dlg.close){dlg.close();}else{dlg.removeAttribute("open");}});
document.addEventListener("keydown",function(e){
if(e.defaultPrevented||e.altKey||e.ctrlKey||e.metaKey)return;
if(dlg&&dlg.open)return;
var tag=e.target&&e.target.tagName;
if(e.key==="ArrowLeft"){stop();go(cur-1,false);e.preventDefault();}
else if(e.key==="ArrowRight"){stop();advance();e.preventDefault();}
else if((e.key===" "||e.key==="Spacebar")&&tag!=="BUTTON"&&tag!=="A"&&tag!=="SUMMARY"){
stop();advance();e.preventDefault();}
else if(e.key==="Home"){stop();go(-1,false);e.preventDefault();}
else if(e.key==="?"){keys();e.preventDefault();}
else if(e.key==="p"||e.key==="P"){if(playing){stop();}else{start();}}
else if(e.key==="+"||e.key==="="){zoom(1.4);}
else if(e.key==="-"){zoom(1/1.4);}
});
var first=parse(window.location.hash);
show(first===null?-1:first,false);
})();
"""
