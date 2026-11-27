"""The mechanism walk's page is a lesson player, and what the player must never do (G430).

`learn mechanism --format html` was a grid of boxes with three buttons. It is now a port of KubeLearn's lesson
player -- an isometric scene, a marker that flies it, a story column, a list of hops, a sequence view and a drawer
of evidence -- driven by the dict `walk()` returns. `tests/test_a_walk_you_can_watch.py` still holds what a
document owes (no address, the same bytes, nothing from a manifest as markup, the walk's exit code). This file
holds what the player added:

1. the scene stands on the reader's own objects: one card per object a hop names, its kind's badge, its name;
2. a thing no manifest holds is drawn as one: dashed, and it says "not in any manifest";
3. a verdict is a glyph and a word wherever it is shown, in the scene and in the list alike;
4. a stopped walk greys what it did not walk, and never marks it holding;
5. without the script the page is still the whole walk;
6. every lesson is drawn, and a lesson with no layout is drawn as a plain row rather than not at all;
7. the port is credited, in the notices and on the page, and the page still names no address.
"""

from __future__ import annotations

import html
import json
import re
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

import pytest

from kube_noob.cli import main
from kube_noob.learn import iso as I
from kube_noob.learn import mechanism as M
from kube_noob.learn import mechanism_html as H
from kube_noob.learn import mechanism_player as P
from kube_noob.learn import mechanism_scene as SC

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "mechanism"
REQUEST = "mech-net-request-to-pod"
SERVICE = "mech-net-pod-calls-a-service"
RBAC = "mech-sec-rbac-and-serviceaccounts"
NODE_DARK = "mech-cp-a-node-goes-dark"
NETPOL = "mech-net-network-policy"
DEPLOY = "mech-cp-deploy-an-app"
AUTOSCALE = "mech-cp-autoscaling"

#: Every walkable lesson against every fixture written for it, and one fragment that stops.
CASES = [
    (REQUEST, FIXTURES / "complete"),
    (REQUEST, FIXTURES / "broken"),
    (REQUEST, FIXTURES / "complete" / "bundle.yaml"),
    (SERVICE, FIXTURES / "service" / "complete"),
    (SERVICE, FIXTURES / "service" / "broken"),
    (RBAC, FIXTURES / "rbac" / "complete"),
    (RBAC, FIXTURES / "rbac" / "broken"),
    (NODE_DARK, FIXTURES / "complete"),
    (NETPOL, FIXTURES / "networkpolicy" / "complete"),
    (NETPOL, FIXTURES / "networkpolicy" / "broken"),
    (DEPLOY, FIXTURES / "deploy" / "complete"),
    (DEPLOY, FIXTURES / "deploy" / "broken"),
    (AUTOSCALE, FIXTURES / "autoscaling" / "complete"),
    (AUTOSCALE, FIXTURES / "autoscaling" / "broken"),
]
IDS = [f"{lesson}:{path.parent.name}/{path.name}" for lesson, path in CASES]


def _run(fmt: str, lesson: str, path: Path, capsys: pytest.CaptureFixture[str]) -> tuple[int, str]:
    capsys.readouterr()
    code = main(["--format", fmt, "learn", "mechanism", lesson, "-f", str(path)])
    return code, capsys.readouterr().out


def _both(lesson: str, path: Path, capsys: pytest.CaptureFixture[str]) -> tuple[dict[str, Any], str, int]:
    json_code, out = _run("json", lesson, path, capsys)
    walked: dict[str, Any] = json.loads(out)
    code, page = _run("html", lesson, path, capsys)
    assert code == json_code == walked["exitCode"]
    return walked, page, code


def _view(page: str) -> dict[str, Any]:
    tag = '<script type="application/json" id="walk-data">'
    start = page.index(tag) + len(tag)
    data: dict[str, Any] = json.loads(page[start : page.index("</script>", start)])
    view: dict[str, Any] = data["view"]
    return view


def _scene(page: str) -> str:
    start = page.index('<svg class="iso scene"')
    return page[start : page.index("</svg>", start)]


def _actor(page: str, actor_id: str) -> str:
    """One actor's markup in the scene: its opening tag, its art and its three label lines."""
    scene = _scene(page)
    start = scene.index(f'id="act-{actor_id}"')
    start = scene.rindex("<g ", 0, start)
    return scene[start : scene.index("</g></g>", scene.index('class="alabel"', start))]


class _NoScript(HTMLParser):
    """The page as a reader without JavaScript gets it: every element but the style and the scripts, as text."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.depth, self.out = 0, []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in ("script", "style"):
            self.depth += 1
        else:
            self.out.append(" ")

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style"):
            self.depth = max(0, self.depth - 1)
        else:
            self.out.append(" ")

    def handle_data(self, data: str) -> None:
        if not self.depth:
            self.out.append(data)


def _static_text(page: str) -> str:
    parser = _NoScript()
    parser.feed(page)
    parser.close()
    return " ".join("".join(parser.out).split())


def _walk_of(steps: list[dict[str, Any]], **over: Any) -> dict[str, Any]:
    judged = sum(1 for s in steps if s["verdict"] in ("holds", "fails"))
    return {
        "lesson": "mech-x-not-a-shipped-lesson",
        "title": "A path",
        "layer": "test",
        "verdict": "broken",
        "verdictReason": "these hops are broken",
        "stoppedAt": None,
        "namespaces": ["shop"],
        "steps": steps,
        "counts": {"declared": len(steps), "judged": judged, "notObservable": 0, "notReached": 0},
        "exitCode": 1,
        **over,
    }


# -- the drawing helpers ------------------------------------------------------------------------------------


def test_the_isometric_helpers_write_the_same_bytes_and_no_negative_zero() -> None:
    assert I.iso(1, 0, 0, 2) == (2 * I.C30, 1.0)
    assert I.iso(0, 0, 1, 2) == (0.0, -2.0)
    assert [I.num(v) for v in (-0.001, 0.0, 1.0, 1.5, -1.25, 12.345)] == ["0", "0", "1", "1.5", "-1.25", "12.35"]
    assert I.box(0, 0, 0, 1, 1, 1, 10, "hot") == (
        '<g class="hot"><polygon class="f-l" points="-8.66,5 0,10 0,0 -8.66,-5"/>'
        '<polygon class="f-r" points="8.66,5 0,10 0,0 8.66,-5"/>'
        '<polygon class="f-t" points="0,-10 8.66,-5 0,0 -8.66,-5"/></g>'
    )
    card = I.resource_card(SC.S * 0.85, "ING")
    assert card.count("<polygon") == 6 and ">ING</text>" in card and 'class="sheet"' in card
    for art in (I.laptop(4.6, "browser"), I.worker_node(4.6, ("v1", "nonsense")), I.rack(4, "DNS"), I.pod(4)):
        assert "-0," not in art and "-0 " not in art and art.isascii()
    assert "slot-other" in I.worker_node(4.6, ("nonsense",)), "an unknown slot is drawn as `other`, not as a class"
    assert I.load_balancer(4.6) == I.load_balancer(4.6) and I.api_server(4.6) and I.scheduler(4.6) and I.etcd(4.6)


def test_a_kind_this_build_has_no_badge_for_gets_its_capitals_and_never_markup() -> None:
    assert [SC.badge_for(k) for k in ("Ingress", "Service", "Deployment", "NetworkPolicy", "Pod")] == [
        *("ING", "SVC", "DEP", "NP", "POD")
    ]
    assert [SC.badge_for(k) for k in ("ServiceAccount", "Role", "RoleBinding", "HorizontalPodAutoscaler")] == [
        *("SA", "ROLE", "RB", "HPA")
    ]
    assert [SC.badge_for(k) for k in ("StatefulSet", "PersistentVolumeClaim")] == ["STS", "PVC"]
    assert SC.badge_for("VerticalPodAutoscaler") == "VPA"
    assert SC.badge_for("widget") == "WID"
    assert SC.badge_for("<script>") == "SCR" and SC.badge_for('"><') == "?"


# -- 1. the scene stands on the reader's own objects ---------------------------------------------------------


def test_a_lesson_whose_hops_read_a_kind_draws_that_kind_on_its_card(capsys: pytest.CaptureFixture[str]) -> None:
    """The NetworkPolicy lesson's hops read the kind and name no object, so the walk carries no `objects`: each
    judged hop still stands on a NetworkPolicy card, and a hop no manifest shows stands on scenery."""
    for path in (FIXTURES / "networkpolicy" / "complete", FIXTURES / "networkpolicy" / "broken"):
        walked, page, _ = _both(NETPOL, path, capsys)
        assert not any(s.get("objects") for s in walked["steps"]), "the lesson names objects now: use the test below"
        view = _view(page)
        assert view["scene"]["layout"] == NETPOL
        for step, hop in zip(walked["steps"], view["hops"], strict=False):
            art = _actor(page, hop["actor"])
            if step["verdict"] == "not-observable":
                assert 'data-manifest="no"' in art and SC.NOT_IN_MANIFEST in art, step["step"]
            else:
                assert 'class="actor res' in art and ">NP</text>" in art, step["step"]


@pytest.mark.parametrize(
    ("lesson", "path"),
    [c for c in CASES if c[0] != NETPOL],
    ids=[i for c, i in zip(CASES, IDS, strict=True) if c[0] != NETPOL],
)
def test_the_scene_has_one_card_per_object_a_hop_names(
    lesson: str, path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    walked, page, _ = _both(lesson, path, capsys)
    view = _view(page)
    assert view["scene"]["layout"] == lesson, "a shipped lesson is drawn with its own layout"
    named = [s["objects"][0] for s in walked["steps"] if s.get("objects")]
    assert named, "the fixture names no object, so this test would prove nothing"
    cards: dict[str, str] = {}
    for step, hop in zip(walked["steps"], view["hops"], strict=False):
        if not step.get("objects"):
            continue
        obj = step["objects"][0]
        kind, _, name = SC.split_object(obj)
        cards.setdefault(obj, hop["actor"])
        assert cards[obj] == hop["actor"], "two hops that read the same object stand on the same card"
        art = _actor(page, hop["actor"])
        assert 'class="actor res' in art and 'data-manifest="yes"' in art
        assert f">{SC.BADGE[kind]}</text>" in art, f"{obj} is drawn without its kind's badge"
        assert f'<text class="n">{H._esc(SC.clip(f"{kind} {name}", 30))}</text>' in art
        assert f'<code class="in">{html.escape(obj)}</code>' in page, "the whole name is in the story beside it"
    assert len(set(cards.values())) == len(set(named)), "two different objects share a card"
    # Every hop stands somewhere, and the route it is reached by is drawn from where the hop before it stood.
    actors = {a["id"] for a in view["scene"]["actors"]}
    for prev, hop in zip([None, *view["hops"]], view["hops"], strict=False):
        assert hop["actor"] in actors and len(hop["frame"]) == 4 and hop["frame"][2] > 0
        if prev is not None:
            assert hop["from"] == prev["actor"]
        assert (hop["from"] == hop["actor"]) == (hop["route"] == [])


def test_a_hostile_object_name_is_text_in_the_scene_and_in_the_sequence() -> None:
    name = '</text><script>alert(1)</script><text onload="x">'
    walked = _walk_of(
        [
            {"step": "a", "title": name, "verdict": "fails", "why": name, "objects": [f"Ingress/{name}/{name}"]},
            {"step": "b", "title": "B", "verdict": "holds", "why": "w", "objects": ["T<s onload=x>A/shop/web"]},
        ],
        namespaces=[name],
    )
    page = H.render_html(walked)
    scene = _scene(page)
    assert "<script" not in scene and "</text><script" not in page
    assert not re.search(r"<[^>]*\son[a-z]+\s*=", scene), "an attribute the name wrote"
    assert "&lt;/text&gt;&lt;script&gt;alert(1)" in scene, "the name never reached the scene, so nothing was tested"
    # The floor carries the namespace and the sequence view carries the hop titles: both are the input's text.
    assert 'class="floor-name"' in scene and "cluster &#183; namespace &lt;/text&gt;" in scene
    seq = page[page.index('<svg class="seq-body"') :]
    seq = seq[: seq.index("</svg>")]
    assert "<script" not in seq and "&lt;script&gt;" in seq
    # A kind out of the input never becomes a class name or a badge with markup in it.
    assert 'class="actor res tone-other"' in scene and ">TA</text>" in scene
    assert '<text class="n">T&lt;s onload=x&gt;A web</text>' in scene
    assert page.isascii() and page.lower().count("<script") == 2


# -- 2. a thing no manifest holds is drawn as one ------------------------------------------------------------


@pytest.mark.parametrize(("lesson", "path"), CASES, ids=IDS)
def test_what_no_manifest_holds_is_dashed_and_says_so(
    lesson: str, path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _, page, _ = _both(lesson, path, capsys)
    view = _view(page)
    seen = 0
    for hop in view["hops"]:
        art = _actor(page, hop["actor"])
        if hop["state"] == "not-observable":
            seen += 1
            assert 'data-manifest="no"' in art and 'data-v="not-observable"' in art
            assert '<text class="ip" y="16">not in any manifest<tspan class="sec"></tspan></text>' in art
            assert "not observable</text>" in art and "holds" not in art
        elif hop["objects"]:
            assert 'data-manifest="yes"' in art
    # Scenery -- the worker nodes, the visitor -- has no hop, so it has no verdict, and it is dashed too.
    for a in view["scene"]["actors"]:
        if not a["hops"]:
            art = _actor(page, a["id"])
            assert 'data-v="none"' in art and 'data-manifest="no"' in art and "not in any manifest" in art
            assert '<text class="st" y="32"></text>' in art
    assert seen == sum(1 for h in view["hops"] if h["state"] == "not-observable")
    # "Dashed" is in the stylesheet, on the attribute and nothing else.
    assert '.actor[data-manifest="no"] polygon' in P.CSS and "stroke-dasharray:4 3" in P.CSS


def test_the_request_lesson_draws_its_unobservable_last_hop_as_a_node(capsys: pytest.CaptureFixture[str]) -> None:
    _, page, _ = _both(REQUEST, FIXTURES / "complete", capsys)
    last = _view(page)["hops"][-1]
    assert last["state"] == "not-observable"
    art = _actor(page, last["actor"])
    assert '<text class="n">Node network</text>' in art and "slot slot-v1" in art


# -- 3. a verdict is a glyph and a word ----------------------------------------------------------------------


def test_a_broken_hop_carries_the_cross_and_the_word_on_its_card_and_in_the_list(
    capsys: pytest.CaptureFixture[str],
) -> None:
    walked, page, code = _both(REQUEST, FIXTURES / "broken", capsys)
    assert code == 1 and walked["steps"][0]["verdict"] == "fails"
    hop = _view(page)["hops"][0]
    art = _actor(page, hop["actor"])
    assert 'data-v="fails"' in art and '<text class="st" y="32">&#10007; BROKEN</text>' in art
    entry = re.search(r'<a class="node s-fails" href="#step-1">(.*?)</a>', page, flags=re.S)
    assert entry is not None
    assert '<span class="glyph" aria-hidden="true">&#10007;</span>' in entry.group(1)
    assert '<span class="chip">BROKEN</span>' in entry.group(1)
    # And in the hop's own facts, the sequence view and the evidence drawer.
    assert '<dt>Verdict</dt><dd><span class="chip s-fails">&#10007; BROKEN</span></dd>' in page
    assert re.search(r'<g class="seq-row s-fails" id="seq-1">.*?&#10007; BROKEN: ', page, flags=re.S)
    assert '<tr data-hop="1"><td>1</td><td>KN-V019</td><td class="sev s-fails">LOW</td>' in page


@pytest.mark.parametrize(("lesson", "path"), CASES, ids=IDS)
def test_every_state_in_the_list_is_a_glyph_and_a_word_and_only_a_hold_gets_the_tick(
    lesson: str, path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _, page, _ = _both(lesson, path, capsys)
    view = _view(page)
    entries = re.findall(r'<a class="node s-([a-z-]+)" href="#step-(\d+)">(.*?)</a>', page, flags=re.S)
    assert len(entries) == len(view["hops"])
    for (state, _n, inner), hop in zip(entries, view["hops"], strict=True):
        assert state == hop["state"] and f'<span class="chip">{H.MARK[state]}</span>' in inner
        assert ("&#10003;" in inner) == (state == "holds"), "a tick beside a hop that does not hold"
        if state in ("not-observable", "not-walked"):
            assert '<span class="glyph hollow" aria-hidden="true"></span>' in inner
        if state == "not-observable":
            assert '<span class="note">not checked by any manifest</span>' in inner
    # In the scene, the tick is on exactly the cards whose worst hop holds.
    states = {h["n"]: h["state"] for h in view["hops"]}
    for a in view["scene"]["actors"]:
        worst = max((states[n] for n in a["hops"]), key=lambda s: SC.RANK[s], default="none")
        art = _actor(page, a["id"])
        assert f'data-v="{worst}"' in art
        assert ("&#10003; holds</text>" in art) == (worst == "holds")


def test_a_card_two_hops_stand_on_shows_the_worse_of_them() -> None:
    walked = _walk_of(
        [
            {"step": "a", "title": "A", "verdict": "holds", "why": "w", "objects": ["Service/shop/web"]},
            {"step": "b", "title": "B", "verdict": "fails", "why": "w", "objects": ["Service/shop/web"]},
            {"step": "c", "title": "C", "verdict": "holds", "why": "w", "objects": ["Service/shop/web"]},
        ]
    )
    page = H.render_html(walked)
    view = _view(page)
    assert len({h["actor"] for h in view["hops"]}) == 1
    art = _actor(page, view["hops"][0]["actor"])
    assert 'data-v="fails"' in art and "&#10007; BROKEN</text>" in art and "&#10003;" not in art
    assert SC.RANK["fails"] > SC.RANK["cannot-judge"] > SC.RANK["holds"] > SC.RANK["not-observable"]
    assert SC.RANK["not-observable"] > SC.RANK["not-walked"]


def test_green_is_kept_for_a_hop_that_holds() -> None:
    """KubeLearn colours a Service card green. Here a card with no verdict yet must not look like a pass."""
    assert "--l-net" not in P.CSS
    assert P.CSS.count("var(--ok)") >= 4 and '.actor[data-v="holds"]{--rk:var(--ok)}' in P.CSS
    for tone in set(SC.TONE.values()):
        rule = re.search(rf"\.tone-{tone}[^{{]*\{{([^}}]*)\}}", P.CSS)
        assert rule is None or "--ok" not in rule.group(1), tone


# -- 4. a stopped walk greys what it did not walk ------------------------------------------------------------


def test_a_stopped_walk_greys_the_hops_after_the_stop_and_never_marks_them_holding(
    capsys: pytest.CaptureFixture[str],
) -> None:
    walked, page, code = _both(REQUEST, FIXTURES / "complete" / "bundle.yaml", capsys)
    assert code == 5 and walked["verdict"] == "stopped" and walked["counts"]["notReached"] == 2
    view = _view(page)
    walked_n = len(walked["steps"])
    after = view["hops"][walked_n:]
    assert [h["state"] for h in after] == ["not-walked", "not-walked"]
    assert view["hops"][walked_n - 1]["state"] == "cannot-judge"
    for hop in after:
        art = _actor(page, hop["actor"])
        assert 'data-v="not-walked"' in art and "not walked</text>" in art
        assert "holds" not in art and "&#10003;" not in art
        entry = re.search(rf'<a class="node s-not-walked" href="#step-{hop["n"]}">(.*?)</a>', page, flags=re.S)
        assert entry is not None and '<span class="chip">not walked</span>' in entry.group(1)
        assert "holds" not in entry.group(1) and "&#10003;" not in entry.group(1)
        assert f'<g class="seq-row s-not-walked" id="seq-{hop["n"]}">' in page
        # No actor a hop that WAS walked stands on is borrowed for it: the Deployment card that holds at hop 4
        # is not the card of the unwalked hop 6, which reads the same kind.
        assert hop["actor"] not in {h["actor"] for h in view["hops"][:walked_n]}
    stop = _actor(page, view["hops"][walked_n - 1]["actor"])
    assert 'data-v="cannot-judge"' in stop and "? cannot judge</text>" in stop
    text = _static_text(page)
    assert "Path verdict: stopped: no verdict reached" in text and "exit code 5 (no verdict was reached)" in text
    assert 't-ok"' not in page and 'class="panel t-warn"' in page
    # The script keeps the same promise while it plays: an unwalked hop is shown as not walked from the start,
    # the marker is drawn only for a hop a rule read, and auto-play never advances into an unwalked hop.
    assert 'if(k-1>upto&&h.state!=="not-walked")return;' in P.JS
    assert 'var DRAWN={"holds":1,"fails":1,"cannot-judge":1};' in P.JS
    assert 'return hops[cur+1].state!=="not-walked";' in P.JS
    assert '.actor[data-v="not-walked"]{opacity:.5}' in P.CSS


# -- 5. without the script the page is still the whole walk --------------------------------------------------


@pytest.mark.parametrize(("lesson", "path"), CASES, ids=IDS)
def test_without_javascript_the_page_lists_every_hop_its_verdict_and_its_whole_explanation(
    lesson: str, path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    walked, page, code = _both(lesson, path, capsys)
    declared = M.lessons()[lesson]["steps"]
    text = _static_text(page)
    assert f"Path verdict: {_view(page)['verdictWord']}" in text and f"exit code {code} (" in text
    assert " ".join(str(walked["verdictReason"]).split()) in text
    for key, label in (("declared", "hops declared"), ("judged", "judged"), ("notObservable", "not observable")):
        assert f"<dt>{label}</dt><dd>{walked['counts'][key]}</dd>" in page
    assert f"<dt>not walked</dt><dd>{walked['counts']['notReached']}</dd>" in page
    for n, step in enumerate(declared, 1):
        assert f'id="step-{n}"' in page and f'href="#step-{n}"' in page
        assert f"Hop {n} of {len(declared)}" in text and step["title"] in text
    for step in walked["steps"]:
        # Whole, not cut: the last clause of a hop's explanation is where the lesson states its limit (G411).
        assert " ".join(str(step["why"]).split()) in text, f"{step['step']}: the explanation is cut"
        for finding in step.get("findings") or ():
            assert finding["ruleId"] in text and finding["title"] in text
    # What hides a hop is a class only the script sets, and nothing hides the overview or the list without it.
    css = P.CSS
    assert ".js .hop{display:none}" in css and ".js #overview{display:none}" in css
    assert not re.search(r"(?<!\.js )(\.hop|#overview|\.toc|\.story)\{display:none", css)
    assert 'class="shell"' in page and "<html lang=" in page and 'class="js"' not in page


def test_an_explanation_longer_than_the_old_cap_is_on_the_page_whole() -> None:
    why = "the rule read it " * 60 + "but KN-X999 does not read a projected volume"
    assert len(why) > 600
    page = H.render_html(_walk_of([{"step": "a", "title": "A", "verdict": "holds", "why": why, "rules": ["KN-X999"]}]))
    assert why in _static_text(page)
    # Only input can be longer than the limit, and then the page says how much it left out.
    long = "x" * 5000
    page = H.render_html(_walk_of([{"step": "a", "title": "A", "verdict": "fails", "why": long}]))
    assert "(cut: 1000 more characters)" in _static_text(page)


def test_the_overview_is_step_zero_and_says_what_the_exit_code_means() -> None:
    walked = _walk_of(
        [
            {"step": "a", "title": "A", "verdict": "holds", "why": "w", "objects": ["Service/shop/web"]},
            {"step": "b", "title": "B", "verdict": "fails", "why": "w", "objects": ["Deployment/shop/web"]},
        ]
    )
    page = H.render_html(walked)
    assert page.count('id="overview"') == 1 and 'href="#overview"' in page
    start = page.index('<section class="panel t-bad" id="overview"')
    block = page[start : page.index("</section>", start)]
    assert '<span class="word">Path verdict: BROKEN</span>' in block
    assert "exit code 1 (a verdict was reached and it is not a pass)" in block
    assert "these hops are broken" in block and '<code class="in">shop</code> (the namespace judged)' in block
    assert 'href="#step-1"' in block and 'href="#step-2">Go to hop 2: BROKEN, the hop to act on</a>' in block
    # More than one namespace is why nothing was judged, and no namespace is not "default".
    assert "(more than one, so none was judged)" in H.render_html({**walked, "namespaces": ["a", "b"]})
    assert "none stated by the walk" in H.render_html({**walked, "namespaces": None})


def test_the_drawer_lists_the_evidence_the_walk_recorded(capsys: pytest.CaptureFixture[str]) -> None:
    walked, page, _ = _both(SERVICE, FIXTURES / "service" / "broken", capsys)
    rows = re.findall(r'<tr data-hop="(\d+)"><td>\d+</td><td>(.*?)</td><td class="sev s-([a-z-]+)">(.*?)</td>', page)
    findings = [(n, f) for n, s in enumerate(walked["steps"], 1) for f in s.get("findings") or ()]
    unjudged = [n for n, s in enumerate(walked["steps"], 1) if s["verdict"] in ("cannot-judge", "not-observable")]
    assert findings and unjudged
    assert len(rows) == len(findings) + len(unjudged)
    for n, f in findings:
        assert (str(n), f["ruleId"], "fails", f["severity"].upper()) in rows
        assert f'<code class="in">{html.escape(f["resource"])}</code></td><td>{html.escape(f["title"])}</td>' in page
    for n in unjudged:
        assert (str(n), "none", "not-observable", "not observable") in rows
    assert f'<span class="count" id="count">{len(rows)} / {len(rows)}</span>' in page
    # A hop that could not be judged brings its reason, and it is not listed as a finding.
    _, stopped, _ = _both(REQUEST, FIXTURES / "complete" / "bundle.yaml", capsys)
    assert '<td class="sev s-cannot-judge">not evaluated</td>' in stopped
    # No row is a sentence about the walk, never a clean bill.
    quiet = H.render_html(_walk_of([{"step": "a", "title": "A", "verdict": "holds", "why": "w"}]))
    assert "The walk recorded no finding and no hop it could not judge." in quiet
    assert "not a statement about anything it did not read" in quiet and '<span class="count" id="count">0 / 0' in quiet


# -- 6. every lesson is drawn --------------------------------------------------------------------------------


@pytest.mark.parametrize(("lesson", "path"), CASES, ids=IDS)
def test_every_lesson_renders_on_its_fixtures_the_same_twice_and_small(
    lesson: str, path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    walked, page, _ = _both(lesson, path, capsys)
    _, again = _run("html", lesson, path, capsys)
    assert page == again, "two runs over the same input wrote two pages"
    assert H.render_html(walked, M.lessons()[lesson]).strip() == page.strip(), "the command and the module differ"
    assert page.startswith("<!doctype html>") and page.isascii()
    assert len(page.encode()) < 250_000, f"the page is {len(page.encode())} bytes"
    assert "http://" not in page and "https://" not in page and "://" not in page and "www." not in page
    assert not re.search(r"\bsrc\s*=|@import|url\(|@font-face|xmlns", page, flags=re.I)
    assert H.CREDIT == "Player design ported from KubeLearn by Joe Sabbagh, MIT"
    assert f'<footer class="credit">{H.CREDIT}.' in page and "joesabbagh" not in page.lower()
    assert f'<meta http-equiv="Content-Security-Policy" content="{H.CSP}">' in page
    for n in range(1, walked["counts"]["declared"] + 1):
        assert f'id="step-{n}"' in page and f'id="seq-{n}"' in page
    # One scene, one marker, a camera box per hop, and the sequence view of the same path.
    assert page.count('<svg class="iso scene"') == 1 and page.count('<g id="dot">') == 1
    assert 'class="floor-top"' in page and 'class="floor-grid"' in page and "slot slot-" in page
    assert "cluster &#183; namespace shop" in page


def test_the_walks_reach_every_exit_code_and_every_state(capsys: pytest.CaptureFixture[str]) -> None:
    """So the parametrised tests above cannot pass on a matrix that lost a row."""
    codes, states, lessons = set(), set(), set()
    for lesson, path in CASES:
        _, page, code = _both(lesson, path, capsys)
        codes.add(code)
        lessons.add(lesson)
        states |= {h["state"] for h in _view(page)["hops"]}
    assert codes == {0, 1, 5}
    assert states == {"holds", "fails", "cannot-judge", "not-observable", "not-walked"}
    assert lessons == set(M.lessons()) == set(SC.LAYOUTS), "a walkable lesson has no fixture here, or no layout"
    for lesson, layout in SC.LAYOUTS.items():
        assert set(layout.steps) == {s["id"] for s in M.lessons()[lesson]["steps"]}, lesson


def test_a_lesson_with_no_layout_is_drawn_as_a_row_and_not_refused() -> None:
    """NetworkPolicy, Deploy an app, Autoscaling and StatefulSet are being written. Each must draw on day one."""
    steps = [
        {"step": "hpa", "title": "The autoscaler", "verdict": "holds", "objects": ["HorizontalPodAutoscaler/shop/web"]},
        {"step": "sts", "title": "The set", "verdict": "fails", "objects": ["StatefulSet/shop/db"]},
        {"step": "pvc", "title": "The claim", "verdict": "holds", "objects": ["PersistentVolumeClaim/shop/data"]},
        {"step": "kubelet", "title": "The kubelet mounts it", "verdict": "not-observable"},
    ]
    for step in steps:
        step["why"] = "w"
    page = H.render_html(_walk_of(steps))
    view = _view(page)
    assert view["scene"]["layout"] == "row" and len(view["scene"]["actors"]) == 4
    for badge in ("HPA", "STS", "PVC"):
        assert f">{badge}</text>" in _scene(page)
    last = _actor(page, view["hops"][3]["actor"])
    assert 'data-manifest="no"' in last and "not in any manifest" in last and "The kubelet mounts it" in last
    assert 'class="floor-top"' in page and all(h["frame"][2] >= 520 for h in view["hops"])
    spots = set()
    for a in view["scene"]["actors"]:
        art = _actor(page, a["id"])
        spots.add(re.search(r'<g transform="translate\(([^)]*)\)">', art).group(1))  # type: ignore[union-attr]
    assert len(spots) == 4, "two actors of the row stand on one spot"
    # A shipped lesson's id on a walk whose hops are not that lesson's is not trusted with its layout either.
    assert _view(H.render_html(_walk_of(steps, lesson=REQUEST)))["scene"]["layout"] == "row"
    # And a path too long for one row wraps: sixty-four unwalked hops are all drawn, none on top of another.
    stopped = _walk_of(
        [{"step": "a", "title": "A", "verdict": "cannot-judge", "why": "no Ingress in the input"}],
        verdict="stopped",
        exitCode=5,
        counts={"declared": 500, "judged": 0, "notObservable": 0, "notReached": 499},
    )
    page = H.render_html(stopped)
    view = _view(page)
    assert len(view["hops"]) == 65 and len(view["scene"]["actors"]) == 65
    # Measured at 282 kB: the cap on drawn placeholders is what bounds a page built from a hand-written count.
    assert len(page.encode()) < 400_000
    assert "435 more hop(s) were not walked and are not drawn here" in page


def test_two_different_objects_at_one_spot_of_a_layout_do_not_stand_on_each_other() -> None:
    lesson = M.lessons()[NODE_DARK]
    ids = [s["id"] for s in lesson["steps"]]
    walked = _walk_of(
        [
            {"step": ids[0], "title": "A", "verdict": "holds", "why": "w", "objects": ["Deployment/shop/a"]},
            {"step": ids[1], "title": "B", "verdict": "fails", "why": "w", "objects": ["StatefulSet/shop/b"]},
        ],
        lesson=NODE_DARK,
        counts={"declared": 4, "judged": 2, "notObservable": 0, "notReached": 2},
    )
    page = H.render_html(walked, lesson)
    view = _view(page)
    assert view["scene"]["layout"] == NODE_DARK
    a, b = (_actor(page, view["hops"][i]["actor"]) for i in (0, 1))
    assert a != b and re.findall(r"translate\([^)]*\)", a)[0] != re.findall(r"translate\([^)]*\)", b)[0]
    assert view["hops"][1]["route"], "the second hop is reached by a route, not drawn on top of the first"


# -- 7. the player's controls, its themes and its credit ------------------------------------------------------


def test_the_player_has_the_controls_the_keys_and_the_deep_links() -> None:
    page = H.render_html(_walk_of([{"step": "a", "title": "A", "verdict": "holds", "why": "w"}]))
    for control in ("prev", "next", "play", "speed", "restart", "zin", "zout", "v-cluster", "v-sequence", "theme"):
        assert re.search(rf'<button type="button"[^>]* id="{control}"', page), control
    # Every button has a name: its text, or an aria-label where it is only an icon.
    for attrs, inner in re.findall(r"<button([^>]*)>(.*?)</button>", page, flags=re.S):
        named = "aria-label=" in attrs or re.sub(r"<svg.*?</svg>|<[^>]+>", "", inner, flags=re.S).strip()
        assert named, f"a button with no name: {attrs}"
    js = P.JS
    for needle in ('"ArrowRight"', '"ArrowLeft"', '"Home"', 'e.key==="?"', '"hashchange"', '"#overview"', "#step-"):
        assert needle in js, needle
    assert '"Start the walk":canAdvance()?"Next hop":"See the verdict"' in js
    # Space is "next", but never where it already means "press this".
    assert 'tag!=="BUTTON"&&tag!=="A"&&tag!=="SUMMARY"' in js
    assert "prefers-reduced-motion" in js and "prefers-reduced-motion:reduce" in P.CSS
    assert "if(!animate||still.matches){box=to.slice();setBox(box);return;}" in js, "the camera eases with motion off"
    assert "if(!move||still.matches||pts.length<2){settle(i);return;}" in js, "the marker flies with motion off"
    # The theme choice is kept where a blocked storage cannot break the page.
    assert "try{window.localStorage.setItem(KEY,t);}catch(e){}" in js
    assert "try{chosen=window.localStorage.getItem(KEY);}catch(e){}" in js
    assert js.count("localStorage") == 2
    # Text reaches the page as text.
    assert "innerHTML" not in js and "document.write" not in js and "eval(" not in js and "insertAdjacent" not in js


def test_both_themes_are_in_the_stylesheet_and_no_font_is_fetched() -> None:
    css = P.CSS
    assert '@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){' in css
    assert ':root[data-theme="dark"]{' in css
    assert "--bg:#080d1b" in css and "--bg:#f3f6fc" in css, "KubeLearn's dark and light tokens"
    assert "--story-w:360px" in css and "@media (max-width:900px)" in css and "max-width:480px" in css
    assert "@font-face" not in css and "Inter" not in css and "JetBrains" not in css
    assert "ui-sans-serif,system-ui" in css and "ui-monospace" in css
    assert ":focus-visible{outline:2px solid var(--accent-text)" in css
    assert css.isascii() and P.JS.isascii() and "url(" not in css


def test_the_port_is_credited_where_a_licence_asks_for_it() -> None:
    notices = (ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
    assert "KubeLearn" in notices and "Copyright (c) 2026 Joe Sabbagh" in notices
    assert "Permission is hereby granted, free of charge" in notices
    assert 'THE SOFTWARE IS PROVIDED "AS IS"' in notices
    for name in ("iso.py", "mechanism_scene.py", "mechanism_player.py", "mechanism_html.py"):
        assert f"src/kube_noob/learn/{name}" in notices, f"{name} is not listed as carrying ported material"
    for module in (I, SC, P, H):
        doc = module.__doc__ or ""
        assert "KubeLearn" in doc and "Joe Sabbagh" in doc and "MIT" in doc, module.__name__


# -- 8. the camera, the chip and the card while the walk is on a hop -----------------------------------------


def _inside(inner: list[float], x0: float, y0: float, x1: float, y1: float) -> bool:
    return inner[0] >= x0 and inner[1] >= y0 and inner[2] <= x1 and inner[3] <= y1


@pytest.mark.parametrize(("lesson", "path"), CASES, ids=IDS)
def test_the_camera_on_a_hop_crops_no_actor_and_keeps_the_caption_band_clear(
    lesson: str, path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The first cut of the player framed two actors tightly: the plate was cut off, a neighbour's label ran off
    the edge, and the caption strip lay over the card the hop was about."""
    _, page, _ = _both(lesson, path, capsys)
    view = _view(page)
    boxes = {a["id"]: a["box"] for a in view["scene"]["actors"]}
    ratio = SC.WORLD[0] / SC.WORLD[1]
    for hop in view["hops"]:
        x, y, w, h = hop["frame"]
        assert w >= 520 and abs(w / h - ratio) < 0.01, hop["frame"]
        clear = y + h * (1 - SC._BAND)
        for actor in (hop["from"], hop["actor"]):
            assert _inside(boxes[actor], x, y, x + w, clear + 0.2), f"hop {hop['n']}: {actor} is under the caption"
        for actor, box in boxes.items():
            apart = box[2] <= x or box[0] >= x + w or box[3] <= y or box[1] >= y + h
            assert apart or _inside(box, x, y, x + w, y + h), f"hop {hop['n']}: the camera cuts through {actor}"
    x, y, w, h = view["scene"]["frame"]
    for actor, box in boxes.items():
        assert _inside(box, x, y, x + w, y + h * (1 - SC._BAND_OVERVIEW) + 0.2), f"the overview crops {actor}"
    # A label is as wide as its text, and the box an actor must fit in knows it.
    wide = SC.Actor("a", "card", (0.0, 0.0), "N" * 30, "s" * 34)
    narrow = SC.Actor("b", "card", (0.0, 0.0), "N", "s")
    assert SC.extent(wide)[2] - SC.extent(wide)[0] > SC.extent(narrow)[2] - SC.extent(narrow)[0] >= 160


def test_the_chip_on_the_marker_is_moved_off_a_label_it_would_cover() -> None:
    quiet = SC.Actor("a", "card", (40.0, 40.0), "Service web", "namespace shop")
    assert SC._chip_dy("a hop", (0.0, 0.0), [quiet]) == -24, "nothing is near, so the chip sits where KubeLearn's does"
    # An actor whose label lies exactly where that chip would be: the chip goes higher, clear of it.
    x, y = quiet.pos
    under = (x, y + quiet.label_dy + 10 + 24)
    moved = SC._chip_dy("a hop title that is thirty-four ch", under, [quiet])
    assert moved < -24
    label_top = y + quiet.label_dy - 13
    assert under[1] + moved + 10 <= label_top, "the chip still lies over the label"
    assert len(SC.clip("x" * 80, 34)) == 34


def test_the_chip_is_clear_of_every_label_on_the_shipped_walks(capsys: pytest.CaptureFixture[str]) -> None:
    for lesson, path in CASES:
        _, page, _ = _both(lesson, path, capsys)
        view = _view(page)
        for hop in view["hops"]:
            assert hop["chipdy"] <= -24 and len(hop["chip"]) <= 34
    # The case that was reported: hop 2 of the Service walk put its chip over "Deployment orders-api".
    _, page, _ = _both(SERVICE, FIXTURES / "service" / "broken", capsys)
    view = _view(page)
    hop = view["hops"][1]
    half, cx, cy = (len(hop["chip"]) * 6.6 + 18) / 2, hop["at"][0], hop["at"][1] + hop["chipdy"]
    for a in view["scene"]["actors"]:
        if a["id"] == hop["actor"]:
            continue
        x0, _top, x1, y1 = a["box"]
        label_top = y1 - 55
        over = min(cx + half, x1) > max(cx - half, x0) and min(cy + 10, y1) > max(cy - 11, label_top)
        assert not over, f"the chip of hop 2 lies over the label of {a['id']}"
    assert 'chipBox.setAttribute("transform","translate(0 "+dy+")");' in P.JS


def test_the_card_under_the_walk_shows_this_hops_verdict_and_keeps_an_earlier_break_beside_it(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Hop 2 of the broken request walk holds, on the card hop 1 broke. The card read BROKEN under a caption that
    said holds. The overview still shows the worse of the two; a hop shows its own."""
    walked, page, _ = _both(REQUEST, FIXTURES / "broken", capsys)
    assert [s["verdict"] for s in walked["steps"][:2]] == ["fails", "holds"]
    view = _view(page)
    assert view["hops"][0]["actor"] == view["hops"][1]["actor"]
    art = _actor(page, view["hops"][0]["actor"])
    assert 'data-v="fails"' in art and "&#10007; BROKEN</text>" in art, "at rest the card shows the worse verdict"
    assert '<tspan class="sec"></tspan>' in art, "the secondary mark is the script's to write, and empty at rest"
    js = P.JS
    assert "if(here>=0&&here<=upto&&a.id===hops[here].actor){" in js and "best=hops[here];" in js
    assert 'if(h&&k-1<here&&h.state==="fails"&&best.state!=="fails")left.push("hop "+k+" "+h.glyph);});}' in js
    assert 'if(a.sec)a.sec.textContent=left.length?" \\u00b7 "+left.join(", "):"";' in js
    # On a hop the focused card is painted with that hop; on the overview no card is in focus.
    assert "paint(i,i);" in js and "paint(flying?i-1:i,i);" in js and "paint(n-1,-1);" in js
    # The mark is written into an element the page already has: the script needs no namespace address to make one.
    assert "createElementNS" not in js and ".alabel .sec{fill:var(--l-drop)" in P.CSS


def test_a_card_for_a_kind_takes_the_name_the_evidence_gives_it(capsys: pytest.CaptureFixture[str]) -> None:
    walked, page, _ = _both(SERVICE, FIXTURES / "service" / "broken", capsys)
    step = walked["steps"][1]
    assert step["verdict"] == "fails" and not step.get("objects")
    assert [f["resource"] for f in step["findings"]] == ["NetworkPolicy/shop/deny-egress"]
    view = _view(page)
    first, second = view["hops"][0], view["hops"][1]
    assert first["actor"] == second["actor"], "the two policy hops still stand on one card"
    art = _actor(page, second["actor"])
    assert '<text class="n">NetworkPolicy deny-egress</text>' in art and ">NP</text>" in art
    assert '<text class="ip" y="16">namespace shop<tspan' in art and "no object named" not in art
    assert second["objects"] == [] and second["evidence"] == ["NetworkPolicy/shop/deny-egress"]
    assert (
        '<dt>Object</dt><dd><code class="in">NetworkPolicy/shop/deny-egress</code> '
        "(named by the finding on this hop; the walk lists none)</dd>"
    ) in page
    assert _embedded_walk(page) == walked, "the walk the page carries is not rewritten to match"
    # Where the evidence names nothing, the card stays a kind and says so.
    _, complete, _ = _both(SERVICE, FIXTURES / "service" / "complete", capsys)
    quiet = _actor(complete, _view(complete)["hops"][0]["actor"])
    assert '<text class="n">NetworkPolicy</text>' in quiet and "kind; no object named" in quiet


def test_several_objects_in_the_evidence_are_counted_and_another_kind_is_not_borrowed() -> None:
    lesson = M.lessons()[SERVICE]
    ids = [s["id"] for s in lesson["steps"]]

    def finding(resource: str) -> dict[str, str]:
        return {"ruleId": "KN-N013", "severity": "medium", "resource": resource, "title": "t"}

    steps = [
        {"step": ids[0], "title": "A", "verdict": "holds", "why": "w"},
        {
            "step": ids[1],
            "title": "B",
            "verdict": "fails",
            "why": "w",
            "findings": [
                finding("NetworkPolicy/shop/a"),
                finding("Deployment/shop/web"),
                finding("NetworkPolicy/shop/b"),
                finding("NetworkPolicy/shop/a"),
            ],
        },
    ]
    walked = _walk_of(steps, lesson=SERVICE, counts={"declared": 7, "judged": 2, "notObservable": 0, "notReached": 5})
    page = H.render_html(walked, lesson)
    hop = _view(page)["hops"][1]
    assert hop["evidence"] == ["NetworkPolicy/shop/a", "NetworkPolicy/shop/b"]
    art = _actor(page, hop["actor"])
    assert '<text class="n">NetworkPolicy a</text>' in art and "namespace shop &#183; +1 more<tspan" in art
    assert "Deployment web" not in art


def test_a_hop_that_stays_on_its_card_is_at_it_and_not_a_journey_from_it_to_itself(
    capsys: pytest.CaptureFixture[str],
) -> None:
    _, page, _ = _both(REQUEST, FIXTURES / "broken", capsys)
    hops = _view(page)["hops"]
    assert hops[0]["caption"] == "01/07  start \u2192 Ingress/shop/shop"
    assert hops[1]["caption"] == "02/07  at Ingress/shop/shop" and hops[1]["route"] == []
    assert hops[2]["caption"] == "03/07  Ingress/shop/shop \u2192 Service/shop/orders-api" and hops[2]["route"]
    assert '<p class="sub route">02/07  at Ingress/shop/shop</p>' in page
    for lesson, path in CASES:
        _, page, _ = _both(lesson, path, capsys)
        for hop in _view(page)["hops"]:
            same = hop["n"] > 1 and hop["from"] == hop["actor"]
            assert ("  at " in hop["caption"]) == same and ("\u2192" in hop["caption"]) != same, hop["caption"]


def _embedded_walk(page: str) -> dict[str, Any]:
    tag = '<script type="application/json" id="walk-data">'
    start = page.index(tag) + len(tag)
    walk: dict[str, Any] = json.loads(page[start : page.index("</script>", start)])["walk"]
    return walk
