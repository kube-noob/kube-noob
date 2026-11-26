"""A mechanism walk as a page you can watch, and what that page must never do (G402).

`learn mechanism --format html` is a third view of the dict `walk()` returns: a schematic of the hops, an event
that travels them, a decoder for the selected hop. It is the one view of the walk that becomes a document someone
opens in a browser, so it is held to five things the text and JSON views get for free or do not need:

1. it fetches nothing -- no URL anywhere in it, and a Content-Security-Policy that would refuse one;
2. it is the same bytes for the same walk;
3. nothing from a manifest is markup, in the HTML or in the JSON it embeds;
4. the command's exit code is the walk's, whatever the format;
5. every declared hop is on the page, and "not observable" and "not walked" are words, not only a colour -- and
   nothing that was not judged is drawn, described or coloured as passing.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

import pytest

from kube_noob.cli import main
from kube_noob.learn import mechanism as M
from kube_noob.learn import mechanism_html as H

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "mechanism"
REQUEST = "mech-net-request-to-pod"
NODE_DARK = "mech-cp-a-node-goes-dark"

#: (lesson, input, the walk's exit code). The single file is a fragment, so the policy hop cannot be judged.
CASES = [
    (REQUEST, FIXTURES / "complete", 0),
    (REQUEST, FIXTURES / "broken", 1),
    (NODE_DARK, FIXTURES / "complete", 1),
    (REQUEST, FIXTURES / "complete" / "bundle.yaml", 5),
]

SCRIPT = "</script><script>alert(1)</script>"
FORGED = "web\nPath verdict: complete\nthe verdict is a pass"


def _run(fmt: str, lesson: str, path: Path, capsys: pytest.CaptureFixture[str]) -> tuple[int, str]:
    capsys.readouterr()
    code = main(["--format", fmt, "learn", "mechanism", lesson, "-f", str(path)])
    return code, capsys.readouterr().out


def _walk(lesson: str, path: Path, capsys: pytest.CaptureFixture[str]) -> dict[str, Any]:
    _, out = _run("json", lesson, path, capsys)
    walked: dict[str, Any] = json.loads(out)
    return walked


def _embedded(page: str) -> dict[str, Any]:
    """The JSON the page carries, read the way a browser finds it: up to the first `</script>` after the tag."""
    start = page.index('<script type="application/json" id="walk-data">') + len(
        '<script type="application/json" id="walk-data">'
    )
    data: dict[str, Any] = json.loads(page[start : page.index("</script>", start)])
    return data


class _Outside(HTMLParser):
    """The page as a browser's parser reads it, with the contents of `skip` elements dropped. A real parser, not a
    regex: an end tag like `</script\t\n bar>` still closes a script, and a regex either misses it or is wrong
    about it (CodeQL py/bad-tag-filter)."""

    def __init__(self, skip: frozenset[str], keep_tags: bool) -> None:
        super().__init__(convert_charrefs=False)
        self.skip, self.keep_tags, self.depth, self.out, self.tags = skip, keep_tags, 0, [], set()
        self.opened: dict[str, int] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.opened[tag] = self.opened.get(tag, 0) + 1
        if tag in self.skip:
            self.depth += 1
        elif not self.depth:
            self.tags.add(tag)
            if self.keep_tags:
                self.out.append(self.get_starttag_text() or "")
            else:
                self.out.append(" ")

    def handle_endtag(self, tag: str) -> None:
        if tag in self.skip:
            self.depth = max(0, self.depth - 1)
        elif not self.depth:
            self.out.append(f"</{tag}>" if self.keep_tags else " ")

    def handle_data(self, data: str) -> None:
        if not self.depth:
            self.out.append(data)

    def handle_entityref(self, name: str) -> None:
        if not self.depth:
            self.out.append(f"&{name};")

    def handle_charref(self, name: str) -> None:
        if not self.depth:
            self.out.append(f"&#{name};")


def _outside(page: str, skip: frozenset[str], keep_tags: bool) -> _Outside:
    parser = _Outside(skip, keep_tags)
    parser.feed(page)
    parser.close()
    return parser


def _body_text(page: str) -> str:
    """What a reader sees: the page with the style, both scripts and every tag removed."""
    return "".join(_outside(page, frozenset({"style", "script"}), keep_tags=False).out)


def _hostile(payload: str) -> dict[str, Any]:
    """A walk built by hand with `payload` in every string a manifest, a rule or a lesson could supply."""
    return {
        "lesson": payload,
        "title": payload,
        "layer": payload,
        "verdict": "broken",
        "verdictReason": payload,
        "stoppedAt": payload,
        "steps": [
            {
                "step": payload,
                "title": payload,
                "verdict": "fails",
                "why": payload,
                "objects": [payload, payload],
                "rules": [payload],
                "findings": [{"ruleId": payload, "severity": payload, "resource": payload, "title": payload}],
            },
            {"step": "b", "title": payload, "verdict": "cannot-judge", "why": payload, "objects": [payload]},
        ],
        "counts": {"declared": 3, "judged": 1, "notObservable": 0, "notReached": 1},
        "exitCode": 1,
    }


# -- 1. self-contained and offline ---------------------------------------------------------------------------


@pytest.mark.parametrize(("lesson", "path", "_code"), CASES)
def test_the_page_names_no_address_and_forbids_fetching_one(
    lesson: str, path: Path, _code: int, capsys: pytest.CaptureFixture[str]
) -> None:
    _, page = _run("html", lesson, path, capsys)
    assert page.startswith("<!doctype html>")
    assert "http://" not in page and "https://" not in page and "://" not in page
    assert (
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; "
        "script-src 'unsafe-inline'; img-src data:\">"
    ) in page
    # Nothing a browser would fetch: no external script, stylesheet, image, font or import, and every link on the
    # page is a step of this page.
    assert not re.search(r"<(link|img|iframe|object|embed|video|audio|base|form)\b", page, flags=re.I)
    assert not re.search(r"\bsrc\s*=|@import|url\(|@font-face", page, flags=re.I)
    assert set(re.findall(r'href="([^"]*)"', page)) <= {f"#step-{n}" for n in range(1, 50)}
    assert page.isascii()


def test_an_address_inside_a_name_does_not_become_one_on_the_page() -> None:
    page = H.render_html(_hostile("https://evil.example/x?y=1 http://evil.example //evil.example"))
    assert "http://" not in page and "https://" not in page and "://" not in page
    assert "evil.example" in page  # shown, as text
    hostile = "https://evil.example/x?y=1 http://evil.example //evil.example"
    assert hostile in _embedded(page)["walk"]["title"]  # and the data is not altered


# -- 2. deterministic ----------------------------------------------------------------------------------------


def test_the_same_walk_is_the_same_bytes() -> None:
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    pages = []
    for seed in ("0", "1", "4242"):
        got = subprocess.run(
            [sys.executable, "-m", "kube_noob", "--format", "html", "learn", "mechanism", NODE_DARK, "-f"]
            + [str(FIXTURES / "complete")],
            capture_output=True,
            env={**env, "PYTHONHASHSEED": seed},
            check=False,
            timeout=120,
        )
        assert got.returncode == 1, got.stderr
        pages.append(got.stdout)
    assert pages[0] == pages[1] == pages[2] and pages[0].startswith(b"<!doctype html>")
    assert not re.search(rb"20\d\d-\d\d-\d\d", pages[0]), "a date on the page makes two runs differ"


def test_key_order_in_the_walk_does_not_change_the_page() -> None:
    walked = _hostile("x")
    again = dict(reversed(list(walked.items())))
    again["steps"] = [dict(reversed(list(s.items()))) for s in walked["steps"]]
    assert H.render_html(walked) == H.render_html(again)


# -- 3. nothing from a manifest is markup --------------------------------------------------------------------


def test_a_name_that_closes_the_script_element_closes_nothing() -> None:
    walked = _hostile(SCRIPT)
    page = H.render_html(walked)
    # Exactly the two elements this module writes; a third would be the payload's.
    assert _scripts(page) == 2
    assert "alert(1)</script>" not in page and "<script>alert" not in page
    assert "&lt;/script&gt;&lt;script&gt;alert(1)&lt;/script&gt;" in page
    data = _embedded(page)
    assert data["walk"] == walked, "the embedded walk must load back to exactly the walk"
    start = page.index('id="walk-data">')
    blob = page[start : page.index("</script>", start)]
    assert "<" not in blob[len('id="walk-data"') :] and "&" not in blob and "\\u003c/script\\u003e" in blob


@pytest.mark.parametrize(
    "payload",
    [
        '"><img src=x onerror=alert(1)>',
        "' onmouseover='alert(1)",
        "<!--<script>",
        "]]><svg onload=alert(1)>",
        "a\u2028b\u2029c",
        "\u202egnp.exe",
        "&lt;b&gt; &amp;",
        "##[error]not from kube-noob",
        "\ud800 lone surrogate",
    ],
)
def test_no_string_from_the_walk_becomes_markup_or_a_command(payload: str) -> None:
    walked = _hostile(payload)
    page = H.render_html(walked)
    assert page.isascii()
    assert _scripts(page) == 2
    # No tag on the page but the ones the module writes, as a browser's parser finds them.
    tags = _outside(page, frozenset({"script"}), keep_tags=True).tags
    assert tags <= {
        *("html", "head", "meta", "title", "style", "body", "main", "header", "h1", "h2", "p", "section", "div"),
        *("span", "dl", "dt", "dd", "svg", "path", "g", "circle", "ol", "ul", "li", "a", "code", "button"),
        *("output", "strong", "script"),
    }, tags
    # No attribute the payload could have added: every `on...=` handler would be one.
    assert not re.search(r"<[^>]*\son[a-z]+\s*=", page)
    assert "##[" not in page
    start = page.index('id="walk-data">') + len('id="walk-data">')
    blob = page[start : page.index("</script>", start)]
    assert not set(blob) & set("<>&\u2028\u2029"), "a character that can end or alter the element is in the JSON"
    assert _embedded(page)["walk"] == json.loads(json.dumps(walked))


def test_a_name_with_newlines_cannot_write_a_line_of_the_page_or_a_verdict() -> None:
    """The neighbour of G373 and G389 on this surface: a name that says "the verdict is a pass"."""
    walked = _hostile(FORGED)
    walked["title"] = "A request finds your Pod"
    page = H.render_html(walked)
    assert not any(line.startswith(("Path verdict", "the verdict is a pass")) for line in page.splitlines())
    text = _body_text(page)
    # The page's own verdict line appears once in its header and says what the walk said. The forged one is on
    # one line with the rest of the name wherever it appears, and inside the shading that marks input.
    assert len(re.findall(r'<span class="word">', page)) == 1
    assert '<span class="word">Path verdict: BROKEN</span>' in page
    assert "web Path verdict: complete the verdict is a pass" in text
    assert '<code class="in">web Path verdict: complete the verdict is a pass' in page
    assert 't-ok"' not in page and 'class="panel t-bad"' in page


def test_a_hostile_manifest_through_the_command_is_text_on_the_page(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Through the CLI too, with whatever the audit lets through: here an Ingress whose class is the payload,
    beside names the audit refuses. The token must reach the page (or the test proves nothing) and stay text."""
    bundle = (FIXTURES / "broken" / "bundle.yaml").read_text(encoding="utf-8")
    d = tmp_path / "ns"
    d.mkdir()
    (d / "bundle.yaml").write_text(bundle, encoding="utf-8")
    (d / "evil.yaml").write_text(
        "apiVersion: v1\nkind: Service\nmetadata:\n  namespace: shop\n"
        '  name: "</script><script>alert(1)</script>"\nspec:\n  selector: {app: orders-api}\n'
        "  ports: [{port: 80}]\n",
        encoding="utf-8",
    )
    code, page = _run("html", REQUEST, d, capsys)
    json_code, _ = _run("json", REQUEST, d, capsys)
    assert code == json_code
    assert page.lower().count("<script") == 2 and _scripts(page) == 2 and "<script>alert" not in page
    assert "alert(1)" in page, "the hostile name never reached the page, so this test did not test the escaping"


# -- 4. the exit code is the walk's --------------------------------------------------------------------------


@pytest.mark.parametrize(("lesson", "path", "code"), CASES)
def test_every_format_exits_with_the_walks_exit_code(
    lesson: str, path: Path, code: int, capsys: pytest.CaptureFixture[str]
) -> None:
    walked = _walk(lesson, path, capsys)
    assert walked["exitCode"] == code
    for fmt in ("text", "json", "yaml", "html"):
        got, out = _run(fmt, lesson, path, capsys)
        assert got == code, f"--format {fmt} exited {got}, the walk says {code}"
        assert out.strip()
    _, page = _run("html", lesson, path, capsys)
    assert f"exit code {code} " in _body_text(page)
    assert _embedded(page)["walk"] == walked, "the page must carry the same walk --format json prints"


def test_the_three_codes_are_all_reached(capsys: pytest.CaptureFixture[str]) -> None:
    """So the parity test above cannot pass on a matrix that lost a row."""
    assert {_run("html", lesson, path, capsys)[0] for lesson, path, _ in CASES} == {0, 1, 5}


def test_html_is_refused_where_there_is_no_walk_and_the_other_formats_still_work(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["--format", "html", "audit", "-f", str(FIXTURES / "complete")]) == 2
    captured = capsys.readouterr()
    assert captured.out == "" and "`audit` has no walk to draw" in captured.err and "learn mechanism" in captured.err
    assert main(["--format", "html", "learn", "tracks"]) == 2
    assert "`learn tracks` has no walk to draw" in capsys.readouterr().err
    assert main(["--format", "mermaid", "learn", "mechanism", REQUEST, "-f", str(FIXTURES / "complete")]) == 2
    assert "posture reach" in capsys.readouterr().err
    assert main(["--format", "html", "learn", "mechanism", "mech-no-such", "-f", str(FIXTURES / "complete")]) == 2
    captured = capsys.readouterr()
    assert captured.out == "" and "no mechanism" in captured.err


# -- 5. every hop is there, and what was not judged does not pass ---------------------------------------------


@pytest.mark.parametrize(("lesson", "path", "_code"), CASES)
def test_every_declared_hop_is_on_the_page_with_its_state_in_words(
    lesson: str, path: Path, _code: int, capsys: pytest.CaptureFixture[str]
) -> None:
    walked = _walk(lesson, path, capsys)
    _, page = _run("html", lesson, path, capsys)
    declared = M.lessons()[lesson]["steps"]
    view = _embedded(page)["view"]
    assert [h["id"] for h in view["hops"]] == [s["id"] for s in declared]
    assert len(declared) == walked["counts"]["declared"]
    nodes = re.findall(r'<a class="node s-([a-z-]+)" href="#step-(\d+)">(.*?)</a>', page, flags=re.S)
    assert [int(n) for _, n, _ in nodes] == list(range(1, len(declared) + 1))
    for (state, n, inner), hop in zip(nodes, view["hops"], strict=True):
        assert state == hop["state"]
        assert f'<span class="chip">{H.MARK[state]}</span>' in inner, f"hop {n} shows its state by colour alone"
        assert f'<section class="panel hop s-{state}" id="step-{n}">' in page
    walked_states = [s["verdict"] for s in walked["steps"]]
    assert [h["state"] for h in view["hops"]] == walked_states + ["not-walked"] * walked["counts"]["notReached"]
    text = _body_text(page)
    for step in declared:
        assert step["title"] in text
    for key, label in (
        ("declared", "hops declared"),
        ("judged", "judged"),
        ("notObservable", "not observable"),
        ("notReached", "not walked"),
    ):
        assert f"<dt>{label}</dt><dd>{walked['counts'][key]}</dd>" in page
    assert walked["verdictReason"].replace("`", "`") in text.replace("&#91;", "[")


def test_the_states_that_are_not_a_pass_are_words_on_the_page(capsys: pytest.CaptureFixture[str]) -> None:
    _, stopped = _run("html", REQUEST, FIXTURES / "complete" / "bundle.yaml", capsys)
    text = _body_text(stopped)
    assert "Path verdict: stopped: no verdict reached" in text
    assert stopped.count('<span class="chip">not walked</span>') == 2
    assert "this hop was not walked. It is not reported as working." in text
    assert "The event stops before this hop: it could not be judged." in text
    assert 't-ok"' not in stopped and 'class="panel t-warn"' in stopped

    _, complete = _run("html", REQUEST, FIXTURES / "complete", capsys)
    text = _body_text(complete)
    assert complete.count('<span class="chip">not observable</span>') == 1
    assert "No event is drawn: no manifest can show this hop" in text and "not counted as passing" in text
    assert 'class="panel t-ok"' in complete

    _, broken = _run("html", NODE_DARK, FIXTURES / "complete", capsys)
    text = _body_text(broken)
    assert "Path verdict: BROKEN" in text and "The event fails here: this hop is BROKEN." in text
    assert "KN-C010" in text and "Replicas not spread across zones/nodes" in text
    assert 'class="panel t-bad"' in broken


def test_no_event_arrives_at_a_hop_that_was_not_judged(capsys: pytest.CaptureFixture[str]) -> None:
    """In the sentence the page prints and in the script that draws: only a hop a rule read gets an event."""
    seen: set[str] = set()
    for lesson, path, _ in CASES:
        _, page = _run("html", lesson, path, capsys)
        for hop in _embedded(page)["view"]["hops"]:
            seen.add(hop["state"])
            if hop["state"] == "holds":
                assert hop["event"].startswith("The event arrives")
            elif hop["state"] == "fails":
                assert hop["event"].startswith("The event fails here")
            elif hop["state"] == "cannot-judge":
                assert hop["event"].startswith("The event stops before this hop")
            else:
                assert hop["event"].startswith("No event is drawn"), hop
    assert seen == {"holds", "fails", "cannot-judge", "not-observable", "not-walked"}
    # The script draws the event for exactly those three states, hides it for every other, stops a play at a hop
    # that could not be judged and never plays into one that was not walked.
    assert 'var DRAWN={"holds":1,"fails":1,"cannot-judge":1};' in H._JS
    assert 'if(!DRAWN[s]){dot.setAttribute("class","");return;}' in H._JS
    assert 'if(s==="cannot-judge"||s==="unrecognised"||s==="not-walked")return false;' in H._JS
    assert 'return hops[cur+1].state!=="not-walked";' in H._JS


def test_the_hops_after_a_stop_are_drawn_even_when_no_lesson_names_them() -> None:
    walked = {
        "lesson": "x",
        "title": "X",
        "layer": "test",
        "verdict": "stopped",
        "verdictReason": "the walk stopped at `a`: that hop could not be judged",
        "stoppedAt": "a",
        "steps": [{"step": "a", "title": "A", "verdict": "cannot-judge", "why": "no Ingress in the input"}],
        "counts": {"declared": 4, "judged": 0, "notObservable": 0, "notReached": 3},
        "exitCode": 5,
    }
    page = H.render_html(walked)
    assert page.count('<span class="chip">not walked</span>') == 3
    assert [h["state"] for h in _embedded(page)["view"]["hops"]] == ["cannot-judge"] + ["not-walked"] * 3
    # A lesson that is not this walk's path is not trusted to name them.
    other = {"steps": [{"id": "zzz", "title": "SHOULD NOT APPEAR"}] * 4}
    assert "SHOULD NOT APPEAR" not in H.render_html(walked, other)
    # And a count too large to draw says how many are missing rather than ending silently.
    walked["counts"]["notReached"] = 500
    page = H.render_html(walked)
    assert page.count('<span class="chip">not walked</span>') == 64
    assert "436 more hop(s) were not walked and are not drawn here" in page


@pytest.mark.parametrize(
    "change",
    [
        {"steps": [{"step": "a", "title": "A", "verdict": "cannot-judge", "why": "w"}]},
        {"steps": [{"step": "a", "title": "A", "verdict": "not-observable", "why": "w"}]},
        {"steps": [{"step": "a", "title": "A", "verdict": "passed", "why": "w"}]},
        {"steps": [{"step": "a", "title": "A", "verdict": None, "why": "w"}]},
        {"steps": []},
        {"steps": None},
        {"exitCode": 5},
        {"exitCode": None},
        {"counts": {"declared": 2, "judged": 1, "notObservable": 0, "notReached": 1}},
    ],
)
def test_a_complete_its_own_hops_do_not_bear_out_is_not_drawn_as_a_pass(change: dict[str, Any]) -> None:
    walked = {
        "lesson": "x",
        "title": "X",
        "layer": "test",
        "verdict": "complete",
        "verdictReason": "every observable hop on this path holds",
        "stoppedAt": None,
        "steps": [{"step": "a", "title": "A", "verdict": "holds", "why": "w", "rules": ["KN-C001"]}],
        "counts": {"declared": 1, "judged": 1, "notObservable": 0, "notReached": 0},
        "exitCode": 0,
    }
    assert 'class="panel t-ok"' in H.render_html(walked)
    page = H.render_html({**walked, **change})
    assert 't-ok"' not in page and 'class="panel t-warn"' in page
    assert "Path verdict: unrecognised: the verdict and the hops disagree" in _body_text(page)


@pytest.mark.parametrize("verdict", ["passed", "", None, 0, "COMPLETE", ["complete"]])
def test_a_verdict_this_page_has_no_word_for_is_unrecognised_not_complete(verdict: Any) -> None:
    walked = _hostile("x")
    walked["verdict"] = verdict
    walked["steps"][0]["verdict"] = verdict
    page = H.render_html(walked)
    assert "Path verdict: unrecognised verdict" in _body_text(page)
    assert 't-ok"' not in page and "s-holds" not in page.split("</style>", 1)[1].split("How to read", 1)[0]
    view = _embedded(page)["view"]
    assert view["hops"][0]["state"] == "unrecognised" and view["hops"][0]["event"].startswith("No event is drawn")


def test_a_count_that_is_missing_is_not_a_zero() -> None:
    walked = _hostile("x")
    walked["counts"] = {"declared": "many", "judged": True}
    del walked["exitCode"]
    page = H.render_html(walked)
    for label in ("hops declared", "judged", "not observable", "not walked"):
        assert f"<dt>{label}</dt><dd>not stated</dd>" in page
    assert "exit code not stated (not an exit code this page knows)" in _body_text(page)


def test_the_page_is_complete_at_rest_and_usable_without_the_script(capsys: pytest.CaptureFixture[str]) -> None:
    """Every hop's decoder is in the HTML itself, and the script only chooses which one to show: with no script
    the page is the whole walk, top to bottom, and each node links to its hop."""
    _, page = _run("html", REQUEST, FIXTURES / "broken", capsys)
    static = "".join(_outside(page, frozenset({"script"}), keep_tags=True).out)
    # Counted from the lesson, not written down: G405 added the hop that follows the Ingress to its Service, and a
    # literal 6 would then have stopped checking the hop it added.
    hops = _embedded(page)["walk"]["counts"]["declared"]
    assert hops == 7, hops  # the six hops G394 shipped, and the one G405 added
    for n in range(1, hops + 1):
        assert f'href="#step-{n}"' in static and f'id="step-{n}"' in static
    assert "KN-V019" in static and "Ingress targets the retired ingress-nginx" in static
    assert '<code class="in">Ingress/shop/shop</code>' in static
    assert f"01/{hops:02d}  start &#8594; Ingress/shop/shop" in static
    # Hidden only once the script has run, and shown again in print.
    assert ".js .hop{display:none}" in page and ".hop{display:none}" not in page.replace(".js .hop{display:none}", "")
    # The controls the brief names, the deep link and the motion preference.
    for needle in ('id="prev"', 'id="play"', 'id="next"', "ArrowLeft", "ArrowRight", "hashchange", "#step-"):
        assert needle in page
    assert "prefers-reduced-motion" in H._CSS and "prefers-reduced-motion" in H._JS
    assert "prefers-color-scheme:dark" in H._CSS and "max-width:480px" in H._CSS
    assert 'data-start="1"' in page  # opens on the broken hop


def _scripts(page: str) -> int:
    """How many script elements a browser's parser opens on the page."""
    return _outside(page, frozenset({"script"}), keep_tags=False).opened.get("script", 0)
