"""Video scripts never type a number: counts, scores, line numbers and terminal lines come from the code when a video
is built (demos/video/facts.py), videos.json passes its schema, and every rule a script names is real and is what the
audit of the example finds."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

import jsonschema
import pytest

ROOT = Path(__file__).resolve().parents[1]
VIDEO = ROOT / "demos" / "video"
TRANSCRIPT = ROOT / "tests" / "fixtures" / "video-sidecar-transcript.txt"  # recorded in CI run 40812189249 (0.6.0)
sys.path.insert(0, str(VIDEO))
sys.path.insert(0, str(VIDEO / "stage"))

import facts as vfacts  # noqa: E402

# Numbers that are not counts: platform versions, a port, an exit code, a UID in the example, the time of day.
FIXED = [
    r"OpenShift \d\.\d\d( and later)?",
    r"OCP \d\.\d\d",
    r"4\.22",
    r"127\.0\.0\.1(:8080)?",
    r"(port |:)8080",
    r"exit( code)? 137",
    r"runAsUser: 1000",
    r"2 a\.m\.",
    r"\b(16:9|1:1|9:16)\b",
    r"\b\d+ (s|seconds)\b",
    r"/100\b",
    r"out of 100",
    r"\btop 3\b",  # what the prompt in the Claude video asks for
    r"^\d+\. ",  # a numbered step on screen
    r"\[kn:[^\]]+\]",  # a citation id
]
SPOKEN_FIXED = ["four twenty-two", "four point twenty", "one thirty-seven", "two in the morning", "two commands"]
NUMBER_WORD = re.compile(r"\b(twenty|thirty|forty|fifty|sixty|seventy|eighty|ninety|hundred|thousand)\b", re.I)


@pytest.fixture(scope="module")
def facts() -> vfacts.Facts:
    return vfacts.Facts(TRANSCRIPT)


def _spec() -> dict[str, Any]:
    return json.loads((VIDEO / "stage" / "videos.json").read_text(encoding="utf-8"))  # type: ignore[no-any-return]


def _typed_numbers(text: str) -> list[str]:
    t = vfacts.PLACEHOLDER.sub("", text)
    for pattern in FIXED:
        t = re.sub(pattern, "", t, flags=re.I)
    for phrase in SPOKEN_FIXED:
        t = t.replace(phrase, "")
    return re.findall(r"\b\d+(?:\.\d+)?\b", t) + NUMBER_WORD.findall(t)


def _script_texts() -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for name, v in _spec()["videos"].items():
        for i, s in enumerate(v["scenes"]):
            for k in ("caption", "vo", "say", "bubble"):
                if k in s:
                    out.append((f"videos.json {name}[{i}].{k}", s[k]))
            for line in s.get("term", []) + s.get("answer", []):
                if not vfacts.RECORDING.match(line):
                    out.append((f"videos.json {name}[{i}] line", line))
    walk = (ROOT / "demos" / "youtube-walkthrough.md").read_text(encoding="utf-8")
    rendered = walk.split("## Voice-over for the rendered cut", 1)[1].split("\n## ", 1)[0]
    out += [("walkthrough voice-over", m) for m in re.findall(r"^\| \d+:\d\d \| (.+?) \|$", rendered, re.M)]
    for doc in ("youtube-walkthrough.md", "ai-video-prompts.md"):
        for line in (ROOT / "demos" / doc).read_text(encoding="utf-8").splitlines():
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if line.startswith("| ") and len(cells) == 5 and cells[0].isdigit():
                out += [(f"{doc} row {cells[0]} on-screen", cells[3]), (f"{doc} row {cells[0]} voice-over", cells[4])]
    chapters = walk.split("Chapters\n", 1)[1].split("```", 1)[0]
    out += [("walkthrough chapters", re.sub(r"^\d+:\d\d ", "", ln)) for ln in chapters.splitlines()]
    return out


def test_scripts_type_no_counts_scores_or_line_numbers() -> None:
    typed = [(where, text, nums) for where, text in _script_texts() if (nums := _typed_numbers(text))]
    assert not typed, "write these as {facts} (demos/video/facts.py): " + "; ".join(
        f"{w}: {n} in {t[:70]!r}" for w, t, n in typed
    )


def test_every_placeholder_and_recording_resolves(facts: vfacts.Facts) -> None:
    import video_script  # demos/video/stage: needs no voice model or numpy

    for name in _spec()["videos"]:
        v = video_script.load(name, facts)
        blob = json.dumps(v, ensure_ascii=False)
        assert not vfacts.PLACEHOLDER.search(blob) and '"@' not in blob, name
    for doc in ("youtube-walkthrough.md", "ai-video-prompts.md"):
        assert not vfacts.PLACEHOLDER.search(facts.fill((ROOT / "demos" / doc).read_text(encoding="utf-8"))), doc
    with pytest.raises(vfacts.FactError, match="unknown fact"):
        facts.fill("{audit.nope}")


def test_facts_match_the_code_and_the_recorded_transcript(facts: vfacts.Facts) -> None:
    from kube_noob import __version__
    from kube_noob.audit.engine import list_rules

    assert facts.get("rules") == len(list_rules()) and facts.get("version") == __version__
    assert facts.get("audit.score") < facts.get("fix.score") <= 100 and facts.get("audit.high") >= 1
    assert (facts.get("sidecar.tools"), facts.get("sidecar.peak"), facts.get("sidecar.limit")) == (41, 92, 256)
    cli = facts.recording("cli:audit")
    assert f"score={float(facts.get('audit.score'))}" in cli[1] and sum(ln.startswith("[HIGH") for ln in cli) == 3
    assert f"high={facts.get('audit.high')}" in cli[1] and facts.get("audit.critical") == 0  # same count as on screen
    tool = "\n".join(facts.recording("tool:audit"))
    assert f"score {facts.get('audit.score')} · high {facts.get('audit.high')}" in tool
    assert f"score after the automatic fixes: {facts.get('fix.score')}" in tool
    client = facts.recording("sidecar:client")
    assert client[0].startswith("$ kubectl") and "41 tools" in client[1] and client[-1].startswith("pod IP")
    assert vfacts.words(63) == "sixty-three" and vfacts.words(256) == "two hundred and fifty-six"


def test_sidecar_facts_fail_loudly_without_the_ci_transcript(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KN_SIDECAR_TRANSCRIPT", raising=False)
    with pytest.raises(vfacts.FactError, match="KN_SIDECAR_TRANSCRIPT"):
        vfacts.Facts().get("sidecar.peak")


def test_the_sidecar_limit_is_the_manifests_and_a_failed_run_is_refused(tmp_path: Path) -> None:
    script = (ROOT / "scripts" / "demo_sidecar_kind.sh").read_text(encoding="utf-8")
    assert "memory.max" in script and "limit 256" not in script  # read from the cgroup, not typed
    assert vfacts._manifest_limit_mib() == 256
    text = TRANSCRIPT.read_text(encoding="utf-8")
    for bad, why in (
        (text.replace("limit 256 MiB", "limit 512 MiB"), "512 MiB there, 256 MiB in"),
        (text.replace("port 8080: closed", "port 8080: OPEN"), "not shown closed"),
    ):
        (tmp_path / "t.txt").write_text(bad, encoding="utf-8")
        with pytest.raises(vfacts.FactError, match=why):
            vfacts.Facts(tmp_path / "t.txt").get("sidecar.limit")


def test_facts_describe_the_product_tree_and_fail_loudly_without_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    assert vfacts.PRODUCT == ROOT  # videos.yml points KN_PRODUCT_ROOT at the release tag's checkout
    monkeypatch.setattr(vfacts, "PRODUCT", tmp_path)
    with pytest.raises(vfacts.FactError, match=r"insecure-deployment\.yaml not found"):
        vfacts.Facts().get("audit.score")


def test_claudes_answer_quotes_the_example_and_the_audit(facts: vfacts.Facts) -> None:
    import yaml

    docs = list(yaml.safe_load_all((ROOT / vfacts.EXAMPLE).read_text(encoding="utf-8")))
    dep = next(d for d in docs if d["kind"] == "Deployment")
    svc = next(d for d in docs if d["kind"] == "Service")
    env = {e["name"]: e.get("value") for c in dep["spec"]["template"]["spec"]["containers"] for e in c.get("env", [])}
    answer = "\n".join(next(s for s in _spec()["videos"]["mcp"]["scenes"] if s["kind"] == "explain")["answer"])
    assert f"DB_PASSWORD: {env['DB_PASSWORD']}" in answer
    pods = dep["spec"]["template"]["metadata"]["labels"]["app"]
    assert f"selector is app: {svc['spec']['selector']['app']}, but the pods are app: {pods}" in answer
    severity = {
        m.group(2): {"CRIT": "critical", "HIGH": "high", "MED": "medium"}[m.group(1)]
        for m in (re.match(r"  (CRIT|HIGH|MED) +(KN-[A-Z]+\d+)", ln) for ln in facts.recording("tool:audit"))
        if m
    }
    claimed = re.findall(r"\(((?:KN-[A-Z]+\d+(?: and )?)+), (high|medium)\)", answer)
    assert len(claimed) == 3
    for ids, sev in claimed:
        assert all(severity.get(i) == sev for i in ids.split(" and ")), (ids, sev, severity)


def test_a_cut_recording_says_so_on_screen(facts: vfacts.Facts) -> None:
    import build_scenes

    cut = r"… \d+ medium and low findings, and the fix, RHACS and red-team lines, left out"
    assert re.fullmatch(cut, facts.recording("cli:audit")[-1])
    steps = build_scenes.parse_transcript("# c\n$ cmd\n" + "\n".join(f"line {i}" for i in range(12)), 9)
    assert steps[0]["output"][9:] == ["… 3 more lines"]
    assert build_scenes.parse_transcript("# c\n$ cmd\nok", 9)[0]["output"] == ["ok"]
    player = (VIDEO / "player.html").read_text(encoding="utf-8")
    assert "(why:|… )" in player  # the walkthrough draws the marker dim, like a why: line
    stage = (VIDEO / "stage" / "stage.html").read_text(encoding="utf-8")
    assert "line.startsWith('… ')" in stage


def test_memory_quantities_read_as_the_cgroup_does(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    manifest = (ROOT / vfacts.SIDECAR_MANIFEST).read_text(encoding="utf-8")
    (tmp_path / "deploy" / "sidecar").mkdir(parents=True)
    monkeypatch.setattr(vfacts, "PRODUCT", tmp_path)
    for quantity, mib in (
        ("256Mi", 256),
        ("1Gi", 1024),
        ("0.5Gi", 512),
        ("268435456", 256),
        ("512M", 488),
        ("1Ti", 2**20),
    ):
        text = manifest.replace("limits: {memory: 256Mi}}", f"limits: {{memory: {quantity}}}}}")
        (tmp_path / vfacts.SIDECAR_MANIFEST).write_text(text, encoding="utf-8")
        assert vfacts._manifest_limit_mib() == mib, quantity
    (tmp_path / vfacts.SIDECAR_MANIFEST).write_text(
        manifest.replace(", limits: {memory: 256Mi}}", "}"), encoding="utf-8"
    )
    with pytest.raises(vfacts.FactError, match="is not a quantity"):
        vfacts._manifest_limit_mib()


def test_rhacs_claims_are_qualified() -> None:
    # Only the findings of rules that map to an RHACS policy carry one (16 of the rules at 0.6.0)
    for script in (ROOT / "demos" / "youtube-walkthrough.md", VIDEO / "stage" / "videos.json"):
        for line in script.read_text(encoding="utf-8").splitlines():
            if re.search(r"RHACS policy (it|that) would", line):
                assert "where there is one" in line, (script.name, line)


def test_the_text_to_video_prompts_say_what_the_rendered_videos_say() -> None:
    doc = (ROOT / "demos" / "ai-video-prompts.md").read_text(encoding="utf-8")
    sections = re.split(r"(?m)^## Video \d+:.*$", doc)[1:]
    spec = _spec()["videos"]
    assert len(sections) == len(spec)
    for name, body in zip(spec, sections, strict=True):
        rows = [ln.strip("| ").split(" | ") for ln in body.splitlines() if re.match(r"^\| \d+ \|", ln)]
        scenes = [s for s in spec[name]["scenes"] if s["kind"] != "end"]
        assert [(r[3].replace("`", ""), r[4]) for r in rows] == [(s["caption"], s["vo"]) for s in scenes], name


def test_the_payoff_scene_shows_the_real_audit_and_fix(facts: vfacts.Facts) -> None:
    pay = facts.payoff()
    lines = (ROOT / vfacts.EXAMPLE).read_text(encoding="utf-8").splitlines()
    assert pay["yaml"] and all(lines[r["n"] - 1] == r["text"] for r in pay["yaml"])
    shown = {r["n"] for r in pay["yaml"]}
    tool = "\n".join(facts.recording("tool:audit"))
    for f in pay["findings"]:
        assert f["line"] in shown and f"{f['rule']}  line {f['line']}" in tool, f  # the same findings as on screen
    assert set(pay["fixedLines"]) <= {f["line"] for f in pay["findings"] if f["severity"] == "high"}
    assert (pay["score"], pay["fixed"], pay["manual"]) == (
        facts.get("audit.score"),
        facts.get("fix.score"),
        facts.get("fix.manual"),
    )
    assert pay["diff"] and all(d["op"] in "+-" for d in pay["diff"])
    payoff = next(s for s in _spec()["videos"]["mcp"]["scenes"] if s["kind"] == "payoff")
    assert "{audit.score}" in payoff["caption"] and "{fix.score}" in payoff["caption"]


def test_rules_a_script_names_are_real_and_found_in_the_example(facts: vfacts.Facts) -> None:
    from kube_noob.audit.engine import list_rules

    real = {r["ruleId"] for r in list_rules()}
    found = set(re.findall(r"KN-[A-Z]+\d+", "\n".join(facts.recording("tool:audit"))))
    spec = json.dumps(_spec()["videos"]["mcp"]) + json.dumps(_spec()["videos"]["teaser"])
    named = set(re.findall(r"KN-[A-Z]+\d+", spec))
    assert named <= real and named <= found, named - found  # Claude's answer must match what the tools return


def test_videos_json_passes_its_schema_and_the_schema_knows_every_scene_kind() -> None:
    schema = json.loads((VIDEO / "stage" / "videos.schema.json").read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    assert not list(jsonschema.Draft202012Validator(schema).iter_errors(_spec()))
    stage = (VIDEO / "stage" / "stage.html").read_text(encoding="utf-8")
    start = stage.index("const KINDS = {")
    body = stage[start : stage.index("\n/* --", start)]
    kinds = re.findall(r"^  (\w+)\(L, dur, sc, T\)", body, re.M)
    assert set(kinds) == set(schema["$defs"]["scene"]["properties"]["kind"]["enum"])
    bad = json.loads(json.dumps(_spec()))
    bad["videos"]["teaser"]["scenes"][0]["vo"] = "Link below."
    bad["videos"]["teaser"]["scenes"].append({"kind": "nope", "min": 1})
    assert len(list(jsonschema.Draft202012Validator(schema).iter_errors(bad))) >= 2


def _walk_run(path: str) -> tuple[int, dict[str, Any]]:
    import subprocess

    r = subprocess.run(
        [sys.executable, "-m", "kube_noob", "learn", "mechanism", vfacts.WALK_LESSON, "-f", path, "--format", "json"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    return r.returncode, json.loads(r.stdout)


def test_the_walk_video_draws_the_hops_the_command_grades(facts: vfacts.Facts) -> None:
    """Every hop, mark, reason and exit code in the walk video is the command's own, on the three inputs it shows."""
    assert set(vfacts.WALKS) == {"complete", "broken", "fragment"}
    for name, path in vfacts.WALKS.items():
        code, real = _walk_run(path)
        shown = facts.walk(name)
        assert shown["exit"] == code == real["exitCode"], name
        assert shown["command"] == f"kube-noob learn mechanism {vfacts.WALK_LESSON} -f {path}"
        assert (shown["title"], shown["reason"]) == (real["title"], real["verdictReason"])
        assert len(shown["steps"]) == real["counts"]["declared"]
        walked = shown["steps"][: len(real["steps"])]
        assert [(s["id"], s["state"], s["why"]) for s in walked] == [
            (s["step"], s["verdict"], s["why"]) for s in real["steps"]
        ]
        for s, r in zip(walked, real["steps"], strict=True):
            assert all(f["ruleId"] in s["finding"] and f["title"] in s["finding"] for f in r.get("findings", [])), s
    spelt = {s["state"]: s["mark"] for name in vfacts.WALKS for s in facts.walk(name)["steps"]}
    assert spelt == {
        "holds": "holds",
        "fails": "BROKEN",
        "cannot-judge": "cannot judge",
        "not-observable": "not checked",
        "not-walked": "not walked",
    }  # the words `learn mechanism` prints, read from its output; only `not walked` has no mark of its own there


def test_a_hop_the_walk_did_not_reach_is_never_drawn_as_holding(facts: vfacts.Facts) -> None:
    code, real = _walk_run(vfacts.WALKS["fragment"])
    shown = facts.walk("fragment")
    assert code == 5 and real["stoppedAt"]
    after = shown["steps"][len(real["steps"]) :]
    assert len(after) == real["counts"]["notReached"] == facts.get("walk.unwalked") >= 1
    assert all(s["state"] == "not-walked" and s["mark"] != "holds" and not s["why"] for s in after)
    assert shown["steps"][shown["focus"]]["id"] == real["stoppedAt"]
    assert shown["note"] == f"{len(after)} hop(s) after it were not walked and are not reported as working."
    # ... and a hop no manifest records is not counted with the ones that hold
    done = facts.walk("complete")
    assert facts.get("walk.holds") == sum(s["state"] == "holds" for s in done["steps"]) >= 1
    assert facts.get("walk.unchecked") == sum(s["state"] == "not-observable" for s in done["steps"]) >= 1
    assert facts.get("walk.holds") + facts.get("walk.unchecked") == facts.get("walk.hops") == len(done["steps"])
    assert done["steps"][done["focus"]]["state"] == "not-observable"


def test_the_walk_facts_are_the_story_the_video_tells(facts: vfacts.Facts) -> None:
    assert [facts.get(f"walk.{n}_exit") for n in ("complete", "broken", "fragment")] == [0, 1, 5]
    broken = facts.walk("broken")
    hop = broken["steps"][broken["focus"]]
    assert hop["state"] == "fails" and facts.get("walk.broken_rule") in hop["finding"]
    assert facts.get("walk.judged") == sum(s["state"] == "holds" for s in facts.walk("fragment")["steps"])
    bundle = facts.recording("walk:bundle")
    assert bundle[0].startswith("# ") and [ln.split()[0] for ln in bundle[1:]] == [
        "Ingress",
        "Service",
        "Deployment",
        "NetworkPolicy",
    ]


def test_the_walk_video_refuses_to_render_a_story_the_command_no_longer_tells(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    whole, part = vfacts.WALKS["complete"], vfacts.WALKS["fragment"]
    for swapped, why in (
        ({"complete": vfacts.WALKS["broken"]}, "no longer holds on every hop"),
        ({"complete": part}, "no longer holds on every hop"),
        ({"broken": whole}, "no hop is BROKEN"),
        ({"fragment": whole}, "no longer stops"),
    ):
        monkeypatch.setattr(vfacts, "WALKS", {**vfacts.WALKS, **swapped})
        with pytest.raises(vfacts.FactError, match=why):
            vfacts.Facts().get("walk.hops")
        monkeypatch.undo()


def test_a_hops_scene_names_the_walk_it_draws_and_the_stage_marks_every_state() -> None:
    schema = json.loads((VIDEO / "stage" / "videos.schema.json").read_text(encoding="utf-8"))
    spec = _spec()
    drawn = [s["walk"] for s in spec["videos"]["walk"]["scenes"] if s["kind"] == "hops"]
    assert drawn == ["complete", "broken", "fragment"]
    bad = json.loads(json.dumps(spec))
    del next(s for s in bad["videos"]["walk"]["scenes"] if s["kind"] == "hops")["walk"]
    assert list(jsonschema.Draft202012Validator(schema).iter_errors(bad))
    stage = (VIDEO / "stage" / "stage.html").read_text(encoding="utf-8")
    for state in ("holds", "fails", "cannot-judge", "not-observable", "not-walked"):
        assert f".hops .{state} " in stage, state  # each state has a look of its own; none borrows `holds`
    assert "esc(s.mark)" in stage  # the word under a hop is the command's, not the stage's
