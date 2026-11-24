from __future__ import annotations

from pathlib import Path

import pytest

from kube_noob.evals.checks import evaluate
from kube_noob.generate.blueprint import Blueprint
from kube_noob.generate.manifests import generate
from kube_noob.knowledge.store import extract_citations, get_store, tokenize
from kube_noob.learn.tutor import Tutor, curriculum, exercises, lessons, quizzes


def test_builtin_knowledge_loaded() -> None:
    store = get_store()
    stats = store.stats()
    assert stats["documents"] >= 28 and stats["byOrigin"] == {"builtin": stats["chunks"]}
    top = store.search("ReadWriteMany gp3-csi pending EFS", limit=3)
    assert top[0].chunk.doc_id in {"rosa-efs", "storage-access-modes", "rosa-hcp"}
    route = store.search("Route apiVersion route.openshift.io reencrypt", limit=1)[0]
    assert route.chunk.doc_id == "ocp-routes"


def test_tokenizer_keeps_compound_terms() -> None:
    toks = tokenize("gp3-csi route.openshift.io/v1")
    assert "gp3-csi" in toks and "gp3" in toks and "route.openshift.io/v1" in toks


def test_curriculum_integrity() -> None:
    store = get_store()
    ex_ids = set(exercises())
    for les in lessons().values():
        for d in les.get("docs", []):
            assert store.doc(d), f"lesson {les['id']} -> missing doc {d}"
        for e in les.get("exercises", []):
            assert e in ex_ids, f"lesson {les['id']} -> missing exercise {e}"
    for q in quizzes().values():
        assert 0 <= q["answer"] < len(q["choices"])
        assert store.get(q["source"]) is not None, q["source"]
    # The count is a floor, not a pin: a new track is a feature, and a test that fails on one teaches the
    # next person to edit the number rather than to check the track. What matters is that every track has
    # lessons and that the ids are unique, which the loop above holds.
    tracks = curriculum()["tracks"]
    assert len(tracks) >= 5 and len({t["id"] for t in tracks}) == len(tracks)
    assert all(t.get("lessons") for t in tracks), [t["id"] for t in tracks if not t.get("lessons")]


@pytest.mark.parametrize("ex_id", [e for e, x in exercises().items() if x.get("reference")])
def test_reference_solutions_pass(ex_id: str) -> None:
    ex = exercises()[ex_id]
    y = generate(Blueprint.model_validate(ex["reference"])).yaml()
    ev = evaluate(y, ex["checks"])
    assert ev.passed, [o.as_dict() for o in ev.outcomes if not o.passed]


@pytest.mark.parametrize("ex_id", [e for e, x in exercises().items() if x.get("starter")])
def test_starters_fail(ex_id: str) -> None:
    ex = exercises()[ex_id]
    assert not evaluate(ex["starter"], ex["checks"]).passed


def test_tutor_flow_and_credits(tmp_path: Path) -> None:
    t = Tutor(tmp_path)
    ex = exercises()["ocp-ex-secure-route"]
    answer = "```yaml\n" + generate(Blueprint.model_validate(ex["reference"])).yaml() + "```"
    r1 = t.submit("ocp-ex-secure-route", answer, learner="ana")
    assert r1["passed"] and r1["pointsEarned"] == 15 and r1["totalCredits"] == 15
    r2 = t.submit("ocp-ex-secure-route", answer, learner="ana")
    assert r2["totalCredits"] == 15  # best score counted once
    q = t.answer_quiz("ocp-q-route-group", 1, learner="ana")
    assert q["correct"] and q["totalCredits"] == 17
    assert t.answer_quiz("ocp-q-route-group", 1, learner="ana")["creditsAwarded"] == 0
    lesson = t.lesson("ocp-102-scc", learner="ana")
    assert "restricted-v2" in lesson["content"] and lesson["citations"]
    assert t.progress("ana")["lessonsRead"] == ["ocp-102-scc"]
    with pytest.raises(ValueError):
        t.progress("../../etc/passwd")


def test_a_shared_server_grades_the_same_way_and_records_nothing(tmp_path: Path) -> None:
    """Replaces the SAFE2 guard, which refused the "local" learner id on a shared server so that callers who
    forgot to pass their own could not collide in one progress file. The guard was too narrow: a caller who passes
    *any* id gets a file, and with one static bearer token an id binds to no identity, so one caller could write
    and read another's. A shared server now records no progress at all, which makes the id harmless and the guard
    pointless -- the grading, the feedback and the right answer are all computed without it.
    """
    from kube_noob import toolkit as tk
    from kube_noob.config import load_settings

    ex = exercises()["ocp-ex-secure-route"]
    answer = "```yaml\n" + generate(Blueprint.model_validate(ex["reference"])).yaml() + "```"

    local = tk.Toolkit(load_settings(overrides={"dataDir": str(tmp_path / "local")}), shared=False)
    kept = local.submit(tk.SubmitIn(exercise_id="ocp-ex-secure-route", answer=answer))
    assert kept["passed"] and kept["totalCredits"] == 15 and "recorded" not in kept
    assert local.progress(tk.LearnerIn(learner="local"))["credits"] == 15

    shared_dir = tmp_path / "shared"
    shared = tk.Toolkit(load_settings(overrides={"dataDir": str(shared_dir)}), shared=True)
    # Every id, including the old default, is accepted and graded identically.
    for learner in (None, "local", "student-7"):
        kw = {} if learner is None else {"learner": learner}
        out = shared.submit(tk.SubmitIn(exercise_id="ocp-ex-secure-route", answer=answer, **kw))
        assert out["passed"], out
        assert out["recorded"] is False and "shared" in out["note"]
        marked = shared.quiz(tk.QuizIn(question_id="ocp-q-route-group", choice=1, **kw))
        assert marked["correct"] and marked["recorded"] is False
        assert shared.lesson(tk.LessonIn(lesson_id="ocp-102-scc", **kw))["citations"]
    assert shared.quiz(tk.QuizIn(question_id="ocp-q-route-group"))["id"] == "ocp-q-route-group"
    assert not (shared_dir / "progress").exists(), "a shared server wrote a progress file"


def test_citation_extraction() -> None:
    assert extract_citations("see [kn:ocp-scc#0] and [kn:ocp-scc#0], [kn:rosa-hcp#2]") == [
        "kn:ocp-scc#0",
        "kn:rosa-hcp#2",
    ]


def test_citations_inside_knowledge_docs_resolve() -> None:
    import re
    from importlib import resources

    store = get_store()
    root = resources.files("kube_noob").joinpath("data", "knowledge")
    missing = [
        (f.name, cid)
        for f in root.iterdir()
        if f.name.endswith(".md")
        for cid in re.findall(r"\[(kn:[\w.-]+#\d+)\]", f.read_text(encoding="utf-8"))
        if store.get(cid) is None
    ]
    assert missing == []


def test_no_fragment_chunks_before_the_last() -> None:
    store = get_store()
    for doc_id in {c.doc_id for c in store.chunks}:
        chunks = store.doc(doc_id)
        for c in chunks[:-1]:
            assert len(c.text) >= 80, (c.chunk_id, c.text)
