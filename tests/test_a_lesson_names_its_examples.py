"""A walkable lesson names its worked examples, so nobody has to remember them (G423).

The website drew each mechanism lesson beside bundles it listed by hand, so a lesson added here had no example
there until someone noticed. A lesson now carries an optional `examples:` list -- fixture directories relative to
`tests/fixtures` -- and this file holds it to what a builder would rely on: every walkable lesson has one, every
entry is a directory of manifests that exists, and walking it for its own lesson reaches a verdict (0 or 1), never
"could not be judged". The shape is refused as strictly as a step's, because a reader joins these to a path.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from kube_noob import cli
from kube_noob.audit.engine import analyze
from kube_noob.learn import mechanism as M

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"

#: Every example of every walkable lesson, with the exit code its walk answers. Written out, so a lesson added
#: without examples and an example whose verdict moved both fail here by name. `a-node-goes-dark` borrows the
#: request-path bundles and has no example of its own: both are BROKEN at the spread hop (KN-C010) and then stop
#: at the budget hop, because neither carries a PodDisruptionBudget. A verdict is reached, which is the bar here;
#: a bundle that walks that lesson to its end is still to be written.
EXPECTED = {
    "mech-cp-a-node-goes-dark": {"mechanism/complete": 1, "mechanism/broken": 1},
    "mech-cp-deploy-an-app": {"mechanism/deploy/complete": 0, "mechanism/deploy/broken": 1},
    "mech-cp-autoscaling": {"mechanism/autoscaling/complete": 0, "mechanism/autoscaling/broken": 1},
    "mech-net-request-to-pod": {"mechanism/complete": 0, "mechanism/broken": 1},
    "mech-net-pod-calls-a-service": {"mechanism/service/complete": 0, "mechanism/service/broken": 1},
    "mech-net-network-policy": {"mechanism/networkpolicy/complete": 0, "mechanism/networkpolicy/broken": 1},
    "mech-sec-rbac-and-serviceaccounts": {"mechanism/rbac/complete": 0, "mechanism/rbac/broken": 1},
}


def test_every_walkable_lesson_names_its_examples_and_no_other_lesson_exists() -> None:
    declared = {lesson_id: list(M.examples(lesson)) for lesson_id, lesson in M.lessons().items()}
    assert declared == {lesson_id: list(dirs) for lesson_id, dirs in EXPECTED.items()}


@pytest.mark.parametrize(
    ("lesson_id", "example", "code"),
    [(lesson_id, example, code) for lesson_id, dirs in EXPECTED.items() for example, code in dirs.items()],
)
def test_each_example_is_a_directory_of_manifests_whose_walk_reaches_a_verdict(
    lesson_id: str, example: str, code: int
) -> None:
    path = FIXTURES / example
    assert path.is_dir(), f"{example} is not a directory under tests/fixtures"
    assert [p for p in path.iterdir() if p.suffix in (".yaml", ".yml")], f"{example} holds no manifest"
    # Read the way the command reads it: a directory is a whole namespace (`cli._partial_input`).
    report = analyze(cli._read(str(path)), "kubernetes", None, partial_bundle=False).as_dict()
    walked = M.walk(M.lessons()[lesson_id], report)
    assert walked["exitCode"] == code, walked["verdictReason"]
    assert walked["verdict"] in ("complete", "broken"), "an example that cannot be judged shows nothing"


def test_a_lesson_without_the_field_has_no_examples_and_still_walks() -> None:
    lesson = {k: v for k, v in M.lessons()["mech-net-network-policy"].items() if k != "examples"}
    assert M.examples(lesson) == ()
    assert M.walk(lesson, {"resources": []})["verdict"] == "stopped"


@pytest.mark.parametrize(
    "bad",
    [
        [],
        "mechanism/complete",
        {"mechanism/complete": 0},
        [7],
        [None],
        [""],
        ["../fixtures/mechanism/complete"],
        ["mechanism/../../etc"],
        ["/etc/passwd"],
        ["mechanism//complete"],
        ["mechanism/complete/"],
        ["mechanism\\complete"],
        ["Mechanism/Complete"],
        ["mechanism/complete\n"],
        ["https://example.com/bundle"],
        ["mechanism/.hidden"],
        ["mechanism/complete", "mechanism/complete"],
    ],
)
def test_a_malformed_examples_field_is_refused_by_the_reader_and_by_the_walk(bad: object) -> None:
    lesson = {**M.lessons()["mech-net-network-policy"], "examples": bad}
    with pytest.raises(ValueError, match="example"):
        M.examples(lesson)
    with pytest.raises(ValueError, match="example"):
        M.walk(lesson, {"resources": ["Deployment/shop/api"]})


def test_a_walk_does_not_print_paths_the_installed_package_does_not_have() -> None:
    """The wheel ships no `tests/`, so the examples are for the repository and its site, not for a walk's answer."""
    lesson = M.lessons()["mech-net-network-policy"]
    report = analyze(cli._read(str(FIXTURES / "mechanism/networkpolicy/complete")), "kubernetes", None).as_dict()
    walked = M.walk(lesson, report)
    assert "examples" not in walked
    assert "mechanism/networkpolicy" not in M.render(walked)
