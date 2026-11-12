"""The false-pass benchmark (G282): every input in ``tests/falsepass/cases`` is run through the real CLI and the
in-process tool, and the suite fails when a command reports a pass on input that does not decide it.

A reviewer found about 250 defects over two days, and most had one shape: an absence, an unknown, an
unrecognised shape, a truncated input or a refused read was reported as clean, allowed, complete or none. Those
reproducers lived in scratch directories. They live here now, as a corpus the gate runs, so the defect class cannot
come back quietly -- and so a case found on a branch starts enforcing the day the branch merges (its probe holds),
without an edit to the corpus.

The first tests are about the harness itself: a benchmark that cannot fail is the absence-as-a-pass defect aimed at
its own gate, so a deliberately wrong case must be refused, a forbidden outcome must fail a case, and a malformed
case file must not load.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

from tests.falsepass import harness as fp

ROOT = Path(__file__).resolve().parents[1]
CASES = fp.load_cases()

# -- the harness refuses a benchmark that cannot fail --------------------------------------------------------------

_GOOD_CSV = (
    "apiVersion: operators.coreos.com/v1alpha1\nkind: ClusterServiceVersion\n"
    "metadata: {name: foo.v1.0.0, namespace: a}\nspec: {version: 1.0.0}\nstatus: {phase: Succeeded}\n---\n"
    "apiVersion: operators.coreos.com/v1alpha1\nkind: Subscription\nmetadata: {name: foo, namespace: a}\n"
    "spec: {name: foo, source: redhat-operators, sourceNamespace: openshift-marketplace, channel: stable}\n"
    "status: {installedCSV: foo.v1.0.0, currentCSV: foo.v1.0.0}\n"
)


def _write_case(tmp_path: Path, name: str, body: dict[str, Any], files: dict[str, str] | None = None) -> fp.Case:
    """A case under a private corpus root, so the test cannot touch the real one."""
    inputs = tmp_path / "inputs" / name
    inputs.mkdir(parents=True)
    for rel, text in (files or {"ops.yaml": _GOOD_CSV}).items():
        (inputs / rel).write_text(text, "utf-8")
    cases = tmp_path / "cases"
    cases.mkdir(exist_ok=True)
    path = cases / f"{name}.yaml"
    path.write_text(yaml.safe_dump({"id": name, **body}, sort_keys=False), "utf-8")
    return fp.load_case(path)


def _complete_inventory_case(verdict_class: str = "finding") -> dict[str, Any]:
    return {
        "class": 1,
        "verdict": verdict_class,
        "summary": "a complete inventory of a clean bundle",
        "provenance": "harness self-test",
        "inputs": "self-x",
        "cli": {"argv": ["operators", "inventory", "-f", "{inputs}/ops.yaml", "--format", "json"]},
        "expect": {"json": {"verdict": "listed"}},
        "forbid": {"what": "nothing", "json": {"verdict": "no-such-verdict"}},
    }


@pytest.fixture
def private_corpus(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(fp, "INPUTS", tmp_path / "inputs")
    return tmp_path


def test_a_case_whose_forbidden_outcome_appears_fails(private_corpus: Path) -> None:
    """The benchmark's whole point: the forbidden outcome -- here `listed`, which this clean bundle produces --
    must fail the case even though the expectation is also met."""
    body = _complete_inventory_case()
    body["forbid"] = {"what": "listed", "json": {"verdict": "listed"}}
    case = _write_case(private_corpus, "self-x", body)
    outcome = fp.evaluate(case, private_corpus / "work", mcp=False)
    assert not outcome.passed
    assert any(p.startswith("CLI: forbidden verdict") for p in outcome.problems), outcome.problems


def test_a_case_whose_expected_outcome_is_missing_fails(private_corpus: Path) -> None:
    body = _complete_inventory_case("not-determined")
    body["expect"] = {"json": {"verdict": "partial"}}
    case = _write_case(private_corpus, "self-x", body)
    outcome = fp.evaluate(case, private_corpus / "work", mcp=False)
    assert not outcome.passed
    assert any("expected verdict" in p for p in outcome.problems), outcome.problems


def test_a_case_that_holds_passes_and_is_judged_twice_for_the_same_bytes(private_corpus: Path) -> None:
    case = _write_case(private_corpus, "self-x", _complete_inventory_case())
    outcome = fp.evaluate(case, private_corpus / "work", mcp=False)
    assert outcome.passed, outcome.problems
    assert outcome.enforced and outcome.seconds < fp.TIMEOUT_SECONDS


def test_a_forbidden_exit_code_fails_even_when_the_json_looks_right(private_corpus: Path) -> None:
    body = _complete_inventory_case()
    body["forbid"] = {"what": "exit 0", "exit": [0]}
    case = _write_case(private_corpus, "self-x", body)
    outcome = fp.evaluate(case, private_corpus / "work", mcp=False)
    assert any(p == "CLI: forbidden exit 0" for p in outcome.problems), outcome.problems


def test_a_forbidden_text_fails_a_text_view_case(private_corpus: Path) -> None:
    body = _complete_inventory_case()
    body["cli"]["argv"] = ["operators", "inventory", "-f", "{inputs}/ops.yaml"]
    body["expect"] = {"text": ["listed"]}
    body["forbid"] = {"what": "the clean sentence", "text": ["every OLM object this needs was read"]}
    case = _write_case(private_corpus, "self-x", body)
    outcome = fp.evaluate(case, private_corpus / "work", mcp=False)
    assert any(p.startswith("CLI: forbidden text") for p in outcome.problems), outcome.problems


def test_an_mcp_forbid_fails_the_case_on_its_own(private_corpus: Path) -> None:
    body = _complete_inventory_case()
    body["mcp"] = {
        "tool": "operator_inventory",
        "args": {"manifests": "{text:ops.yaml}"},
        "expect": {"json": {"verdict": "listed"}},
        "forbid": {"json": {"complete": True}},
    }
    case = _write_case(private_corpus, "self-x", body)
    outcome = fp.evaluate(case, private_corpus / "work")
    assert outcome.ran_mcp
    assert any(p == "MCP: forbidden complete == true" for p in outcome.problems), outcome.problems


def test_a_case_waiting_for_a_branch_is_not_enforced_until_its_probe_holds(private_corpus: Path) -> None:
    body = _complete_inventory_case()
    body["expected_on"] = "some/branch"
    body["probe"] = {"module": "kube_noob.no_such_module_ever"}
    case = _write_case(private_corpus, "self-x", body)
    assert not case.enforced
    body["probe"] = {"module": "kube_noob.operators"}
    assert _write_case(private_corpus, "self-y", body).enforced
    body["probe"] = {"grep": {"file": "src/kube_noob/operators.py", "text": "no text like this is in the file"}}
    assert not _write_case(private_corpus, "self-z", body).enforced
    body["probe"] = {"command": ["operators", "no-such-subcommand"]}
    assert not _write_case(private_corpus, "self-w", body).enforced
    body["probe"] = {"command": ["operators", "inventory"]}
    assert _write_case(private_corpus, "self-v", body).enforced


@pytest.mark.parametrize(
    ("edit", "message"),
    [
        (lambda b: b.pop("forbid"), "forbid must name the false pass"),
        (lambda b: b.update(forbid={"what": "x"}), "forbid must name the false pass"),
        (lambda b: b.update(forbid={"json": {"a": 1}}), "forbid.what must say"),
        (lambda b: b.update(expect={}), "expect must assert something"),
        (lambda b: b.update(expect={"exit": [0]}), "must be asserted in the output"),
        (lambda b: b.update(verdict="error-exit-2", expect={"exit": [0]}), "must expect exactly exit 2"),
        (lambda b: b.update(verdict="clean"), "verdict must be one of"),
        (lambda b: b.update(**{"class": 23}), "class must be a defect class number"),
        (lambda b: b.update(expected_on="a/b"), "needs a probe"),
        (lambda b: b.update(probe={"module": "kube_noob"}), "a probe without expected_on"),
        (lambda b: b.update(bogus=1), "unknown keys"),
        (lambda b: b.update(inputs="no-such-inputs"), "inputs must name a directory"),
        (lambda b: b.update(generate="no-such-generator"), "generate must name one of"),
        (lambda b: b.update(mcp={"tool": "x", "args": {}}), "mcp.expect and mcp.forbid"),
        (lambda b: b.update(cli={"argv": []}), "cli.argv is required"),
        (lambda b: b.update(cli={"argv": ["audit"], "kubectl": "nope"}), "cli.kubectl must name a scenario"),
    ],
)
def test_a_malformed_case_file_is_refused(private_corpus: Path, edit: Any, message: str) -> None:
    """A case with no forbidden outcome, no expectation or an unknown key would pass by accident; the loader
    refuses it so the corpus stays a contract."""
    body = _complete_inventory_case()
    edit(body)
    with pytest.raises(fp.CaseError, match=message):
        _write_case(private_corpus, "self-x", body)


def test_the_id_must_match_the_file_name(private_corpus: Path) -> None:
    body = _complete_inventory_case()
    body["id"] = "other"
    with pytest.raises(fp.CaseError, match="id must equal the file name"):
        _write_case(private_corpus, "self-x", body)


def test_json_paths_resolve_lists_and_missing_steps_yield_nothing() -> None:
    data = {"a": [{"b": 1}, {"b": 2}], "c": {"d": "x"}, "e": []}
    assert fp.resolve(data, "a[*].b") == [1, 2]
    assert fp.resolve(data, "a[0].b") == [1]
    assert fp.resolve(data, "a[-1].b") == [2]
    assert fp.resolve(data, "c.d") == ["x"]
    assert fp.resolve(data, "c.missing") == []
    assert fp.resolve(data, "e[*]") == []
    assert fp.resolve(data, "e") == [[]]
    assert fp.resolve(None, "a") == []


def test_the_stub_kubectl_answers_from_the_most_specific_file(tmp_path: Path) -> None:
    scenario = tmp_path / "s"
    scenario.mkdir()
    (scenario / "default.json").write_text('{"kind":"List","items":[]}', "utf-8")
    (scenario / "pods--shop.json").write_text('{"kind":"PodList","items":[1]}', "utf-8")
    (scenario / "pods.web.json").write_text('{"kind":"Pod"}', "utf-8")
    (scenario / "services.stderr").write_text("Error from server (Forbidden): services is forbidden\n", "utf-8")
    (scenario / "services.exit").write_text("1\n", "utf-8")
    env = {**os.environ, "FALSEPASS_KUBECTL": str(scenario)}

    def run(*args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-I", str(fp.STUB_BIN / "kubectl"), *args],
            capture_output=True,
            text=True,
            env=env,
            check=False,
            timeout=30,
        )

    assert json.loads(run("get", "pods", "--namespace", "shop", "--output", "json").stdout)["items"] == [1]
    assert json.loads(run("get", "pods", "web", "--namespace", "shop").stdout)["kind"] == "Pod"
    assert json.loads(run("get", "pods", "--all-namespaces").stdout)["items"] == []
    refused = run("get", "services", "--all-namespaces")
    assert refused.returncode == 1 and "Forbidden" in refused.stderr and refused.stdout == ""
    assert run("version", "--output", "json").returncode == 0
    unset = subprocess.run(
        [sys.executable, "-I", str(fp.STUB_BIN / "kubectl"), "get", "pods"],
        capture_output=True,
        text=True,
        env={k: v for k, v in os.environ.items() if k != "FALSEPASS_KUBECTL"},
        check=False,
        timeout=30,
    )
    assert unset.returncode == 70


def test_the_summary_table_counts_enforced_waiting_and_failed() -> None:
    case = CASES[0]
    waiting = fp.Case(**{**case.__dict__, "expected_on": "x/y", "probe": fp.Probe("module", "kube_noob.nope")})
    outcomes = [
        fp.Outcome(case, True, [], 1.0, False),
        fp.Outcome(case, True, ["CLI: forbidden exit 0"], 1.0, False),
        fp.Outcome(waiting, False, ["CLI: forbidden exit 0"], 1.0, False),
    ]
    text = "\n".join(fp.summary_lines(outcomes))
    assert "waiting for x/y" in text and "still open" in text
    total = next(line for line in text.splitlines() if line.startswith("total"))
    assert total.split()[-4:] == ["3", "2", "1", "1"]


# -- the corpus --------------------------------------------------------------------------------------------------


def test_the_corpus_is_not_empty_and_every_file_loads() -> None:
    assert len(CASES) >= 60
    classes = {c.defect_class for c in CASES}
    assert len(classes) >= 12, sorted(classes)
    assert any(c.expected_on is None for c in CASES), "nothing enforces on main"
    assert any(c.mcp_tool for c in CASES), "no case drives the in-process tool"
    assert any(c.kubectl for c in CASES), "no case reads the stub cluster"


def test_every_input_directory_belongs_to_a_case() -> None:
    used = {c.inputs for c in CASES if c.inputs}
    present = {p.name for p in fp.INPUTS.iterdir() if p.is_dir()}
    assert present == used, f"orphans: {sorted(present - used)}; missing: {sorted(used - present)}"


def test_every_input_is_small_enough_to_read_in_a_diff() -> None:
    """Large inputs are generated in code; a 50 KB file in the corpus is a reviewer's blind spot."""
    big = [p for p in fp.INPUTS.rglob("*") if p.is_file() and not p.is_symlink() and p.stat().st_size > 50_000]
    assert big == [], big


def test_generated_inputs_are_the_same_bytes_every_time(tmp_path: Path) -> None:
    for name, gen in fp.GENERATORS.items():
        a, b = tmp_path / name / "a", tmp_path / name / "b"
        a.mkdir(parents=True)
        b.mkdir(parents=True)
        gen(a)
        gen(b)
        for p in sorted(a.iterdir()):
            assert p.read_bytes() == (b / p.name).read_bytes(), name


@pytest.fixture(scope="session")
def outcomes(request: pytest.FixtureRequest) -> list[fp.Outcome]:
    """Every case's outcome, printed as one table at the end of the session (tests/conftest.py)."""
    found: list[fp.Outcome] = []
    request.config.stash[fp.STASH_KEY] = found
    return found


@pytest.mark.parametrize("case", CASES, ids=[c.id for c in CASES])
def test_a_false_pass_never_comes_back(case: fp.Case, tmp_path: Path, outcomes: list[fp.Outcome]) -> None:
    outcome = fp.evaluate(case, tmp_path)
    outcomes.append(outcome)
    detail = "\n".join(outcome.problems)
    if not outcome.enforced:
        if outcome.passed:
            return  # it holds already; it enforces the day its branch merges, and nothing here changes
        pytest.xfail(f"waiting for {case.expected_on}: {outcome.problems[0][:160]}")
    assert outcome.passed, f"{case.id}: class {case.defect_class} ({fp.DEFECT_CLASSES[case.defect_class]})\n{detail}"
    assert outcome.seconds < fp.TIMEOUT_SECONDS
