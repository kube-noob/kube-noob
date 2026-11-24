"""The adversarial corpus: sixteen inputs built to make a scanner under-report, each with its honest answer.

Three external reviews, asked separately what would most increase this product's credibility with a defence
buyer, landed on the same artifact: not a better claim, but a set of manifests that make a scanner report less
than is there, with the honest answer written down beside each one, that anyone can run against whatever tool
they already use. `corpus/` is that set and `scripts/corpus_run.py` is its runner. This file is the half that
makes it a regression suite: a change that makes a fixture answer differently fails here, in CI, in the same
run as the rest of the gate.

Two things are deliberately absent. There is no comparison with any other tool, and no claim about one: a
league table invites an argument about the table, a reproducible corpus does not (`corpus/README.md` says so in
its own words, and `test_the_readme_says_why_there_is_no_scoreboard` holds that sentence). And no expected
answer here was derived from the code: every one was measured with the real CLI first, and where the measured
answer is one the maintainer does not call honest it is recorded under `open_defect` with its guidance row
rather than asserted, so the commit that fixes it does not have to fight this file (G377).

The runner is driven as a module rather than re-implemented, so there is one definition of what the corpus
asserts; `test_the_runner_agrees_with_every_record` is the whole corpus and is the slow test here.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import corpus_run

CORPUS = Path(__file__).resolve().parent.parent / "corpus"
README = CORPUS / "README.md"
CASES = sorted(p.parent for p in CORPUS.glob("*/honest-answer.yaml"))
IDS = [p.name for p in CASES]

#: Every dotted token any corpus file may carry, decided one at a time. A host or group not in this set has to
#: be added here deliberately, which is the point: `example.com`, `example.invalid` and `203.0.113.0/24` are
#: reserved for documentation (RFC 2606, RFC 6761, RFC 5737), the API groups are real ones a case is ABOUT, and
#: everything else here is a field path, a version or a file name rather than a name that resolves anywhere.
ALLOWED_DOTTED = frozenset(
    {
        "1.16",
        "1.31",
        "203.0.113.0",
        "203.0.113.10",
        "AGENTS.md",
        "README.md",
        "after.json",
        "apps.example.invalid",
        "apps.openshift.io",
        "argoproj.io",
        "audit.example.invalid",
        "before.json",
        "corpus.py",
        "discovery.k8s.io",
        "example.com",
        "example.invalid",
        "guidance.md",
        "honest-answer.yaml",
        "kubernetes.io",
        "metadata.name",
        "observability.example.invalid",
        "policy.example.invalid",
        "projectcalico.org",
        "rbac.authorization.k8s.io",
        "rbac.k8s.io",
        "registry.example.com",
        "run.py",
        "spec.podTemplate",
        "spec.template.Spec",
        "spec.template.spec",
    }
)
#: Credential shapes no fixture may carry, whatever else changes in it.
SECRET_SHAPES = ("BEGIN PRIVATE KEY", "BEGIN RSA", "AKIA", "ghp_", "xoxb-", "Bearer ey", "password:", "token:")


def record(case: Path) -> dict[str, Any]:
    return yaml.safe_load((case / "honest-answer.yaml").read_text(encoding="utf-8"))  # type: ignore[no-any-return]


def test_the_corpus_is_not_empty_and_every_case_has_a_record() -> None:
    assert len(CASES) >= 16, "a case was removed; the corpus is append-only like the guidance table"
    for case in CASES:
        assert (case / "honest-answer.yaml").is_file()


@pytest.mark.parametrize("case", CASES, ids=IDS)
def test_every_record_names_its_object_its_mechanism_and_an_exit_code(case: Path) -> None:
    doc = record(case)
    assert doc["id"] == case.name
    assert len(doc["object"]) > 40, "what the object is, not a label"
    assert len(doc["mechanism"]) > 80, "one sentence on the mechanism, not a category"
    honest = doc["honest"]
    assert honest["verdict"] in {"failed", "incomplete", "undetermined", "complete", "passed"}
    assert isinstance(honest["exit_code"], int)
    assert honest["must_name"], "an answer that names nothing cannot be checked for naming the thing"


@pytest.mark.parametrize("case", CASES, ids=IDS)
def test_no_mechanism_sentence_names_another_product(case: Path) -> None:
    """The fixtures are the claim. A sentence about a named competitor's behaviour is a claim about them."""
    doc = record(case)
    prose = " ".join([doc["object"], doc["mechanism"], README.read_text(encoding="utf-8")]).lower()
    for name in ("checkov", "kubescape", "trivy", "kubesec", "polaris", "datree", "snyk", "prisma", "aqua "):
        assert name not in prose, f"{name!r} appears in corpus prose; the corpus names no other tool"


@pytest.mark.parametrize("case", CASES, ids=IDS)
def test_no_fixture_carries_anything_that_looks_like_a_real_secret_or_host(case: Path) -> None:
    """Everything in the corpus is invented. A fixture that ships a credential shape is worse than no fixture."""
    for path in sorted(case.rglob("*")):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        for word in SECRET_SHAPES:
            assert word not in text, f"{path} carries {word!r}"
        dotted = set(re.findall(r"[A-Za-z0-9][A-Za-z0-9-]*(?:\.[A-Za-z0-9-]+)+", text))
        assert frozenset() == dotted - ALLOWED_DOTTED, f"{path} names a host or group nobody decided on"


def test_the_readme_says_why_there_is_no_scoreboard() -> None:
    text = README.read_text(encoding="utf-8")
    assert "no scoreboard here, on purpose" in text
    assert "league table invites an argument about the table" in text
    assert "python scripts/corpus_run.py" in text, "the command a stranger runs is in the README"


def test_the_readme_table_agrees_with_every_record() -> None:
    """The one hand-written list in the directory, held to the records it summarises."""
    rows = {}
    for line in README.read_text(encoding="utf-8").splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")] if re.match(r"\| \d\d \|", line) else []
        if len(cells) == 4 and cells[0].isdigit():
            rows[cells[0]] = (cells[2], int(cells[3]))
    assert len(rows) == len(CASES), f"the README table has {len(rows)} rows for {len(CASES)} cases"
    for case in CASES:
        doc = record(case)
        number = case.name.split("-", 1)[0]
        assert rows[number] == (doc["honest"]["verdict"], doc["honest"]["exit_code"]), case.name


def test_every_open_defect_names_a_guidance_row_that_exists() -> None:
    """A measured answer the maintainer does not call honest is traceable, or it is a shrug in a data file."""
    guidance = (Path(__file__).resolve().parent.parent / "docs" / "guidance.md").read_text(encoding="utf-8")
    found = 0
    for case in CASES:
        for row in corpus_run._open_defects(record(case)):
            found += 1
            assert f"| {row['guidance']} |" in guidance, f"{case.name} cites {row['guidance']}, which is not a row"
            assert len(row["measured"]) > 40, "say what was measured"
    assert found >= 1, "case 16's open defect was removed without its guidance row changing"


def test_the_runner_reads_each_commands_own_verdict_word_and_not_its_own() -> None:
    """A runner with its own opinion of the answer is a second source of truth for the thing it checks."""
    ok = corpus_run.Result(0, json.dumps({"passed": True, "incomplete": False}), "")
    bad = corpus_run.Result(1, json.dumps({"passed": False, "incomplete": False}), "")
    unread = corpus_run.Result(1, json.dumps({"passed": False, "incomplete": True}), "")
    gate = ["--format", "json", "gate", "-f", "manifests"]
    assert frozenset({"passed", "failed", "incomplete"}) == frozenset(
        corpus_run.verdict_word(gate, r) for r in (ok, bad, unread)
    )
    diff = ["--format", "json", "posture", "diff", "a", "b"]
    told = corpus_run.Result(1, json.dumps({"verdict": "undetermined"}), "")
    assert corpus_run.verdict_word(diff, told) == "undetermined"
    scan = ["--format", "json", "posture", "scan", "-f", "manifests"]
    five = corpus_run.Result(5, "{}", "incomplete: 1 object(s) not read")
    assert corpus_run.verdict_word(scan, five) == "incomplete"
    assert corpus_run.verdict_word(scan, corpus_run.Result(0, "{}", "")) == "complete"


def test_the_runner_finds_the_command_by_name_and_not_by_stripping_the_flags() -> None:
    """`--format json gate` is not the command `json`: argv is not a word list with the flags removed (class 22)."""
    assert corpus_run._command_of(["--format", "json", "gate", "-f", "manifests"]) == "gate"
    assert corpus_run._command_of(["--format", "json", "posture", "diff", "a", "b"]) == "posture diff"
    scan = ["--format", "json", "posture", "scan", "-f", "x", "--require-complete"]
    assert corpus_run._command_of(scan) == "posture scan"


def test_a_record_that_disagrees_with_the_tool_is_reported_and_not_accommodated(tmp_path: Path) -> None:
    """The one test that proves the harness can fail. A runner nothing can make fail asserts nothing."""
    case = tmp_path / "90-a-record-the-tool-disagrees-with"
    (case / "manifests").mkdir(parents=True)
    (case / "manifests" / "cm.yaml").write_text(
        "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: ok, namespace: app}\ndata: {a: '1'}\n", encoding="utf-8"
    )
    (case / "honest-answer.yaml").write_text(
        "id: 90-a-record-the-tool-disagrees-with\n"
        'object: "A ConfigMap that every rule reads, recorded with an answer the tool does not give."\n'
        'mechanism: "The record claims the verdict is incomplete and the exit code 5; the tool reads the object '
        'in full and says so, which is the disagreement this test is here to see reported."\n'
        "honest:\n"
        '  command: ["--format", "json", "gate", "-f", "manifests", "--platform", "kubernetes", "--version", "1.31"]\n'
        "  verdict: incomplete\n"
        "  exit_code: 5\n"
        "  must_name:\n"
        '    - "Secret/app/nothing-like-this"\n',
        encoding="utf-8",
    )
    doc = corpus_run.record_of(case)
    wrong = corpus_run.check(case, doc, tmp_path / "tmp")
    assert any("exit code is" in line for line in wrong), wrong
    assert any("verdict is" in line for line in wrong), wrong
    assert any("never names" in line for line in wrong), wrong


def test_the_runner_agrees_with_every_record() -> None:
    """The corpus itself: every case, through the real CLI, against the answer recorded beside it."""
    done = subprocess.run(
        [sys.executable, str(Path(corpus_run.__file__))],
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, done.stdout + done.stderr
    assert f"{len(CASES)} case(s); 0 disagreed" in done.stdout, done.stdout
