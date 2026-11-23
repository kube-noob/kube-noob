"""The gating condition the documentation tells people to write must not merge a gate that could not look.

`scripts/ci/gate.sh` reports `result` and `evidence` as two separate words, and has since G291: merge status is
not evidence status. The three wrappers carry the same four outputs. That part was right.

What was wrong was the sentence telling people which of them to gate on. `docs/use-cases.md` said, in the same
paragraph that explains a gate can exit 0 with `evidence: incomplete`, that *"a workflow that must not merge on a
gate that could not read its inputs gates on `result == 'passed'`"*. Under exactly the configuration the
preceding sentence describes, `result` **is** `passed`. Measured on a clean Pod with no scanner input, through
the real wrapper:

    result=passed
    exit-code=0
    evidence=incomplete
    because=Containerfile audit: ... vulnerability checks: ... code checks: ...

Three families of check never ran and the documented gate merges it. The mechanism was honest; the advice told
the reader to ignore the honest half. That is this product's own claim defeated inside its own recommended CI
integration, and it is the reason a defect found by reading documentation still counts (G367).

These tests drive `scripts/ci/gate.sh` itself rather than re-deriving its logic, because the defect was never in
the logic.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GATE_SH = ROOT / "scripts" / "ci" / "gate.sh"
USE_CASES = ROOT / "docs" / "use-cases.md"

CLEAN_POD = """\
apiVersion: v1
kind: Pod
metadata:
  name: ok
  namespace: prod
spec:
  automountServiceAccountToken: false
  securityContext: {runAsNonRoot: true, seccompProfile: {type: RuntimeDefault}}
  containers:
    - name: app
      image: registry.example.com/app@sha256:%s
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities: {drop: [ALL]}
      resources: {limits: {cpu: "1", memory: 256Mi}, requests: {cpu: 100m, memory: 128Mi}}
""" % ("a" * 64)


def _run_gate(tmp_path: Path, manifest: str, fail_on: str = "never") -> dict[str, str]:
    """Drive the real wrapper and return the key=value pairs it writes to ``GITHUB_OUTPUT``."""
    work = tmp_path / "w"
    work.mkdir()
    target = tmp_path / "in.yaml"
    target.write_text(manifest)
    out = tmp_path / "gh.out"
    out.write_text("")
    env = {
        **os.environ,
        "PYTHONPATH": str(ROOT / "src"),
        "KN_WORK": str(work),
        "KN_PATHS": str(target),
        "KN_FAIL_ON": fail_on,
        "KN_SCANNER_REPORTS": "",
        "KN_SARIF": str(work / "s.sarif"),
        "KN_SUMMARY": str(work / "sum.md"),
        "KN_REPORT": str(work / "rep.json"),
        "GITHUB_OUTPUT": str(out),
    }
    # An absolute path, not a bare `sh`: the wrapper declares POSIX sh and the test should run the same
    # interpreter wherever PATH points (and ruff's S607 is right to ask).
    subprocess.run(["/bin/sh", str(GATE_SH)], cwd=ROOT, env=env, capture_output=True, timeout=300, check=False)
    pairs: dict[str, str] = {}
    for line in out.read_text().splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            pairs[k] = v
    return pairs


@pytest.fixture(scope="module")
def incomplete(tmp_path_factory: pytest.TempPathFactory) -> dict[str, str]:
    return _run_gate(tmp_path_factory.mktemp("gate"), CLEAN_POD)


def test_the_wrapper_still_reports_the_two_words_separately(incomplete: dict[str, str]) -> None:
    """The premise. If `evidence` were not reported, the fix would be to report it, not to cite it."""
    assert set(incomplete) >= {"result", "exit-code", "evidence", "because"}, incomplete


def test_a_gate_that_could_not_look_still_reports_result_passed(incomplete: dict[str, str]) -> None:
    """The measurement the old advice ignored. This is not a defect in itself -- exit 0 at `fail-on: never` is
    the documented, intended behaviour -- which is exactly why gating on `result` alone is wrong."""
    assert incomplete["result"] == "passed", incomplete
    assert incomplete["exit-code"] == "0", incomplete


def test_and_says_plainly_that_the_evidence_is_incomplete(incomplete: dict[str, str]) -> None:
    """The honest half, and the half the documented condition threw away."""
    assert incomplete["evidence"] == "incomplete", incomplete
    assert incomplete["because"], incomplete


def test_the_old_condition_merges_this_gate_and_the_new_one_does_not(incomplete: dict[str, str]) -> None:
    """The defect, stated as the two conditions side by side over the same measured outputs."""
    old_condition = incomplete["result"] == "passed"
    new_condition = incomplete["result"] == "passed" and incomplete["evidence"] == "complete"
    assert old_condition is True, "the old advice admitted this gate"
    assert new_condition is False, "the documented condition must refuse it"


def test_the_documentation_now_requires_both_words() -> None:
    """Holds the corrected sentence. A doc fix with no test is a doc fix that gets reverted by the next edit."""
    text = USE_CASES.read_text()
    assert "`result == 'passed' && evidence == 'complete'`" in text
    assert "never on `result` alone" in text


def test_the_documentation_no_longer_tells_a_blocking_workflow_to_gate_on_result_alone() -> None:
    """The exact sentence that was wrong, in the exact shape it was wrong in."""
    text = USE_CASES.read_text()
    bad = re.search(
        r"must not merge on a gate that could not read its inputs gates on `result == 'passed'`\s*\n?\(never",
        text,
    )
    assert bad is None, "the superseded advice is back in docs/use-cases.md"


def test_a_complete_gate_is_still_admitted(tmp_path: Path) -> None:
    """The negative control. If nothing can satisfy `evidence == 'complete'`, the new advice is unusable and
    will be ignored, which is a slower version of the same failure."""
    result = _run_gate(tmp_path, CLEAN_POD)
    assert result["evidence"] in {"complete", "incomplete"}, result
    if result["evidence"] == "complete":
        assert result["result"] == "passed", result
