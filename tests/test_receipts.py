"""A receipt is a verdict somebody who does not trust the runner can check.

The product claim is a deterministic three-valued verdict. A claim is only worth something if a third party can
check it, so `audit --receipt` and `gate --receipt` write one self-describing JSON document that binds the inputs
by SHA-256, the tool version, the meaning of every rule, the settings that changed the verdict, the scope that was
actually read, and the verdict itself -- and `receipt verify` re-runs those inputs and answers one of three things:
the verdict is reproduced, it differs (naming the fields), or it CANNOT BE CHECKED because an input is missing, an
input's hash differs, or the receipt was written by another kube-noob. The third answer is the important one: it is
not a pass, it exits 5, and it names the input it could not get.

Integrity, not authenticity. SHA-256 only, no signature, no key: the document proves that the same inputs give the
same verdict and proves nothing about who produced it. It says so in its own text, and a test here holds that
sentence.
"""

from __future__ import annotations

import io
import json
import os
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any

import pytest

from kube_noob import cli, receipt

_ROOT = Path(__file__).resolve().parents[1]

_DEPLOY = """apiVersion: apps/v1
kind: Deployment
metadata: {name: app, namespace: prod}
spec:
  replicas: 1
  selector: {matchLabels: {app: app}}
  template:
    metadata: {labels: {app: app}}
    spec:
      containers:
        - name: api
          image: acme/api:latest
          securityContext: {privileged: true}
"""


_ROLLOUT = """apiVersion: argoproj.io/v1alpha1
kind: Rollout
metadata: {name: ro, namespace: prod}
spec:
  replicas: 2
  selector: {matchLabels: {app: ro}}
  template:
    metadata: {labels: {app: ro}}
    spec:
      containers:
        - name: api
          image: acme/api:latest
          securityContext: {privileged: true}
"""


def _run(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = cli.main(argv)
    return rc, out.getvalue(), err.getvalue()


@pytest.fixture
def bundle(tmp_path: Path) -> Path:
    p = tmp_path / "app.yaml"
    p.write_text(_DEPLOY, encoding="utf-8")
    return p


def _doc(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _rewrite(path: Path, doc: dict[str, Any], *, redigest: bool) -> None:
    if redigest:
        doc["integrity"]["payloadDigest"] = receipt.digest_of(doc["payload"])
    path.write_text(json.dumps(doc, indent=2, sort_keys=True), encoding="utf-8")


# --- determinism: the payload is the product -----------------------------------------------------------------------


def test_two_runs_minutes_apart_write_an_identical_payload_and_a_different_envelope(
    bundle: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Determinism IS the feature. If the payload carried the clock, two honest runs would never match and the
    document would prove nothing, so every fact that cannot be deterministic lives in the envelope instead."""
    import datetime as dt

    first, second = tmp_path / "a.json", tmp_path / "b.json"
    monkeypatch.setattr(receipt, "_now", lambda: dt.datetime(2026, 11, 15, 9, 0, 0, tzinfo=dt.UTC))
    assert _run(["audit", "-f", str(bundle), "--receipt", str(first)])[0] == 1
    monkeypatch.setattr(receipt, "_now", lambda: dt.datetime(2026, 11, 15, 9, 7, 13, tzinfo=dt.UTC))
    assert _run(["audit", "-f", str(bundle), "--receipt", str(second)])[0] == 1
    a, b = _doc(first), _doc(second)
    assert receipt.canonical(a["payload"]) == receipt.canonical(b["payload"])
    assert a["integrity"]["payloadDigest"] == b["integrity"]["payloadDigest"]
    assert a["envelope"] != b["envelope"]
    assert a["envelope"]["takenAt"] != b["envelope"]["takenAt"]


def test_the_envelope_records_no_host_and_no_runner_and_says_why(bundle: Path, tmp_path: Path) -> None:
    """An unsigned document cannot attest to who produced it, so a hostname in it would be a claim it cannot
    support -- and a receipt is made to be forwarded. The envelope says that in place of the fields."""
    out = tmp_path / "r.json"
    _run(["audit", "-f", str(bundle), "--receipt", str(out)])
    env = _doc(out)["envelope"]
    assert env["host"] is None and env["runner"] is None
    assert "not recorded" in env["notIncluded"]
    text = json.dumps(_doc(out))
    assert os.uname().nodename not in text


def test_the_payload_digest_covers_the_payload_and_not_the_envelope(bundle: Path, tmp_path: Path) -> None:
    out = tmp_path / "r.json"
    _run(["audit", "-f", str(bundle), "--receipt", str(out)])
    doc = _doc(out)
    assert doc["integrity"]["payloadDigest"] == receipt.digest_of(doc["payload"])
    doc["envelope"]["durationMs"] = 999999
    assert receipt.digest_of(doc["payload"]) == doc["integrity"]["payloadDigest"]


# --- what the document binds ---------------------------------------------------------------------------------------


def test_a_receipt_binds_every_input_by_hash_with_the_path_as_given_and_the_resolved_path(
    bundle: Path, tmp_path: Path
) -> None:
    import hashlib

    out = tmp_path / "r.json"
    _run(["audit", "-f", str(bundle), "--receipt", str(out)])
    inputs = _doc(out)["payload"]["inputs"]
    assert len(inputs) == 1
    got = inputs[0]
    assert got["path"] == str(bundle)
    assert got["resolvedPath"] == str(bundle.resolve())
    assert got["sha256"] == hashlib.sha256(bundle.read_bytes()).hexdigest()
    assert got["bytes"] == len(bundle.read_bytes())
    assert got["role"] == "manifest"


def test_an_exceptions_file_is_bound_by_hash_like_any_other_input(bundle: Path, tmp_path: Path) -> None:
    exc = tmp_path / "exc.yaml"
    exc.write_text(
        "apiVersion: kube-noob.io/v1\nkind: ExceptionList\nexceptions: []\n",
        encoding="utf-8",
    )
    out = tmp_path / "r.json"
    _run(["audit", "-f", str(bundle), "--exceptions", str(exc), "--receipt", str(out)])
    payload = _doc(out)["payload"]
    roles = {i["role"] for i in payload["inputs"]}
    assert "exceptions" in roles
    assert payload["settings"]["exceptions"] == str(exc)


def test_a_receipt_records_which_meaning_of_a_rule_it_used(bundle: Path, tmp_path: Path) -> None:
    """A rule id can stay stable while its default severity, its subject or its wording changes, so "KN-S001 clean"
    is worthless without saying WHICH KN-S001. The meaning version is derived from the rule's own declaration."""
    out = tmp_path / "r.json"
    _run(["audit", "-f", str(bundle), "--receipt", str(out)])
    rs = _doc(out)["payload"]["ruleSet"]
    assert rs["rules"] == len(rs["meanings"])
    assert rs["meanings"]["KN-S001"] == receipt.rule_meaning("KN-S001")
    assert rs["digest"] == receipt.rule_set()["digest"]


def test_changing_a_rules_severity_changes_its_meaning_version_under_the_same_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from kube_noob.audit.model import Severity
    from kube_noob.audit.rules import RULES

    before = receipt.rule_meaning("KN-S001")
    before_set = receipt.rule_set()["digest"]
    import dataclasses

    monkeypatch.setitem(RULES, "KN-S001", dataclasses.replace(RULES["KN-S001"], severity=Severity.INFO))
    assert receipt.rule_meaning("KN-S001") != before
    assert receipt.rule_set()["digest"] != before_set


def test_a_receipt_records_the_settings_that_changed_the_verdict(bundle: Path, tmp_path: Path) -> None:
    out = tmp_path / "r.json"
    _run(
        [
            "audit",
            "-f",
            str(bundle),
            "--platform",
            "openshift",
            "--version",
            "4.20",
            "--cni",
            "calico:3.32",
            "--fail-on",
            "critical",
            "--min-severity",
            "medium",
            "--receipt",
            str(out),
        ]
    )
    s = _doc(out)["payload"]["settings"]
    assert s["platform"] == "openshift" and s["platformVersion"] == "4.20"
    assert s["cni"] == "calico:3.32" and s["failOn"] == "critical" and s["minSeverity"] == "medium"
    # One file is a partial bundle, which is what the shipped audit already means by it: `audit -f one.yaml`
    # cannot tell "this namespace has no NetworkPolicy" from "you did not pass it".
    assert s["partialBundle"] is True


def test_the_verdict_carries_the_counts_the_exit_code_and_every_finding_by_fingerprint(
    bundle: Path, tmp_path: Path
) -> None:
    out, rep = tmp_path / "r.json", tmp_path / "rep.json"
    rc, text, _ = _run(["audit", "-f", str(bundle), "--format", "json", "--receipt", str(out)])
    rep.write_text(text, encoding="utf-8")
    report = json.loads(text)
    v = _doc(out)["payload"]["verdict"]
    assert v["exitCode"] == rc == 1
    assert v["counts"] == report["summary"]["counts"]
    assert sorted(f["fingerprint"] for f in v["findings"]) == sorted(f["fingerprint"] for f in report["findings"])


def test_the_scope_names_what_was_read_and_what_was_not(tmp_path: Path) -> None:
    d = tmp_path / "manifests"
    d.mkdir()
    (d / "ok.yaml").write_text(_DEPLOY, encoding="utf-8")
    (d / "broken.yaml").write_text("a: [unclosed\n", encoding="utf-8")
    out = tmp_path / "r.json"
    _run(["audit", "-f", str(d), "--skip-unreadable", "--receipt", str(out)])
    scope = _doc(out)["payload"]["scope"]
    assert scope["inputsRead"] == 1
    assert [b["path"] for b in scope["inputsNotRead"]] == ["broken.yaml"]
    assert scope["resources"]


def test_the_receipt_records_the_score_the_command_gave_and_never_a_second_judgement(tmp_path: Path) -> None:
    """ONE predicate decides whether a score is withheld: ``Report.undetermined()`` (G272). The receipt reads its
    answer out of the report as ``summary.score`` and ``summary.scoreWithheld`` and records it. A receipt with a
    withholding rule of its own could withhold a score the command printed, or print one the command withheld,
    and then the document would disagree with the run it claims to describe."""
    f = tmp_path / "ro.yaml"
    f.write_text(_ROLLOUT, encoding="utf-8")
    out = tmp_path / "r.json"
    _, text, _ = _run(["audit", "-f", str(f), "--format", "json", "--receipt", str(out)])
    report = json.loads(text)
    v = _doc(out)["payload"]["verdict"]
    assert v["score"] == report["summary"]["score"] is None
    assert v["scoreWithheld"] == report["summary"]["scoreWithheld"]
    assert "not audited" in v["scoreWithheld"]


def test_a_complete_run_records_the_score_the_command_reported(tmp_path: Path) -> None:
    """The other direction of the same rule: a determined run has a score, and the receipt records that number
    rather than one of its own."""
    d = tmp_path / "manifests"
    d.mkdir()
    (d / "ok.yaml").write_text(_DEPLOY, encoding="utf-8")
    out = tmp_path / "r.json"
    _, text, _ = _run(["audit", "-f", str(d), "--format", "json", "--receipt", str(out)])
    v = _doc(out)["payload"]["verdict"]
    assert v["scoreWithheld"] is None
    assert v["score"] == json.loads(text)["summary"]["score"] is not None


def test_an_undetermined_report_is_exit_1_in_the_receipt_whatever_fail_on_says(tmp_path: Path) -> None:
    """AGENTS.md, "1 and 5 are not two answers to the same question": 1 means a verdict was reached and it is not
    a pass, and an undetermined report is not a clean one at any threshold, so `--fail-on never` cannot turn it
    into a 0. A receipt that recorded 0 there would disagree with the exit code the command returned, which is a
    published contract -- and a receipt that disagrees with it is worse than no receipt."""
    f = tmp_path / "ro.yaml"
    f.write_text(_ROLLOUT, encoding="utf-8")
    out = tmp_path / "r.json"
    rc, _, _ = _run(["audit", "-f", str(f), "--fail-on", "never", "--receipt", str(out)])
    assert rc == 1
    assert _doc(out)["payload"]["verdict"]["exitCode"] == 1
    assert _doc(out)["payload"]["verdict"]["score"] is None


def test_the_one_exit_code_rule_lives_in_one_place() -> None:
    """`receipt.audit_exit_code` is what the CLI returns, what the receipt records and what the MCP verifier
    recomputes on a replay, and it READS `summary.scoreWithheld` rather than deciding undetermined again."""
    withheld = {"summary": {"counts": {}, "score": None, "scoreWithheld": "1 rule not evaluated in full: KN-S038"},
                "findings": []}  # fmt: skip
    assert receipt.audit_exit_code(withheld, "never") == 1
    assert receipt.audit_exit_code(withheld, "critical") == 1
    clean = {"summary": {"counts": {}, "score": 100.0}, "findings": []}
    assert receipt.audit_exit_code(clean, "never") == 0
    assert receipt.audit_exit_code(clean, "high") == 0
    assert not hasattr(receipt, "score_withheld"), "a second withheld-score predicate came back"


def test_an_input_the_caller_waived_stays_named_and_does_not_change_the_score(tmp_path: Path) -> None:
    """`--skip-unreadable` is the caller saying "decide without that file", so a verdict WAS reached on the
    evidence that remained and the score is that verdict's. What the waiver must never do is make the gap
    disappear: the file stays named in the receipt's scope (AGENTS.md, G272)."""
    d = tmp_path / "manifests"
    d.mkdir()
    (d / "ok.yaml").write_text(_DEPLOY, encoding="utf-8")
    (d / "broken.yaml").write_text("a: [unclosed\n", encoding="utf-8")
    out = tmp_path / "r.json"
    rc, text, _ = _run(["audit", "-f", str(d), "--skip-unreadable", "--format", "json", "--receipt", str(out)])
    assert rc == 1
    payload = _doc(out)["payload"]
    assert payload["verdict"]["score"] == json.loads(text)["summary"]["score"]
    assert payload["verdict"]["scoreWithheld"] is None
    assert [b["path"] for b in payload["scope"]["inputsNotRead"]] == ["broken.yaml"]


def test_the_document_states_that_it_proves_integrity_and_not_authenticity(bundle: Path, tmp_path: Path) -> None:
    out = tmp_path / "r.json"
    _run(["audit", "-f", str(bundle), "--receipt", str(out)])
    doc = _doc(out)
    assert doc["integrity"]["algorithm"] == "sha256"
    assert doc["integrity"]["signed"] is False
    statement = doc["integrity"]["statement"]
    assert "same inputs give the same verdict" in statement
    assert "nothing about who produced it" in statement
    assert "no signature" in statement
    text = json.dumps(doc)
    assert "cryptography" not in text.lower() or "no signature" in statement


def test_the_control_coverage_roll_up_counts_the_buckets_the_report_publishes(bundle: Path, tmp_path: Path) -> None:
    """A reader that meets a shape it does not recognise must produce a number it can defend or say nothing. Five
    zeros beside 93 rules is neither, and it is what reading the wrong level of `controlSummary` produced."""
    out = tmp_path / "r.json"
    _, text, _ = _run(["audit", "-f", str(bundle), "--format", "json", "--receipt", str(out)])
    rows = json.loads(text)["controlSummary"]["controls"]
    got = _doc(out)["payload"]["scope"]["controlCoverage"]
    for key in ("findings", "clean", "notEvaluated", "excepted", "withheld"):
        assert got[key] == sum(int(r.get(key, 0)) for r in rows), key
    assert got["findings"] and got["clean"], got


def test_an_audit_refused_for_an_unreadable_input_writes_no_receipt(tmp_path: Path) -> None:
    """Exit 5 means there was no verdict to bind. A receipt file written anyway would be the verdict of a run that
    did not happen, which is worse than no file (class 1)."""
    d = tmp_path / "manifests"
    d.mkdir()
    (d / "ok.yaml").write_text(_DEPLOY, encoding="utf-8")
    (d / "broken.yaml").write_text("a: [unclosed\n", encoding="utf-8")
    out = tmp_path / "r.json"
    rc, _, _ = _run(["audit", "-f", str(d), "--receipt", str(out)])
    assert rc == 5
    assert not out.exists()


def test_a_receipt_path_in_a_folder_that_is_not_there_is_a_usage_error(bundle: Path, tmp_path: Path) -> None:
    rc, _, err = _run(["audit", "-f", str(bundle), "--receipt", str(tmp_path / "nope" / "r.json")])
    assert rc == 2, err


@pytest.mark.parametrize("extra", [[], ["--compact"], ["--oscal"], ["--format", "sarif"]])
def test_the_flag_that_changes_the_report_does_not_change_the_receipt(
    bundle: Path, tmp_path: Path, extra: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """`--compact`, `--oscal` and `--format sarif` each REPLACE or reshape the report. The receipt binds the
    verdict, not the view, so its payload is the same bytes under all of them -- the same promise the exit code
    already makes (class 25: fix the predicate, not the call site)."""
    import datetime as dt

    monkeypatch.setattr(receipt, "_now", lambda: dt.datetime(2026, 11, 15, 9, 0, 0, tzinfo=dt.UTC))
    out = tmp_path / f"r{len(extra)}{''.join(extra)[:4]}.json".replace("-", "")
    _run(["audit", "-f", str(bundle), "--receipt", str(out), *extra])
    baseline = tmp_path / "base.json"
    if not baseline.exists():
        _run(["audit", "-f", str(bundle), "--receipt", str(baseline)])
    assert receipt.canonical(_doc(out)["payload"]) == receipt.canonical(_doc(baseline)["payload"])


def test_a_receipt_is_checked_from_another_working_directory_with_base(tmp_path: Path) -> None:
    """A receipt travels with the files. `--base` resolves each recorded path under another checkout; the digests
    still have to match, so moving the files cannot turn a changed input into a reproduced verdict."""
    import os
    import shutil

    d = tmp_path / "repo"
    d.mkdir()
    (d / "ok.yaml").write_text(_DEPLOY, encoding="utf-8")
    out = tmp_path / "r.json"
    os.chdir(d)
    _run(["audit", "-f", ".", "--receipt", str(out)])
    other = tmp_path / "elsewhere"
    shutil.copytree(d, other)
    os.chdir(tmp_path)
    assert _run(["receipt", "verify", str(out), "--base", str(other), "--format", "json"])[0] == 0
    (other / "ok.yaml").write_text(_DEPLOY.replace("privileged: true", "privileged: false"), encoding="utf-8")
    rc, text, _ = _run(["receipt", "verify", str(out), "--base", str(other), "--format", "json"])
    assert rc == 5
    assert json.loads(text)["status"] == "cannot-be-checked"


# --- receipt verify: three answers ---------------------------------------------------------------------------------


def test_verify_says_the_verdict_is_reproduced_when_nothing_changed(bundle: Path, tmp_path: Path) -> None:
    out = tmp_path / "r.json"
    _run(["audit", "-f", str(bundle), "--receipt", str(out)])
    rc, text, _ = _run(["receipt", "verify", str(out), "--format", "json"])
    assert rc == 0
    assert json.loads(text)["status"] == "identical"


def test_verify_cannot_check_a_receipt_whose_input_is_gone_and_names_it(bundle: Path, tmp_path: Path) -> None:
    out = tmp_path / "r.json"
    _run(["audit", "-f", str(bundle), "--receipt", str(out)])
    bundle.unlink()
    rc, text, _ = _run(["receipt", "verify", str(out), "--format", "json"])
    assert rc == 5
    answer = json.loads(text)
    assert answer["status"] == "cannot-be-checked"
    assert any(str(bundle) in str(c["which"]) for c in answer["cannotCheck"])
    assert answer["verdictReproduced"] is None


def test_verify_cannot_check_a_receipt_whose_input_changed_and_names_it(bundle: Path, tmp_path: Path) -> None:
    """The dangerous reading is "the hash moved, so the verdict changed". It is not: a changed input is a DIFFERENT
    question, and answering it as "differs" would let a careless reader treat a re-audit as a reproduction."""
    out = tmp_path / "r.json"
    _run(["audit", "-f", str(bundle), "--receipt", str(out)])
    bundle.write_text(_DEPLOY.replace("privileged: true", "privileged: false"), encoding="utf-8")
    rc, text, _ = _run(["receipt", "verify", str(out), "--format", "json"])
    assert rc == 5
    answer = json.loads(text)
    assert answer["status"] == "cannot-be-checked"
    entry = next(c for c in answer["cannotCheck"] if c["what"] == "input")
    assert str(bundle) in str(entry["which"])
    assert "sha256" in entry["why"] or "digest" in entry["why"]


def test_verify_cannot_check_a_receipt_from_another_kube_noob_and_names_both_versions(
    bundle: Path, tmp_path: Path
) -> None:
    out = tmp_path / "r.json"
    _run(["audit", "-f", str(bundle), "--receipt", str(out)])
    doc = _doc(out)
    doc["payload"]["tool"]["version"] = "0.0.1"
    _rewrite(out, doc, redigest=True)
    rc, text, _ = _run(["receipt", "verify", str(out), "--format", "json"])
    assert rc == 5
    answer = json.loads(text)
    assert answer["status"] == "cannot-be-checked"
    entry = next(c for c in answer["cannotCheck"] if c["what"] == "toolVersion")
    from kube_noob import __version__

    assert "0.0.1" in entry["why"] and __version__ in entry["why"]


def test_verify_names_the_fields_that_differ_when_the_payload_claims_another_verdict(
    bundle: Path, tmp_path: Path
) -> None:
    """A re-digested payload is self-consistent, so the only way to catch it is to re-run the inputs."""
    out = tmp_path / "r.json"
    _run(["audit", "-f", str(bundle), "--receipt", str(out)])
    doc = _doc(out)
    doc["payload"]["verdict"]["counts"]["critical"] = 99
    _rewrite(out, doc, redigest=True)
    rc, text, _ = _run(["receipt", "verify", str(out), "--format", "json"])
    assert rc == 1
    answer = json.loads(text)
    assert answer["status"] == "differs"
    assert any(d["field"] == "verdict.counts.critical" for d in answer["differs"])
    assert answer["verdictReproduced"] is False


def test_verify_refuses_a_receipt_whose_payload_does_not_match_its_digest(bundle: Path, tmp_path: Path) -> None:
    """One byte of one finding changed, digest left alone: the document is not self-consistent, so it is refused
    rather than checked. Exit 4 (refused input), never 0."""
    out = tmp_path / "r.json"
    _run(["audit", "-f", str(bundle), "--receipt", str(out)])
    doc = _doc(out)
    fp = doc["payload"]["verdict"]["findings"][0]["fingerprint"]
    doc["payload"]["verdict"]["findings"][0]["fingerprint"] = ("0" if fp[0] != "0" else "1") + fp[1:]
    _rewrite(out, doc, redigest=False)
    rc, _, err = _run(["receipt", "verify", str(out), "--format", "json"])
    assert rc == 4
    assert "payloadDigest" in err or "digest" in err


def test_verify_cannot_check_a_receipt_with_an_unknown_schema(tmp_path: Path) -> None:
    out = tmp_path / "r.json"
    out.write_text(json.dumps({"schema": "kube-noob.receipt/99", "payload": {}, "integrity": {}}), encoding="utf-8")
    rc, _, err = _run(["receipt", "verify", str(out)])
    assert rc == 4
    assert "kube-noob.receipt/99" in err


def test_verify_cannot_check_a_receipt_whose_run_it_cannot_replay_and_says_which_input(tmp_path: Path) -> None:
    """A gate run that also read a Containerfile, a scanner report or a rendered chart is not replayable from the
    files the receipt binds, so the answer is the third one, naming the input class -- never a pass."""
    man = tmp_path / "app.yaml"
    man.write_text(_DEPLOY, encoding="utf-8")
    cf = tmp_path / "Containerfile"
    cf.write_text("FROM registry.access.redhat.com/ubi9/ubi:latest\nUSER 0\n", encoding="utf-8")
    out = tmp_path / "r.json"
    _run(["gate", "-f", str(man), "--containerfile", str(cf), "--receipt", str(out)])
    assert _doc(out)["payload"]["replay"]["supported"] is False
    rc, text, _ = _run(["receipt", "verify", str(out), "--format", "json"])
    assert rc == 5
    answer = json.loads(text)
    assert answer["status"] == "cannot-be-checked"
    entry = next(c for c in answer["cannotCheck"] if c["what"] == "replay")
    assert entry["which"] == "gate" and "Containerfile" in entry["why"]
    # The text view names the thing and the reason once each, not the reason twice.
    rc_text, out_text, _ = _run(["receipt", "verify", str(out)])
    assert rc_text == 5
    assert "cannot check the replay gate:" in out_text
    assert out_text.count("a Containerfile was audited as a build") == 1


def test_stdin_is_bound_by_hash_but_cannot_be_checked_because_its_bytes_are_not_a_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "r.json"
    monkeypatch.setattr("sys.stdin", io.StringIO(_DEPLOY))
    _run(["audit", "-f", "-", "--receipt", str(out)])
    got = _doc(out)["payload"]["inputs"][0]
    assert got["path"] == "-" and got["resolvedPath"] is None and got["sha256"]
    assert "standard input" in got["notRetrievable"]
    rc, text, _ = _run(["receipt", "verify", str(out), "--format", "json"])
    assert rc == 5
    assert json.loads(text)["status"] == "cannot-be-checked"


def test_a_file_added_to_the_directory_since_cannot_be_checked(tmp_path: Path) -> None:
    """Per-input digests cannot see a file ADDED to a directory: the receipt names what it read, the replay reads
    those files, both agree, and `audit -f dir/` today would answer differently. The input-set digest catches it,
    and a skipped input reading as complete is the defect that is."""
    d = tmp_path / "manifests"
    d.mkdir()
    (d / "ok.yaml").write_text(_DEPLOY, encoding="utf-8")
    out = tmp_path / "r.json"
    _run(["audit", "-f", str(d), "--receipt", str(out)])
    assert _run(["receipt", "verify", str(out), "--format", "json"])[0] == 0
    (d / "second.yaml").write_text(_DEPLOY.replace("name: app", "name: app2"), encoding="utf-8")
    rc, text, _ = _run(["receipt", "verify", str(out), "--format", "json"])
    assert rc == 5
    answer = json.loads(text)
    assert answer["status"] == "cannot-be-checked"
    assert any("set of files" in c["why"] for c in answer["cannotCheck"])


# --- the gate ------------------------------------------------------------------------------------------------------


def test_gate_writes_a_receipt_whose_exit_code_is_the_one_the_gate_returned(tmp_path: Path) -> None:
    man = tmp_path / "app.yaml"
    man.write_text(_DEPLOY, encoding="utf-8")
    out = tmp_path / "r.json"
    rc, _, _ = _run(["gate", "-f", str(man), "--receipt", str(out)])
    payload = _doc(out)["payload"]
    assert payload["command"] == "gate"
    assert payload["verdict"]["exitCode"] == rc == 1
    assert payload["verdict"]["findings"]


def test_a_gate_receipt_of_manifests_alone_is_reproduced(tmp_path: Path) -> None:
    man = tmp_path / "app.yaml"
    man.write_text(_DEPLOY, encoding="utf-8")
    out = tmp_path / "r.json"
    _run(["gate", "-f", str(man), "--receipt", str(out)])
    rc, text, _ = _run(["receipt", "verify", str(out), "--format", "json"])
    assert rc == 0, text
    assert json.loads(text)["status"] == "identical"


def test_writing_a_receipt_says_on_stderr_what_it_does_not_prove(bundle: Path, tmp_path: Path) -> None:
    """The caveat must not live only inside the JSON: a reader meeting the word "receipt" in a compliance pack
    will read it as a signature, and the one moment the person who made it is certainly looking is now."""
    out = tmp_path / "r.json"
    _, _, err = _run(["audit", "-f", str(bundle), "--receipt", str(out)])
    assert "unsigned" in err
    assert "nothing about who produced it" in err
    assert "receipt verify" in err


def test_a_gate_receipt_records_the_gates_own_headline_word(tmp_path: Path) -> None:
    """The gate's headline is `incomplete`, never `passed`, while the audit under it reached no verdict (G272).
    The receipt records that word beside the exit code, from `gate.verdict_word` -- the same function every
    renderer calls -- so the two cannot be read apart."""
    f = tmp_path / "ro.yaml"
    f.write_text(_ROLLOUT, encoding="utf-8")
    out = tmp_path / "r.json"
    rc, _, _ = _run(["gate", "-f", str(f), "--fail-on", "never", "--receipt", str(out)])
    assert rc == 1
    payload = _doc(out)["payload"]
    assert payload["scope"]["gateVerdict"] == "incomplete"
    assert payload["verdict"]["exitCode"] == 1
    assert "not audited" in (payload["verdict"]["scoreWithheld"] or "")
    assert payload["scope"]["notAudited"]


def test_a_scope_list_that_was_cut_says_how_much(tmp_path: Path) -> None:
    """A cap with no count is the defect where truncation hides what it dropped. The count is recorded even when
    it is zero, so a reader can always tell a complete list from a cut one."""
    docs = "\n---\n".join(
        _DEPLOY.replace("name: app", f"name: app-{i}").replace("app: app", f"app: app-{i}") for i in range(3)
    )
    f = tmp_path / "many.yaml"
    f.write_text(docs, encoding="utf-8")
    out = tmp_path / "r.json"
    _run(["audit", "-f", str(f), "--receipt", str(out)])
    scope = _doc(out)["payload"]["scope"]
    assert scope["resourcesWithheld"] == 0 and scope["assumptionsWithheld"] == 0
    assert len(scope["resources"]) == scope["documents"]
    assert receipt.capped(list(range(700))) == (list(range(500)), 200)


def test_a_receipt_that_is_not_there_is_exit_2_not_a_refused_document(tmp_path: Path) -> None:
    """2 is the published meaning of "a file that is not there"; 4 is a refused input. A receipt nobody has handed
    over yet is the first, and reporting it as the second would tell a pipeline the document was rejected."""
    rc, _, err = _run(["receipt", "verify", str(tmp_path / "nope.json")])
    assert rc == 2, err


def test_the_temporary_file_a_receipt_is_written_through_is_not_a_guessable_name(bundle: Path, tmp_path: Path) -> None:
    """`<path>.partial` beside a path the caller chose is a name something else can plant a link at first."""
    out = tmp_path / "r.json"
    _run(["audit", "-f", str(bundle), "--receipt", str(out)])
    assert not (tmp_path / "r.json.partial").exists()
    left = sorted(f.name for f in tmp_path.iterdir() if f.is_file())
    assert left == ["app.yaml", "r.json"], left


def test_a_gate_that_exits_5_still_has_a_verdict_and_the_receipt_records_that_code(tmp_path: Path) -> None:
    """The asymmetry with `audit` is deliberate and it is about whether a verdict exists. `audit` refuses before
    it reads anything, so there is nothing to bind; the gate audits what it could read and then exits 5, so there
    IS a verdict -- and a receipt that recorded 1 for a run that exited 5 would contradict the contract."""
    d = tmp_path / "manifests"
    d.mkdir()
    (d / "ok.yaml").write_text(_DEPLOY, encoding="utf-8")
    (d / "broken.yaml").write_text("a: [unclosed\n", encoding="utf-8")
    out = tmp_path / "r.json"
    rc, _, err = _run(["gate", "-f", str(d), "--receipt", str(out)])
    assert rc == 5, err
    payload = _doc(out)["payload"]
    assert payload["verdict"]["exitCode"] == 5
    # 5 is "no verdict was reached because the evidence offered was not enough", which is a different question
    # from "is this a pass": the audit under the gate WAS determined, so nothing is withheld and the gate's own
    # word is `failed` (AGENTS.md, G272). The unread file is named either way.
    assert payload["verdict"]["scoreWithheld"] is None
    assert payload["scope"]["gateVerdict"] == "failed"
    assert [b["path"] for b in payload["scope"]["inputsNotRead"]]


# --- the output boundary -------------------------------------------------------------------------------------------


def test_the_receipt_is_written_through_the_one_output_boundary(tmp_path: Path) -> None:
    """A CI step that prints a receipt must not run a workflow command out of it (G279)."""
    doc = {"payload": {"note": "##[set-output name=x]"}, "integrity": {}, "envelope": {}}
    out = tmp_path / "r.json"
    receipt.write(out, doc)
    text = out.read_text(encoding="utf-8")
    assert "##[" not in text
    assert "\\u005b" in text
    assert json.loads(text)["payload"]["note"] == "##[set-output name=x]"


def test_a_hostile_input_path_in_a_receipt_reaches_the_reader_through_the_boundary(tmp_path: Path) -> None:
    """A receipt's input paths come from whoever ran the audit, and `receipt verify` echoes one when it cannot get
    the file. A path carrying a bidi override, a tag character or a terminal escape must arrive marked, never
    spliced into a plain name and never as a sequence the terminal runs (class 7, G279)."""
    from kube_noob import sanitize

    chars = ("\u061c", "\u00ad", "\U000e0041", "\u202e", "\u2066", "\u200b", "\x1b")
    name = "m" + "m".join(chars) + "m.yaml"
    src = tmp_path / name
    src.write_text(_DEPLOY, encoding="utf-8")
    out = tmp_path / "r.json"
    assert _run(["audit", "-f", str(src), "--receipt", str(out)])[0] == 1
    src.unlink()
    rc, text, err = _run(["receipt", "verify", str(out)])
    assert rc == 5
    shown = text + err
    assert shown.strip()
    assert not any(ch in shown for ch in chars), ascii(shown)[:400]
    assert "\x07" not in shown
    assert sanitize.visible_lines(shown) == shown
    assert "mmmmmmm.yaml" not in shown, "the hostile name was spliced into a plain one"


def test_a_receipt_file_is_written_readable_only_by_its_owner(bundle: Path, tmp_path: Path) -> None:
    import stat

    out = tmp_path / "r.json"
    _run(["audit", "-f", str(bundle), "--receipt", str(out)])
    assert stat.S_IMODE(out.stat().st_mode) == 0o600


def test_the_receipt_flag_refuses_the_stream_the_report_uses(bundle: Path, tmp_path: Path) -> None:
    rc, _, err = _run(["audit", "-f", str(bundle), "--receipt", "-"])
    assert rc == 2
    assert "path" in err


def test_a_reader_gone_before_verify_writes_its_answer_is_exit_141(bundle: Path, tmp_path: Path) -> None:
    """`receipt verify` writes a document, so it owes the same contract every other document writer here owes:
    the reader that went away gets exit 141, not the code of a truncated answer (G279)."""
    import os
    import subprocess
    import sys

    out = tmp_path / "r.json"
    _run(["audit", "-f", str(bundle), "--receipt", str(out)])
    r, w = os.pipe()
    os.close(r)
    env = {**os.environ, "PYTHONPATH": str(_ROOT / "src")}
    env.pop("KUBE_NOOB_DEBUG", None)
    p = subprocess.Popen(
        [sys.executable, "-m", "kube_noob", "receipt", "verify", str(out), "--format", "json"],
        stdout=w,
        stderr=subprocess.PIPE,
        env=env,
    )
    os.close(w)
    _, err = p.communicate(timeout=300)
    assert p.returncode == 141, (p.returncode, err.decode()[-500:])


def test_a_receipt_is_written_whole_or_not_at_all(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Half a receipt reads as a receipt (class 16), so it is written to a temporary file and moved into place.
    A write that fails leaves whatever was there, and leaves no half-written file behind either."""
    import os

    out = tmp_path / "r.json"
    out.write_text("{}", encoding="utf-8")

    def boom(src: Any, dst: Any) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError):
        receipt.write(out, {"payload": {"a": 1}, "integrity": {}, "envelope": {}})
    monkeypatch.undo()
    assert out.read_text(encoding="utf-8") == "{}"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["r.json"]


# --- the MCP tool --------------------------------------------------------------------------------------------------


def test_the_verify_receipt_tool_answers_from_the_text_it_is_given(bundle: Path, tmp_path: Path) -> None:
    from kube_noob.config import load_settings
    from kube_noob.toolkit import Toolkit, VerifyReceiptIn

    out = tmp_path / "r.json"
    _run(["audit", "-f", str(bundle), "--receipt", str(out)])
    kit = Toolkit(load_settings())
    good = kit.verify_receipt(VerifyReceiptIn(receipt=out.read_text(encoding="utf-8"), manifests=_DEPLOY))
    assert good["status"] == "identical"
    bad = kit.verify_receipt(
        VerifyReceiptIn(receipt=out.read_text(encoding="utf-8"), manifests=_DEPLOY.replace("true", "false"))
    )
    assert bad["status"] == "cannot-be-checked"
    none = kit.verify_receipt(VerifyReceiptIn(receipt=out.read_text(encoding="utf-8")))
    assert none["status"] == "cannot-be-checked"


def test_the_verify_receipt_tool_does_not_strip_the_bytes_it_hashes() -> None:
    """Every other input on this server is whitespace-stripped. This one must not be: a receipt binds bytes, and
    trimming a trailing newline before hashing would turn every honest check into "the input changed", which is
    the one answer this tool exists to tell apart from a changed verdict."""
    from kube_noob.toolkit import VerifyReceiptIn

    assert VerifyReceiptIn(receipt="{}", manifests="a: 1\n").manifests == "a: 1\n"


def test_the_verify_receipt_tool_is_offered_and_counted(tmp_path: Path) -> None:
    from kube_noob.config import load_settings
    from kube_noob.toolkit import Toolkit

    names = {t.name for t in Toolkit(load_settings()).specs()}
    assert "verify_receipt" in names


# --- documentation -------------------------------------------------------------------------------------------------


def test_the_documents_say_integrity_not_authenticity() -> None:
    uc = (_ROOT / "docs" / "use-cases.md").read_text(encoding="utf-8")
    section = uc[uc.index("receipt") :] if "receipt" in uc else ""
    assert "SHA-256" in section
    assert "who produced it" in section
