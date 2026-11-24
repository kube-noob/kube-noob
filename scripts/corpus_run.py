#!/usr/bin/env python3
"""Run kube-noob over the adversarial corpus and assert each case's recorded honest answer.

    python scripts/corpus_run.py

The corpus (``corpus/``) is a set of Kubernetes manifests built to make a scanner under-report, each with the
honest answer recorded beside it in ``honest-answer.yaml``. This runner is the other half: it drives the real CLI
over every case and fails when an answer is not the recorded one, so the corpus is also a regression suite.

Three things it deliberately does NOT do.

* It does not re-derive a verdict. Each command's verdict word is read from the word that command itself
  publishes -- ``gate``'s own ``incomplete``/``passed`` keys, ``posture diff``'s own ``verdict`` -- or, where a
  command publishes the word only as its exit status, from that status by the published exit-code contract
  (``posture scan``: 5 is "the evidence was incomplete"). A runner with its own opinion about what the answer
  should have been is a second source of truth for the thing it is checking (review class 9).
* It does not adjust a recorded answer to match what the tool does. A disagreement is reported as a
  disagreement; which of the two is wrong is a question for a person, and the corpus's README says which way the
  presumption runs.
* It reads no clock, no network and no cluster. ``posture snapshot`` writes its snapshots into a directory this
  runner makes per run and deletes after, so two runs over the same corpus assert the same thing.

Exit status: 0 when every case answered as recorded, 1 when any did not, 2 when the corpus itself is malformed.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "corpus"
RECORD = "honest-answer.yaml"

#: How each command's own verdict word is read out of its own output. The key is the command as it appears on the
#: command line, longest match first, so `posture diff` is not read as `posture`.
_READERS = ("gate", "audit", "posture diff", "posture scan")


@dataclass(frozen=True)
class Result:
    """What one command did: its exit status and its two streams, as bytes-faithful text."""

    code: int
    out: str
    err: str


def _command_of(argv: list[str]) -> str:
    """Which command this argv runs, found by the command NAME and not by position.

    Stripping the flags and taking the first token left would read `--format json gate` as the command `json`,
    which is review class 22: argv is not a list of words with the flags removed. The command names kube-noob
    defines are not values any flag in the corpus takes, so the first token that IS one of them is the command,
    and a group command (`posture`) takes the next token with it.
    """
    heads = {name.split()[0] for name in _READERS}
    for index, token in enumerate(argv):
        if token not in heads:
            continue
        rest = [t for t in argv[index + 1 :] if not t.startswith("-")]
        for name in sorted(_READERS, key=len, reverse=True):
            parts = name.split()
            if parts[0] == token and rest[: len(parts) - 1] == parts[1:]:
                return name
    raise SystemExit(f"corpus_run: no verdict reader for {' '.join(argv)!r}")


def verdict_word(argv: list[str], result: Result) -> str:
    """The word the command itself used, never a word this runner decided on.

    `gate` publishes two booleans and its text headline is one of three words over them. `posture diff`
    publishes `verdict`. `posture scan` publishes no verdict field: its answer about completeness is its exit
    status, where 5 means the evidence was incomplete (AGENTS.md, "Exit codes are a public contract"), and it
    prints that word on stderr, which this runner checks rather than assuming.
    """
    name = _command_of(argv)
    if name == "posture scan":
        if result.code == 5:
            if "incomplete" not in result.err:
                raise AssertionError(f"exit 5 without the word on stderr: {result.err.strip()!r}")
            return "incomplete"
        return "complete"
    doc = _json(result)
    if name == "posture diff":
        return str(doc.get("verdict") or "determined")
    if name == "gate":
        if doc.get("incomplete"):
            return "incomplete"
        return "passed" if doc.get("passed") else "failed"
    summary = doc.get("summary") or {}
    return str(summary.get("verdict") or "determined")


def named_objects(argv: list[str], result: Result) -> list[str]:
    """Everything the answer says it did not read, as the answer itself names it."""
    name = _command_of(argv)
    if name == "posture scan":
        doc = _json(result)
        return [str(x) for x in (doc.get("notRead") or [])]
    doc = _json(result)
    out = [str(row.get("object", "")) for row in (doc.get("notAudited") or [])]
    out += [str(x) for x in (doc.get("unreadable") or [])]
    out += [str(x) for x in (doc.get("skipped") or [])]
    out += [str(x) for x in (doc.get("resources") or [])]
    return [x for x in out if x]


def _json(result: Result) -> dict[str, Any]:
    try:
        doc = json.loads(result.out)
    except json.JSONDecodeError as exc:
        raise AssertionError(f"not one JSON document on stdout: {exc}") from exc
    if not isinstance(doc, dict):
        raise AssertionError(f"stdout is not a JSON object but {type(doc).__name__}")
    return doc


def run(cwd: Path, argv: list[str], tmp: Path) -> Result:
    """The real CLI, as a child process, so the exit status is the published one and not a return value."""
    line = [sys.executable, "-m", "kube_noob.cli", *[a.replace("{tmp}", str(tmp)) for a in argv]]
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(ROOT / "src"), env.get("PYTHONPATH", "")]).rstrip(os.pathsep)
    env["KUBE_NOOB_LEARNING_ENABLED"] = "false"
    env["KUBE_NOOB_DATA_DIR"] = str(tmp / "data")
    env["XDG_CONFIG_HOME"] = str(tmp / "cfg")
    for var in ("KUBE_NOOB_CONFIG", "KUBE_NOOB_WEB_ENABLED", "KUBE_NOOB_CLUSTER_ENABLED", "KUBE_NOOB_DEFAULT_PLATFORM"):
        env.pop(var, None)
    done = subprocess.run(line, cwd=cwd, env=env, capture_output=True, text=True, check=False)
    return Result(done.returncode, done.stdout, done.stderr)


def cases() -> list[Path]:
    found = sorted(p.parent for p in CORPUS.glob(f"*/{RECORD}"))
    if not found:
        raise SystemExit(f"corpus_run: no case with a {RECORD} under {CORPUS}")
    return found


def record_of(case: Path) -> dict[str, Any]:
    doc = yaml.safe_load((case / RECORD).read_text(encoding="utf-8"))
    if not isinstance(doc, dict):
        raise SystemExit(f"corpus_run: {case.name}/{RECORD} is not a mapping")
    missing = [k for k in ("id", "object", "mechanism", "honest") if k not in doc]
    if missing:
        raise SystemExit(f"corpus_run: {case.name}/{RECORD} has no {', '.join(missing)}")
    if doc["id"] != case.name:
        raise SystemExit(f"corpus_run: {case.name}/{RECORD} calls itself {doc['id']!r}")
    for key in ("command", "verdict", "exit_code", "must_name"):
        if key not in doc["honest"]:
            raise SystemExit(f"corpus_run: {case.name}/{RECORD} records no honest.{key}")
    return doc


def _open_defects(doc: dict[str, Any]) -> list[dict[str, Any]]:
    """Answers recorded as measured-but-not-honest. Each must name the guidance row that holds the measurement."""
    raw = doc.get("open_defect")
    rows = raw if isinstance(raw, list) else ([] if raw is None else [raw])
    for row in rows:
        missing = [k for k in ("guidance", "command", "measured") if k not in row]
        if missing:
            raise SystemExit(f"corpus_run: {doc['id']} open_defect has no {', '.join(missing)}")
    return rows


def check(case: Path, doc: dict[str, Any], tmp: Path) -> list[str]:
    """Every way this case's answer differs from the recorded one. Empty means it answered as recorded."""
    wrong: list[str] = []
    for step in doc.get("setup") or []:
        got = run(case, list(step), tmp)
        if got.code != 0:
            wrong.append(f"setup {' '.join(step)} exited {got.code}: {got.err.strip()[:200]}")
            return wrong
    honest = doc["honest"]
    got = run(case, list(honest["command"]), tmp)
    if got.code != honest["exit_code"]:
        wrong.append(f"exit code is {got.code}, recorded {honest['exit_code']}")
    try:
        word = verdict_word(list(honest["command"]), got)
    except AssertionError as exc:
        wrong.append(str(exc))
    else:
        if word != honest["verdict"]:
            wrong.append(f"verdict is {word!r}, recorded {honest['verdict']!r}")
    try:
        named = named_objects(list(honest["command"]), got)
    except AssertionError as exc:
        wrong.append(str(exc))
    else:
        for want in honest["must_name"]:
            if not any(want in entry for entry in named):
                wrong.append(f"the answer never names {want!r}")
    again = run(case, list(honest["command"]), tmp)
    if again.out != got.out:
        wrong.append("two runs over the same files printed different bytes")
    for extra in doc.get("also") or []:
        more = run(case, list(extra["command"]), tmp)
        if more.code != extra["exit_code"]:
            wrong.append(f"{' '.join(extra['command'])} exited {more.code}, recorded {extra['exit_code']}")
        for prefix in extra.get("no_output_line_starts_with") or []:
            for stream, text in (("stdout", more.out), ("stderr", more.err)):
                for number, line in enumerate(text.splitlines(), start=1):
                    if line.startswith(prefix):
                        wrong.append(f"{stream} line {number} begins {prefix!r}: {line[:80]!r}")
    return wrong


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--case", action="append", help="only this case id; repeat")
    args = parser.parse_args(argv)
    wanted = set(args.case or [])
    failures = 0
    checked = 0
    for case in cases():
        if wanted and case.name not in wanted:
            continue
        doc = record_of(case)
        tmp = Path(tempfile.mkdtemp(prefix="kube-noob-corpus-"))
        try:
            wrong = check(case, doc, tmp)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        checked += 1
        if wrong:
            failures += 1
            print(f"DISAGREES  {case.name}")
            for line in wrong:
                print(f"           {line}")
        else:
            print(f"as recorded {case.name}: {doc['honest']['verdict']}, exit {doc['honest']['exit_code']}")
        for open_defect in _open_defects(doc):
            # Printed, never asserted. A runner that held an open defect in place would fail the commit that
            # fixed it, and a corpus that keeps quiet about one is a corpus with a pass in it.
            print(f"  open defect ({open_defect['guidance']}): kube-noob {' '.join(open_defect['command'])}")
            print(f"           {open_defect['measured']}")
    if not checked:
        print("corpus_run: no case matched", file=sys.stderr)
        return 2
    print(f"\n{checked} case(s); {failures} disagreed with the recorded honest answer")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
