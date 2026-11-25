"""A command we print is a command that runs.

Two different claims live in the docs and they need two different checks.

A command inside a fenced block is an instruction: a reader copies the line and runs it, so it has to reach
the code. That is checked by handing the words to the real parser and refusing any exit the parser calls an
error.

A command in backticks in a sentence or a table cell is usually a reference -- `kube-noob audit` names the
command, it is not a runnable line, and demanding `-f` there would force a rewrite of a hundred correct
sentences. What a reference still has to get right is the NAME: every leading word has to be a command that
exists. `kube-noob posture history` named a subcommand that was never there, and no test looked, because the
only guard walked the longest real prefix of the words and `posture` exists (G237).

Neither check runs a command. The parser is asked to parse and nothing else, so a command that reads a
cluster or the network is as safe to check as `--help`.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import pathlib
import re
import shlex

import pytest

from kube_noob.cli import build_parser

ROOT = pathlib.Path(__file__).resolve().parents[1]

_FENCE = re.compile(r"^\s*```")
_INLINE = re.compile(r"`(kube-noob [^`]+)`")
_COMMENT = re.compile(r"\s+#.*$")

# A line with any of these is not one command's worth of words: it has a placeholder a reader fills in, a
# pipe or a chain, a shell expansion, or a glob. Those are read by a person, not by a parser.
_NOT_ONE_COMMAND = re.compile(r"[<>|&$`*?{}\[\]]|\\$|\.\.\.")

# The docs that print commands. `docs/guidance.md` is in here on purpose: it is the defect ledger, and a row
# that quotes a command has to quote it correctly.
_DOCS = ("README.md", *(f"docs/{p.name}" for p in sorted((ROOT / "docs").glob("*.md"))))

# A reference that names a command which deliberately does not exist, because the row's subject IS that it
# does not exist. Keyed by (doc, the command text) -- never by line number, since guidance.md grows at the
# bottom and every row below a new one would shift.
_EXEMPT: dict[tuple[str, str], str] = {
    ("docs/guidance.md", "kube-noob vuln rank"): (
        "G237 quotes it as one of the three subcommands a red team found printed and unrunnable; the row is "
        "about the name being wrong, so the name has to stay wrong"
    ),
}

# Floors, so that an extractor that silently stops matching cannot pass by finding nothing. Measured, not
# guessed: raise them when the docs grow, and never lower one to make a run go green.
_MIN_FENCED = 150
_MIN_INLINE = 100


def _body(doc: str) -> list[tuple[int, str, bool]]:
    """Every line of a doc, with its number and whether it sits inside a fenced block."""
    out: list[tuple[int, str, bool]] = []
    inside = False
    for n, raw in enumerate((ROOT / doc).read_text(encoding="utf-8").splitlines(), 1):
        if _FENCE.match(raw):
            inside = not inside
            continue
        out.append((n, raw, inside))
    return out


def _clean(text: str) -> str:
    return _COMMENT.sub("", text).strip()


def _fenced() -> list[tuple[str, int, str]]:
    """Commands a reader is meant to run."""
    found = []
    for doc in _DOCS:
        for n, raw, inside in _body(doc):
            if not inside:
                continue
            line = raw.strip().removeprefix("$ ").strip()
            if not line.startswith("kube-noob "):
                continue
            line = _clean(line)
            if _NOT_ONE_COMMAND.search(line):
                continue
            found.append((doc, n, line))
    return found


def _inline() -> list[tuple[str, int, str]]:
    """Commands a sentence or a table cell names."""
    found = []
    for doc in _DOCS:
        for n, raw, inside in _body(doc):
            if inside:
                continue
            for cmd in _INLINE.findall(raw):
                line = _clean(cmd)
                if _NOT_ONE_COMMAND.search(line):
                    continue
                found.append((doc, n, line))
    return found


def _subcommands(parser: argparse.ArgumentParser) -> dict[str, argparse.ArgumentParser]:
    for action in parser._actions:  # argparse publishes no accessor for this
        if isinstance(action, argparse._SubParsersAction):
            return dict(action.choices)
    return {}


def _unknown_name(argv: list[str]) -> str | None:
    """The first leading word that is not a command, or None when every one of them is."""
    parser = build_parser()
    for word in argv:
        if word.startswith("-"):
            return None
        sub = _subcommands(parser)
        if not sub:
            return None
        if word not in sub:
            return f"{word!r} is not one of {sorted(sub)}"
        parser = sub[word]
    return None


def _parse_error(argv: list[str]) -> str | None:
    """What the parser said, when it refused these words."""
    parser = build_parser()
    buf = io.StringIO()
    try:
        with contextlib.redirect_stderr(buf), contextlib.redirect_stdout(buf):
            parser.parse_args(argv)
    except SystemExit as exc:
        if exc.code in (0, None):
            return None
        said = buf.getvalue().strip().splitlines()
        return said[-1].strip() if said else f"exit {exc.code}"
    except Exception as exc:  # noqa: BLE001 - any refusal of the words is the finding
        return f"{type(exc).__name__}: {exc}"
    return None


def test_both_checks_can_still_refuse() -> None:
    """A check that cannot fail is not a check.

    Without this, a `return None` dropped into either helper turns 285 passing cases into 285 passing cases,
    and the next wrong command in the docs ships. These two argv are the exact shapes the two checks exist
    for: a flag the command does not take, and a subcommand that does not exist.
    """
    assert _parse_error(["corpus", "jira", "--min-version", "4.10"]) is not None, (
        "the fenced-block check no longer refuses an unrecognised flag"
    )
    assert _parse_error(["audit"]) is not None, "the fenced-block check no longer refuses a missing required argument"
    assert _unknown_name(["posture", "history"]) is not None, (
        "the name check no longer refuses a subcommand that does not exist"
    )
    assert _unknown_name(["audit"]) is None, (
        "the name check refuses a real command with its arguments left off, which is what a sentence does"
    )


def test_the_scan_found_the_commands() -> None:
    """A check that found nothing passes for the wrong reason."""
    fenced, inline = _fenced(), _inline()
    assert len(fenced) >= _MIN_FENCED, f"only {len(fenced)} fenced commands; the extractor stopped matching"
    assert len(inline) >= _MIN_INLINE, f"only {len(inline)} inline commands; the extractor stopped matching"


@pytest.mark.parametrize(("doc", "line_no", "command"), _fenced(), ids=str)
def test_every_command_in_a_fenced_block_runs(doc: str, line_no: int, command: str) -> None:
    said = _parse_error(shlex.split(command)[1:])
    assert said is None, f"{doc}:{line_no} prints a command that cannot run: {command}\n  {said}"


@pytest.mark.parametrize(("doc", "line_no", "command"), _inline(), ids=str)
def test_every_command_a_sentence_names_exists(doc: str, line_no: int, command: str) -> None:
    if (doc, command) in _EXEMPT:
        pytest.skip(_EXEMPT[(doc, command)])
    said = _unknown_name(shlex.split(command)[1:])
    assert said is None, f"{doc}:{line_no} names a command that does not exist: {command}\n  {said}"


def test_no_exemption_outlives_its_reason() -> None:
    """An exemption for a command that is now spelled right, or now gone, is a lie the next reader inherits."""
    seen = {(doc, command) for doc, _n, command in _inline()}
    for key, why in _EXEMPT.items():
        assert key in seen, f"{key} is exempt but no longer in the docs -- drop the exemption ({why})"
        assert _unknown_name(shlex.split(key[1])[1:]) is not None, (
            f"{key} is exempt but now names a real command -- drop the exemption ({why})"
        )
