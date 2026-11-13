"""GitHub Actions workflow commands in kube-noob's output (G279, review CP3-Q3).

The runner reads a workflow command from EVERY line a step writes. Two parsers, ported below from actions/runner
v2.321.0, ``src/Runner.Common/ActionCommand.cs`` (``TryParseV2``, ``TryParse``) and the command list registered
in ``src/Runner.Worker/ActionCommandManager.cs`` (``stop-commands`` plus each ``IActionCommandExtension``,
matched without regard to case; ``internal-set-repo-path`` is registered only while a plugin runs):

* ``TryParseV2``: the line, after ``TrimStart()``, starts with ``::`` and has a second ``::``; the word before
  the first space is the command.
* ``TryParse`` (legacy): ``##[`` ANYWHERE in the line, up to the next ``]``; the word before the first space is
  the command.

A ConfigMap key such as ``p##[stop-commands]resumetoken99`` printed in an audit line therefore stopped command
processing for the rest of the step; ``q##[error file=...]All checks passed`` forged an annotation;
``r##[set-output name=result]passed`` set a step output; ``s##[add-mask]KN-S026`` masked text. Every text
kube-noob writes now goes through ``sanitize.CommandGuard`` at the output boundary, always (a log is replayed
later, so GITHUB_ACTIONS says nothing): ``##[`` becomes ``## [`` and a line-leading ``::`` becomes ``: :``. The
only workflow commands left are the annotations ``gate --github-annotations`` writes on purpose.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from kube_noob import sanitize

# actions/runner v2.321.0 src/Runner.Worker/ActionCommandManager.cs: _stopCommand and every extension's Command.
REGISTERED = {
    "stop-commands",
    "set-env",
    "set-output",
    "save-state",
    "add-mask",
    "add-path",
    "add-matcher",
    "remove-matcher",
    "debug",
    "warning",
    "error",
    "notice",
    "group",
    "endgroup",
    "echo",
}
# .NET's Char.IsWhiteSpace, which String.TrimStart() trims.
_DOTNET_SPACE = (
    "\t\n\x0b\x0c\r \x85\xa0\u1680" + "".join(map(chr, range(0x2000, 0x200B))) + "\u2028\u2029\u202f\u205f\u3000"
)


def try_parse_v2(message: str) -> str | None:
    """ActionCommand.TryParseV2 (actions/runner v2.321.0): the command name, or None."""
    message = message.lstrip(_DOTNET_SPACE)
    if not message.startswith("::"):
        return None
    end = message.find("::", 2)
    if end < 0:
        return None
    name = message[2:end].split(" ", 1)[0]
    return name if name.lower() in REGISTERED else None


def try_parse(message: str) -> str | None:
    """ActionCommand.TryParse, the legacy ``##[`` form (actions/runner v2.321.0): the command name, or None."""
    p = message.find("##[")
    if p < 0:
        return None
    rb = message.find("]", p)
    if rb < 0:
        return None
    name = message[p + 3 : rb].split(" ", 1)[0]
    return name if name.lower() in REGISTERED else None


def commands(text: str) -> list[tuple[int, str, str]]:
    """Every line the runner would take for a command, as ActionCommandManager.TryProcessCommand tries them:
    V2 first, then the legacy form. The runner reads lines as .NET's StreamReader.ReadLine splits them."""
    found = []
    for i, line in enumerate(text.replace("\r\n", "\n").replace("\r", "\n").split("\n")):
        name = try_parse_v2(line) or try_parse(line)
        if name:
            found.append((i, name, line))
    return found


PAYLOADS = [
    "p##[stop-commands]resumetoken99",
    "q##[error file=.github/workflows/release.yml,line=1,title=kube-noob]All checks passed",
    "r##[set-output name=result]passed",
    "s##[add-mask]KN-S026",
]
V2_PAYLOADS = ["::stop-commands::tok", "  ::error::forged", "\u3000::set-output name=x::y", "::ADD-MASK::KN"]


def test_the_ported_parser_sees_every_payload() -> None:
    """The port is only worth something if it sees what the runner sees."""
    assert [try_parse(p) for p in PAYLOADS] == ["stop-commands", "error", "set-output", "add-mask"]
    assert [try_parse_v2(p) for p in V2_PAYLOADS] == ["stop-commands", "error", "set-output", "ADD-MASK"]
    assert try_parse("##[unknown]x") is None and try_parse_v2(": :error::x") is None


@pytest.mark.parametrize("payload", PAYLOADS + V2_PAYLOADS + ["a\n::error::x", "##[##[error]x", "###[error]x"])
def test_the_guard_leaves_no_command(payload: str) -> None:
    out = sanitize.CommandGuard().feed(f"[HIGH] KN-S026 ConfigMap/shop/leg data.{payload}\n{payload}\n")
    assert commands(out) == [], out


def test_the_guard_works_across_writes() -> None:
    """print() writes the text and the newline separately, and a caller may write a line in pieces."""
    for pieces in (["#", "#[error]x"], ["##", "[error]x"], ["  ", ":", ":error::x"], ["ok\n", "::error::x"]):
        g = sanitize.CommandGuard()
        out = "".join(g.feed(p) for p in pieces)
        assert commands(out) == [], (pieces, out)


def test_the_guard_changes_nothing_else() -> None:
    text = "[HIGH] KN-S026 a: b :: c ## [x] #[y] url http://a::b/ fe80::1\n  - item: ok\n"
    assert sanitize.CommandGuard().feed(text) == text
    # the marker names the character broken (third review: `: :` and `## [` read as text with a space in it)
    assert sanitize.CommandGuard().feed("::error::x") == "<U+003A>:error::x"
    assert sanitize.CommandGuard().feed("a##[b]") == "a##<U+005B>b]"


def _legacy_cm(tmp_path: Path) -> Path:
    cm = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": "leg", "namespace": "shop"},
        "data": dict.fromkeys([*PAYLOADS, "t::error::colons"], "postgres://u:hunter2@db/x"),
    }
    f = tmp_path / "leg.yaml"
    f.write_text(json.dumps(cm), encoding="utf-8")
    return f


def _run(argv: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str, str]:
    from kube_noob.cli import main

    rc = main(argv)
    out = capsys.readouterr()
    return rc, out.out, out.err


def _gate_annotations_only(found: list[tuple[int, str, str]]) -> list[tuple[int, str, str]]:
    """What is left once kube-noob's own annotations are set aside: they are V2 commands, built by gate."""
    return [f for f in found if not (try_parse_v2(f[2]) in {"error", "warning"} and f[2].startswith("::"))]


@pytest.mark.parametrize(
    "argv",
    [
        ["audit", "-f", "F"],
        ["audit", "-f", "F", "--compact"],
        ["--format", "json", "audit", "-f", "F"],
        ["--format", "yaml", "audit", "-f", "F"],
        ["--format", "sarif", "audit", "-f", "F"],
        ["gate", "-f", "F", "--fail-on", "never"],
        ["gate", "-f", "F", "--fail-on", "never", "--github-annotations"],
        ["--format", "json", "gate", "-f", "F", "--fail-on", "never"],
        ["fix", "-f", "F"],
        ["ksi", "-f", "F"],
    ],
    ids=" ".join,
)
def test_no_command_reaches_the_log_from_a_manifest(
    argv: list[str], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    f = _legacy_cm(tmp_path)
    rc, out, err = _run([str(f) if x == "F" else x for x in argv], capsys)
    assert rc in (0, 1, 3), err[-400:]
    assert "KN-S026" in out or "leg" in out, out[:400]
    assert _gate_annotations_only(commands(out)) == [], commands(out)
    assert commands(err) == [], commands(err)
    if "--format" in argv and argv[1] in {"json", "sarif"}:
        assert set(json.dumps(json.loads(out))) and PAYLOADS[0] in out.replace("\\u005b", "[")
        assert PAYLOADS[0] in json.dumps(json.loads(out), ensure_ascii=False)  # lossless: the data is the data
    if "--format" in argv and argv[1] == "yaml":
        assert PAYLOADS[0] in json.dumps(yaml.safe_load(out), ensure_ascii=False)


def test_the_gate_annotations_are_the_only_commands_and_they_still_parse(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    f = _legacy_cm(tmp_path)
    _, out, _ = _run(["gate", "-f", str(f), "--fail-on", "high", "--github-annotations"], capsys)
    found = commands(out)
    assert found and {name for _, name, _ in found} <= {"error", "warning"}, found
    for _, _, line in found:
        assert line.startswith("::") and "##[" not in line, line  # one command each, nothing smuggled in it


@pytest.mark.parametrize(
    "argv",
    [
        ["diagnose", "PAYLOAD"],
        ["insight", "PAYLOAD"],
        ["known-issues", "PAYLOAD"],
        ["audit", "-f", "/nonexistent/PAYLOAD.yaml"],  # the error path, on stderr
    ],
    ids=lambda v: v[0],
)
@pytest.mark.parametrize("payload", PAYLOADS + ["::error::forged"])
def test_no_command_reaches_the_log_from_pasted_text_or_an_error(
    argv: list[str], payload: str, capsys: pytest.CaptureFixture[str]
) -> None:
    text = f"Back-off restarting failed container\n{payload}\nOOMKilled {payload}"
    _, out, err = _run([x.replace("PAYLOAD", text if x == "PAYLOAD" else payload) for x in argv], capsys)
    assert out + err, argv  # something was written, and none of it is a command
    assert commands(out) == [] and commands(err) == [], (commands(out), commands(err))


def test_the_yaml_document_keeps_a_colon_pair_off_the_start_of_a_line() -> None:
    from kube_noob.yamlio import dump_documents, dump_yaml

    long = "x " * 70 + "::error::forged " + "y " * 70
    data: dict[str, Any] = {"a": long, "::error::k": "v", "b": "line1\n::stop-commands::t\nline3", "c": "##[group]g"}
    for text in (dump_yaml(data, width=120), dump_documents([data])):
        assert commands(text) == [], text
        assert yaml.safe_load(text.replace("---\n", "", 1)) == data  # lossless


def test_the_files_gate_writes_carry_no_command_either(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Not stdout, but a CI step that prints the SARIF, Code Quality or HTML file must not run a command from it."""
    f = _legacy_cm(tmp_path)
    files = {k: tmp_path / f"out.{k}" for k in ("sarif", "codequality", "html")}
    argv = ["gate", "-f", str(f), "--fail-on", "never", *[x for k, p in files.items() for x in (f"--{k}", str(p))]]
    _run(argv, capsys)
    for k, p in files.items():
        text = p.read_text(encoding="utf-8")
        assert "KN-S026" in text and commands(text) == [], (k, commands(text))
    sarif = json.loads(files["sarif"].read_text(encoding="utf-8"))
    assert PAYLOADS[0] in json.dumps(sarif, ensure_ascii=False)  # the same data, escaped differently
