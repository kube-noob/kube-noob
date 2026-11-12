"""The third review of G279: what still reached a CI log or a reader unchanged, and what still read as data.

Each test names the review item it holds. The runner's own parsers are ported in tests/test_workflow_commands.py
(actions/runner v2.321.0); Azure Pipelines (``##vso[``) and TeamCity (``##teamcity[``) read their service
messages anywhere in a line, so those are matched as substrings here.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from kube_noob import sanitize
from tests.test_workflow_commands import commands

_OTHER_CI = re.compile(r"##(?:vso|teamcity)\[", re.IGNORECASE)


def ci_commands(text: str) -> list[Any]:
    """Every workflow command GitHub, Azure Pipelines or TeamCity would read from ``text``."""
    found: list[Any] = list(commands(text))
    found += [(i, "other-ci", line) for i, line in enumerate(text.split("\n")) if _OTHER_CI.search(line)]
    return found


HOSTILE = [
    "p##[stop-commands]resumetoken99",
    "q##[error file=.github/workflows/release.yml,line=1,title=kube-noob]All checks passed",
    "k##vso[task.setvariable variable=KUBECONFIG]/tmp/evil",
    "##teamcity[setParameter name=x value=y]",
    "mon##[endgroup]",
]


def _run(argv: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str, str]:
    from kube_noob.cli import main

    rc = main(argv)
    out = capsys.readouterr()
    return rc, out.out, out.err


# ------------------------------------------------------------------ 5 + Q2: one unambiguous, always-on rewrite


@pytest.mark.parametrize(
    ("raw", "shown"),
    [
        ("a##[error]x", "a##<U+005B>error]x"),
        ("k##vso[task.setvariable variable=K]v", "k##vso<U+005B>task.setvariable variable=K]v"),
        ("##teamcity[setParameter name=x]", "##teamcity<U+005B>setParameter name=x]"),
        ("::error::x", "<U+003A>:error::x"),
        ("  ::warning::x", "  <U+003A>:warning::x"),
        ("a: b :: c ## [x] #[y] fe80::1 listen [::]:80;", "a: b :: c ## [x] #[y] fe80::1 listen [::]:80;"),
    ],
)
def test_the_guard_marks_the_one_character_that_makes_a_command(raw: str, shown: str) -> None:
    """`## [` and `: :` were ambiguous: a reader could not tell them from text that had a space there. The marker
    names the character that was broken, in the style `visible` already uses."""
    assert sanitize.CommandGuard().feed(raw) == shown
    assert ci_commands(sanitize.CommandGuard().feed(raw + "\n")) == []


@pytest.mark.parametrize(
    "pieces",
    [
        ["#", "#vs", "o[task.setvariable]x\n"],
        ["##teamci", "ty[x]\n"],
        [":", ":error::x\n"],
        ["  :", ":error::x\n"],
        ["ok\n:", ":", "error::x\n"],
    ],
)
def test_the_guard_is_the_same_however_the_text_is_split(pieces: list[str]) -> None:
    whole = sanitize.CommandGuard().feed("".join(pieces))
    g = sanitize.CommandGuard()
    assert "".join(g.feed(p) for p in pieces) + g.flush() == whole
    assert ci_commands(whole) == []


def test_a_lone_colon_at_the_start_of_a_line_is_written_when_the_stream_is_flushed() -> None:
    g = sanitize.CommandGuard()
    assert g.feed(":") + g.flush() == ":"
    assert g.feed(":x") == "<U+003A>x"  # the first was already written: the second is the one marked


def test_the_rewrite_does_not_depend_on_the_terminal() -> None:
    """Same input, same bytes: the rule is on whether or not the stream is a TTY."""
    import io

    from kube_noob.cli import _VisibleStream

    class Tty(io.StringIO):
        def isatty(self) -> bool:
            return True

    a, b = io.StringIO(), Tty()
    for inner in (a, b):
        s = _VisibleStream(inner)
        s.write("x##[error]y\n::error::z\n")
        s.flush()
    assert a.getvalue() == b.getvalue() == "x##<U+005B>error]y\n<U+003A>:error::z\n"


# ------------------------------------------------------------------------------- 6: an escape inside a name


def test_an_escape_between_identifier_characters_is_marked_and_in_prose_removed() -> None:
    assert sanitize.visible_lines("web\x1b[31mx", mark=True) == "web<ESC>x"
    assert sanitize.visible_lines("web\x1b[31m\x1b[1mx", mark=True) == "web<ESC>x"
    assert sanitize.visible_lines("a \x1b[31mred\x1b[0m.", mark=True) == "a red."
    assert sanitize.visible_lines("web\x1b[31mx") == "webx"  # without mark: removed, as for MCP


# -------------------------------------------------------------------- 7: annotations clean, then escape


def test_an_annotation_is_cleaned_before_it_is_escaped() -> None:
    """Escaping first turned `%` into `%25`, and the cleaner then took `ESC %2` for an escape sequence: the runner
    showed `a5b` for `a<ESC>%b`. Cleaning first removes `ESC %b` as the sequence it is."""
    from kube_noob.gate import _annotation

    f = {"ruleId": "KN-S001", "title": "t", "resource": "Pod/x", "message": "a\x1b%b c%d", "severity": "high"}
    line = _annotation("error", f)
    data = line.split("::", 2)[2]
    expected = sanitize.visible("a\x1b%b c%d", mark=True).replace("%", "%25")
    assert data.endswith(expected), (data, expected)
    assert "5b" not in data.split("Pod/x", 1)[1]


# ------------------------------------------------------------------------------- 1: documents and headers


def _exceptions_file(tmp_path: Path) -> Path:
    f = tmp_path / "exc.yaml"
    f.write_text(
        yaml.safe_dump(
            {
                "apiVersion": "kube-noob.io/v1",
                "kind": "ExceptionList",
                "exceptions": [
                    {
                        "id": "EXC-001",
                        "rule": "KN-S009",
                        "scope": {"namespace": "monitoring", "kind": "DaemonSet", "name": "node-exporter"},
                        "owner": "team",
                        "reason": "reviewed\n::error title=forged::forged\nsee ##[group]grp ##vso[task.complete]",
                        "expires": "2020-06-30",
                        "ticket": "OPS-1",
                    },
                    {
                        "id": "EXC-002",
                        "rule": "KN-S009",
                        "scope": {"namespace": "mon##[endgroup]", "kind": "DaemonSet", "name": "node-exporter"},
                        "owner": "o##[debug]x",
                        "reason": "active ##[add-mask]abc ##teamcity[x]",
                        "expires": "2027-06-30",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    return f


def test_policy_generate_composes_no_command_into_its_header(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The header echoed an exception's namespace and reason: `mon##[endgroup]` was a parsed endgroup in stdout
    and in the -o file. Comments are kube-noob's own text, so changing them changes no data."""
    exc = _exceptions_file(tmp_path)
    out_file = tmp_path / "p.yaml"
    _, stdout, _ = _run(["policy", "generate", "--engine", "kyverno", "--exceptions", str(exc)], capsys)
    _run(["policy", "generate", "--engine", "kyverno", "--exceptions", str(exc), "-o", str(out_file)], capsys)
    assert stdout == out_file.read_text(encoding="utf-8")
    assert "EXC-002" in stdout and ci_commands(stdout) == [], ci_commands(stdout)
    assert list(yaml.safe_load_all(stdout))  # still a valid set of documents


def _hostile_manifest(tmp_path: Path) -> Path:
    docs = [
        {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": "c", "namespace": "shop", "annotations": {"note": "\n".join(HOSTILE)}},
            "data": dict.fromkeys(HOSTILE, "postgres://u:hunter2@db/x") | {"m": "a\n::error::forged\nb"},
        },
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "web", "namespace": "shop"},
            "spec": {
                "selector": {"matchLabels": {"app": "web"}},
                "template": {
                    "metadata": {"labels": {"app": "web"}},
                    "spec": {"containers": [{"name": "c", "image": "web:latest", "args": HOSTILE}]},
                },
            },
        },
    ]
    f = tmp_path / "m.yaml"
    f.write_text("---\n".join(json.dumps(d) + "\n" for d in docs), encoding="utf-8")
    return f


DOCUMENTS = [
    ["fix", "-f", "M"],
    ["--format", "json", "fix", "-f", "M"],
    ["fix", "-f", "M", "-o", "OUT"],
    ["--format", "json", "audit", "-f", "M", "--oscal"],
    ["--format", "sarif", "audit", "-f", "M"],
    ["--format", "yaml", "audit", "-f", "M"],
    ["gate", "-f", "M", "--fail-on", "never", "--sarif", "OUT", "--codequality", "OUT2", "--html", "OUT3"],
]


@pytest.mark.parametrize("argv", DOCUMENTS, ids=" ".join)
def test_no_document_built_from_hostile_input_carries_a_command(
    argv: list[str], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    m = _hostile_manifest(tmp_path)
    paths = {"M": m, "OUT": tmp_path / "o1", "OUT2": tmp_path / "o2", "OUT3": tmp_path / "o3"}
    _, out, err = _run([str(paths[x]) if x in paths else x for x in argv], capsys)
    texts = {"stdout": out, "stderr": err}
    texts |= {k: p.read_text(encoding="utf-8") for k, p in paths.items() if k != "M" and p.exists()}
    for name, text in texts.items():
        assert ci_commands(text) == [], (name, ci_commands(text)[:3])


def test_the_helm_chart_files_carry_no_command(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from kube_noob.generate import helm
    from kube_noob.generate.blueprint import Blueprint

    bp = Blueprint.model_validate(
        {
            "name": "web",
            "namespace": "shop",
            "image": "registry.example.com/web:1.0",
            "env": {"MSG": "a ##[error]x ##vso[task.x]y"},
        }
    )
    helm.generate_chart(bp, str(tmp_path / "chart"))
    for p in (tmp_path / "chart").rglob("*"):
        if p.is_file():
            assert ci_commands(p.read_text(encoding="utf-8")) == [], p


# ------------------------------------------------------------------------------------ 4: admission review


def test_admission_review_prints_the_document_unchanged_and_command_free(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Through the text boundary `##[x]` became `## [x]` inside the AdmissionReview: the document changed."""
    req = {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "request": {
            "uid": "u1",
            "kind": {"group": "", "version": "v1", "kind": "ConfigMap"},
            "namespace": "shop",
            "operation": "CREATE",
            "object": {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {"name": "cfg", "namespace": "shop"},
                "data": {"##[x]": "postgres://u:hunter2@db/x"},
            },
        },
    }
    f = tmp_path / "r.json"
    f.write_text(json.dumps(req), encoding="utf-8")
    _, out, _ = _run(["admission", "review", "-f", str(f)], capsys)
    doc = json.loads(out)
    assert any("'##[x]'" in w for w in doc["response"].get("warnings", [])), doc
    assert ci_commands(out) == []


def test_no_document_is_printed_through_the_text_boundary() -> None:
    """A document printed with `print(json.dumps(...))` is changed by the boundary. Only text views may print."""
    src = (Path(__file__).resolve().parents[1] / "src" / "kube_noob" / "cli.py").read_text(encoding="utf-8")
    assert not re.search(r"print\(json\.dumps\(", src)


# ------------------------------------------------------------------------- 3: YAML keeps its readable style


NGINX = "server {\n    listen 80;\n    listen [::]:80;\n    location / { proxy_pass http://[::1]:8080; }\n}\n"


def test_a_config_file_with_colon_pairs_keeps_its_block_style() -> None:
    from kube_noob.yamlio import dump_documents, dump_yaml

    data = {"nginx.conf": NGINX, "addr": "fe80::1", "path": "std::io::Write"}
    documents = dump_documents([data])
    assert "nginx.conf: |" in documents, documents  # the block style a GitOps diff reads line by line
    plain = dump_yaml(data, sort_keys=False, width=120, allow_unicode=True)
    assert plain == yaml.safe_dump(data, sort_keys=False, width=120, allow_unicode=True)  # byte for byte
    for text in (documents, plain):
        assert "addr: fe80::1" in text and "path: std::io::Write" in text
        assert yaml.safe_load(text.replace("---\n", "", 1)) == data
        assert ci_commands(text) == []


@pytest.mark.parametrize("sep", ["\u2060", '"', "\\", "\x1b", "\u00e9", " ", "\t", "\u3000"])
def test_a_colon_pair_after_an_escaped_character_never_starts_a_folded_line(sep: str) -> None:
    """PyYAML folds a double-quoted scalar at a space AND right after any escape it writes (`\\"`, `\\\\`,
    `\\e`, `\\u2060`): the end-to-end fuzz found `    ::set-output name=o::P` as a continuation line. Every
    column the colon pair can land on is tried."""
    from kube_noob.yamlio import dump_documents, dump_yaml

    for n in range(60, 200):
        for filler in ("x", "x y "):
            data = {"k": (filler * n)[:n] + sep + "::error::z tail", "m": "a\nb" + sep + "::warning::w"}
            for text in (dump_yaml(data, width=120, allow_unicode=True), dump_documents([data])):
                assert ci_commands(text) == [], (n, filler, text)
                assert yaml.safe_load(text.replace("---\n", "", 1)) == data


def test_a_string_a_line_of_which_could_start_with_a_colon_pair_is_still_quoted() -> None:
    from kube_noob.yamlio import dump_documents

    data = {"a": "x\n  ::error::y", "b": "w " * 70 + "::warning::z " + "q " * 70, "c": "x ##vso[task.x]y"}
    text = dump_documents([data])
    assert ci_commands(text) == [], text
    assert yaml.safe_load(text.replace("---\n", "", 1)) == data


# ------------------------------------------------------------------------------------------- 2: watch


def test_watch_writes_through_the_boundary() -> None:
    from kube_noob import cli

    assert ("watch",) not in cli._UNWRAPPED
    assert {("serve",), ("mcp",), ("admission", "serve")} == cli._UNWRAPPED


# ------------------------------------------------------------------------- 9: an unexpected error, one line


def test_an_unexpected_error_is_one_clean_line_and_exit_4(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from kube_noob import cli

    def boom(a: Any, s: Any) -> int:
        raise RuntimeError("bad \x1b[31mname\n::error::forged ##[group]g")

    monkeypatch.setattr(cli, "_dispatch", boom)
    monkeypatch.delenv("KUBE_NOOB_DEBUG", raising=False)
    rc, _, err = _run(["known-issues", "x"], capsys)
    assert rc == 4
    assert "Traceback" not in err and len(err.strip().splitlines()) == 1, err
    assert "RuntimeError" in err and "\x1b" not in err and ci_commands(err) == []

    monkeypatch.setenv("KUBE_NOOB_DEBUG", "1")
    rc, _, err = _run(["known-issues", "x"], capsys)
    assert rc == 4 and "Traceback" in err and "\x1b" not in err and ci_commands(err) == []


# --------------------------------------------------------------------------- 10: the offline CNI default


def test_an_offline_answer_the_admin_tier_decides_says_which_cni_semantics_it_used(
    capsys: pytest.CaptureFixture[str],
) -> None:
    ex = Path(__file__).resolve().parents[1] / "examples" / "netpol-admin-tiers.yaml"
    docs = [d for d in yaml.safe_load_all(ex.read_text(encoding="utf-8")) if isinstance(d, dict)]
    wl = [
        f"{d['metadata'].get('namespace', 'default')}/{d['metadata']['name']}"
        for d in docs
        if d.get("kind") in ("Deployment", "StatefulSet", "DaemonSet", "Pod")
    ]
    base = ["policy", "reach", "-f", str(ex), "--from", wl[0], "--to", wl[1], "--port", "8080"]
    _, text, _ = _run(base, capsys)
    _, js, _ = _run(["--format", "json", *base], capsys)
    caveat = "evaluated with OVN-Kubernetes semantics; pass --cni"
    assert caveat in text, text
    assert any(caveat in n for n in json.loads(js)["notes"])
    _, named, _ = _run([*base, "--cni", "ovn-kubernetes"], capsys)
    assert caveat not in named


# ------------------------------------------------------------------------ 11: a list response needs a kind


def test_a_list_response_without_a_kind_is_not_a_list() -> None:
    """A misrouted endpoint answering `{"items": []}` is not "none exist"."""
    from kube_noob.debug.cluster import list_items
    from kube_noob.errors import ClusterAccessError

    with pytest.raises(ClusterAccessError, match="kind"):
        list_items({"items": []}, "networkpolicies", "shop")
    assert list_items({"kind": "NetworkPolicyList", "items": []}, "networkpolicies", "shop") == []
    assert list_items({"kind": "List", "items": []}, "networkpolicies", "shop") == []


# ------------------------------------------------------------------------------ 8: seven more evasions


EVASIONS_3 = {
    "aliased module": 'import unicodedata as ud\nok = [c for c in s if ud.category(c)[0] != "C"]',
    "range membership": "ok = [c for c in s if ord(c) not in range(0x7f, 0xa0)]",
    "dict-comprehension table": "T = {i: None for i in range(32)}\nout = s.translate(T)",
    "string.printable filter": 'import string\nok = "".join(c for c in s if c in string.printable)',
    "bytes decode": "ESC = bytes([27]).decode()",
    "chr of int literal": 'ESC = chr(int("1b", 16))',
    "codecs unicode_escape": 'import codecs\nESC = codecs.decode("\\\\x1b", "unicode_escape")',
}


@pytest.mark.parametrize("name", sorted(EVASIONS_3))
def test_the_structural_check_sees_seven_more_ways(name: str) -> None:
    from tests.private_lists import private_lists

    assert private_lists(f"import re, unicodedata\n{EVASIONS_3[name]}\n"), name


def test_the_structural_check_still_passes_ordinary_code() -> None:
    from tests.private_lists import private_lists

    ok = [
        "import string\nLETTERS = set(string.ascii_letters)",
        "T = {ord(c): None for c in '|*'}\nout = s.translate(T)",
        "n = int('1b', 16)",
        "data = bytes([1, 2, 3])",
        "import codecs\nb = codecs.decode(h, 'hex')",
        "ok = [x for x in xs if x in range(1, 10)]",
    ]
    for src in ok:
        assert not private_lists(src), src


def test_the_debug_variable_and_exit_4_are_documented() -> None:
    root = Path(__file__).resolve().parents[1]
    for doc in ("AGENTS.md", "SECURITY.md"):
        assert "KUBE_NOOB_DEBUG" in (root / doc).read_text(encoding="utf-8"), doc
