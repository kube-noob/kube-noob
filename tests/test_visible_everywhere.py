"""Invisible characters do not reach terminal or file output from any module (G279).

`sanitize.visible` (G270) works on Unicode categories. Eleven modules kept their own hand-written control-character
lists, which missed U+061C (Arabic letter mark), U+00AD (soft hyphen), the tag block (U+E0000-U+E007F) and the bidi
overrides and isolates. MCP results pass through `sanitize.clean`, so the gap was terminal and file output: text,
Markdown job summaries, SARIF, HTML, tickets. Each test puts those characters into the untrusted field one module
echoes and checks the output; the last one fails if a twelfth module writes its own list again.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from kube_noob import sanitize

#: The characters the private lists missed, and the bidi override every list should have had.
HOSTILE_CHARS = (
    "\u061c",  # ARABIC LETTER MARK (Cf)
    "\u00ad",  # SOFT HYPHEN (Cf)
    "\U000e0041",  # TAG LATIN CAPITAL LETTER A (Cf)
    "\U000e007f",  # CANCEL TAG (Cf)
    "\u202e",  # RIGHT-TO-LEFT OVERRIDE (Cf)
    "\u2066",  # LEFT-TO-RIGHT ISOLATE (Cf)
    "\u200b",  # ZERO WIDTH SPACE (Cf)
    "\x1b",  # ESC
)
HOSTILE = "x" + "x".join(HOSTILE_CHARS) + "x"


def _clean(text: str) -> bool:
    return not any(ch in text for ch in HOSTILE_CHARS)


# ------------------------------------------------------------------------------------------- the shared helper


def test_the_shared_variants_keep_what_each_caller_needs() -> None:
    assert sanitize.visible("a \u202eb") == "a b"  # in prose, format characters go without a space
    assert sanitize.visible("a\u202eb") == "a<U+202E>b"  # inside a name, marked (fourth review)
    assert sanitize.visible_lines("a\u202eb\nc\td\re") == "a<U+202E>b\nc\td e"
    assert sanitize.visible_squeezed("a\r\n\u202e\u061cb  c") == "a b  c"
    assert sanitize.visible("a/\x07b", replacement="?") == "a/?b"
    assert sanitize.has_invisible("ls\u202e") and sanitize.has_invisible("ls\t-l")
    assert not sanitize.has_invisible("ls\t-l", keep="\t") and not sanitize.has_invisible("oc get pods -n shop")
    for text in ("plain text", "na\u00efve caf\u00e9 \u2192 \u2713 \u65e5\u672c\u8a9e", "  two  spaces  ", ""):
        for fn in (sanitize.visible, sanitize.visible_lines, sanitize.visible_squeezed):
            assert fn(text) == text, (fn.__name__, text)


# ------------------------------------------------------------------------------------------- the eleven modules


def test_cli_terminal_lines(capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    """`_tprint` leaves the cleaning to the output boundary (fourth review), so it is tested through it."""
    import sys

    from kube_noob.cli import _tprint, _VisibleStream

    monkeypatch.setattr(sys, "stdout", _VisibleStream(sys.stdout))
    _tprint(f"name {HOSTILE}\nsecond line\twith a tab")
    out = capsys.readouterr().out
    assert _clean(out) and out.endswith("second line\twith a tab\n")


NETPOL = """
apiVersion: v1
kind: Namespace
metadata: {name: shop}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: orders, namespace: shop}
spec:
  template:
    metadata: {labels: {app: orders}}
    spec: {containers: [{name: c, image: o, ports: [{containerPort: 8080}]}]}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: shop}
spec:
  template:
    metadata: {labels: {app: web}}
    spec: {containers: [{name: c, image: w}]}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: "deny%s"
  namespace: shop
spec: {podSelector: {}, policyTypes: [Ingress]}
"""


@pytest.mark.parametrize(
    "written",
    [
        HOSTILE.replace("\x1b", "\\e"),  # the characters as they are (YAML spells ESC as \e)
        # JSON-style escapes: YAML decodes "\udb40\udc41" to two LONE surrogates, which made print() raise and
        # the command exit 4 with "surrogates not allowed" instead of answering
        json.dumps(HOSTILE)[1:-1],
    ],
)
def test_netpol_policy_names_in_the_text_view(tmp_path: Path, capsys: pytest.CaptureFixture[str], written: str) -> None:
    from kube_noob.cli import main

    f = tmp_path / "np.yaml"
    f.write_text(NETPOL % written, encoding="utf-8")
    rc = main(["policy", "reach", "--from", "shop/web", "--to", "shop/orders", "--port", "8080", "-f", str(f)])
    out = capsys.readouterr().out
    assert rc == 1 and "shop/deny" in out and _clean(out), out
    assert not any(0xD800 <= ord(ch) <= 0xDFFF for ch in out)


def test_policy_explain_denials() -> None:
    from kube_noob.debug.policy import explain

    text = (
        'Error from server: admission webhook "validate.kyverno.svc-fail" denied the request:\n\n'
        f"resource Deployment/shop/web was blocked due to the following policies\n\ndisallow-latest-tag:\n"
        f"  validate-image-tag: 'validation error: Using a mutable image tag e.g. latest {HOSTILE} is not allowed.'"
    )
    out = explain(text)
    assert out["denials"], out
    assert _clean(json.dumps(out, ensure_ascii=False))


def test_kyverno_migrate_header_lines() -> None:
    from kube_noob.kyverno_migrate import _header

    out = _header([f"from policy {HOSTILE}", "line\u2028two"])
    assert _clean(out) and out.count("\n") == 2 and all(ln.startswith("# ") for ln in out.splitlines())


def _sarif(message: str, uri: str) -> str:
    return json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {"name": "semgrep", "rules": [{"id": "r1", "properties": {"tags": ["security"]}}]}
                    },
                    "results": [
                        {
                            "ruleId": "r1",
                            "level": "error",
                            "message": {"text": message},
                            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
                        }
                    ],
                }
            ],
        }
    )


def test_code_sarif_messages_and_paths() -> None:
    from kube_noob.code import sarif

    rep = sarif.parse(_sarif(f"bad {HOSTILE} thing", f"src/a{HOSTILE}.py"), "t", roots=[])
    (finding,) = rep.findings
    assert _clean(finding.message) and "bad" in finding.message
    assert _clean(finding.location.path) and finding.location.resolved is False


def test_ticket_remarks() -> None:
    from kube_noob.tickets import _clip

    out = _clip(f"Fixed by {HOSTILE} upgrading")
    assert _clean(out) and out.startswith("Fixed by")


def test_alertmanager_labels_and_annotations() -> None:
    from kube_noob.signals.alertmanager import _clean as clean_value

    assert _clean(clean_value(f"KubePodCrashLooping {HOSTILE}"))


def test_gate_markdown_cells() -> None:
    from kube_noob.gate import _cell

    out = _cell(f"image {HOSTILE}\nrow")
    assert _clean(out) and "\n" not in out


def test_mustgather_names_with_invisible_characters_are_not_read_and_not_echoed(tmp_path: Path) -> None:
    from kube_noob.mustgather import ingest

    root = tmp_path / "mg" / "must-gather.local.1" / "quay-io-x"
    pods = root / "namespaces" / "shop" / "core"
    pods.mkdir(parents=True)
    (root / "version").write_text(f"oc 4.16\x1b[2J{HOSTILE}\n")
    (pods / "pods.yaml").write_text("kind: PodList\nitems: []\n")
    (pods / f"pods{HOSTILE.replace(chr(0x1B), '')}.yaml").write_text("kind: PodList\nitems: []\n")
    bundle = ingest.open_bundle(tmp_path / "mg")
    assert any("control characters in the name" in r for r in bundle.skipped)
    text = ingest.render_text(bundle)
    assert _clean(text), text
    assert _clean(json.dumps(bundle.as_dict(), ensure_ascii=False))


def test_vuln_report_strings() -> None:
    from kube_noob.vuln.reports import _s

    out = _s(f"openssl {HOSTILE}\r\n1.1")
    assert _clean(out) and "\n" not in out and out.startswith("openssl")


def test_a_remembered_command_with_invisible_characters_is_refused() -> None:
    from pydantic import ValidationError

    from kube_noob.memory.model import Command

    with pytest.raises(ValidationError, match="control characters"):
        Command(command="oc get pods\u202e -n shop", label="read-only")
    with pytest.raises(ValidationError, match="control characters"):
        Command(command="oc get pods\u00ad -n shop", label="read-only")
    assert Command(command="oc get pods\t-n shop", label="read-only").command == "oc get pods\t-n shop"


# ------------------------------------------------------------------- the HTML report and the Markdown writers


def _poison(node: Any, keys: frozenset[str]) -> Any:
    """Every string under one of ``keys`` (names, messages, paths: what came from the input) gets HOSTILE."""
    if isinstance(node, dict):
        return {k: (v + HOSTILE if isinstance(v, str) and k in keys else _poison(v, keys)) for k, v in node.items()}
    if isinstance(node, list):
        return [_poison(v, keys) for v in node]
    return node


UNTRUSTED_KEYS = frozenset(
    {"name", "message", "title", "path", "file", "object", "resource", "detail", "summary", "image", "ref", "target"}
)


def _gate_report(tmp_path: Path) -> dict[str, Any]:
    from kube_noob import gate

    manifest = (
        "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: web, namespace: shop}\nspec:\n  template:\n"
        "    spec:\n      containers: [{name: c, image: 'nginx:latest', securityContext: {privileged: true}}]\n"
    )
    path = tmp_path / "deploy.yaml"
    path.write_text(manifest)
    sources = gate.collect([str(path)], lambda p: Path(p).read_text())
    return gate.run(sources, platform="kubernetes", version="1.33")


def test_gate_markdown_job_summary(tmp_path: Path) -> None:
    from kube_noob import gate

    md = gate.markdown(_poison(_gate_report(tmp_path), UNTRUSTED_KEYS))
    assert "kube-noob gate" in md and _clean(md)


def test_the_html_report(tmp_path: Path) -> None:
    from kube_noob import report_html

    page = report_html.render(_poison(_gate_report(tmp_path), UNTRUSTED_KEYS))
    assert "<html" in page and _clean(page)


def test_the_diagnostic_bundle_markdown() -> None:
    from kube_noob.debug.diagnose import bundle_markdown

    md = bundle_markdown(
        {"target": f"deployment/shop/web{HOSTILE}", "backend": "oc", "evidence": [f"event {HOSTILE}"], "logs": {}}
    )
    assert _clean(md)


def test_the_drift_markdown() -> None:
    from kube_noob import drift

    obj = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "cm" + HOSTILE, "namespace": "shop"}}
    snap = drift.snapshot([obj], source="test")
    md = drift.markdown(drift.first_report(snap))
    assert _clean(md)


def test_the_threat_model_markdown() -> None:
    from kube_noob.vuln import threat

    text = (Path(__file__).parent / "fixtures" / "vuln" / "shop.yaml").read_text()
    text = re.sub(r"(?m)^(  name: )(\S+)$", lambda m: m.group(1) + json.dumps(m.group(2) + HOSTILE), text, count=1)
    md = threat.render_markdown(threat.model(text, platform="kubernetes"))
    assert _clean(md)


def test_the_mustgather_report_markdown(tmp_path: Path) -> None:
    from kube_noob.mustgather import analyse, ingest, report, sample

    b = ingest.open_bundle(sample.write(tmp_path))
    md = report.markdown(_poison(report.build(b, analyse.analyse(b)), UNTRUSTED_KEYS))
    assert _clean(md)


# ------------------------------------------------------------------------------------- the twelfth module

#: (file, the exact source of the expression) -> why it may stay outside sanitize.py. One entry per pattern, not
#: per file, so a second list added to an allowed file is still caught.
ALLOWED_PRIVATE: dict[tuple[str, str], str] = {
    ("src/kube_noob/tiers.py", 'r"^[^\\x00-\\x1f\\x7f]+\\Z"'): (
        "validates a configured tier name and refuses it; it cleans nothing and shows nothing"
    ),
    ("src/kube_noob/build/logs.py", 'r"\\x1b\\[[0-9;?]{0,20}[A-Za-z]|\\x1b\\][^\\x07]{0,200}\\x07"'): (
        "strips colour codes from a build log BEFORE its patterns run; an input normaliser that must keep every "
        "other character so the patterns still match"
    ),
    ("src/kube_noob/insight.py", 'r"\\x1b\\[[0-9;?]*[A-Za-z]"'): (
        "strips colour codes from pasted text before its patterns run, as above"
    ),
    ("src/kube_noob/audit/rules.py", '" \\t\\n\\r\\f\\v"'): (
        "the characters str.strip() and the generated admission policy's RE2 class treat as blank (G245); a "
        "definition of blank, not an output filter"
    ),
    ("src/kube_noob/toolkit.py", 'r"^[^\\x00]+$"'): "a tool argument's path pattern: refuses a NUL, shows nothing",
    (
        "src/kube_noob/toolkit.py",
        'r"^/[^\\x00]{0,499}$"',
    ): "a tool argument's path pattern: refuses a NUL, shows nothing",
    ("src/kube_noob/build/github_history.py", "c.isprintable"): (
        "refuses a token from the environment that holds whitespace or control characters; never shown"
    ),
    ("src/kube_noob/rhacs_central.py", "c.isprintable"): (
        "refuses a token from the environment that holds whitespace or control characters; never shown"
    ),
    ("src/kube_noob/build/containerfile.py", 'text.removeprefix("\\ufeff")'): (
        "drops a byte-order mark at the start of a Containerfile before it is parsed; one character, not a list"
    ),
}


def _private_lists(rel: str, src: str) -> list[tuple[int, str]]:
    from tests.private_lists import private_lists

    return [(line, seg) for line, seg in private_lists(src) if (rel, seg) not in ALLOWED_PRIVATE]


def test_no_module_outside_sanitize_keeps_its_own_control_character_list() -> None:
    """A private copy of what `sanitize.visible` does is how eleven modules came to miss U+061C, the soft hyphen
    and the tag block. `tests/private_lists.py` reads every module's syntax tree and says what it catches and what
    it cannot; anything it finds outside sanitize.py must be in ALLOWED_PRIVATE, per (file, expression), with why.
    """
    src = Path(__file__).resolve().parents[1] / "src" / "kube_noob"
    found = {}
    for path in sorted(src.rglob("*.py")):
        rel = path.relative_to(src.parents[1]).as_posix()
        if rel == "src/kube_noob/sanitize.py" or "/data/" in rel:
            continue
        hits = _private_lists(rel, path.read_text(encoding="utf-8"))
        if hits:
            found[rel] = hits
    assert found == {}, (
        "a private control-character list; use sanitize.visible / visible_lines / visible_squeezed / has_invisible "
        f"(or add (file, expression) to ALLOWED_PRIVATE with the reason): {found}"
    )
    for rel, seg in ALLOWED_PRIVATE:  # the allowlist cannot outlive the patterns it names
        assert seg in (src.parents[1] / rel).read_text(encoding="utf-8"), (rel, seg)


EVASIONS = {
    "bytes regex": 'BAD = re.compile(rb"[\\x00-\\x1f\\x7f]")',
    "range C1 ints": "BAD = {chr(c) for c in range(0x80, 0xa0)}",
    "getattr isprintable": 'ok = "".join(c for c in s if getattr(c, "isprintable")())',
    "filter(str.isprintable)": 'ok = "".join(filter(str.isprintable, s))',
    "aliased category": 'from unicodedata import category as cat\nok = [c for c in s if cat(c)[0] != "C"]',
    "join-built class": 'BAD = re.compile("[" + "".join(map(chr, range(32))) + "]")',
    "N{} bidi class": 'BAD = re.compile("[\\N{RIGHT-TO-LEFT OVERRIDE}\\N{LEFT-TO-RIGHT OVERRIDE}]")',
    "raw N{} class": 'BAD = re.compile(r"[\\N{ESCAPE}\\N{BELL}]")',
    "raw u0000-u001f": 'BAD = re.compile(r"[\\u0000-\\u001f]")',
    "raw u0080-u009f": 'BAD = re.compile(r"[\\u0080-\\u009f]")',
    "raw octal": 'BAD = re.compile(r"[\\0-\\37\\177]")',
    "f-string class": 'ESC = "\\x1b"\nBAD = re.compile(f"[{ESC}\\x07]")',
    "f-string raw": 'LO = 0\nBAD = re.compile(rf"[\\x{LO}0-\\x1f]")',
    "single raw ESC literal": 'BAD = s.replace("\\x1b", "")',
    "ord compare": 'ok = "".join(c for c in s if 32 <= ord(c) < 127)',
    "codec errors": 'ok = s.encode("ascii", "ignore").decode()',
    "isascii and isprintable": 'ok = "".join(c for c in s if c.isascii() and c.isprintable)',
    "hex escape upper U": 'BAD = re.compile("[\\U0000202E\\U0000202D]")',
    "regex unicode property": 'BAD = regex.compile(r"\\p{Cc}|\\p{Cf}")',
    "re.sub C0": 're.sub(r"[\\x00-\\x1F]", " ", s)',
    "constant pattern": 'X = r"[\\x7F-\\x9F]"',
    "octal ESC class": 'BAD = "[\\033]"',
    "category call": 'ok = [c for c in s if unicodedata.category(c) in ("Cc", "Cf")]',
    "chr ESC": "x = chr(0x1b)",
    "bidi class": 'BAD = "[\\u202a-\\u202e]"',
}
NOT_A_LIST = {
    "markdown pipe escape via translate": 'T = str.maketrans({"|": "\\\\|"})\nout = s.translate(T)',
    "path separator translate": 'name = s.translate(str.maketrans("/", "_"))',
    "accent folding via category": (
        'folded = "".join(c for c in unicodedata.normalize("NFD", s) if unicodedata.category(c) != "Mn")'
    ),
    "non-ASCII detection": 'NON_ASCII = re.compile("[^\\x20-\\x7e]")',
    "a help text naming an escape": 'HELP = "use \\\\x1b[31m for red"',
    "a whitespace class": 'WS = re.compile(r"[ \\t\\r\\n]+")',
    "an ASCII check": "ok = ord(c) < 128",
    "a loop over a range": "total = sum(i for i in range(32))",
}


@pytest.mark.parametrize("name", sorted(EVASIONS))
def test_the_structural_check_sees_the_usual_ways_to_write_a_list(name: str) -> None:
    assert _private_lists("src/kube_noob/x.py", f"import re, regex, unicodedata\n{EVASIONS[name]}\n"), name


@pytest.mark.parametrize("name", sorted(NOT_A_LIST))
def test_the_structural_check_does_not_fail_on_code_that_keeps_no_list(name: str) -> None:
    assert not _private_lists("src/kube_noob/x.py", f"import re, unicodedata\n{NOT_A_LIST[name]}\n"), name


# ------------------------------------------------------------------- the rule `visible` follows (review, G279)

#: Real text whose format characters are part of the word: each must come out exactly as it went in.
LEGITIMATE = {
    "hindi conjunct with ZWJ": "\u0915\u094d\u200d\u0937",
    "hindi word": "\u0928\u092e\u0938\u094d\u0924\u0947",
    "sinhala yansaya with ZWJ": "\u0dc1\u0dca\u200d\u0dbb\u0dd3",
    "kannada": "\u0c95\u0ca8\u0ccd\u0ca8\u0ca1",
    "malayalam chillu with ZWJ": "\u0d28\u0d4d\u200d",
    "persian with ZWNJ": "\u0645\u06cc\u200c\u062e\u0648\u0627\u0647\u0645",
    "arabic": "\u0645\u0631\u062d\u0628\u0627",
    "hebrew": "\u05e9\u05dc\u05d5\u05dd",
    "japanese": "\u65e5\u672c\u8a9e\u306e\u30c6\u30ad\u30b9\u30c8",
    "emoji ZWJ family": "\U0001f468\u200d\U0001f469\u200d\U0001f467",
    "emoji with variation selector and ZWJ": "\u2764\ufe0f\u200d\U0001f525",
    # assigned after Python 3.11's Unicode 14 table: kept the same on every interpreter
    "unicode 15 emoji": "\U0001fae8\U0001f6dc",
    "unicode 16 legacy computing": "\U0001cc00\U0001cc01",
    "unassigned today": "\U0002fa1f\U000300ff",
}


@pytest.mark.parametrize("name", sorted(LEGITIMATE))
def test_text_in_scripts_that_need_joiners_survives_unchanged(name: str) -> None:
    text = LEGITIMATE[name]
    for fn in (sanitize.visible, sanitize.visible_lines, sanitize.visible_squeezed):
        assert fn(text) == text, (fn.__name__, name)
    assert not sanitize.has_invisible(text)
    cleaned, _ = sanitize.clean(text)
    assert cleaned == text, name  # `clean` keeps the joiners in the same places


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        # Inside a name a removed character leaves a marker, never nothing: `paypal` is another name (fourth review)
        ("a\u202eb", "a<U+202E>b"),
        ("pay\u200bpal", "pay<U+200B>pal"),
        ("x\u200dy", "x<U+200D>y"),  # a joiner between ASCII letters only splits a word
        ("x\u200cy", "x<U+200C>y"),
        ("a \u202eb", "a b"),  # in prose: removed without a space
        ("\u05e9\u200f\u05dc", "\u05e9\u05dc"),  # RLM: invisible, removed without a space
        ("\ufeffkind", "kind"),
        ("a\U000e0041b", "a<U+E0041>b"),
        ("soft\u00adhyphen", "soft<U+00AD>hyphen"),
        ("a\ufff9b\ufffbc", "a<U+FFF9>b<U+FFFB>c"),
        ("a\x1b[31mred\x1b[0m", "a<ESC>red"),  # inside a word: marked; at its end, removed
        ("a \x1b[31mred\x1b[0m done", "a red done"),
        ("a\x1b]8;;http://evil.example\x1b\\link\x1b]8;;\x1b\\b", "a<ESC>link<ESC>b"),
        ("a\x1b]52;c;ZWNobyBwd25k\x07b", "a<ESC>b"),
        ("a\x9bb\x85c\x07d", "a b c d"),
        ("a\u2028b\u2029c", "a b c"),
        ("a\ud800b", "a b"),
        ("a\ue000b", "a b"),  # private use: what it shows depends on the reader's font
    ],
)
def test_hostile_characters_do_not_survive(text: str, expected: str) -> None:
    assert sanitize.visible(text) == expected


def test_crlf_is_a_line_break() -> None:
    assert sanitize.visible_lines("one\r\ntwo\rthree\n") == "one\ntwo three\n"
    assert sanitize.visible("one\r\ntwo") == "one two"


def test_the_format_list_covers_every_format_character_this_interpreter_knows() -> None:
    """The list is fixed so output does not depend on the Python version; this fails on an interpreter whose
    Unicode table has a format character the list lacks, so the list is updated rather than silently short."""
    import unicodedata

    from kube_noob.sanitize import _FORMAT

    missing = [hex(c) for c in range(0x110000) if unicodedata.category(chr(c)) == "Cf" and c not in _FORMAT]
    assert missing == []


# ------------------------------------------------------------------------- every CLI command, one boundary


def _leaves() -> list[tuple[str, ...]]:
    import argparse

    from kube_noob.cli import build_parser

    def walk(p: argparse.ArgumentParser, path: tuple[str, ...]) -> list[tuple[str, ...]]:
        subs = [a for a in p._actions if isinstance(a, argparse._SubParsersAction)]
        if not subs:
            return [path]
        return [leaf for a in subs for name, sp in a.choices.items() for leaf in walk(sp, (*path, name))]

    return sorted(set(walk(build_parser(), ())))


def _hostile_inputs(tmp_path: Path) -> dict[str, str]:
    def yaml_escaped(s: str) -> str:
        return "".join(
            f"\\U{ord(c):08x}" if ord(c) > 0xFFFF else (f"\\u{ord(c):04x}" if ord(c) > 0x7E or ord(c) < 0x20 else c)
            for c in s
        )

    poison = yaml_escaped(HOSTILE + "\x1b]52;c;ZWNobyBwd25k\x07" + "\ud800")
    manifest = tmp_path / "m.yaml"
    manifest.write_text(
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n"
        f'  name: "web{poison}"\n  namespace: shop\n'
        "spec:\n  selector: {matchLabels: {app: web}}\n  template:\n    metadata: {labels: {app: web}}\n"
        "    spec:\n      containers:\n"
        f'      - name: "c{poison}"\n        image: "nginx:latest{poison}"\n'
        "        securityContext: {privileged: true}\n---\n"
        "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n"
        f'  name: "deny{poison}"\n  namespace: shop\nspec: {{podSelector: {{}}, policyTypes: [Ingress]}}\n',
        encoding="utf-8",
    )
    plain = HOSTILE + "\x1b]52;c;ZWNobyBwd25k\x07"
    events = tmp_path / "ev.txt"
    events.write_text(
        f"Back-off restarting failed container web{plain} in pod web-1\nError: ImagePullBackOff {plain}\n",
        encoding="utf-8",
    )
    denial = tmp_path / "den.txt"
    denial.write_text(
        'Error from server: admission webhook "validate.kyverno.svc-fail" denied the request:\n\n'
        "resource Deployment/shop/web was blocked due to the following policies\n\ndisallow-latest-tag:\n"
        f"  validate-image-tag: 'validation error: Using a mutable image tag e.g. latest {plain} is not allowed.'\n",
        encoding="utf-8",
    )
    return {"M": str(manifest), "EV": str(events), "DEN": str(denial), "OUT": str(tmp_path / "out.json"), "T": plain}


#: Commands driven with hostile input. Every value is an argv tail; M, EV, DEN, OUT and T are filled in.
DRIVEN: dict[str, list[list[str]]] = {
    "audit": [["-f", "M"], ["-f", "M", "--compact"], ["--format", "yaml", "-f", "M"], ["--format", "sarif", "-f", "M"]],
    "validate": [["-f", "M"]],
    "redteam": [["-f", "M"]],
    "fix": [["-f", "M"]],
    "gate": [["-f", "M"], ["-f", "M", "--github-annotations"], ["--format", "yaml", "-f", "M"]],
    "policy reach": [["--from", "shop:app=web", "--to", "shop:app=web", "--port", "8080", "-f", "M"]],
    "policy explain": [["-f", "DEN"], ["--format", "yaml", "-f", "DEN"]],
    "diagnose": [["-f", "EV"], ["--format", "yaml", "-f", "EV"]],
    "signals": [["-f", "EV"], ["--format", "yaml", "-f", "EV"]],
    "insight": [["-f", "EV"], ["--format", "yaml", "-f", "EV"]],
    "known-issues": [["T"]],
    "vuln threat": [["-f", "M"], ["--format", "yaml", "-f", "M"]],
    "posture scan": [["-f", "M"]],
    "posture snapshot": [["-f", "M", "-o", "OUT"]],
    "operators inventory": [["-f", "M"]],
    "ksi": [["-f", "M"]],
    "build diagnose": [["-f", "EV"]],
}
#: Commands not driven here, each with the reason. All of them still write through the same boundary, which
#: `test_every_command_writes_through_the_boundary` holds for every command the parser has.
NOT_DRIVEN: dict[str, str] = {
    **dict.fromkeys(
        ["admission serve", "serve", "mcp", "watch"], "a long-running server or loop; its output is the same streams"
    ),
    **dict.fromkeys(["debug", "bundle"], "needs a live cluster; the live text is covered in test_absent_vs_unread*"),
    **dict.fromkeys(
        [
            "corpus advisories",
            "corpus build",
            "corpus history",
            "corpus jira",
            "corpus jira-projects",
            "corpus known-issues",
            "ask",
        ],
        "needs the network or a model",
    ),
    **dict.fromkeys(
        [
            "corpus add-docs",
            "corpus db-bundle",
            "corpus db-check",
            "corpus import",
            "corpus jira-audit",
            "corpus jira-changes",
            "corpus jira-snapshot",
            "corpus seal",
            "corpus stats",
            "corpus unseal",
            "corpus verify",
            "incidents confirm",
            "incidents list",
            "incidents show",
            "learning forget",
            "learning note",
            "learning profile",
            "learning show",
            "memory add",
            "memory import",
            "memory init",
            "memory match",
            "memory migrate-learning",
            "memory outcome",
            "memory replay",
            "memory stats",
            "memory validate",
            "train bench",
            "train export",
            "train grade",
            "train tasks",
            "ticket",
            "upgrade-risks",
        ],
        "reads or writes a local data directory or corpus this test does not build",
    ),
    **dict.fromkeys(
        [
            "completion",
            "config",
            "demo",
            "doctor",
            "explain",
            "generate",
            "rules",
            "search",
            "selftest",
            "learn exercise",
            "learn lesson",
            "learn progress",
            "learn quiz",
            "learn submit",
            "learn tracks",
            "protocol",
            "policy generate",
        ],
        "prints kube-noob's own bundled text, not text from the input",
    ),
    **dict.fromkeys(
        [
            "admission review",
            "build analytics",
            "build audit",
            "build history",
            "code report",
            "exceptions check",
            "helm-audit",
            "helm-chart",
            "must-gather analyze",
            "policy migrate-check",
            "posture diff",
            "posture report",
            "rhacs compare",
            "vuln report",
        ],
        "takes an input shape (a chart, a must-gather, SARIF, a scanner report, a snapshot, a policy export, an "
        "AdmissionReview) this table has no hostile fixture for; its writers are covered by the module tests above",
    ),
}


def test_every_command_is_driven_or_named_with_a_reason() -> None:
    names = {" ".join(leaf) for leaf in _leaves()}
    assert set(DRIVEN) | set(NOT_DRIVEN) == names, {
        "new, add it to DRIVEN or NOT_DRIVEN": sorted(names - set(DRIVEN) - set(NOT_DRIVEN)),
        "gone": sorted((set(DRIVEN) | set(NOT_DRIVEN)) - names),
    }
    assert not set(DRIVEN) & set(NOT_DRIVEN)


@pytest.mark.parametrize(("command", "tail"), [(c, t) for c, tails in sorted(DRIVEN.items()) for t in tails], ids=str)
def test_a_command_driven_with_hostile_input_prints_none_of_it(
    command: str, tail: list[str], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from kube_noob.cli import main

    inputs = _hostile_inputs(tmp_path)
    fmt = [tail[0], tail[1]] if tail[:1] == ["--format"] else []
    rest = tail[2:] if fmt else tail
    argv = [*fmt, *command.split(), *(inputs.get(x, x) for x in rest)]
    rc = main(argv)
    out = capsys.readouterr()
    text = out.out + out.err
    assert rc in (0, 1, 3), (rc, text[-500:])  # never 4: one hostile name must not fail the run
    assert text.strip(), argv
    assert _clean(text) and "\ud800" not in text and "\x07" not in text, ascii(text)[:400]


@pytest.mark.parametrize("leaf", _leaves(), ids=" ".join)
def test_every_command_writes_through_the_boundary(
    leaf: tuple[str, ...], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Whatever a command writes, to stdout or stderr, reaches the reader through `sanitize.visible_lines` --
    except the three servers in `cli._UNWRAPPED` (serve, mcp, admission serve), which are not wrapped at all
    (review D6): their stdout is a protocol stream (MCP JSON-RPC) or a server log, each message already made safe
    where it is built, and a line filter in front of a protocol stream could only corrupt it. `watch` prints text
    views and is wrapped (third review)."""
    import argparse

    from kube_noob import cli

    def dispatch(a: argparse.Namespace, s: Any) -> int:
        print(f"{' '.join(leaf)} {HOSTILE}")
        print(f"{' '.join(leaf)} {HOSTILE}", file=__import__("sys").stderr)
        return 0

    sub = {"admission_cmd": leaf[1]} if leaf[0] == "admission" and len(leaf) > 1 else {}
    monkeypatch.setattr(cli, "_dispatch", dispatch)
    monkeypatch.setattr(cli, "_settings", lambda a: None)
    monkeypatch.setattr(
        argparse.ArgumentParser,
        "parse_args",
        lambda self, argv=None: argparse.Namespace(cmd=leaf[0], format="text", **sub),
    )
    assert cli.main(list(leaf)) == 0
    out = capsys.readouterr()
    if tuple(leaf) in cli._UNWRAPPED:
        assert out.out == f"{' '.join(leaf)} {HOSTILE}\n" == out.err  # untouched, byte for byte
        return
    assert _clean(out.out + out.err) and " ".join(leaf) in out.out


def test_only_the_three_servers_are_left_unwrapped() -> None:
    from kube_noob import cli

    assert {("serve",), ("mcp",), ("admission", "serve")} == cli._UNWRAPPED


def test_the_yaml_view_carries_no_format_characters_and_json_escapes_them(capsys: pytest.CaptureFixture[str]) -> None:
    from kube_noob.cli import _emit, main

    main(["--format", "yaml", "known-issues", HOSTILE])
    assert _clean(capsys.readouterr().out)
    _emit({"name": HOSTILE}, "json")
    printed = capsys.readouterr().out
    assert _clean(printed) and json.loads(printed)["name"] == HOSTILE  # ensure_ascii: escaped, not dropped


def test_one_name_holding_a_lone_surrogate_does_not_fail_the_audit(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from kube_noob.cli import main

    m = tmp_path / "m.yaml"
    m.write_text(
        'apiVersion: v1\nkind: Pod\nmetadata: {name: "web\\ud800", namespace: shop}\n'
        "spec: {containers: [{name: c, image: 'nginx:latest'}]}\n",
        encoding="utf-8",
    )
    for argv in (["audit", "-f", str(m)], ["validate", "-f", str(m)], ["--format", "sarif", "audit", "-f", str(m)]):
        assert main(argv) in (0, 1), argv
        out = capsys.readouterr().out
        assert "\ud800" not in out and "surrogates" not in out
