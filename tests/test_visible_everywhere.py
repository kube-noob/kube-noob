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
    assert sanitize.visible("a\u202eb") == "a b"
    assert sanitize.visible_lines("a\u202eb\nc\td\re") == "a b\nc\td e"
    assert sanitize.visible_squeezed("a\r\n\u202e\u061cb  c") == "a b  c"
    assert sanitize.visible("a/\u202eb", replacement="?") == "a/?b"
    assert sanitize.has_invisible("ls\u202e") and sanitize.has_invisible("ls\t-l")
    assert not sanitize.has_invisible("ls\t-l", keep="\t") and not sanitize.has_invisible("oc get pods -n shop")
    for text in ("plain text", "naïve café → ✓ 日本語", "  two  spaces  ", ""):
        for fn in (sanitize.visible, sanitize.visible_lines, sanitize.visible_squeezed):
            assert fn(text) == text, (fn.__name__, text)


# ------------------------------------------------------------------------------------------- the eleven modules


def test_cli_terminal_lines(capsys: pytest.CaptureFixture[str]) -> None:
    from kube_noob.cli import _tprint

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

#: Character classes that are allowed to stay outside sanitize.py, and why. Anything else that spells out C0
#: controls or bidi code points in a regex is a private copy of what sanitize.visible already does.
ALLOWED_PRIVATE = {
    # validation, not output: a tier name is refused unless every character prints (and the shared helper is a
    # superset; this only rejects)
    "src/kube_noob/tiers.py": "validates a configured name; refuses rather than cleans",
    # colour codes stripped from build logs and pasted text BEFORE pattern matching: an input normaliser, not an
    # output sanitiser, and it must keep every other character so the patterns still match
    "src/kube_noob/build/logs.py": "strips ANSI colour from a build log before its patterns run",
    "src/kube_noob/insight.py": "strips ANSI colour from pasted text before its patterns run",
}
_PRIVATE_LIST = re.compile(
    r"re\.compile\(\s*r?[\"'][^\"']*(?:\\x0|\\x1[0-9a-f]|\\x7f|\\x9f|\\x85|\\u20(?:0[b-f]|2[89a-f]|6[0-9a-f]))"
)


def test_no_module_outside_sanitize_keeps_its_own_control_character_list() -> None:
    src = Path(__file__).resolve().parents[1] / "src" / "kube_noob"
    found = []
    for path in sorted(src.rglob("*.py")):
        rel = path.relative_to(src.parents[1]).as_posix()
        if rel == "src/kube_noob/sanitize.py" or rel in ALLOWED_PRIVATE:
            continue
        if _PRIVATE_LIST.search(path.read_text(encoding="utf-8")):
            found.append(rel)
    assert found == [], (
        "a private control-character list; use sanitize.visible / visible_lines / visible_squeezed / has_invisible "
        f"(or add the file to ALLOWED_PRIVATE with the reason): {found}"
    )
    for rel in ALLOWED_PRIVATE:  # the allowlist cannot outlive the files it names
        assert (src.parents[1] / rel).is_file(), rel
