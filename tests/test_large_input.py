"""A chart that renders to more than a megabyte is audited, and more than one run reads is refused in one line.

The megabyte was a request-size guard for the MCP server, and the command line shared it: `kube-noob audit -f` on
the render of cloudnative-pg 0.29.2 (1,307,969 bytes) exited 4 with a pydantic dump, and so did three more of the
25 charts in ``bench/charts.yaml`` (G447). Every test here puts the object that matters LAST, because a size limit
that cuts instead of refusing reads the start and says nothing of the rest.
"""

from __future__ import annotations

import io
import json
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any

import anyio
import pytest
from mcp import Client

from kube_noob import cli, limits, tool_runner, yamlio
from kube_noob import toolkit as tk
from kube_noob.config import load_settings
from kube_noob.errors import InputTooLarge, ManifestError
from kube_noob.server.mcp_app import build_server

POD = """apiVersion: v1
kind: Pod
metadata:
  name: last-privileged
  namespace: bench
spec:
  containers:
    - name: c
      image: registry.example.com/app:1.0
      securityContext:
        privileged: true
"""
WHERE = ["--platform", "openshift", "--version", "4.22"]
#: What a refusal must never look like: pydantic's own report of a string that is too long.
DUMP = ("validation error", "string_too_long", "input_value", "errors.pydantic.dev", "Traceback")


def _configmap(i: int, size: int) -> str:
    head = f"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cm-{i}\n  namespace: bench\n"
    return f'{head}data:\n  note: "{"x" * size}"\n'


def render(chars: int, *, last: str = POD) -> str:
    """Valid objects, at least ``chars`` characters of them, with ``last`` at the end: the shape of a chart that
    ships its CRDs as templates, in few enough documents to stay under the document limit."""
    parts: list[str] = []
    total = 0
    while total < chars:
        parts.append(_configmap(len(parts), 20_000))
        total += len(parts[-1]) + 4
    return "---\n".join([*parts, last])


def exact(chars: int) -> str:
    """Exactly ``chars`` characters: a comment, then the privileged Pod. No white space at either end, because the
    models strip it before they measure and the test is about the character after the last one allowed."""
    pod = POD.rstrip("\n")
    room = chars - len(pod)
    line = "# " + "x" * 98 + "\n"
    body = line * (room // len(line))
    rest = room - len(body)
    text = body + ("#" * (rest - 1) + "\n" if rest else "") + pod
    assert len(text) == chars == len(text.strip())
    return text


def run(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = cli.main(argv)
    return rc, out.getvalue(), err.getvalue()


def assert_clean_refusal(err: str, size: str, limit: str) -> None:
    lines = [ln for ln in err.splitlines() if ln.strip()]
    assert len(lines) == 1, err
    assert lines[0].startswith("error: "), err
    assert size in err and limit in err, err
    assert "split" in err and "by part" in err, err
    assert "none of it was audited" in err, err
    assert not any(d in err for d in DUMP), err


# --- the command line reads a large local input, to its last object ---------------------------------------------

COMMANDS: dict[str, list[str]] = {
    "audit": ["audit", "-f", "{f}", *WHERE, "--format", "json"],
    "validate": ["validate", "-f", "{f}", *WHERE, "--format", "json"],
    "fix": ["fix", "-f", "{f}", *WHERE, "--format", "json"],
    "redteam": ["redteam", "-f", "{f}", *WHERE, "--format", "json"],
    "gate": ["gate", "-f", "{f}", *WHERE, "--format", "json"],
    "verify": ["verify", "-f", "{f}", *WHERE, "--format", "json"],
}


def _argv(name: str, path: Path) -> list[str]:
    return [a.replace("{f}", str(path)) for a in COMMANDS[name]]


@pytest.mark.parametrize("name", sorted(COMMANDS))
def test_a_render_over_a_megabyte_is_read_to_its_last_object(name: str, tmp_path: Path) -> None:
    f = tmp_path / "rendered.yaml"
    f.write_text(render(1_300_000), encoding="utf-8")
    assert f.stat().st_size > tk.MAX_MANIFEST_CHARS
    rc, out, err = run(_argv(name, f))
    assert rc in (0, 1), (rc, err[:400])  # an answer, whatever it is: never a refusal
    assert "last-privileged" in out + err, f"{name}: the last object of the input is not in the answer"
    assert not any(d in err for d in DUMP)


def test_the_audit_of_a_large_render_finds_what_the_same_object_gets_alone(tmp_path: Path) -> None:
    """Present and violating, at the end of 1.3 MB: the findings on the Pod are the findings it gets by itself.
    A cut anywhere before it loses them, and a cut through it loses some."""
    alone = tmp_path / "pod.yaml"
    alone.write_text(POD, encoding="utf-8")
    big = tmp_path / "rendered.yaml"
    big.write_text(render(1_300_000), encoding="utf-8")

    def rules(path: Path) -> list[str]:
        rc, out, err = run(["audit", "-f", str(path), *WHERE, "--format", "json"])
        assert rc == 1, err[:300]
        return sorted(f["ruleId"] for f in json.loads(out)["findings"] if "last-privileged" in str(f.get("resource")))

    assert rules(alone)
    assert rules(big) == rules(alone)


def test_a_large_render_with_nothing_wrong_in_it_is_not_given_a_finding_for_its_size(tmp_path: Path) -> None:
    """Present and fine: the same 1.3 MB with a ConfigMap last. No finding names it, and nothing is refused."""
    fine = _configmap(9999, 10).replace("cm-9999", "last-fine")
    f = tmp_path / "rendered.yaml"
    f.write_text(render(1_300_000, last=fine), encoding="utf-8")
    rc, out, err = run(["audit", "-f", str(f), *WHERE, "--format", "json", "--fail-on", "never"])
    assert rc == 0, err[:300]
    report = json.loads(out)
    assert not [x for x in report["findings"] if "last-fine" in str(x.get("resource"))]
    assert report["summary"]["counts"]["critical"] == 0


def test_a_directory_over_a_megabyte_in_all_is_read_to_its_last_file(tmp_path: Path) -> None:
    d = tmp_path / "k8s"
    d.mkdir()
    for i in range(3):
        (d / f"a{i}.yaml").write_text(render(450_000, last=_configmap(i + 500, 10)), encoding="utf-8")
    (d / "z-last.yaml").write_text(POD, encoding="utf-8")
    rc, out, err = run(["audit", "-f", str(d), *WHERE, "--format", "json"])
    assert rc == 1, err[:300]
    assert any("last-privileged" in str(f.get("resource")) for f in json.loads(out)["findings"])


def test_standard_input_over_a_megabyte_is_read_to_its_last_object(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO(render(1_300_000)))
    rc, out, err = run(["audit", "-f", "-", *WHERE, "--format", "json"])
    assert rc == 1, err[:300]
    assert "last-privileged" in out


# --- more than one run reads: one line, exit 4, nothing audited --------------------------------------------------


def test_the_local_limit_is_measured_against_the_largest_chart_and_agrees_in_every_layer() -> None:
    """kyverno 3.10.0 rendered to 5,916,202 bytes, the largest of the four charts the megabyte refused. The limit
    has to clear it with room, and the layers under the command line must not be smaller than the one above."""
    from kube_noob import gate, verify

    assert limits.MAX_LOCAL_BYTES >= 2 * 5_916_202
    assert limits.MAX_REQUEST_CHARS == tk.MAX_MANIFEST_CHARS == 1_000_000
    assert yamlio.MAX_INPUT_BYTES == limits.MAX_LOCAL_BYTES
    assert gate.MAX_TOTAL == limits.MAX_LOCAL_BYTES
    assert verify.MAX_FILE_BYTES == verify.MAX_TOTAL_BYTES == limits.MAX_LOCAL_BYTES


def test_a_file_over_the_local_limit_is_refused_in_one_line_and_nothing_is_printed(tmp_path: Path) -> None:
    f = tmp_path / "huge.yaml"
    f.write_text(exact(limits.MAX_LOCAL_BYTES + 1), encoding="utf-8")
    rc, out, err = run(["audit", "-f", str(f), *WHERE, "--format", "json"])
    assert rc == 4
    assert out == ""
    assert_clean_refusal(err, f"{limits.MAX_LOCAL_BYTES + 1:,} bytes", f"{limits.MAX_LOCAL_BYTES:,}")


@pytest.mark.parametrize("name", sorted(COMMANDS))
def test_every_command_refuses_the_same_way_over_the_local_limit(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The limit lowered so that the test does not need 16 MB per command; the path through each command is the
    real one. 1.3 MB is over a 1.2 MB limit and over the request cap, so a command that fell back to either
    pydantic's message or a cut shows here."""
    monkeypatch.setattr(limits, "MAX_LOCAL_BYTES", 1_200_000)
    f = tmp_path / "rendered.yaml"
    text = render(1_300_000)
    f.write_text(text, encoding="utf-8")
    rc, out, err = run(_argv(name, f))
    assert rc == 4, (rc, err[:400])
    assert out == ""
    assert_clean_refusal(err, f"{len(text):,} bytes", "1,200,000")


def test_a_directory_over_the_limit_in_all_is_refused_though_each_file_is_under_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(limits, "MAX_LOCAL_BYTES", 1_200_000)
    d = tmp_path / "k8s"
    d.mkdir()
    for i in range(3):
        (d / f"a{i}.yaml").write_text(render(450_000, last=_configmap(i + 500, 10)), encoding="utf-8")
    (d / "z-last.yaml").write_text(POD, encoding="utf-8")
    for argv in (["audit", "-f", str(d), *WHERE, "--format", "json"], ["gate", "-f", str(d), *WHERE]):
        rc, out, err = run(argv)
        assert rc == 4, (argv[0], rc, err[:300])
        assert out == ""
        assert "1,200,000" in err and "none of it was audited" in err
        assert not any(x in err for x in DUMP)
        if argv[0] == "audit":
            # Refused while the files are being counted, by name, and before the fourth one is opened.
            assert f"the manifests under {d} is 1,3" in err, err


def test_the_limit_is_the_last_byte_read_not_the_first_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(limits, "MAX_LOCAL_BYTES", 50_000)
    with limits.local_files():
        assert limits.check(exact(50_000)) == exact(50_000)  # unchanged: never a shorter text
        with pytest.raises(InputTooLarge, match=r"50,001 bytes .* at most 50,000"):
            limits.check(exact(50_001))
    assert len(yamlio.load_documents(exact(50_000))) == 1
    with pytest.raises(InputTooLarge, match=r"50,001 bytes"):
        yamlio.load_documents(exact(50_001))


def test_the_local_limit_counts_bytes_so_text_that_is_not_ascii_is_not_let_through_at_four_times_the_size(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(limits, "MAX_LOCAL_BYTES", 50_000)
    text = "# " + "é" * 30_000 + "\n" + POD.rstrip()  # 30,000 and some characters, 60,000 and some bytes
    assert len(text) < 50_000 < len(text.encode())
    with limits.local_files(), pytest.raises(InputTooLarge, match=f"{len(text.encode()):,} bytes"):
        tk.AuditIn(manifests=text)


def test_the_refusal_is_a_manifest_error_and_not_a_value_error() -> None:
    """A ManifestError, so every caller that reports a manifest it could not read reports this one. Not a
    ValueError, or pydantic folds it back into the dump this replaces."""
    assert issubclass(InputTooLarge, ManifestError)
    assert not issubclass(InputTooLarge, ValueError)


def _chart_and_helm(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, rendered: str) -> Path:
    """A chart directory, and a `helm` on PATH that prints ``rendered`` whatever it is asked."""
    import os

    out = tmp_path / "rendered.yaml"
    out.write_text(rendered, encoding="utf-8")
    tools = tmp_path / "tools"
    tools.mkdir()
    helm = tools / "helm"
    helm.write_text(f"#!/bin/sh\ncat {out}\n", encoding="utf-8")
    helm.chmod(0o755)
    monkeypatch.setenv("PATH", os.pathsep.join([str(tools), os.environ["PATH"]]))
    chart = tmp_path / "work" / "chart"  # helm is run only from outside the working directory
    (chart / "templates").mkdir(parents=True)
    (chart / "Chart.yaml").write_text("apiVersion: v2\nname: web\nversion: 0.1.0\n", encoding="utf-8")
    return chart


def test_a_chart_that_renders_to_more_than_a_megabyte_is_audited_to_its_last_object(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    chart = _chart_and_helm(tmp_path, monkeypatch, render(1_300_000))
    monkeypatch.chdir(chart.parent)
    rc, out, err = run(["helm-audit", str(chart), *WHERE, "--format", "json"])
    assert rc == 1, err[:300]
    assert any("last-privileged" in str(f.get("resource")) for f in json.loads(out)["findings"])
    rc, out, err = run(["gate", "--chart", str(chart), *WHERE, "--format", "json"])
    assert rc == 1, err[:300]
    assert "last-privileged" in out


def test_a_render_over_the_limit_is_refused_by_name_and_not_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from kube_noob.generate import helm_render

    text = render(1_300_000)
    chart = _chart_and_helm(tmp_path, monkeypatch, text)
    monkeypatch.chdir(chart.parent)
    monkeypatch.setattr(helm_render, "MAX_RENDERED", 1_200_000)
    assert helm_render.MAX_RENDERED != limits.MAX_LOCAL_BYTES
    for argv in (["helm-audit", str(chart), *WHERE], ["gate", "--chart", str(chart), *WHERE]):
        rc, out, err = run(argv)
        assert rc == 4, (argv[0], rc, err[:300])
        assert out == ""
        assert_clean_refusal(err, f"{len(text):,} bytes", "1,200,000")
        assert "helm template rendered" in err


def test_the_render_limit_is_the_command_lines_own() -> None:
    from kube_noob.generate import helm_render

    assert helm_render.MAX_RENDERED == limits.MAX_LOCAL_BYTES


# --- the request cap is what it was, on every request surface ----------------------------------------------------


def _call(tool: str, args: dict[str, Any]) -> Any:
    server = build_server(load_settings())

    async def go() -> Any:
        async with Client(server) as c:
            return await c.call_tool(tool, args)

    return anyio.run(go)


def test_mcp_reads_a_megabyte_and_refuses_one_character_more_in_one_line() -> None:
    at = _call("kubenoob_audit_manifests", {"manifests": exact(1_000_000), "platform": "openshift", "version": "4.22"})
    assert not at.is_error
    assert "last-privileged" in json.dumps(at.structured_content)
    over = _call("kubenoob_audit_manifests", {"manifests": exact(1_000_001), "platform": "openshift"})
    assert over.is_error
    text = over.content[0].text
    assert "`manifests` is 1,000,001 characters" in text and "at most 1,000,000" in text
    assert "split it into several calls" in text and "by part" in text and "none of it was audited" in text
    assert not any(d in text for d in DUMP)
    assert len(text.splitlines()) == 1


@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("kubenoob_fix_manifests", {"manifests": "X"}),
        ("kubenoob_validate_manifests", {"manifests": "X"}),
        ("kubenoob_run_protocol", {"request": "review this", "manifests": "X"}),
        ("kubenoob_policy_migrate_check", {"policies": "X"}),
        ("kubenoob_verify_change", {"manifests": "X"}),
        ("kubenoob_verify_change", {"command": "kubectl apply -f a.yaml", "files": {"a.yaml": "X"}}),
    ],
)
def test_every_tool_that_takes_manifests_refuses_the_same_way(tool: str, args: dict[str, Any]) -> None:
    big = exact(1_000_001)
    filled: dict[str, Any] = {
        k: (big if v == "X" else dict.fromkeys(v, big) if isinstance(v, dict) else v) for k, v in args.items()
    }
    res = _call(tool, filled)
    assert res.is_error
    text = res.content[0].text
    assert "characters and one request carries at most 1,000,000" in text, text[:300]
    assert not any(d in text for d in DUMP), text[:300]


def test_a_server_started_from_the_command_line_keeps_the_request_cap() -> None:
    """`kube-noob serve` and `kube-noob mcp` are command-line commands. Whatever the caller holds, the door every
    tool call goes through sets the request cap again."""
    spec = next(s for s in tk.Toolkit(load_settings()).specs() if s.name == "audit_manifests")
    args = {"manifests": exact(1_000_001), "platform": "openshift"}
    with limits.local_files():
        tk.AuditIn(**args)  # the command line itself would read it
        with pytest.raises(InputTooLarge, match="1,000,001 characters"):
            tool_runner.call(spec, args, "test")
        assert limits.is_local()  # and the caller's own setting is put back
    assert not limits.is_local()


@pytest.mark.parametrize(
    ("names", "local"),
    [
        ({"cmd": "audit"}, True),
        ({"cmd": "gate"}, True),
        ({"cmd": "insight"}, True),
        ({"cmd": "admission", "admission_cmd": "review"}, True),
        ({"cmd": "serve"}, False),
        ({"cmd": "mcp"}, False),
        ({"cmd": "admission", "admission_cmd": "serve"}, False),
    ],
)
def test_a_server_command_is_not_given_the_local_limit(names: dict[str, str], local: bool) -> None:
    import argparse

    with cli._input_limit(argparse.Namespace(**names)):
        assert limits.is_local() is local
    assert not limits.is_local()


def test_the_request_cap_is_the_default_so_a_caller_that_forgets_to_say_gets_the_smaller_limit() -> None:
    with pytest.raises(InputTooLarge, match="at most 1,000,000"):
        tk.AuditIn(manifests=exact(1_000_001))
    assert tk.AuditIn(manifests=exact(1_000_000)).manifests == exact(1_000_000)


def test_the_schema_an_mcp_client_is_shown_still_says_a_megabyte() -> None:
    server = build_server(load_settings())
    seen = 0
    for tool in server._tool_manager.list_tools():
        for name, prop in tool.parameters["properties"].items():
            if name not in {"manifests", "policies", "against", "stdin", "containerfile"}:
                continue
            shapes = [prop, *prop.get("anyOf", [])]
            strings = [s for s in shapes if s.get("type") == "string"]
            if not strings:
                continue
            assert [s.get("maxLength") for s in strings] == [1_000_000], (tool.name, name)
            seen += 1
    assert seen >= 15
    audit = server._tool_manager.get_tool("kubenoob_audit_manifests")
    assert audit is not None
    assert audit.parameters["properties"]["manifests"]["minLength"] == 1


def test_text_that_is_not_manifests_keeps_the_request_cap_on_the_command_line_too() -> None:
    with limits.local_files(), pytest.raises(InputTooLarge, match="`containerfile` is 1,000,001 characters"):
        tk.ContainerfileIn(containerfile="FROM scratch\n" + "#" * (1_000_001 - 13))


def test_rest_refuses_an_argument_over_the_cap_with_the_same_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from starlette.testclient import TestClient

    from kube_noob.server.http import MAX_BODY_BYTES, http_app

    token = "rest-" + "token-" + "y" * 8
    monkeypatch.setenv("KUBE_NOOB_HTTP_TOKEN", token)
    s = load_settings(
        overrides={"dataDir": str(tmp_path / "data"), "server": {"host": "0.0.0.0", "allowedHosts": ["testserver"]}}  # noqa: S104
    )
    body = {"manifests": exact(1_000_001), "platform": "openshift"}
    assert len(json.dumps(body)) < MAX_BODY_BYTES  # past the body limit it is a 413 and never reaches the tool
    with TestClient(http_app(s)) as client:
        r = client.post("/v1/audit", json=body, headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 400
    answer = r.json()
    assert answer["outcome"] == "invalid-arguments"
    assert "`manifests` is 1,000,001 characters" in answer["error"] and "at most 1,000,000" in answer["error"]
    assert not any(d in answer["error"] for d in DUMP)


# --- an argument a model refuses for another reason is one line too ----------------------------------------------


@pytest.mark.parametrize("name", ["audit", "validate", "fix"])
def test_an_argument_a_model_refuses_is_one_line_without_pydantics_report(name: str, tmp_path: Path) -> None:
    """A platform version longer than the model takes reaches the model, which refuses it. The refusal was
    pydantic's four lines; it is the argument and the reason. (An empty file no longer reaches the model on any
    of these: every command refuses text with no Kubernetes object first, exit 2, G443.)"""
    f = tmp_path / "cm.yaml"
    f.write_text("apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a, namespace: n}\n", encoding="utf-8")
    rc, out, err = run([name, "-f", str(f), "--platform", "openshift", "--version", "4.22." + "1" * 12])
    assert rc == 4
    assert out == ""
    assert err.strip() == "error: version: String should have at most 16 characters"
    assert not any(d in err for d in DUMP)


def test_rest_reports_an_argument_a_model_refused_without_quoting_the_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spec = next(s for s in tk.Toolkit(load_settings()).specs() if s.name == "audit_manifests")
    from kube_noob.server.mcp_app import CallFailed, run_tool

    with pytest.raises(CallFailed) as caught:
        run_tool(spec, {"manifests": POD, "platform": "s3cr3t-value-the-caller-sent"}, "test")
    message = caught.value.message
    assert message.startswith("invalid arguments: platform: ")
    assert "s3cr3t-value-the-caller-sent" not in message
    assert not any(d in message for d in DUMP)


# --- insight hands each analyser the whole text or says why not --------------------------------------------------


def test_insight_does_not_audit_the_first_megabyte_of_manifests_and_call_it_the_audit() -> None:
    """`insight()` accepts 2,000,000 characters and cut the manifests to 1,000,000 before the audit: the Pod at the
    end went unread and the answer listed `audit` under `ran`. Either the whole text is audited or it is named
    under `skipped` with the reason."""
    from kube_noob import insight as insight_mod

    # The cut falls exactly between two documents, so what is left of a cut text is valid YAML with nothing
    # wrong in it: the case where a cut leaves no trace at all. (Cut mid-document, the loader refuses the
    # remains, and that refusal would hide whether the slice is still there.)
    head = render(900_000, last=_configmap(7777, 10))
    pad = tk.MAX_MANIFEST_CHARS - len(head) - 4
    head += "---\n" + "#" * (pad - 1) + "\n"
    assert len(head) == tk.MAX_MANIFEST_CHARS and yamlio.load_documents(head)
    text = head + "---\n" + POD
    assert tk.MAX_MANIFEST_CHARS < len(text) < insight_mod.MAX_TEXT
    out = insight_mod.insight(tk.Toolkit(load_settings()), text, "openshift", "4.22")
    read_it = "last-privileged" in json.dumps(out["findings"])
    said_so = any(s["kind"] == "manifests" and "not audited" in s["why"] for s in out["skipped"])
    assert read_it or said_so
    assert not (said_so and "audit" in out["ran"])
    under = render(600_000)
    whole = insight_mod.insight(tk.Toolkit(load_settings()), under, "openshift", "4.22")
    assert "audit" in whole["ran"] and "last-privileged" in json.dumps(whole["findings"])


def test_insight_says_when_it_read_only_the_start_of_its_text() -> None:
    from kube_noob import insight as insight_mod

    text = "CrashLoopBackOff\n" + "x" * insight_mod.MAX_TEXT
    out = insight_mod.insight(tk.Toolkit(load_settings()), text)
    assert out["inputTruncated"]["characters"] == len(text)
    assert out["inputTruncated"]["read"] == insight_mod.MAX_TEXT
    assert "inputTruncated" not in insight_mod.insight(tk.Toolkit(load_settings()), "CrashLoopBackOff in pod web")


@pytest.mark.parametrize("helper", ["_containerfile", "_policy_migrate"])
def test_an_insight_analyser_refuses_text_over_the_cap_instead_of_reading_its_start(helper: str) -> None:
    from kube_noob import insight as insight_mod

    kit = tk.Toolkit(load_settings())
    text = "FROM scratch\n" + "# pad\n" * 170_000 + "USER 0\n"
    assert len(text) > tk.MAX_MANIFEST_CHARS
    answer = getattr(insight_mod, helper)(kit, text)
    assert isinstance(answer, str), "a result was built from a text that had been cut"
    assert "1,000,000" in answer and "none of it was audited" in answer
