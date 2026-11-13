from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import anyio
import pytest
from mcp import Client

from kube_noob.agent.loop import Agent
from kube_noob.agent.providers import ToolCall, Turn
from kube_noob.cli import main
from kube_noob.config import Settings, load_settings
from kube_noob.evals.export import export_grpo, export_sft
from kube_noob.knowledge.store import get_store
from kube_noob.server.http import http_app
from kube_noob.server.mcp_app import build_server
from kube_noob.toolkit import Toolkit
from tests.conftest import FIXTURES

BAD = (FIXTURES / "bad-bundle.yaml").read_text()


def test_toolkit_availability_gates() -> None:
    names = {s.name for s in Toolkit(load_settings()).specs()}
    assert "web_fetch" not in names and "cluster_get" not in names and "run_protocol" in names
    on = load_settings(overrides={"webEnabled": True, "cluster": {"enabled": True}})
    names_on = {s.name for s in Toolkit(on).specs()}
    assert {"web_fetch", "cluster_get", "cluster_debug_workload"} <= names_on


def test_full_install_instructions_keep_the_pasted_tool_sentence() -> None:
    """A full install still has Containerfile and code modules. The instructions must name both, and the
    semicolons that split those clauses have to survive the conditional."""
    from kube_noob.server.mcp_app import _instructions

    text = _instructions(load_settings())
    assert (
        "pass the log to kubenoob_build_diagnose and a Containerfile to kubenoob_containerfile_audit; "
        "for scanner output" in text
    )
    assert "rank 1 (shipped and exposed); for 'what could go wrong with this app?'" in text


def test_instructions_omit_tools_the_build_does_not_ship(monkeypatch: pytest.MonkeyPatch) -> None:
    """The plugin drops kube_noob.build.containerfile and kube_noob.code.ship. Naming those tools tells the
    model to call something this process cannot run."""
    import importlib.util

    from kube_noob.server.mcp_app import _instructions

    real = importlib.util.find_spec

    def fake(name: str, *args: object, **kwargs: object) -> object:
        if name in {"kube_noob.build.containerfile", "kube_noob.code.ship"}:
            return None
        return real(name, *args, **kwargs)

    monkeypatch.setattr(importlib.util, "find_spec", fake)
    text = _instructions(load_settings())
    assert "kubenoob_containerfile_audit" not in text
    assert "kubenoob_code_report" not in text
    assert "kubenoob_build_diagnose" in text
    assert "kubenoob_vuln_report" in text
    assert "; for 'what could go wrong with this app?'" in text


def test_mcp_in_process(settings: Settings) -> None:
    server = build_server(settings)

    async def run() -> dict[str, Any]:
        async with Client(server) as c:
            tools = await c.list_tools()
            names = {t.name for t in tools.tools}
            audit = await c.call_tool(
                "kubenoob_audit_manifests", {"manifests": BAD, "platform": "openshift", "version": "4.22"}
            )
            proto = await c.call_tool("kubenoob_run_protocol", {"request": "review for ROSA HCP", "manifests": BAD})
            bad_args = await c.call_tool("kubenoob_search_knowledge", {"query": "x"})
            gen = await c.call_tool(
                "kubenoob_generate_manifests",
                {
                    "blueprint": {
                        "name": "web",
                        "namespace": "a",
                        "image": "quay.io/a/web:1.0.0",
                        "platform": "openshift",
                        "exposure": {"type": "route"},
                    }
                },
            )
            prompts = await c.list_prompts()
            res = await c.read_resource("kubenoob://knowledge/ocp-scc")
            return {
                "names": names,
                "audit": audit,
                "proto": proto,
                "bad": bad_args,
                "gen": gen,
                "prompts": {p.name for p in prompts.prompts},
                "res": res,
            }

    out = anyio.run(run)
    assert {
        "kubenoob_run_protocol",
        "kubenoob_audit_manifests",
        "kubenoob_diagnose",
        "kubenoob_learn_submit",
        "kubenoob_grade_answer",
    } <= out["names"]
    assert not any(n.startswith("kubenoob_web") or n.startswith("kubenoob_cluster") for n in out["names"])
    audit = out["audit"].structured_content
    assert audit["summary"]["maxSeverity"] == "critical"
    proto = out["proto"].structured_content
    assert proto["auditValidationBrief"]["platform"] == "rosa-hcp"
    assert (
        proto["auditValidationBrief"]["after"]["counts"]["critical"]
        < proto["auditValidationBrief"]["before"]["counts"]["critical"]
    )
    assert out["bad"].is_error
    assert out["gen"].structured_content["status"] == "ok"
    assert {"master_controller", "debug_session", "tutor", "getting_started"} <= out["prompts"]
    assert "restricted-v2" in out["res"].contents[0].text


def test_mcp_guard_errors_reach_the_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Guard failures must surface their message (not an opaque crash) so the calling model can act on them."""
    from tests.test_debug import _fake_kubectl

    _fake_kubectl(tmp_path)
    monkeypatch.setenv("PATH", f"{tmp_path / 'bin'}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("KUBE_NOOB_DATA_DIR", str(tmp_path))
    server = build_server(load_settings(overrides={"cluster": {"enabled": True, "backend": "kubectl"}}))

    async def run() -> tuple[Any, Any]:
        async with Client(server) as c:
            secrets = await c.call_tool("kubenoob_cluster_get", {"resource": "secrets", "namespace": "a"})
            bad_name = await c.call_tool("kubenoob_cluster_get", {"resource": "pods", "name": "x; rm -rf /"})
            return secrets, bad_name

    secrets, bad_name = anyio.run(run)
    assert secrets.is_error and "not permitted" in secrets.content[0].text
    assert bad_name.is_error and "Invalid name" in bad_name.content[0].text


def test_http_app_auth_and_health(monkeypatch: pytest.MonkeyPatch) -> None:
    from starlette.testclient import TestClient

    s = load_settings(overrides={"server": {"host": "0.0.0.0", "allowedHosts": ["testserver"]}})  # noqa: S104
    with pytest.raises(RuntimeError, match="Refusing"):
        http_app(s)
    monkeypatch.setenv("KUBE_NOOB_HTTP_TOKEN", "s3cret-token")
    app = http_app(s)
    with TestClient(app) as client:
        assert client.get("/healthz").json()["status"] == "ok"
        assert client.get("/readyz").json()["status"] == "ready"
        init = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "t", "version": "1"},
            },
        }
        headers = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
        assert client.post("/mcp", json=init, headers=headers).status_code == 401
        r = client.post("/mcp", json=init, headers={**headers, "Authorization": "Bearer s3cret-token"})
        assert r.status_code == 200, r.text
        assert r.json()["result"]["serverInfo"]["name"] == "kube_noob_mcp"
        assert client.post("/mcp", json=init, headers={**headers, "Authorization": "Bearer wrong"}).status_code == 401


class ScriptedProvider:
    name = "scripted"
    model = "scripted-1"

    def __init__(self) -> None:
        self.calls = 0

    def turn(self, system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> Turn:
        self.calls += 1
        assert "webEnabled: false" in system or "Web access is disabled" in system
        if self.calls == 1:
            return Turn(
                "",
                [
                    ToolCall("t1", "search_knowledge", {"query": "restricted-v2 runAsUser"}),
                    ToolCall("t2", "nonexistent_tool", {}),
                ],
                "tool_use",
                self.model,
                {"role": "assistant", "content": "calling"},
            )
        last = json.dumps(messages[-1])
        assert "kn:ocp-scc" in last and "Unknown tool" in last
        return Turn(
            "Remove runAsUser; restricted-v2 assigns a UID from the namespace range [kn:ocp-scc#0] [kn:fake#1].",
            [],
            "end_turn",
            self.model,
            {"role": "assistant", "content": "done"},
        )

    def tool_results_message(self, results: list[tuple[ToolCall, str, bool]]) -> list[dict[str, Any]]:
        return [{"role": "user", "content": [{"id": c.call_id, "out": o, "err": e} for c, o, e in results]}]

    def user_message(self, text: str) -> dict[str, Any]:
        return {"role": "user", "content": text}

    def complete_text(self, prompt: str, max_tokens: int = 1024) -> str:
        return "{}"


def test_agent_loop_with_tools(settings: Settings) -> None:
    agent = Agent(settings, provider=ScriptedProvider())
    res = agent.ask("Why is my pod rejected on OpenShift?")
    assert res.rounds == 2 and len(res.tool_calls) == 2 and res.tool_calls[1]["error"]
    assert [c["chunkId"] for c in res.citations] == ["kn:ocp-scc#0"] and res.invalid_citations == ["kn:fake#1"]


def test_cli_audit_exit_codes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    f = tmp_path / "bad.yaml"
    f.write_text(BAD)
    assert main(["audit", "-f", str(f), "--platform", "openshift", "--version", "4.22"]) == 1
    assert "KN-V002" in capsys.readouterr().out
    # The fixture's `apps.openshift.io/v1 Route` is an object the rules refuse to read, so the verdict is
    # undetermined and `--fail-on never` still exits 1 (G281, review 4): never 0 for undetermined.
    assert main(["audit", "-f", str(f), "--fail-on", "never", "--format", "json"]) == 1
    out = json.loads(capsys.readouterr().out)
    assert out["summary"]["maxSeverity"] == "critical"
    assert [n["kind"] for n in out["notAudited"]] == ["Route"]
    good = tmp_path / "good.yaml"
    good.write_text(BAD.replace("apps.openshift.io/v1\nkind: Route", "route.openshift.io/v1\nkind: Route"))
    assert main(["audit", "-f", str(good), "--fail-on", "never", "--format", "json"]) == 0


def test_cli_generate_fix_diagnose_learn(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "gen.yaml"
    assert (
        main(
            [
                "generate",
                "--name",
                "web",
                "--namespace",
                "demo",
                "--image",
                "nginxinc/nginx-unprivileged:1.27.2",
                "--replicas",
                "2",
                "-o",
                str(out),
            ]
        )
        == 0
    )
    assert main(["learn", "submit", "k8s-ex-hardened-deployment", "-f", str(out), "--learner", "cli"]) == 0
    capsys.readouterr()
    assert main(["generate", "--name", "x", "--namespace", "y", "--image", "z:1", "--expose", "route"]) == 3
    bad = tmp_path / "bad.yaml"
    bad.write_text(BAD)
    fixed = tmp_path / "fixed.yaml"
    assert main(["fix", "-f", str(bad), "--platform", "rosa-hcp", "-o", str(fixed)]) == 0
    assert "route.openshift.io/v1" in fixed.read_text()
    ev = tmp_path / "ev.txt"
    ev.write_text("Warning FailedMount Multi-Attach error for volume pvc-1")
    capsys.readouterr()
    assert main(["diagnose", "-f", str(ev), "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["diagnoses"][0]["id"] == "DBG-MULTIATTACH"
    assert main(["debug", "deployment/x", "-n", "y"]) == 2  # cluster access disabled by default
    assert main(["corpus", "jira"]) == 2  # network ingestion requires --online


def test_export_datasets(tmp_path: Path) -> None:
    sft = export_sft(tmp_path / "sft.jsonl", get_store(), synthetic_limit=6)
    assert sft["records"] > 50 and sft["bySource"]["curriculum"] >= 4 and sft["bySource"]["playbook"] >= 20
    lines = [json.loads(x) for x in (tmp_path / "sft.jsonl").read_text().splitlines()]
    assert all(r["messages"][2]["content"] for r in lines)
    assert all(r["metadata"]["labelSource"] == "deterministic" for r in lines)
    grpo = export_grpo(tmp_path / "grpo.jsonl")
    assert grpo["records"] == 16


def test_http_host_checks(monkeypatch: pytest.MonkeyPatch) -> None:
    from starlette.testclient import TestClient

    init = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}},
    }
    headers = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
    # Loopback sidecar without a token: DNS-rebinding protection rejects foreign Host headers.
    with TestClient(http_app(load_settings()), base_url="http://evil.example") as client:
        assert client.post("/mcp", json=init, headers=headers).status_code == 421
    # Token-authenticated remote bind without an allowlist: reachable by its Service DNS name.
    monkeypatch.setenv("KUBE_NOOB_HTTP_TOKEN", "s3cret-token")
    remote = load_settings(overrides={"server": {"host": "0.0.0.0"}})  # noqa: S104
    with TestClient(http_app(remote), base_url="http://kube-noob.ns.svc:8080") as client:
        r = client.post("/mcp", json=init, headers={**headers, "Authorization": "Bearer s3cret-token"})
        assert r.status_code == 200, r.text
        assert client.post("/mcp", json=init, headers=headers).status_code == 401


def test_mcp_rejects_unknown_arguments(settings: Settings) -> None:
    async def run() -> tuple[Any, Any, Any]:
        async with Client(build_server(settings)) as c:
            tools = {t.name: t for t in (await c.list_tools()).tools}
            typo = await c.call_tool("kubenoob_grade_answer", {"taskId": "bench-qa-oom", "completion": "x"})
            good = await c.call_tool("kubenoob_explain_rule", {"rule_id": "KN-ST001"})
            return tools["kubenoob_grade_answer"], typo, good

    schema_tool, typo, good = anyio.run(run)
    assert schema_tool.input_schema.get("additionalProperties") is False
    assert typo.is_error and "taskId" in typo.content[0].text
    assert not good.is_error


def test_http_body_limit_and_audit_log(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    import logging

    from starlette.testclient import TestClient

    from kube_noob.server.http import MAX_BODY_BYTES

    monkeypatch.setenv("KUBE_NOOB_HTTP_TOKEN", "s3cret-token")
    headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "Authorization": "Bearer s3cret-token",
    }
    with TestClient(http_app(load_settings()), base_url="http://127.0.0.1:8080") as client:
        big = b"x" * (MAX_BODY_BYTES + 1)
        assert client.post("/mcp", content=big, headers=headers).status_code == 413

        def chunks() -> Any:
            for _ in range(9):
                yield b"y" * (1024 * 1024)

        assert client.post("/mcp", content=chunks(), headers=headers).status_code == 413
        call = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "kubenoob_explain_rule", "arguments": {"rule_id": "KN-ST001"}},
        }
        with caplog.at_level(logging.INFO, logger="kube_noob.audit"):
            r = client.post("/mcp", json=call, headers={**headers, "MCP-Protocol-Version": "2025-06-18"})
        assert r.status_code == 200, r.text
        assert any("tool=kubenoob_explain_rule" in m and "outcome=ok" in m for m in caplog.messages)
