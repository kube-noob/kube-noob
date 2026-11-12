"""`kube-noob hook claude-code`: the PreToolUse hook that makes an agent pass `kube-noob verify` (G280).

The sample input in tests/fixtures/hook/pretooluse-bash.json is the PreToolUse example and the Bash `tool_input`
table of the Claude Code hooks reference (https://code.claude.com/docs/en/hooks, reached from
https://docs.claude.com/en/docs/claude-code/hooks, read 2026-11-12), with `cwd` and `command` filled in per case.
The protocol it is held to, from the same page: exit 2 blocks and stderr is the reason the agent sees; exit 0 with
no output lets the call proceed; any other exit code does NOT block; `permissionDecision: "allow"` would skip the
user's permission prompt, so the hook never prints it.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from kube_noob import hook, verify

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = (ROOT / "tests" / "fixtures" / "hook" / "pretooluse-bash.json").read_text()
GOOD = ROOT / "tests" / "fixtures" / "gate" / "good" / "orders-api.yaml"
BAD = ROOT / "tests" / "fixtures" / "gate" / "bad" / "insecure-deployment.yaml"


OPTS = hook.Options(platform="openshift", version="4.20")
CLI_OPTS = ["--platform", "openshift", "--version", "4.20"]


def _hook(raw: str, env: dict[str, str], **kw: object) -> tuple[int, str, str]:
    return hook.run(raw, env, options=OPTS, **kw)  # type: ignore[arg-type]


def _input(command: str, cwd: Path, **override: object) -> str:
    doc = json.loads(SAMPLE.replace("@CWD@", "CWD").replace("@COMMAND@", "CMD"))
    doc["cwd"], doc["tool_input"]["command"] = str(cwd), command
    doc.update(override)
    return json.dumps(doc)


@pytest.fixture
def ws(tmp_path: Path) -> Path:
    (tmp_path / "k8s").mkdir()
    shutil.copy(BAD, tmp_path / "k8s" / "bad.yaml")
    shutil.copy(GOOD, tmp_path / "k8s" / "good.yaml")
    return tmp_path


def test_a_denied_apply_is_blocked_with_exit_2_and_the_findings_on_stderr(ws: Path) -> None:
    code, out, err = _hook(_input("kubectl apply -f k8s/bad.yaml -n shop", ws), {})
    assert code == 2 and out == ""
    assert "blocked" in err and "KN-S013" in err and "k8s/bad.yaml" in err


def test_an_allowed_apply_and_a_read_pass_silently(ws: Path) -> None:
    # The good fixture passes the gate for OpenShift 4.20, which the hook is told with --platform and --version.
    assert _hook(_input("kubectl apply -f k8s/good.yaml", ws), {}) == (0, "", "")
    assert _hook(_input("kubectl get pods -A", ws), {}) == (0, "", "")
    assert _hook(_input("npm test && git status", ws), {}) == (0, "", "")


def test_the_hook_never_answers_allow_in_json(ws: Path) -> None:
    """`permissionDecision: allow` skips the user's own permission prompt; a pass is a silent exit 0."""
    for cmd in ("kubectl apply -f k8s/good.yaml", "ls", "kubectl apply -f k8s/bad.yaml"):
        _, out, _ = _hook(_input(cmd, ws), {})
        assert out == "" and "allow" not in out


def test_not_determined_blocks(ws: Path) -> None:
    for cmd in (
        "kubectl apply -f https://example.com/x.yaml",
        "kubectl delete ns shop",
        "echo x | sh",
        "kubectl exec -it web -- sh",
        "$K apply -f k8s/good.yaml",
    ):
        code, _, err = _hook(_input(cmd, ws), {})
        assert code == 2 and "not determined" in err, cmd
        assert "Ask the user" in err


def test_an_internal_error_blocks_rather_than_allows(ws: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*a: object, **k: object) -> None:
        raise RuntimeError("bug")

    monkeypatch.setattr(verify, "evaluate", boom)
    code, _, err = _hook(_input("kubectl apply -f k8s/good.yaml", ws), {})
    assert code == 2 and "RuntimeError" in err and "blocked" in err
    monkeypatch.setattr(verify, "plan", boom)
    assert _hook(_input("ls", ws), {})[0] == 2


@pytest.mark.parametrize(
    "raw",
    [
        "not json",
        "[]",
        json.dumps({"tool_name": "Bash", "tool_input": {"command": 7}, "cwd": "/"}),
        json.dumps({"tool_name": "Bash", "tool_input": {"command": "ls"}}),
        json.dumps({"tool_name": "Bash", "tool_input": {"command": "ls"}, "cwd": "relative"}),
        json.dumps({"tool_name": "Bash", "tool_input": {"command": "ls"}, "cwd": "/no/such/dir"}),
        json.dumps(
            {"hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_input": {"command": "ls"}, "cwd": "/"}
        ),
        "{" * 100_000,
    ],
)
def test_input_the_hook_does_not_recognise_blocks(raw: str) -> None:
    code, out, err = hook.run(raw, {})
    assert code == 2 and out == "" and err


def test_oversized_input_blocks() -> None:
    assert hook.run("x" * (hook.MAX_INPUT + 1), {})[0] == 2


def test_another_tool_passes(ws: Path) -> None:
    raw = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Edit", "tool_input": {}, "cwd": str(ws)})
    assert hook.run(raw, {}) == (0, "", "")


def test_the_escape_hatch_is_the_hooks_own_environment_not_the_command(ws: Path) -> None:
    assert _hook(_input("kubectl apply -f k8s/bad.yaml", ws), {"KUBE_NOOB_HOOK": "off"}) == (0, "", "")
    for cmd in (
        "KUBE_NOOB_HOOK=off kubectl apply -f k8s/bad.yaml",
        "export KUBE_NOOB_HOOK=off; kubectl apply -f k8s/bad.yaml",
        "env KUBE_NOOB_HOOK=off kubectl apply -f k8s/bad.yaml",
    ):
        assert _hook(_input(cmd, ws), {})[0] == 2, cmd


def test_the_time_budget_blocks_when_spent(ws: Path) -> None:
    code, _, err = _hook(_input("kubectl apply -f k8s/good.yaml", ws), {}, budget=-1)
    assert code == 2 and ("budget" in err or "time budget" in err)


def test_the_hook_is_deterministic(ws: Path) -> None:
    raw = _input("kubectl apply -f k8s/", ws)
    assert hook.run(raw, {}) == hook.run(raw, {})


def test_the_cli_round_trip_over_stdin(ws: Path) -> None:
    env = {**os.environ, "KUBE_NOOB_HOOK": ""}
    run = [sys.executable, "-m", "kube_noob", "hook", "claude-code", *CLI_OPTS]
    blocked = subprocess.run(
        run,
        input=_input("sh -c 'kubectl apply -f k8s/bad.yaml'", ws),
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
        check=False,
    )
    assert blocked.returncode == 2 and blocked.stdout == "" and "KN-S013" in blocked.stderr
    allowed = subprocess.run(
        run, input=_input("kubectl get pods", ws), capture_output=True, text=True, env=env, timeout=120, check=False
    )
    assert (allowed.returncode, allowed.stdout, allowed.stderr) == (0, "", "")


def test_a_broken_configuration_file_still_blocks_rather_than_passes(ws: Path, tmp_path: Path) -> None:
    """The hook answers before kube-noob reads its configuration: an error there would have exited 2 or 4, and 4
    lets the command through."""
    bad = tmp_path / "bad-config.yaml"
    bad.write_text("webEnabled: [not, a, bool]\n")
    env = {**os.environ, "KUBE_NOOB_CONFIG": str(bad), "KUBE_NOOB_HOOK": ""}
    r = subprocess.run(
        [sys.executable, "-m", "kube_noob", "hook", "claude-code", *CLI_OPTS],
        input=_input("kubectl apply -f k8s/bad.yaml", ws),
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
        check=False,
    )
    assert r.returncode == 2 and "KN-S013" in r.stderr


# -- install -----------------------------------------------------------------------------------------------------


def test_install_prints_the_snippet_and_writes_only_with_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from kube_noob.cli import main

    monkeypatch.chdir(tmp_path)
    assert main(["hook", "install", "--claude-code", "--format", "json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["merge"] == hook.settings_snippet() and not (tmp_path / ".claude").exists()
    assert main(["hook", "install", "--claude-code", "--project", "--write"]) == 0
    written = json.loads((tmp_path / ".claude" / "settings.json").read_text())
    assert written == hook.settings_snippet()


def test_install_merges_without_clobbering_and_is_idempotent(tmp_path: Path) -> None:
    path = tmp_path / ".claude" / "settings.json"
    path.parent.mkdir()
    mine = {
        "permissions": {"allow": ["Bash(npm test)"]},
        "hooks": {
            "PreToolUse": [{"matcher": "Edit", "hooks": [{"type": "command", "command": "./lint.sh"}]}],
            "Stop": [{"hooks": [{"type": "command", "command": "./notify.sh"}]}],
        },
    }
    path.write_text(json.dumps(mine))
    os.chmod(path, 0o640)
    assert hook.write_settings(path) is True
    got = json.loads(path.read_text())
    assert got["permissions"] == mine["permissions"] and got["hooks"]["Stop"] == mine["hooks"]["Stop"]
    assert got["hooks"]["PreToolUse"][0] == mine["hooks"]["PreToolUse"][0]
    assert got["hooks"]["PreToolUse"][1] == hook.settings_snippet()["hooks"]["PreToolUse"][0]
    assert path.stat().st_mode & 0o777 == 0o640
    assert hook.write_settings(path) is False
    assert json.loads(path.read_text()) == got
    assert [p.name for p in path.parent.iterdir()] == ["settings.json"], "no temporary file is left behind"


def test_install_refuses_a_link_and_a_file_that_is_not_a_json_object(tmp_path: Path) -> None:
    real = tmp_path / "elsewhere.json"
    real.write_text("{}")
    (tmp_path / "p" / ".claude").mkdir(parents=True)
    link = tmp_path / "p" / ".claude" / "settings.json"
    os.symlink(real, link)
    with pytest.raises(hook.InstallError, match="symbolic link"):
        hook.write_settings(link)
    assert real.read_text() == "{}"
    (tmp_path / "q").mkdir()
    os.symlink(tmp_path / "p" / ".claude", tmp_path / "q" / ".claude")
    with pytest.raises(hook.InstallError, match="symbolic link"):
        hook.write_settings(tmp_path / "q" / ".claude" / "x.json")
    bad = tmp_path / "r" / ".claude" / "settings.json"
    bad.parent.mkdir(parents=True)
    for text in ("[1, 2]", "{not json"):
        bad.write_text(text)
        with pytest.raises(hook.InstallError):
            hook.write_settings(bad)
        assert bad.read_text() == text


def test_the_settings_snippet_uses_only_fields_the_hooks_reference_defines() -> None:
    (group,) = hook.settings_snippet()["hooks"]["PreToolUse"]
    assert set(group) == {"matcher", "hooks"} and group["matcher"] == "Bash"
    (h,) = group["hooks"]
    assert set(h) <= {"type", "command", "args", "timeout", "if", "statusMessage", "onFailure", "shell", "async"}
    assert h["type"] == "command" and h["onFailure"] == "block"
    assert h["timeout"] > hook.BUDGET_SECONDS * 2, "the hook answers well inside the time Claude Code gives it"


# -- the plugin ---------------------------------------------------------------------------------------------------


def test_the_plugin_hook_is_inert_until_the_user_opts_in(monkeypatch: pytest.MonkeyPatch, ws: Path) -> None:
    import io

    monkeypatch.delenv(hook.PLUGIN_OPTION_ENV, raising=False)
    monkeypatch.setattr(
        sys, "stdin", io.TextIOWrapper(io.BytesIO(_input("kubectl apply -f k8s/bad.yaml", ws).encode()))
    )
    assert hook.plugin_main() == 0
    monkeypatch.setenv(hook.PLUGIN_OPTION_ENV, "true")
    monkeypatch.setenv(hook.PLUGIN_PLATFORM_ENV, "openshift")
    monkeypatch.setenv(hook.PLUGIN_VERSION_ENV, "4.20")
    monkeypatch.delenv(hook.OFF_ENV, raising=False)
    monkeypatch.setattr(
        sys, "stdin", io.TextIOWrapper(io.BytesIO(_input("kubectl apply -f k8s/bad.yaml", ws).encode()))
    )
    assert hook.plugin_main() == 2
    monkeypatch.setenv(hook.PLUGIN_PLATFORM_ENV, "openshift; rm -rf /")
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(_input("ls", ws).encode())))
    assert hook.plugin_main() == 2, "a platform the hook does not know blocks rather than guessing"


def test_install_carries_the_target_and_refuses_a_version_that_is_not_one(tmp_path: Path) -> None:
    snippet = hook.settings_snippet(hook.Options("openshift", "4.20", "critical"))
    (group,) = snippet["hooks"]["PreToolUse"]
    assert (
        group["hooks"][0]["command"]
        == "kube-noob hook claude-code --platform openshift --version 4.20 --fail-on critical"
    )
    with pytest.raises(hook.InstallError):
        hook.Options("openshift", "4.20; curl x").args()


def test_the_plugin_wires_the_hook_with_documented_fields_only() -> None:
    plugin = ROOT / "plugin" / "kube-noob"
    cfg = json.loads((plugin / "hooks" / "hooks.json").read_text())
    assert set(cfg) <= {"description", "hooks"}
    (group,) = cfg["hooks"]["PreToolUse"]
    assert group["matcher"] == "Bash"
    (h,) = group["hooks"]
    assert set(h) <= {"type", "command", "args", "timeout"}
    # The same launcher as .mcp.json: exec form, the locked environment, nothing written into the plugin root.
    mcp = json.loads((plugin / ".mcp.json").read_text())["mcpServers"]["kube-noob"]
    assert h["command"] == mcp["command"] and h["args"][:-1] == mcp["args"][:-1]
    assert h["args"][-1] == "${CLAUDE_PLUGIN_ROOT}/hooks/kube_noob_hook.py"
    # No onFailure: block. The hook is installed for everyone who installs the plugin and is off until they opt in;
    # a uv that cannot start would otherwise block every Bash command of a user who never turned the check on.
    # Its own errors still block (exit 2), and `kube-noob hook install` writes onFailure: block for a hard gate.
    assert "onFailure" not in h and h["timeout"] > hook.BUDGET_SECONDS * 2
    assert (plugin / "hooks" / "kube_noob_hook.py").is_file()
    manifest = json.loads((plugin / ".claude-plugin" / "plugin.json").read_text())
    option = manifest["userConfig"]["verify_cluster_commands"]
    assert option["type"] == "boolean" and option["default"] is False
    launcher = (plugin / "hooks" / "kube_noob_hook.py").read_text()
    assert hook.PLUGIN_OPTION_ENV in launcher, "the launcher checks the opt-in before it imports anything"
    assert not (ROOT / "plugin" / "kube-noob-skills" / "hooks").exists()


def test_the_plugin_hook_runs_from_the_bundled_copy(ws: Path) -> None:
    script = ROOT / "plugin" / "kube-noob" / "hooks" / "kube_noob_hook.py"
    env = {
        "PATH": os.environ.get("PATH", ""),
        hook.PLUGIN_OPTION_ENV: "true",
        hook.PLUGIN_PLATFORM_ENV: "openshift",
        hook.PLUGIN_VERSION_ENV: "4.20",
    }
    r = subprocess.run(
        [sys.executable, "-I", "-B", str(script)],
        input=_input("kubectl apply -f k8s/bad.yaml", ws),
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
        check=False,
    )
    assert r.returncode == 2 and "KN-S013" in r.stderr, r.stderr[-2000:]
    off = subprocess.run(
        [sys.executable, "-I", "-B", str(script)],
        input=_input("kubectl apply -f k8s/bad.yaml", ws),
        capture_output=True,
        text=True,
        env={"PATH": env["PATH"]},
        timeout=120,
        check=False,
    )
    assert off.returncode == 0 and off.stderr == ""
