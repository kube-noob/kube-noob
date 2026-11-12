"""``kube-noob hook claude-code``: a Claude Code PreToolUse hook that runs ``kube-noob verify`` before a Bash command
that changes cluster state, and blocks it unless the answer is ``allow``.

The protocol, from the Claude Code hooks reference (https://code.claude.com/docs/en/hooks, reached from
https://docs.claude.com/en/docs/claude-code/hooks, read 2026-11-12):

- the hook receives one JSON object on stdin with ``tool_name``, ``tool_input`` (for Bash: ``command``,
  ``description``, ``timeout``, ``run_in_background``), ``cwd``, ``hook_event_name`` and session fields;
- exit 0 lets the call proceed (stdout, if any, must be one JSON object); exit 2 blocks a PreToolUse call and
  "Claude sees the stderr message as the denial reason"; any other exit code is a NON-blocking error -- exit 1
  does not block;
- a command hook defaults to a 600-second timeout, and a hook that fails or times out lets the action through
  unless the hook sets ``"onFailure": "block"`` (Claude Code v2.1.295 or later);
- ``permissionDecision: "allow"`` skips the user's permission prompt, so this hook never prints it: a pass is a
  silent exit 0, and the user's own permission rules still apply.

So this hook blocks with exit 2 and a message on stderr -- for ``deny``, for ``not-determined`` (fail closed), and
for its own errors, including input it does not recognise and an exhausted time budget: a crashed check is not a
pass. It never runs the command, reads only inside the ``cwd`` the hook input names (``kube_noob.verify``'s rules:
no link followed, nothing outside the tree, no URL), and answers well inside its budget.

The human's escape hatch is ``KUBE_NOOB_HOOK=off`` in the environment Claude Code itself was started with. The
hook reads its own process environment, which a command the agent writes cannot change: ``KUBE_NOOB_HOOK=off
kubectl apply ...`` sets the variable for kubectl, not for the hook, and the line is checked like any other.
"""

from __future__ import annotations

import copy
import json
import os
import re
import sys
import tempfile
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from kube_noob import sanitize

MAX_INPUT = 1_000_000
#: Seconds this hook gives itself before it blocks for lack of time. The configured hook timeout (below) is well
#: above it, so the hook always answers instead of being cut off (which Claude Code would treat as a failure).
BUDGET_SECONDS = 20.0
#: The `timeout` written into the settings snippet, in seconds (the hooks reference's unit).
HOOK_TIMEOUT = 60
OFF_ENV = "KUBE_NOOB_HOOK"
#: The Claude plugin's opt-in, exported to hook processes by Claude Code as CLAUDE_PLUGIN_OPTION_<KEY> for the
#: plugin's `userConfig` option `verify_cluster_commands` (plugins reference, "Reference a saved value").
PLUGIN_OPTION_ENV = "CLAUDE_PLUGIN_OPTION_VERIFY_CLUSTER_COMMANDS"
PLUGIN_PLATFORM_ENV = "CLAUDE_PLUGIN_OPTION_VERIFY_PLATFORM"
PLUGIN_VERSION_ENV = "CLAUDE_PLUGIN_OPTION_VERIFY_VERSION"
HOOK_COMMAND = "kube-noob hook claude-code"
#: The one local file this module writes, and only with `hook install --claude-code --write`. Listed in the safety
#: contract next to the MCP tools that write this machine's own state.
SETTINGS_WRITE = (
    "kube-noob hook install --claude-code --write",
    "the Claude Code settings file named by --user, --project or --local: the PreToolUse hook merged in, existing "
    "hooks kept, written atomically, refused through a symbolic link; without --write it prints the JSON only",
)


_VERSION = re.compile(r"^\d{1,2}\.\d{1,3}(\.\d{1,3})?\Z")


@dataclass(frozen=True)
class Options:
    """What the hook checks for: the same target and threshold `kube-noob verify` takes."""

    platform: str = "kubernetes"
    version: str | None = None
    fail_on: str = "high"

    def args(self) -> str:
        """The flags for the settings snippet; every value is from a closed set or a version pattern, so the
        string is safe in a shell-form hook command."""
        from kube_noob.catalog import PLATFORMS

        if self.platform not in PLATFORMS or self.fail_on not in _FAIL_ON:
            raise InstallError("unknown platform or --fail-on")
        if self.version is not None and not _VERSION.match(self.version):
            raise InstallError(f"--version {self.version!r} is not a version such as 4.20 or 1.33")
        out = ""
        if self.platform != "kubernetes":
            out += f" --platform {self.platform}"
        if self.version:
            out += f" --version {self.version}"
        if self.fail_on != "high":
            out += f" --fail-on {self.fail_on}"
        return out


_FAIL_ON = ("info", "low", "medium", "high", "critical", "never")


def settings_snippet(options: Options | None = None) -> dict[str, Any]:
    command = HOOK_COMMAND + (options or Options()).args()
    return {
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "Bash",
                    "hooks": [{"type": "command", "command": command, "timeout": HOOK_TIMEOUT, "onFailure": "block"}],
                }
            ]
        }
    }


def _block(message: str) -> tuple[int, str, str]:
    return 2, "", message.rstrip() + "\n"


def _pass() -> tuple[int, str, str]:
    return 0, "", ""


def run(
    raw: bytes | str, env: Mapping[str, str], *, budget: float = BUDGET_SECONDS, options: Options | None = None
) -> tuple[int, str, str]:
    """(exit code, stdout, stderr) for one hook call. Never raises: an error blocks."""
    start = time.monotonic()
    try:
        return _run(raw, env, start + budget, options or Options())
    except Exception as exc:  # noqa: BLE001 - a crashed check is not a pass
        return _block(
            f"kube-noob hook could not check this command ({type(exc).__name__}), so it is blocked. Ask the user "
            "to review it."
        )


def _run(raw: bytes | str, env: Mapping[str, str], deadline: float, options: Options) -> tuple[int, str, str]:
    if str(env.get(OFF_ENV, "")).strip().lower() == "off":
        return _pass()
    data = raw.encode("utf-8", "replace") if isinstance(raw, str) else raw
    if len(data) > MAX_INPUT:
        return _block(f"kube-noob hook: the hook input is larger than {MAX_INPUT:,} bytes; blocked.")
    from kube_noob import sanitize

    try:
        doc = sanitize.loads_bounded(data)
    except Exception:  # noqa: BLE001
        return _block("kube-noob hook: the hook input is not the JSON Claude Code sends; blocked.")
    if not isinstance(doc, dict):
        return _block("kube-noob hook: the hook input is not a JSON object; blocked.")
    event = doc.get("hook_event_name")
    if event is not None and event != "PreToolUse":
        return _block(f"kube-noob hook: configured for {str(event)[:40]!r}; it answers PreToolUse only. Blocked.")
    if doc.get("tool_name") != "Bash":
        return _pass()  # the matcher should send only Bash; anything else is not this hook's business
    tool_input = doc.get("tool_input")
    command = tool_input.get("command") if isinstance(tool_input, dict) else None
    if not isinstance(command, str):
        return _block("kube-noob hook: a Bash call with no command string; blocked.")
    cwd = doc.get("cwd")
    if not isinstance(cwd, str) or not cwd.startswith("/") or not Path(cwd).is_dir():
        return _block("kube-noob hook: the hook input names no working directory that exists; blocked.")
    return check(command, Path(cwd), deadline, options)


def check(command: str, cwd: Path, deadline: float, options: Options | None = None) -> tuple[int, str, str]:
    """Pass a line that starts no cluster change; verify the rest."""
    from kube_noob import verify

    o = options or Options()
    plan = verify.plan(command, cwd=cwd, deadline=deadline, platform=o.platform, version=o.version)
    # A line with no kube tool has no commands here at all, and that is the pass-through case on purpose: the
    # reader has already put anything it could not see into `undetermined`, so "nothing that changes a cluster"
    # is a positive finding, not an empty one.
    changes = [c for c in plan.commands if c["class"] not in {"read-only", "local"}]
    if not plan.undetermined and not plan.deny and len(changes) == 0:
        return _pass()
    result = verify.evaluate(
        plan.sources, command=plan, from_command=True, platform=o.platform, version=o.version, fail_on=o.fail_on
    )
    if time.monotonic() > deadline:
        return _block(
            f"kube-noob hook: the check took longer than its {BUDGET_SECONDS:.0f}-second budget, so the command is "
            "blocked. Run kube-noob verify --command on it to see why."
        )
    if result["verdict"] == "allow":
        return _pass()
    return _block(verify.hook_message(result))


def main(stdin: Any = None, env: Mapping[str, str] | None = None, options: Options | None = None) -> int:
    raw = (stdin or sys.stdin.buffer).read(MAX_INPUT + 1)
    code, out, err = run(raw, os.environ if env is None else env, options=options)
    if out:
        sys.stdout.write(out)
    if err:
        sys.stderr.write(err)
    return code


def plugin_main() -> int:
    """The Claude plugin's hook: inert until the user turns on the plugin's ``verify_cluster_commands`` option, so
    installing or updating the plugin never starts blocking anybody's commands on its own."""
    if os.environ.get(PLUGIN_OPTION_ENV, "").strip().lower() not in {"true", "1", "yes", "on"}:
        return 0
    from kube_noob.catalog import PLATFORMS

    platform = os.environ.get(PLUGIN_PLATFORM_ENV, "").strip() or "kubernetes"
    version = os.environ.get(PLUGIN_VERSION_ENV, "").strip() or None
    if platform not in PLATFORMS or (version is not None and not _VERSION.match(version)):
        sys.stderr.write(
            f"kube-noob hook: the plugin's verify_platform ({platform[:40]!r}) or verify_version "
            f"({str(version)[:20]!r}) is not one kube-noob knows ({', '.join(PLATFORMS)}; versions like 4.20 or "
            "1.33); blocked until it is fixed in /config.\n"
        )
        return 2
    return main(options=Options(platform=platform, version=version))


# -- install -----------------------------------------------------------------------------------------------------


class InstallError(ValueError):
    pass


def settings_path(scope: str, project_dir: Path, home: Path) -> Path:
    """Where Claude Code reads settings (hooks reference, "Hook locations")."""
    if scope == "user":
        return home / ".claude" / "settings.json"
    if scope == "local":
        return project_dir / ".claude" / "settings.local.json"
    return project_dir / ".claude" / "settings.json"


def merged(existing: dict[str, Any], options: Options | None = None) -> tuple[dict[str, Any], bool]:
    """``existing`` with this hook added to PreToolUse, and whether anything changed. Every other key, event and
    hook is kept as it was; a second install adds nothing."""
    out = copy.deepcopy(existing)
    hooks = out.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise InstallError("the settings file's `hooks` is not an object; fix it by hand first")
    groups = hooks.setdefault("PreToolUse", [])
    if not isinstance(groups, list):
        raise InstallError("the settings file's `hooks.PreToolUse` is not a list; fix it by hand first")
    for g in groups:
        if isinstance(g, dict) and isinstance(g.get("hooks"), list):
            for h in g["hooks"]:
                command = str(h.get("command", "")).strip() if isinstance(h, dict) else ""
                if command == HOOK_COMMAND or command.startswith(HOOK_COMMAND + " "):
                    return out, False  # already there (with its own flags, which a person may have chosen)
    groups.append(settings_snippet(options)["hooks"]["PreToolUse"][0])
    return out, True


def write_settings(path: Path, options: Options | None = None) -> bool:
    """Merge the hook into ``path`` atomically. Refuses a symbolic link anywhere from the `.claude` folder down,
    and a file that is not a JSON object."""
    folder = path.parent
    for p in (folder, path):
        if p.is_symlink():
            raise InstallError(f"{p} is a symbolic link; kube-noob does not write through links")
    existing: dict[str, Any] = {}
    if path.exists():
        if not path.is_file():
            raise InstallError(f"{path} is not a file")
        text = path.read_text(encoding="utf-8")
        try:
            loaded = sanitize.loads_bounded(text, sanitize.MAX_JSON_DEPTH_FILE) if text.strip() else {}
        except json.JSONDecodeError as exc:
            raise InstallError(f"{path} is not valid JSON ({exc.msg} at line {exc.lineno}); fix it first") from exc
        except sanitize.JsonTooDeep as exc:
            raise InstallError(f"{path}: {exc}") from exc
        if not isinstance(loaded, dict):
            raise InstallError(f"{path} does not hold a JSON object")
        existing = loaded
    new, changed = merged(existing, options)
    if not changed:
        return False
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    if folder.is_symlink():
        raise InstallError(f"{folder} is a symbolic link; kube-noob does not write through links")
    mode = path.stat().st_mode & 0o777 if path.exists() else 0o600
    fd, tmp = tempfile.mkstemp(prefix=".settings.", suffix=".tmp", dir=folder)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(new, indent=2) + "\n")
        os.chmod(tmp, mode)
        if path.is_symlink():
            raise InstallError(f"{path} became a symbolic link; not written")
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    return True
