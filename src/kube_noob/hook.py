"""``kube-noob hook claude-code``: a Claude Code PreToolUse hook that runs ``kube-noob verify`` before a Bash command
that changes cluster state: it passes an ``allow``, blocks a ``deny`` and asks the user about a ``not-determined``.

The protocol, from the Claude Code hooks reference (https://code.claude.com/docs/en/hooks, reached from
https://docs.claude.com/en/docs/claude-code/hooks, read 2026-11-12):

- the hook receives one JSON object on stdin with ``tool_name``, ``tool_input`` (for Bash and for the PowerShell
  tool: ``command``, ``description``, ``timeout``, ``run_in_background``), ``cwd``, ``hook_event_name`` and session
  fields;
- exit 0 lets the call proceed (stdout, if any, must be one JSON object); exit 2 blocks a PreToolUse call and
  "Claude sees the stderr message as the denial reason"; any other exit code is a NON-blocking error -- exit 1
  does not block;
- ``permissionDecision: "ask"`` "prompts the user to confirm", with ``permissionDecisionReason`` "shown to the user
  in the permission prompt"; in a ``-p`` run nobody can answer, so Claude Code denies the call;
- a command hook defaults to a 600-second timeout, and a hook that fails, cannot start or times out lets the action
  through unless the hook sets ``"onFailure": "block"`` (Claude Code v2.1.295 or later);
- ``permissionDecision: "allow"`` skips the user's permission prompt, so this hook never prints it: a pass is a
  silent exit 0, and the user's own permission rules still apply.

So this hook blocks with exit 2 and a message on stderr for ``deny`` and for its own errors (input it does not
recognise, a crash, an exhausted 20-second budget, enforced by a worker thread so no in-bounds input runs past it);
it asks the user, with the reasons, for ``not-determined``. It never runs the command, reads only inside the ``cwd``
the hook input names (``kube_noob.verify``'s rules: no link followed, nothing outside the tree, no URL), and runs only
a ``helm`` from an absolute PATH entry outside that tree.

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
import threading
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
#: Bash and the PowerShell tool, whose `tool_input` also carries `command` (hooks reference, "The matcher
#: `Bash|PowerShell` covers the PowerShell tool as well as Bash").
MATCHER = "Bash|PowerShell"
#: `permissionDecisionReason`, `additionalContext` and plain stdout are capped at 10,000 characters by Claude Code.
MAX_REASON = 9_000
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
                    "matcher": MATCHER,
                    "hooks": [{"type": "command", "command": command, "timeout": HOOK_TIMEOUT, "onFailure": "block"}],
                }
            ]
        }
    }


def _block(message: str) -> tuple[int, str, str]:
    return 2, "", message.rstrip() + "\n"


def _pass() -> tuple[int, str, str]:
    return 0, "", ""


def _ask(message: str) -> tuple[int, str, str]:
    """PreToolUse's documented `ask`: the user is prompted with the reason; in a `-p` run nobody can answer, so
    Claude Code denies the call and Claude reads the reason (hooks reference, permissionDecisionReason)."""
    out = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask",
            "permissionDecisionReason": message[:MAX_REASON],
        }
    }
    return 0, json.dumps(out) + "\n", ""


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
    try:
        doc = sanitize.loads_bounded(data)
    except Exception:  # noqa: BLE001
        return _block("kube-noob hook: the hook input is not the JSON Claude Code sends; blocked.")
    if not isinstance(doc, dict):
        return _block("kube-noob hook: the hook input is not a JSON object; blocked.")
    event = doc.get("hook_event_name")
    if event is not None and event != "PreToolUse":
        return _block(f"kube-noob hook: configured for {str(event)[:40]!r}; it answers PreToolUse only. Blocked.")
    tool = doc.get("tool_name")
    if tool not in {"Bash", "PowerShell"}:
        return _pass()  # the matcher sends Bash and PowerShell; anything else is not this hook's business
    tool_input = doc.get("tool_input")
    command = tool_input.get("command") if isinstance(tool_input, dict) else None
    if not isinstance(command, str):
        return _block(f"kube-noob hook: a {tool} call with no command string; blocked.")
    if tool == "PowerShell":
        return _powershell(command)
    cwd = doc.get("cwd")
    if not isinstance(cwd, str) or not cwd.startswith("/") or not Path(cwd).is_dir():
        return _block("kube-noob hook: the hook input names no working directory that exists; blocked.")
    return check(command, Path(cwd), deadline, options)


_PS_KUBE = re.compile(
    r"(?<![\w.-])(kubectl|oc|helm|kustomize|kubecolor|kapp|helmfile|argocd|flux)(?:\.exe)?(?![\w-])", re.I
)


def _powershell(command: str) -> tuple[int, str, str]:
    """The PowerShell tool's `tool_input.command` (hooks reference: "The fields match the Bash tool"). verify reads
    POSIX shell, not PowerShell, so a PowerShell command that names a kube tool is not determined and asks; one that
    names none passes."""
    m = _PS_KUBE.search(command)
    if m is None:
        return _pass()
    return _ask(
        f"kube-noob verify does not read PowerShell, and this command names {m.group(1)}. Approve it only if you know "
        "what it changes in the cluster."
    )


def check(command: str, cwd: Path, deadline: float, options: Options | None = None) -> tuple[int, str, str]:
    """Pass a line that starts no cluster change; verify the rest. allow passes silently, deny blocks (exit 2),
    not-determined asks the user."""
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
        return _block(_TIMEOUT_MESSAGE)
    if result["verdict"] == "allow":
        return _pass()
    if result["verdict"] == "deny":
        return _block(verify.hook_message(result))
    return _ask(verify.hook_message(result, limit=MAX_REASON))


_TIMEOUT_MESSAGE = (
    f"kube-noob hook: the check took longer than its {BUDGET_SECONDS:.0f}-second budget, so the command is blocked. "
    "Run kube-noob verify --command on it to see why."
)


def main(stdin: Any = None, env: Mapping[str, str] | None = None, options: Options | None = None) -> int:
    """Answer one hook call within the budget, whatever happens: the check runs in a worker thread and the hook
    blocks (exit 2) when it has not answered by then -- a check that is still running is not a pass, and Claude Code
    would let a hook that hits its own timeout through unless `onFailure` is set."""
    try:
        raw = (stdin or sys.stdin.buffer).read(MAX_INPUT + 1)
        box: list[tuple[int, str, str]] = []
        worker = threading.Thread(
            target=lambda: box.append(run(raw, os.environ if env is None else env, options=options)), daemon=True
        )
        worker.start()
        worker.join(BUDGET_SECONDS + 1.0)
        if not box:
            _write(sys.stderr, _TIMEOUT_MESSAGE + "\n")
            os._exit(2)  # the worker is still running; do not wait for it at interpreter shutdown
        code, out, err = box[0]
        _write(sys.stdout, out)
        _write(sys.stderr, err)
        return code
    except BaseException:  # noqa: BLE001 - a crashed hook is not a pass
        _write(sys.stderr, "kube-noob hook failed while answering; the command is blocked.\n")
        return 2


def _write(stream: Any, text: str) -> None:
    if not text:
        return
    try:
        stream.write(text)
        stream.flush()
    except (OSError, ValueError):
        pass  # a closed stream: the exit code still answers


#: The values that turn the plugin's check on, matched exactly and ignoring ASCII case -- the rule the shell guard in
#: the plugin's hooks.json applies (`[Tt][Rr][Uu][Ee]|1|[Yy][Ee][Ss]|[Oo][Nn]`) and the launcher repeats. No
#: whitespace is stripped anywhere, so the three cannot disagree about " true".
PLUGIN_ON_VALUES = frozenset({"true", "1", "yes", "on"})


def plugin_opted_in(value: str | None) -> bool:
    """Whether the plugin option's value turns the check on (see PLUGIN_ON_VALUES)."""
    return value is not None and value.isascii() and value.lower() in PLUGIN_ON_VALUES


def plugin_main() -> int:
    """The Claude plugin's hook: inert until the user turns on the plugin's ``verify_cluster_commands`` option, so
    installing or updating the plugin never starts blocking anybody's commands on its own."""
    if not plugin_opted_in(os.environ.get(PLUGIN_OPTION_ENV)):
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
    wanted = settings_snippet(options)["hooks"]["PreToolUse"][0]
    want_cmd = wanted["hooks"][0]["command"]
    for g in groups:
        if isinstance(g, dict) and isinstance(g.get("hooks"), list):
            for h in g["hooks"]:
                command = str(h.get("command", "")).strip() if isinstance(h, dict) else ""
                if not (command == HOOK_COMMAND or command.startswith(HOOK_COMMAND + " ")):
                    continue
                if command == want_cmd and _covers(g.get("matcher")) and h.get("onFailure") == "block":
                    return out, False  # this exact hook is installed
                # A kube-noob entry that would not do what this install promises: on another matcher (it never
                # runs on Bash), with other flags (`--fail-on never` allows everything), without onFailure.
                raise InstallError(
                    f"a different kube-noob hook is already there (matcher {str(g.get('matcher'))[:40]!r}, command "
                    f"{command[:120]!r}, onFailure {str(h.get('onFailure'))[:20]!r}); edit or remove it, then run "
                    "this again"
                )
    groups.append(wanted)
    return out, True


def _covers(matcher: Any) -> bool:
    """Whether a matcher sends both Bash and PowerShell calls to the hook (hooks reference: `*`, empty or omitted
    match every tool; letters and `|` are an exact list)."""
    if matcher in (None, "", "*"):
        return True
    if not isinstance(matcher, str) or not re.fullmatch(r"[A-Za-z0-9_|, -]+", matcher):
        return False
    names = {m.strip() for m in re.split(r"[|,]", matcher)}
    return {"Bash", "PowerShell"} <= names


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
        if not os.access(path, os.W_OK) or not (path.stat().st_mode & 0o200):
            raise InstallError(f"{path} is read-only; kube-noob does not replace a file its owner made read-only")
        text = path.read_text(encoding="utf-8")
        if not sanitize.json_nesting_ok(text, sanitize.MAX_JSON_DEPTH_FILE):
            raise InstallError(f"{path}: JSON nested too deeply")
        duplicate: list[str] = []

        def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
            keys = [k for k, _ in items]
            duplicate.extend(k for k in set(keys) if keys.count(k) > 1)
            return dict(items)

        try:
            loaded = sanitize.loads_bounded(text, sanitize.MAX_JSON_DEPTH_FILE, pairs) if text.strip() else {}
        except json.JSONDecodeError as exc:
            raise InstallError(f"{path} is not valid JSON ({exc.msg} at line {exc.lineno}); fix it first") from exc
        if duplicate:
            raise InstallError(
                f"{path} repeats the key(s) {', '.join(sorted(set(duplicate))[:5])}; JSON keeps only the last one, so "
                "a merge would drop the others. Fix it first"
            )
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
