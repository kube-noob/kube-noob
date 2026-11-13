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

import contextlib
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
    #: The program the settings entry runs. `hook install` writes the absolute path of the kube-noob that ran it, so
    #: a `kube-noob` earlier on the agent's PATH (a file in the repository, a virtualenv) is not the one that runs.
    executable: str = "kube-noob"

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


def current_executable() -> str:
    """The absolute path of the kube-noob being run, for the settings entry; "kube-noob" when it cannot be found."""
    import shutil

    candidates = [sys.argv[0] if sys.argv and Path(sys.argv[0]).name.startswith("kube-noob") else None]
    candidates.append(shutil.which("kube-noob"))
    for c in candidates:
        if c and Path(c).is_file() and os.access(c, os.X_OK):
            path = str(Path(c).resolve())
            if path.isprintable():
                return path
    return "kube-noob"


def _is_kube_noob_hook(command: str) -> bool:
    """`kube-noob hook claude-code ...`, under any path to kube-noob (bare, absolute, quoted)."""
    import shlex

    try:
        words = shlex.split(command)
    except ValueError:
        return False
    return len(words) >= 3 and Path(words[0]).name == "kube-noob" and words[1:3] == ["hook", "claude-code"]


def settings_snippet(options: Options | None = None) -> dict[str, Any]:
    import shlex

    o = options or Options()
    if not o.executable.isprintable() or not (o.executable == "kube-noob" or o.executable.startswith("/")):
        raise InstallError("the kube-noob path for the settings entry is not an absolute, printable path")
    command = shlex.quote(o.executable) + HOOK_COMMAND[len("kube-noob") :] + o.args()
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
        return _run(raw, env, start + budget, options or Options(), budget)
    except Exception as exc:  # noqa: BLE001 - a crashed check is not a pass
        return _block(
            f"kube-noob hook could not check this command ({type(exc).__name__}), so it is blocked. Ask the user "
            "to review it."
        )


def _run(
    raw: bytes | str, env: Mapping[str, str], deadline: float, options: Options, budget: float = BUDGET_SECONDS
) -> tuple[int, str, str]:
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
    return check(command, Path(cwd), deadline, options, budget)


_PS_KUBE = re.compile(
    r"(?<![\w.-])(kubectl|oc|helm|kustomize|kubecolor|kapp|helmfile|argocd|flux|k|kc|kctl)(?:\.exe)?(?![\w-])", re.I
)
#: PowerShell constructs that build or run a command the text does not spell: the call operator `&`, `iex` /
#: `Invoke-Expression`, `Start-Process`, `Invoke-Command`, `Get-Command`/`gcm` (resolves a name), a `.ps1`/`.bat`
#: /`.cmd` script, `wsl`, `cmd /c`, `cmd.exe`, string concatenation or formatting ('ku'+'bectl', -join, -f),
#: `[Convert]::FromBase64String`, `[Text.Encoding]`, a backtick inside a word, `.Invoke(`, `[scriptblock]`.
_PS_CONSTRUCT = re.compile(
    r"(?<![\w])&\s*[(\$'\"]|(?<![\w.-])(iex|invoke-expression|invoke-command|start-process|start-job|gcm|get-command|"
    r"wsl|cmd|cmd\.exe|powershell|pwsh|bash|sh)(?![\w-])|\.(ps1|bat|cmd)(?![\w])|\[convert\]|\[text\.encoding\]|"
    r"frombase64string|\.invoke\(|\[scriptblock\]|['\"]\s*\+\s*['\"]|-join|(?<=['\"])\s*-f\s|\w`\w|\$\w+\s*=\s*['\"]",
    re.I,
)


def _powershell(command: str) -> tuple[int, str, str]:
    """The PowerShell tool's `tool_input.command` (hooks reference: "The fields match the Bash tool"). verify reads
    POSIX shell, not PowerShell, so a PowerShell command that names a kube tool asks; so does one that builds or
    runs a command the text does not spell -- `& ('ku'+'bectl')`, `iex`, `gcm kube*`, a `.ps1` script, `wsl -e`,
    base64 (fifth review) -- since a substring test alone let every built name through. One that does neither
    passes."""
    m = _PS_KUBE.search(command)
    if m is not None:
        return _ask(
            f"kube-noob verify does not read PowerShell, and this command names {m.group(1)}. Approve it only if "
            "you know what it changes in the cluster."
        )
    c = _PS_CONSTRUCT.search(command)
    if c is not None:
        return _ask(
            "kube-noob verify does not read PowerShell, and this command builds or runs a command its text does not "
            f"spell ({c.group(0).strip()[:40]!r}). Approve it only if you know what it runs."
        )
    return _pass()


def check(
    command: str, cwd: Path, deadline: float, options: Options | None = None, budget: float = BUDGET_SECONDS
) -> tuple[int, str, str]:
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
        return _block(_timeout_message(budget))
    if result["verdict"] == "allow":
        return _pass()
    if result["verdict"] == "deny":
        return _block(verify.hook_message(result))
    return _ask(verify.hook_message(result, limit=MAX_REASON))


def _timeout_message(budget: float) -> str:
    """The budget the hook ran with, not the default: the message said "20-second" whatever it was."""
    return (
        f"kube-noob hook: the check took longer than its {budget:g}-second budget, so the command is blocked. "
        "Run kube-noob verify --command on it to see why."
    )


def main(
    stdin: Any = None,
    env: Mapping[str, str] | None = None,
    options: Options | None = None,
    *,
    budget: float | None = None,
    isolate: str | None = None,
) -> int:
    """Answer one hook call within the budget, whatever happens: the check runs in a CHILD PROCESS that is killed
    when the budget is spent, and the hook then blocks (exit 2). A thread could not do this: a regular expression
    running in C holds the interpreter until it returns, so a Makefile line built to be slow kept the hook past
    Claude Code's timeout -- which lets the call through unless `onFailure` is set.

    ``isolate``: "fork" (POSIX, the default there), "spawn" (a fresh interpreter, the default where there is no
    fork) or "thread" (tests only: not bounded against C code)."""
    limit = BUDGET_SECONDS + 1.0 if budget is None else budget
    try:
        tolerant_streams()  # the deny's stderr and the ask's reason carry « »; an ASCII terminal still gets them
        raw = (stdin or sys.stdin.buffer).read(MAX_INPUT + 1)
        mode = isolate or ("fork" if hasattr(os, "fork") else "spawn")
        got = _bounded(raw, dict(os.environ if env is None else env), options, limit, mode)
        if got is None:
            _write(sys.stderr, _timeout_message(limit) + "\n")
            return 2
        code, out, err = got
        if out and not _write(sys.stdout, out):
            # The `ask` (or any answer on stdout) did not reach Claude Code: blocking is the only safe reading.
            _write(sys.stderr, "kube-noob hook could not write its answer; the command is blocked.\n")
            return 2
        _write(sys.stderr, err)
        return code
    except BaseException:  # noqa: BLE001 - a crashed hook is not a pass
        _write(sys.stderr, "kube-noob hook failed while answering; the command is blocked.\n")
        return 2


def _bounded(
    raw: bytes, env: dict[str, str], options: Options | None, limit: float, mode: str
) -> tuple[int, str, str] | None:
    """run() in a child bounded by ``limit`` seconds: its answer, or None when it was killed for time."""
    if mode == "thread":
        box: list[tuple[int, str, str]] = []
        worker = threading.Thread(target=lambda: box.append(run(raw, env, options=options)), daemon=True)
        worker.start()
        worker.join(limit)
        return box[0] if box else None
    if mode == "fork":
        rfd, wfd = os.pipe()
        pid = os.fork()
        if pid == 0:  # pragma: no cover - the child; its result reaches the parent through the pipe
            code = 3
            try:
                os.close(rfd)
                data = json.dumps(run(raw, env, options=options)).encode()
                view = memoryview(data)
                while view:
                    view = view[os.write(wfd, view) :]
                code = 0
            finally:
                os._exit(code)
        os.close(wfd)
        answer = _read_until(rfd, limit, lambda: _kill(pid))
        os.close(rfd)
        _, status = os.waitpid(pid, 0)
        if answer is None:
            return None
        if status != 0:
            return _block("kube-noob hook: the check stopped before it answered; blocked.")
        return _decode(answer)
    # spawn: a fresh interpreter on the same code (kube_noob.hook_spawn). The Claude plugin starts no program, so
    # its copy has no such module: there, without fork, the check runs in a thread (bounded except against C code;
    # the reader's patterns are linear, and the plugin's guard kills uv at 45 seconds).
    try:
        from kube_noob.hook_spawn import run_spawned
    except ImportError:
        return _bounded(raw, env, options, limit, "thread")
    answer = run_spawned(raw, env, None if options is None else dict(options.__dict__), limit)
    if answer is None:
        return None
    return _decode(answer) if answer else _block("kube-noob hook: the check stopped before it answered; blocked.")


def _read_until(fd: int, limit: float, on_timeout: Any) -> bytes | None:
    import select

    deadline = time.monotonic() + limit
    chunks: list[bytes] = []
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            on_timeout()
            return None
        ready, _, _ = select.select([fd], [], [], remaining)
        if not ready:
            continue
        chunk = os.read(fd, 65536)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def _kill(pid: int) -> None:
    import signal

    with contextlib.suppress(OSError):
        os.kill(pid, signal.SIGKILL)


def _decode(data: bytes) -> tuple[int, str, str]:
    try:
        code, out, err = sanitize.loads_bounded(data)
        if code in (0, 2) and isinstance(out, str) and isinstance(err, str) and _only_ask(out):
            return int(code), out, err
    except (ValueError, TypeError):
        pass
    return _block("kube-noob hook: the check gave no answer it could read; blocked.")


def _only_ask(out: str) -> bool:
    """The hook prints nothing, or a PreToolUse `ask`. Anything else on stdout (an `allow`, which would skip the
    user's prompt) is not an answer this hook gives, whatever produced it."""
    if not out.strip():
        return True
    try:
        doc = sanitize.loads_bounded(out)
        return set(doc) == {"hookSpecificOutput"} and doc["hookSpecificOutput"].get("permissionDecision") == "ask"
    except (ValueError, TypeError, AttributeError, KeyError):
        return False


def tolerant_streams() -> None:
    """stdout and stderr write under any terminal encoding: a character the encoding lacks (the « » around text
    from the repository, under `PYTHONIOENCODING=ascii` or `LC_ALL=POSIX`) is written as an escape such as `\\xab`
    rather than raising, which turned a verify allow into exit 4 and a harness that refuses on non-zero refused
    every command. `kube-noob verify` calls this too; it lives here so the plugin's copy needs nothing of the CLI."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            with contextlib.suppress(OSError, ValueError, TypeError):  # a stream that cannot be reconfigured
                reconfigure(errors="backslashreplace")


def _write(stream: Any, text: str) -> bool:
    """Write and flush; False when the stream is closed or the pipe is broken."""
    if not text:
        return True
    try:
        stream.write(text)
        stream.flush()
        return True
    except (OSError, ValueError):
        return False  # a closed stream: the exit code still answers


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
                if not _is_kube_noob_hook(command):
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
