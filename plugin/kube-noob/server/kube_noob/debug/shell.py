"""Read a shell command line into the simple commands it would run, without running anything.

``kube-noob verify --command`` and the Claude Code hook ask one question of a line an agent is about to run: which
``kubectl``, ``oc``, ``helm`` and ``kustomize`` commands does it start, with which arguments, from which directory,
after which other commands? The answer has to see through the forms that hide a command (``sh -c '...'``, ``bash
-lc``, ``eval``, ``env``, ``sudo``, ``xargs``, ``find -exec``, ``watch``, ``timeout``, a full path, the ``k`` alias,
``kubectl1.30``, backslash-newlines, a word split by quotes such as ``kub"e"ctl`` or written ``$'kubectl'``, command
substitutions anywhere -- in ``${x:-$(...)}``, ``$(( ... ))`` and unquoted here-documents too --, a here-document
fed to a shell, a script file in the working tree) or say that it cannot.

What this reader does NOT see through is reported, never assumed harmless (``Line.opaque``): a command word built
from an expansion (``$CMD apply``), ``eval`` of a value only known when it runs, code piped into a shell, a script
it cannot read, or a kube tool named in the arguments of a program that runs its arguments as code (``python -c``,
``ssh``, ``docker``, ``awk``, ``git -c``, ``man -P``). The caller decides what an opaque line means.

It also records what the line WRITES before a later command reads it (output redirections) and the directory each
command runs in (``cd``/``pushd`` with a literal argument; ``( ... )`` and child shells keep their own), because a
file named by ``kubectl apply -f`` is only the file on disk if nothing earlier on the line rewrote it, and only the
file in the working directory if nothing changed directory first.

Bounded: 20,000 characters, 4 levels of ``sh -c``/``eval``/script nesting, 2,000 words, 200 commands. Quoting
follows POSIX sh (single quotes literal, backslash escapes outside them, double quotes keep ``$`` and backticks
live, bash's ``$'...'``). It is a reader for the shapes agents write, not a shell: a construct it does not parse is
opaque.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Callable
from dataclasses import dataclass, field

MAX_CHARS = 20_000
MAX_DEPTH = 4
MAX_WORDS = 2_000
MAX_COMMANDS = 200
MAX_SCRIPT_BYTES = 256 * 1024

#: Programs that change or read cluster state. ``k`` is the alias the Kubernetes docs suggest for kubectl
#: (kubernetes.io/docs/reference/kubectl/quick-reference/, "alias k=kubectl"); ``kubecolor`` passes its
#: arguments to kubectl.
KUBE_TOOLS = frozenset({"kubectl", "oc", "helm", "kustomize", "kubecolor", "k"})
_KUBE_NAME = re.compile(r"(kubectl|oc|helm|kustomize|kubecolor)[-_.]?v?\d+(?:\.\d+)*", re.IGNORECASE)
#: A kube tool named anywhere in a word. ``k`` is left out: a single letter inside an argument is not evidence.
MENTION = re.compile(r"(?<![\w.-])(kubectl|oc|helm|kustomize|kubecolor)(?:[-_.]?v?\d+(?:\.\d+)*)?(?:\.exe)?(?![\w-])")
SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "ash", "mksh", "yash", "fish"})
#: Programs whose arguments are data: a kube tool named in them is text, not a command. Each one is either a pure
#: text tool or never runs its arguments (``git commit -m "kubectl ..."``, ``grep kubectl``, ``echo``). ``git`` is
#: here for its ordinary use; ``git -c`` (an alias or pager that runs a command) is checked like an executor.
DATA_ONLY = frozenset(
    {
        "echo",
        "printf",
        "grep",
        "egrep",
        "fgrep",
        "rg",
        "ag",
        "cat",
        "head",
        "tail",
        "wc",
        "sort",
        "uniq",
        "cut",
        "tr",
        "column",
        "nl",
        "ls",
        "git",
        "gh",
        "jq",
        "yq",
        "diff",
        "cmp",
        "mkdir",
        "touch",
        "cp",
        "mv",
        "rm",
        "ln",
        "chmod",
        "tee",
        "test",
        "[",
        "[[",
        "true",
        "false",
        "which",
        "type",
        "whereis",
        "cd",
        "pushd",
        "popd",
        "pwd",
        "stat",
        "file",
        "base64",
        "kube-noob",
        "yamllint",
        "kubeconform",
        "kubeval",
        "read",
        ":",
        "sleep",
        "date",
        "basename",
        "dirname",
        "realpath",
        "readlink",
    }
)
#: Programs that run their arguments (or a file they name) as code. A kube tool named in their arguments is not
#: data: it is a command this reader cannot follow, so the line is opaque. Interpreters are checked on their code
#: argument (`-c`, `-e`) and on a script file in the tree; the rest on every argument.
INTERPRETERS: dict[str, frozenset[str]] = {
    "python": frozenset({"-c"}),
    "python3": frozenset({"-c"}),
    "python2": frozenset({"-c"}),
    "pypy3": frozenset({"-c"}),
    "node": frozenset({"-e", "--eval", "-p", "--print"}),
    "nodejs": frozenset({"-e", "--eval", "-p", "--print"}),
    "deno": frozenset({"eval"}),
    "bun": frozenset({"-e", "--eval"}),
    "perl": frozenset({"-e", "-E"}),
    "ruby": frozenset({"-e"}),
    "php": frozenset({"-r"}),
    "lua": frozenset({"-e"}),
}
EXECUTORS = frozenset(
    {
        "ssh",
        "docker",
        "podman",
        "nerdctl",
        "minikube",
        "su",
        "runuser",
        "nsenter",
        "chroot",
        "systemd-run",
        "unshare",
        "firejail",
        "flatpak-spawn",
        "setpriv",
        "script",
        "tmux",
        "screen",
        "parallel",
        "expect",
        "at",
        "batch",
        "crontab",
        "pwsh",
        "powershell",
        "osascript",
        "awk",
        "gawk",
        "mawk",
        "nawk",
        "busybox",
        "sed",
        "vim",
        "vi",
        "nvim",
        "ex",
        "emacs",
        "man",
        "less",
        "more",
        "make",
        "just",
        "task",
    }
)
#: Other programs that deploy to a cluster. verify does not model them; each one that is not reading is not
#: determined. `kapp deploy -f FILE` is modelled like `kubectl apply -f FILE` by the caller.
DEPLOYERS: dict[str, frozenset[str]] = {
    "helmfile": frozenset({"template", "lint", "diff", "list", "status", "build", "deps", "repos", "version", "help"}),
    "argocd": frozenset({"version", "help", "context", "login", "logout"}),
    "flux": frozenset(
        {"get", "check", "version", "logs", "events", "stats", "tree", "trace", "diff", "export", "help"}
    ),
    "skaffold": frozenset({"build", "render", "diagnose", "fix", "version", "help", "schema", "inspect"}),
    "terraform": frozenset(
        {"init", "workspace", "plan", "validate", "fmt", "show", "output", "providers", "version", "graph", "help"}
    ),
    "tofu": frozenset(
        {"init", "workspace", "plan", "validate", "fmt", "show", "output", "providers", "version", "graph", "help"}
    ),
    "pulumi": frozenset({"preview", "stack", "config", "about", "version", "whoami", "logs"}),
    "istioctl": frozenset({"analyze", "version", "proxy-status", "proxy-config", "verify-install", "x", "help"}),
    "velero": frozenset({"get", "describe", "version", "help"}),
    "kubeadm": frozenset({"version", "help", "config"}),
    "kapp": frozenset({"inspect", "list", "ls", "version", "help", "logs"}),
    "kpt": frozenset({"fn", "pkg", "help", "version"}),
    "crossplane": frozenset({"version", "help", "beta"}),
    "eksctl": frozenset({"get", "version", "info", "help", "utils"}),
    "ansible-playbook": frozenset({"--check", "--syntax-check", "--list-tasks", "--list-hosts"}),
    "kustomize-controller": frozenset(),
    # Tools that create, change or delete whole clusters. Reading subcommands pass (and `list`/`get` one level down,
    # `k3d cluster list`); the rest is not determined, by name.
    "kind": frozenset({"get", "version", "help", "export", "completion", "build"}),
    "minikube": frozenset(
        {
            "status",
            "profile",
            "ip",
            "version",
            "logs",
            "dashboard",
            "docker-env",
            "podman-env",
            "update-context",
            "service",
            "help",
            "completion",
            "config",
        }
    ),
    "k3d": frozenset({"version", "help", "completion"}),
    "kops": frozenset({"get", "version", "export", "validate", "toolbox", "help", "completion"}),
    "clusterctl": frozenset({"describe", "version", "generate", "get", "help", "completion", "config"}),
    "talosctl": frozenset(
        {
            "get",
            "list",
            "ls",
            "logs",
            "version",
            "dmesg",
            "read",
            "health",
            "dashboard",
            "config",
            "kubeconfig",
            "help",
            "completion",
            "containers",
            "stats",
            "processes",
            "services",
            "time",
            "events",
            "memory",
            "mounts",
        }
    ),
    "openshift-install": frozenset({"version", "explain", "wait-for", "gather", "help", "completion"}),
    "crc": frozenset({"status", "version", "console", "ip", "oc-env", "podman-env", "config", "help", "completion"}),
    "microk8s": frozenset({"status", "inspect", "version", "config", "help"}),
    "k0s": frozenset({"version", "status", "kubeconfig", "help", "completion"}),
}
#: Words that open or close a shell construct rather than name a program.
KEYWORDS = frozenset(
    {"if", "then", "else", "elif", "fi", "do", "done", "while", "until", "!", "{", "}", "esac", "coproc"}
)
#: Words after which the rest of the simple command is not a command (``for x in a b``, ``case $x in``).
NON_COMMANDS = frozenset({"for", "case", "select", "function"})
_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\[[^\]]*\])?\+?=")
_HEREDOC = re.compile(r"^(-?)\s*(['\"]?)([A-Za-z0-9_.-]+)\2")
#: Where an output redirection writes nothing a later command could read as a manifest.
_NULL_TARGETS = frozenset({"/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty"})
# Lexer patterns, matched at a position (never on a slice, which copied the rest of the line for every token) and
# each free of overlapping quantifiers, so a crafted line costs time linear in its length.
_REDIR_OP = re.compile(r"\d*(<<<|<<-|<<|<>|>>|>&|<&|>\||<|>)")
_DUP_FD = re.compile(r"\d+(?![\w./])|-")
_BRACE_LIST = re.compile(r"\{[^}\s,]*,[^}\s]*\}")  # the first part stops at the first comma: no backtracking
_HEX2 = re.compile(r"[0-9A-Fa-f]{1,2}")
_OCT3 = re.compile(r"[0-7]{1,3}")
_HEX8 = re.compile(r"[0-9A-Fa-f]{1,8}")
_PARAM = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*|[0-9@*#?$!-])")
_WORD_END = re.compile(r"[\s|;&()<>]")
_ANSI_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "a": "\a", "b": "\b", "f": "\f", "v": "\v", "e": "\x1b", "E": "\x1b"}


@dataclass(frozen=True)
class Word:
    text: str  # after quote removal
    dynamic: bool  # holds an expansion (`$X`, `$(...)`, backticks) whose value is only known at run time
    raw: str  # as written, for messages
    glob: bool = False  # an unquoted `*`, `?` or `[...]` the shell would expand against the file system


@dataclass
class Command:
    """One simple command, after the wrappers that only run it (``env``, ``sudo``, ``sh -c``...) are removed."""

    words: list[Word]
    stdin: str | None = None  # a here-document, here-string or `< file` content the command reads
    stdin_kind: str = ""  # "heredoc", "herestring", "file", "pipe" or ""
    stdin_dynamic: bool = False  # the here-document or here-string expands variables
    via: list[str] = field(default_factory=list)  # the wrappers seen through, outermost first
    assignments: list[str] = field(default_factory=list)  # VAR names assigned in front of it
    values: dict[str, Word] = field(default_factory=dict)  # the words assigned in front of it, by name
    args_from_stdin: bool = False  # under xargs: more arguments arrive at run time
    source: Command | None = None  # the command whose output is piped into this one
    writes: list[Word] = field(default_factory=list)  # files its output redirections write
    cwd: str | None = ""  # its directory relative to the start ("" is the start, "/x" absolute); None: unknown

    @property
    def argv(self) -> list[str]:
        return [w.text for w in self.words]

    @property
    def tool(self) -> str:
        return program(self.words[0].text) if self.words else ""


@dataclass
class Line:
    commands: list[Command] = field(default_factory=list)
    opaque: list[str] = field(default_factory=list)  # why some part of the line could not be read
    assignments: list[str] = field(default_factory=list)  # every variable the line assigns or exports
    values: dict[str, Word] = field(default_factory=dict)  # the last literal value each of them got
    cwd: str | None = ""  # the directory the next command runs in


def program(word: str) -> str:
    """``/usr/local/bin/kubectl``, ``kubectl.exe``, ``Kubectl`` (a case-insensitive file system) and ``kubectl1.30``
    are kubectl."""
    base = word.rsplit("/", 1)[-1]
    if base.lower().endswith(".exe"):
        base = base[:-4]
    low = base.lower()
    if low in KUBE_TOOLS:
        return low
    if low in {"microk8s.kubectl", "microk8s.helm", "microk8s.helm3"}:
        return "kubectl" if low.endswith("kubectl") else "helm"
    m = _KUBE_NAME.fullmatch(base)
    return m.group(1).lower() if m else base


# -- lexing ------------------------------------------------------------------------------------------------------


@dataclass
class _Tok:
    kind: str  # "word", "op", "redir"
    value: str
    word: Word | None = None


def substitutions(text: str) -> list[str]:
    """The command substitutions ``$( ... )`` and backticks inside ``text`` (a ``${...}`` body, an arithmetic
    expression, an unquoted here-document), outermost first; ``$(( ... ))`` and ``${ ... }`` are searched inside."""
    out: list[str] = []
    i = 0
    while i < len(text) and len(out) < MAX_COMMANDS:
        if text.startswith("$((", i):
            end = _close(text, i + 1)
            if end < 0:
                break
            out.extend(substitutions(text[i + 3 : end - 1]))
            i = end + 1
        elif text.startswith("$(", i):
            end = _close(text, i + 1)
            if end < 0:
                break
            out.append(text[i + 2 : end])
            i = end + 1
        elif text.startswith("${", i):
            end = _brace_end(text, i + 1)
            if end < 0:
                break
            out.extend(substitutions(text[i + 2 : end]))
            i = end + 1
        elif text[i] == "`":
            end = i + 1
            while end < len(text) and text[end] != "`":
                end += 2 if text[end] == "\\" else 1
            out.append(text[i + 1 : end])
            i = end + 1
        elif text[i] == "\\":
            i += 2
        else:
            i += 1
    return out


def _close(s: str, i: int) -> int:
    """Index of the `)` matching the `(` at s[i], quote-aware; -1 when there is none."""
    depth = 0
    quote = ""
    while i < len(s):
        ch = s[i]
        if quote:
            if ch == "\\" and quote == '"':
                i += 2
                continue
            if ch == quote:
                quote = ""
        elif ch in "'\"":
            quote = ch
        elif ch == "\\":
            i += 2
            continue
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def _brace_end(s: str, i: int) -> int:
    """Index of the `}` matching the `{` at s[i], skipping nested `${`, `$(` and quotes; -1 when there is none."""
    depth = 0
    quote = ""
    while i < len(s):
        ch = s[i]
        if quote:
            if ch == "\\" and quote == '"':
                i += 2
                continue
            if ch == quote:
                quote = ""
        elif ch in "'\"":
            quote = ch
        elif ch == "\\":
            i += 2
            continue
        elif s.startswith("$(", i):
            end = _close(s, i + 1)
            if end < 0:
                return -1
            i = end + 1
            continue
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


class _Lexer:
    """POSIX-ish tokens: words with quotes removed, control operators, redirections, here-document bodies."""

    def __init__(self, text: str, line: Line, depth: int, sub: Callable[[str, int], None]) -> None:
        self.s = text
        self.i = 0
        self.line = line
        self.depth = depth
        self.sub = sub  # parse a command substitution's text as commands of this line
        self.pending: list[tuple[str, bool, _Tok]] = []  # here-documents waiting for the end of the line

    def error(self, why: str) -> None:
        if why not in self.line.opaque:
            self.line.opaque.append(why)

    def tokens(self) -> list[_Tok]:
        out: list[_Tok] = []
        s = self.s
        while self.i < len(s):
            ch = s[self.i]
            if ch == "\\" and s[self.i : self.i + 2] == "\\\n":
                self.i += 2  # line continuation
                continue
            if ch in " \t\r":
                self.i += 1
                continue
            if ch == "#" and (not out or out[-1].kind != "word" or s[self.i - 1] in " \t\n;|&("):
                while self.i < len(s) and s[self.i] != "\n":
                    self.i += 1
                continue
            if ch == "\n":
                self.i += 1
                out.append(_Tok("op", "\n"))
                self._heredocs()
                continue
            if s.startswith(("&&", "||", ";;"), self.i):
                out.append(_Tok("op", s[self.i : self.i + 2]))
                self.i += 2
                continue
            if ch in "|;&()":
                if ch == "&" and s.startswith("&>", self.i):
                    self.i += 2 + (s[self.i + 2 : self.i + 3] == ">")
                    self._redirect_target(out, ">")
                    continue
                if ch == "|" and s.startswith("|&", self.i):
                    out.append(_Tok("op", "|"))
                    self.i += 2
                    continue
                out.append(_Tok("op", ch))
                self.i += 1
                continue
            m = _REDIR_OP.match(s, self.i)
            if (
                m
                and (ch in "<>" or m.group(0)[: -len(m.group(1))].isdigit())
                and not s.startswith(("<(", ">("), self.i)
            ):
                op = m.group(1)
                self.i += len(m.group(0))
                if op in {"<<", "<<-"}:
                    self._heredoc_marker(out, op == "<<-")
                else:
                    self._redirect_target(out, op)
                continue
            w = self._word()
            if w is None:
                return out
            out.append(_Tok("word", w.text, w))
            if len(out) > MAX_WORDS:
                self.error(f"more than {MAX_WORDS} words")
                return out
        if self.pending:
            self._heredocs()
        return out

    def _redirect_target(self, out: list[_Tok], op: str) -> None:
        while self.i < len(self.s) and self.s[self.i] in " \t":
            self.i += 1
        fd = _DUP_FD.match(self.s, self.i) if op in {">&", "<&"} else None
        if fd is not None:
            self.i += len(fd.group(0))
            return
        target = self._word()
        if target is None:
            self.error("a redirection with no target")
            return
        out.append(_Tok("redir", ">" if op in {">&", ">|", ">>", "<>"} else op, target))

    def _heredoc_marker(self, out: list[_Tok], strip: bool) -> None:
        while self.i < len(self.s) and self.s[self.i] in " \t":
            self.i += 1
        m = _HEREDOC.match(self.s[self.i :])
        if not m:
            self.error("a here-document whose delimiter could not be read")
            return
        self.i += len(m.group(0))
        # A quoted delimiter keeps the body literal; an unquoted one expands $, backticks and $( ) in it.
        tok = _Tok("redir", "<<", Word("", not m.group(2), m.group(0)))
        out.append(tok)
        self.pending.append((m.group(3), strip, tok))

    def _heredocs(self) -> None:
        for delim, strip, tok in self.pending:
            body: list[str] = []
            found = False
            while self.i < len(self.s):
                end = self.s.find("\n", self.i)
                end = len(self.s) if end < 0 else end
                raw = self.s[self.i : end]
                self.i = end + 1
                check = raw.lstrip("\t") if strip else raw
                if check == delim:
                    found = True
                    break
                body.append(check)
            if not found:
                self.error(f"a here-document that never reaches its delimiter {delim!r}")
            expands = tok.word is not None and tok.word.dynamic
            text = "\n".join(body) + ("\n" if body else "")
            live = expands and bool(re.search(r"\$|`", text))
            if live:
                for inner in substitutions(text):
                    self.sub(inner, self.depth + 1)  # an unquoted here-document runs its substitutions
            tok.word = Word(text, live, tok.word.raw if tok.word else "")
        self.pending = []

    def _word(self) -> Word | None:
        s = self.s
        buf: list[str] = []
        raw_start = self.i
        dynamic = False
        glob = False
        while self.i < len(s):
            ch = s[self.i]
            if ch in " \t\r\n|;&()" or (ch in "<>" and not s.startswith(("<(", ">("), self.i)):
                break
            if ch == "\\":
                nxt = s[self.i + 1 : self.i + 2]
                if nxt == "\n":
                    self.i += 2
                    continue
                buf.append(nxt)
                self.i += 2
                continue
            if ch == "'":
                end = s.find("'", self.i + 1)
                if end < 0:
                    self.error("an unterminated single quote")
                    self.i = len(s)
                    return None
                buf.append(s[self.i + 1 : end])
                self.i = end + 1
                continue
            if ch == "$" and s[self.i + 1 : self.i + 2] == "'":
                decoded = self._ansi_c()
                if decoded is None:
                    return None
                buf.append(decoded)
                continue
            if ch == "$" and s[self.i + 1 : self.i + 2] == '"':
                self.i += 1  # $"..." is a double-quoted string (translated, in bash)
                continue
            if ch == '"':
                self.i += 1
                while self.i < len(s) and s[self.i] != '"':
                    c = s[self.i]
                    if c == "\\" and s[self.i + 1 : self.i + 2] in {'"', "\\", "$", "`", "\n"}:
                        if s[self.i + 1] != "\n":
                            buf.append(s[self.i + 1])
                        self.i += 2
                        continue
                    if c in "$`":
                        dynamic |= self._expansion(buf)
                        continue
                    buf.append(c)
                    self.i += 1
                if self.i >= len(s):
                    self.error("an unterminated double quote")
                    return None
                self.i += 1
                continue
            if ch in "$`":
                dynamic |= self._expansion(buf)
                continue
            if s.startswith(("<(", ">("), self.i):
                self.i += 1
                inner = self._balanced()
                if inner is None:
                    return None
                self.sub(inner, self.depth + 1)
                buf.append("/dev/fd/63")
                dynamic = True
                continue
            if ch in "*?" or (ch == "[" and "]" in s[self.i + 1 : self._word_end()]):
                glob = True  # a glob: the words are the matching file names, known only on that file system
            if ch == "{" and _BRACE_LIST.match(s, self.i):
                dynamic = True  # a brace expansion makes several words
            if ch == "~" and not buf:
                dynamic = True
            buf.append(ch)
            self.i += 1
        if self.i == raw_start:
            return None if self.i >= len(s) else Word("", False, "")
        text = "".join(buf)
        if text in {"[", "[[", "]", "]]"}:
            glob = False  # the test builtin and its closing bracket
        return Word(text, dynamic, s[raw_start : self.i], glob)

    def _word_end(self) -> int:
        m = _WORD_END.search(self.s, self.i)
        return m.start() if m else len(self.s)

    def _ansi_c(self) -> str | None:
        """Decode bash's $'...' at self.i (which is `$`)."""
        s = self.s
        i = self.i + 2
        out: list[str] = []
        while i < len(s) and s[i] != "'":
            c = s[i]
            if c == "\\" and i + 1 < len(s):
                n = s[i + 1]
                if n in _ANSI_ESCAPES:
                    out.append(_ANSI_ESCAPES[n])
                    i += 2
                elif n == "x":
                    m = _HEX2.match(s, i + 2)
                    out.append(chr(int(m.group(0), 16)) if m else "x")
                    i += 2 + (len(m.group(0)) if m else 0)
                elif n in "01234567":
                    m = _OCT3.match(s, i + 1)
                    digits = m.group(0) if m else "0"
                    out.append(chr(int(digits, 8)))
                    i += 1 + len(digits)
                elif n in {"u", "U"}:
                    m = _HEX8.match(s, i + 2)
                    out.append(chr(min(int(m.group(0), 16), 0x10FFFF)) if m else n)
                    i += 2 + (len(m.group(0)) if m else 0)
                else:
                    out.append(n)
                    i += 2
                continue
            out.append(c)
            i += 1
        if i >= len(s):
            self.error("an unterminated $'...' string")
            self.i = len(s)
            return None
        self.i = i + 1
        return "".join(out)

    def _expansion(self, buf: list[str]) -> bool:
        """Consume `$...` or a backtick expansion at self.i; returns whether the value is only known at run time."""
        s = self.s
        if s[self.i] == "`":
            end = self.i + 1
            while end < len(s) and s[end] != "`":
                end += 2 if s[end] == "\\" else 1
            if end >= len(s):
                self.error("an unterminated backtick command substitution")
                self.i = len(s)
                return True
            self.sub(s[self.i + 1 : end], self.depth + 1)
            buf.append("${...}")
            self.i = end + 1
            return True
        nxt = s[self.i + 1 : self.i + 2]
        if nxt == "(":
            self.i += 1
            inner = self._balanced()
            if inner is not None:
                if inner.startswith("(") and inner.endswith(")"):
                    for cmd in substitutions(inner[1:-1]):  # $(( arithmetic )) runs only what is inside it
                        self.sub(cmd, self.depth + 1)
                else:
                    self.sub(inner, self.depth + 1)
            buf.append("${...}")
            return True
        if nxt == "{":
            end = _brace_end(s, self.i + 1)
            if end < 0:
                self.error("an unterminated ${...} expansion")
                self.i = len(s)
                return True
            for cmd in substitutions(s[self.i + 2 : end]):  # ${x:-$(...)} runs the substitution
                self.sub(cmd, self.depth + 1)
            buf.append(s[self.i : end + 1])
            self.i = end + 1
            return True
        m = _PARAM.match(s, self.i)
        if m:
            buf.append(m.group(0))
            self.i += len(m.group(0))
            return True
        buf.append("$")
        self.i += 1
        return False

    def _balanced(self) -> str | None:
        """The text inside the parenthesis at self.i (which is `(`), quote-aware; self.i ends after the `)`."""
        end = _close(self.s, self.i)
        if end < 0:
            self.error("an unterminated $( or <( substitution")
            self.i = len(self.s)
            return None
        inner = self.s[self.i + 1 : end]
        self.i = end + 1
        return inner


# -- parsing -----------------------------------------------------------------------------------------------------


#: ``read_script(path, cwd)``: the text of a script the line runs, "" for a file that is not text, None when it
#: is not read. ``cwd`` is the command's directory as `Command.cwd` gives it.
ScriptReader = Callable[[str, str | None], str | None]


def parse(text: str, read_script: ScriptReader | None = None) -> Line:
    """Every simple command ``text`` would start, with wrappers removed, and what could not be read."""
    line = Line()
    if len(text) > MAX_CHARS:
        line.opaque.append(f"the command is longer than {MAX_CHARS:,} characters")
        return line
    _parse_into(text, line, 0, read_script)
    return line


def _parse_into(text: str, line: Line, depth: int, read_script: ScriptReader | None, isolate: bool = False) -> None:
    """``isolate``: a child shell (``sh -c``, ``$( )``, a script run as a program): its `cd` does not outlive it."""
    if depth > MAX_DEPTH:
        line.opaque.append(f"commands nested more than {MAX_DEPTH} levels deep (sh -c, eval, scripts)")
        return
    saved = line.cwd

    def sub(inner: str, d: int) -> None:
        _parse_into(inner, line, d, read_script, isolate=True)

    toks = _Lexer(text, line, depth, sub).tokens()
    # Split into pipelines of simple commands. A pipe gives the next command its stdin.
    piped = False
    producer: Command | None = None
    current: list[_Tok] = []
    stack: list[str | None] = []
    seq = [*toks, _Tok("op", ";")]
    for n, tok in enumerate(seq):
        if tok.kind == "op":
            if (
                tok.value == "("
                and len(current) == 1
                and current[0].kind == "word"
                and n + 1 < len(seq)
                and seq[n + 1].kind == "op"
                and seq[n + 1].value == ")"
            ):
                current = []  # `NAME()`: a function definition, not a run of NAME; its body is read as it comes
                seq[n + 1] = _Tok("op", ";")
                continue
            if current:
                before = len(line.commands)
                _simple(current, line, depth, read_script, piped, producer if piped else None)
                made = line.commands[before:]
                if piped and made:
                    made[0].source = producer
                producer = made[-1] if made else None
            elif tok.value != "|":
                producer = None
            if tok.value == "(":
                stack.append(line.cwd)
            elif tok.value == ")":
                line.cwd = stack.pop() if stack else None
            piped = tok.value == "|"
            current = []
            continue
        current.append(tok)
        if len(line.commands) > MAX_COMMANDS:
            line.opaque.append(f"more than {MAX_COMMANDS} commands")
            return
    if isolate:
        line.cwd = saved


def _simple(
    toks: list[_Tok],
    line: Line,
    depth: int,
    read_script: ScriptReader | None,
    piped: bool,
    producer: Command | None = None,
) -> None:
    words = [t.word for t in toks if t.kind == "word" and t.word is not None]
    cmd = Command(words=list(words), stdin_kind="pipe" if piped else "", cwd=line.cwd, source=producer)
    for t in toks:
        if t.kind != "redir" or t.word is None:
            continue
        if t.value == "<<":
            cmd.stdin, cmd.stdin_kind, cmd.stdin_dynamic = t.word.text, "heredoc", t.word.dynamic
        elif t.value == "<<<":
            cmd.stdin, cmd.stdin_kind, cmd.stdin_dynamic = t.word.text + "\n", "herestring", t.word.dynamic
        elif t.value == "<":
            cmd.stdin, cmd.stdin_kind, cmd.stdin_dynamic = t.word.text, "file", t.word.dynamic
        elif t.value == ">" and t.word.text not in _NULL_TARGETS:
            cmd.writes.append(t.word)
    _unwrap(cmd, line, depth, read_script)


def _drop(cmd: Command, n: int, via: str) -> None:
    del cmd.words[:n]
    cmd.via.append(via)


def _assign(cmd: Command, line: Line, w: Word) -> None:
    name = w.text.split("=", 1)[0].split("[", 1)[0].rstrip("+")
    cmd.assignments.append(name)
    line.assignments.append(name)
    value = Word(w.text.split("=", 1)[1] if "=" in w.text else "", w.dynamic, w.raw)
    cmd.values[name] = value
    line.values[name] = value


def _assignments(cmd: Command, line: Line) -> None:
    while cmd.words and _ASSIGN.match(cmd.words[0].text) and not cmd.words[0].raw.startswith(("'", '"')):
        _assign(cmd, line, cmd.words[0])
        del cmd.words[0]


def _skip_options(cmd: Command, start: int, with_value: frozenset[str]) -> int:
    """Index of the first word after the options of the wrapper at cmd.words[start - 1].

    ``with_value`` names the options that take a value, short (`-u`) and long (`--user`). A long option takes its
    value after `=` or as the next word; a cluster of short options (`-nu admin`, `-Eu admin`, `-uadmin`) takes the
    next word when its last option needs a value and nothing follows it in the cluster."""
    i = start
    while i < len(cmd.words):
        t = cmd.words[i].text
        if t == "--":
            return i + 1
        if not t.startswith("-") or t == "-":
            return i
        if t.startswith("--"):
            i += 2 if (t in with_value) else 1
            continue
        takes_next = False
        for j in range(1, len(t)):
            if "-" + t[j] in with_value:
                takes_next = j == len(t) - 1  # `-uadmin` carries its value; `-nu` takes the next word
                break
        i += 2 if takes_next else 1
    return i


# Wrappers that run the rest of their arguments as a command, with the options that take a value (sudo(8),
# doas(1), time(1), nice(1), ionice(1), stdbuf(1), caffeinate(8)).
_WRAPPERS: dict[str, frozenset[str]] = {
    "sudo": frozenset(
        {
            "-u",
            "-g",
            "-C",
            "-h",
            "-p",
            "-U",
            "-r",
            "-t",
            "-D",
            "-R",
            "-T",
            "--user",
            "--group",
            "--close-from",
            "--host",
            "--prompt",
            "--other-user",
            "--role",
            "--type",
            "--chdir",
            "--chroot",
            "--command-timeout",
        }
    ),
    "doas": frozenset({"-u", "-C"}),
    "command": frozenset(),
    "builtin": frozenset(),
    "exec": frozenset({"-a"}),
    "nohup": frozenset(),
    "time": frozenset({"-f", "-o", "--format", "--output"}),
    "nice": frozenset({"-n", "--adjustment"}),
    "ionice": frozenset({"-c", "-n", "-p", "--class", "--classdata", "--pid"}),
    "setsid": frozenset(),
    "stdbuf": frozenset({"-i", "-o", "-e", "--input", "--output", "--error"}),
    "unbuffer": frozenset(),
    "chronic": frozenset(),
    "caffeinate": frozenset({"-t", "-w"}),
}


def _cd(cmd: Command, line: Line, tool: str) -> None:
    """Follow `cd`/`pushd` with a literal directory; anything else leaves the directory unknown."""
    args = [w for w in cmd.words[1:] if not (w.text.startswith("-") and w.text != "-")]
    if tool == "popd" or len(args) != 1 or args[0].dynamic or args[0].glob or args[0].text in {"-", ""}:
        line.cwd = None  # `cd` alone is $HOME, `cd -` the last one, `popd` a stack this reader does not keep
        return
    target = args[0].text
    if target.startswith("/"):
        line.cwd = posixpath.normpath(target)
    elif line.cwd is not None:
        joined = posixpath.normpath(posixpath.join(line.cwd or ".", target))
        line.cwd = "" if joined == "." else joined


def _unwrap(cmd: Command, line: Line, depth: int, read_script: ScriptReader | None) -> None:
    for _ in range(32):
        _assignments(cmd, line)
        while cmd.words and cmd.words[0].text in KEYWORDS and not cmd.words[0].dynamic:
            del cmd.words[0]
        _assignments(cmd, line)
        if cmd.words and any(
            _kube_tail(_SPLIT_COMMAND_TEXT.split(v.text)) for v in cmd.values.values() if not v.dynamic
        ):
            name = next(k for k, v in cmd.values.items() if _kube_tail(_SPLIT_COMMAND_TEXT.split(v.text)))
            line.opaque.append(f"{_show(name)} is set to a kube command for the program that follows")
            return
        if cmd.words and cmd.words[0].text == "--" and not cmd.words[0].dynamic:
            del cmd.words[0]  # `timeout 30 -- kubectl ...`: the end of a wrapper's options
            continue
        if not cmd.words:
            return
        first = cmd.words[0]
        if first.text == "function" and not first.dynamic:
            # `function f { BODY; }`: the body's commands are read like `f() { BODY; }` (a call can run them).
            del cmd.words[:2]
            continue
        if first.text in NON_COMMANDS and not first.dynamic:
            return  # `for x in a b`: the words are a loop's list, not a command
        if first.text in {"export", "declare", "typeset", "local", "readonly"}:
            for w in cmd.words[1:]:
                if _ASSIGN.match(w.text):
                    _assign(cmd, line, w)
                elif re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", w.text):
                    line.assignments.append(w.text)
            _mention_check(cmd, line, "export")
            return
        if first.dynamic or first.glob:
            line.opaque.append(f"the command word {_show(first.raw)} is only known when the line runs")
            return
        if any(c.isspace() for c in first.text) and (MENTION.search(first.text) or _kube_tail(first.text.split())):
            # `'kubectl delete ns prod'`: one quoted word; the shell looks for a program of that whole name.
            line.opaque.append(f"the command word {_show(first.raw)} is a quoted kube command")
            return
        tool = program(first.text)
        if tool in _WRAPPERS:
            if tool == "command" and len(cmd.words) > 1 and cmd.words[1].text in {"-v", "-V"}:
                return  # `command -v kubectl` asks where it is
            end = _skip_options(cmd, 1, _WRAPPERS[tool])
            if tool in {"sudo", "doas"} and _runs_a_shell(cmd.words[1:end]):
                # `sudo -s CMD`, `sudo -i CMD`, `--shell`, `--login`, `doas -s`: the rest is run by a shell, as with
                # `sh -c`, so a quoted `'kubectl delete ns prod'` is a command line, not a program name.
                rest = cmd.words[end:]
                if any(w.dynamic for w in rest):
                    line.opaque.append(f"{tool} runs a shell on a value only known when the line runs")
                    return
                if rest:
                    _nested(" ".join(w.text for w in rest), cmd, line, depth, read_script, f"{tool} shell")
                return
            _drop(cmd, end, tool)
            continue
        if tool == "corepack" and len(cmd.words) > 1 and not cmd.words[1].text.startswith("-"):
            _drop(cmd, 1, "corepack")  # `corepack pnpm run x` runs pnpm
            continue
        if tool == "env":
            i = 1
            while i < len(cmd.words):
                t = cmd.words[i].text
                if t in {"-u", "--unset", "-C", "--chdir"}:
                    i += 2
                elif t in {"-S", "--split-string"} or t.startswith("--split-string="):
                    nxt_word = cmd.words[i + 1].text if i + 1 < len(cmd.words) else ""
                    split = t.split("=", 1)[1] if "=" in t else nxt_word
                    tail = cmd.words[i + 2 if "=" not in t else i + 1 :]
                    _nested(split + " " + " ".join(w.text for w in tail), cmd, line, depth, read_script, "env -S")
                    return
                elif t.startswith("-") and t != "-":
                    i += 1
                elif _ASSIGN.match(t):
                    _assign(cmd, line, cmd.words[i])
                    i += 1
                else:
                    break
            _drop(cmd, i, "env")
            continue
        if tool == "timeout":
            i = _skip_options(cmd, 1, frozenset({"-s", "--signal", "-k", "--kill-after"}))
            if i < len(cmd.words) and cmd.words[i].text == "--":
                i += 1
            _drop(cmd, i + 1, "timeout")  # and the duration (`timeout 30 -- cmd` loses its `--` next round)
            continue
        if tool == "watch":
            i = _skip_options(cmd, 1, frozenset({"-n", "--interval", "-d", "-q"}))
            _nested(" ".join(w.raw for w in cmd.words[i:]), cmd, line, depth, read_script, "watch", isolate=True)
            return
        if tool == "xargs":
            if not _xargs(cmd, line, read_script):
                return
            continue
        if tool in SHELLS:
            _shell(cmd, line, depth, read_script)
            return
        if tool == "eval":
            if any(w.dynamic for w in cmd.words[1:]):
                line.opaque.append("eval of a value only known when the line runs")
                return
            _nested(" ".join(w.text for w in cmd.words[1:]), cmd, line, depth, read_script, "eval")
            return
        if tool in {"source", "."}:
            _source(cmd, line, depth, read_script, tool)
            return
        if tool == "alias":
            for w in cmd.words[1:]:
                if MENTION.search(w.text) or re.search(r"=\s*['\"]?k\b", w.text):
                    line.opaque.append(f"defines an alias for a kube tool ({_show(w.text)})")
            return
        if tool == "find":
            _find(cmd, line, depth, read_script)
            return
        if tool in {"fc", "r"} and not (tool == "fc" and any(w.text in {"-l"} for w in cmd.words[1:2])):
            # `fc -s PREFIX` (and zsh's `r`) runs an earlier command from the shell's history: one verify cannot see.
            line.opaque.append(f"{_show(tool)} re-runs a command from the shell's history, which verify cannot see")
            return
        if tool in {"cd", "pushd", "popd"}:
            line.commands.append(cmd)
            _cd(cmd, line, tool)
            return
        if tool in KUBE_TOOLS:
            line.commands.append(cmd)
            return
        if tool == "trap":
            # `trap 'COMMAND' EXIT` runs COMMAND later in this shell: read it like eval.
            if len(cmd.words) > 1 and not cmd.words[1].text.startswith("-"):
                if cmd.words[1].dynamic:
                    line.opaque.append("trap runs a value only known when the line runs")
                else:
                    _nested(cmd.words[1].text, cmd, line, depth, read_script, "trap")
            line.commands.append(cmd)
            return
        if tool in {"microk8s", "k3s"} and len(cmd.words) > 1 and program(cmd.words[1].text) in KUBE_TOOLS:
            _drop(cmd, 1, tool)  # `microk8s kubectl ...`, `k3s kubectl ...` run the bundled kubectl
            continue
        if tool == "minikube" and len(cmd.words) > 1 and cmd.words[1].text == "kubectl":
            passed = cmd.words[2:]
            if passed and passed[0].text == "--":
                passed = passed[1:]
            cmd.words = [Word("kubectl", False, "kubectl"), *passed]
            cmd.via.append("minikube kubectl")
            continue
        if tool == "make":
            _make(cmd, line, depth, read_script)
            line.commands.append(cmd)
            return
        if tool in {"npm", "yarn", "pnpm", "bun"}:
            _npm(cmd, line, depth, read_script, tool)
            line.commands.append(cmd)
            return
        if tool == "git":
            if any(w.text == "-c" or w.text.startswith(("-c", "--config-env")) for w in cmd.words[1:3]):
                _mention_check(cmd, line, "git -c")  # an alias or a pager in -c runs a command
            _git(cmd, line)
            line.commands.append(cmd)
            return
        if tool == "docker" and len(cmd.words) > 1 and cmd.words[1].text == "compose":
            _runner(Command(words=cmd.words[1:], cwd=cmd.cwd), line, depth, read_script, "docker-compose")
            _opaque_check(cmd, line, tool, read_script, executor=True)
            line.commands.append(cmd)
            return
        if tool in RUNNERS:
            before = len(line.opaque)
            _runner(cmd, line, depth, read_script, tool)
            if len(line.opaque) == before:
                _opaque_check(cmd, line, tool, read_script, executor=False)
            line.commands.append(cmd)
            return
        if tool == "parallel":
            _parallel(cmd, line, read_script)
            line.commands.append(cmd)
            return
        if tool in DATA_ONLY:
            line.commands.append(cmd)
            return
        if tool in INTERPRETERS:
            _interpreter(cmd, line, tool, read_script)
            _opaque_check(cmd, line, tool, read_script, executor=False)
            line.commands.append(cmd)
            return
        if tool in EXECUTORS:
            _opaque_check(cmd, line, tool, read_script, executor=True)
            line.commands.append(cmd)
            return
        if "/" in first.text:
            # A path to a program: read it as a script when it is a text file in the working tree. An absolute
            # path the reader will not open (/usr/bin/python3) is an ordinary program; a relative one it cannot
            # open is a script nobody can see into.
            text = read_script(first.text, cmd.cwd) if read_script is not None else None
            if text is not None:
                if _names_kube(text):
                    _nested(text, cmd, line, depth, read_script, f"script {first.text}", isolate=True)
            elif not first.text.startswith("/"):
                _script(cmd.words[0:1], cmd, line, depth, read_script, "script")
                return
        # Any other program is opaque, not transparent: whatever it is called, a kube command in its arguments or
        # on its standard input is one it may run (`aws-vault exec prod -- kubectl ...`, `echo '...' | at now`).
        _opaque_check(cmd, line, tool, read_script, executor=False)
        line.commands.append(cmd)
        return
    line.opaque.append("more than 32 wrappers around one command")


#: A Makefile line longer than this is not parsed: the Makefile is unknown and a `make` that reads it is not
#: determined. (A reviewer's line of 250,000 spaces took a backtracking rule pattern 62 seconds.)
MAX_MAKE_LINE = 4_096
MAX_MAKE_INCLUDES = 16
_MAKE_SELF = re.compile(r"\$[({]MAKE[)}]")
#: A make variable reference without nesting (`$(VAR)`, `${VAR}`, `$(dir $@)`); a nested one stays and is opaque.
_MAKE_VAR = re.compile(r"\$[({][^(){}$]{0,200}[)}]|\$[@<^?*%+|]")
#: A make variable (or any reference) where a recipe names the program it runs.
_MAKE_VAR_AS_COMMAND = re.compile(r"(?:^|[;&|(]\s{0,20}|\b(?:then|do|else)\s{1,20})[@+-]{0,3}\$[({]")
#: Targets read before make is not determined (2,000 recipes read in under a second).
MAX_MAKE_TARGETS = 5_000
#: make's options that take a value as the next word (GNU make 4.4, `make --help`); -j and -l take one only when it
#: is a number.
_MAKE_VALUE_OPTIONS = frozenset(
    {"-f", "--file", "--makefile", "-C", "--directory", "-I", "--include-dir", "-o", "--old-file",
     "--assume-old", "-W", "--what-if", "--new-file", "--assume-new", "-E", "--eval", "-O", "--output-sync",
     "--jobserver-style", "--debug", "--shuffle"}
)  # fmt: skip


def _make_rule(raw: str) -> tuple[list[str], str] | None:
    """`targets: prerequisites` (or `::`), without a pattern: the targets and what follows the colon, or None when
    the line is not a rule (a variable assignment `X := y`, a recipe, a comment). Linear in the line's length."""
    if not raw or raw[0] in " \t#":
        return None
    idx = raw.find(":")
    if idx <= 0:
        return None
    head = raw[:idx]
    if "=" in head or "#" in head:
        return None
    after = raw[idx + 1 :]
    if after.startswith(":"):
        after = after[1:]
    if after.startswith("="):
        return None  # `X := y`, `X ::= y`
    return head.split(), after


def _make_logical_lines(text: str) -> list[str] | None:
    """The Makefile's lines with backslash-newline continuations joined, or None when a line is too long to read."""
    out: list[str] = []
    pending = ""
    for physical in text.splitlines()[:20_000]:
        if len(physical) > MAX_MAKE_LINE or len(pending) > MAX_MAKE_LINE * 4:
            return None
        joined = pending + " " + physical.lstrip("\t ") if pending else physical
        pending = ""
        if joined.endswith("\\") and not joined.endswith("\\\\"):
            pending = joined[:-1]
            continue
        out.append(joined)
    if pending:
        out.append(pending)
    return out


def _make_dir(cwd: str | None, directory: str) -> str | None:
    """`make -C DIR` relative to the command's directory, or None when it leaves what verify can follow."""
    if cwd is None:
        return None
    if directory.startswith("/"):
        return posixpath.normpath(directory)
    joined = posixpath.normpath(posixpath.join(cwd or ".", directory))
    return "" if joined == "." else joined


def _make(cmd: Command, line: Line, depth: int, read_script: ScriptReader | None) -> None:
    """`make TARGET`: the recipe lines of the targets asked for (and the targets they depend on) are shell lines,
    read like `sh -c`, in the directory make runs in.

    The Makefile is the one make reads: `-f FILE`, `-fFILE`, `--file=FILE`, `--makefile FILE` (several are read in
    order), `-f -` and `-f /dev/stdin` from standard input, else GNUmakefile, makefile or Makefile, in the directory
    `-C DIR`/`--directory=DIR` names. `include`, `-include` and `sinclude` are followed inside the tree; a
    `$(shell ...)` or `!=` outside a recipe runs whenever the Makefile is read, so it is checked too. Inline recipes
    (`target: ; command`) and backslash-continued lines are read. A recipe built from make variables in a Makefile
    that names a kube tool (or given a kube tool in a command-line variable) is opaque, as is `--eval`, a Makefile
    verify cannot read when it was named, and a line longer than MAX_MAKE_LINE."""
    words = cmd.words[1:]
    makefiles: list[str] = []
    directory: str | None = cmd.cwd
    targets: list[str] = []
    variables: dict[str, str] = {}
    evals: list[str] = []
    i = 0
    while i < len(words):
        w = words[i]
        t = w.text
        nxt = words[i + 1].text if i + 1 < len(words) else None
        value: str | None
        if t.startswith("--") and "=" in t:
            name, value = t.split("=", 1)
            took = 1
        elif t in _MAKE_VALUE_OPTIONS:
            name, value = t, nxt
            took = 2
        elif t.startswith("-") and not t.startswith("--") and len(t) > 2 and "-" + t[1] in _MAKE_VALUE_OPTIONS:
            name, value = "-" + t[1], t[2:]
            took = 1
        elif t in {"-j", "-l", "--jobs", "--load-average"} and nxt is not None and nxt.replace(".", "").isdigit():
            i += 2
            continue
        elif t.startswith("-"):
            i += 1
            continue
        elif _ASSIGN.match(t):
            k, v = t.split("=", 1)
            variables[k.rstrip(":+?")] = v
            if w.dynamic:
                line.opaque.append(f"make is given the variable {_show(k)} with a value only known when the line runs")
                return
            i += 1
            continue
        else:
            targets.append(t)
            i += 1
            continue
        if value is None:
            line.opaque.append(f"make {_show(name)} with no value")
            return
        if name in {"-f", "--file", "--makefile"}:
            makefiles.append(value)
        elif name in {"-C", "--directory"}:
            directory = _make_dir(directory, value)
        elif name in {"-E", "--eval"}:
            evals.append(value)
        i += took
    if directory is None:
        line.opaque.append("make runs in a directory verify could not follow")
        return
    for e in evals:
        if _names_kube(e) or "$(" in e:
            line.opaque.append(f"make --eval adds Makefile text that verify does not run: {_show(e)}")
            return

    def read(name: str) -> str | None:
        return read_script(name, directory) if read_script is not None else None

    texts: list[str] = []
    if makefiles:
        for name in makefiles:
            if name in {"-", "/dev/stdin"}:
                known, text = _stdin_text(cmd, read_script)
                if not known:
                    line.opaque.append("make reads its Makefile from standard input, which verify cannot read")
                    return
            else:
                got = read(name)
                if got is None:
                    line.opaque.append(f"make reads {_show(name)}, which verify could not read")
                    return
                text = got
            texts.append(text)
    else:
        for name in ("GNUmakefile", "makefile", "Makefile"):
            got = read(name)
            if got is not None:
                texts.append(got)
                break
        if not texts:
            if directory != cmd.cwd and (directory.startswith(("/", "..")) or directory == ".."):
                line.opaque.append(f"make -C {_show(directory)} reads a Makefile outside the working directory")
            return  # no Makefile here: make stops before it runs anything
    lines: list[str] = []
    missing: list[str] = []  # included files not in the tree yet
    pending = [(t, 0) for t in texts]
    included = 0
    while pending:
        text, level = pending.pop(0)
        got_lines = _make_logical_lines(text)
        if got_lines is None:
            line.opaque.append(f"a Makefile line is longer than {MAX_MAKE_LINE:,} characters; verify did not read it")
            return
        for raw in got_lines:
            stripped = raw.lstrip(" ")
            word = stripped.split(None, 1)[0] if stripped else ""
            if word in {"include", "-include", "sinclude"} and not raw.startswith("\t"):
                for name in stripped.split()[1:]:
                    if "$" in name:
                        line.opaque.append(f"make includes {_show(name)}, a name built from make variables")
                        return
                    if level >= 3 or included >= MAX_MAKE_INCLUDES:
                        line.opaque.append("make includes Makefiles more than 3 levels or 16 files deep")
                        return
                    got = read(name)
                    if got is None:
                        # A missing include in the tree stops make (`include`) or is skipped (`-include`); one
                        # outside the tree is a file verify cannot see.
                        if name.startswith(("/", "~")) or posixpath.normpath(name).startswith(".."):
                            line.opaque.append(f"make includes {_show(name)}, which verify could not read")
                            return
                        missing.append(name)
                        continue
                    included += 1
                    pending.append((got, level + 1))
                continue
            lines.append(raw)
    if not any(_names_kube(t) for t in [*texts, *(t for t, _ in pending)]) and not any(
        _names_kube("\n".join(lines)) or _names_kube(v) for v in [*variables.values(), ""]
    ):
        return
    names_kube_values = [k for k, v in variables.items() if _names_kube(v) or MENTION.search(v)]
    rules: dict[str, tuple[list[str], list[str]]] = {}
    first = ""
    current: str | None = None
    fallback = False
    for raw in lines:
        if raw.startswith("\t") and current is not None:
            rules[current][1].append(raw[1:].lstrip("@-+ "))
            continue
        if (
            not raw.startswith("\t")
            and ("$(shell" in raw or "${shell" in raw or "!=" in raw)
            and _kube_tail(_SPLIT_COMMAND_TEXT.split(raw))
        ):
            # Run whenever the Makefile is read; `$(shell kubectl config current-context)` only reads.
            line.opaque.append(f"the Makefile runs a shell command whenever it is read: {_show(raw)}")
            return
        rule = _make_rule(raw)
        if rule is not None:
            names, after = rule
            if raw.startswith(".DEFAULT") or raw.startswith(".SUFFIXES"):
                fallback = True
            elif raw.startswith(".") and len(names) == 1 and names[0].count(".") == 2:
                fallback = True  # an old-fashioned suffix rule `.c.o:`
            if raw.startswith("."):
                current = None
                continue
            fallback = fallback or any("%" in n for n in names)
            current = names[0] if names else None
            prerequisites, _, inline = after.partition(";")
            for n in names:
                rules.setdefault(n, (prerequisites.split(), []))
            if inline.strip() and current is not None:
                rules[current][1].append(inline.strip().lstrip("@-+ "))
            first = first or (names[0] if names else "")
        elif raw.strip() and not raw.startswith("\t"):
            current = None
    rebuilt = [m for m in missing if m in rules or fallback]
    if rebuilt:
        # make builds a missing included file with a rule and then reads it: text verify cannot see.
        line.opaque.append(f"make builds the included {_show(rebuilt[0])} with a rule and then reads it")
        return
    seen: set[str] = set()
    todo = targets or [first]
    while todo and len(seen) < MAX_MAKE_TARGETS:
        t = todo.pop()
        if t in seen:
            continue
        seen.add(t)
        if t not in rules:
            if not fallback and t:
                continue
            line.opaque.append(
                f"make target {_show(t)} is not a rule verify can read in a Makefile that names a kube tool"
            )
            continue
        deps, recipe = rules[t]
        todo.extend(deps)
        for written in recipe:
            r = _MAKE_SELF.sub("make", written)  # `$(MAKE) -C sub` is make, read as such
            if "$(" in r or "${" in r:
                # A make variable is a value verify does not resolve. In a kube command, or as the program a recipe
                # runs (`$(KUBECTL) apply`), that is not determined; as an argument of another program
                # (`docker build -t app:$(REV) .`) it is a word, read as one.
                if _names_kube(r) or _MAKE_VAR_AS_COMMAND.search(r):
                    line.opaque.append(f"make target {_show(t)} runs a recipe built from make variables: {_show(r)}")
                    continue
                r = _MAKE_VAR.sub("MAKEVAR", r)
            saved = line.cwd
            line.cwd = directory
            _nested(r, cmd, line, depth, read_script, f"make {t}", isolate=True)
            line.cwd = saved
    if todo:
        # Not a silent stop: a target past the cap is a recipe verify did not read (D1, a 51st target deployed).
        line.opaque.append(f"make: more than {MAX_MAKE_TARGETS:,} targets reachable; not all were read")
    if names_kube_values and not line.opaque:
        line.opaque.append(f"make is given a kube tool in the variable {_show(names_kube_values[0])}")


#: The options of npm, pnpm, yarn and bun that pick the package a script comes from, by tool.
_PKG_DIR_OPTIONS = {
    "npm": frozenset({"--prefix", "-C"}),
    "pnpm": frozenset({"-C", "--dir"}),
    "yarn": frozenset({"--cwd"}),
    "bun": frozenset({"--cwd"}),
}
_PKG_WORKSPACE_OPTIONS = frozenset({"-w", "--workspace", "--filter", "-F"})
#: Their subcommands that run a package's program, not a script: executors, held to the opaque check.
_PKG_EXECUTORS = frozenset({"exec", "x", "dlx"})


def _npm(cmd: Command, line: Line, depth: int, read_script: ScriptReader | None, tool: str) -> None:
    """`npm run NAME` (and `npm test`, `yarn NAME`, `pnpm NAME`, `bun run NAME`): the package.json script and its
    pre/post scripts are shell lines, read like `sh -c` in the package's directory, which `--prefix`, `-C`, `--dir`,
    `--cwd` and `-w`/`--workspace` (a path) choose. Install commands read the install lifecycle scripts; the
    scripts of dependencies are not seen. `npm exec`, `npm x`, `pnpm dlx` and `yarn dlx` run a package's program,
    and `yarn NAME`/`pnpm NAME` without such a script runs a binary: those are checked like any opaque program."""
    words = cmd.words[1:]
    directory = ""
    workspace: str | None = None
    positional: list[str] = []
    i = 0
    while i < len(words):
        t = words[i].text
        if t == "--":
            positional.extend(w.text for w in words[i + 1 :])
            break
        name, eq, value = t.partition("=") if t.startswith("--") else (t, "", "")
        if name in _PKG_DIR_OPTIONS.get(tool, frozenset()) or name in _PKG_WORKSPACE_OPTIONS:
            if not eq:
                value = words[i + 1].text if i + 1 < len(words) else ""
                i += 1
            if name in _PKG_WORKSPACE_OPTIONS:
                workspace = value
            else:
                directory = posixpath.join(directory, value) if directory else value
            i += 1
            continue
        if t.startswith("-") and positional and positional[0] in _PKG_EXECUTORS:
            positional.append(t)  # an option of the program `exec` runs
        elif not t.startswith("-"):
            positional.append(t)
        i += 1
    if not positional and tool == "yarn":
        positional = ["install"]
    if not positional:
        return
    sub = positional[0]
    if sub in _PKG_EXECUTORS:
        inner = Command(words=[Word(p, False, p) for p in positional[1:]], cwd=cmd.cwd)
        if inner.words:
            _opaque_check(inner, line, f"{tool} {sub}", read_script, executor=False)
            _opaque_check(Command(words=[Word(tool, False, tool), *inner.words]), line, tool, None, executor=False)
        return
    if sub in {"run", "run-script"} and len(positional) > 1:
        names = [positional[1]]
    elif sub in {"install", "i", "ci", "add"}:
        names = ["preinstall", "install", "postinstall", "prepare"]
    elif sub in {"test", "t", "start", "stop", "restart"} or tool in {"yarn", "pnpm", "bun"}:
        names = [{"t": "test"}.get(sub, sub)]
    else:
        return
    if workspace is not None:
        directory = posixpath.join(directory, workspace) if directory else workspace
    pkg_dir = _make_dir(cmd.cwd, directory) if directory else cmd.cwd
    if pkg_dir is None:
        line.opaque.append(f"{tool} runs a package in a directory verify could not follow")
        return
    text = read_script("package.json", pkg_dir) if read_script is not None else None
    if text is None:
        if directory:
            line.opaque.append(f"{tool} runs scripts of {_show(directory)}/package.json, which verify could not read")
        elif tool in {"yarn", "pnpm", "bun"} and sub not in {"install", "add", "test"}:
            _opaque_check(cmd, line, tool, None, executor=False)
        return
    try:
        from kube_noob.sanitize import loads_bounded

        scripts = loads_bounded(text).get("scripts")
    except (ValueError, AttributeError):
        if _names_kube(text):
            line.opaque.append("package.json names a kube tool and could not be read as JSON")
        return
    if not isinstance(scripts, dict):
        scripts = {}
    ran = False
    for name in names:
        for key in (f"pre{name}", name, f"post{name}"):
            body = scripts.get(key)
            if isinstance(body, str):
                ran = True
                saved = line.cwd
                line.cwd = pkg_dir
                _nested(body, cmd, line, depth, read_script, f"{tool} {key}", isolate=True)
                line.cwd = saved
    if not ran and tool in {"yarn", "pnpm", "bun"} and sub not in {"install", "add", "run", "test"}:
        # `yarn NAME` with no such script runs the package binary NAME with the rest of the words.
        _opaque_check(cmd, line, tool, None, executor=False)


def _names_kube(text: str) -> bool:
    return bool(MENTION.search(text) or re.search(r"(?<![\w.-])k\s", text))


#: The subcommands of each kube tool, so `pytest -k helm` (helm named as data) is told apart from
#: `npx kubectl delete ...` (a command). kubectl and oc: `kubectl --help` and `oc --help` (master, 2026-11-12);
#: helm: `helm --help` (v3); kustomize: `kustomize --help` (v5).
_KUBECTL_SUBS = frozenset(
    {
        "annotate", "api-resources", "api-versions", "apply", "attach", "auth", "autoscale", "certificate",
        "cluster-info", "completion", "config", "cordon", "cp", "create", "debug", "delete", "describe", "diff",
        "drain", "edit", "events", "exec", "explain", "expose", "get", "kustomize", "label", "logs", "patch",
        "plugin", "port-forward", "proxy", "replace", "rollout", "run", "scale", "set", "taint", "top", "uncordon",
        "version", "wait", "krew", "adm", "new-app", "new-project", "new-build", "project", "projects", "process",
        "start-build", "rsh", "rsync", "login", "logout", "whoami", "status", "tag", "import-image", "policy",
        "secrets", "extract", "image", "idle", "observe", "registry", "serviceaccounts", "rollback", "cancel-build",
        "import", "options",
    }
)  # fmt: skip
_HELM_SUBS = frozenset(
    {
        "install", "upgrade", "uninstall", "delete", "rollback", "plugin", "repo", "pull", "push", "package",
        "dependency", "dep", "registry", "create", "test", "template", "lint", "list", "ls", "status", "history",
        "get", "show", "search", "env", "version", "verify", "completion",
    }
)  # fmt: skip
_KUSTOMIZE_SUBS = frozenset({"build", "edit", "create", "cfg", "fn", "localize", "version", "help", "completion"})
_SPLIT_COMMAND_TEXT = re.compile(r"[\s;&|()`'\"{}<>]+")


#: The names kubectl is aliased to in the wild. Alone in another program's arguments they are not evidence; followed
#: by one of kubectl's own subcommands they are kubectl.
KUBECTL_ALIASES = frozenset({"k", "kc", "kctl"})
_VERBISH = re.compile(r"[A-Za-z][A-Za-z0-9-]{0,40}")
#: A subcommand word the shell expands at run time: a parameter, a substitution, a glob, a brace or a tilde.
_EXPANDS = re.compile(r"[$`*?\[{~]")


def _kube_tail(tokens: list[str]) -> str | None:
    """`TOOL SUB` when the tokens hold a kube command another program may run, else None.

    The tool is recognised by name in any case or version (`KubeCtl`, `kubectl1.30`, `helm3`, `/usr/local/bin/oc`,
    `nixpkgs#kubectl`), and `k`, `kc` or `kctl` when one of kubectl's subcommands follows. What follows is read the
    way cobra reads it (steps.kube_root): an unknown root flag, a `--` before the subcommand, a subcommand only
    known at run time (a parameter, a substitution, a glob or a brace), or a word-shaped subcommand kubectl does
    not have (it then looks for a plugin of that name) all count, as does a known subcommand that is not
    read-only. A tool named with nothing after it, or followed by a path or a number (`brew install helm`,
    `pytest -k helm tests/`), does not: it is data."""
    from kube_noob.debug.steps import classify_argv, kube_root

    for i, t in enumerate(tokens[:MAX_WORDS]):
        name = next(
            (p for p in (program(part) for part in re.split(r"[#=:@,]", t)) if p in KUBE_TOOLS and p != "k"), None
        )
        alias = name is None and t in KUBECTL_ALIASES
        if alias:
            name = "kubectl"
        if name is None:
            continue
        rest = tokens[i + 1 : i + 1 + 64]
        while rest and rest[0] == "--":
            rest = rest[1:]
        if not rest:
            continue
        if name in {"kubectl", "oc", "kubecolor"}:
            sub, _, _, unknown = kube_root(rest)
            if alias and sub not in _KUBECTL_SUBS:
                continue
            if unknown and sub:
                return f"{name} {unknown[0]}"
            subs = _KUBECTL_SUBS
        else:
            sub = next((r for r in rest if not r.startswith("-")), "")
            subs = _HELM_SUBS if name == "helm" else _KUSTOMIZE_SUBS
        if not sub:
            continue
        if sub == "--" or _EXPANDS.search(sub):
            return f"{name} {sub}"
        if sub in subs:
            if classify_argv([name, *rest]) != "read":
                return f"{name} {sub}"
            continue
        if _VERBISH.fullmatch(sub) and program(sub) not in KUBE_TOOLS and sub not in KUBECTL_ALIASES:
            return f"{name} {sub}"
    return None


def _stdin_text(cmd: Command, read_script: ScriptReader | None, depth: int = 0) -> tuple[bool, str]:
    """What arrives on the command's standard input, when it is known from the line: a here-document or
    here-string, a `< FILE` in the tree, or the output of `echo`/`printf` literals, of `cat` of files in the tree,
    of `tee` and `cat` passing their own input on, and of `base64 -d` of known input. (False, "") when not known."""
    if depth > 8:
        return False, ""
    if cmd.stdin_kind in {"heredoc", "herestring"} and cmd.stdin is not None:
        return True, cmd.stdin
    if cmd.stdin_kind == "file" and cmd.stdin is not None:
        if cmd.stdin_dynamic or read_script is None:
            return False, ""
        text = read_script(cmd.stdin, cmd.cwd)
        return (text is not None), text or ""
    src = cmd.source
    if cmd.stdin_kind != "pipe" or src is None or not src.words:
        return False, ""
    if src.tool in {"echo", "printf"}:
        if any(w.dynamic for w in src.words[1:]):
            return False, ""
        return True, " ".join(w.text for w in src.words[1:]).replace("\\n", "\n")
    files = [w for w in src.words[1:] if not w.text.startswith("-")]
    if src.tool in {"cat", "tee"} and (src.tool == "tee" or not files):
        return _stdin_text(src, read_script, depth + 1)  # passes its own input on
    if src.tool == "cat":
        if files and read_script is not None and not any(w.dynamic or w.glob for w in files):
            texts = [read_script(w.text, src.cwd) for w in files[:16]]
            if all(t is not None for t in texts):
                return True, "\n".join(t or "" for t in texts)
        return False, ""
    if src.tool == "base64" and any(w.text in {"-d", "--decode", "-D"} for w in src.words[1:]):
        known, data = _stdin_text(src, read_script, depth + 1)
        if not known:
            return False, ""
        import base64
        import binascii

        try:
            return True, base64.b64decode("".join(data.split()), validate=False).decode("utf-8", "replace")
        except (binascii.Error, ValueError):
            return False, ""
    return False, ""


#: Executors that run what they are given as a command line, where a value only known at run time is a command
#: verify cannot see (`ssh host "$(cat cmds.txt)"`).
_REMOTE_COMMAND = frozenset({"ssh", "su", "runuser", "at", "batch", "script", "expect", "osascript", "tmux", "screen"})


def _opaque_check(
    cmd: Command, line: Line, tool: str, read_script: ScriptReader | None, *, executor: bool, argv: bool = True
) -> None:
    """A program the reader does not model is opaque. If its arguments hold a kube command, or its standard input
    is text that names a kube tool, the line is not determined: verify cannot tell what the program does with it.
    An executor (ssh, at, docker ...) is held to more: any kube tool named in its arguments counts, a file in the
    tree it is given that names one counts (`at -f cmds.txt`, `crontab cron.txt`, `docker run ... sh deploy.sh`),
    commands it reads from a file verify could not open count, and so does a command only known at run time."""
    shown = _show(tool, 40)
    if argv:
        args = [w.text for w in cmd.words[1:]]
        found = None
        if executor:
            m = next((MENTION.search(a) for a in args if MENTION.search(a)), None)
            found = m.group(1) if m else None
        if found is None:
            found = _kube_tail(args)
        if found is None:
            spaced = [a for a in args if any(c.isspace() for c in a) or ";" in a]
            found = next((f for f in (_kube_tail(_SPLIT_COMMAND_TEXT.split(a)) for a in spaced) if f), None)
        if found is not None:
            line.opaque.append(
                f"{shown} is given `{_show(found, 40)}` in its arguments, and verify does not model what {shown} "
                "does with it"
            )
            return
        if executor:
            if tool in _REMOTE_COMMAND and any(w.dynamic for w in cmd.words[1:]):
                line.opaque.append(f"{shown} runs a command only known when the line runs")
                return
            if tool == "minikube" and len(args) > 1 and args[0] == "ssh":
                line.opaque.append("minikube ssh runs a command on a cluster node")
                return
            for w in cmd.words[1:17]:
                if w.dynamic or w.glob or w.text.startswith("-") or read_script is None:
                    continue
                text = read_script(w.text.split("=", 1)[-1], cmd.cwd)
                if text is not None and (MENTION.search(text) or _kube_tail(_SPLIT_COMMAND_TEXT.split(text))):
                    line.opaque.append(f"{shown} is given {_show(w.text, 60)}, a file that names a kube tool")
                    return
            if tool in {"at", "batch", "crontab"} and _unread_file_argument(cmd, tool, read_script):
                line.opaque.append(f"{shown} runs commands from a file verify could not read")
                return
    known, text = _stdin_text(cmd, read_script)
    if known:
        if MENTION.search(text) or _kube_tail(_SPLIT_COMMAND_TEXT.split(text)):
            line.opaque.append(f"{shown} reads text that names a kube tool on its standard input")
    elif executor and cmd.stdin_kind == "file":
        line.opaque.append(f"{shown} reads its input from {_show(cmd.stdin or '', 60)}, which verify could not read")


def _unread_file_argument(cmd: Command, tool: str, read_script: ScriptReader | None) -> bool:
    """`at -f FILE`, `batch -f FILE` and `crontab FILE`: a file of commands that verify could not read."""
    words = cmd.words[1:]
    if tool == "crontab":
        names = [w for w in words if not w.text.startswith("-")]
        name = names[0] if names else None
    else:
        name = next((words[i + 1] for i, w in enumerate(words[:-1]) if w.text == "-f"), None)
    if name is None or name.text == "-":
        return False
    return name.dynamic or read_script is None or read_script(name.text, cmd.cwd) is None


def _runs_a_shell(options: list[Word]) -> bool:
    """sudo's -s/--shell and -i/--login (alone or in a cluster, `-su`, `-iu`), and doas's -s, run the command
    through a shell (sudo(8): "the command is passed to the shell for execution")."""
    for w in options:
        t = w.text
        if t in {"--shell", "--login"}:
            return True
        if t.startswith("-") and not t.startswith("--"):
            for c in t[1:]:
                if c in "si":
                    return True
                if "-" + c in _WRAPPERS["sudo"]:
                    break  # the rest of the cluster is that option's value
    return False


#: xargs options that take a value (GNU findutils xargs --help); -i/-e/-l take one only when attached.
_XARGS_VALUE = frozenset(
    {"-I", "-n", "-P", "-d", "-E", "-L", "-s", "-a", "--arg-file", "--delimiter", "--max-args", "--max-procs",
     "--max-lines", "--max-chars", "--eof", "--process-slot-var"}
)  # fmt: skip


def _xargs(cmd: Command, line: Line, read_script: ScriptReader | None) -> bool:
    """`xargs [options] COMMAND`: COMMAND is run with words read from its input (`-a FILE` or standard input).

    When that input is known (a literal echo/printf/here-string, a file in the tree) and names a kube tool, the
    command xargs builds is one verify cannot see: not determined. When it is not known, and the command is a shell,
    eval, an interpreter, an executor or the replace string itself (`xargs -I{} {}`), not determined too. Otherwise
    the command is read as usual, its arguments marked as arriving at run time. Returns whether to keep unwrapping."""
    words = cmd.words
    i = 1
    replace: str | None = None
    arg_file: Word | None = None
    while i < len(words):
        t = words[i].text
        if t == "--":
            i += 1
            break
        if not t.startswith("-") or t == "-":
            break
        name, eq, value = t.partition("=") if t.startswith("--") else (t, "", "")
        if name in {"-I", "--replace"} or (t.startswith(("-I", "-i")) and not t.startswith("--")):
            if name == "-I" and not eq:
                replace = words[i + 1].text if i + 1 < len(words) else "{}"
                i += 2
                continue
            replace = value or (t[2:] if t.startswith(("-I", "-i")) and len(t) > 2 else "{}")
            i += 1
            continue
        if name in {"-a", "--arg-file"} or (t.startswith("-a") and len(t) > 2 and not t.startswith("--")):
            if eq:
                arg_file = Word(value, words[i].dynamic, value)
                i += 1
            elif len(t) > 2 and not t.startswith("--"):
                arg_file = Word(t[2:], words[i].dynamic, t[2:])
                i += 1
            else:
                arg_file = words[i + 1] if i + 1 < len(words) else None
                i += 2
            continue
        i += (
            2
            if (name in _XARGS_VALUE and not eq and len(t) == len(name) and (len(t) == 2 or t.startswith("--")))
            else 1
        )
    inner = words[i:] or [Word("echo", False, "echo")]
    if arg_file is not None:
        text = None if arg_file.dynamic or read_script is None else read_script(arg_file.text, cmd.cwd)
        known, data = (text is not None), text or ""
    else:
        known, data = _stdin_text(cmd, read_script)
    first = inner[0].text
    runs_code = (
        program(first) in SHELLS
        or first in {"eval", "exec", "source", "."}
        or program(first) in INTERPRETERS
        or program(first) in EXECUTORS
        or (replace is not None and replace in first)
        or program(first) in _WRAPPERS
        or program(first) in {"timeout", "nice", "env", "xargs", "parallel", "make"}
    )
    if known and (MENTION.search(data) or _kube_tail(_SPLIT_COMMAND_TEXT.split(data))):
        line.opaque.append("xargs builds a command from input that names a kube tool")
        return False
    if not known and runs_code:
        line.opaque.append(f"xargs runs {_show(first, 40)} on input verify cannot read")
        return False
    if replace is not None and replace in first:
        line.opaque.append("xargs runs a program named by its input")
        return False
    _drop(cmd, i, "xargs")
    cmd.args_from_stdin = True
    if not cmd.words:
        cmd.words = [Word("echo", False, "echo")]
    return True


def _parallel(cmd: Command, line: Line, read_script: ScriptReader | None) -> None:
    """GNU parallel runs a command per input line, or each input line as a command when none is given. Inputs:
    `::: ARGS`, `:::: FILES`, `-a FILE`/`--arg-file FILE`, else standard input. Input that names a kube tool, or that
    verify cannot read while what runs is a shell or the input itself, is not determined."""
    words = cmd.words[1:]
    command: list[str] = []
    inputs: list[str] = []
    unknown = False
    i = 0
    mode = "command"
    while i < len(words):
        w = words[i]
        t = w.text
        if t in {":::", ":::+"}:
            mode = "args"
        elif t in {"::::", "::::+"}:
            mode = "files"
        elif mode == "args":
            inputs.append(t)
            unknown = unknown or w.dynamic
        elif mode == "files" or t in {"-a", "--arg-file"} or t.startswith("--arg-file="):
            if mode != "files":
                if "=" in t:
                    target = Word(t.split("=", 1)[1], w.dynamic, t)
                else:
                    target = words[i + 1] if i + 1 < len(words) else Word("", True, "")
                    i += 1
            else:
                target = w
            text = None if target.dynamic or read_script is None else read_script(target.text, cmd.cwd)
            if text is None:
                unknown = True
            else:
                inputs.append(text)
        elif t in {"-j", "-S", "--sshlogin", "--jobs", "-d", "--delimiter", "-I", "--colsep", "-N"}:
            i += 1
        elif t.startswith("-") and not command:
            pass
        else:
            command.append(t)
        i += 1
    if not inputs and not unknown:
        known, data = _stdin_text(cmd, read_script)
        if known:
            inputs.append(data)
        else:
            unknown = True
    text = "\n".join(inputs + command)
    if MENTION.search(text) or _kube_tail(_SPLIT_COMMAND_TEXT.split(text)):
        line.opaque.append("parallel runs commands from input or arguments that name a kube tool")
    elif unknown and (not command or program(command[0]) in SHELLS or program(command[0]) in INTERPRETERS):
        line.opaque.append("parallel runs commands from input verify cannot read")


def _git(cmd: Command, line: Line) -> None:
    """git is mostly data, but some of it runs a program: `bisect run CMD`, `rebase -x CMD`, `difftool -x CMD`,
    `fetch --upload-pack CMD`, `filter-branch --tree-filter CMD`, `config alias.x '!CMD'`, `config core.pager CMD`,
    and `diff --ext-diff` runs the diff program git's configuration names. A kube command in any of those, or an
    external diff verify cannot see, is not determined. A commit message, a grep pattern and the like are data."""
    words = [w.text for w in cmd.words[1:]]
    sub = next((w for w in words if not w.startswith("-")), "")
    if "--ext-diff" in words:
        line.opaque.append("git --ext-diff runs the diff program git's configuration names, which verify cannot see")
        return
    if sub in {"commit", "tag", "notes", "grep", "log", "show", "shortlog", "status", "diff", "add", "rm", "mv"}:
        return  # their arguments are messages, patterns and paths
    found = _kube_tail(words)
    if found is None:
        spaced = [w for w in words if any(c.isspace() for c in w) or w.startswith("!")]
        found = next((f for f in (_kube_tail(_SPLIT_COMMAND_TEXT.split(w.lstrip("!"))) for w in spaced) if f), None)
    if found is None and sub == "config":
        found = next((m.group(1) for w in words for m in [MENTION.search(w)] if m), None)
    if found is not None:
        line.opaque.append(f"git {_show(sub, 20)} is given `{_show(found, 40)}`, a command git runs")


#: Programs that run a recipe from a project file, read like make when the file can be parsed, and otherwise not
#: determined when the file names a kube tool; or that compile and run project code, which verify does not read.
RUNNERS = frozenset(
    {"just", "task", "go-task", "tox", "nox", "earthly", "pre-commit", "deno", "go", "cargo", "bazel", "bazelisk",
     "docker-compose", "ansible", "vagrant", "devbox"}
)  # fmt: skip
_RUNNER_FILES = {
    "just": ("justfile", "Justfile", ".justfile"),
    "task": ("Taskfile.yml", "Taskfile.yaml", "taskfile.yml", "taskfile.yaml"),
    "go-task": ("Taskfile.yml", "Taskfile.yaml"),
    "tox": ("tox.ini", "pyproject.toml", "setup.cfg"),
    "nox": ("noxfile.py",),
    "earthly": ("Earthfile",),
    "pre-commit": (".pre-commit-config.yaml",),
    "docker-compose": ("compose.yaml", "compose.yml", "docker-compose.yml", "docker-compose.yaml"),
    "vagrant": ("Vagrantfile",),
    "devbox": ("devbox.json",),
}
_RUNNER_LISTS = frozenset({"--list", "-l", "--summary", "--show", "--dump", "--version", "--help", "-h", "--list-all"})
#: Code that starts a program, in the languages a project file or script is written in.
_SPAWNS = re.compile(
    r"subprocess|os\.system|os\.exec|os\.spawn|os\.popen|pty\.spawn|child_process|execSync|spawnSync|"
    r"\"os/exec\"|exec\.Command|Command::new|ProcessBuilder|Runtime\.getRuntime|Deno\.Command|Deno\.run|"
    r"\bsession\.run\b|\bsystem\(|\bpopen\(|\bexec\(|`[^`\n]{1,200}`"
)


def _runner(cmd: Command, line: Line, depth: int, read_script: ScriptReader | None, tool: str) -> None:
    words = [w.text for w in cmd.words[1:]]
    sub = next((w for w in words if not w.startswith("-")), "")
    shown = _show(tool, 20)
    if tool == "go" and sub not in {"run", "generate", "test"}:
        return  # build, vet, mod, fmt: compile or inspect without running the program
    if tool == "go" and sub == "test":
        return  # tests run project code, but `go test` is what every repository runs; stated in SECURITY.md
    if tool == "go" or (tool == "cargo" and sub == "run") or (tool in {"bazel", "bazelisk"} and sub in {"run", "test"}):
        line.opaque.append(f"{tool} {_show(sub, 20)} compiles and runs project code, which verify does not read")
        return
    if tool == "cargo":
        return
    if tool in {"bazel", "bazelisk"}:
        return
    if tool == "deno":
        if sub == "task":
            _deno_task(cmd, line, depth, read_script, words)
        elif sub == "run" and not any(_kube_tail(words[i:]) for i in range(len(words))):
            script = next((w for w in words[1:] if not w.startswith("-")), "")
            text = read_script(script, cmd.cwd) if script and read_script is not None else None
            if text is None or MENTION.search(text) or _SPAWNS.search(text):
                line.opaque.append(f"deno run {_show(script)} may start programs verify cannot see")
        return
    if tool == "ansible":
        module = next((words[i + 1] for i, w in enumerate(words[:-1]) if w in {"-m", "--module-name"}), "")
        if re.search(r"k8s|kubernetes|helm|openshift|kubectl", module + " " + " ".join(words), re.I):
            line.opaque.append(f"ansible runs the module {_show(module or 'shell')} against a cluster")
        return
    if tool == "pre-commit" and sub not in {"run", "try-repo", ""}:
        return
    if tool == "vagrant" and sub not in {"up", "provision", "reload", "resume"}:
        return
    if tool == "devbox" and sub not in {"run", "shell", "services"}:
        return
    if tool == "docker-compose" and sub not in {"run", "up", "exec", "start", "create"}:
        return
    text = None
    name = ""
    for name in _RUNNER_FILES.get(tool, ()):
        text = read_script(name, cmd.cwd) if read_script is not None else None
        if text is not None:
            break
    if text is None:
        return  # no recipe file: the runner stops before it runs anything
    if tool in {"just", "task", "go-task"} and set(words) & _RUNNER_LISTS:
        return  # `just --list`, `task --list`: they print the recipes
    if tool in {"just", "task", "go-task"}:
        recipes = _just_recipes(text, words) if tool == "just" else _task_recipes(text, words)
        if recipes is not None:
            saved = line.cwd
            for r in recipes:
                _nested(r, cmd, line, depth, read_script, f"{tool} recipe", isolate=True)
            line.cwd = saved
            return
    names = MENTION.search(text) or re.search(r"\.kube\b|kubeconfig|KUBECONFIG", text)
    if names or (tool in {"nox", "vagrant"} and _SPAWNS.search(text)) or (tool == "earthly" and "LOCALLY" in text):
        line.opaque.append(f"{shown} runs a recipe from {_show(name)}, which verify does not read")


def _just_recipes(text: str, words: list[str]) -> list[str] | None:
    """The lines of the requested just recipes (the first recipe by default) and of their dependencies, or None
    when the justfile uses what this reader does not follow (variables, `set`, imports, shebang recipes)."""
    recipes: dict[str, tuple[list[str], list[str]]] = {}
    order: list[str] = []
    current: str | None = None
    for raw in text.splitlines()[:5000]:
        if len(raw) > MAX_MAKE_LINE:
            return None
        if raw.startswith((" ", "\t")) and current is not None:
            body = raw.strip().lstrip("@-")
            if body.startswith("#!") or "{{" in body:
                return None
            recipes[current][1].append(body)
            continue
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith(("set ", "import ", "mod ", "export ", "alias ")) or ":=" in stripped:
            return None
        rule = _make_rule(stripped)
        if rule is None:
            return None
        names, after = rule
        if not names:
            return None
        current = names[0].lstrip("@")
        recipes[current] = ([d for d in after.split() if not d.startswith("#")], [])
        order.append(current)
    targets = [w for w in words if not w.startswith("-")] or order[:1]
    out: list[str] = []
    seen: set[str] = set()
    todo = list(targets)
    while todo:
        t = todo.pop()
        if t in seen:
            continue
        seen.add(t)
        if t not in recipes:
            return None if recipes else []
        needs, steps = recipes[t]
        todo.extend(needs)
        out.extend(steps)
    return out


def _task_recipes(text: str, words: list[str]) -> list[str] | None:
    """The `cmds` of the requested go-task tasks (`default` when none is named) and their `deps`, or None when the
    Taskfile uses what this reader does not follow (includes, templates, a task given as a `task:` call)."""
    from kube_noob.sanitize import safe_load_bounded

    try:
        doc = safe_load_bounded(text)
    except Exception:  # noqa: BLE001 - an unreadable Taskfile is not read
        return None
    if not isinstance(doc, dict) or doc.get("includes") or not isinstance(doc.get("tasks"), dict):
        return None
    tasks = doc["tasks"]
    targets = [w for w in words if not w.startswith("-") and "=" not in w] or ["default"]
    out: list[str] = []
    seen: set[str] = set()
    todo = list(targets)
    while todo:
        t = todo.pop()
        if t in seen:
            continue
        seen.add(t)
        task = tasks.get(t)
        if task is None:
            return None if t != "default" else out
        if isinstance(task, list):
            task = {"cmds": task}
        if isinstance(task, str):
            task = {"cmds": [task]}
        if not isinstance(task, dict):
            return None
        for d in task.get("deps") or []:
            todo.append(d if isinstance(d, str) else str(d.get("task", "")) if isinstance(d, dict) else "")
        for c in task.get("cmds") or []:
            body = c if isinstance(c, str) else c.get("cmd") if isinstance(c, dict) else None
            if isinstance(c, dict) and "task" in c:
                todo.append(str(c["task"]))
                continue
            if not isinstance(body, str) or "{{" in body:
                return None
            out.append(body)
    return out


def _deno_task(cmd: Command, line: Line, depth: int, read_script: ScriptReader | None, words: list[str]) -> None:
    """`deno task NAME` runs deno.json's tasks.NAME (a shell line), like npm run."""
    from kube_noob.sanitize import loads_bounded

    name = next((w for w in words[1:] if not w.startswith("-")), "")
    text = None
    for f in ("deno.json", "deno.jsonc"):
        text = read_script(f, cmd.cwd) if read_script is not None else None
        if text is not None:
            break
    if text is None or not name:
        return
    try:
        tasks = loads_bounded(text).get("tasks") or {}
    except (ValueError, AttributeError):
        if _names_kube(text):
            line.opaque.append("deno.json names a kube tool and could not be read as JSON")
        return
    body = tasks.get(name) if isinstance(tasks, dict) else None
    if isinstance(body, dict):
        body = body.get("command")
    if isinstance(body, str):
        _nested(body, cmd, line, depth, read_script, f"deno task {name}", isolate=True)


def _mention_check(cmd: Command, line: Line, tool: str) -> None:
    for w in cmd.words[1:]:
        m = MENTION.search(w.text)
        if m:
            line.opaque.append(
                f"{_show(tool)} is given {m.group(1)} in its arguments, and verify does not model what "
                f"{_show(tool)} does with them"
            )
            return
    if cmd.stdin and MENTION.search(cmd.stdin):
        line.opaque.append(f"{_show(tool)} reads text that names a kube tool on its standard input")


def _interpreter(cmd: Command, line: Line, tool: str, read_script: ScriptReader | None) -> None:
    """`python -c CODE`, `node -e CODE`: the code is checked; `python deploy.py`: the file is read when it is in the
    tree. `python -m pytest -k helm` names helm as data, which is not a command."""
    flags = INTERPRETERS[tool]
    words = cmd.words[1:]
    i = 0
    while i < len(words):
        t = words[i].text
        if t in flags:
            code = words[i + 1].text if i + 1 < len(words) else ""
            m = MENTION.search(code)
            if m:
                line.opaque.append(f"{tool} runs code that names {m.group(1)}, which verify does not follow")
            return
        if t in {"-m", "-"} or not t.startswith("-"):
            break
        i += 1
    if i < len(words) and words[i].text == "-":
        if cmd.stdin and MENTION.search(cmd.stdin):
            line.opaque.append(f"{tool} runs code from standard input that names a kube tool")
        return
    if i < len(words) and not words[i].text.startswith("-") and read_script is not None:
        text = read_script(words[i].text, cmd.cwd)
        m = MENTION.search(text or "")
        if m:
            line.opaque.append(
                f"{tool} runs {_show(words[i].text)}, which names {m.group(1)}; verify does not follow {tool} programs"
            )
        elif text is not None and _SPAWNS.search(text):
            # A program built at run time (`"kube" + "ctl"`) names nothing; starting one is what counts.
            line.opaque.append(
                f"{tool} runs {_show(words[i].text)}, which starts other programs; verify does not follow them"
            )


def _nested(
    text: str,
    cmd: Command,
    line: Line,
    depth: int,
    read_script: ScriptReader | None,
    via: str,
    isolate: bool = False,
) -> None:
    before = len(line.commands)
    _parse_into(text, line, depth + 1, read_script, isolate=isolate)
    for c in line.commands[before:]:
        c.via[:0] = [*cmd.via, via]
        c.assignments[:0] = cmd.assignments
        c.values = {**cmd.values, **c.values}


def _shell(cmd: Command, line: Line, depth: int, read_script: ScriptReader | None) -> None:
    name = program(cmd.words[0].text)
    i = 1
    has_c = False
    while i < len(cmd.words):
        t = cmd.words[i].text
        if t in {"-o", "+o", "--rcfile", "--init-file"}:
            i += 2
            continue
        if t.startswith("-") and not t.startswith("--") and "c" in t[1:]:
            has_c = True
            i += 1
            continue
        if t.startswith(("-", "+")) and t not in {"-", "--"}:
            i += 1
            continue
        if t == "--":
            i += 1
        break
    if has_c:
        if i >= len(cmd.words):
            line.opaque.append(f"{name} -c with no command")
            return
        script = cmd.words[i]
        if script.dynamic:
            line.opaque.append(f"{name} -c runs a value only known when the line runs ({_show(script.raw)})")
            return
        _nested(script.text, cmd, line, depth, read_script, f"{name} -c", isolate=True)
        return
    if i < len(cmd.words):
        _script(cmd.words[i : i + 1], cmd, line, depth, read_script, name)
        return
    # No -c and no file: the shell reads its program from stdin.
    if cmd.stdin_kind in {"heredoc", "herestring"} and cmd.stdin is not None:
        if cmd.stdin_dynamic:
            line.opaque.append(f"{name} runs a here-document that expands variables")
            return
        _nested(cmd.stdin, cmd, line, depth, read_script, f"{name} <<", isolate=True)
        return
    if cmd.stdin_kind == "file" and cmd.stdin is not None:
        _script([Word(cmd.stdin, cmd.stdin_dynamic, cmd.stdin)], cmd, line, depth, read_script, f"{name} <")
        return
    line.opaque.append(f"{name} runs commands from a pipe or the terminal, which verify cannot read")


def _source(cmd: Command, line: Line, depth: int, read_script: ScriptReader | None, via: str) -> None:
    """`source FILE` runs FILE in this shell: its functions, aliases and `cd` stay. A file in the tree is read like
    any script. A virtualenv's `bin/activate` that is not there yet (created earlier on the same line) only sets
    PATH and a prompt; it is passed, which is stated: a `kubectl` placed in that directory would shadow the real one."""
    words = cmd.words[1:2]
    if words and not words[0].dynamic and words[0].text.endswith("bin/activate"):
        text = read_script(words[0].text, cmd.cwd) if read_script is not None else None
        if text is None or not _names_kube(text):
            line.commands.append(cmd)
            return
    _script(words, cmd, line, depth, read_script, via, isolate=False)


def _script(
    words: list[Word],
    cmd: Command,
    line: Line,
    depth: int,
    read_script: ScriptReader | None,
    via: str,
    isolate: bool = True,
) -> None:
    if not words:
        line.opaque.append(f"{via} with no file")
        return
    w = words[0]
    if w.dynamic or w.glob:
        line.opaque.append(f"{via} runs a script whose name is only known when the line runs ({_show(w.raw)})")
        return
    text = read_script(w.text, cmd.cwd) if read_script is not None else None
    if text is None:
        line.opaque.append(
            f"runs the script {_show(w.text)}, which verify could not read (outside the working directory, missing, "
            "a link, binary or too large, or after a `cd` it could not follow)"
        )
        return
    if not _names_kube(text):
        return  # a script that names no kube tool starts none (as far as its text shows)
    _nested(text, cmd, line, depth, read_script, f"{via} {w.text}", isolate=isolate)


def _find(cmd: Command, line: Line, depth: int, read_script: ScriptReader | None) -> None:
    words = cmd.words
    i = 1
    found_exec = False
    while i < len(words):
        if words[i].text in {"-exec", "-execdir", "-ok", "-okdir"}:
            found_exec = True
            j = i + 1
            while j < len(words) and words[j].text not in {";", "+"}:
                j += 1
            inner = Command(
                words=[Word(w.text, w.dynamic or w.text == "{}", w.raw, w.glob) for w in words[i + 1 : j]], cwd=cmd.cwd
            )
            inner.via = [*cmd.via, "find -exec"]
            inner.args_from_stdin = any(w.text == "{}" for w in words[i + 1 : j])
            _unwrap(inner, line, depth + 1, read_script)
            i = j + 1
            continue
        i += 1
    if not found_exec:
        line.commands.append(cmd)


def _show(text: str, limit: int = 80) -> str:
    """One line, printable, bounded: input-derived text inside a message."""
    from kube_noob.sanitize import visible

    flat = " ".join(visible(text).split())
    return flat if len(flat) <= limit else flat[: limit - 3] + "..."
