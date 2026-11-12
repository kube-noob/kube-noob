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
    "kubectx": frozenset(),
    "kubens": frozenset(),
    "crossplane": frozenset({"version", "help", "beta"}),
    "eksctl": frozenset({"get", "version", "info", "help", "utils"}),
    "ansible-playbook": frozenset({"--check", "--syntax-check", "--list-tasks", "--list-hosts"}),
    "kustomize-controller": frozenset(),
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
            m = re.match(r"\d*(<<<|<<-|<<|<>|>>|>&|<&|>\||<|>)", s[self.i :])
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
        fd = re.match(r"\d+(?![\w./])|-", self.s[self.i :]) if op in {">&", "<&"} else None
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
            if ch == "{" and re.match(r"\{[^}\s]*,[^}\s]*\}", s[self.i :]):
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
        m = re.compile(r"[\s|;&()<>]").search(self.s, self.i)
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
                    m = re.match(r"[0-9A-Fa-f]{1,2}", s[i + 2 :])
                    out.append(chr(int(m.group(0), 16)) if m else "x")
                    i += 2 + (len(m.group(0)) if m else 0)
                elif n in "01234567":
                    m = re.match(r"[0-7]{1,3}", s[i + 1 :])
                    digits = m.group(0) if m else "0"
                    out.append(chr(int(digits, 8)))
                    i += 1 + len(digits)
                elif n in {"u", "U"}:
                    m = re.match(r"[0-9A-Fa-f]{1,8}", s[i + 2 :])
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
        m = re.match(r"\$([A-Za-z_][A-Za-z0-9_]*|[0-9@*#?$!-])", s[self.i :])
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
    for tok in [*toks, _Tok("op", ";")]:
        if tok.kind == "op":
            if current:
                before = len(line.commands)
                _simple(current, line, depth, read_script, piped)
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


def _simple(toks: list[_Tok], line: Line, depth: int, read_script: ScriptReader | None, piped: bool) -> None:
    words = [t.word for t in toks if t.kind == "word" and t.word is not None]
    cmd = Command(words=list(words), stdin_kind="pipe" if piped else "", cwd=line.cwd)
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
    """Index of the first word after the options of the wrapper at cmd.words[start - 1]."""
    i = start
    while i < len(cmd.words):
        t = cmd.words[i].text
        if t == "--":
            return i + 1
        if not t.startswith("-") or t == "-":
            return i
        i += 2 if (t in with_value) else 1
    return i


# Wrappers that run the rest of their arguments as a command, with the options that take a separate value.
_WRAPPERS: dict[str, frozenset[str]] = {
    "sudo": frozenset({"-u", "-g", "-C", "-h", "-p", "-U", "-r", "-t", "-D", "-R", "-T"}),
    "doas": frozenset({"-u", "-C"}),
    "command": frozenset(),
    "builtin": frozenset(),
    "exec": frozenset({"-a"}),
    "nohup": frozenset(),
    "time": frozenset({"-f", "-o"}),
    "nice": frozenset({"-n"}),
    "ionice": frozenset({"-c", "-n", "-p"}),
    "setsid": frozenset(),
    "stdbuf": frozenset({"-i", "-o", "-e"}),
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
        if not cmd.words:
            return
        first = cmd.words[0]
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
        tool = program(first.text)
        if tool in _WRAPPERS:
            if tool == "command" and len(cmd.words) > 1 and cmd.words[1].text in {"-v", "-V"}:
                return  # `command -v kubectl` asks where it is
            _drop(cmd, _skip_options(cmd, 1, _WRAPPERS[tool]), tool)
            continue
        if tool == "env":
            i = 1
            while i < len(cmd.words):
                t = cmd.words[i].text
                if t in {"-u", "--unset", "-C", "--chdir"}:
                    i += 2
                elif t in {"-S", "--split-string"} or t.startswith("--split-string="):
                    rest = t.split("=", 1)[1] if "=" in t else (cmd.words[i + 1].text if i + 1 < len(cmd.words) else "")
                    tail = cmd.words[i + 2 if "=" not in t else i + 1 :]
                    _nested(rest + " " + " ".join(w.text for w in tail), cmd, line, depth, read_script, "env -S")
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
            _drop(cmd, i + 1, "timeout")  # and the duration
            continue
        if tool == "watch":
            i = _skip_options(cmd, 1, frozenset({"-n", "--interval", "-d", "-q"}))
            _nested(" ".join(w.raw for w in cmd.words[i:]), cmd, line, depth, read_script, "watch", isolate=True)
            return
        if tool == "xargs":
            i = _skip_options(
                cmd, 1, frozenset({"-I", "-i", "-n", "-P", "-d", "-E", "-L", "-s", "-a", "--arg-file", "--delimiter"})
            )
            _drop(cmd, i, "xargs")
            cmd.args_from_stdin = True
            if not cmd.words:
                cmd.words = [Word("echo", False, "echo")]
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
            line.commands.append(cmd)
            return
        if tool in DATA_ONLY:
            line.commands.append(cmd)
            return
        if tool in INTERPRETERS:
            _interpreter(cmd, line, tool, read_script)
            line.commands.append(cmd)
            return
        if tool in EXECUTORS:
            _mention_check(cmd, line, tool)
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
        line.commands.append(cmd)
        return
    line.opaque.append("more than 32 wrappers around one command")


_MAKE_RULE = re.compile(r"^([^\s:=#][^:=#]*?)\s*::?(?!=)(.*)\Z")
_MAKE_FALLBACK = re.compile(
    r"^(?:\s*-?include\s|\s*sinclude\s|\.DEFAULT\s*:|\.SUFFIXES\s*:|\.[^\s:]+\.[^\s:]+\s*:)", re.M
)


def _make(cmd: Command, line: Line, depth: int, read_script: ScriptReader | None) -> None:
    """`make TARGET`: the recipe lines of the targets asked for (and the targets they depend on) are shell lines,
    read like `sh -c`. A recipe built from make variables (`$(KUBECTL) apply`) in a Makefile that names a kube tool
    is opaque; a Makefile verify cannot read is not followed."""
    words = [w.text for w in cmd.words[1:]]
    makefile: str | None = None
    targets: list[str] = []
    i = 0
    while i < len(words):
        t = words[i]
        if t in {"-f", "--file", "--makefile"}:
            makefile = words[i + 1] if i + 1 < len(words) else None
            i += 2
            continue
        if t in {"-C", "--directory"} or t.startswith("-C"):
            line.opaque.append("make -C runs a Makefile in another directory, which verify does not follow")
            return
        if t.startswith("-") or "=" in t:
            i += 1
            continue
        targets.append(t)
        i += 1
    text = None
    if read_script is not None:
        for name in [makefile] if makefile else ["GNUmakefile", "makefile", "Makefile"]:
            if name:
                text = read_script(name, cmd.cwd)
                if text:
                    break
    if not text or not _names_kube(text):
        return
    rules: dict[str, tuple[list[str], list[str]]] = {}
    first = ""
    current: str | None = None
    for raw in text.splitlines()[:5000]:
        if raw.startswith("\t") and current is not None:
            rules[current][1].append(raw[1:].lstrip("@-+ "))
            continue
        m = _MAKE_RULE.match(raw)
        if m and not raw.startswith("."):
            names = m.group(1).split()
            current = names[0] if names else None
            for n in names:
                rules.setdefault(n, (m.group(2).split(";")[0].split(), []))
            first = first or (names[0] if names else "")
        elif raw.strip() and not raw.startswith("\t"):
            current = None
    # A target with no rule runs none of this Makefile's recipes -- make stops, or uses a built-in rule (a compile
    # or a copy) -- unless a pattern rule, a .DEFAULT rule or an included file could supply one.
    fallback = any("%" in n for n in rules) or bool(_MAKE_FALLBACK.search(text))
    seen: set[str] = set()
    todo = targets or [first]
    while todo and len(seen) < 50:
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
        for r in recipe:
            if "$(" in r or "${" in r:
                line.opaque.append(f"make target {_show(t)} runs a recipe built from make variables: {_show(r)}")
                continue
            _nested(r, cmd, line, depth, read_script, f"make {t}", isolate=True)


def _npm(cmd: Command, line: Line, depth: int, read_script: ScriptReader | None, tool: str) -> None:
    """`npm run NAME` (and `npm test`, `yarn NAME`, `pnpm NAME`, `bun run NAME`): the package.json script and its
    pre/post scripts are shell lines, read like `sh -c`. Install commands read the install lifecycle scripts; the
    scripts of dependencies are not seen."""
    words = [w.text for w in cmd.words[1:] if not w.text.startswith("-")]
    if not words and tool == "yarn":
        words = ["install"]
    if not words:
        return
    sub = words[0]
    if sub in {"run", "run-script"} and len(words) > 1:
        names = [words[1]]
    elif sub in {"install", "i", "ci", "add"}:
        names = ["preinstall", "install", "postinstall", "prepare"]
    elif sub in {"test", "t", "start", "stop", "restart"} or (tool in {"yarn", "pnpm"} and sub not in {"exec", "dlx"}):
        names = [{"t": "test"}.get(sub, sub)]
    else:
        return
    text = read_script("package.json", cmd.cwd) if read_script is not None else None
    if not text:
        return
    try:
        from kube_noob.sanitize import loads_bounded

        scripts = loads_bounded(text).get("scripts") if _names_kube(text) else None
    except (ValueError, AttributeError):
        line.opaque.append("package.json names a kube tool and could not be read as JSON")
        return
    if not isinstance(scripts, dict):
        return
    for name in names:
        for key in (f"pre{name}", name, f"post{name}"):
            body = scripts.get(key)
            if isinstance(body, str):
                _nested(body, cmd, line, depth, read_script, f"{tool} {key}", isolate=True)


def _names_kube(text: str) -> bool:
    return bool(MENTION.search(text) or re.search(r"(?<![\w.-])k\s", text))


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
