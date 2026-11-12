"""Read a shell command line into the simple commands it would run, without running anything.

``kube-noob verify --command`` and the Claude Code hook ask one question of a line an agent is about to run: which
``kubectl``, ``oc``, ``helm`` and ``kustomize`` commands does it start, with which arguments? The answer has to see
through the forms that hide a command (``sh -c '...'``, ``bash -lc``, ``eval``, ``env``, ``sudo``, ``xargs``, ``find
-exec``, ``watch``, ``timeout``, a full path, the ``k`` alias, backslash-newlines, a word split by quotes such as
``kub"e"ctl``, a here-document fed to a shell, a script file in the working tree) or say that it cannot.

What this reader does NOT see through is reported, never assumed harmless (``Line.opaque``): a command word built
from an expansion (``$CMD apply``), ``eval`` of a value only known when it runs, code piped into a shell, a script
it cannot read, or a kube tool named in the arguments of a program it does not model (``python -c``, ``ssh``,
``make``, ``awk``). The caller decides what an opaque line means; for a check before an action it means "not
determined", which blocks.

Bounded: 20,000 characters, 4 levels of ``sh -c``/``eval``/script nesting, 2,000 words, 200 commands. Quoting
follows POSIX sh (single quotes literal, backslash escapes outside them, double quotes keep ``$`` and backticks
live). It is a reader for the shapes agents write, not a shell: a construct it does not parse is opaque.
"""

from __future__ import annotations

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
#: A kube tool named anywhere in a word. ``k`` is left out: a single letter inside an argument is not evidence.
MENTION = re.compile(r"(?<![\w.-])(kubectl|oc|helm|kustomize|kubecolor)(?:\.exe)?(?![\w-])")
SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "ash", "mksh", "yash", "fish"})
#: Programs whose arguments are data: a kube tool named in them is text, not a command. Each one is either a pure
#: text tool or never runs its arguments (``git commit -m "kubectl ..."``, ``grep kubectl``, ``echo``).
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
        "less",
        "more",
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
        "man",
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
    }
)
#: Words that open or close a shell construct rather than name a program.
KEYWORDS = frozenset({"if", "then", "else", "elif", "fi", "do", "done", "while", "until", "!", "{", "}", "esac"})
#: Words after which the rest of the simple command is not a command (``for x in a b``, ``case $x in``).
NON_COMMANDS = frozenset({"for", "case", "select", "function"})
_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\[[^\]]*\])?\+?=")
_HEREDOC = re.compile(r"^(-?)\s*(['\"]?)([A-Za-z0-9_.-]+)\2")


@dataclass(frozen=True)
class Word:
    text: str  # after quote removal
    dynamic: bool  # holds an expansion (`$X`, `$(...)`, backticks, a glob) whose value is only known at run time
    raw: str  # as written, for messages


@dataclass
class Command:
    """One simple command, after the wrappers that only run it (``env``, ``sudo``, ``sh -c``...) are removed."""

    words: list[Word]
    stdin: str | None = None  # a here-document, here-string or `< file` content the command reads
    stdin_kind: str = ""  # "heredoc", "herestring", "file", "pipe" or ""
    stdin_dynamic: bool = False  # the here-document or here-string expands variables
    via: list[str] = field(default_factory=list)  # the wrappers seen through, outermost first
    assignments: list[str] = field(default_factory=list)  # VAR names assigned in front of it
    args_from_stdin: bool = False  # under xargs: more arguments arrive at run time
    source: Command | None = None  # the command whose output is piped into this one

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
    subshell: bool = False  # the line opens a ( subshell ), whose `cd` does not outlive it


def program(word: str) -> str:
    """``/usr/local/bin/kubectl`` and ``kubectl.exe`` are kubectl."""
    base = word.rsplit("/", 1)[-1]
    return base[:-4] if base.lower().endswith(".exe") else base


# -- lexing ------------------------------------------------------------------------------------------------------


@dataclass
class _Tok:
    kind: str  # "word", "op", "redir"
    value: str
    word: Word | None = None


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
                    self._redirect(out, 2 + (s[self.i + 2 : self.i + 3] == ">"))
                    continue
                if ch == "|" and s.startswith("|&", self.i):
                    out.append(_Tok("op", "|"))
                    self.i += 2
                    continue
                out.append(_Tok("op", ch))
                self.i += 1
                continue
            m = re.match(r"\d*(<<<|<<-|<<|<>|>>|>&|<&|>\||<|>)", s[self.i :])
            if m and (ch in "<>" or m.group(0)[: -len(m.group(1))].isdigit()):
                if m.group(1).startswith("<(") or s.startswith(("<(", ">("), self.i):
                    pass  # a process substitution, read as a word below
                else:
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

    def _redirect(self, out: list[_Tok], width: int) -> None:
        self.i += width
        self._redirect_target(out, ">")

    def _redirect_target(self, out: list[_Tok], op: str) -> None:
        while self.i < len(self.s) and self.s[self.i] in " \t":
            self.i += 1
        fd = re.match(r"\d+|-", self.s[self.i :]) if op in {">&", "<&"} else None
        if fd is not None:
            self.i += len(fd.group(0))
            return
        target = self._word()
        if target is None:
            self.error("a redirection with no target")
            return
        out.append(_Tok("redir", op, target))

    def _heredoc_marker(self, out: list[_Tok], strip: bool) -> None:
        while self.i < len(self.s) and self.s[self.i] in " \t":
            self.i += 1
        m = _HEREDOC.match(self.s[self.i :])
        if not m:
            self.error("a here-document whose delimiter could not be read")
            return
        self.i += len(m.group(0))
        tok = _Tok("redir", "<<", Word("", False, m.group(0)))
        out.append(tok)
        # A quoted delimiter keeps the body literal; an unquoted one expands $ and backticks in it.
        self.pending.append((m.group(3), strip, tok))
        tok.word = Word("", not m.group(2), m.group(0))

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
            tok.word = Word(text, live, tok.word.raw if tok.word else "")
        self.pending = []

    def _word(self) -> Word | None:
        s = self.s
        buf: list[str] = []
        raw_start = self.i
        dynamic = False
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
            if ch in "*?[" or (ch == "{" and re.match(r"\{[^}\s]*,[^}\s]*\}", s[self.i :])):
                dynamic = True  # a glob or brace expansion: the words are only known at run time
            if ch == "~" and not buf:
                dynamic = True
            buf.append(ch)
            self.i += 1
        if self.i == raw_start:
            return None if self.i >= len(s) else Word("", False, "")
        return Word("".join(buf), dynamic, s[raw_start : self.i])

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
            if inner is not None and not inner.startswith("("):
                self.sub(inner, self.depth + 1)  # $(( arithmetic )) runs nothing
            buf.append("${...}")
            return True
        if nxt == "{":
            end = s.find("}", self.i)
            if end < 0:
                self.error("an unterminated ${...} expansion")
                self.i = len(s)
                return True
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
        s = self.s
        depth = 0
        start = self.i + 1
        quote = ""
        while self.i < len(s):
            ch = s[self.i]
            if quote:
                if ch == "\\" and quote == '"':
                    self.i += 2
                    continue
                if ch == quote:
                    quote = ""
            elif ch in "'\"":
                quote = ch
            elif ch == "\\":
                self.i += 2
                continue
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    self.i += 1
                    return s[start : self.i - 1]
            self.i += 1
        self.error("an unterminated $( or <( substitution")
        return None


# -- parsing -----------------------------------------------------------------------------------------------------


ScriptReader = Callable[[str], str | None]


def parse(text: str, read_script: ScriptReader | None = None) -> Line:
    """Every simple command ``text`` would start, with wrappers removed, and what could not be read.

    ``read_script(path)`` returns the text of a script the line runs (``./deploy.sh``, ``bash ci/apply.sh``) when the
    caller allows reading it, or None; a script that is not read and names a kube tool cannot be, so it is listed as
    opaque only when its text is known to mention one or cannot be read at all."""
    line = Line()
    if len(text) > MAX_CHARS:
        line.opaque.append(f"the command is longer than {MAX_CHARS:,} characters")
        return line
    _parse_into(text, line, 0, read_script)
    return line


def _parse_into(text: str, line: Line, depth: int, read_script: ScriptReader | None) -> None:
    if depth > MAX_DEPTH:
        line.opaque.append(f"commands nested more than {MAX_DEPTH} levels deep (sh -c, eval, scripts)")
        return

    def sub(inner: str, d: int) -> None:
        _parse_into(inner, line, d, read_script)

    toks = _Lexer(text, line, depth, sub).tokens()
    # Split into pipelines of simple commands. A pipe gives the next command its stdin.
    piped = False
    producer: Command | None = None
    current: list[_Tok] = []
    for tok in [*toks, _Tok("op", ";")]:
        if tok.kind == "op":
            if tok.value in {"(", ")"}:
                line.subshell = True
            if current:
                before = len(line.commands)
                _simple(current, line, depth, read_script, piped)
                made = line.commands[before:]
                if piped and made:
                    made[0].source = producer
                producer = made[-1] if made else None
            elif tok.value != "|":
                producer = None
            piped = tok.value == "|"
            current = []
            continue
        current.append(tok)
        if len(line.commands) > MAX_COMMANDS:
            line.opaque.append(f"more than {MAX_COMMANDS} commands")
            return


def _simple(toks: list[_Tok], line: Line, depth: int, read_script: ScriptReader | None, piped: bool) -> None:
    words = [t.word for t in toks if t.kind == "word" and t.word is not None]
    cmd = Command(words=list(words), stdin_kind="pipe" if piped else "")
    for t in toks:
        if t.kind != "redir" or t.word is None:
            continue
        if t.value == "<<":
            cmd.stdin, cmd.stdin_kind, cmd.stdin_dynamic = t.word.text, "heredoc", t.word.dynamic
        elif t.value == "<<<":
            cmd.stdin, cmd.stdin_kind, cmd.stdin_dynamic = t.word.text + "\n", "herestring", t.word.dynamic
        elif t.value == "<":
            cmd.stdin, cmd.stdin_kind, cmd.stdin_dynamic = t.word.text, "file", t.word.dynamic
    _unwrap(cmd, line, depth, read_script)


def _drop(cmd: Command, n: int, via: str) -> None:
    del cmd.words[:n]
    cmd.via.append(via)


def _assignments(cmd: Command, line: Line) -> None:
    while cmd.words and _ASSIGN.match(cmd.words[0].text) and not cmd.words[0].raw.startswith(("'", '"')):
        name = cmd.words[0].text.split("=", 1)[0].split("[", 1)[0].rstrip("+")
        cmd.assignments.append(name)
        line.assignments.append(name)
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
                if _ASSIGN.match(w.text) or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", w.text):
                    line.assignments.append(w.text.split("=", 1)[0])
            _mention_check(cmd, line, "export")
            return
        if first.dynamic:
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
                    name = t.split("=", 1)[0]
                    cmd.assignments.append(name)
                    line.assignments.append(name)
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
            _nested(" ".join(w.raw for w in cmd.words[i:]), cmd, line, depth, read_script, "watch")
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
            _script(cmd.words[1:2], cmd, line, depth, read_script, tool)
            return
        if tool == "alias":
            for w in cmd.words[1:]:
                if MENTION.search(w.text) or re.search(r"=\s*['\"]?k\b", w.text):
                    line.opaque.append(f"defines an alias for a kube tool ({_show(w.text)})")
            return
        if tool == "find":
            _find(cmd, line, depth, read_script)
            return
        if tool in KUBE_TOOLS:
            line.commands.append(cmd)
            return
        if tool in DATA_ONLY:
            line.commands.append(cmd)
            return
        if "/" in first.text:
            # A path to a program: read it as a script when it is a text file in the working tree. An absolute
            # path the reader will not open (/usr/bin/python3) is an ordinary program; a relative one it cannot
            # open is a script nobody can see into.
            text = read_script(first.text) if read_script is not None else None
            if text is not None:
                if MENTION.search(text) or re.search(r"(?<![\w.-])k\s", text):
                    _nested(text, cmd, line, depth, read_script, f"script {first.text}")
            elif not first.text.startswith("/"):
                _script(cmd.words[0:1], cmd, line, depth, read_script, "script")
                return
        _mention_check(cmd, line, tool)
        line.commands.append(cmd)
        return
    line.opaque.append("more than 32 wrappers around one command")


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


def _nested(text: str, cmd: Command, line: Line, depth: int, read_script: ScriptReader | None, via: str) -> None:
    before = len(line.commands)
    _parse_into(text, line, depth + 1, read_script)
    for c in line.commands[before:]:
        c.via[:0] = [*cmd.via, via]
        c.assignments[:0] = cmd.assignments


def _shell(cmd: Command, line: Line, depth: int, read_script: ScriptReader | None) -> None:
    name = program(cmd.words[0].text)
    i = 1
    script: Word | None = None
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
        _nested(script.text, cmd, line, depth, read_script, f"{name} -c")
        return
    if i < len(cmd.words):
        _script(cmd.words[i : i + 1], cmd, line, depth, read_script, name)
        return
    # No -c and no file: the shell reads its program from stdin.
    if cmd.stdin_kind in {"heredoc", "herestring"} and cmd.stdin is not None:
        if cmd.stdin_dynamic:
            line.opaque.append(f"{name} runs a here-document that expands variables")
            return
        _nested(cmd.stdin, cmd, line, depth, read_script, f"{name} <<")
        return
    if cmd.stdin_kind == "file" and cmd.stdin is not None:
        _script([Word(cmd.stdin, cmd.stdin_dynamic, cmd.stdin)], cmd, line, depth, read_script, f"{name} <")
        return
    line.opaque.append(f"{name} runs commands from a pipe or the terminal, which verify cannot read")


def _script(
    words: list[Word], cmd: Command, line: Line, depth: int, read_script: ScriptReader | None, via: str
) -> None:
    if not words:
        line.opaque.append(f"{via} with no file")
        return
    w = words[0]
    if w.dynamic:
        line.opaque.append(f"{via} runs a script whose name is only known when the line runs ({_show(w.raw)})")
        return
    text = read_script(w.text) if read_script is not None else None
    if text is None:
        line.opaque.append(
            f"runs the script {_show(w.text)}, which verify could not read (outside the working "
            "directory, missing, a link, binary or too large)"
        )
        return
    if not MENTION.search(text) and not re.search(r"(?<![\w.-])k\s", text):
        return  # a script that names no kube tool starts none (as far as its text shows)
    _nested(text, cmd, line, depth, read_script, f"{via} {w.text}")


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
            inner = Command(words=[Word(w.text, w.dynamic or w.text == "{}", w.raw) for w in words[i + 1 : j]])
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
