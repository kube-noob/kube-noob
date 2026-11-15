"""How a container launches kube-apiserver or etcd, and how their flags parse (G272).

Split out of `rules.py`, which `KN-S038` and `KN-S039` use it from, so that file stays under the 256 KiB the Claude
plugin directory reads. Recognition here is fail-safe: a container is "not this server" only when nothing points
at the binary or it is positively something else; every other shape is read or declined, never passed over.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

#: How much of one input-derived fragment a message carries. A flag value or a container name is the user's own
#: text: cleaned of invisible and control characters, collapsed to one line and cut here, so it can neither forge
#: a line of the text view nor flood a SARIF message (G272).
SHOWN_LIMIT = 200


def _shown(value: object, limit: int = SHOWN_LIMIT) -> str:
    """``value`` as one visible line of at most ``limit`` characters, saying how much was cut.

    `sanitize.visible` makes it printable (every non-printing character, by Unicode category, and every terminal
    escape sequence); this collapses it to one line and caps it, which `visible` leaves to its callers.
    """
    from kube_noob.sanitize import visible

    text = str(value)
    if len(text) > limit * 4:
        cut = len(text) - limit * 4
        text = text[: limit * 4]
    else:
        cut = 0
    text = " ".join(visible(text).split())
    if len(text) > limit:
        cut += len(text) - limit
        text = text[:limit]
    return f"{text}... ({cut} more characters)" if cut else text


def _quoted(value: object, limit: int = SHOWN_LIMIT) -> str:
    return f"'{_shown(value, limit)}'"


def shown_value(value: object) -> str:
    """A scalar the tool quotes in its own words: `null` for None, YAML's `true`/`false`, else the cleaned text --
    never a Python repr (R6, G272)."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    return _shown(value, 40)


#: Shells whose script may start a control-plane binary. Such a container is RECOGNISED and then declined: the
#: flags are in a script kube-noob does not execute, so neither a finding nor a pass can be read from it.
_SHELLS = frozenset({"sh", "bash", "ash", "dash", "zsh", "ksh", "mksh"})
#: Distributions that run the API server and etcd inside one binary of their own, configured through that
#: binary's flags (`--kube-apiserver-arg`, `--etcd-arg`) and configuration file.
_EMBEDDING = frozenset({"k3s", "rke2", "k0s"})
#: The subcommands of each that run the control plane (k0s calls `controller` `server` too).
_EMBEDDING_SERVER = {
    "k3s": frozenset({"server"}),
    "rke2": frozenset({"server"}),
    "k0s": frozenset({"controller", "server"}),
}
#: Global flags of the embedding binaries that come before the subcommand: booleans, and flags that take the next
#: token. Any other flag given before the subcommand without `=` has an arity not read here, so the container is
#: declined rather than its subcommand guessed (G272).
_EMBEDDING_GLOBAL_BOOLS = frozenset({"debug", "help", "h", "version", "v"})
_EMBEDDING_GLOBAL_VALUES = frozenset({"data-dir", "d", "config", "c", "log", "l"})
#: The flag of each embedding binary that passes one `key=value` to the API server it runs.
_EMBEDDED_APISERVER_ARG = {"k3s": "kube-apiserver-arg", "rke2": "kube-apiserver-arg"}
#: Programs shipped beside a binary, in its image, that are not the server: `etcdctl snapshot save` in the etcd
#: image is a backup job, read and recognised as not etcd.
_SIBLINGS = {"etcd": frozenset({"etcdctl", "etcdutl"})}
#: Image names that carry kube-apiserver although no component of the name is it.
_APISERVER_IMAGE_NAMES = frozenset({"hyperkube", "hardened-kubernetes"})
#: A component of an image name that makes it a DIFFERENT program built around the binary: `etcd-operator`,
#: `etcd-backup`, `etcd-exporter` are not etcd.
_IMAGE_NOT_THE_SERVER = frozenset(
    {"operator", "controller", "manager", "exporter", "backup", "proxy", "defrag", "client", "ctl", "tools", "druid"}
)
#: Commands a shell script on the etcd image may run and still be positively not etcd: the clients, and builtins
#: and coreutils that start nothing else. Not `find` (-exec), `tar` (--to-command), `sort` (--compress-program),
#: `xargs`, `awk`, `sed` (e), `env`, `nice`, `timeout` or anything else that can run another program (G272).
_ETCD_SCRIPT_SAFE = frozenset(
    {
        "etcdctl", "etcdutl", "echo", "printf", "sleep", "test", "[", "[[", "true", "false", ":", "date",
        "mkdir", "cp", "mv", "rm", "ls", "cat", "gzip", "gunzip", "sha256sum", "md5sum",
        "export", "set", "exit", "wc", "head", "tail", "grep", "cut", "tee", "touch", "chmod",
        "basename", "dirname", "stat", "df", "du",
    }
)  # fmt: skip
_SHELL_KEYWORDS = frozenset({"if", "then", "else", "elif", "fi", "while", "until", "do", "done", "!", "time"})
#: GNU and busybox `env` options that take the next token as their value.
_ENV_VALUE_OPTIONS = frozenset({"-u", "--unset", "-C", "--chdir"})
_ENV_FLAG_OPTIONS = frozenset({"-", "-i", "--ignore-environment", "-0", "--null", "-v", "--debug"})
#: How many `env` / `busybox` prefixes are stripped before the command they start is looked at.
_LAUNCHER_DEPTH = 8
#: How much of one shell script or argv token is searched for the binary. Longer text counts as naming it if the
#: name is anywhere in it: unread is not absent.
_SCRIPT_SCAN = 65_536
#: A word starts after the start of the text, whitespace, a shell operator or quote, or `:-` (a default value).
_WORD_START = r"(?:^|(?<=[\s;&|()`'\"{}<>])|(?<=:-))"
#: The directory part of a command word: none, `.`, `/`, or a directory ending in `bin` or `sbin`. A path such as
#: `/var/lib/etcd` is a data directory, not the program (G272).
_BIN_DIR = r"(?:(?:\.|(?:/[^\s/;&|()`'\"]+)*/s?bin)?/)?"
_MENTION_PATTERNS: dict[str, tuple[re.Pattern[str], ...]] = {}
#: What puts a word in COMMAND position in a script: its start, a shell operator or a newline, or a keyword that
#: runs the next word (`exec`, with `-a NAME`, `then`, `do`, `else`, `nohup`, `time`), then `NAME=value`
#: assignments. There an absolute path names the program from ANY directory (`/opt/k8s/kube-apiserver`); in
#: argument position only a `bin` directory does, so `tar czf b /var/lib/etcd` is not etcd (G272).
_COMMAND_POSITION = (
    r"(?:^|[;&|(\n`]|\b(?:exec|then|do|else|nohup|time))\s*(?:-a\s+\S+\s+)?(?>[A-Za-z_]\w*=\S*\s+)*"
    r"/(?:[^\s/;&|()`'\"]+/)*"
)


def k3s_arg(item: str) -> tuple[str, str, str]:
    """One `--kube-apiserver-arg` / `--etcd-arg` value as k3s and RKE2 read it (pkg/util/args.go GetArgs,
    fetched 2026-11-13): one leading `--` is trimmed (`strings.TrimPrefix`, exactly once), the first `=` splits
    name from value, no `=` means the value "true", and a trailing run of `-` and `+` on the name
    (`strings.TrimRight(arg, "-+")`) is the append (`+`) or prepend (`-`) marker, either of which puts the value
    on the flag beside the distribution's own default -- a second occurrence, which pflag appends to a slice such
    as --authorization-mode. Nothing is trimmed (configfilearg/parser.go passes a config value untouched, so a
    padded name is a flag pflag refuses). Returns (the cleaned RAW name, the name with `_` read as `-` as
    kube-apiserver's pflag does, the value). Both readers of this syntax -- the k3s argv and the Rancher config --
    call this one function, and `k3s_pairs` orders what they read as GetArgs does (G272, sixth and seventh reviews).
    """
    body = item[2:] if item.startswith("--") else item
    name, eq, value = body.partition("=")
    raw = name.rstrip("-+")
    return raw, raw.replace("_", "-"), value if eq else "true"


def k3s_pairs(values: list[str]) -> list[tuple[str, str, int]]:
    """The (flag, value, index of the value it came from) list kube-apiserver receives from a list of
    `--kube-apiserver-arg` values: GetArgs keys them on the cleaned raw name, keeps the order of repeats within
    one key, `slices.Sort`s the keys and emits them in that order -- so `anonymous_auth=true` then
    `anonymous-auth=false` reaches pflag as `--anonymous-auth=false --anonymous_auth=true`, which pflag folds
    to one flag whose LAST value, true, wins (G272, seventh review). The fold happens here, after the sort."""
    by_key: dict[str, list[tuple[str, int]]] = {}
    for i, item in enumerate(values):
        raw, _, value = k3s_arg(item)
        by_key.setdefault(raw, []).append((value, i))
    out: list[tuple[str, str, int]] = []
    for raw in sorted(by_key):
        out.extend((raw.replace("_", "-"), value, i) for value, i in by_key[raw])
    return out


#: Why a `$(NAME)` in argv cannot be read from the manifest.
_NO_LITERAL = "env {name} has no literal value in this container"


def expand_argv(tokens: tuple[str, ...], container: dict[str, Any]) -> tuple[tuple[str, ...], str | None]:
    """``tokens`` with `$(NAME)` references expanded as the kubelet expands them, or why they cannot be.

    third_party/forked/golang/expansion/expand.go (v1.31.0): `$$` is one literal `$`; `$(NAME)` is replaced by
    the mapping of NAME; a `$` before anything else, and an unclosed `$(`, are literal. The kubelet's mapping is
    the container's environment: a `$(NAME)` is read here only from a literal `env[].value` in the same
    container (the last entry of that name), never from `valueFrom`, from `envFrom`, from a value that itself
    carries `$(`, or from a name the manifest does not define (the kubelet may add it from a Service), and any of
    those declines with the name. Before this `$$(MODE)` was declined as an expansion the kubelet never performs,
    and `--anonymous-auth=$(ANON)` beside `ANON: "true"` was declined though the value was in the input (G272).
    """
    literal: dict[str, str] = {}
    unreadable: set[str] = set()
    raw_env = container.get("env")
    for e in raw_env if isinstance(raw_env, list) else []:
        if not isinstance(e, dict) or not isinstance(e.get("name"), str):
            continue
        value = e.get("value")
        if "valueFrom" in e or not isinstance(value, str) or "$(" in value:
            unreadable.add(e["name"])
            literal.pop(e["name"], None)
        else:
            literal[e["name"]] = value
            unreadable.discard(e["name"])
    env_from = bool(container.get("envFrom"))
    out: list[str] = []
    for token in tokens:
        if "$" not in token:
            out.append(token)
            continue
        buf: list[str] = []
        i, n = 0, len(token)
        while i < n:
            ch = token[i]
            if ch != "$" or i + 1 >= n:
                buf.append(ch)
                i += 1
                continue
            nxt = token[i + 1]
            if nxt == "$":
                buf.append("$")
                i += 2
            elif nxt == "(":
                close = token.find(")", i + 2)
                if close < 0:
                    buf.append("$(")
                    i += 2
                    continue
                name = token[i + 2 : close]
                if name in literal and name not in unreadable:
                    buf.append(literal[name])
                else:
                    return (), _NO_LITERAL.format(name=_shown(name, 60)) + (
                        " (envFrom may set it)" if env_from and name not in unreadable else ""
                    )
                i = close + 1
            else:
                buf.append("$" + nxt)
                i += 2
        out.append("".join(buf))
    return tuple(out), None


def _basename(token: str) -> str:
    return token.rsplit("/", 1)[-1]


def _image_name(image: object) -> str:
    """The repository's last path segment: `registry.k8s.io/kube-apiserver:v1.34.0` is `kube-apiserver`."""
    if not isinstance(image, str):
        return ""
    return image.split("@", 1)[0].rsplit("/", 1)[-1].partition(":")[0]


def _image_tag(image: object) -> str:
    """The tag after the last `:` of the last path segment, or "" (a digest alone has none)."""
    if not isinstance(image, str):
        return ""
    return image.split("@", 1)[0].rsplit("/", 1)[-1].partition(":")[2]


def _image_is(binary: str, image: str) -> bool:
    """Is ``binary`` a dash-separated run of the image name's components (`etcd-amd64`, `hardened-etcd`,
    `mirrored-coreos-etcd`, `kube-apiserver-amd64`), and no component marks another program (`etcd-operator`)?"""
    parts, want = image.lower().split("-"), binary.split("-")
    if any(p in _IMAGE_NOT_THE_SERVER for p in parts):
        return False
    return any(parts[i : i + len(want)] == want for i in range(len(parts) - len(want) + 1))


def _mentions(binary: str, text: str) -> bool:
    """Does ``text`` name ``binary`` as a command word: bare, or as a path in a `bin` or `sbin` directory, `.` or
    `/`, anywhere -- at the end of a script, before `;`, `&`, `|`, `)` or a newline, after `exec`, `then` or
    `&&`, as `${X:-binary}` -- or as an absolute path from any directory in command position, or as Windows'
    `binary.exe`? Not as a `--flag=` value and not inside a longer name (`etcdctl`, `/var/lib/etcd`,
    `etcd-operator`). Shell quoting is removed first, so `e''tcd`, `"et"cd` and `\\etcd` are etcd. Text longer
    than `_SCRIPT_SCAN` names it if the name is anywhere in it."""
    if len(text) > _SCRIPT_SCAN:
        return binary in text
    # The name must occur at all before any pattern is tried: a 20,000-token argv is scanned for four names by
    # two rules, and the regexes alone took seconds on a shared runner. Quotes can split the name (`e''tcd`), so
    # the second look is at the text with quoting removed, and only when there is quoting to remove.
    if binary not in text:
        quoted = re.search(r"[\"'\\]", text) is not None
        if not quoted or binary not in re.sub(r"[\"'\\]", "", text):
            return False
    pats = _MENTION_PATTERNS.get(binary)
    if pats is None:
        b = re.escape(binary)
        pats = (
            re.compile(_WORD_START + _BIN_DIR + b + r"(?![\w./-])"),
            re.compile(_COMMAND_POSITION + b + r"(?![\w./-])"),
            re.compile(r"(?:^|(?<=[\s\"'&;|(\\/:]))" + b + r"\.exe(?![\w.-])", re.IGNORECASE),
        )
        _MENTION_PATTERNS[binary] = pats
    unquoted = re.sub(r"[\"'\\]", "", text)
    # Command position needs a script: a single argv word such as `/var/lib/etcd` is an argument, and only its
    # `bin` directory could make it the program (the first pattern).
    usable = pats if any(ch.isspace() or ch in ";&|" for ch in text) else (pats[0], pats[2])
    return any(p.search(t) is not None for p in usable for t in {text, unquoted})


def _words(text: str) -> list[str]:
    """The whitespace-separated words of an argv token, a script or an env value, quotes removed."""
    if len(text) > _SCRIPT_SCAN:
        text = text[:_SCRIPT_SCAN]
    return [w.strip("\"'") for w in text.split()]


def _abs_program(binary: str, value: str) -> bool:
    """Is a whole value (an env variable) an absolute path to the binary, from any directory? `BIN=/opt/x/etcd`
    used as `$(BIN)` in command position is the program (G272)."""
    return (
        value.startswith("/") and _basename(value.strip()) == binary and not any(ch.isspace() for ch in value.strip())
    )


def _names(binary: str, token: str) -> bool:
    """Is one argv token the binary: bare, or a path whose directory is `*/bin`, `*/sbin`, `/` or `.`, or a
    Windows `binary.exe` in any directory? Never a `--flag=value`, never `/var/lib/etcd` (G272)."""
    if len(token) > _SCRIPT_SCAN:
        return False
    if re.split(r"[\\/]", token)[-1].lower() == f"{binary}.exe":
        return True
    return re.fullmatch(_BIN_DIR + re.escape(binary), token) is not None


def _expands(tokens: tuple[str, ...]) -> bool:
    """Does any argv token carry a `$(VAR)` the kubelet expands, whose value is not in the manifest?"""
    return any("$(" in t for t in tokens)


def _is_hint(token: str, hints: frozenset[str]) -> bool:
    """A flag token naming one of the binary's own flags (`_` read as `-`, as kube-apiserver reads it)."""
    return token.startswith("-") and token.lstrip("-").partition("=")[0].replace("_", "-") in hints


def _after_launchers(argv: list[str]) -> list[str] | None:
    """The argv a chain of `env ...` and `busybox APPLET` prefixes finally runs, or None when it cannot be read.

    `env` takes options (`-i`, `-u NAME`, `-C DIR`, `--`) and `NAME=VALUE` assignments before the command; `-S`
    splits a string into a command line of its own, and an option not listed here may take a value, so both
    are unreadable rather than guessed. `busybox sh` is the `sh` applet. An `env` with no command prints the
    environment and starts nothing: an empty list.
    """
    for _ in range(_LAUNCHER_DEPTH):
        if not argv:
            return argv
        head = _basename(argv[0])
        if head == "busybox" and len(argv) > 1:
            argv = argv[1:]
            continue
        if head != "env":
            return argv
        i = 1
        while i < len(argv):
            t = argv[i]
            if t == "--":
                i += 1
                break
            if t in _ENV_VALUE_OPTIONS:
                i += 2
            elif t in _ENV_FLAG_OPTIONS or t.startswith(("--unset=", "--chdir=")) or (t[:2] in {"-u", "-C"} and t[2:]):
                i += 1
            elif t.startswith("-"):
                return None  # -S / --split-string, or an option whose argument handling is not read here
            elif "=" in t:
                i += 1  # NAME=VALUE
            else:
                break
        argv = argv[i:]
    return None


def _inline_script(argv: list[str]) -> str | None:
    """The `-c` script of a shell argv, or None when it runs a script file or stdin instead."""
    i, inline = 1, False
    while i < len(argv):
        t = argv[i]
        if t == "--" or not t.startswith(("-", "+")) or t in {"-", "+"}:
            break
        if t.startswith("-") and not t.startswith("--") and "c" in t[1:]:
            inline = True
        i += 2 if t in {"-o", "+o", "-O", "+O"} else 1
    if not inline:
        return None
    if i < len(argv) and argv[i] == "--":
        i += 1
    return argv[i] if i < len(argv) else ""


def _only_etcd_clients(script: str) -> bool:
    """Is every command this script can run etcdctl, etcdutl or a builtin/coreutil that starts nothing else?

    The narrow rule for a shell on the etcd image (G272): the whole script is read (it is under `_SCRIPT_SCAN`),
    every command position -- the first word after the start, `;`, `&`, `|`, `(`, `)`, `{`, `}`, a newline, a
    keyword such as `then` or `do`, and inside `$(...)` and backquotes -- after leading `NAME=value`
    assignments is one of `_ETCD_SCRIPT_SAFE`, and there is no `exec`, `.`, `source`, `eval`, path or variable in
    command position. Anything else, or anything not parsed, is not this rule's to call safe.
    """
    if len(script) > _SCRIPT_SCAN or "\\" in script:
        return False
    segments: list[str] = []
    rest = script
    for _ in range(64):  # command substitutions, innermost first
        m = re.search(r"\$\(([^()]*)\)|`([^`]*)`", rest)
        if m is None:
            break
        segments.append(m.group(1) if m.group(1) is not None else m.group(2))
        rest = rest[: m.start()] + "X" + rest[m.end() :]
    else:
        return False
    if "$(" in rest or "`" in rest:
        return False
    segments.append(rest)
    for seg in segments:
        for part in re.split(r"[;&|(){}\n]", seg):
            words = part.split()
            while words and (words[0] in _SHELL_KEYWORDS or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=\S*", words[0])):
                words = words[1:]
            if words and words[0] not in _ETCD_SCRIPT_SAFE:
                return False
    return True


def _embedded_subcommand(argv: list[str]) -> tuple[int, str] | None:
    """(index, subcommand) of an embedding binary's argv after its global flags, or None when a global flag of
    unknown arity hides it. `k3s --debug server` and `k3s --data-dir /data server` are servers (G272)."""
    i = 1
    while i < len(argv):
        t = argv[i]
        if not t.startswith("-"):
            return i, t
        name, eq, _ = t.lstrip("-").partition("=")
        if eq or name in _EMBEDDING_GLOBAL_BOOLS:
            i += 1
        elif name in _EMBEDDING_GLOBAL_VALUES:
            i += 2
        else:
            return None
    return i, ""


@dataclass(frozen=True)
class _Launch:
    """How a container runs a control-plane binary: its flags when they can be read, else why they cannot."""

    tokens: tuple[str, ...] = ()
    #: How many argv tokens come before the flags (the binary, or `hyperkube` and the binary).
    skip: int = 0
    declined: str = ""
    #: The container MAY run the binary -- its image, flags or a mention say so -- through something not read.
    maybe: bool = False
    #: The embedding binary (`k3s`) whose server subcommand runs it: `tokens` are that subcommand's arguments.
    embedded: str = ""


def _launch(
    c: dict[str, Any],
    binary: str,
    hints: frozenset[str],
    env_prefix: str | None,
    script_hints: frozenset[str] = frozenset(),
) -> _Launch | None:
    """Recognise a container that runs ``binary``, or None when it positively does not.

    FAIL-SAFE (G272, third review): a container is "not this server" only when NOTHING points at the binary --
    no image whose name has it as a component, no flag of its own (``hints``) in argv, no ``env_prefix``
    variable, no mention of it or of an embedding binary as a command word in argv, args, env values or a
    script -- or when it is positively something else: the binary's own client (`etcdctl`), an embedding
    binary's other subcommand (`k3s agent`), or a script on the etcd image made only of etcdctl and coreutils.
    ``script_hints`` (etcd's `--config-file`) count only beside a script entrypoint, where half the programs in a
    cluster do not take them. Read directly: `command[0]` is the binary, or `hyperkube` followed by it; and an
    embedding server, whose `--kube-apiserver-arg` values the rule reads. Every other shape with evidence is
    DECLINED with the reason: a shell whose script names it, a wrapper with the binary later in argv, no
    `command` or an empty one (the image's entrypoint), a script file, any other entrypoint, a non-string argv.
    """
    command, args = c.get("command"), c.get("args")

    def strings(v: object) -> list[str]:
        if isinstance(v, str):
            return [v]
        return [t for t in v if isinstance(t, str)] if isinstance(v, list) else []

    texts = [*strings(command), *strings(args)]
    raw_env = c.get("env")
    env = [e for e in raw_env if isinstance(e, dict)] if isinstance(raw_env, list) else []
    env_names = [str(e.get("name") or "") for e in env]
    env_values = [v for e in env if isinstance(v := e.get("value"), str)]
    image = _image_name(c.get("image"))
    own_image = _image_is(binary, image) or (
        binary == "kube-apiserver" and (image.lower() in _APISERVER_IMAGE_NAMES or _image_is("hyperkube", image))
    )
    embed_image = next((e for e in sorted(_EMBEDDING) if _image_is(e, image)), "")
    mentioned = any(_mentions(binary, t) for t in [*texts, *env_values]) or any(
        _abs_program(binary, v) for v in env_values
    )
    embed_mention = next((e for e in sorted(_EMBEDDING) if any(_mentions(e, t) for t in texts)), "")
    # Flag words inside a script or an env value count as much as a whole argv token (G272): `sh -c "exec $BIN
    # --etcd-servers=..."` carries the API server's flags whatever $BIN is.
    flagged = any(_is_hint(w, hints) for t in [*texts, *env_values] for w in _words(t))
    raw_from = c.get("envFrom")
    prefixes = (
        [str(e.get("prefix") or "") for e in raw_from if isinstance(e, dict)] if isinstance(raw_from, list) else []
    )
    settings = env_prefix is not None and (
        any(n.startswith(env_prefix) for n in env_names) or any(p.startswith(env_prefix) for p in prefixes)
    )
    evidence = bool(own_image or embed_image or mentioned or embed_mention or flagged or settings)

    def why() -> str:
        if own_image:
            return f"its image is {binary}'s"
        if embed_image:
            return f"its image is {embed_image}'s, which runs {binary} inside it"
        if mentioned:
            return f"an argument names {binary}"
        if embed_mention:
            return f"an argument names {embed_mention}, which runs {binary} inside it"
        if flagged:
            return f"its arguments carry {binary}'s flags"
        return f"it sets {env_prefix}* variables, which are {binary}'s settings"

    if command is None or command == []:
        # `command: []` is accepted and means the same as no command: the image's ENTRYPOINT (omitempty), with
        # `args` as its arguments. The first review only took this branch for a missing key (G272).
        if evidence:
            return _Launch(
                declined="with no command (or an empty one), so it runs its image's entrypoint, which the manifest "
                f"does not state, while {why()}",
                maybe=True,
            )
        return None
    readable = (
        isinstance(command, list)
        and all(isinstance(t, str) for t in command)
        and (args is None or (isinstance(args, list) and all(isinstance(t, str) for t in args)))
    )
    if not readable or not isinstance(command, list):
        if evidence:
            return _Launch(
                declined="with a command or args that are not a list of strings, which the API server refuses"
            )
        return None
    argv: list[str] = [*command, *(args if isinstance(args, list) else [])]
    head = _basename(argv[0])
    if head == binary:
        return _Launch(tuple(argv[1:]), 1)
    if head == "hyperkube" and len(argv) > 1 and argv[1] == binary:
        return _Launch(tuple(argv[2:]), 2)
    if head == "hyperkube" and binary == "kube-apiserver" and len(argv) > 1 and argv[1] == "apiserver":
        return _Launch(declined="through hyperkube's 'apiserver' alias, which is not read")
    inner = _after_launchers(argv)
    target = inner if inner else []
    offset = len(argv) - len(target)
    thead = _basename(target[0]) if target else ""
    if thead in _EMBEDDING:
        found = _embedded_subcommand(target)
        if found is None:
            return _Launch(
                declined=f"possibly inside {thead}, whose global flags before the subcommand are not all read, so "
                "which subcommand it runs is not known",
                maybe=True,
            )
        idx, sub = found
        if sub in _EMBEDDING_SERVER[thead]:
            return _Launch(tuple(target[idx + 1 :]), offset + idx + 1, embedded=thead)
        return None  # read: another subcommand (`k3s agent`, `k3s kubectl`), which runs no control plane
    if thead in _SIBLINGS.get(binary, ()):
        return None  # read: the binary's own client (`etcdctl`), not its server
    if thead in _SHELLS:
        script = _inline_script(target)
        if any(_mentions(e, t) for t in target[1:] for e in (binary, *_EMBEDDING)):
            return _Launch(declined="from a shell script, whose flags are not read")
        if not evidence:
            return None  # an inline script that does not run it, or a script file with nothing pointing at it
        if (
            binary == "etcd"
            and script is not None
            and own_image
            and not (flagged or settings or mentioned or embed_mention)
            and _only_etcd_clients(script)
        ):
            return None  # read: a backup or wait script on the etcd image that runs only etcdctl and coreutils
        if script is None:
            return _Launch(declined="from a script file the shell runs, which is not read", maybe=True)
        return _Launch(
            declined=f"from a shell script that runs commands kube-noob does not read, while {why()}", maybe=True
        )
    if inner and inner is not argv and _names(binary, inner[0]):
        return _Launch(declined=f"through {_quoted(head, 80)}, whose handling of the arguments is not read")
    if any(_names(binary, t) for t in argv[1:]):
        return _Launch(declined=f"through {_quoted(head, 80)}, whose handling of the arguments is not read")
    script_entry = bool(target) and target[0].endswith(".sh")
    if not evidence and script_entry and any(_is_hint(t, script_hints) for t in texts):
        return _Launch(
            declined=f"through {_quoted(head, 80)}, a script kube-noob does not read, with {binary}'s "
            "configuration-file flag",
            maybe=True,
        )
    if evidence:
        return _Launch(
            declined=f"through {_quoted(head, 80)}, an entrypoint kube-noob does not read, while {why()}",
            maybe=True,
        )
    return None


def _flag_values(
    tokens: tuple[str, ...] | list[str],
    names: frozenset[str],
    bools: frozenset[str],
    single_dash: bool,
    *,
    pflag: bool = False,
) -> tuple[dict[str, list[tuple[str, int]]], str | None]:
    """Every value given for each flag in ``names``, in order, with the index of its token -- or why not.

    pflag (kube-apiserver) reads `--name` and one-letter `-x` shorthands; Go's `flag` package (etcd) reads `-name`
    too (``single_dash``). A known boolean (``bools``) given bare is true and never consumes the next token; any
    other flag given without `=` takes the next token whatever it looks like, as both parsers do. So when a flag
    kube-noob does not know is given without `=` and followed by a token that starts with `-`, whether that next
    flag is real or swallowed as a value depends on a flag table this rule does not carry: declined, in both
    directions (G272). Also declined: a known value flag with no value or with a flag as its value, an argument
    that is not a flag (a subcommand, or a value whose flag is not known), anything after `--`, and syntax both
    parsers refuse (`---x`, `--=x`, `-=x`).

    With ``pflag``: `_` in a flag name is `-` (component-base's cli.Run sets WordSepNormalizeFunc, so
    `--authorization_mode` IS `--authorization-mode`); `-h` is `--help` (a boolean) and `-v` is klog's verbosity
    (it takes a value, attached or as the next token). Without it -- Go's `flag` package -- `-h` and `-help` stop
    the parse there with ErrHelp, so nothing after them is read, as etcd does not read it.
    """
    out: dict[str, list[tuple[str, int]]] = {}
    i, n = 0, len(tokens)
    while i < n:
        t = tokens[i]
        nxt = tokens[i + 1] if i + 1 < n else None
        if t == "--":
            if i + 1 < n:
                return out, f"passes {_quoted(tokens[i + 1], 80)} after '--', as an argument rather than a flag"
            break
        if t.startswith(("---", "--=", "-=")):
            return out, f"has {_quoted(t, 80)}, which its flag parser refuses as bad syntax, so it does not start"
        if t.startswith("--"):
            body, long = t[2:], True
        elif t.startswith("-") and len(t) > 1:
            body, long = t[1:], single_dash
            if pflag and t[1] == "h":
                out.setdefault("help", []).append((t[3:] if t[2:3] == "=" else "true", i))
                i += 1
                continue
            if pflag and t[1] == "v":
                if len(t) == 2:
                    if nxt is None or nxt.startswith("-"):
                        return out, f"gives -v no value before {_quoted(nxt, 80) if nxt else 'the end'}"
                    i += 1
                i += 1
                continue
        else:
            return out, f"has an argument {_quoted(t, 80)} that is not a flag (a subcommand, or a stray value)"
        name, eq, value = body.partition("=")
        if long and _FLAG_NAME.fullmatch(name) is None:
            # Every kube-apiserver and etcd flag is words of lowercase letters and digits, starting with a
            # letter, joined by single dashes (pflag adds `_` as a separator, which WordSepNormalizeFunc turns
            # into `-`): a name with an uppercase letter, a dot, a trailing dash (`--anonymous-auth-`), digits
            # alone (`--123`) or anything else is one neither binary defines, and pflag's parseLongArg (v1.0.5
            # flag.go L962-979) errors on an unknown flag -- UnknownFlags is not whitelisted -- so the server
            # does not start. Before G272's fifth review `--Anonymous-Auth=true` was read as a MEDIUM finding,
            # and before the sixth `--anonymous-auth-=true` was skipped and the defaults reported. A misspelling
            # of that shape (`--anonymous-ath`) is still read as a stray flag: the full flag table is per release
            # and is not carried here.
            binary = "kube-apiserver" if pflag else "etcd"
            return out, (
                f"has {_quoted(t, 80)}: {binary} has no such flag; its flag parser refuses it, so this server does "
                "not start"
            )
        if pflag:
            name = name.replace("_", "-")
        elif "_" in name:
            # Go's flag package has no normaliser and etcd defines no flag with `_` in it: an undefined flag,
            # which ends the parse with an error, so the server does not start (G272).
            return out, f"has {_quoted(t, 80)}, a flag Go's flag parser does not define, so it does not start"
        if long and not pflag and name in {"h", "help"}:
            out.setdefault("help", []).append(("true", i))
            break  # Go's flag package returns ErrHelp here and reads nothing further
        if eq:
            if long and name in names:
                out.setdefault(name, []).append((value, i))
        elif long and name in bools:
            if name in names:
                out.setdefault(name, []).append(("true", i))
        elif long and name in names:
            if nxt is None or nxt.startswith("-"):
                return out, f"gives --{name} no value before {_quoted(nxt, 80) if nxt else 'the end'}"
            out.setdefault(name, []).append((nxt, i + 1))
            i += 1
        elif nxt is not None and nxt.startswith("-"):
            return out, (
                f"has {_quoted(t, 80)} followed by {_quoted(nxt, 80)}: whether {_quoted(t, 80)} takes a value, and so "
                "swallows the next flag, is not known here"
            )
        elif nxt is not None:
            i += 1  # its value, or a positional the binary refuses; either way not one of these flags
        i += 1
    return out, None


def _exits_at_once(flags: dict[str, list[tuple[str, int]]], pflag: bool) -> bool | str:
    """True when `--help` or `--version` makes the binary print and exit (not a server), False when it serves,
    or why that cannot be read.

    Only values at real flag positions count: `--etcd-prefix --version` gives --etcd-prefix the value, and that
    shape is declined by `_flag_values` before this is asked (G272). kube-apiserver's --version (component-base
    verflag) prints for `true` and `raw`, serves for `false` and for `vX.Y.Z` (which sets the reported version),
    and refuses anything else; the last occurrence wins. etcd's -version is a Go boolean; its -h/-help is not a
    defined flag, so Go's parser stops with ErrHelp wherever it appears.
    """
    helps = flags.get("help", [])
    if helps and not pflag:
        return True
    verdict: bool | str = False
    for name, values in (("help", helps), ("version", flags.get("version", []))):
        for value, _ in values:
            sets_version = pflag and name == "version" and (value == "raw" or value.startswith("v"))
            if not sets_version and _go_bool(value) is None:
                return f"sets --{name}={_quoted(value, 60)}, a value its flag parser refuses, so it does not start"
        if values and (values[-1][0] == "raw" or _go_bool(values[-1][0])):
            verdict = True
    return verdict


#: strconv.ParseBool, which both pflag and Go's flag package use for a boolean flag's value.
_GO_TRUE = frozenset({"1", "t", "T", "TRUE", "true", "True"})
_GO_FALSE = frozenset({"0", "f", "F", "FALSE", "false", "False"})


def _go_bool(value: str) -> bool | None:
    return True if value in _GO_TRUE else False if value in _GO_FALSE else None


#: The insecure (unauthenticated, unauthorized) port, as each release reads it. Read from the source at each tag:
#: v1.18.0 and v1.19.0 staging/src/k8s.io/apiserver/pkg/server/options/deprecated_insecure_serving.go register
#: --insecure-bind-address and --address on ONE variable, --insecure-port and --port on another (L70, L76, L89,
#: L94 at v1.19.0), with kube-apiserver's defaults 127.0.0.1 and 8080 (pkg/kubeapiserver/options/serving.go
#: L47-48) and no serving at a port <= 0; v1.20.0, v1.21.0 and v1.23.0 keep all four as dummies on shared
#: variables and cmd/kube-apiserver/app/server.go checkNonZeroInsecurePort refuses to start on a non-zero port
#: (L91-102 at v1.20.0); v1.24.0 removed them, so the server refuses any of them as an unknown flag (G272).
INSECURE_PORT_REFUSED = (1, 20)
INSECURE_PORT_REMOVED = (1, 24)
_INSECURE_PORT_FLAGS = ("insecure-port", "port")
_INSECURE_ADDRESS_FLAGS = ("insecure-bind-address", "address")
INSECURE_FLAGS = frozenset({*_INSECURE_PORT_FLAGS, *_INSECURE_ADDRESS_FLAGS})
#: The shape of every flag name kube-apiserver (pflag, `_` normalised to `-`) and etcd (Go's flag package, no
#: normaliser) define: words of lowercase letters and digits, the first starting with a letter, joined by single
#: separators -- never a leading digit, a trailing separator or two separators in a row (G272).
_FLAG_NAME = re.compile(r"[a-z][a-z0-9]*(?:[-_][a-z0-9]+)*")
_GO_INT = re.compile(
    r"[+-]?(?:0[xX](?:_?[0-9a-fA-F])+|0[bB](?:_?[01])+|0[oO](?:_?[0-7])+|0(?:_?[0-7])*|[1-9](?:_?[0-9])*)"
)


def _pflag_int(value: str) -> int | None:
    """pflag IntVar's parse, strconv.ParseInt(s, 0, 64): a base prefix, a leading 0 for octal (`08080` is
    refused), underscores only between digits. None when pflag refuses it."""
    if _GO_INT.fullmatch(value) is None:
        return None
    sign, body = (-1, value[1:]) if value[:1] == "-" else (1, value.lstrip("+"))
    body = body.replace("_", "")
    if body[:2].lower() in {"0x", "0b", "0o"}:
        return sign * int(body, 0)
    return sign * (int(body[1:], 8) if body.startswith("0") and len(body) > 1 else int(body))


def _pflag_ip(value: str) -> bool | None:
    """pflag IPVar's parse, `net.ParseIP(strings.TrimSpace(s))` (pflag ip.go, ipValue.Set): None when refused,
    else whether the address is loopback. Surrounding whitespace is trimmed, as pflag trims it -- `= 0.0.0.0`
    serves on 0.0.0.0 and was declined as refused (G272, sixth review). Go's net.ParseIP takes no zone
    (`fe80::1%eth0` is refused), where Python's ip_address would accept one."""
    import ipaddress

    value = value.strip()
    if "%" in value:
        return None
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return None


def insecure_serving(
    flags: dict[str, list[tuple[str, int]]], version_stated: bool, minor: tuple[int, int], target: str
) -> tuple[str, str, int] | None:
    """("finding", what it serves, the argv index to point at), ("decline", why, -1), or None (nothing to say).

    The last occurrence across both names of a pair wins, because both names set one variable. CRITICAL only on
    a stated release up to 1.19, with an effective port above 0 on an address that is not loopback (the port is
    8080 when only the address is given). 1.20 to 1.23 refuse a non-zero port; from 1.24, and on an assumed
    version, any of the four flags declines.
    """
    ports = sorted((o for f in _INSECURE_PORT_FLAGS for o in flags.get(f, [])), key=lambda o: o[1])
    addrs = sorted((o for f in _INSECURE_ADDRESS_FLAGS for o in flags.get(f, [])), key=lambda o: o[1])
    if not ports and not addrs:
        return None
    if not version_stated or minor >= INSECURE_PORT_REMOVED:
        return (
            "decline",
            "sets --insecure-port, --port, --insecure-bind-address or --address, which Kubernetes 1.24 removed: on "
            f"the target ({target}) the server refuses to start with them, or it runs an older release than the one "
            "audited",
            -1,
        )
    for value, _ in ports:
        parsed = _pflag_int(value)
        if parsed is None:
            return (
                "decline",
                f"sets an insecure port of {_quoted(value, 40)}, which pflag refuses, so it does not start",
                -1,
            )
        if not 0 <= parsed <= 65535:
            # DeprecatedInsecureServingOptions.Validate (v1.19.0 L57): "must be between 0 and 65535, inclusive"
            return (
                "decline",
                f"sets an insecure port of {parsed}, outside 0-65535, which the API server refuses, so it does not "
                "start",
                -1,
            )
    for value, _ in addrs:
        if _pflag_ip(value) is None:
            return (
                "decline",
                f"sets an insecure address of {_quoted(value, 60)}, which pflag refuses, so it does not start",
                -1,
            )
    port = _pflag_int(ports[-1][0]) if ports else None
    if minor >= INSECURE_PORT_REFUSED:
        if port:
            return (
                "decline",
                "sets a non-zero insecure port, and the API server refuses to start with a non-zero insecure port "
                "(1.20–1.23, checkNonZeroInsecurePort)",
                -1,
            )
        return None
    effective_port = 8080 if port is None else port
    address = addrs[-1][0].strip() if addrs else "127.0.0.1"
    if effective_port <= 0 or _pflag_ip(address):
        return None
    index = ports[-1][1] if ports else addrs[-1][1]
    said = "the default port 8080" if port is None else f"port {effective_port}"
    return ("finding", f"serves the insecure port ({said}) on {_quoted(address, 60)}", index)
