"""Shell completion scripts, generated from the parser so they cannot drift from the CLI.

Hand-written completions go stale the moment a subcommand is added, and a stale completion is worse than
none: it teaches the wrong command. These are walked off ``build_parser()`` at generation time, so a
command that exists is offered and a command that was removed stops being offered.
"""

from __future__ import annotations

import argparse
import shlex
from typing import Any

SHELLS = ("bash", "zsh", "fish")


def _options(parser: argparse.ArgumentParser) -> list[str]:
    out: list[str] = []
    for action in parser._actions:
        out.extend(s for s in action.option_strings if s.startswith("--"))
    return sorted(set(out))


def _subcommands(parser: argparse.ArgumentParser) -> dict[str, argparse.ArgumentParser]:
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return dict(action.choices)
    return {}


def tree(parser: argparse.ArgumentParser) -> dict[str, Any]:
    """``{"options": [...], "commands": {name: {same shape}}}`` for the whole CLI."""
    return {
        "options": _options(parser),
        "commands": {name: tree(sub) for name, sub in sorted(_subcommands(parser).items())},
    }


def _flat(node: dict[str, Any], prefix: tuple[str, ...] = ()) -> list[tuple[tuple[str, ...], list[str], list[str]]]:
    rows = [(prefix, sorted(node["commands"]), node["options"])]
    for name, child in node["commands"].items():
        rows.extend(_flat(child, (*prefix, name)))
    return rows


def _bash(node: dict[str, Any], prog: str) -> str:
    lines = [
        f"# {prog} completion for bash. Regenerate with: {prog} completion bash",
        f"_{prog.replace('-', '_')}_complete() {{",
        "    local cur prev words cword; COMPREPLY=()",
        '    cur="${COMP_WORDS[COMP_CWORD]}"',
        '    local path="" i',
        "    for ((i=1; i<COMP_CWORD; i++)); do",
        '        case "${COMP_WORDS[i]}" in -*) ;; *) path="$path ${COMP_WORDS[i]}" ;; esac',
        "    done",
        '    path="${path# }"',
        '    case "$path" in',
    ]
    for prefix, commands, options in _flat(node):
        pattern = " ".join(prefix) if prefix else ""
        words = " ".join([*commands, *options])
        case_pat = shlex.quote(pattern) if pattern else '""'
        lines.append(f"        {case_pat}) __kn_words={shlex.quote(words)} ;;")
    lines += [
        "        *) __kn_words= ;;",
        "    esac",
        '    mapfile -t COMPREPLY < <(compgen -W "$__kn_words" -- "$cur")',
        "}",
        f"complete -F _{prog.replace('-', '_')}_complete {prog}",
    ]
    return "\n".join(lines) + "\n"


def _zsh(node: dict[str, Any], prog: str) -> str:
    lines = [
        f"#compdef {prog}",
        f"# {prog} completion for zsh. Regenerate with: {prog} completion zsh",
        f"_{prog.replace('-', '_')}() {{",
        '    local -a words_for; local path="" w',
        "    for w in ${words[2,$((CURRENT-1))]}; do",
        '        case "$w" in -*) ;; *) path="${path} ${w}" ;; esac',
        "    done",
        '    path="${path# }"',
        '    case "$path" in',
    ]
    for prefix, commands, options in _flat(node):
        pattern = " ".join(prefix) if prefix else ""
        words = " ".join([*commands, *options])
        case_pat = shlex.quote(pattern) if pattern else '""'
        lines.append(f"        {case_pat}) words_for=({words}) ;;")
    lines += [
        "        *) words_for=() ;;",
        "    esac",
        '    compadd -- "${words_for[@]}"',
        "}",
        f'_{prog.replace("-", "_")} "$@"',
    ]
    return "\n".join(lines) + "\n"


def _fish(node: dict[str, Any], prog: str) -> str:
    lines = [f"# {prog} completion for fish. Regenerate with: {prog} completion fish"]
    for prefix, commands, options in _flat(node):
        if not prefix:
            cond = "__fish_use_subcommand"
        else:
            cond = "__fish_seen_subcommand_from " + " ".join(prefix)
        for c in commands:
            lines.append(f"complete -c {prog} -n {shlex.quote(cond)} -f -a {shlex.quote(c)}")
        for o in options:
            lines.append(f"complete -c {prog} -n {shlex.quote(cond)} -l {shlex.quote(o.lstrip('-'))}")
    return "\n".join(lines) + "\n"


def script(shell: str, parser: argparse.ArgumentParser, prog: str = "kube-noob") -> str:
    """The completion script for ``shell``, walked off ``parser``."""
    if shell not in SHELLS:
        raise ValueError(f"Unknown shell {shell!r}; use one of {', '.join(SHELLS)}")
    node = tree(parser)
    return {"bash": _bash, "zsh": _zsh, "fish": _fish}[shell](node, prog)
