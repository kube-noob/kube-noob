"""Classify troubleshooting steps so read-only evidence always comes first.

- ``read``:   observes state without changing it (get, describe, logs, events, can-i, registry inspect, offline audit)
- ``exec``:   runs something inside a container, on a node or against the network (rsh, exec, debug, curl, openssl);
              still non-mutating by intent, but it executes code, so it needs explicit approval
- ``change``: mutates cluster, release or cloud state (apply, delete, patch, scale, rollout, drain, helm upgrade,
              rosa edit ...); always requires approval and never appears in a playbook's checks
Unknown commands are treated as ``exec`` (approval required), never as ``read``.
"""

from __future__ import annotations

import re
from typing import Literal

StepKind = Literal["read", "exec", "change"]

_KUBE_READ = {
    "get",
    "describe",
    "logs",
    "events",
    "explain",
    "api-resources",
    "api-versions",
    "version",
    "whoami",
    "status",
    "top",
    "wait",
    # Print information and change nothing; the pre-action hook (G280) would otherwise block each of them, because
    # a subcommand this table does not name is treated as a change.
    "cluster-info",
    "completion",
    "help",
    "options",
    "projects",
}
_KUBE_EXEC = {"rsh", "exec", "debug", "port-forward", "attach", "proxy", "rsync", "cp"}
# `oc adm policy scc-subject-review` / `scc-review` / `who-can` evaluate policy and never grant anything
_ADM_POLICY_READ = re.compile(r"\b(scc-subject-review|scc-review|who-can)\b")
_HELM_READ = {"status", "history", "get", "list", "ls", "show", "template", "lint", "search", "env", "version"}
_ROSA_READ = {"describe", "list", "logs", "verify", "whoami", "version"}
_LOCAL_READ = {"skopeo": {"inspect"}, "roxctl": {"deployment", "image"}}
_NETWORK_EXEC = {"curl", "wget", "openssl", "dig", "nslookup", "nc", "ping", "getent"}
_LOCAL_INFO = {"date", "hostname", "uname", "id"}  # read the local machine only
_KUBECONFIG_READ = {"view", "current-context", "get-contexts", "get-clusters"}


def split_comment(text: str) -> tuple[str, str | None]:
    """Split ``cmd  # why`` into the bare command and its note. A ``#`` inside quotes or glued to a word is data.

    Commands shown to users never carry trailing comments: zsh (the macOS default) passes ``#`` and every word after
    it as arguments unless ``interactivecomments`` is set, so a pasted ``oc logs x  # note`` fails.
    """
    quote: str | None = None
    for i, ch in enumerate(text):
        if quote:
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
        elif ch == "#" and (i == 0 or text[i - 1].isspace()):
            why = text[i + 1 :].strip()
            return text[:i].rstrip(), why or None
    return text.rstrip(), None


_RANK = {"read": 0, "exec": 1, "change": 2}
_TEXT_FILTERS = {
    "grep",
    "egrep",
    "fgrep",
    "awk",
    "sort",
    "uniq",
    "head",
    "tail",
    "wc",
    "cut",
    "tr",
    "column",
    "less",
    "more",
    "cat",
    "yq",
    "jq",
    "base64",
    "sed",
    "tee",
    "nl",
    "xxd",
    "true",
}
_ENV_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=\S*\Z")


def _segments(cmd: str) -> list[str]:
    """Split a shell line on |, ||, &&, ; outside quotes."""
    parts: list[str] = []
    buf: list[str] = []
    quote: str | None = None
    i = 0
    while i < len(cmd):
        ch = cmd[i]
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
            buf.append(ch)
        elif ch in "|;&":
            if ch == "&" and cmd[i : i + 2] != "&&":
                buf.append(ch)
            else:
                parts.append("".join(buf))
                buf = []
                if cmd[i : i + 2] in {"||", "&&"}:
                    i += 1
        else:
            buf.append(ch)
        i += 1
    parts.append("".join(buf))
    return [p.strip() for p in parts if p.strip()]


#: kubectl's global flags that take a value as the next word (kubernetes/cli-runtime
#: pkg/genericclioptions/config_flags.go and kubernetes/kubectl pkg/cmd/cmd.go, master, read 2026-11-12). They may
#: come before the subcommand: `kubectl -n shop get pods` reads, and was classified as a change.
KUBE_GLOBAL_VALUE_FLAGS = frozenset(
    {
        "-n",
        "--namespace",
        "--context",
        "--kubeconfig",
        "--cluster",
        "--user",
        "-s",
        "--server",
        "--token",
        "--as",
        "--as-group",
        "--as-uid",
        "--as-user-extra",
        "--certificate-authority",
        "--client-certificate",
        "--client-key",
        "--tls-server-name",
        "--request-timeout",
        "--cache-dir",
        "--proxy-url",
        "--username",
        "--password",
        "-v",
        "--v",
        "--vmodule",
        "--log-flush-frequency",
        "--profile",
        "--profile-output",
        # kubectl's preferences file (kubernetes/kubectl pkg/kuberc/kuberc.go, AddFlags): its aliases can make
        # `get` run `delete`, so `--kuberc FILE get` was read as a get.
        "--kuberc",
    }
)
#: Names a kubectl runs under: the binary, the `k` alias the Kubernetes docs suggest
#: (kubernetes.io/docs/reference/kubectl/quick-reference/, `alias k=kubectl`) and kubecolor, which passes its
#: arguments to kubectl.
KUBE_CLIS = frozenset({"oc", "kubectl", "k", "kubecolor"})
#: `--dry-run` with no value means client (kubectl pkg/cmd/util/helpers.go GetDryRunStrategy: NoOptDefVal
#: "unchanged" -> DryRunClient, and the deprecated boolean `true` -> DryRunClient). `server` still sends the request
#: with dryRun=All, which kube-noob treats as the dry-run tier (D), so it stays a change.
_DRY_RUN_CLIENT = frozenset({"client", "unchanged", "true"})
#: kubectl verbs whose own command table defines `--dry-run` (kubernetes/kubectl pkg/cmd/*, master, read 2026-11-13),
#: plus `oc new-app`. Only on these does the flag mean a dry run: on `exec`, `debug` or a plugin it is an argument
#: of whatever runs (`kubectl someplugin --dry-run=client` was read as a read).
DRY_RUN_VERBS = frozenset(
    {"apply", "create", "delete", "patch", "replace", "scale", "autoscale", "label", "annotate", "set", "expose",
     "run", "rollout", "taint", "drain", "cordon", "uncordon", "new-app"}
)  # fmt: skip


#: kubectl's root flags that take no value: pflag bool flags, whose no-option default is "true", so cobra does not
#: take the next word for them (cli-runtime config_flags.go: --insecure-skip-tls-verify, --disable-compression;
#: kubectl cmd.go: --match-server-version, --warnings-as-errors; cobra's own --help/-h).
KUBE_GLOBAL_BOOL_FLAGS = frozenset(
    {"--insecure-skip-tls-verify", "--disable-compression", "--match-server-version", "--warnings-as-errors", "--help",
     "-h"}
)  # fmt: skip


def kube_root(args: list[str]) -> tuple[str, str, int, list[str]]:
    """How cobra finds kubectl's subcommand, and the root flags kubectl does not define.

    cobra v1.10.2 command.go stripFlags (lines 674-710): before the subcommand, a `--flag` without `=` and a
    two-letter `-f` take the NEXT WORD as their value unless the flag has a no-option default (a bool), whether or
    not the root command defines the flag -- so `kubectl -f x apply` runs apply, `kubectl -o yaml delete ns prod`
    runs delete, and `kubectl --log-file f delete ...` runs delete. `--` ends the search; a word after it is not a
    subcommand cobra finds, so `kubectl -n prod -- delete ns prod` is returned as the subcommand `--` (not read).

    Returns (subcommand, the first word after it that is not a flag, its index, unknown root flags)."""
    i = 0
    unknown: list[str] = []
    while i < len(args):
        t = args[i]
        if t == "--":
            rest = args[i + 1 :]
            return ("--", rest[0], i, unknown) if rest else ("", "", -1, unknown)
        if t.startswith("-") and t != "-":
            name = t.split("=", 1)[0]
            attached = not name.startswith("--") and len(name) > 2 and name[:2] in KUBE_GLOBAL_VALUE_FLAGS
            if name not in KUBE_GLOBAL_VALUE_FLAGS and name not in KUBE_GLOBAL_BOOL_FLAGS and not attached:
                unknown.append(name)
            takes = "=" not in t and (
                (t.startswith("--") and name not in KUBE_GLOBAL_BOOL_FLAGS) or (len(t) == 2 and t != "-h")
            )
            i += 2 if takes else 1
            continue
        rest = args[i + 1 : args.index("--", i + 1) if "--" in args[i + 1 :] else len(args)]
        nxt = next((a for a in rest if not a.startswith("-")), "")
        return t, nxt, i, unknown
    return "", "", -1, unknown


def kube_subcommand(args: list[str]) -> tuple[str, str, int]:
    """The subcommand, the first word after it that is not a flag, and the subcommand's index in ``args`` (-1 when
    there is none), found the way cobra finds it (see kube_root)."""
    sub, nxt, idx, _ = kube_root(args)
    return sub, nxt, idx


def dry_run(args: list[str]) -> str:
    """kubectl's (and helm's) --dry-run strategy for these arguments: "client", "server" or "" (none).

    The LAST occurrence wins (pflag sets the flag each time it is seen), nothing after `--` is a flag, and `none`
    or `false` is no dry run: `delete ns prod --dry-run=client --dry-run=none` deletes."""
    found = ""
    for i, t in enumerate(args):
        if t == "--":
            break
        if t == "--dry-run":
            nxt = args[i + 1] if i + 1 < len(args) else ""
            if nxt in {"client", "server", "none"}:  # helm also takes `--dry-run server`
                found = "" if nxt == "none" else nxt
            else:
                found = "client"
        elif t.startswith("--dry-run="):
            v = t.split("=", 1)[1].lower()
            found = "client" if v in _DRY_RUN_CLIENT else "server" if v == "server" else ""
    return found


def runs_local_code(args: list[str]) -> bool:
    """kustomize with plugins, exec functions or helm enabled runs programs on this machine (kustomize's own
    flags: --enable-alpha-plugins, --enable-exec, --enable-helm, and kubectl kustomize's --enable-helm)."""
    return any(a.split("=", 1)[0] in {"--enable-alpha-plugins", "--enable-exec", "--enable-helm"} for a in args)


def _classify_segment(seg: str) -> StepKind:
    toks = seg.split()
    while toks and _ENV_ASSIGN.match(toks[0]):  # KUBECONFIG=... oc delete ...
        toks = toks[1:]
    if toks and toks[0] in {"sudo", "env", "command", "exec", "time", "nohup"}:
        toks = toks[1:]
        while toks and _ENV_ASSIGN.match(toks[0]):
            toks = toks[1:]
    return classify_argv(toks)


def classify_argv(toks: list[str]) -> StepKind:
    """Classify one command given as its words: the program and its arguments, no shell syntax.

    ``kube_noob.debug.shell`` produces these words from a whole shell line, seeing through quoting and wrappers;
    ``classify_step`` produces them by splitting a step on white space. One decision table serves both."""
    if not toks:
        return "read"
    from kube_noob.debug.shell import program

    tool = program(toks[0])  # /usr/local/bin/oc, oc.exe, kubectl1.30 and Kubectl name their tool
    rest = toks[1:]
    sub = rest[0] if rest else ""
    nxt = rest[1] if len(rest) > 1 else ""
    if tool == "xargs":  # `... | xargs oc delete pod` runs the command that follows
        args = [t for t in rest if not t.startswith("-")]
        return _classify_segment(" ".join(args)) if args else "exec"
    if tool in KUBE_CLIS:
        sub, nxt, _ = kube_subcommand(rest)
        seg = " ".join(toks)
        if any(a == "--kuberc" or a.startswith("--kuberc=") for a in rest):
            return "change"  # a preferences file named here can alias any subcommand to any other
        if sub == "diff":
            # Stores nothing in the cluster, but runs a diff program on this machine: `diff`, or whatever
            # KUBECTL_EXTERNAL_DIFF names (kubectl pkg/cmd/diff/diff.go), which a step cannot see.
            return "exec"
        if sub == "cluster-info" and nxt == "dump":
            return "exec"  # writes a directory of objects and pod logs with --output-directory
        if sub == "kustomize":
            return "exec" if runs_local_code(rest) else "read"  # renders locally; --enable-helm runs helm
        if sub in _KUBE_READ or sub == "":  # "": `kubectl` alone prints its help
            return "read"
        if sub == "auth":
            return "read" if nxt in {"can-i", "whoami"} else "change"
        if sub == "config":
            return "read" if nxt in _KUBECONFIG_READ else "change"
        if sub == "plugin":
            return "read" if nxt == "list" else "exec"
        if sub == "rollout":
            return "read" if nxt in {"status", "history"} else "change"
        if sub in _KUBE_EXEC:
            return "exec"
        if sub == "adm":
            # must-gather creates a namespace and a privileged pod; it changes the cluster.
            if nxt in {"top", "inspect"} or (nxt == "policy" and _ADM_POLICY_READ.search(seg)):
                return "read"
            if nxt == "prune" and not any(
                t == "--confirm" or (t.startswith("--confirm=") and t.split("=", 1)[1].lower() != "false") for t in rest
            ):
                return "read"  # without --confirm, oc adm prune only lists what it would remove
            return "change"
        if sub in DRY_RUN_VERBS and dry_run(rest) == "client":
            return "read"  # apply, create, patch, delete ... --dry-run=client send nothing that is stored
        return "change"
    if tool == "helm":
        if sub == "repo":
            return "read" if nxt == "list" else "change"  # add, update and remove change the local repositories file
        if sub in {"install", "upgrade"} and dry_run(rest) == "client":
            return "read"  # helm renders and prints; nothing is installed
        return "read" if sub in _HELM_READ else "change"
    if tool == "kustomize":
        if runs_local_code(rest):
            return "exec"
        return "read" if sub in {"build", "cfg", "version", "help", ""} else "change"
    if tool == "rosa":
        return "read" if sub in _ROSA_READ else "change"
    if tool == "aws":  # aws <service> <operation>: describe-*, get-* and list-* only read
        return "read" if nxt.startswith(("describe-", "get-", "list-")) else "change"
    if tool == "kube-noob":
        return "read" if sub not in {"serve", "mcp", "corpus", "ask"} else "exec"
    if tool in _LOCAL_READ:
        allowed = _LOCAL_READ[tool]
        return "read" if allowed is None or sub in allowed else "exec"
    if tool in _TEXT_FILTERS:
        if tool == "sed" and any(t.startswith("-i") or t == "--in-place" for t in rest):
            return "change"
        if tool == "tee":
            return "change"
        return "read"
    if tool in _LOCAL_INFO:
        return "read"
    if tool in _NETWORK_EXEC:
        return "exec"
    return "exec"


def classify_step(text: str) -> StepKind:
    """Classify a step; a shell line is as dangerous as its most dangerous segment."""
    cmd = split_comment(text)[0].strip().strip("`")
    if not cmd or not re.match(r"^([A-Za-z_][A-Za-z0-9_]*=\S*\s+)*[a-z/][\w./-]*\s", cmd + " "):
        return "read"  # prose guidance such as "Read the policy names ..."
    kinds = [_classify_segment(seg) for seg in _segments(cmd)]
    return max(kinds, key=lambda k: _RANK[k]) if kinds else "read"
