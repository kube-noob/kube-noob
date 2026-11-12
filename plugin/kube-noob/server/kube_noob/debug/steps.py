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


def kube_subcommand(args: list[str]) -> tuple[str, str, int]:
    """The subcommand, the first word after it that is not a flag, and the subcommand's index in ``args`` (-1 when
    there is none). Global flags in front are skipped (`-n shop get pods`)."""
    i = 0
    while i < len(args):
        t = args[i]
        if t in KUBE_GLOBAL_VALUE_FLAGS:
            i += 2
            continue
        if t.startswith("-") and t != "-":
            i += 1
            continue
        nxt = next((a for a in args[i + 1 :] if not a.startswith("-")), "")
        return t, nxt, i
    return "", "", -1


def dry_run(args: list[str]) -> str:
    """kubectl's (and helm's) --dry-run strategy for these arguments: "client", "server" or "" (none)."""
    for i, t in enumerate(args):
        if t == "--dry-run":
            nxt = args[i + 1] if i + 1 < len(args) else ""
            if nxt in {"client", "server", "none"}:  # helm also takes `--dry-run server`
                return "" if nxt == "none" else nxt
            return "client"
        if t.startswith("--dry-run="):
            v = t.split("=", 1)[1].lower()
            return "client" if v in _DRY_RUN_CLIENT else "server" if v == "server" else ""
    return ""


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
    tool = toks[0].rsplit("/", 1)[-1]  # /usr/local/bin/oc -> oc
    if tool.lower().endswith(".exe"):
        tool = tool[:-4]
    rest = toks[1:]
    sub = rest[0] if rest else ""
    nxt = rest[1] if len(rest) > 1 else ""
    if tool == "xargs":  # `... | xargs oc delete pod` runs the command that follows
        args = [t for t in rest if not t.startswith("-")]
        return _classify_segment(" ".join(args)) if args else "exec"
    if tool in KUBE_CLIS:
        sub, nxt, _ = kube_subcommand(rest)
        seg = " ".join(toks)
        # diff sends server-side dry-run requests and stores nothing; kustomize renders a directory locally.
        if sub in _KUBE_READ or sub in {"diff", "kustomize", ""}:  # "": `kubectl` alone prints its help
            return "read"
        if sub == "auth":
            return "read" if nxt in {"can-i", "whoami"} else "change"
        if sub == "config":
            return "read" if nxt in _KUBECONFIG_READ else "change"
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
        if dry_run(rest) == "client":
            return "read"  # apply, create, patch, delete ... --dry-run=client send nothing that is stored
        return "change"
    if tool == "helm":
        if sub == "repo":
            return "read" if nxt == "list" else "change"  # add, update and remove change the local repositories file
        if sub in {"install", "upgrade"} and dry_run(rest) == "client":
            return "read"  # helm renders and prints; nothing is installed
        return "read" if sub in _HELM_READ else "change"
    if tool == "kustomize":
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
