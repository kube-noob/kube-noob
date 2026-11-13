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
#: `diff` is the helm-diff plugin, which renders and compares and changes no release.
_HELM_READ = {
    "status", "history", "get", "list", "ls", "show", "template", "lint", "search", "env", "version", "diff", "help"
}  # fmt: skip
#: krew's subcommands that read the plugin index or the installed list; install, upgrade and uninstall run code.
_KREW_READ = {"list", "info", "search", "version"}
#: `oc adm upgrade` with nothing but these flags prints the upgrade status; `--to*`, `--clear`, `channel`,
#: `rollback` and the rest change it (openshift/oc pkg/cli/admin/upgrade, master, read 2026-11-13).
_ADM_UPGRADE_STATUS_FLAGS = {"-o", "--output", "--include-not-recommended", "-h", "--help"}
#: `oc adm upgrade status` and `recommend` print; `accept`, `channel`, `rollback` and the rest change the upgrade.
_ADM_UPGRADE_READ_SUBCOMMANDS = {"status", "recommend"}
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
#: Flags of kubectl's verbs that take no value when given bare (bool flags and the optional-value ones with a
#: NoOptDefVal: --validate, --dry-run, --cascade), read from kubernetes/kubectl pkg/cmd/*/*.go, master,
#: 2026-11-13. A bare flag not listed here is read as taking the next word, which is pflag's rule for every
#: non-bool flag; so an unknown flag before `--dry-run` or `-h` fails closed.
KUBE_BOOL_FLAGS = KUBE_GLOBAL_BOOL_FLAGS | frozenset(
    {"--validate", "--dry-run", "--cascade", "-A", "--all", "--all-namespaces", "--force", "--now", "--wait",
     "--overwrite", "-R", "--recursive", "--prune", "--server-side", "--force-conflicts", "--openapi-patch",
     "--ignore-not-found", "--save-config", "--record", "--show-managed-fields", "--allow-missing-template-keys",
     "--local", "--list", "-i", "--stdin", "--interactive", "-t", "--tty", "-w", "--watch", "--watch-only",
     "--previous", "--follow", "--show-labels", "--show-kind", "--no-headers", "--rm", "--attach",
     "--leave-stdin-open", "-q", "--quiet", "--privileged", "--expose", "--command", "--delete-emptydir-data",
     "--delete-local-data", "--disable-eviction", "--ignore-daemonsets", "--ignore-errors", "--timestamps",
     "--all-containers", "--include-not-recommended", "--to-latest", "--clear", "--confirm", "--orphans",
     "--windows-line-endings", "--resolve-image", "--append-hash", "--disable-filter", "--enable-helm",
     "--enable-alpha-plugins", "--enable-exec", "--no-wait", "--allow-explicit-upgrade",
     "--allow-upgrade-with-warnings", "--to-multi-arch", "--pullspecs", "--commits", "--public", "--short"}
)  # fmt: skip
#: helm's flags that take no value when given bare (helm/helm cmd/helm/*.go and pkg/action, master, 2026-11-13;
#: `--dry-run` has a no-option default of "client" since 3.13).
HELM_BOOL_FLAGS = frozenset(
    {"--dry-run", "-h", "--help", "--debug", "--install", "-i", "--atomic", "--wait", "--wait-for-jobs",
     "--create-namespace", "--skip-crds", "--no-hooks", "--keep-history", "--hide-notes", "--render-subchart-notes",
     "--cleanup-on-fail", "--reset-values", "--reuse-values", "--reset-then-reuse-values", "--dependency-update",
     "--devel", "--verify", "--generate-name", "-g", "--skip-schema-validation", "--take-ownership",
     "--disable-openapi-validation", "--insecure-skip-tls-verify", "--kube-insecure-skip-tls-verify", "--plain-http",
     "--pass-credentials", "--hide-secret", "--rollback-on-failure", "--force", "--replace", "--untar", "--prov",
     "--strict", "--with-subcharts", "--quiet", "--all", "--all-namespaces", "-A", "--deployed", "--failed",
     "--pending", "--uninstalled", "--uninstalling", "--superseded", "--short", "-q", "--reverse", "-r", "--date",
     "-d", "--include-crds", "--is-upgrade", "--validate", "--skip-tests", "--logs", "--fail-on-missing",
     "--no-update", "--force-update", "--skip-refresh", "--versions", "-l", "--regexp", "--starter"}
)  # fmt: skip
#: The verbs each tool itself defines (kubernetes/kubectl pkg/cmd/cmd.go; openshift/oc pkg/cli/cli.go; helm cmd/helm;
#: master, read 2026-11-13). A word not here is a plugin (`kubectl-<word>` on PATH), which kubectl execs with
#: the remaining arguments, `--help` included -- so help prints and runs nothing only on a built-in verb.
KUBECTL_BUILTINS = frozenset(
    {"", "help", "get", "describe", "logs", "events", "explain", "api-resources", "api-versions", "version", "top",
     "wait", "cluster-info", "completion", "options", "apply", "create", "delete", "patch", "replace", "scale",
     "autoscale", "label", "annotate", "set", "edit", "expose", "run", "rollout", "drain", "cordon", "uncordon",
     "taint", "certificate", "config", "auth", "plugin", "kustomize", "diff", "exec", "attach", "port-forward",
     "proxy", "cp", "debug", "alpha"}
)  # fmt: skip
OC_BUILTINS = KUBECTL_BUILTINS | frozenset(
    {"adm", "whoami", "projects", "project", "status", "new-project", "new-app", "new-build", "process",
     "start-build", "cancel-build", "import-image", "tag", "policy", "secrets", "rsh", "rsync", "login", "logout",
     "registry", "extract", "observe", "idle", "image", "serviceaccounts", "rollback", "get-token", "expose",
     "env", "volume", "volumes", "build-logs", "deploy"}
)  # fmt: skip
HELM_BUILTINS = frozenset(
    {"", "help", "install", "upgrade", "uninstall", "delete", "del", "un", "rollback", "template", "lint", "list",
     "ls", "status", "history", "hist", "get", "show", "inspect", "search", "repo", "dependency", "dep", "package",
     "pull", "fetch", "push", "registry", "plugin", "create", "env", "verify", "version", "completion", "test"}
)  # fmt: skip


def builtin(tool: str, sub: str) -> bool:
    """Whether ``sub`` is a verb the tool itself defines, not a plugin it would exec."""
    if tool == "helm":
        return sub in HELM_BUILTINS
    if tool == "oc":
        return sub in OC_BUILTINS
    return sub in KUBECTL_BUILTINS


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


def takes_value(flag: str, tool: str = "kubectl") -> bool:
    """Whether a bare flag (no `=`) takes the NEXT word as its value, the way pflag reads it: a bool flag or one
    with a no-option default (`--validate`, `--dry-run`, `--cascade`) does not; every other flag does, including
    one this table does not know. `-n --dry-run=client` sets the namespace to "--dry-run=client" and is no dry
    run; `-h` after `-n` is the namespace `-h`."""
    if flag == "--" or not flag.startswith("-") or flag == "-" or "=" in flag:
        return False
    if not flag.startswith("--") and len(flag) > 2:
        return False  # `-nx`: the value is attached
    bools = HELM_BOOL_FLAGS if tool == "helm" else KUBE_BOOL_FLAGS
    return flag not in bools


def positionals(args: list[str], tool: str = "kubectl") -> list[str]:
    """The words that are not flags and not a flag's value, read with pflag's arity rule; `--` ends the flags."""
    out: list[str] = []
    previous = ""
    for i, t in enumerate(args):
        if t == "--":
            out.extend(args[i + 1 :])
            break
        if takes_value(previous, tool):
            previous = ""
            continue
        previous = t
        if not t.startswith("-") or t == "-":
            out.append(t)
    return out


def dry_run(args: list[str], tool: str = "kubectl") -> str:
    """kubectl's (and helm's) --dry-run strategy for these arguments: "client", "server", "" (none) or "unsure".

    The LAST occurrence wins (pflag sets the flag each time it is seen), nothing after `--` is a flag, `none` or
    `false` is no dry run, and a `--dry-run` that is the VALUE of the bare flag before it (`-n --dry-run=client`,
    helm's `--description --dry-run`) is no flag at all. The bool-flag tables (``takes_value``) only ever REMOVE
    credit here: a flag wrongly listed as bool would otherwise let `--thatflag --dry-run=client` be credited while
    it runs for real, and those tables are not verified against the sources. So a dry run is credited only when
    its arity needs no table: `--dry-run=VALUE` after a positional word, a `--flag=value` token or another
    `--dry-run`; bare `--dry-run` after a word that is not a flag. Anything else is "unsure" -- a caller that
    allows on a dry run must ask, and no caller treats it as one."""
    found = ""
    unsure = False
    previous = ""
    for i, t in enumerate(args):
        if t == "--":
            break
        before, previous = previous, t
        if t != "--dry-run" and not t.startswith("--dry-run="):
            continue
        if takes_value(before, tool):
            continue  # by the tables this word is the value of the flag before it; either way it earns nothing
        before_is_flag = before.startswith("-") and before != "-"
        if t == "--dry-run":
            unsure = unsure or before_is_flag
            nxt = args[i + 1] if i + 1 < len(args) else ""
            if nxt in {"client", "server", "none"}:  # helm also takes `--dry-run server`
                found = "" if nxt == "none" else nxt
            else:
                found = "client"
        else:
            self_contained = "=" in before or before == "--dry-run"
            unsure = unsure or (before_is_flag and not self_contained)
            v = t.split("=", 1)[1].lower()
            found = "client" if v in _DRY_RUN_CLIENT else "server" if v == "server" else ""
    return "unsure" if unsure and found else found


def runs_local_code(args: list[str]) -> bool:
    """kustomize with plugins, exec functions or helm enabled runs programs on this machine (kustomize's own
    flags: --enable-alpha-plugins, --enable-exec, --enable-helm, and kubectl kustomize's --enable-helm)."""
    return any(a.split("=", 1)[0] in {"--enable-alpha-plugins", "--enable-exec", "--enable-helm"} for a in args)


def _adm_reads(rest: list[str]) -> bool:
    """`oc adm release info ...` (the only release subcommand that writes nothing) and `oc adm upgrade` as a read:
    `status` or `recommend`, or no positional (`channel`, `rollback`, `accept`) and no flag but the output ones --
    `--to`, `--to-latest`, `--to-image`, `--to-multi-arch`, `--clear`, `--force` and `--allow-*` change it."""
    _, nxt, idx = kube_subcommand(rest)
    after = rest[idx + 2 :] if idx >= 0 else []
    if nxt == "release":
        return [a for a in after if not a.startswith("-")][:1] == ["info"]
    if after[:1] and after[0] in _ADM_UPGRADE_READ_SUBCOMMANDS:
        return not any(t.startswith(("--to", "--clear")) or t == "--force" for t in after)
    i = 0
    while i < len(after):
        t = after[i]
        name = t.split("=", 1)[0]
        if not t.startswith("-") or name not in _ADM_UPGRADE_STATUS_FLAGS:
            return False
        i += 2 if name in {"-o", "--output"} and "=" not in t else 1
    return True


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
        if sub == "krew":
            return "read" if nxt in _KREW_READ else "exec"
        if sub == "neat":
            # kubectl-neat strips managed fields from `get`/`describe` output or a file; given any other first
            # word it passes it to kubectl, so `neat delete ns prod` deletes.
            positional = positionals(rest[kube_subcommand(rest)[2] + 1 :])
            return "read" if not positional or positional[0] in {"get", "describe"} else "change"
        if sub == "registry":
            return "read" if nxt == "info" else "change"  # `oc registry login` writes a credential
        if sub == "adm":
            # must-gather creates a namespace and a privileged pod; it changes the cluster. `prune` without
            # --confirm only lists what it would remove (a playbook check); verify still asks about it, since a
            # word only known at run time can be --confirm.
            if nxt in {"top", "inspect", "node-logs"} or (nxt == "policy" and _ADM_POLICY_READ.search(seg)):
                return "read"
            if nxt in {"release", "upgrade"} and _adm_reads(rest):
                return "read"
            if nxt == "prune" and not any(
                t == "--confirm" or (t.startswith("--confirm=") and t.split("=", 1)[1].lower() != "false") for t in rest
            ):
                return "read"
            return "change"
        if sub in DRY_RUN_VERBS and dry_run(rest) == "client":
            return "read"  # apply, create, patch, delete ... --dry-run=client send nothing that is stored
        return "change"
    if tool == "helm":
        if sub == "repo":
            return "read" if nxt == "list" else "change"  # add, update and remove change the local repositories file
        if sub in {"install", "upgrade"} and dry_run(rest, "helm") == "client":
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
