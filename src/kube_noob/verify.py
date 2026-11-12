"""``kube-noob verify``: the deterministic check a change must pass before it is applied.

One answer for a change, three-valued:

- ``allow``: everything the change sends was read, and it adds no finding at or above ``--fail-on``;
- ``deny``: it adds a finding at or above ``--fail-on`` (or grants cluster-admin, the privileged SCC, a host path or
  wildcard RBAC in a command; or the exception list has expired or refused entries). More evidence cannot turn a
  deny into an allow, so a deny stands even when something else was not read;
- ``not-determined``: what the change does could not be decided from its text and the local files -- a URL, a
  ``-f -`` with nothing on stdin, a strategic-merge patch, ``exec``, a delete, a command substitution, a flag whose
  effect verify does not know, a file it would not read. Never an allow.

The change is either manifests (``-f``) or a command line an agent intends to run (``--command``). A command is read
by ``kube_noob.debug.shell`` (which sees through ``sh -c``, ``env``, ``sudo``, ``xargs``, quoting and the rest, or
says it cannot), classified by the same table ``diagnose`` uses (``kube_noob.debug.steps.classify_argv``), and the
files it names are resolved inside the working directory: no symbolic link, nothing outside the tree, no URL, no
network, and the command is never run. ``helm install``/``upgrade`` of a local chart is rendered with ``helm
template`` exactly as ``gate --chart`` renders it; a kustomization is read only when it lists resources and does
nothing else.

The manifests are checked by the CI gate's own code (``kube_noob.gate.run``), so ``verify -f X`` and ``gate -f X``
cannot disagree about a finding. With ``--against`` (the current state of the same objects) only the findings the
change ADDS count, the way the admission webhook judges an UPDATE (G250).
"""

from __future__ import annotations

import copy
import json
import os
import re
import stat
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from kube_noob import sanitize
from kube_noob.debug import shell
from kube_noob.debug.steps import KUBE_CLIS, classify_argv, kube_subcommand

VERDICTS = ("allow", "deny", "not-determined")
CLASSES = ("none", "read-only", "local", "runs-code", "changes-state", "destructive")
MAX_FILE_BYTES = 5_000_000
MAX_FILES = 2_000
MAX_TOTAL_BYTES = 5_000_000
MAX_KUSTOMIZE_DEPTH = 5
MAX_SHOWN = 50  # findings in the text view; the JSON has all of them and the count withheld is stated
#: kubectl reads these from a directory (cli-runtime pkg/resource visitor: FileExtensions).
KUBECTL_EXTENSIONS = (".json", ".yaml", ".yml")
#: A path pasted into a suggested command unquoted: characters a shell leaves alone, and no leading `-` (a flag).
_SAFE_PATH = re.compile(r"^[A-Za-z0-9._/@%+=:,][A-Za-z0-9._/@%+=:,-]*\Z")

# kubectl flags that change which cluster, which identity or which credentials a command uses. verify checks
# manifests; it does not know what a named cluster holds or allows, so a command that picks one is not determined.
_TARGETING = frozenset(
    {
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
        "--insecure-skip-tls-verify",
        "--tls-server-name",
        "--username",
        "--password",
        "--proxy-url",
        "--kube-context",  # helm
        "--kube-apiserver",
        "--kube-token",
        "--kube-as-user",
        "--kube-as-group",
        "--kube-ca-file",
        "--kube-insecure-skip-tls-verify",
        "--kube-tls-server-name",
    }
)
# Flags whose effect on what apply/create/replace send is nothing (output, validation, ownership, timing, logging).
# Read from kubernetes/kubectl pkg/cmd/{apply,create,replace}/*.go and pkg/cmd/util/helpers.go, master, 2026-11-12.
_HARMLESS = frozenset(
    {
        "-o",
        "--output",
        "--validate",
        "--field-manager",
        "--server-side",
        "--force-conflicts",
        "--overwrite",
        "--openapi-patch",
        "--wait",
        "--timeout",
        "--template",
        "--show-managed-fields",
        "--allow-missing-template-keys",
        "--save-config",
        "--record",
        "--windows-line-endings",
        "--request-timeout",
        "-v",
        "--v",
        "--vmodule",
        "--warnings-as-errors",
        "--cache-dir",
        "--match-server-version",
        "--disable-compression",
        "--log-flush-frequency",
        "--profile",
        "--profile-output",
        "--dry-run",
        "-n",
        "--namespace",
    }
)
_VALUE_FLAGS = frozenset(
    {
        "-o",
        "--output",
        "--validate",
        "--field-manager",
        "--timeout",
        "--template",
        "--request-timeout",
        "-v",
        "--v",
        "--vmodule",
        "--cache-dir",
        "--log-flush-frequency",
        "--profile",
        "--profile-output",
        "-n",
        "--namespace",
        "-f",
        "--filename",
        "-k",
        "--kustomize",
        "-l",
        "--selector",
        "--grace-period",
        "--cascade",
        "--prune-allowlist",
        "--applyset",
        "--subresource",
        "--raw",
        "-p",
        "--patch",
        "--patch-file",
        "--type",
        *_TARGETING,
    }
)
# What a change that is not a manifest does, by subcommand. Each is not determined: verify reads no cluster.
_NO_MANIFEST = {
    "delete": "deletes objects",
    "drain": "evicts every pod on a node",
    "cordon": "stops scheduling on a node",
    "uncordon": "resumes scheduling on a node",
    "taint": "changes which pods a node accepts",
    "scale": "changes a replica count",
    "autoscale": "creates an autoscaler from flags",
    "rollout": "restarts, pauses, resumes or rolls back a workload",
    "label": "changes labels, which decide what selectors, policies and Services match",
    "annotate": "changes annotations",
    "set": "changes a workload's image, environment, resources or service account in place",
    "edit": "opens an editor on live objects",
    "expose": "creates a Service from flags",
    "run": "creates a pod from flags",
    "certificate": "approves or denies a certificate signing request",
    "config": "changes which cluster and identity later commands use",
    "auth": "reconciles RBAC from a file without verify reading it",
    "adm": "runs an administrative action",
    "new-app": "creates objects from a template, an image or a repository",
    "new-project": "creates a project",
    "process": "instantiates a template",
    "start-build": "starts a build",
    "import-image": "imports an image",
    "tag": "changes an image stream tag",
    "policy": "changes RBAC",
    "secrets": "links a secret",
    "plugin": "runs a kubectl plugin",
}
_DESTRUCTIVE = frozenset({"delete", "drain", "uninstall", "rollback"})
_EXEC_REASON = "runs a process in the cluster or opens a connection to it"
# Workload resource names (and short names, as kubectl api-resources prints them) to kinds, for `patch TYPE NAME`
# against a baseline. A type not listed is not determined rather than guessed.
_RESOURCE_KINDS = {
    "deployment": "Deployment",
    "deployments": "Deployment",
    "deploy": "Deployment",
    "statefulset": "StatefulSet",
    "statefulsets": "StatefulSet",
    "sts": "StatefulSet",
    "daemonset": "DaemonSet",
    "daemonsets": "DaemonSet",
    "ds": "DaemonSet",
    "pod": "Pod",
    "pods": "Pod",
    "po": "Pod",
    "service": "Service",
    "services": "Service",
    "svc": "Service",
    "job": "Job",
    "jobs": "Job",
    "cronjob": "CronJob",
    "cronjobs": "CronJob",
    "cj": "CronJob",
    "networkpolicy": "NetworkPolicy",
    "networkpolicies": "NetworkPolicy",
    "netpol": "NetworkPolicy",
    "role": "Role",
    "roles": "Role",
    "rolebinding": "RoleBinding",
    "rolebindings": "RoleBinding",
    "clusterrole": "ClusterRole",
    "clusterroles": "ClusterRole",
    "clusterrolebinding": "ClusterRoleBinding",
    "clusterrolebindings": "ClusterRoleBinding",
    "serviceaccount": "ServiceAccount",
    "serviceaccounts": "ServiceAccount",
    "sa": "ServiceAccount",
}
# The kustomization keys verify can render: a list of resources and nothing that transforms them.
_KUSTOMIZE_PLAIN = frozenset({"apiVersion", "kind", "resources", "metadata"})
KUSTOMIZATION_FILES = ("kustomization.yaml", "kustomization.yml", "Kustomization")


class VerifyError(ValueError):
    """Input the caller gave verify (not the command it checks) that cannot be used: exit 2."""


@dataclass
class _Read:
    """Manifests a command sends, and what it could not read."""

    sources: list[Any] = field(default_factory=list)  # kube_noob.gate.Source
    undetermined: list[str] = field(default_factory=list)
    not_evaluated: list[dict[str, str]] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)  # grants found in the command itself
    commands: list[dict[str, Any]] = field(default_factory=list)
    baseline: list[Any] = field(default_factory=list)  # objects a patch starts from
    namespace: str | None = None


def show(text: Any, limit: int = 200) -> str:
    """Input-derived text made one printable line (no newline can forge a row, no invisible character survives)."""
    flat = " ".join(sanitize.visible(str(text)).split())
    return flat if len(flat) <= limit else flat[: limit - 3] + "..."


# -- reading files a command names -------------------------------------------------------------------------------


def _refused(raw: str) -> str:
    """Why a name a command gives is never read, whatever the tree: a URL, a home directory, a NUL."""
    if "\x00" in raw:
        return "a path with a NUL character"
    if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", raw):
        return "a URL: verify reads no network"
    if raw.startswith("~"):
        return "a path in a home directory: outside the working directory"
    return ""


class _Tree:
    """Files inside one directory tree, opened without following a symbolic link anywhere on the way."""

    def __init__(self, root: Path, deadline: float) -> None:
        self.root = root.resolve()
        self.deadline = deadline
        self.total = 0
        self.count = 0

    def locate(self, raw: str, base: Path) -> tuple[Path | None, str]:
        """The path inside the tree, or None and why not."""
        refused = _refused(raw)
        if refused:
            return None, refused
        p = PurePosixPath(raw)
        joined = PurePosixPath(os.path.normpath(str(base / p) if not p.is_absolute() else str(p)))
        try:
            rel = Path(str(joined)).relative_to(self.root)
        except ValueError:
            return None, "outside the working directory"
        cur = self.root
        for part in rel.parts:
            cur = cur / part
            try:
                st = os.lstat(cur)
            except FileNotFoundError:
                return None, "no such file or directory"
            except OSError as exc:
                return None, f"cannot be read ({exc.__class__.__name__})"
            if stat.S_ISLNK(st.st_mode):
                return None, "a symbolic link: verify does not follow links"
        return cur, ""

    def read(self, path: Path) -> tuple[str | None, str]:
        if time.monotonic() > self.deadline:
            return None, "the time budget ran out before it was read"
        self.count += 1
        if self.count > MAX_FILES:
            return None, f"more than {MAX_FILES} files"
        try:
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        except OSError as exc:
            return None, f"cannot be opened ({exc.__class__.__name__})"
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                return None, "not a regular file"
            if st.st_size > MAX_FILE_BYTES:
                return None, f"larger than {MAX_FILE_BYTES:,} bytes"
            self.total += st.st_size
            if self.total > MAX_TOTAL_BYTES:
                return None, f"the files together are larger than {MAX_TOTAL_BYTES:,} bytes"
            data = b""
            while len(data) <= MAX_FILE_BYTES:
                chunk = os.read(fd, 1 << 20)
                if not chunk:
                    break
                data += chunk
        finally:
            os.close(fd)
        if len(data) > MAX_FILE_BYTES:
            return None, f"larger than {MAX_FILE_BYTES:,} bytes"
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return None, "not UTF-8 text"
        if "\x00" in text:
            return None, "binary, not text"
        return text, ""

    def uri(self, path: Path) -> str:
        return path.relative_to(self.root).as_posix()

    def script(self, raw: str, base: Path) -> str | None:
        """The text of a script a line runs, "" for a file that is not text, None when it is not read."""
        where, _ = self.locate(raw, base)
        if where is None:
            return None
        try:
            if not stat.S_ISREG(os.lstat(where).st_mode):
                return None
        except OSError:
            return None
        text, why = self.read(where)
        if text is None:
            return "" if why in {"not UTF-8 text", "binary, not text"} else None
        return text


# -- commands ----------------------------------------------------------------------------------------------------


def _class_of(kind: str, sub: str, tool: str, args: list[str]) -> str:
    if kind == "read":
        return "read-only"
    if kind == "exec":
        return "runs-code"
    if sub in _DESTRUCTIVE or (tool in KUBE_CLIS and sub in {"apply", "replace"} and _destructive_apply(args)):
        return "destructive"
    if tool == "helm" and sub in {
        "repo",
        "dependency",
        "dep",
        "plugin",
        "package",
        "pull",
        "push",
        "registry",
        "create",
        "completion",
        "env",
        "lint",
        "verify",
        "search",
        "show",
    }:
        return "local"
    if tool == "kustomize":
        return "local"
    return "changes-state"


def _destructive_apply(args: list[str]) -> bool:
    return any(
        a in {"--prune", "--force", "--all"} or a.startswith(("--prune=", "--force=", "--all=", "--applyset"))
        for a in args
    ) and not any(a in {"--force=false", "--prune=false", "--all=false"} for a in args)


def _flag(args: list[str], i: int) -> tuple[str, str | None, int]:
    """(name, value, next index) for the flag at args[i]; value None when the flag takes none."""
    t = args[i]
    if t.startswith("--") and "=" in t:
        name, value = t.split("=", 1)
        return name, value, i + 1
    if not t.startswith("--") and len(t) > 2 and t[:2] in {"-f", "-k", "-n", "-o", "-l", "-p", "-s", "-v"}:
        return t[:2], t[2:].lstrip("="), i + 1  # -fdeploy.yaml, -n=shop
    if t in _VALUE_FLAGS:
        return t, (args[i + 1] if i + 1 < len(args) else ""), i + 2
    return t, None, i + 1


def plan(
    line_text: str,
    *,
    cwd: Path,
    stdin: str | None = None,
    platform: str = "kubernetes",
    version: str | None = None,
    deadline: float | None = None,
    inline_files: dict[str, str] | None = None,
) -> _Read:
    """The manifests a command line sends, and why anything it does is not determined.

    ``inline_files`` (the MCP tool): the files the command names, given as text, so no file is read from disk; a
    file the command names that is not in it is not determined."""
    deadline = deadline if deadline is not None else time.monotonic() + 30
    tree = _Tree(cwd, deadline)
    out = _Read()
    reader = (
        (lambda raw: _inline_script(inline_files, raw))
        if inline_files is not None
        else (lambda raw: tree.script(raw, tree.root))
    )
    line = shell.parse(line_text, reader)
    for why in line.opaque:
        out.undetermined.append(why)
    base = tree.root
    cwd_known = True
    targeting_env = [a for a in line.assignments if a in {"KUBECONFIG"}]
    for cmd in line.commands:
        tool = shell.program(cmd.words[0].text) if cmd.words else ""
        if tool in {"cd", "pushd", "popd"}:
            # A later relative path is resolved where the line will be. A `cd` inside ( ... ) does not outlive the
            # subshell, which this reader does not track, so then the directory is unknown.
            arg = cmd.words[1] if len(cmd.words) > 1 else None
            if tool == "popd" or arg is None or arg.dynamic or line.subshell or arg.text == "-":
                cwd_known = False
            else:
                where, _ = tree.locate(arg.text, base)
                if where is None:
                    cwd_known = False
                else:
                    base = where
            continue
        if tool not in shell.KUBE_TOOLS:
            continue
        name = "kubectl" if tool in {"k", "kubecolor"} else tool
        args = [w.text for w in cmd.words[1:]]
        kind = classify_argv([name, *args])
        if tool == "kustomize":
            sub = args[0] if args else ""
        elif name == "helm":
            sub = next((a for a in args if not a.startswith("-")), "")
        else:
            sub = kube_subcommand(args)[0]
        cls = _class_of(kind, sub, name, args)
        shown = " ".join(show(w.raw or w.text, 120) for w in cmd.words[:24])
        entry: dict[str, Any] = {"command": shown, "tool": name, "class": cls}
        if cmd.via:
            entry["via"] = [show(v, 60) for v in cmd.via]
        out.commands.append(entry)
        if cls in {"read-only", "local"}:
            continue
        before = len(out.undetermined)
        if not cwd_known:
            out.undetermined.append(f"{shown}: the line changes directory in a way verify cannot follow")
            continue
        if targeting_env or set(cmd.assignments) & {"KUBECONFIG"}:
            out.undetermined.append(f"{shown}: KUBECONFIG is set on the line, which picks the cluster")
        if cmd.args_from_stdin:
            out.undetermined.append(f"{shown}: arguments arrive at run time ({', '.join(cmd.via)})")
        granted = _grants(cmd)
        out.deny.extend(f"{shown}: {g}" for g in granted)
        if name in KUBE_CLIS:
            _kubectl(cmd, name, args, sub, cls, shown, out, tree, base, stdin, inline_files, granted)
        elif name == "helm":
            _helm(cmd, args, sub, cls, shown, out, tree, base, platform, version)
        if len(out.undetermined) == before and cls in {"runs-code"}:
            out.undetermined.append(f"{shown}: {_EXEC_REASON}")
    return out


def _inline_script(files: dict[str, str] | None, raw: str) -> str | None:
    if files is None:
        return None
    return files.get(raw) if raw in files else files.get(os.path.normpath(raw))


def _grants(cmd: shell.Command) -> list[str]:
    """Grants the memory verifier refuses (privileged SCC, cluster-admin, wildcard RBAC...), in a command's words.
    The list is the verifier's own (``kube_noob.memory.verify._GRANT_COMMANDS``), not a copy."""
    from kube_noob.memory.verify import _GRANT_COMMANDS

    text = " ".join(w.text for w in cmd.words)
    return [what for rx, what in _GRANT_COMMANDS if rx.search(text) and "hostPath" not in rx.pattern]


def _kubectl(
    cmd: shell.Command,
    name: str,
    args: list[str],
    sub: str,
    cls: str,
    shown: str,
    out: _Read,
    tree: _Tree,
    base: Path,
    stdin: str | None,
    inline_files: dict[str, str] | None,
    granted: list[str],
) -> None:
    sub_index = kube_subcommand(args)[2]
    if sub in {"apply", "create", "replace", "patch"} or (sub == "auth" and "reconcile" in args):
        pass
    elif sub in _NO_MANIFEST or cls == "destructive":
        if not granted:
            why = _NO_MANIFEST.get(sub, "changes cluster state")
            out.undetermined.append(f"{shown}: {why}; verify reads no cluster, so what that changes is not known")
        return
    elif cls == "runs-code":
        return
    else:
        out.undetermined.append(f"{shown}: `{show(sub, 40)}` is not a subcommand verify knows the effect of")
        return
    if sub == "auth":
        out.undetermined.append(f"{shown}: auth reconcile writes RBAC; verify the file it names with -f instead")
        return
    if cls == "destructive":
        out.undetermined.append(
            f"{shown}: --prune, --force or --all deletes objects that are not in these files, which verify cannot see"
        )
    files: list[tuple[str, bool]] = []  # (path, is kustomization)
    recursive = False
    patch_text: str | None = None
    patch_type = "strategic"
    positional: list[str] = []
    i = 0
    while i < len(args):
        if i == sub_index:
            i += 1
            continue
        t = args[i]
        if not t.startswith("-") or t == "-":
            positional.append(t)
            i += 1
            continue
        name_, value, nxt = _flag(args, i)
        i = nxt
        if name_ in _TARGETING:
            out.undetermined.append(
                f"{shown}: {name_} picks the cluster or identity; verify checks manifests and does not know what "
                "that cluster holds"
            )
        elif name_ in {"-f", "--filename"}:
            for part in (value or "").split(","):
                files.append((part, False))
        elif name_ in {"-k", "--kustomize"}:
            files.append((value or "", True))
        elif name_ in {"-R", "--recursive"}:
            recursive = value is None or value.lower() != "false"
        elif name_ in {"-n", "--namespace"}:
            out.namespace = value
        elif name_ in {"-p", "--patch"}:
            patch_text = value
        elif name_ == "--patch-file":
            got = _read_named(value or "", tree, base, inline_files, out, shown)
            patch_text = got[1] if got else None
            if got is None:
                return
        elif name_ == "--type":
            patch_type = value or ""
        elif name_ in {"--edit", "--raw"}:
            out.undetermined.append(f"{shown}: {name_} sends something other than the files verify reads")
        elif name_ in {
            "--prune",
            "--force",
            "--all",
            "--prune-allowlist",
            "--applyset",
            "-l",
            "--selector",
            "--grace-period",
            "--cascade",
            "--subresource",
            "--local",
        }:
            pass  # destructive ones are reported above; selector and subresource narrow what is sent
        elif name_ not in _HARMLESS and name_ not in {"-R", "--recursive"}:
            out.undetermined.append(f"{shown}: {show(name_, 40)} is a flag verify does not know the effect of")
    if sub == "create" and positional:
        out.undetermined.append(
            f"{shown}: `create {show(positional[0], 40)}` builds the object from flags. Render it with "
            "--dry-run=client -o yaml into a file and verify the file"
        )
        return
    if sub == "patch":
        _patch(cmd, positional, files, patch_text, patch_type, shown, out, tree, base, stdin, inline_files)
        return
    if not files:
        out.undetermined.append(f"{shown}: names no file (-f or -k), so what it sends is not known")
        return
    for raw, is_kustomize in files:
        if raw == "-" and not is_kustomize:
            text, why = _stdin_of(cmd, stdin, tree, base, inline_files)
            if text is None:
                out.undetermined.append(f"{shown}: -f - reads standard input, and {why}")
            else:
                out.sources.append(_source("stdin", text))
            continue
        if is_kustomize:
            _kustomization(raw, shown, out, tree, base, inline_files, 0)
            continue
        _files(raw, recursive, shown, out, tree, base, inline_files)


def _source(uri: str, text: str, chart: str | None = None) -> Any:
    """A file the command sends, classified the way the gate classifies a file found in a directory: one YAML
    cannot read is unreadable, one with no Kubernetes object is skipped -- and both are gaps, since kubectl would
    still send it."""
    from kube_noob import gate

    unreadable = gate.unreadable_reason(text)
    skip = None if unreadable else gate._classify(None, text)
    return gate.Source(uri, text, chart=chart, skip=skip, unreadable=unreadable)


def _read_named(
    raw: str, tree: _Tree, base: Path, inline: dict[str, str] | None, out: _Read, shown: str
) -> tuple[str, str] | None:
    """(uri, text) of one named file, or None after recording why it was not read."""
    refused = _refused(raw)
    if refused:
        out.undetermined.append(f"{shown}: {show(raw, 120)}: {refused}")
        return None
    if inline is not None:
        given_as = raw if raw in inline else os.path.normpath(raw)
        if given_as in inline:
            return given_as, inline[given_as]
        out.undetermined.append(f"{shown}: {show(raw, 120)} was not given with the command, so it was not read")
        return None
    where, why = tree.locate(raw, base)
    if where is None or not where.is_file():
        out.undetermined.append(f"{shown}: {show(raw, 120)}: {why or 'not a file'}")
        return None
    text, why = tree.read(where)
    if text is None:
        out.undetermined.append(f"{shown}: {tree.uri(where)}: {why}")
        return None
    return tree.uri(where), text


def _files(
    raw: str, recursive: bool, shown: str, out: _Read, tree: _Tree, base: Path, inline: dict[str, str] | None
) -> None:
    refused = _refused(raw)
    if refused:
        out.undetermined.append(f"{shown}: {show(raw, 120)}: {refused}")
        return
    if inline is not None:
        prefix = os.path.normpath(raw).rstrip("/") + "/"
        found = sorted(k for k in inline if k.startswith(prefix) and k.endswith(KUBECTL_EXTENSIONS))
        if raw in inline or os.path.normpath(raw) in inline:
            got = _read_named(raw, tree, base, inline, out, shown)
            if got:
                out.sources.append(_source(*got))
        elif found:
            for k in found:
                if recursive or "/" not in k[len(prefix) :]:
                    out.sources.append(_source(k, inline[k]))
        else:
            out.undetermined.append(f"{shown}: {show(raw, 120)} was not given with the command, so it was not read")
        return
    where, why = tree.locate(raw, base)
    if where is None:
        out.undetermined.append(f"{shown}: {show(raw, 120)}: {why}")
        return
    if where.is_dir():
        found_any = False
        for path in _walk(where, recursive, out, tree):
            found_any = True
            text, why = tree.read(path)
            if text is None:
                out.undetermined.append(f"{shown}: {tree.uri(path)}: {why}")
                continue
            out.sources.append(_source(tree.uri(path), text))
        if not found_any:
            out.undetermined.append(
                f"{shown}: {tree.uri(where) or '.'} holds no .yaml, .yml or .json file, so kubectl would send nothing "
                "verify has seen"
            )
        return
    text, why = tree.read(where)
    if text is None:
        out.undetermined.append(f"{shown}: {tree.uri(where)}: {why}")
        return
    out.sources.append(_source(tree.uri(where), text))


def _walk(root: Path, recursive: bool, out: _Read, tree: _Tree) -> list[Path]:
    """The files kubectl would read from a directory: .json, .yaml and .yml; links are not followed and listed."""
    found: list[Path] = []
    stack = [root]
    while stack:
        d = stack.pop()
        try:
            entries = sorted(os.scandir(d), key=lambda e: e.name)
        except OSError as exc:
            out.undetermined.append(f"{tree.uri(d)}: cannot be listed ({exc.__class__.__name__})")
            continue
        for e in entries:
            p = Path(e.path)
            if e.is_symlink():
                if e.name.endswith(KUBECTL_EXTENSIONS) or recursive:
                    out.undetermined.append(f"{tree.uri(p)}: a symbolic link, which verify does not follow")
                continue
            if e.is_dir(follow_symlinks=False):
                if recursive:
                    stack.append(p)
                continue
            if e.name.endswith(KUBECTL_EXTENSIONS):
                found.append(p)
                if len(found) > MAX_FILES:
                    out.undetermined.append(f"{tree.uri(root)}: more than {MAX_FILES} files")
                    return found[:MAX_FILES]
    return sorted(found)


def _stdin_of(
    cmd: shell.Command, stdin: str | None, tree: _Tree, base: Path, inline: dict[str, str] | None
) -> tuple[str | None, str]:
    if cmd.stdin_kind in {"heredoc", "herestring"}:
        if cmd.stdin_dynamic:
            return None, "the here-document expands variables, so its text is only known when the line runs"
        return cmd.stdin, ""
    if cmd.stdin_kind == "file" and cmd.stdin is not None:
        if cmd.stdin_dynamic:
            return None, "it is redirected from a file named by an expansion"
        dummy = _Read()
        got = _read_named(cmd.stdin, tree, base, inline, dummy, "")
        return (got[1], "") if got else (None, (dummy.undetermined or ["the file was not read"])[0].lstrip(": "))
    if cmd.stdin_kind == "pipe":
        src = cmd.source
        if src is None or not src.words:
            return None, "it is piped from something verify cannot read"
        tool = src.tool
        args = list(src.words[1:])
        if tool == "cat" and args and not any(w.dynamic or w.text.startswith("-") for w in args):
            parts: list[str] = []
            for w in args:
                dummy = _Read()
                got = _read_named(w.text, tree, base, inline, dummy, "")
                if got is None:
                    return None, f"cat reads {show(w.text, 80)}, which was not read"
                parts.append(got[1])
            return "\n---\n".join(parts), ""
        if tool in {"cat"} and not args and src.stdin_kind in {"heredoc", "herestring"}:
            return _stdin_of(src, stdin, tree, base, inline)
        if tool in {"echo", "printf"}:
            return None, f"it is piped from {tool}, which verify does not render"
        if tool == "kustomize" and len(args) >= 2 and args[0].text == "build" and not args[1].dynamic:
            sub = _Read()
            _kustomization(args[1].text, "kustomize build", sub, tree, base, inline, 0)
            if sub.undetermined:
                return None, sub.undetermined[0]
            return "\n---\n".join(s.text for s in sub.sources), ""
        return None, f"it is piped from {show(tool, 40)}, whose output verify does not model"
    if stdin is not None:
        return stdin, ""
    return None, "no standard input was given to verify"


def _kustomization(
    raw: str, shown: str, out: _Read, tree: _Tree, base: Path, inline: dict[str, str] | None, depth: int
) -> None:
    """The resources of a kustomization that only lists resources. Anything that transforms them is not
    determined: verify does not run kustomize."""
    if depth > MAX_KUSTOMIZE_DEPTH:
        out.undetermined.append(f"{shown}: kustomizations nested more than {MAX_KUSTOMIZE_DEPTH} deep")
        return
    if inline is not None:
        out.undetermined.append(f"{shown}: -k {show(raw, 80)}: kustomizations are read from files only (CLI)")
        return
    where, why = tree.locate(raw, base)
    if where is None or not where.is_dir():
        out.undetermined.append(f"{shown}: -k {show(raw, 120)}: {why or 'not a directory'}")
        return
    kfile = next((where / n for n in KUSTOMIZATION_FILES if (where / n).is_file()), None)
    if kfile is None:
        out.undetermined.append(f"{shown}: {tree.uri(where) or '.'} has no kustomization file")
        return
    text, why = tree.read(kfile)
    if text is None:
        out.undetermined.append(f"{shown}: {tree.uri(kfile)}: {why}")
        return
    try:
        docs = sanitize.safe_load_all_bounded(text)
    except Exception as exc:  # noqa: BLE001 - any parse failure is a file not read
        out.undetermined.append(f"{shown}: {tree.uri(kfile)}: not readable YAML ({exc.__class__.__name__})")
        return
    data = docs[0] if len(docs) == 1 and isinstance(docs[0], dict) else None
    if data is None:
        out.undetermined.append(f"{shown}: {tree.uri(kfile)}: not one kustomization object")
        return
    extra = sorted(k for k in data if k not in _KUSTOMIZE_PLAIN)
    if extra:
        out.undetermined.append(
            f"{shown}: {tree.uri(kfile)} uses {', '.join(show(k, 40) for k in extra[:5])}, which transform the "
            f"resources; verify does not run kustomize. Render it (kustomize build {tree.uri(where) or '.'} > "
            "rendered.yaml) and verify the file"
        )
        return
    resources = data.get("resources") or []
    if not isinstance(resources, list) or not all(isinstance(r, str) for r in resources):
        out.undetermined.append(f"{shown}: {tree.uri(kfile)}: resources is not a list of paths")
        return
    if not resources:
        out.undetermined.append(f"{shown}: {tree.uri(kfile)} lists no resources")
    for r in resources:
        loc, why = tree.locate(r, where)
        if loc is None:
            out.undetermined.append(f"{shown}: {tree.uri(kfile)}: resource {show(r, 120)}: {why}")
        elif loc.is_dir():
            _kustomization(tree.uri(loc), shown, out, tree, tree.root, inline, depth + 1)
        else:
            text, why = tree.read(loc)
            if text is None:
                out.undetermined.append(f"{shown}: {tree.uri(loc)}: {why}")
            else:
                out.sources.append(_source(tree.uri(loc), text))


def _patch(
    cmd: shell.Command,
    positional: list[str],
    files: list[tuple[str, bool]],
    patch_text: str | None,
    patch_type: str,
    shown: str,
    out: _Read,
    tree: _Tree,
    base: Path,
    stdin: str | None,
    inline: dict[str, str] | None,
) -> None:
    """A JSON merge patch (RFC 7386) or JSON patch (RFC 6902) applied to an object verify has: one named with -f, or
    one in the baseline (`--against`) found by kind and name. A strategic merge patch merges lists by keys only the
    API server knows, so it is not determined."""
    if patch_text is None:
        out.undetermined.append(f"{shown}: patch with no -p or --patch-file")
        return
    if patch_type not in {"merge", "json"}:
        out.undetermined.append(
            f"{shown}: a {show(patch_type, 20)} patch merges lists by keys the API server knows; verify applies "
            "only --type merge and --type json"
        )
        return
    try:
        patch = sanitize.loads_bounded(patch_text)
    except Exception:  # noqa: BLE001
        out.undetermined.append(f"{shown}: the patch is not JSON verify can read")
        return
    target: tuple[str, dict[str, Any]] | None = None
    if files:
        if len(files) != 1 or files[0][1]:
            out.undetermined.append(f"{shown}: patch names more than one file")
            return
        got = _read_named(files[0][0], tree, base, inline, out, shown)
        if got is None:
            return
        docs = [d for d in sanitize.safe_load_all_bounded(got[1]) if isinstance(d, dict)]
        if len(docs) != 1:
            out.undetermined.append(f"{shown}: {got[0]} holds {len(docs)} objects; patch needs exactly one")
            return
        target = (got[0], docs[0])
    else:
        out.undetermined.append(
            f"{shown}: patches an object by name, and verify does not have it. Pass the file that holds it with "
            "-f in the command, or verify the patched file"
        )
        return
    patched = _apply_patch(copy.deepcopy(target[1]), patch, patch_type)
    if patched is None:
        out.undetermined.append(f"{shown}: the patch does not apply to {target[0]}")
        return
    import yaml

    out.baseline.append(_source(target[0], yaml.safe_dump(target[1], sort_keys=False)))
    out.sources.append(_source(f"{target[0]} (patched)", yaml.safe_dump(patched, sort_keys=False)))


def _merge(target: Any, patch: Any) -> Any:
    if not isinstance(patch, dict):
        return copy.deepcopy(patch)
    result = dict(target) if isinstance(target, dict) else {}
    for k, v in patch.items():
        if v is None:
            result.pop(k, None)
        else:
            result[k] = _merge(result.get(k), v)
    return result


def _pointer(doc: Any, ptr: str) -> tuple[Any, str] | None:
    if ptr == "":
        return None
    if not ptr.startswith("/"):
        return None
    parts = [p.replace("~1", "/").replace("~0", "~") for p in ptr[1:].split("/")]
    cur = doc
    for p in parts[:-1]:
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        elif isinstance(cur, list) and p.isdigit() and int(p) < len(cur):
            cur = cur[int(p)]
        else:
            return None
    return cur, parts[-1]


def _apply_patch(obj: dict[str, Any], patch: Any, kind: str) -> dict[str, Any] | None:
    if kind == "merge":
        merged = _merge(obj, patch)
        return merged if isinstance(merged, dict) else None
    if not isinstance(patch, list) or len(patch) > 500:
        return None
    doc: Any = obj
    for op in patch:
        if not isinstance(op, dict) or not isinstance(op.get("path"), str):
            return None
        name = op.get("op")
        loc = _pointer(doc, op["path"])
        if loc is None:
            return None
        parent, member = loc
        if name in {"add", "replace"}:
            if "value" not in op:
                return None
            if isinstance(parent, dict):
                if name == "replace" and member not in parent:
                    return None
                parent[member] = copy.deepcopy(op["value"])
            elif isinstance(parent, list):
                if member == "-" and name == "add":
                    parent.append(copy.deepcopy(op["value"]))
                elif member.isdigit() and int(member) <= len(parent) - (name == "replace"):
                    if name == "add":
                        parent.insert(int(member), copy.deepcopy(op["value"]))
                    else:
                        parent[int(member)] = copy.deepcopy(op["value"])
                else:
                    return None
            else:
                return None
        elif name == "remove":
            if isinstance(parent, dict) and member in parent:
                del parent[member]
            elif isinstance(parent, list) and member.isdigit() and int(member) < len(parent):
                del parent[int(member)]
            else:
                return None
        else:
            return None  # move, copy and test: not modelled, so not applied
    return doc if isinstance(doc, dict) else None


def _helm(
    cmd: shell.Command,
    args: list[str],
    sub: str,
    cls: str,
    shown: str,
    out: _Read,
    tree: _Tree,
    base: Path,
    platform: str,
    version: str | None,
) -> None:
    if sub not in {"install", "upgrade"}:
        if cls not in {"local", "read-only"}:
            why = "removes a release" if sub in {"uninstall", "delete"} else f"`helm {show(sub, 30)}` changes a release"
            out.undetermined.append(f"{shown}: {why}; verify reads no cluster")
        return
    positional: list[str] = []
    values: list[str] = []
    namespace = "default"
    generate_name = False
    i = 0
    helm_value_flags = {
        "-f",
        "--values",
        "-n",
        "--namespace",
        "--version",
        "--timeout",
        "--description",
        "--history-max",
        "--labels",
        "-o",
        "--output",
        "--repo",
        "--post-renderer",
        "--post-renderer-args",
        "--set",
        "--set-string",
        "--set-file",
        "--set-json",
        "--set-literal",
        "--name-template",
        *_TARGETING,
    }
    harmless = {
        "--install",
        "-i",
        "--atomic",
        "--wait",
        "--wait-for-jobs",
        "--timeout",
        "--create-namespace",
        "--description",
        "--history-max",
        "--cleanup-on-fail",
        "--skip-crds",
        "--debug",
        "--labels",
        "--render-subchart-notes",
        "--hide-notes",
        "--no-hooks",
        "--disable-openapi-validation",
        "-o",
        "--output",
        "--dry-run",
        "--rollback-on-failure",
        "--take-ownership",
        "--skip-schema-validation",
        "--reset-values",
        "--dependency-update",
        "--devel",
        "--verify",
        "-n",
        "--namespace",
    }
    sub_seen = False
    while i < len(args):
        t = args[i]
        if not t.startswith("-"):
            if not sub_seen and t == sub:
                sub_seen = True
            else:
                positional.append(t)
            i += 1
            continue
        name_: str = t
        value: str | None = None
        if t.startswith("--") and "=" in t:
            name_, value = t.split("=", 1)
        if value is None and name_ in helm_value_flags:
            value = args[i + 1] if i + 1 < len(args) else ""
            i += 2
        else:
            i += 1
        if name_ in {"-f", "--values"}:
            values.append(value or "")
        elif name_ in {"-n", "--namespace"}:
            namespace = value or "default"
        elif name_ in {"--generate-name", "-g"}:
            generate_name = True
        elif name_ in _TARGETING:
            out.undetermined.append(f"{shown}: {name_} picks the cluster; verify does not know what it holds")
        elif name_ in {
            "--set",
            "--set-string",
            "--set-file",
            "--set-json",
            "--set-literal",
            "--reuse-values",
            "--reset-then-reuse-values",
        }:
            out.undetermined.append(
                f"{shown}: {name_} sets values verify does not pass to helm template; put them in a values file"
            )
        elif name_ in {
            "--repo",
            "--post-renderer",
            "--post-renderer-args",
            "--version",
            "--force",
            "--replace",
            "--name-template",
        }:
            out.undetermined.append(f"{shown}: {name_} is not rendered offline by verify")
        elif name_ not in harmless:
            out.undetermined.append(f"{shown}: {show(name_, 40)} is a helm flag verify does not know the effect of")
    chart_raw = positional[0] if generate_name and positional else (positional[1] if len(positional) > 1 else None)
    if chart_raw is None:
        out.undetermined.append(f"{shown}: names no chart")
        return
    where, why = tree.locate(chart_raw, base)
    if where is None or not (where / "Chart.yaml").is_file():
        out.undetermined.append(
            f"{shown}: chart {show(chart_raw, 120)} is not a chart directory in the working tree "
            f"({why or 'no Chart.yaml'}); verify renders local charts only"
        )
        return
    value_files: list[str] = []
    for v in values:
        loc, why = tree.locate(v, base)
        if loc is None or not loc.is_file():
            out.undetermined.append(f"{shown}: values {show(v, 120)}: {why or 'not a file'}")
            return
        value_files.append(str(loc))
    if out.undetermined:
        return
    try:
        from kube_noob.generate.helm_render import kube_version_arg, render_chart
    except ImportError:
        out.undetermined.append(f"{shown}: this build of kube-noob does not render charts (helm is not run)")
        return
    from kube_noob.errors import KubeNoobError

    left = max(1.0, min(30.0, tree.deadline - time.monotonic()))
    try:
        text = render_chart(
            str(where),
            value_files,
            namespace=namespace,
            release="kube-noob-verify",
            timeout=left,
            kube_version=kube_version_arg(platform, version),
        )
    except (KubeNoobError, OSError, Exception) as exc:  # noqa: BLE001 - a chart that does not render is not read
        out.undetermined.append(f"{shown}: helm template did not render the chart: {show(str(exc), 300)}")
        return
    out.sources.append(_source(f"{tree.uri(where)}/(rendered)", text, chart=tree.uri(where)))


# -- the verdict -------------------------------------------------------------------------------------------------


def _key(f: dict[str, Any]) -> tuple[str, str, str]:
    return (str(f.get("ruleId")), str(f.get("resource")), str(f.get("path")))


def _unread_pods(sources: list[Any]) -> list[str]:
    """Pod specs the audit has no reader for, or in an API group it does not know for the kind: a container no rule
    looked at. The audit's own detectors (``kube_noob.audit.podspec``), not a copy; the gate only notes them, and
    a check before an action cannot allow what it did not read."""
    from kube_noob.audit.podspec import refused_group, unread_pod_specs
    from kube_noob.yamlio import load_documents

    out: list[str] = []
    for s in sources:
        if s.skip or s.unreadable:
            continue
        try:
            docs = load_documents(s.text)
        except Exception:  # noqa: BLE001
            out.append(f"{show(s.uri)} could not be read for pod specs")
            continue
        for d in docs:
            if unread_pod_specs(d):
                out.append(f"{show(d.ref(), 120)} in {show(s.uri)} carries a pod spec no audit rule reads")
            elif refused_group(d) is not None:
                out.append(f"{show(d.ref(), 120)} in {show(s.uri)} is in an API group kube-noob does not read pods for")
    return out


def evaluate(
    sources: list[Any],
    *,
    against: list[Any] | None = None,
    platform: str = "kubernetes",
    version: str | None = None,
    fail_on: str = "high",
    exceptions: str | None = None,
    cni: str | None = None,
    command: _Read | None = None,
    from_command: bool = False,
) -> dict[str, Any]:
    """The verdict for these manifests (and the command that sends them, when there is one).

    Duplicate objects are the audit's own KN-V014 (high), so they deny at the default threshold here exactly as
    they fail the gate; verify keeps no second list of them."""
    from kube_noob import gate
    from kube_noob.audit.model import Severity

    cmd = command or _Read()
    undetermined = list(cmd.undetermined)
    deny = list(cmd.deny)
    not_evaluated: list[dict[str, str]] = list(cmd.not_evaluated)
    report: dict[str, Any] | None = None
    added: list[dict[str, Any]] = []
    preexisting = 0
    if sources:
        try:
            report = gate.run(
                sources, platform=platform, version=version, exceptions=exceptions, fail_on=fail_on, cni=cni
            )
        except gate.GateError as exc:
            if not from_command:
                raise VerifyError(str(exc)) from exc
            undetermined.append(f"the manifests could not be checked: {show(str(exc), 300)}")
    elif (
        from_command
        and not undetermined
        and not deny
        and any(c["class"] not in {"read-only", "local"} for c in cmd.commands)
    ):
        undetermined.append("the command sends nothing verify could read")
    if report is not None:
        for s in report["skipped"]:
            not_evaluated.append({"what": show(s["file"]), "why": show(s["why"])})
            if from_command:
                # kubectl sends every .yaml it is pointed at; a file the audit skipped is one it would still send.
                undetermined.append(f"{show(s['file'])} was not audited ({show(s['why'])}), and kubectl would send it")
        for u in report["unreadable"]:
            not_evaluated.append({"what": show(u["file"]), "why": f"not read: {show(u['why'])}"})
            undetermined.append(f"{show(u['file'])} could not be read ({show(u['why'])})")
        for a in report.get("assumptions") or []:
            not_evaluated.append({"what": "audit", "why": show(a, 600)})
        undetermined.extend(_unread_pods(sources))
        base_keys: Counter[tuple[str, str, str]] = Counter()
        baseline = list(against or []) + list(cmd.baseline)
        if baseline:
            try:
                before = gate.run(
                    baseline, platform=platform, version=version, exceptions=exceptions, fail_on="never", cni=cni
                )
            except gate.GateError as exc:
                raise VerifyError(f"--against: {exc}") from exc
            base_keys = Counter(_key(f) for f in before["findings"])
            for u in before["unreadable"]:
                not_evaluated.append(
                    {"what": f"baseline {show(u['file'])}", "why": "not read, so its findings count as added"}
                )
            not_evaluated.append(
                {
                    "what": "reach",
                    "why": "what the change newly exposes (who can reach what) is not compared; only findings are",
                }
            )
        for f in report["findings"]:
            k = _key(f)
            if base_keys[k] > 0:
                base_keys[k] -= 1
                preexisting += 1
                continue
            added.append(f)
        floor = None if fail_on == "never" else Severity.parse(fail_on)
        failing = [f for f in added if floor is not None and Severity.parse(f["severity"]) >= floor]
        if failing:
            deny.append(f"{len(failing)} finding(s) at {fail_on} or above that this change adds")
        if exceptions:
            from kube_noob.audit import exceptions as exception_list

            if not exception_list.review(exceptions).summary()["gate"]:
                deny.append("the exception list has expired or refused entries (kube-noob exceptions check)")
    verdict = "deny" if deny else ("not-determined" if undetermined else "allow")
    floor = None if fail_on == "never" else Severity.parse(fail_on)
    shown = [_finding(f, floor) for f in added if floor is None or Severity.parse(f["severity"]) >= floor]
    below = len(added) - len(shown)
    klass = max((c["class"] for c in cmd.commands), key=CLASSES.index, default="none")
    result: dict[str, Any] = {
        "verdict": verdict,
        "failOn": fail_on,
        "platform": platform,
        "version": version,
        "class": klass,
        "commands": cmd.commands,
        "deny": sorted(dict.fromkeys(show(d, 400) for d in deny)),
        "notDetermined": list(dict.fromkeys(show(u, 400) for u in undetermined)),
        "findings": shown,
        "belowThreshold": below,
        "preexisting": preexisting,
        "files": [show(s.uri) for s in sources],
        "notEvaluated": not_evaluated,
        "next": _next(shown, sources, platform, version, verdict, fail_on),
        "admission": (report or {}).get("admission"),
    }
    return result


def _finding(f: dict[str, Any], floor: Any) -> dict[str, Any]:
    return {
        "ruleId": f["ruleId"],
        "severity": f["severity"],
        "title": show(f["title"]),
        "uri": show(f["uri"]),
        "line": f.get("line"),
        "resource": show(f["resource"]),
        "path": show(f.get("path") or ""),
        "message": show(f["message"], 400),
        "fix": show(f["remediation"], 300),
        "admission": show(f["admission"]),
    }


def _next(
    findings: list[dict[str, Any]],
    sources: list[Any],
    platform: str,
    version: str | None,
    verdict: str,
    fail_on: str = "high",
) -> list[dict[str, Any]]:
    """`kube-noob fix` for each file whose failing findings the mechanical fixer clears, measured by running it."""
    if verdict != "deny" or not findings:
        return []
    from kube_noob.audit.engine import analyze
    from kube_noob.audit.fixer import fix_manifests
    from kube_noob.catalog import k8s_version_for

    by_uri: dict[str, set[str]] = {}
    for f in findings:
        by_uri.setdefault(f["uri"], set()).add(f["ruleId"])
    texts = {show(s.uri): s for s in sources}
    out: list[dict[str, Any]] = []
    for uri in sorted(by_uri):
        s = texts.get(uri)
        if s is None or s.chart is not None or uri == "stdin" or uri.endswith("(patched)"):
            continue
        try:
            fixed = fix_manifests(s.text, platform=platform, k8s_version=k8s_version_for(platform, version))
            after: set[str] | None = {f.rule_id for f in analyze(fixed.yaml(), platform, version).findings}
        except Exception:  # noqa: BLE001 - no suggestion is better than a wrong one
            after = None
        if after is None:
            continue
        cleared = sorted(r for r in by_uri[uri] if r not in after)
        if not cleared:
            continue
        flags = f" --platform {platform}" + (f" --version {version}" if version and _SAFE_PATH.match(version) else "")
        entry: dict[str, Any] = {"file": uri, "clears": cleared, "remains": sorted(by_uri[uri] - set(cleared))}
        if _SAFE_PATH.match(uri):
            entry["command"] = (
                f"kube-noob fix -f {uri}{flags} -o {uri} && kube-noob verify -f {uri}{flags} --fail-on {fail_on}"
            )
        out.append(entry)
    return out


# -- rendering ---------------------------------------------------------------------------------------------------


def exit_code(result: dict[str, Any], allow_undetermined: bool = False) -> int:
    """AGENTS.md's table, no new meaning: 1 findings at or above --fail-on, 5 incomplete evidence."""
    if result["verdict"] == "deny":
        return 1
    if result["verdict"] == "not-determined" and not allow_undetermined:
        return 5
    return 0


def text(result: dict[str, Any], top: int = MAX_SHOWN) -> str:
    lines = [f"kube-noob verify: {result['verdict']}"]
    target = result["platform"] + (f" {result['version']}" if result.get("version") else "")
    lines.append(f"  checked for {show(target, 40)}, failing at {result['failOn']}; class: {result['class']}")
    for c in result["commands"]:
        via = f" (via {', '.join(c['via'])})" if c.get("via") else ""
        lines.append(f"  command [{c['class']}]: {c['command']}{via}")
    for d in result["deny"]:
        lines.append(f"  denied: {d}")
    for u in result["notDetermined"]:
        lines.append(f"  not determined: {u}")
    findings = result["findings"]
    if findings:
        lines.append(f"findings this change adds at {result['failOn']} or above ({len(findings)}):")
        for f in findings[:top]:
            where = f"{f['uri']}:{f['line']}" if f.get("line") else f["uri"]
            lines.append(f"  [{f['severity'].upper():8}] {f['ruleId']} {where} {f['resource']}: {f['message']}")
            lines.append(f"      fix: {f['fix']}")
            lines.append(f"      admission: {f['admission']}")
        if len(findings) > top:
            lines.append(f"  {len(findings) - top} more finding(s) are not shown here; --format json has all of them")
    if result["belowThreshold"]:
        lines.append(f"  {result['belowThreshold']} finding(s) below {result['failOn']} are not listed")
    if result["preexisting"]:
        lines.append(f"  {result['preexisting']} finding(s) were already in the baseline and are not counted")
    for n in result["next"]:
        if n.get("command"):
            lines.append(f"next: {n['command']}")
        else:
            lines.append(f"next: kube-noob fix on {n['file']} clears {', '.join(n['clears'])}")
        if n["remains"]:
            lines.append(f"      still needs a manual fix: {', '.join(n['remains'])}")
    if result["notEvaluated"]:
        lines.append("not evaluated:")
        for n in result["notEvaluated"]:
            lines.append(f"  - {n['what']}: {n['why']}")
    return "\n".join(lines)


def hook_message(result: dict[str, Any], limit: int = 9_000) -> str:
    """What the agent sees when the hook blocks: the verdict, the reasons, the findings and the next command."""
    head = (
        "kube-noob verify blocked this command: it is not determined to be safe, so a person decides."
        if result["verdict"] == "not-determined"
        else "kube-noob verify blocked this command: it adds findings that fail the check."
    )
    body = text(result, top=10)
    msg = head + "\n" + body
    if result["verdict"] == "not-determined":
        msg += "\nAsk the user to review and run this command, or change it so verify can read what it sends."
    return msg if len(msg) <= limit else msg[: limit - 60] + "\n[cut: run kube-noob verify for the whole report]"


def dumps(result: dict[str, Any]) -> str:
    return json.dumps(result, indent=2, sort_keys=False)
