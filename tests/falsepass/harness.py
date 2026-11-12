"""The false-pass benchmark: inputs that do not decide a verdict, and the pass each one used to be read as.

Over two days of adversarial review (G270-G280) about 250 defects were found before merge, and most had one
shape: an absence, an unknown, an unrecognised shape, a truncated input or a refused read was reported as clean,
allowed, complete or none. The reproducers lived in scratch directories; this corpus keeps them. Each case under
``tests/falsepass/cases/`` names its input, the command line (and, where one exists, the MCP tool), the verdict
class the input decides, and the FORBIDDEN outcome: the false pass as it was observed. The benchmark runs every
case through the real CLI (a subprocess, ``-I``, no network, a fixed environment) and the in-process tool, and
fails when a forbidden outcome appears or the expected one does not.

A case whose fix is on a branch that has not merged carries ``expected_on`` and a ``probe`` that says what the
merge brings (a module, a command, a string in a source file). While the probe is not satisfied the case is run,
its outcome is recorded and printed, and it does not fail the suite; the day the branch merges the probe holds
and the case enforces, with no edit to the corpus. A case is never weakened to pass: a defect this corpus knows
about stays in it until the code answers it.

``scripts/false_pass_report.py`` prints the same corpus as the Markdown table in ``docs/false-pass-benchmark.md``.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import sys
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
import yaml

from kube_noob import sanitize

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
CASES = HERE / "cases"
INPUTS = HERE / "inputs"
STUB_BIN = HERE / "bin"

#: The verdict classes a case may expect. ``error-exit-N`` is the one class checked by its name: N is the exit code.
CLASSES = ("not-determined", "undetermined", "not-evaluated", "deny", "finding")
_ERROR_EXIT = re.compile(r"^error-exit-([0-9]+)\Z")

#: The defect classes of the builder brief, by number. The benchmark reports per class so a reviewer can see which
#: shapes the corpus holds and which it still lacks.
DEFECT_CLASSES: dict[int, str] = {
    1: "a skipped input reads as complete",
    2: "truncation hides the worst item",
    3: "substring matching on errors or kinds",
    4: "an unknown or unrecognised value reads as the benign default",
    5: "duplicates and ordering",
    6: "the caveat exists only in JSON",
    7: "input-derived strings forge output",
    8: "docs claim what the code does not do",
    9: "a second source of truth",
    10: "tests that fail only in CI",
    11: "the object asked about is not the object answered",
    12: "quadratic loops inside caps",
    13: "the verdict word contradicts the counts",
    14: "a rule about a kind that is absent counts as evaluated and clean",
    15: "a match tier hides what it did not match",
    16: "a crash, an empty stdout or a truncated document is read as an answer",
    17: "untrusted text in fields that read as the tool's own words",
    18: "a fixed, guessable delimiter, temp path or id",
    19: "a network-reachable endpoint with no time budget",
    20: "a default that silently loses data across replicas or sessions",
    21: "fixing the reported shape, not its neighbours",
    22: "parsing argv or flags without the real parser's rules",
}

#: Seconds one CLI run may take. Every input is small by construction (large ones are generated in code), so a run
#: that takes longer is itself a finding -- the quadratic-loop class -- and the case fails rather than waits.
TIMEOUT_SECONDS = 120.0

#: Characters of input-derived text shown in a failure message. Inputs are hostile on purpose.
SHOWN = 400

#: Where the test session keeps every case's outcome, for the table tests/conftest.py prints at the end.
STASH_KEY: pytest.StashKey[list[Any]] = pytest.StashKey()

_ENV_KEEP = ("PATH", "LANG", "LC_ALL", "TMPDIR", "SYSTEMROOT", "PYTHONHASHSEED")


class CaseError(ValueError):
    """A case file that the harness refuses: the corpus is a contract and a malformed case must not pass by accident."""


@dataclass(frozen=True)
class Checks:
    """What an output must (``expect``) or must never (``forbid``) show. ``json`` holds for every value at the path,
    ``json_any`` for at least one value at each path, ``json_one_of`` when at least one of its paths matches (a
    decline and a finding are both honest answers; a clean read of the same input is not)."""

    exit: tuple[int, ...] = ()
    json: dict[str, Any] = field(default_factory=dict)
    json_any: dict[str, Any] = field(default_factory=dict)
    json_one_of: dict[str, Any] = field(default_factory=dict)
    text: tuple[str, ...] = ()
    stderr: tuple[str, ...] = ()

    @classmethod
    def read(cls, raw: Any, where: str) -> Checks:
        if raw is None:
            return cls()
        if not isinstance(raw, dict):
            raise CaseError(f"{where}: expect/forbid must be a mapping")
        unknown = set(raw) - {"exit", "json", "json_any", "json_one_of", "text", "stderr", "what"}
        if unknown:
            raise CaseError(f"{where}: unknown keys {sorted(unknown)}")
        exits = raw.get("exit", [])
        if isinstance(exits, int):
            exits = [exits]
        if not all(isinstance(e, int) for e in exits):
            raise CaseError(f"{where}: exit must be an integer or a list of them")
        for key in ("json", "json_any", "json_one_of"):
            if not isinstance(raw.get(key, {}), dict):
                raise CaseError(f"{where}: {key} must be a mapping of path to value")
        for key in ("text", "stderr"):
            if not all(isinstance(t, str) and t for t in raw.get(key, [])):
                raise CaseError(f"{where}: {key} must be a list of non-empty strings")
        return cls(
            exit=tuple(exits),
            json=dict(raw.get("json", {})),
            json_any=dict(raw.get("json_any", {})),
            json_one_of=dict(raw.get("json_one_of", {})),
            text=tuple(raw.get("text", [])),
            stderr=tuple(raw.get("stderr", [])),
        )

    @property
    def empty(self) -> bool:
        return not (self.exit or self.json or self.json_any or self.json_one_of or self.text or self.stderr)


@dataclass(frozen=True)
class Probe:
    """How the harness tells that the fix a case waits for has landed. One of: a module importable, a CLI command
    accepted (``command``), or a string in a source file (``grep``)."""

    kind: str
    value: str
    file: str = ""

    @classmethod
    def read(cls, raw: Any, where: str) -> Probe:
        if not isinstance(raw, dict) or len(raw) != 1:
            raise CaseError(f"{where}: probe must be one of module:, command:, grep:")
        (kind, value), *_ = raw.items()
        if kind == "module" and isinstance(value, str) and value:
            return cls("module", value)
        if kind == "command" and isinstance(value, list) and value and all(isinstance(v, str) for v in value):
            return cls("command", " ".join(value))
        if kind == "grep" and isinstance(value, dict) and set(value) == {"file", "text"}:
            file, text = value["file"], value["text"]
            if isinstance(file, str) and isinstance(text, str) and text:
                return cls("grep", text, file)
        raise CaseError(f"{where}: probe {kind!r} is not one the harness knows")

    def satisfied(self) -> bool:
        if self.kind == "module":
            try:
                return importlib.util.find_spec(self.value) is not None
            except (ModuleNotFoundError, ValueError):
                return False
        if self.kind == "grep":
            path = ROOT / self.file
            return path.is_file() and self.value in path.read_text("utf-8")
        # command: argparse exits 2 for a subcommand it does not know, and prints usage for --help on one it does.
        proc = subprocess.run(
            [sys.executable, "-I", "-m", "kube_noob.cli", *self.value.split(), "--help"],
            capture_output=True,
            text=True,
            check=False,
            timeout=TIMEOUT_SECONDS,
            env=fixed_env(ROOT),
        )
        return proc.returncode == 0


@dataclass(frozen=True)
class Case:
    id: str
    defect_class: int
    verdict_class: str
    summary: str
    provenance: str
    expected_on: str | None
    probe: Probe | None
    inputs: str | None
    generate: str | None
    argv: tuple[str, ...]
    env: dict[str, str]
    kubectl: str | None
    expect: Checks
    forbid: Checks
    forbidden_what: str
    mcp_tool: str | None
    mcp_args: dict[str, Any]
    mcp_expect: Checks
    mcp_forbid: Checks
    path: Path

    @property
    def enforced(self) -> bool:
        """True when the case counts: no branch is waited for, or the probe says its fix is present."""
        return self.probe is None or self.probe.satisfied()


def _str(raw: dict[str, Any], key: str, where: str, required: bool = True) -> str:
    value = raw.get(key)
    if value is None and not required:
        return ""
    if not isinstance(value, str) or not value.strip():
        raise CaseError(f"{where}: {key} must be a non-empty string")
    return value.strip()


def load_case(path: Path) -> Case:
    where = path.name
    raw = yaml.safe_load(path.read_text("utf-8"))
    if not isinstance(raw, dict):
        raise CaseError(f"{where}: not a mapping")
    allowed = {
        "id", "class", "verdict", "summary", "provenance", "expected_on", "probe", "inputs", "generate",
        "cli", "mcp", "expect", "forbid",
    }  # fmt: skip
    unknown = set(raw) - allowed
    if unknown:
        raise CaseError(f"{where}: unknown keys {sorted(unknown)}")
    case_id = _str(raw, "id", where)
    if case_id != path.stem or not re.fullmatch(r"[a-z0-9][a-z0-9-]{2,80}", case_id):
        raise CaseError(f"{where}: id must equal the file name and be lower-case words joined by '-'")
    defect_class = raw.get("class")
    if not isinstance(defect_class, int) or defect_class not in DEFECT_CLASSES:
        raise CaseError(f"{where}: class must be a defect class number 1-{max(DEFECT_CLASSES)}")
    verdict = _str(raw, "verdict", where)
    error_exit = _ERROR_EXIT.match(verdict)
    if verdict not in CLASSES and not error_exit:
        raise CaseError(f"{where}: verdict must be one of {CLASSES} or error-exit-N")
    expected_on = raw.get("expected_on")
    probe = None
    if expected_on is not None:
        if not isinstance(expected_on, str) or not expected_on:
            raise CaseError(f"{where}: expected_on must be a branch name")
        if "probe" not in raw:
            raise CaseError(f"{where}: a case with expected_on needs a probe that says when the fix has landed")
        probe = Probe.read(raw["probe"], where)
    elif "probe" in raw:
        raise CaseError(f"{where}: a probe without expected_on would never enforce")
    inputs = raw.get("inputs")
    if inputs is not None and (not isinstance(inputs, str) or not (INPUTS / inputs).is_dir()):
        raise CaseError(f"{where}: inputs must name a directory under tests/falsepass/inputs")
    generate = raw.get("generate")
    if generate is not None and (not isinstance(generate, str) or generate not in GENERATORS):
        raise CaseError(f"{where}: generate must name one of {sorted(GENERATORS)}")
    cli = raw.get("cli")
    if not isinstance(cli, dict) or not isinstance(cli.get("argv"), list) or not cli["argv"]:
        raise CaseError(f"{where}: cli.argv is required")
    if not all(isinstance(a, str) for a in cli["argv"]):
        raise CaseError(f"{where}: cli.argv must be strings")
    env = cli.get("env", {})
    if not isinstance(env, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in env.items()):
        raise CaseError(f"{where}: cli.env must map strings to strings")
    kubectl = cli.get("kubectl")
    if kubectl is not None and (inputs is None or not (INPUTS / inputs / kubectl).is_dir()):
        raise CaseError(f"{where}: cli.kubectl must name a scenario directory inside the case's inputs")
    expect = Checks.read(raw.get("expect"), where + " expect")
    forbid = Checks.read(raw.get("forbid"), where + " forbid")
    if expect.empty:
        raise CaseError(f"{where}: expect must assert something; a case with no expectation cannot fail")
    if forbid.empty:
        raise CaseError(f"{where}: forbid must name the false pass; that is what the benchmark exists to refuse")
    forbidden_what = raw.get("forbid", {}).get("what")
    if not isinstance(forbidden_what, str) or not forbidden_what.strip():
        raise CaseError(f"{where}: forbid.what must say, in words, what the false pass looked like")
    if error_exit and tuple(expect.exit) != (int(error_exit.group(1)),):
        raise CaseError(f"{where}: verdict {verdict} must expect exactly exit {error_exit.group(1)}")
    if not error_exit and not (expect.json or expect.json_any or expect.json_one_of or expect.text or expect.stderr):
        raise CaseError(f"{where}: verdict {verdict} must be asserted in the output, not only by exit code")
    mcp = raw.get("mcp")
    mcp_tool, mcp_args, mcp_expect, mcp_forbid = None, {}, Checks(), Checks()
    if mcp is not None:
        if not isinstance(mcp, dict) or not isinstance(mcp.get("tool"), str) or not isinstance(mcp.get("args"), dict):
            raise CaseError(f"{where}: mcp needs tool: and args:")
        mcp_tool, mcp_args = mcp["tool"], dict(mcp["args"])
        mcp_expect = Checks.read(mcp.get("expect"), where + " mcp.expect")
        mcp_forbid = Checks.read(mcp.get("forbid"), where + " mcp.forbid")
        if mcp_expect.empty or mcp_forbid.empty:
            raise CaseError(f"{where}: mcp.expect and mcp.forbid must both assert something")
        if mcp_expect.exit or mcp_forbid.exit or mcp_expect.stderr or mcp_forbid.stderr:
            raise CaseError(f"{where}: an in-process tool has no exit code or stderr; use json/json_any/text")
    return Case(
        id=case_id,
        defect_class=defect_class,
        verdict_class=verdict,
        summary=_str(raw, "summary", where),
        provenance=_str(raw, "provenance", where),
        expected_on=expected_on,
        probe=probe,
        inputs=inputs,
        generate=generate,
        argv=tuple(cli["argv"]),
        env=dict(env),
        kubectl=kubectl,
        expect=expect,
        forbid=forbid,
        forbidden_what=forbidden_what.strip(),
        mcp_tool=mcp_tool,
        mcp_args=mcp_args,
        mcp_expect=mcp_expect,
        mcp_forbid=mcp_forbid,
        path=path,
    )


def load_cases(directory: Path = CASES) -> list[Case]:
    cases = [load_case(p) for p in sorted(directory.glob("*.yaml"))]
    ids = [c.id for c in cases]
    if len(set(ids)) != len(ids):
        raise CaseError("duplicate case ids")
    return cases


# -- generated inputs ----------------------------------------------------------------------------------------------
# Inputs over a few kilobytes are built here rather than stored: the corpus stays readable in a diff, and the
# shape under test (a count past a cap, a long run of items) is stated as code.


def _csv(name: str, ns: str, version: str = "1.0.0", phase: str = "Succeeded") -> dict[str, Any]:
    return {
        "apiVersion": "operators.coreos.com/v1alpha1",
        "kind": "ClusterServiceVersion",
        "metadata": {"name": name, "namespace": ns},
        "spec": {"version": version, "displayName": name},
        "status": {"phase": phase},
    }


def gen_csv_list_over_cap(target: Path) -> None:
    """A ClusterServiceVersionList longer than the 50,000-item cap, and an empty SubscriptionList: the overflow
    used to be sliced away before it was counted, so the verdict stayed ``listed, complete``."""
    items = [{"metadata": {"name": f"op{i:05d}.v1.0.0", "namespace": f"ns{i % 7}"}} for i in range(50_050)]
    docs = [
        {"apiVersion": "operators.coreos.com/v1alpha1", "kind": "ClusterServiceVersionList", "items": items},
        {"apiVersion": "operators.coreos.com/v1alpha1", "kind": "SubscriptionList", "items": []},
    ]
    with (target / "csvs.json").open("w", encoding="utf-8") as fh:
        json.dump(docs[0], fh, separators=(",", ":"))
    with (target / "subs.json").open("w", encoding="utf-8") as fh:
        json.dump(docs[1], fh, separators=(",", ":"))


def gen_many_bindings_then_cluster_admin(target: Path) -> None:
    """A privileged workload bound to cluster-admin, buried under 130 RoleBindings to a Role that is not in the
    input: the graph's node cap once cut the capability nodes first and the summary said there was none."""
    docs: list[dict[str, Any]] = [
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "web", "namespace": "shop"},
            "spec": {
                "selector": {"matchLabels": {"app": "web"}},
                "template": {
                    "metadata": {"labels": {"app": "web"}},
                    "spec": {
                        "serviceAccountName": "web",
                        "containers": [{"name": "c", "image": "i", "securityContext": {"privileged": True}}],
                    },
                },
            },
        },
        {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "web", "namespace": "shop"}},
        {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRoleBinding",
            "metadata": {"name": "web-admin"},
            "subjects": [{"kind": "ServiceAccount", "name": "web", "namespace": "shop"}],
            "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "cluster-admin"},
        },
    ]
    for i in range(130):
        docs.append(
            {
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "RoleBinding",
                "metadata": {"name": f"rb{i:03d}", "namespace": f"ns{i:03d}"},
                "subjects": [{"kind": "ServiceAccount", "name": "web", "namespace": "shop"}],
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "gone"},
            }
        )
    (target / "bundle.yaml").write_text(yaml.safe_dump_all(docs, sort_keys=True), "utf-8")


def gen_alerts_info_flood_then_critical(target: Path) -> None:
    """299 info alerts with long labels, then one critical ``etcdMembersDown`` last, with a config that caps the
    report at the smallest size allowed: at the cap the critical alert was the one dropped, heading included, while
    the header still counted every alert and said ``diagnosed`` for all of them."""
    alerts = []
    for i in range(299):
        alerts.append(
            {
                "status": "firing",
                "labels": {"alertname": "InfoOnly", "severity": "info", "pod": f"p{i:03d}-" + "x" * 600},
                "annotations": {"summary": "nothing to see " + "y" * 600, "team": "t" * 400},
            }
        )
    alerts.append(
        {
            "status": "firing",
            "labels": {"alertname": "etcdMembersDown", "severity": "critical", "namespace": "openshift-etcd"},
            "annotations": {"summary": "etcd cluster has members that are down"},
        }
    )
    payload = {"version": "4", "status": "firing", "receiver": "kube-noob", "alerts": alerts}
    (target / "payload.json").write_text(json.dumps(payload, separators=(",", ":")), "utf-8")
    (target / "kube-noob.yaml").write_text("offline: true\nalertReports:\n  maxReportBytes: 262144\n", "utf-8")


GENERATORS = {
    "csv-list-over-cap": gen_csv_list_over_cap,
    "many-bindings-then-cluster-admin": gen_many_bindings_then_cluster_admin,
    "alerts-info-flood-then-critical": gen_alerts_info_flood_then_critical,
}


# -- running ----------------------------------------------------------------------------------------------------


def fixed_env(home: Path, extra: dict[str, str] | None = None, kubectl_dir: Path | None = None) -> dict[str, str]:
    """The environment every case runs in: no KUBE_NOOB_* variable from the shell, no config file, no data dir
    with notes in it, no proxy, the offline lock on, and -- for a live case -- a stub kubectl first on PATH."""
    env = {k: v for k, v in os.environ.items() if k in _ENV_KEEP}
    env["HOME"] = str(home)
    env["XDG_CONFIG_HOME"] = str(home / "cfg")
    env["XDG_DATA_HOME"] = str(home / "data")
    env["KUBE_NOOB_DATA_DIR"] = str(home / "data")
    env["KUBE_NOOB_OFFLINE"] = "1"
    env["KUBE_NOOB_LEARNING_ENABLED"] = "false"
    env["PYTHONIOENCODING"] = "utf-8"
    env["NO_COLOR"] = "1"
    env["COLUMNS"] = "120"
    if kubectl_dir is not None:
        env["PATH"] = str(STUB_BIN) + os.pathsep + env.get("PATH", "")
        env["FALSEPASS_KUBECTL"] = str(kubectl_dir)
        env["KUBE_NOOB_CLUSTER_ENABLED"] = "true"
        env["KUBE_NOOB_CLUSTER_BACKEND"] = "kubectl"
    env.update(extra or {})
    return env


@dataclass(frozen=True)
class Run:
    argv: tuple[str, ...]
    exit: int
    stdout: str
    stderr: str
    seconds: float
    json: Any = None


def _materialise(case: Case, work: Path) -> Path:
    """The case's inputs, copied or generated under ``work`` so a run can never write into the corpus."""
    target = work / "in"
    target.mkdir(parents=True, exist_ok=True)
    if case.inputs is not None:
        src = INPUTS / case.inputs
        for p in sorted(src.rglob("*")):
            rel = p.relative_to(src)
            if p.is_symlink():
                (target / rel).symlink_to(os.readlink(p))
            elif p.is_dir():
                (target / rel).mkdir(parents=True, exist_ok=True)
            else:
                (target / rel).parent.mkdir(parents=True, exist_ok=True)
                (target / rel).write_bytes(p.read_bytes())
    if case.generate is not None:
        GENERATORS[case.generate](target)
    return target


def substitute(value: Any, inputs: Path) -> Any:
    """``{inputs}`` is the input directory; ``{text:relative/path}`` is that file's text, for a tool argument."""
    if isinstance(value, str):
        out = value.replace("{inputs}", str(inputs))
        m = re.fullmatch(r"\{text:([^{}]+)\}", out)
        if m:
            return (inputs / m.group(1)).read_text("utf-8")
        return out
    if isinstance(value, list):
        return [substitute(v, inputs) for v in value]
    if isinstance(value, dict):
        return {k: substitute(v, inputs) for k, v in value.items()}
    return value


def run_cli(case: Case, inputs: Path, home: Path, python: str = sys.executable) -> Run:
    """One run of the CLI over ``inputs`` (already materialised), with ``home`` as the process's only writable
    place. Two runs share the inputs so a path in the output cannot differ between them."""
    argv = [str(a) for a in substitute(list(case.argv), inputs)]
    kubectl_dir = inputs / case.kubectl if case.kubectl else None
    home.mkdir(parents=True, exist_ok=True)
    env = fixed_env(home, case.env, kubectl_dir)
    started = time.monotonic()
    try:
        proc = subprocess.run(
            [python, "-I", "-m", "kube_noob.cli", *argv],
            capture_output=True,
            check=False,
            timeout=TIMEOUT_SECONDS,
            env=env,
            cwd=home,
            stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired:
        return Run(tuple(argv), -1, "", f"timed out after {TIMEOUT_SECONDS:.0f} s", TIMEOUT_SECONDS)
    seconds = time.monotonic() - started
    stdout = proc.stdout.decode("utf-8", "replace")
    stderr = proc.stderr.decode("utf-8", "replace")
    parsed: Any = None
    if _wants_json(case):
        try:
            parsed = json.loads(stdout)
        except ValueError:
            parsed = None
    return Run(tuple(argv), proc.returncode, stdout, stderr, seconds, parsed)


def _wants_json(case: Case) -> bool:
    return bool(case.expect.json or case.expect.json_any or case.expect.json_one_of)


def run_mcp(case: Case, inputs: Path) -> tuple[Any, str]:
    """The in-process tool result (a dict) or the error it raised, as (value, text-for-matching)."""
    from kube_noob import tool_runner
    from kube_noob.config import load_settings
    from kube_noob.toolkit import Toolkit

    assert case.mcp_tool is not None
    args = substitute(case.mcp_args, inputs)
    overrides: dict[str, Any] = {"offline": True, "learningEnabled": False}
    saved = {k: os.environ.get(k) for k in ("PATH", "FALSEPASS_KUBECTL")}
    if case.kubectl:
        # A live tool reads the same stub cluster the CLI did, through the same backend.
        overrides["cluster"] = {"enabled": True, "backend": "kubectl"}
        os.environ["PATH"] = str(STUB_BIN) + os.pathsep + os.environ.get("PATH", "")
        os.environ["FALSEPASS_KUBECTL"] = str(inputs / case.kubectl)
    try:
        kit = Toolkit(load_settings(overrides=overrides))
        specs = {s.name: s for s in kit.specs()}
        if case.mcp_tool not in specs:
            return None, f"tool {case.mcp_tool} is not offered"
        try:
            result = tool_runner.call(specs[case.mcp_tool], args, "test")
        except Exception as exc:  # noqa: BLE001 - the error IS the outcome under test
            return {"error": type(exc).__name__, "message": str(exc)}, f"{type(exc).__name__}: {exc}"
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    return result, json.dumps(result, sort_keys=True, ensure_ascii=False)


# -- matching ---------------------------------------------------------------------------------------------------


def resolve(data: Any, path: str) -> list[Any]:
    """Every value at ``path`` in ``data``: ``a.b`` descends mappings, ``a[0]`` indexes, ``a[*]`` fans out over a
    list, and a missing step yields nothing (never a default)."""
    tokens = re.findall(r"[^.\[\]]+|\[\*\]|\[-?\d+\]", path)
    current: list[Any] = [data]
    for tok in tokens:
        nxt: list[Any] = []
        for item in current:
            if tok == "[*]":
                if isinstance(item, list):
                    nxt.extend(item)
            elif tok.startswith("["):
                if isinstance(item, list):
                    idx = int(tok[1:-1])
                    if -len(item) <= idx < len(item):
                        nxt.append(item[idx])
            elif isinstance(item, dict) and tok in item:
                nxt.append(item[tok])
        current = nxt
    return current


def _matches(value: Any, wanted: Any) -> bool:
    if isinstance(wanted, dict) and set(wanted) == {"in"}:
        return value in wanted["in"]
    if isinstance(wanted, dict) and set(wanted) == {"contains"}:
        return isinstance(value, str) and wanted["contains"] in value
    return bool(value == wanted)


def violations(checks: Checks, run: Run | None, data: Any, text: str, stderr: str, forbid: bool) -> list[str]:
    """What ``checks`` found wrong. With ``forbid`` every listed thing must be absent; otherwise present."""
    out: list[str] = []
    verb = "forbidden" if forbid else "expected"
    if run is not None and checks.exit:
        hit = run.exit in checks.exit
        if forbid and hit:
            out.append(f"{verb} exit {run.exit}")
        if not forbid and not hit:
            out.append(f"{verb} exit in {list(checks.exit)}, got {run.exit}")
    for path, wanted in checks.json.items():
        values = resolve(data, path)
        if forbid:
            if any(_matches(v, wanted) for v in values):
                out.append(f"{verb} {path} == {_show(wanted)}")
        elif not values or not all(_matches(v, wanted) for v in values):
            out.append(f"{verb} {path} == {_show(wanted)}, got {_show(values)}")
    for path, wanted in checks.json_any.items():
        values = resolve(data, path)
        if forbid:
            if any(_matches(v, wanted) for v in values):
                out.append(f"{verb} some {path} == {_show(wanted)}")
        elif not any(_matches(v, wanted) for v in values):
            out.append(f"{verb} some {path} == {_show(wanted)}, got {_show(values)}")
    if checks.json_one_of:
        hits = [p for p, w in checks.json_one_of.items() if any(_matches(v, w) for v in resolve(data, p))]
        if forbid and hits:
            out.append(f"{verb} {hits[0]} == {_show(checks.json_one_of[hits[0]])}")
        if not forbid and not hits:
            out.append(f"{verb} one of {_show(checks.json_one_of)}, none matched")
    for needle in checks.text:
        if forbid and needle in text:
            out.append(f"{verb} text {needle!r}")
        if not forbid and needle not in text:
            out.append(f"{verb} text {needle!r} missing")
    for needle in checks.stderr:
        if forbid and needle in stderr:
            out.append(f"{verb} stderr {needle!r}")
        if not forbid and needle not in stderr:
            out.append(f"{verb} stderr {needle!r} missing")
    return out


def _show(value: Any) -> str:
    """A value from a run, made printable: input-derived text is hostile and goes through the one boundary."""
    text = json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)
    text = " ".join(sanitize.visible(text).split())
    return text if len(text) <= SHOWN else text[:SHOWN] + f"... ({len(text)} characters)"


@dataclass
class Outcome:
    case: Case
    enforced: bool
    problems: list[str]
    seconds: float
    ran_mcp: bool

    @property
    def passed(self) -> bool:
        return not self.problems


def evaluate(case: Case, work: Path, python: str = sys.executable, *, mcp: bool = True) -> Outcome:
    """Run the case through the CLI twice (the bytes must agree) and through the tool, and judge both."""
    problems: list[str] = []
    inputs = _materialise(case, work)
    first = run_cli(case, inputs, work / "home1", python)
    if first.exit == -1:
        problems.append(f"CLI: {first.stderr}")
        return Outcome(case, case.enforced, problems, first.seconds, False)
    second = run_cli(case, inputs, work / "home2", python)
    if first.stdout != second.stdout or first.exit != second.exit:
        problems.append("CLI: two runs of the same input gave different bytes or exit codes")
    if _wants_json(case) and first.json is None:
        problems.append("CLI: stdout is not JSON: " + _show(first.stdout[:SHOWN]))
    problems += ["CLI: " + p for p in violations(case.forbid, first, first.json, first.stdout, first.stderr, True)]
    problems += ["CLI: " + p for p in violations(case.expect, first, first.json, first.stdout, first.stderr, False)]
    ran_mcp = False
    if mcp and case.mcp_tool is not None:
        ran_mcp = True
        value, text = run_mcp(case, inputs)
        problems += ["MCP: " + p for p in violations(case.mcp_forbid, None, value, text, "", True)]
        problems += ["MCP: " + p for p in violations(case.mcp_expect, None, value, text, "", False)]
    if problems:
        problems.append("argv: " + _show(list(first.argv)))
        problems.append(f"exit {first.exit}; stdout: " + _show(first.stdout) + "; stderr: " + _show(first.stderr))
    return Outcome(case, case.enforced, problems, first.seconds + second.seconds, ran_mcp)


# -- the table --------------------------------------------------------------------------------------------------


def _by(cases: list[Case]) -> Iterator[tuple[str, list[Case]]]:
    yield from ((f"class {n}: {DEFECT_CLASSES[n]}", [c for c in cases if c.defect_class == n]) for n in DEFECT_CLASSES)


def summary_lines(outcomes: list[Outcome]) -> list[str]:
    """The table CI prints: per defect class and per source branch, how many cases, how many enforce today, how
    many wait for a merge (and whether those pass already), and how many failed."""
    lines = ["false-pass benchmark", ""]
    lines.append(f"{'defect class':<70} {'cases':>5} {'enforced':>8} {'waiting':>7} {'failed':>6}")
    for title, group in _by([o.case for o in outcomes]):
        if not group:
            continue
        rows = [o for o in outcomes if o.case in group]
        lines.append(_row(title, rows))
    lines.append("")
    lines.append(f"{'source branch':<70} {'cases':>5} {'enforced':>8} {'waiting':>7} {'failed':>6}")
    for branch in sorted({o.case.expected_on or "main" for o in outcomes}):
        rows = [o for o in outcomes if (o.case.expected_on or "main") == branch]
        lines.append(_row(branch, rows))
    lines.append("")
    waiting = [o for o in outcomes if not o.enforced]
    for o in waiting:
        state = "passes already" if o.passed else "still open"
        lines.append(f"  waiting for {o.case.expected_on}: {o.case.id} ({state})")
    lines.append(_row("total", outcomes))
    return lines


def _row(title: str, rows: list[Outcome]) -> str:
    enforced = sum(1 for o in rows if o.enforced)
    waiting = sum(1 for o in rows if not o.enforced)
    failed = sum(1 for o in rows if o.enforced and not o.passed)
    return f"{title[:70]:<70} {len(rows):>5} {enforced:>8} {waiting:>7} {failed:>6}"
