#!/usr/bin/env python3
"""Every number and recorded terminal line a demo video shows or says, computed when the video is built.

The scripts never type a count by hand. A voice-over line, caption or terminal line in stage/videos.json or the
voice-over table in demos/youtube-walkthrough.md writes {name} where a number goes, {name:words} to spell it out for
the voice ("sixty-three"), and a terminal line "@name" is replaced by a recording made now. A release that changes a
count, a score or a line number therefore changes the video, and tests/test_video_facts.py fails a script that types a
number instead.

Usage:
  python demos/video/facts.py [--sidecar <transcript.txt>]          print every fact as JSON
  python demos/video/facts.py fill <file> [--sidecar <transcript>]  print <file> with each {name} filled in

Facts:
  version, rules, selftest                       the installed kube-noob
  audit.score, audit.critical, audit.high, audit.medium, audit.low
                                                 examples/insecure-deployment.yaml for OpenShift 4.22, through the
                                                 same audit tool Claude calls
  fix.changes, fix.manual, fix.score             the same file through the fix tool (score after the fixes)
  scan.findings, scan.unevaluated, scan.evaluated, scan.replicas, scan.exit, scan.verdict,
  scan.object, scan.why                          the adversarial corpus case whose every severity count is
                                                 honestly zero (demos/video/facts.py SCAN)
  walk.hops, walk.holds, walk.unchecked, walk.judged, walk.unwalked, walk.broken_rule,
  walk.complete_exit, walk.broken_exit, walk.fragment_exit
                                                 `kube-noob learn mechanism` on the three inputs the walk video
                                                 shows (demos/video/facts.py WALKS)
  protocol.steps, protocol.score                 `kube-noob demo protocol` (the walkthrough's chapter 3)
  sidecar.version, sidecar.tools, sidecar.peak, sidecar.limit
                                                 the transcript scripts/demo_sidecar_kind.sh records on a kind cluster
                                                 in CI (--sidecar, or KN_SIDECAR_TRANSCRIPT)
Recordings: @cli:audit (the CLI audit of that file), @tool:audit (Claude's audit and fix tool calls on it, as the
plugin shows them), @sidecar:client (the app calling the sidecar on 127.0.0.1, and the closed pod port, from the CI
transcript).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
# The source tree whose example and sidecar manifest the facts describe: the release tag's checkout when
# .github/workflows/videos.yml renders an older tag with a newer pipeline (pipeline_ref); this tree otherwise.
PRODUCT = Path(os.environ.get("KN_PRODUCT_ROOT") or ROOT).resolve()
EXAMPLE = "examples/insecure-deployment.yaml"
SIDECAR_MANIFEST = "deploy/sidecar/app-with-kube-noob-sidecar.yaml"
#: The adversarial corpus case the scan video is about: a privileged container inside a kind no rule reads,
#: so every severity count is honestly zero and the honest answer is still not a pass. `honest-answer.yaml`
#: beside it pins the verdict word and the exit code, and `scripts/corpus_run.py` reproduces it.
SCAN = "corpus/09-a-rollout-with-a-privileged-container/manifests/rollout.yaml"
#: The mechanism walk the walk video is about, and the three inputs it is shown on. The first two are the
#: fixture's own directories (a directory is taken to be the whole namespace). The third is the SAME bundle as
#: the first, passed as one file: a file is a fragment of a namespace, so the policy hop cannot be judged and the
#: walk stops there -- tests/fixtures/mechanism/README.md, "Exit 5".
WALK_LESSON = "mech-net-request-to-pod"
WALKS = {
    "complete": "tests/fixtures/mechanism/complete",
    "broken": "tests/fixtures/mechanism/broken",
    "fragment": "tests/fixtures/mechanism/complete/bundle.yaml",
}
#: A hop the walk stopped before. `learn mechanism` prints no mark for one -- it prints the sentence the scene
#: shows under the path -- so this is the one state the video names itself, and it is never `holds`.
NOT_WALKED = ("not-walked", "not walked")
PLATFORM, VERSION = "openshift", "4.22"
PLACEHOLDER = re.compile(r"\{([a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*)(?::(words))?\}")
RECORDING = re.compile(r"^@([a-z]+:[a-z]+)$")


class FactError(ValueError):
    pass


def _num(x: float) -> int | float:
    return int(x) if float(x).is_integer() else round(float(x), 1)


_ONES = [
    "zero",
    "one",
    "two",
    "three",
    "four",
    "five",
    "six",
    "seven",
    "eight",
    "nine",
    "ten",
    "eleven",
    "twelve",
    "thirteen",
    "fourteen",
    "fifteen",
    "sixteen",
    "seventeen",
    "eighteen",
    "nineteen",
]
_TENS = ["_", "_", "twenty", "thirty", "forty", "fifty", "sixty", "seventy", "eighty", "ninety"]


def words(n: int) -> str:
    """63 -> "sixty-three" (0 to 9999), for voice lines."""
    if not 0 <= n <= 9999 or n != int(n):
        raise FactError(f"cannot spell {n}")
    n = int(n)
    if n < 20:
        return _ONES[n]
    if n < 100:
        return _TENS[n // 10] + ("" if n % 10 == 0 else "-" + _ONES[n % 10])
    if n < 1000:
        rest = n % 100
        return _ONES[n // 100] + " hundred" + ("" if rest == 0 else " and " + words(rest))
    rest = n % 1000
    return words(n // 1000) + " thousand" + ("" if rest == 0 else (" and " if rest < 100 else " ") + words(rest))


def _product(rel: str) -> Path:
    path = PRODUCT / rel
    if not path.is_file():
        raise FactError(f"{path} not found (KN_PRODUCT_ROOT={os.environ.get('KN_PRODUCT_ROOT', '')!r})")
    return path


def _cli(*args: str) -> str:
    _product(EXAMPLE)
    r = subprocess.run(
        [sys.executable, "-m", "kube_noob", *args],
        cwd=PRODUCT,
        capture_output=True,
        text=True,
        check=False,
        timeout=600,
    )
    if r.returncode not in (0, 1) or not r.stdout.strip():  # audit exits 1 when it finds problems
        raise FactError(f"`kube-noob {' '.join(args)}` failed ({r.returncode}): {r.stderr.strip()[:300]}")
    return r.stdout


def _kit() -> Any:
    from kube_noob.config import load_settings
    from kube_noob.toolkit import Toolkit

    return Toolkit(load_settings(overrides={"offline": True}))


def parse_transcript(text: str) -> list[dict[str, Any]]:
    """`# caption` / `$ command` / output lines, the format scripts/demo_sidecar_kind.sh writes."""
    steps: list[dict[str, Any]] = []
    for line in text.splitlines():
        if line.startswith("# "):
            steps.append({"caption": line[2:], "command": "", "output": []})
        elif line.startswith("$ ") and steps and not steps[-1]["command"]:
            steps[-1]["command"] = line[2:]
        elif steps and steps[-1]["command"]:
            steps[-1]["output"].append(line)
    for s in steps:
        while s["output"] and not s["output"][-1].strip():
            s["output"].pop()
    return steps


_QUANTITY = re.compile(r"(\d+(?:\.\d+)?)([KMGTPE]i|[kMGTPE]|)")
_UNITS = {"": 1, "k": 10**3, "M": 10**6, "G": 10**9, "T": 10**12, "P": 10**15, "E": 10**18}
_UNITS.update({f"{u}i": 2 ** (10 * (i + 1)) for i, u in enumerate("KMGTPE")})


def _manifest_limit_mib() -> int:
    """limits.memory of the kube-noob container in the sidecar example, in MiB (rounded down, as the cgroup is)."""
    import yaml

    for doc in yaml.safe_load_all(_product(SIDECAR_MANIFEST).read_text(encoding="utf-8")):
        if doc and doc.get("kind") == "Deployment":
            for c in doc["spec"]["template"]["spec"]["containers"]:
                if c["name"] != "kube-noob":
                    continue
                value = str(((c.get("resources") or {}).get("limits") or {}).get("memory", ""))
                m = _QUANTITY.fullmatch(value)
                if not m:
                    raise FactError(f"{SIDECAR_MANIFEST}: kube-noob memory limit {value!r} is not a quantity")
                return int(float(m.group(1)) * _UNITS[m.group(2)]) // 2**20
    raise FactError(f"{SIDECAR_MANIFEST}: no kube-noob container")


def _payoff(
    manifests: str, rules: dict[str, Any], shown: list[dict[str, Any]], fix: dict[str, Any], values: dict[str, Any]
) -> dict[str, Any]:
    lines = manifests.splitlines()
    marked = sorted({x["line"] for x in shown if x["line"]})
    first, last = max(1, marked[0] - 9), min(len(lines), marked[-1] + 1)
    fixed_rules = {c["ruleId"] for c in fix["changes"]}

    def value(v: Any) -> str:
        if isinstance(v, bool):
            return str(v).lower()
        if isinstance(v, dict):
            return "{" + ", ".join(f"{k}: {value(x)}" for k, x in v.items()) + "}"
        if isinstance(v, list):
            return "[" + ", ".join(value(x) for x in v) + "]"
        return str(v)

    diff = []
    for c in fix["changes"]:
        name = c["path"].rsplit(".", 1)[-1]
        if c.get("before") is not None:
            diff.append({"op": "-", "text": f"{name}: {value(c['before'])}"})
        if c.get("after") is not None:
            diff.append({"op": "+", "text": f"{name}: {value(c['after'])}"})
    return {
        "yaml": [{"n": i, "text": lines[i - 1]} for i in range(first, last + 1)],
        "findings": [
            {"rule": x["ruleId"], "severity": x["severity"], "line": x["line"], "title": rules[x["ruleId"]]["title"]}
            for x in shown
        ],
        "fixedLines": [x["line"] for x in shown if x["ruleId"] in fixed_rules],
        "diff": diff,
        "score": values["audit.score"],
        "fixed": values["fix.score"],
        "manual": values["fix.manual"],
    }


def _change(c: dict[str, Any]) -> str:
    def show(v: Any) -> str:
        if v is None:
            return "removed" if c.get("before") is not None else "unset"
        if isinstance(v, bool):
            return str(v).lower()
        if isinstance(v, dict) and "type" in v:
            return str(v["type"])
        if isinstance(v, list):
            return ",".join(map(str, v))
        return str(v)

    name = c["path"].rsplit(".", 1)[-1]
    return (
        f"{name} → {show(c['after'])}"
        if c.get("before") is None
        else f"{name}: {show(c['before'])} → {show(c['after'])}"
    )


class Facts:
    """The facts, each group computed the first time one of its names is asked for."""

    def __init__(self, sidecar: Path | str | None = None) -> None:
        env = os.environ.get("KN_SIDECAR_TRANSCRIPT")
        self.sidecar = Path(sidecar) if sidecar else Path(env) if env else None
        self._values: dict[str, Any] = {}
        self._recordings: dict[str, list[str]] = {}
        self._groups: dict[str, Callable[[], None]] = {
            "version": self._base,
            "rules": self._base,
            "selftest": self._base,
            "audit": self._audit,
            "fix": self._audit,
            "protocol": self._protocol,
            "sidecar": self._sidecar,
            "cli": self._cli_audit,
            "tool": self._audit,
            "scan": self._scan,
            "walk": self._walk,
        }
        self._walks: dict[str, dict[str, Any]] = {}
        self._done: set[str] = set()

    # ---------------------------------------------------------------- groups

    def _base(self) -> None:
        from kube_noob import __version__
        from kube_noob.audit.engine import list_rules

        self._values["version"] = __version__
        self._values["rules"] = len(list_rules())
        self._values["selftest"] = int(json.loads(_cli("--format", "json", "selftest"))["total"])

    def _audit(self) -> None:
        from kube_noob.audit.engine import list_rules
        from kube_noob.toolkit import AuditIn, FixIn

        kit = _kit()
        manifests = _product(EXAMPLE).read_text(encoding="utf-8")
        # EXAMPLE is one file, and the recording below runs `audit -f <that file>`, which reports a partial
        # bundle. The numbers in the script have to be the numbers on screen, so ask for the same thing.
        a = kit.audit(AuditIn(manifests=manifests, platform=PLATFORM, version=VERSION, partial_bundle=True))
        counts = a["summary"]["counts"]
        self._values.update(
            {
                "audit.score": _num(a["summary"]["score"]),
                "audit.critical": counts["critical"],
                "audit.high": counts["high"],
                "audit.medium": counts["medium"],
                "audit.low": counts["low"],
            }
        )
        f = kit.fix(FixIn(manifests=manifests, platform=PLATFORM, version=VERSION))
        self._values.update(
            {
                "fix.changes": len(f["changes"]),
                "fix.manual": len(f["manualFollowUps"]),
                "fix.score": _num(f["after"]["score"]),
            }
        )
        rules = {r["ruleId"]: r for r in list_rules()}
        high = [x for x in a["findings"] if x["severity"] in ("critical", "high")]
        wiring = [x for x in a["findings"] if x["severity"] == "medium" and rules[x["ruleId"]]["stage"] == "validate"]
        lines = [
            f"● kube-noob · kubenoob_audit_manifests (platform: {PLATFORM}, version: {VERSION})",
            f"  score {self._values['audit.score']} · "
            + (f"critical {counts['critical']} · " if counts["critical"] else "")
            + f"high {counts['high']} · medium {counts['medium']} · low {counts['low']}",
        ]
        lines += [
            f"  {'CRIT' if x['severity'] == 'critical' else 'HIGH'}  {x['ruleId']}  line {x['line']}  "
            f"{rules[x['ruleId']]['title']}"
            for x in high
        ]
        lines += [f"  MED   {x['ruleId']}  line {x['line']}  {rules[x['ruleId']]['title']}" for x in wiring[:1]]
        changes = [_change(c) for c in f["changes"]]
        self._payoff = _payoff(manifests, rules, high + wiring[:1], f, self._values)
        lines.append("● kube-noob · kubenoob_fix_manifests")
        for i in range(0, len(changes), 3):
            lines.append("  " + " · ".join(changes[i : i + 3]))
        lines.append(f"  score after the automatic fixes: {self._values['fix.score']}")
        self._recordings["tool:audit"] = lines

    def _cli_audit(self) -> None:
        args = ["audit", "-f", EXAMPLE, "--platform", PLATFORM, "--version", VERSION]
        out = _cli(*args).splitlines()
        lines = [f"$ kube-noob {' '.join(args)}", out[0]]
        rest = 0
        for i, line in enumerate(out):
            if line.startswith("[HIGH") or line.startswith("[CRITICAL"):
                lines.append(re.sub(r"( L\d+) .*$", r"\1", line))  # the field path makes the line too wide
                lines.append(out[i + 1])
            elif re.match(r"\[(MEDIUM|LOW)", line):
                rest += 1
        if rest:
            lines.append(f"… {rest} medium and low findings, and the fix, RHACS and red-team lines, left out")
        self._recordings["cli:audit"] = lines

    def _scan(self) -> None:
        """The zero that is not a pass, through the same audit tool Claude calls and the same gate CI runs.

        Nothing here is typed. The counts come from the audit, the object's name and the reason it was not read
        come from `notAudited`, and the exit code comes from `receipt.audit_exit_code` -- the one place that
        arithmetic lives -- so the video cannot claim an exit code the command does not return.
        """
        import yaml

        from kube_noob import receipt
        from kube_noob.audit.engine import list_rules
        from kube_noob.toolkit import AuditIn

        manifests = _product(SCAN).read_text(encoding="utf-8")
        a = _kit().audit(AuditIn(manifests=manifests, platform=PLATFORM, partial_bundle=True))
        summary = a["summary"]
        counts = summary["counts"]
        not_audited = a.get("notAudited") or []
        if not not_audited:
            raise FactError(f"{SCAN} is audited in full, so the scan video would be about nothing")
        if sum(counts.values()) or a.get("findings"):
            raise FactError(f"{SCAN} now produces findings, so its zero is no longer the point")
        unevaluated = (a.get("controlSummary") or {}).get("rulesNotEvaluated") or {}
        doc = yaml.safe_load(manifests)
        self._values.update(
            {
                "scan.findings": sum(counts.values()),
                "scan.unevaluated": len(unevaluated),
                "scan.evaluated": len(list_rules()) - len(unevaluated),
                "scan.replicas": int(doc["spec"]["replicas"]),
                "scan.exit": receipt.audit_exit_code(a, "high"),
                "scan.verdict": str(summary.get("verdict")),
                "scan.object": str(not_audited[0]["object"]),
                "scan.why": str(not_audited[0].get("why") or not_audited[0].get("reason") or ""),
            }
        )
        args = ["gate", "-f", str(Path(SCAN).parent)]
        out = _cli(*args).splitlines()
        # Two recordings, not one: the terminal holds about a dozen lines, and a single scene showed the end of
        # the severity table with its own heading scrolled off -- a caption saying every severity is zero over a
        # frame showing two of them.
        table = [ln for ln in out if ln.startswith("| ")]
        if len(table) < 2:
            raise FactError("the gate no longer prints a severity table for this input")
        self._recordings["scan:table"] = [f"$ kube-noob {' '.join(args)}", out[0], "", *table]
        for i, line in enumerate(out):
            if line.startswith("### Not passed"):
                verdict = [line, "", out[i + 2], "", out[i + 4]]
                break
        else:
            raise FactError("the gate no longer prints a `### Not passed` section for this input")
        verdict += ["", f"$ echo $?  -> {self._values['scan.exit']}"]
        self._recordings["scan:verdict"] = verdict

    def _walk_one(self, name: str) -> dict[str, Any]:
        """One run of `learn mechanism`, as the scene draws it: the command, every declared hop with the mark the
        command printed for it, the reason, the finding, and the exit code the process returned."""
        path = WALKS[name]
        if not (PRODUCT / path).exists():
            raise FactError(f"{PRODUCT / path} not found (KN_PRODUCT_ROOT={os.environ.get('KN_PRODUCT_ROOT', '')!r})")
        args = ["learn", "mechanism", WALK_LESSON, "-f", path]
        runs = [
            subprocess.run(
                [sys.executable, "-m", "kube_noob", *args, *extra],
                cwd=PRODUCT,
                capture_output=True,
                text=True,
                check=False,
                timeout=600,
            )
            for extra in (["--format", "json"], [])
        ]
        as_json, as_text = runs
        # 0 holds, 1 broken, 5 stopped: the three answers a walk has. Anything else is a crash, not a walk.
        if (
            as_json.returncode not in (0, 1, 5)
            or not as_json.stdout.strip()
            or as_text.returncode != as_json.returncode
        ):
            raise FactError(
                f"`kube-noob {' '.join(args)}` failed ({as_json.returncode}, {as_text.returncode}): "
                f"{as_json.stderr.strip()[:300]}"
            )
        walked = json.loads(as_json.stdout)
        if walked["exitCode"] != as_json.returncode:
            raise FactError(
                f"`kube-noob {' '.join(args)}` says exit {walked['exitCode']} and exits {as_json.returncode}"
            )
        # The marks are the words the command prints (`3. [holds] ...`), read from its text and not typed here.
        marks = re.findall(r"^\d+\. \[([^\]]+)\] ", as_text.stdout, re.M)
        if len(marks) != len(walked["steps"]):
            raise FactError(f"`kube-noob {' '.join(args)}` prints {len(marks)} hops and reports {len(walked['steps'])}")
        steps = [
            {
                "id": str(s["step"]),
                "title": str(s["title"]),
                "state": str(s["verdict"]),
                "mark": mark,
                "why": str(s["why"]),
                "finding": " · ".join(
                    f"{f['severity'].upper()}  {f['ruleId']}  {f['resource']}  {f['title']}"
                    for f in s.get("findings") or ()
                ),
            }
            for s, mark in zip(walked["steps"], marks, strict=True)
        ]
        note = next((ln for ln in as_text.stdout.splitlines() if "were not walked" in ln), "")
        return {
            "command": f"kube-noob {' '.join(args)}",
            "title": str(walked["title"]),
            "verdict": str(walked["verdict"]),
            "reason": str(walked["verdictReason"]),
            "note": note,
            "exit": as_json.returncode,
            "steps": steps,
            "counts": walked["counts"],
            "stoppedAt": walked.get("stoppedAt"),
        }

    def _walk(self) -> None:
        """The mechanism walk on three inputs, through the command itself. Nothing here is typed: the hops, their
        marks and reasons, the rule that breaks one and all three exit codes are what `learn mechanism` returned.

        The group refuses to render rather than mislead. The video says one walk holds, one names a broken hop
        and one stops at a hop it cannot judge; if the command stops telling any of those three, the scene would
        be drawn from a different story than its caption, so each is checked and raises.
        """
        import yaml

        from kube_noob.learn import mechanism as mech

        walks = {name: self._walk_one(name) for name in WALKS}
        done, broken, part = walks["complete"], walks["broken"], walks["fragment"]
        declared = mech.lessons()[WALK_LESSON]["steps"]
        states = [s["state"] for s in done["steps"]]
        holds, unchecked = states.count("holds"), states.count("not-observable")
        if done["exit"] != 0 or len(states) != len(declared) or holds + unchecked != len(states) or not unchecked:
            raise FactError(f"{WALKS['complete']} no longer holds on every hop a manifest can answer for")
        fails = [s for s in broken["steps"] if s["state"] == "fails" and s["finding"]]
        if broken["exit"] != 1 or not fails or broken["stoppedAt"]:
            raise FactError(f"{WALKS['broken']}: no hop is BROKEN with the walk reaching the end")
        unwalked = int(part["counts"]["notReached"])
        if part["exit"] != 5 or not part["stoppedAt"] or not unwalked or not part["note"]:
            raise FactError(f"{WALKS['fragment']} no longer stops at a hop it cannot judge")
        for w in walks.values():
            # Every declared hop is drawn, and one the walk stopped before is drawn as exactly that.
            w["steps"] += [
                {"id": str(d["id"]), "title": str(d["title"]), "state": NOT_WALKED[0], "mark": NOT_WALKED[1]}
                | {"why": "", "finding": ""}
                for d in declared[len(w["steps"]) :]
            ]
            if [s["id"] for s in w["steps"]] != [str(d["id"]) for d in declared]:
                raise FactError(f"`{w['command']}` walks hops the lesson does not declare, or in another order")
            # The hop the scene reads out: the first one that is anything but `holds`.
            w["focus"] = next(i for i, s in enumerate(w["steps"]) if s["state"] != "holds")
            del w["counts"], w["stoppedAt"]
        rule = re.search(r"\bKN-[A-Z]+\d+\b", fails[0]["finding"])
        if not rule:
            raise FactError(f"{WALKS['broken']}: the broken hop names no rule")
        self._walks = walks
        self._values.update(
            {
                "walk.hops": len(declared),
                "walk.holds": holds,
                "walk.unchecked": unchecked,
                "walk.judged": sum(s["state"] == "holds" for s in part["steps"]),
                "walk.unwalked": unwalked,
                "walk.broken_rule": rule.group(0),
                "walk.complete_exit": done["exit"],
                "walk.broken_exit": broken["exit"],
                "walk.fragment_exit": part["exit"],
            }
        )
        bundle = _product(f"{WALKS['complete']}/bundle.yaml")
        docs = [d for d in yaml.safe_load_all(bundle.read_text(encoding="utf-8")) if isinstance(d, dict)]
        width = max(len(str(d.get("kind"))) for d in docs)
        self._recordings["walk:bundle"] = [f"# {WALKS['complete']}/"] + [
            f"{d.get('kind')!s:<{width}}  {d['metadata'].get('namespace')}/{d['metadata']['name']}" for d in docs
        ]

    def _protocol(self) -> None:
        text = _cli("demo", "protocol")
        m = re.search(r"score (\d+(?:\.\d+)?)/100", text)
        n = re.search(r"\((\d+)-step protocol\)", text)
        if not m or not n:
            raise FactError(f"unexpected `kube-noob demo protocol` output: {text[:300]!r}")
        self._values["protocol.score"] = _num(float(m.group(1)))
        self._values["protocol.steps"] = int(n.group(1))

    def _sidecar(self) -> None:
        if not self.sidecar:
            raise FactError(
                "the sidecar facts come from the transcript scripts/demo_sidecar_kind.sh records in CI (artifact "
                "sidecar-transcript-4.22): pass --sidecar <file> or set KN_SIDECAR_TRANSCRIPT"
            )
        steps = parse_transcript(self.sidecar.read_text(encoding="utf-8"))
        text = "\n".join(line for s in steps for line in s["output"])
        conn = re.search(r"connected to kube_noob_mcp (\S+) at \S+: (\d+) tools", text)
        mem = re.search(r"current \d+ MiB; peak (\d+) MiB; limit (\d+) MiB", text)
        if not conn or not mem:
            raise FactError(
                f"{self.sidecar}: no 'connected to kube_noob_mcp' or memory line; is it a sidecar transcript?"
            )
        if "port 8080: closed" not in text:
            raise FactError(f"{self.sidecar}: the pod port is not shown closed; the video shows only a passing run")
        limit = _manifest_limit_mib()
        if int(mem.group(2)) != limit:
            raise FactError(
                f"{self.sidecar}: the kube-noob container's memory limit is {mem.group(2)} MiB there, {limit} MiB in "
                f"{SIDECAR_MANIFEST}; record the transcript again (scripts/demo_sidecar_kind.sh)"
            )
        self._values.update(
            {
                "sidecar.version": conn.group(1),
                "sidecar.tools": int(conn.group(2)),
                "sidecar.peak": int(mem.group(1)),
                "sidecar.limit": int(mem.group(2)),
            }
        )
        client = next(s for s in steps if "sidecar_client.py" in s["command"])
        port = next(s for s in steps if "port 8080" in s["caption"])
        self._recordings["sidecar:client"] = (
            [f"$ {client['command']}"]
            + [line for line in client["output"] if not line.startswith("cited:")]
            + [f"# {port['caption']}"]
            + port["output"]
        )

    def _ensure(self, name: str) -> None:
        group = re.split(r"[.:]", name, maxsplit=1)[0]
        if group not in self._groups:
            raise FactError(f"unknown fact {name!r}; see demos/video/facts.py")
        fn = self._groups[group]
        if fn.__name__ not in self._done:
            fn()
            self._done.add(fn.__name__)

    # ---------------------------------------------------------------- use

    def get(self, name: str) -> Any:
        self._ensure(name)
        if name not in self._values:
            raise FactError(f"unknown fact {name!r}; see demos/video/facts.py")
        return self._values[name]

    def payoff(self) -> dict[str, Any]:
        """The payoff scene: the example's YAML, its findings on their lines, the fix as a diff, and both scores."""
        self._ensure("audit")
        return json.loads(json.dumps(self._payoff))

    def walk(self, name: str) -> dict[str, Any]:
        """One hops scene: `learn mechanism` on one of WALKS, every declared hop with its mark, and the exit code."""
        self._ensure("walk")
        if name not in self._walks:
            raise FactError(f"unknown walk {name!r}; see WALKS in demos/video/facts.py")
        return json.loads(json.dumps(self._walks[name]))

    def recording(self, name: str) -> list[str]:
        self._ensure(name)
        if name not in self._recordings:
            raise FactError(f"unknown recording @{name}; see demos/video/facts.py")
        return list(self._recordings[name])

    def fill(self, text: str) -> str:
        def sub(m: re.Match[str]) -> str:
            value = self.get(m.group(1))
            return words(value) if m.group(2) else str(value)

        return PLACEHOLDER.sub(sub, text)

    def lines(self, lines: list[str]) -> list[str]:
        """Terminal lines: "@name" becomes that recording, every other line is filled."""
        out: list[str] = []
        for line in lines:
            m = RECORDING.match(line)
            out.extend(self.recording(m.group(1)) if m else [self.fill(line)])
        return out

    def all(self) -> dict[str, Any]:
        for name in ("version", "audit", "protocol", "cli", *(["sidecar"] if self.sidecar else [])):
            self._ensure(name)
        return {**self._values, "recordings": self._recordings}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", nargs="?", choices=["fill"])
    ap.add_argument("file", nargs="?", type=Path)
    ap.add_argument("--sidecar", type=Path)
    a = ap.parse_args(argv)
    facts = Facts(a.sidecar)
    try:
        if a.cmd == "fill":
            if not a.file:
                ap.error("fill needs a file")
            print(facts.fill(a.file.read_text(encoding="utf-8")), end="")
        else:
            print(json.dumps(facts.all(), indent=2, ensure_ascii=False))
    except FactError as e:
        print(f"facts: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
