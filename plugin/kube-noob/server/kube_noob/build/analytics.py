"""Build and test analytics (requirements R4.4): flaky tests, slow steps and their trend, failure classes over time.

Input is a CI history on disk, one folder per run:

- ``run.json``: the run as the GitHub Actions API (``GET /repos/{o}/{r}/actions/runs/{id}`` with ``jobs`` from
  ``.../jobs``) or ``gh run view <id> --json databaseId,headSha,attempt,conclusion,createdAt,jobs`` writes it: id,
  commit, attempt, conclusion, created time, and jobs with their steps' start and end times.
- ``*.xml``: JUnit XML reports of that run (Surefire, Gradle, pytest, Jest, go-junit-report). Surefire's
  ``flakyFailure`` and ``rerunFailure`` (a test that failed and then passed on a rerun) count as flaky in that run.
- ``*.log``: optional build logs; a failed run's cause class comes from ``kube_noob.build.logs``.

``kube_noob.build.github_history`` writes the same folders from the GitHub Actions API when that is enabled.

Definitions (stated so the numbers can be checked by hand):

- flaky: a test that both passed and failed on the same commit (across runs and attempts), or that a single run
  reports as failed and then passed on a rerun.
- step time: seconds from ``started_at`` to ``completed_at``; per job and step name the count, mean, median, 90th
  percentile (nearest rank) and maximum, over runs where the step completed.
- trend: the mean of the newest half of the runs (by created time) against the oldest half, as a percentage.
"""

from __future__ import annotations

import datetime as dt
import math
import re
import xml.etree.ElementTree as ET  # DTDs and entities are refused before parsing (_safe_xml)
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from kube_noob import sanitize

MAX_RUNS = 5_000
MAX_XML_BYTES = 20_000_000
MAX_CASES = 200_000
MAX_LOG_BYTES = 5_000_000
_DTD = re.compile(rb"<!(?:DOCTYPE|ENTITY)", re.I)


class HistoryError(ValueError):
    """Not a CI history, or a file over its bounds."""


@dataclass
class Case:
    test: str
    outcome: str  # passed | failed | skipped | flaky (failed then passed on a rerun within the run)
    seconds: float


@dataclass
class Run:
    run_id: str
    commit: str
    attempt: int
    created: dt.datetime
    conclusion: str
    steps: list[tuple[str, str, float | None]] = field(default_factory=list)  # (job, step, seconds)
    failed_steps: list[str] = field(default_factory=list)  # "job / step" of steps that concluded failure
    cases: list[Case] = field(default_factory=list)
    failure_class: str | None = None
    folder: str = ""


def _time(value: Any) -> dt.datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _seconds(text: Any) -> float:
    try:
        v = float(str(text).replace(",", ""))
    except ValueError:
        return 0.0
    return v if math.isfinite(v) and v >= 0 else 0.0


def _safe_xml(data: bytes, where: str) -> ET.Element:
    if len(data) > MAX_XML_BYTES:
        raise HistoryError(f"{where}: larger than {MAX_XML_BYTES} bytes")
    if _DTD.search(data[:65_536]):
        raise HistoryError(f"{where}: has a DOCTYPE or ENTITY declaration; JUnit reports need neither")
    try:
        return ET.fromstring(data)  # noqa: S314 - no DTD, so no entity expansion
    except ET.ParseError as exc:
        raise HistoryError(f"{where}: not XML ({exc})") from exc


def parse_junit(data: bytes, where: str = "junit") -> list[Case]:
    root = _safe_xml(data, where)
    out: list[Case] = []
    for tc in root.iter("testcase"):
        if len(out) >= MAX_CASES:
            raise HistoryError(f"{where}: more than {MAX_CASES} test cases")
        cls = (tc.get("classname") or tc.get("class") or "").strip()
        name = (tc.get("name") or "").strip()
        if not name:
            continue
        test = f"{cls}::{name}" if cls else name
        tags = {child.tag for child in tc}
        if tags & {"failure", "error"}:
            outcome = "failed"
        elif tags & {"flakyFailure", "flakyError", "rerunFailure", "rerunError"}:
            outcome = "flaky"
        elif "skipped" in tags:
            outcome = "skipped"
        else:
            outcome = "passed"
        out.append(Case(test, outcome, _seconds(tc.get("time", 0))))
    return out


def _run_meta(doc: dict[str, Any], where: str) -> tuple[str, str, int, dt.datetime, str, list[dict[str, Any]]]:
    run_id = str(doc.get("id") or doc.get("databaseId") or "")
    commit = str(doc.get("head_sha") or doc.get("headSha") or "")
    attempt = int(doc.get("run_attempt") or doc.get("attempt") or 1)
    created = _time(doc.get("created_at") or doc.get("createdAt") or doc.get("run_started_at"))
    conclusion = str(doc.get("conclusion") or "")
    if not run_id or not re.fullmatch(r"[0-9a-f]{7,64}", commit) or created is None:
        raise HistoryError(f"{where}: needs an id, a commit (head_sha) and a created time")
    jobs = [j for j in doc.get("jobs") or [] if isinstance(j, dict)]
    return run_id, commit, attempt, created, conclusion, jobs


def load_history(folder: Path) -> list[Run]:
    if not folder.is_dir():
        raise HistoryError(f"{folder}: not a folder")
    runs: list[Run] = []
    for sub in sorted(p for p in folder.iterdir() if p.is_dir() and not p.is_symlink()):
        meta = sub / "run.json"
        if not meta.is_file():
            continue
        if len(runs) >= MAX_RUNS:
            raise HistoryError(f"more than {MAX_RUNS} runs")
        try:
            doc = sanitize.loads_bounded(meta.read_text(encoding="utf-8"), sanitize.MAX_JSON_DEPTH_FILE)
        except (ValueError, RecursionError) as exc:
            raise HistoryError(f"{meta}: not JSON") from exc
        if not isinstance(doc, dict):
            raise HistoryError(f"{meta}: not a JSON object")
        run_id, commit, attempt, created, conclusion, jobs = _run_meta(doc, str(meta))
        run = Run(run_id, commit, attempt, created, conclusion, folder=sub.name)
        for job in jobs:
            for step in job.get("steps") or []:
                if not isinstance(step, dict):
                    continue
                start = _time(step.get("started_at") or step.get("startedAt"))
                end = _time(step.get("completed_at") or step.get("completedAt"))
                secs = (end - start).total_seconds() if start and end and end >= start else None
                job_name, step_name = str(job.get("name") or "job"), str(step.get("name") or "step")
                run.steps.append((job_name, step_name, secs))
                if str(step.get("conclusion") or "").lower() == "failure":
                    run.failed_steps.append(f"{job_name} / {step_name}")
        for xml in sorted(sub.glob("*.xml")):
            run.cases.extend(parse_junit(xml.read_bytes(), str(xml)))
        logs = sorted(sub.glob("*.log"))
        if conclusion == "failure" and logs:
            from kube_noob.build import logs as build_logs

            text = logs[-1].read_bytes()[-MAX_LOG_BYTES:].decode("utf-8", "replace")
            run.failure_class = build_logs.diagnose(text).cause or "unrecognised"
        elif conclusion == "failure" and any(c.outcome == "failed" for c in run.cases):
            run.failure_class = "test"
        elif conclusion == "failure":
            run.failure_class = "unrecognised"
        runs.append(run)
    if not runs:
        raise HistoryError(f"{folder}: no run folders with a run.json")
    runs.sort(key=lambda r: (r.created, r.run_id, r.attempt))
    return runs


def _pct(values: list[float], q: float) -> float:
    """Nearest-rank percentile."""
    ordered = sorted(values)
    rank = max(1, math.ceil(q * len(ordered)))
    return ordered[rank - 1]


def analyse(runs: list[Run], top: int = 20) -> dict[str, Any]:
    by_commit: dict[tuple[str, str], set[str]] = defaultdict(set)
    within: set[str] = set()
    fails: Counter[str] = Counter()
    durations: dict[str, list[float]] = defaultdict(list)
    for r in runs:
        for c in r.cases:
            if c.outcome in {"passed", "failed"}:
                by_commit[(c.test, r.commit)].add(c.outcome)
            if c.outcome == "flaky":
                within.add(c.test)
            if c.outcome == "failed":
                fails[c.test] += 1
            durations[c.test].append(c.seconds)
    flaky_commits: dict[str, list[str]] = defaultdict(list)
    for (test, commit), outcomes in by_commit.items():
        if outcomes == {"passed", "failed"}:
            flaky_commits[test].append(commit)
    flaky = sorted(set(flaky_commits) | within)
    failing = sorted(t for t in fails if t not in flaky)  # failed, and never passed on a commit where it failed
    steps: dict[tuple[str, str], list[tuple[dt.datetime, float]]] = defaultdict(list)
    for r in runs:
        for job, step, secs in r.steps:
            if secs is not None:
                steps[(job, step)].append((r.created, secs))
    step_rows: list[dict[str, Any]] = []
    for (job, step), points in steps.items():
        points.sort()
        values = [v for _, v in points]
        half = len(values) // 2
        trend = None
        if half >= 2:
            old, new = values[:half], values[-half:]
            old_mean = sum(old) / len(old)
            trend = round((sum(new) / len(new) - old_mean) / old_mean * 100, 1) if old_mean else None
        step_rows.append(
            {
                "job": job,
                "step": step,
                "runs": len(values),
                "meanSeconds": round(sum(values) / len(values), 2),
                "medianSeconds": round(_pct(values, 0.5), 2),
                "p90Seconds": round(_pct(values, 0.9), 2),
                "maxSeconds": round(max(values), 2),
                "trendPercent": trend,
            }
        )
    step_rows.sort(key=lambda r: (-r["meanSeconds"], r["job"], r["step"]))
    classes: dict[str, Counter[str]] = defaultdict(Counter)
    for r in runs:
        if r.failure_class:
            week = r.created.strftime("%G-W%V")
            classes[week][r.failure_class] += 1
    means = sorted(
        ((round(sum(v) / len(v), 3), t, len(v)) for t, v in durations.items() if v), key=lambda x: (-x[0], x[1])
    )
    slow_tests = [{"test": t, "runs": n, "meanSeconds": m} for m, t, n in means[:top]]
    run_outcomes: dict[str, set[str]] = defaultdict(set)
    failed_at: dict[str, Counter[str]] = defaultdict(Counter)
    for r in runs:
        if r.conclusion in {"success", "failure"}:
            run_outcomes[r.commit].add(r.conclusion)
        for name in r.failed_steps:
            failed_at[r.commit][name] += 1
    flaky_runs = [
        {"commit": c, "failedSteps": sorted(failed_at[c])}
        for c in sorted(run_outcomes)
        if run_outcomes[c] == {"success", "failure"}
    ]
    return {
        "runs": len(runs),
        "commits": len({r.commit for r in runs}),
        "from": runs[0].created.isoformat(),
        "to": runs[-1].created.isoformat(),
        "conclusions": dict(Counter(r.conclusion or "unknown" for r in runs)),
        "flakyTests": [
            {
                "test": t,
                "commits": sorted(flaky_commits.get(t, [])),
                "rerunInRun": t in within,
                "failures": fails.get(t, 0),
            }
            for t in flaky
        ],
        "failingTests": [{"test": t, "failures": fails[t]} for t in failing],
        "flakyRuns": flaky_runs,
        "steps": step_rows,
        "slowestSteps": step_rows[:top],
        "slowerSteps": sorted(
            (r for r in step_rows if r["trendPercent"] is not None and r["trendPercent"] >= 10),
            key=lambda r: -float(r["trendPercent"] or 0),
        )[:top],
        "slowestTests": slow_tests,
        "failureClasses": {week: dict(sorted(c.items())) for week, c in sorted(classes.items())},
        "definitions": {
            "flaky": "passed and failed on the same commit, or failed then passed on a rerun within one run",
            "flakyRuns": "a commit with both a failed and a successful run (or attempt)",
            "trend": "mean of the newest half of the runs against the oldest half, in percent",
            "p90": "nearest-rank 90th percentile",
        },
    }
