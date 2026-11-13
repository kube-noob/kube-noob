"""Benchmark runner: ask a model (via the agent) every benchmark task and grade the answers deterministically."""

from __future__ import annotations

import statistics
import time
from typing import Any

from kube_noob.agent.loop import Agent
from kube_noob.config import Settings
from kube_noob.evals.judge import build_judge
from kube_noob.evals.reward import benchmark, grade
from kube_noob.knowledge.store import get_store


def run_benchmark(settings: Settings, task_ids: list[str] | None = None, use_tools: bool = True) -> dict[str, Any]:
    tasks = benchmark()
    selected = [tasks[t] for t in task_ids] if task_ids else list(tasks.values())
    agent = Agent(settings)
    if not use_tools:
        agent.specs = {}
    judge = build_judge(settings)
    rows: list[dict[str, Any]] = []
    for task in selected:
        t0 = time.monotonic()
        res = agent.ask(task["prompt"])
        g = grade(task, res.answer, get_store(settings.data_dir)).as_dict()
        row: dict[str, Any] = {
            "taskId": task["id"],
            "type": task.get("type", "manifest"),
            "grade": g,
            "model": res.model,
            "rounds": res.rounds,
            "toolCalls": len(res.tool_calls),
            "seconds": round(time.monotonic() - t0, 1),
            "notes": res.notes,
        }
        opinion = judge.judge(task, res.answer, g)
        if opinion is not None:
            row["judge"] = opinion  # eval-only; never exported as a training label by default
        rows.append(row)
    rewards = [r["grade"]["reward"] for r in rows]
    return {
        "model": agent.provider.model,
        "provider": agent.provider.name,
        "webEnabled": settings.web_enabled,
        "tasks": len(rows),
        "meanReward": round(statistics.fmean(rewards), 4) if rewards else 0.0,
        "passRate": round(sum(1 for r in rows if r["grade"]["components"]["task"] >= 0.999) / len(rows), 4)
        if rows
        else 0.0,
        "results": rows,
    }
