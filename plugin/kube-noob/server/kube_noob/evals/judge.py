"""Pluggable, eval-only judges.

Default is ``none``: all scoring is deterministic (``evals.reward``). An LLM judge can add a qualitative opinion to
evaluation reports, but its outputs are tagged ``labelSource: llm-judge`` and ``export`` refuses to include them in
training datasets unless the operator passes ``allow_llm_labels`` after confirming their provider terms permit it.
"""

from __future__ import annotations

import json
import re
from typing import Any, Protocol

from kube_noob.config import Settings

JUDGE_PROMPT = """You are grading an answer about Kubernetes/OpenShift/ROSA/Helm/StackRox for technical correctness.
Task: {task}
Answer:
<<<
{answer}
>>>
Deterministic grader result (authoritative for YAML validity and security findings): {grade}
Return ONLY JSON: {{"score": <0..1>, "rationale": "<two sentences: biggest correctness issue or strength>"}}"""


class Judge(Protocol):
    name: str

    def judge(self, task: dict[str, Any], answer: str, grade: dict[str, Any]) -> dict[str, Any] | None: ...


class NoJudge:
    name = "none"

    def judge(self, task: dict[str, Any], answer: str, grade: dict[str, Any]) -> dict[str, Any] | None:
        return None


class LLMJudge:
    def __init__(self, settings: Settings) -> None:
        from kube_noob.agent.providers import build_provider

        js = settings.judge
        llm = settings.llm.model_copy(
            update={"provider": js.provider, "model": js.model, "base_url": js.base_url, "api_key_env": js.api_key_env}
        )
        self.provider = build_provider(llm, settings)
        self.name = f"llm-judge:{js.provider}:{js.model}"

    def judge(self, task: dict[str, Any], answer: str, grade: dict[str, Any]) -> dict[str, Any] | None:
        prompt = JUDGE_PROMPT.format(
            task=task.get("prompt", ""), answer=answer[:12000], grade=json.dumps(grade.get("components", {}))
        )
        reply = self.provider.complete_text(prompt, max_tokens=300)
        m = re.search(r"\{.*\}", reply, re.DOTALL)
        if not m:
            return {"score": None, "rationale": "judge returned no JSON", "labelSource": "llm-judge"}
        try:
            data = json.loads(m.group(0))
        except json.JSONDecodeError:
            return {"score": None, "rationale": "judge returned invalid JSON", "labelSource": "llm-judge"}
        score = data.get("score")
        return {
            "score": float(score) if isinstance(score, int | float) else None,
            "rationale": str(data.get("rationale", ""))[:500],
            "labelSource": "llm-judge",
            "judge": self.name,
        }


def build_judge(settings: Settings) -> Judge:
    if settings.judge.provider == "none":
        return NoJudge()
    return LLMJudge(settings)
