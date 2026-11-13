"""Standalone agent: the 7-step protocol driven by an LLM over the local toolkit."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError

from kube_noob.agent.providers import Provider, build_provider
from kube_noob.config import Settings
from kube_noob.errors import KubeNoobError
from kube_noob.knowledge.store import extract_citations, get_store
from kube_noob.prompts import system_prompt
from kube_noob.toolkit import Toolkit, ToolSpec

_log = logging.getLogger(__name__)
MAX_TOOL_OUTPUT = 60_000


@dataclass
class AgentResult:
    answer: str
    model: str
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    citations: list[dict[str, Any]] = field(default_factory=list)
    invalid_citations: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    rounds: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "answer": self.answer,
            "model": self.model,
            "rounds": self.rounds,
            "toolCalls": self.tool_calls,
            "citations": self.citations,
            "invalidCitations": self.invalid_citations,
            "notes": self.notes,
        }


def tool_schemas(specs: list[ToolSpec]) -> list[dict[str, Any]]:
    return [{"name": s.name, "description": s.description, "input_schema": s.model.model_json_schema()} for s in specs]


class Agent:
    def __init__(self, settings: Settings, provider: Provider | None = None) -> None:
        self.settings = settings
        self.toolkit = Toolkit(settings)
        self.specs = {s.name: s for s in self.toolkit.specs()}
        self.provider = provider or build_provider(settings.llm, settings)

    def _run_tool(self, name: str, args: dict[str, Any]) -> tuple[str, bool]:
        spec = self.specs.get(name)
        if spec is None:
            return f"Unknown tool {name!r}. Available: {', '.join(sorted(self.specs))}", True
        try:
            model = spec.model.model_validate(args)
            out = spec.fn(model)
        except ValidationError as exc:
            return f"Invalid arguments for {name}: {exc.errors(include_url=False)}", True
        except (KubeNoobError, KeyError, ValueError) as exc:
            return f"{type(exc).__name__}: {exc}", True
        except Exception as exc:  # noqa: BLE001 - a tool bug must not abort the conversation; details are logged
            _log.exception("tool %s crashed", name)
            return f"Tool {name} failed unexpectedly ({type(exc).__name__}); try different input.", True
        text = json.dumps(out, default=str)
        if len(text) > MAX_TOOL_OUTPUT:
            text = text[:MAX_TOOL_OUTPUT] + "... [truncated; narrow the request]"
        return text, False

    def ask(self, question: str, history: list[dict[str, Any]] | None = None) -> AgentResult:
        messages = list(history or []) + [self.provider.user_message(question)]
        schemas = tool_schemas(list(self.specs.values()))
        result = AgentResult(answer="", model=self.provider.model)
        system = system_prompt(self.settings)
        for rnd in range(1, self.settings.llm.max_tool_rounds + 1):
            turn = self.provider.turn(system, messages, schemas)
            result.rounds = rnd
            result.model = turn.model
            result.notes.extend(turn.notes)
            messages.append(turn.raw_assistant)
            if turn.stop_reason == "pause_turn":
                continue  # server-side tool (web search) still running; resend to continue
            if not turn.tool_calls:
                result.answer = turn.text
                break
            outputs: list[tuple[Any, str, bool]] = []
            for call in turn.tool_calls:
                out, err = self._run_tool(call.name, call.arguments)
                result.tool_calls.append({"name": call.name, "arguments": call.arguments, "error": err})
                outputs.append((call, out, err))
            messages.extend(self.provider.tool_results_message(outputs))
        else:
            result.notes.append(f"stopped after {self.settings.llm.max_tool_rounds} tool rounds")
            result.answer = result.answer or "The agent reached its tool-round limit before finishing."
        store = get_store(self.settings.data_dir)
        for cid in extract_citations(result.answer):
            c = store.get(cid)
            if c is None:
                result.invalid_citations.append(cid)
            else:
                result.citations.append(c.citation())
        return result
