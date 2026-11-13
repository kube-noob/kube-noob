"""LLM providers for the standalone agent.

* ``anthropic``          - Claude via the Anthropic API (default model ``claude-fable-5-1``). Supports server-side
                           fallbacks when the requested model's safety classifier declines (security tooling can trip
                           cyber classifiers) and Anthropic's server-side web search when ``webEnabled`` is true.
* ``openai-compatible``  - any ``/v1/chat/completions`` endpoint with tool calling (vLLM, Ollama, LM Studio, TGI) -
                           this is how a model you fine-tune later plugs in.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx

from kube_noob.config import LLMSettings, Settings, check_endpoint, is_local_url
from kube_noob.errors import ProviderError
from kube_noob.net import Purpose, http_client

FALLBACK_BETA = "server-side-fallback-2026-07-01"


@dataclass
class ToolCall:
    call_id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class Turn:
    text: str
    tool_calls: list[ToolCall]
    stop_reason: str
    model: str
    raw_assistant: Any  # provider-native assistant message to append to history
    notes: list[str] = field(default_factory=list)


class Provider(Protocol):
    name: str
    model: str

    def turn(self, system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> Turn: ...

    def tool_results_message(self, results: list[tuple[ToolCall, str, bool]]) -> list[dict[str, Any]]: ...

    def user_message(self, text: str) -> dict[str, Any]: ...

    def complete_text(self, prompt: str, max_tokens: int = 1024) -> str: ...


DEFAULT_KEY_ENV = "ANTHROPIC_API_KEY"

# The default key variable is per provider, and only ``anthropic`` has one. ``openai-compatible`` points at whatever
# endpoint the user named - a local vLLM, an in-cluster model, a third-party gateway - and the Anthropic key is not
# that endpoint's credential to receive, so with no ``apiKeyEnv`` the request carries no Authorization header at all.
_PROVIDER_KEY_ENV = {"anthropic": DEFAULT_KEY_ENV}


def key_env(llm: LLMSettings) -> str | None:
    """The variable holding this provider's API key: ``apiKeyEnv`` when set (validated in config), else the
    provider's own default, else ``None`` - there is no cross-provider fallback."""
    return llm.api_key_env or _PROVIDER_KEY_ENV.get(llm.provider)


def _api_key(llm: LLMSettings) -> str:
    name = key_env(llm)
    if name is None:
        raise ProviderError(
            f"Provider '{llm.provider}' has no default key variable; set llm.apiKeyEnv to the variable holding the "
            "key for your endpoint."
        )
    key = os.environ.get(name, "")
    if not key:
        raise ProviderError(
            f"Environment variable {name} is not set; the agent needs an API key for provider '{llm.provider}'."
        )
    return key


def redact(text: str, *secrets: str) -> str:
    """Error bodies from a model endpoint reach stderr, logs and CI output. A gateway that quotes the Authorization
    header back in a 400 would put the key there, so every secret this process holds is masked before the body is
    quoted."""
    for secret in secrets:
        if len(secret) >= 8:
            text = text.replace(secret, "[redacted]")
    return text


class AnthropicProvider:
    name = "anthropic"

    def __init__(self, llm: LLMSettings, settings: Settings, fallbacks: bool = True) -> None:
        try:
            import anthropic
        except ImportError as exc:
            raise ProviderError(
                "llm.provider is 'anthropic' but the Anthropic SDK is not installed: pip install 'kube-noob[ask]' "
                "(or use llm.provider: openai-compatible with a local model)."
            ) from exc

        self.model = llm.model
        self.llm = llm
        self.settings = settings
        self.fallbacks = fallbacks
        self.key = _api_key(llm)
        kwargs: dict[str, Any] = {"api_key": self.key, "timeout": llm.timeout_seconds, "max_retries": 3}
        if llm.base_url:
            kwargs["base_url"] = llm.base_url
        else:
            # The SDK reads ANTHROPIC_BASE_URL itself, which would carry the key to a host that never went through
            # config's endpoint check. Hold it to the same rule: no plain http to a non-local host.
            env_base = os.environ.get("ANTHROPIC_BASE_URL", "").strip()
            if env_base:
                try:
                    check_endpoint(env_base, llm.allow_insecure_base_url, "ANTHROPIC_BASE_URL")
                except ValueError as exc:
                    raise ProviderError(str(exc)) from exc
        self.client = anthropic.Anthropic(**kwargs)

    def _server_tools(self) -> list[dict[str, Any]]:
        if not self.settings.web_enabled:
            return []
        return [
            {
                "type": "web_search_20250305",
                "name": "web_search",
                "max_uses": 5,
                "allowed_domains": list(self.settings.web.allowed_domains),
            }
        ]

    def _create(self, **kw: Any) -> Any:
        import anthropic

        try:
            if self.fallbacks:
                try:
                    return self.client.beta.messages.create(fallbacks="default", betas=[FALLBACK_BETA], **kw)
                except anthropic.APIStatusError as exc:
                    if "fallback" not in str(exc).lower() and "beta" not in str(exc).lower():
                        raise
                    self.fallbacks = False
            return self.client.messages.create(**kw)
        except anthropic.APIConnectionError as exc:
            raise ProviderError(f"Cannot reach the Anthropic API ({exc}). Check network/proxy access.") from exc
        except anthropic.AuthenticationError as exc:
            raise ProviderError("The Anthropic API rejected the key in llm.apiKeyEnv (HTTP 401).") from exc
        except anthropic.APIStatusError as exc:
            raise ProviderError(
                f"Anthropic API error HTTP {exc.status_code}: {redact(str(exc), self.key)[:300]}"
            ) from exc

    def turn(self, system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> Turn:
        anth_tools = [
            {"name": t["name"], "description": t["description"], "input_schema": t["input_schema"]} for t in tools
        ] + self._server_tools()
        resp = self._create(
            model=self.model, max_tokens=self.llm.max_tokens, system=system, messages=messages, tools=anth_tools
        )
        content = getattr(resp, "content", None)
        if not isinstance(content, list):
            raise ProviderError(
                "The Anthropic API returned a response without a content list; the endpoint may not be the "
                f"Messages API (got {type(content).__name__})."
            )
        text_parts: list[str] = []
        calls: list[ToolCall] = []
        notes: list[str] = []
        for block in content:
            btype = getattr(block, "type", "")
            if btype == "text":
                text_parts.append(str(getattr(block, "text", "")))
            elif btype == "tool_use":
                calls.append(ToolCall(block.id, block.name, dict(block.input or {})))
            elif btype == "fallback":
                notes.append(
                    f"served by fallback model {block.to.model} (requested {block.from_.model})"
                    if hasattr(block, "from_")
                    else "served by a fallback model"
                )
        if resp.stop_reason == "refusal":
            details = getattr(resp, "stop_details", None)
            notes.append(f"model declined: {getattr(details, 'explanation', '') or 'refusal'}")
        # Keep thinking/tool_use/server-tool blocks verbatim (required for multi-turn tool use); the fallback marker is
        # response metadata, not conversation content.
        raw = {
            "role": "assistant",
            "content": [b.model_dump(exclude_none=True) for b in content if getattr(b, "type", "") != "fallback"],
        }
        return Turn("".join(text_parts), calls, str(resp.stop_reason), str(resp.model), raw, notes)

    def tool_results_message(self, results: list[tuple[ToolCall, str, bool]]) -> list[dict[str, Any]]:
        return [
            {
                "role": "user",
                "content": [
                    {"type": "tool_result", "tool_use_id": c.call_id, "content": out, "is_error": err}
                    for c, out, err in results
                ],
            }
        ]

    def user_message(self, text: str) -> dict[str, Any]:
        return {"role": "user", "content": text}

    def complete_text(self, prompt: str, max_tokens: int = 1024) -> str:
        resp = self._create(model=self.model, max_tokens=max_tokens, messages=[{"role": "user", "content": prompt}])
        content = getattr(resp, "content", None)
        if not isinstance(content, list):
            raise ProviderError("The Anthropic API returned a response without a content list.")
        return "".join(str(getattr(b, "text", "")) for b in content if getattr(b, "type", "") == "text")


class OpenAICompatibleProvider:
    name = "openai-compatible"

    def __init__(self, llm: LLMSettings, settings: Settings) -> None:
        if not llm.base_url:
            raise ProviderError(
                "llm.baseUrl is required for provider 'openai-compatible' (e.g. "
                "http://localhost:8000/v1 for vLLM, http://localhost:11434/v1 for Ollama)."
            )
        self.model = llm.model
        self.llm = llm
        self.settings = settings
        self.base = llm.base_url.rstrip("/")
        name = key_env(llm)
        self.key_name = name
        self.key = os.environ.get(name, "") if name else ""

    def _post(self, payload: dict[str, Any]) -> dict[str, Any]:
        headers = {"Content-Type": "application/json"}
        if self.key:
            headers["Authorization"] = f"Bearer {self.key}"
        try:
            with http_client(self.settings, Purpose.LLM, timeout=self.llm.timeout_seconds, extra_headers=headers) as c:
                resp = c.post(f"{self.base}/chat/completions", content=json.dumps(payload))
        except httpx.TimeoutException as exc:
            raise ProviderError(
                f"{self.base} did not answer within {self.llm.timeout_seconds}s (llm.timeoutSeconds)"
            ) from exc
        except httpx.TransportError as exc:
            raise ProviderError(f"Cannot reach the model endpoint {self.base}: {exc}") from exc
        except httpx.TooManyRedirects as exc:
            # Every hop carried the key, so this is reported rather than retried.
            raise ProviderError(
                f"{self.base} kept redirecting; set llm.baseUrl to the final URL the endpoint serves."
            ) from exc
        if resp.is_redirect:
            raise ProviderError(
                f"{self.base} redirected to {resp.headers.get('location', '?')}; set llm.baseUrl to the final URL"
                + (" (redirects are never followed under the offline lock)" if self.settings.offline else "")
            )
        if resp.status_code >= 400:
            hint = ""
            if resp.status_code in (401, 403) and not self.key:
                hint = (
                    " - the request carried no API key: set llm.apiKeyEnv to the variable holding this endpoint's key"
                )
            raise ProviderError(f"{self.base} returned HTTP {resp.status_code}: {self._clean(resp.text)[:300]}{hint}")
        try:
            body = resp.json()
        except ValueError as exc:
            raise ProviderError(f"{self.base} returned a non-JSON response: {self._clean(resp.text)[:200]}") from exc
        if not isinstance(body, dict):
            raise ProviderError(
                f"{self.base} returned {type(body).__name__} where the chat completions API returns an object."
            )
        return body

    def _clean(self, text: str) -> str:
        return redact(text, self.key)

    def _message(self, data: dict[str, Any]) -> dict[str, Any]:
        """The one choice's message, or a ProviderError. An endpoint is not trusted input: a proxy, a captive portal
        or a different API version can all answer 200 with something else."""
        choices = data.get("choices")
        if not isinstance(choices, list) or not choices:
            raise ProviderError(
                f"{self.base} answered with no choices; the endpoint may not be a chat completions API. "
                f"Keys: {sorted(data)[:8]}"
            )
        choice = choices[0]
        if not isinstance(choice, dict):
            raise ProviderError(f"{self.base} answered with a {type(choice).__name__} choice, not an object.")
        msg = choice.get("message")
        if msg is None:
            msg = {}
        if not isinstance(msg, dict):
            raise ProviderError(f"{self.base} answered with a {type(msg).__name__} message, not an object.")
        return msg

    def turn(self, system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> Turn:
        payload = {
            "model": self.model,
            "max_tokens": self.llm.max_tokens,
            "messages": [{"role": "system", "content": system}, *messages],
            "tools": [
                {
                    "type": "function",
                    "function": {"name": t["name"], "description": t["description"], "parameters": t["input_schema"]},
                }
                for t in tools
            ],
        }
        data = self._post(payload)
        msg = self._message(data)
        choice = data["choices"][0]
        calls = []
        tool_calls = msg.get("tool_calls")
        for tc in tool_calls if isinstance(tool_calls, list) else []:
            if not isinstance(tc, dict):
                continue
            raw_fn = tc.get("function")
            fn: dict[str, Any] = raw_fn if isinstance(raw_fn, dict) else {}
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {"__invalid_json__": fn.get("arguments")}
            calls.append(ToolCall(str(tc.get("id")), str(fn.get("name")), args if isinstance(args, dict) else {}))
        text = msg.get("content")
        text = text if isinstance(text, str) else ""
        raw: dict[str, Any] = {"role": "assistant", "content": text}
        if isinstance(tool_calls, list) and tool_calls:
            raw["tool_calls"] = tool_calls
        return Turn(text, calls, str(choice.get("finish_reason")), str(data.get("model", self.model)), raw)

    def tool_results_message(self, results: list[tuple[ToolCall, str, bool]]) -> list[dict[str, Any]]:
        return [{"role": "tool", "tool_call_id": c.call_id, "content": out} for c, out, _ in results]

    def user_message(self, text: str) -> dict[str, Any]:
        return {"role": "user", "content": text}

    def complete_text(self, prompt: str, max_tokens: int = 1024) -> str:
        data = self._post(
            {"model": self.model, "max_tokens": max_tokens, "messages": [{"role": "user", "content": prompt}]}
        )
        content = self._message(data).get("content")
        return content if isinstance(content, str) else ""


def build_provider(llm: LLMSettings, settings: Settings) -> Provider:
    if llm.provider == "none":
        raise ProviderError("llm.provider is 'none'; configure 'anthropic' or 'openai-compatible' to use the agent.")
    if settings.offline and not (llm.provider == "openai-compatible" and is_local_url(llm.base_url)):
        raise ProviderError(
            "The offline lock is on: the agent may only use a local model (llm.provider: openai-compatible with a "
            "loopback or *.svc llm.baseUrl). Use the MCP server from your own client, or point llm.baseUrl at a "
            "model served in the cluster."
        )
    if llm.provider == "anthropic":
        return AnthropicProvider(llm, settings)
    return OpenAICompatibleProvider(llm, settings)
