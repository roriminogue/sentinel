"""Anthropic-backed tool-capable client."""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

import anthropic

from .base_agent_client import AgentClient, AgentTrace, RecordedToolCall, ToolHandler

DEFAULT_MODEL = "claude-haiku-4-5"
DEFAULT_MAX_TOKENS = 1024

_RETRYABLE = (
    anthropic.RateLimitError,
    anthropic.InternalServerError,
    anthropic.APIConnectionError,
    anthropic.APITimeoutError,
)


class AnthropicAgentClient(AgentClient):
    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        api_key: Optional[str] = None,
        max_retries: int = 4,
        base_backoff: float = 2.0,
    ) -> None:
        self._client = anthropic.Anthropic(api_key=api_key)
        self._model = model
        self._max_tokens = max_tokens
        self._max_retries = max_retries
        self._base_backoff = base_backoff

    @property
    def model(self) -> str:
        return self._model

    def run(
        self,
        system: str,
        task: str,
        tools: List[Dict[str, Any]],
        tool_handler: ToolHandler,
        max_steps: int,
    ) -> AgentTrace:
        trace = AgentTrace()
        messages: List[Dict[str, Any]] = [{"role": "user", "content": task}]

        for step in range(1, max_steps + 1):
            response = self._create_with_retry(system, messages, tools)
            trace.steps_used = step

            text = "".join(
                b.text for b in response.content if getattr(b, "type", None) == "text"
            )
            if text:
                trace.final_text = text

            tool_uses = [
                b for b in response.content if getattr(b, "type", None) == "tool_use"
            ]
            if not tool_uses:
                return trace

            messages.append({"role": "assistant", "content": response.content})

            # All tool results for one assistant turn go back in a single user
            # message — splitting them suppresses parallel tool use.
            results = []
            for block in tool_uses:
                arguments = dict(block.input or {})
                tool_result = tool_handler(block.name, arguments)
                trace.tool_calls.append(
                    RecordedToolCall(
                        step=step,
                        name=block.name,
                        arguments=arguments,
                        result=tool_result,
                    )
                )
                results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": tool_result,
                    }
                )
            messages.append({"role": "user", "content": results})

        trace.hit_step_limit = True
        return trace

    def _create_with_retry(
        self,
        system: str,
        messages: List[Dict[str, Any]],
        tools: List[Dict[str, Any]],
    ) -> "anthropic.types.Message":
        attempt = 0
        while True:
            try:
                return self._client.messages.create(
                    model=self._model,
                    max_tokens=self._max_tokens,
                    system=system,
                    tools=tools,
                    messages=messages,
                )
            except _RETRYABLE:
                if attempt >= self._max_retries:
                    raise
                time.sleep(self._base_backoff * (2**attempt))
                attempt += 1
