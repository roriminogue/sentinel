"""Anthropic-backed target client."""

from __future__ import annotations

import time
from typing import List, Optional

import anthropic

from .base_client import PROVIDER_REFUSAL, TargetClient, TargetReply

DEFAULT_MODEL = "claude-haiku-4-5"
DEFAULT_MAX_TOKENS = 1024

# Provider errors worth retrying: rate limits, transient 5xx/overload, and
# network failures. 4xx client errors (bad request, auth) are not retried.
_RETRYABLE = (
    anthropic.RateLimitError,
    anthropic.InternalServerError,
    anthropic.APIConnectionError,
    anthropic.APITimeoutError,
)


class AnthropicClient(TargetClient):
    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        api_key: Optional[str] = None,
        max_retries: int = 4,
        base_backoff: float = 2.0,
        system_prompt: Optional[str] = None,
    ) -> None:
        # anthropic.Anthropic() reads ANTHROPIC_API_KEY from the environment
        # when api_key is None.
        self._client = anthropic.Anthropic(api_key=api_key)
        self._model = model
        self._max_tokens = max_tokens
        self._max_retries = max_retries
        self._base_backoff = base_backoff
        self._system_prompt = system_prompt

    @property
    def model(self) -> str:
        return self._model

    @property
    def system_prompt(self) -> Optional[str]:
        return self._system_prompt

    def send(self, turns: List[str]) -> TargetReply:
        messages = []
        reply = TargetReply(text="")
        for turn in turns:
            messages.append({"role": "user", "content": turn})
            message = self._create_with_retry(messages)
            reply = TargetReply(
                text=_extract_text(message),
                stop_reason=getattr(message, "stop_reason", None),
            )
            if reply.stop_reason == PROVIDER_REFUSAL:
                # The API declined the turn and returned no reply, so there is
                # nothing to thread into the next turn; the attack ends here.
                return reply
            messages.append({"role": "assistant", "content": reply.text})
        return reply

    def _create_with_retry(self, messages: list) -> "anthropic.types.Message":
        request = {
            "model": self._model,
            "max_tokens": self._max_tokens,
            "messages": messages,
        }
        # Omit the field entirely when unset: sending system=None is not the
        # same request as sending no system prompt.
        if self._system_prompt:
            request["system"] = self._system_prompt
        attempt = 0
        while True:
            try:
                return self._client.messages.create(**request)
            except _RETRYABLE:
                if attempt >= self._max_retries:
                    raise
                time.sleep(self._base_backoff * (2**attempt))
                attempt += 1


def _extract_text(message: "anthropic.types.Message") -> str:
    parts = [b.text for b in message.content if getattr(b, "type", None) == "text"]
    return "\n".join(parts)
