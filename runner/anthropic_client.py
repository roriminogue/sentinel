"""Anthropic-backed target client."""

from __future__ import annotations

import time
from typing import List, Optional

import anthropic

from .base_client import TargetClient

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
    ) -> None:
        # anthropic.Anthropic() reads ANTHROPIC_API_KEY from the environment
        # when api_key is None.
        self._client = anthropic.Anthropic(api_key=api_key)
        self._model = model
        self._max_tokens = max_tokens
        self._max_retries = max_retries
        self._base_backoff = base_backoff

    @property
    def model(self) -> str:
        return self._model

    def send(self, turns: List[str]) -> str:
        messages = []
        final_text = ""
        for turn in turns:
            messages.append({"role": "user", "content": turn})
            reply = self._create_with_retry(messages)
            final_text = _extract_text(reply)
            messages.append({"role": "assistant", "content": final_text})
        return final_text

    def _create_with_retry(self, messages: list) -> "anthropic.types.Message":
        attempt = 0
        while True:
            try:
                return self._client.messages.create(
                    model=self._model,
                    max_tokens=self._max_tokens,
                    messages=messages,
                )
            except _RETRYABLE:
                if attempt >= self._max_retries:
                    raise
                time.sleep(self._base_backoff * (2**attempt))
                attempt += 1


def _extract_text(message: "anthropic.types.Message") -> str:
    parts = [b.text for b in message.content if getattr(b, "type", None) == "text"]
    return "\n".join(parts)
