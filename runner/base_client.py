"""Abstract interface for any target LLM.

Swapping in OpenAI, Ollama, or another provider means implementing this one
class — the runner depends only on this interface, never on a concrete SDK.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Optional

# A provider declined the request itself (for example a safety system blocked
# it) rather than the model writing a reply. The text is usually empty.
PROVIDER_REFUSAL = "refusal"


@dataclass(frozen=True)
class TargetReply:
    text: str
    # Why generation stopped, as reported by the provider ("end_turn",
    # "max_tokens", "refusal", ...). None when the provider does not say.
    stop_reason: Optional[str] = None


class TargetClient(ABC):
    """A target model the corpus is fired at."""

    @property
    @abstractmethod
    def model(self) -> str:
        """Identifier of the model being tested (stored with each result)."""

    @abstractmethod
    def send(self, turns: List[str]) -> TargetReply:
        """Send an ordered list of user turns and return the model's final reply.

        A single-turn attack passes a one-element list. Multi-turn attacks pass
        each user turn in order; the implementation threads the assistant
        replies back into the conversation so later turns see earlier context.
        If the provider refuses a turn outright, stop there and return that
        refusal — there is no reply to continue from.

        Implementations should let exceptions propagate (including provider
        errors after their own retries are exhausted); the runner decides how to
        record failures.
        """
