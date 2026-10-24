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


def describe_system_prompt(system_prompt: Optional[str]) -> str:
    """One-line human description of a configuration's system prompt."""
    if not system_prompt:
        return "none (bare model)"
    first_line = system_prompt.splitlines()[0]
    if len(first_line) > 60:
        first_line = first_line[:60] + "..."
    return f'"{first_line}" ({len(system_prompt)} characters)'


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

    @property
    def system_prompt(self) -> Optional[str]:
        """Setup instructions the target runs under, if any.

        Real chatbots are a model plus instructions; testing the bare model
        says little about a deployment. Recorded with every result so runs
        under different instructions are never mistaken for the same test.
        """
        return None

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
