"""Abstract interface for any target LLM.

Swapping in OpenAI, Ollama, or another provider means implementing this one
class — the runner depends only on this interface, never on a concrete SDK.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List


class TargetClient(ABC):
    """A target model the corpus is fired at."""

    @property
    @abstractmethod
    def model(self) -> str:
        """Identifier of the model being tested (stored with each result)."""

    @abstractmethod
    def send(self, turns: List[str]) -> str:
        """Send an ordered list of user turns and return the model's final reply.

        A single-turn attack passes a one-element list. Multi-turn attacks pass
        each user turn in order; the implementation is responsible for threading
        the assistant replies back into the conversation so later turns see the
        earlier context.

        Implementations should let exceptions propagate (including provider
        errors after their own retries are exhausted); the runner decides how to
        record failures.
        """
