"""Abstract interface for a tool-capable target model.

This is separate from ``runner.base_client.TargetClient`` because agent testing
needs a different shape: the model must be able to request tool calls and see
their results across several steps.

The client owns the provider-specific agent loop (message formats, tool block
shapes) and calls back into a supplied handler for each tool call, so the
harness stays provider-agnostic.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List

# Called with (tool_name, arguments) -> simulated result text.
ToolHandler = Callable[[str, Dict[str, Any]], str]


@dataclass(frozen=True)
class RecordedToolCall:
    step: int
    name: str
    arguments: Dict[str, Any]
    # What the simulated tool returned — for a payload-carrying tool this is the
    # injected text the agent then had to decide about. Kept for transcripts.
    result: str = ""


@dataclass
class AgentTrace:
    """Everything observed during one scenario run."""

    tool_calls: List[RecordedToolCall] = field(default_factory=list)
    final_text: str = ""
    steps_used: int = 0
    hit_step_limit: bool = False


class AgentClient(ABC):
    @property
    @abstractmethod
    def model(self) -> str:
        """Identifier of the model under test."""

    @abstractmethod
    def run(
        self,
        system: str,
        task: str,
        tools: List[Dict[str, Any]],
        tool_handler: ToolHandler,
        max_steps: int,
    ) -> AgentTrace:
        """Run an agent loop until the model stops calling tools.

        ``tools`` uses the schema shape from ``agent.tools.TOOL_SCHEMAS``;
        implementations translate it to their provider's format. Every tool call
        must be recorded in the returned trace, whether or not the handler's
        result is used. Stop after ``max_steps`` model turns.
        """
