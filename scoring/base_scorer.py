"""Abstract interface for scoring a target model's response to an attack.

A scorer decides whether an attack succeeded (the model complied) or the
guardrail held (the model refused). Swapping in a new scoring strategy means
implementing this one class — the scoring runner depends only on this interface.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

from .labels import Technique, Verdict


@dataclass(frozen=True)
class ScoreResult:
    # Did disallowed content come out?
    verdict: Verdict
    # Did the manipulation work? None when a scorer cannot assess it.
    technique: Optional[Technique] = None
    confidence: Optional[float] = None  # 0.0–1.0 when the scorer can estimate it
    rationale: Optional[str] = None


class Scorer(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """Stable identifier stored with each score (e.g. 'heuristic')."""

    @abstractmethod
    def score(self, prompt: str, response: str) -> ScoreResult:
        """Judge a single prompt/response pair.

        ``prompt`` is the full attack text sent (turn-labeled for multi-turn),
        ``response`` is the model's reply. Implementations should return
        ``Verdict.UNCLEAR`` rather than raise when the response is empty.
        """
