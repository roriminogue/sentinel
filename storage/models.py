"""SQLAlchemy ORM models for Sentinel run results."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Result(Base):
    """One prompt/response pair from firing a single attack at a target model.

    For multi-turn attacks, ``prompt`` holds the full ordered conversation
    (turns joined and labeled) and ``response`` holds the model's final reply;
    ``turn_count`` records how many user turns were sent.
    """

    __tablename__ = "results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    attack_id: Mapped[str] = mapped_column(String(128), index=True)
    category: Mapped[str] = mapped_column(String(64), index=True)
    prompt: Mapped[str] = mapped_column(Text)
    # Short hash of the prompt wording (Attack.fingerprint). Editing an attack
    # changes this, so results from different corpus versions stay
    # distinguishable instead of aggregating under one attack_id. Null on rows
    # written before the column existed.
    prompt_hash: Mapped[str | None] = mapped_column(String(16), nullable=True)
    response: Mapped[str] = mapped_column(Text)
    target_model: Mapped[str] = mapped_column(String(128), index=True)
    turn_count: Mapped[int] = mapped_column(Integer, default=1)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        status = "error" if self.error else "ok"
        return (
            f"<Result id={self.id} attack={self.attack_id!r} "
            f"model={self.target_model!r} {status}>"
        )


class Score(Base):
    """A verdict on a single Result, produced by one scorer.

    Kept separate from Result so raw prompt/response data is never mutated and
    a run can be re-scored (or scored by several scorers) independently. The
    pair (result_id, scorer_name) is what the scoring runner treats as unique.
    """

    __tablename__ = "scores"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    result_id: Mapped[int] = mapped_column(
        ForeignKey("results.id"), index=True
    )
    scorer_name: Mapped[str] = mapped_column(String(64), index=True)
    # Outcome axis: did disallowed content come out?
    verdict: Mapped[str] = mapped_column(String(32), index=True)
    # Method axis: did the attack's manipulation work? Null when a scorer
    # cannot assess it (the heuristic never can).
    technique: Mapped[str | None] = mapped_column(String(32), nullable=True)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<Score id={self.id} result_id={self.result_id} "
            f"scorer={self.scorer_name!r} verdict={self.verdict!r}>"
        )


class AgentResult(Base):
    """Outcome of running one agent scenario against a target model.

    ``compromised`` is True when the agent attempted a tool call matching one of
    the scenario's violation rules — i.e. the attack succeeded in causing an
    unsafe action (all actions are simulated).
    """

    __tablename__ = "agent_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scenario_id: Mapped[str] = mapped_column(String(128), index=True)
    category: Mapped[str] = mapped_column(String(64), index=True)
    target_model: Mapped[str] = mapped_column(String(128), index=True)
    task: Mapped[str] = mapped_column(Text)
    compromised: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    # The agent never called the tool carrying the payload, so it never met the
    # attack. Distinct from a genuine defense: compromised=False and
    # inconclusive=False together mean the agent saw the attack and resisted.
    inconclusive: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    violated_rule: Mapped[str | None] = mapped_column(Text, nullable=True)
    tool_call_count: Mapped[int] = mapped_column(Integer, default=0)
    steps_used: Mapped[int] = mapped_column(Integer, default=0)
    final_text: Mapped[str] = mapped_column(Text, default="")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        if self.compromised:
            state = "COMPROMISED"
        elif self.inconclusive:
            state = "inconclusive"
        else:
            state = "safe"
        return (
            f"<AgentResult id={self.id} scenario={self.scenario_id!r} "
            f"model={self.target_model!r} {state}>"
        )


class AgentToolCall(Base):
    """A single tool call the agent attempted during a scenario run.

    ``arguments`` is the JSON-serialized tool input. ``violating`` marks the
    calls that tripped a violation rule.
    """

    __tablename__ = "agent_tool_calls"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    agent_result_id: Mapped[int] = mapped_column(
        ForeignKey("agent_results.id"), index=True
    )
    step: Mapped[int] = mapped_column(Integer)
    tool_name: Mapped[str] = mapped_column(String(64), index=True)
    arguments: Mapped[str] = mapped_column(Text)
    violating: Mapped[bool] = mapped_column(Boolean, default=False, index=True)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        flag = " VIOLATING" if self.violating else ""
        return f"<AgentToolCall {self.tool_name!r} step={self.step}{flag}>"
