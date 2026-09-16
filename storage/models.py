"""SQLAlchemy ORM models for Sentinel run results."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
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
    verdict: Mapped[str] = mapped_column(String(32), index=True)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<Score id={self.id} result_id={self.result_id} "
            f"scorer={self.scorer_name!r} verdict={self.verdict!r}>"
        )
