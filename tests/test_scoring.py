"""Tests for the Phase 2 scoring layer.

These use the heuristic scorer and a fake scorer, so they need no API key.
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scoring import HeuristicScorer, ScoreResult, Scorer, Technique, Verdict  # noqa: E402
from scoring.llm_judge import _parse_verdict  # noqa: E402
from scoring.score import run  # noqa: E402
from storage import (  # noqa: E402
    Result,
    Score,
    make_engine,
    make_session_factory,
    session_scope,
)


class FakeScorer(Scorer):
    """Always returns COMPLIED; records how many times it was called."""

    def __init__(self) -> None:
        self.calls = 0

    @property
    def name(self) -> str:
        return "fake"

    def score(self, prompt: str, response: str) -> ScoreResult:
        self.calls += 1
        return ScoreResult(
            verdict=Verdict.COMPLIED,
            technique=Technique.ADOPTED,
            confidence=0.9,
            rationale="test",
        )


def _seed(db_path: str, rows: list[tuple[str, str]], error: str | None = None) -> None:
    engine = make_engine(db_path)
    sf = make_session_factory(engine)
    with session_scope(sf) as session:
        for attack_id, response in rows:
            session.add(
                Result(
                    attack_id=attack_id,
                    category="direct_jailbreak",
                    prompt="p",
                    response=response,
                    target_model="m",
                    turn_count=1,
                    error=error,
                )
            )


def test_heuristic_detects_refusal():
    s = HeuristicScorer()
    assert s.score("p", "I can't help with that request.").verdict == Verdict.REFUSED
    assert s.score("p", "I'm sorry, but I cannot assist.").verdict == Verdict.REFUSED
    assert s.score("p", "That is against my guidelines.").verdict == Verdict.REFUSED


def test_heuristic_detects_compliance_and_empty():
    s = HeuristicScorer()
    assert s.score("p", "Sure! Here are the steps: first, ...").verdict == Verdict.COMPLIED
    assert s.score("p", "").verdict == Verdict.UNCLEAR
    assert s.score("p", "   ").verdict == Verdict.UNCLEAR


def test_llm_judge_parses_both_axes():
    r = _parse_verdict(
        '{"verdict": "complied", "technique": "resisted", "confidence": 0.9,'
        ' "rationale": "rejected the persona but answered anyway"}'
    )
    assert r.verdict == Verdict.COMPLIED
    assert r.technique == Technique.RESISTED

    # A missing or invalid technique degrades to unclear, never to a guess.
    missing = _parse_verdict('{"verdict": "refused"}')
    assert missing.technique == Technique.UNCLEAR
    bad = _parse_verdict('{"verdict": "refused", "technique": "banana"}')
    assert bad.technique == Technique.UNCLEAR


def test_heuristic_never_claims_to_know_technique():
    """The heuristic only matches words; it cannot see whether framing worked."""
    s = HeuristicScorer()
    for response in ("I can't help with that.", "Sure, here are the steps.", ""):
        assert s.score("p", response).technique == Technique.UNCLEAR


def test_llm_judge_parser_handles_valid_and_garbage():
    good = _parse_verdict('{"verdict": "refused", "confidence": 0.8, "rationale": "declined"}')
    assert good.verdict == Verdict.REFUSED
    assert good.confidence == 0.8

    wrapped = _parse_verdict('Here you go: {"verdict":"complied","confidence":1}')
    assert wrapped.verdict == Verdict.COMPLIED

    garbage = _parse_verdict("no json here")
    assert garbage.verdict == Verdict.UNCLEAR

    bad_label = _parse_verdict('{"verdict": "banana"}')
    assert bad_label.verdict == Verdict.UNCLEAR


def test_run_scores_all_and_writes_table(tmp_path):
    db_path = str(tmp_path / "s.db")
    _seed(db_path, [("a1", "I can't help with that."), ("a2", "Sure, here is how.")])

    tally = run(HeuristicScorer(), db_path)
    assert tally[str(Verdict.REFUSED)] == 1
    assert tally[str(Verdict.COMPLIED)] == 1

    engine = make_engine(db_path)
    sf = make_session_factory(engine)
    with session_scope(sf) as session:
        scores = session.query(Score).all()
        assert len(scores) == 2
        assert all(s.scorer_name == "heuristic" for s in scores)


def test_run_skips_already_scored(tmp_path):
    db_path = str(tmp_path / "s.db")
    _seed(db_path, [("a1", "Sure, here is how."), ("a2", "Sure, here is how.")])

    fake = FakeScorer()
    run(fake, db_path)
    assert fake.calls == 2

    # Second run with the same scorer should skip everything.
    fake2 = FakeScorer()
    run(fake2, db_path)
    assert fake2.calls == 0

    # ...unless rescore is requested.
    fake3 = FakeScorer()
    run(fake3, db_path, rescore=True)
    assert fake3.calls == 2


def test_run_skips_errored_results_by_default(tmp_path):
    db_path = str(tmp_path / "s.db")
    _seed(db_path, [("ok1", "I can't help with that.")])
    _seed(db_path, [("bad1", ""), ("bad2", "")], error="BadRequestError: boom")

    fake = FakeScorer()
    run(fake, db_path)
    assert fake.calls == 1  # only the non-errored result

    # ...unless explicitly included.
    fake2 = FakeScorer()
    run(fake2, db_path, include_errors=True)
    assert fake2.calls == 2  # the two errored rows, the ok one already scored


def test_rescore_replaces_instead_of_accumulating(tmp_path):
    """A stale verdict left behind shows up in reports as if it were current."""
    db_path = str(tmp_path / "s.db")
    _seed(db_path, [("a1", "Sure, here is how.")])

    run(HeuristicScorer(), db_path)
    run(HeuristicScorer(), db_path, rescore=True)
    run(HeuristicScorer(), db_path, rescore=True)

    engine = make_engine(db_path)
    sf = make_session_factory(engine)
    with session_scope(sf) as session:
        scores = session.query(Score).filter(Score.scorer_name == "heuristic").all()
        assert len(scores) == 1, "rescoring must replace the previous verdict"


def test_missing_columns_are_added_without_losing_rows(tmp_path):
    """An older database must survive a schema addition, not need deleting."""
    import sqlite3

    db_path = str(tmp_path / "old.db")
    _seed(db_path, [("a1", "I can't help with that.")])
    run(HeuristicScorer(), db_path)

    # Simulate a database written before the 'technique' column existed.
    raw = sqlite3.connect(db_path)
    raw.execute("ALTER TABLE scores DROP COLUMN technique")
    raw.commit()
    raw.close()

    # Opening it again should re-add the column and keep the existing rows.
    engine = make_engine(db_path)
    sf = make_session_factory(engine)
    with session_scope(sf) as session:
        scores = session.query(Score).all()
        assert len(scores) == 1
        assert scores[0].technique is None
        assert session.query(Result).count() == 1


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
