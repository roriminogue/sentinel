"""Smoke tests for the corpus, storage, and runner wiring.

These use a fake in-memory target client, so they need no API key or network.
"""

from __future__ import annotations

import os
import sys
from typing import List

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from attacks import AttackCategory, load_corpus  # noqa: E402
from runner.base_client import TargetClient  # noqa: E402
from runner.run import run  # noqa: E402
from storage import Result, make_engine, make_session_factory, session_scope  # noqa: E402


class FakeClient(TargetClient):
    """Echoes a canned reply and records how many turns it saw per attack."""

    def __init__(self, model: str = "fake-model", fail_on: set[str] | None = None):
        self._model = model
        self._fail_on = fail_on or set()
        self.calls: list[List[str]] = []

    @property
    def model(self) -> str:
        return self._model

    def send(self, turns: List[str]) -> str:
        self.calls.append(list(turns))
        first = turns[0]
        if first in self._fail_on:
            raise RuntimeError("simulated provider failure")
        return f"REFUSAL: I can't help with that. (saw {len(turns)} turn(s))"


def test_corpus_has_all_categories_with_enough_prompts():
    corpus = load_corpus()
    for category in AttackCategory:
        count = sum(1 for a in corpus if a.category == category)
        assert 5 <= count <= 8, f"{category} has {count} attacks"


def test_fingerprint_tracks_prompt_wording():
    """Editing an attack must change its fingerprint, or old and new results
    silently aggregate under the same id as if they were the same test."""
    from attacks.corpus import Attack

    base = dict(
        id="x", category=AttackCategory.DIRECT_JAILBREAK, description="d", source="s"
    )
    a = Attack(prompt="hello", **base)
    same = Attack(prompt="hello", **base)
    edited = Attack(prompt="hello!", **base)

    assert a.fingerprint == same.fingerprint
    assert a.fingerprint != edited.fingerprint

    # Multi-turn attacks hash their whole ordered conversation.
    turns = Attack(turns=["a", "b"], **base)
    reordered = Attack(turns=["b", "a"], **base)
    assert turns.fingerprint != reordered.fingerprint


def test_run_stores_prompt_hash(tmp_path):
    db_path = str(tmp_path / "h.db")
    run(FakeClient(), db_path)

    corpus = {a.id: a.fingerprint for a in load_corpus()}
    engine = make_engine(db_path)
    sf = make_session_factory(engine)
    with session_scope(sf) as session:
        for row in session.query(Result).all():
            assert row.prompt_hash == corpus[row.attack_id]


def test_corpus_ids_unique_and_wellformed():
    corpus = load_corpus()
    ids = [a.id for a in corpus]
    assert len(ids) == len(set(ids))
    for a in corpus:
        assert a.description and a.source
        assert a.messages  # non-empty
        if a.is_multi_turn:
            assert len(a.messages) >= 2


def test_run_populates_database(tmp_path):
    db_path = str(tmp_path / "test.db")
    client = FakeClient()
    total, errors = run(client, db_path)

    corpus = load_corpus()
    assert total == len(corpus)
    assert errors == 0

    engine = make_engine(db_path)
    sf = make_session_factory(engine)
    with session_scope(sf) as session:
        rows = session.query(Result).all()
        assert len(rows) == len(corpus)
        assert all(r.target_model == "fake-model" for r in rows)
        assert all(r.response.startswith("REFUSAL") for r in rows)
        # turn_count matches the corpus definition
        by_id = {r.attack_id: r for r in rows}
        for a in corpus:
            assert by_id[a.id].turn_count == len(a.messages)


def test_run_records_errors_without_crashing(tmp_path):
    db_path = str(tmp_path / "test.db")
    corpus = load_corpus()
    first_turn = corpus[0].messages[0]
    client = FakeClient(fail_on={first_turn})

    total, errors = run(client, db_path)
    assert total == len(corpus)
    assert errors == 1

    engine = make_engine(db_path)
    sf = make_session_factory(engine)
    with session_scope(sf) as session:
        failed = session.query(Result).filter(Result.error.isnot(None)).all()
        assert len(failed) == 1
        assert failed[0].attack_id == corpus[0].id
        assert "simulated provider failure" in failed[0].error


def test_multi_turn_sends_all_turns(tmp_path):
    db_path = str(tmp_path / "test.db")
    client = FakeClient()
    run(client, db_path)

    corpus = load_corpus()
    multi = [a for a in corpus if a.is_multi_turn]
    assert multi
    sent_lengths = {tuple(c) for c in client.calls}
    for a in multi:
        assert tuple(a.messages) in sent_lengths


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
