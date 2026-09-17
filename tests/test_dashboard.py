"""Tests for the HTML dashboard renderer."""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from attacks import load_corpus  # noqa: E402
from reporting.dashboard import gather, render  # noqa: E402
from storage import (  # noqa: E402
    AgentResult,
    Result,
    Score,
    make_engine,
    make_session_factory,
    session_scope,
)


def _seed(
    db_path: str,
    response: str = "I can't help with that.",
    disagree: bool = False,
) -> None:
    attack = load_corpus()[0]
    engine = make_engine(db_path)
    sf = make_session_factory(engine)
    with session_scope(sf) as session:
        row = Result(
            attack_id=attack.id,
            category=str(attack.category),
            prompt=attack.rendered_prompt,
            prompt_hash=attack.fingerprint,
            response=response,
            target_model="m",
            turn_count=1,
        )
        session.add(row)
        session.flush()
        session.add(
            Score(
                result_id=row.id,
                scorer_name="heuristic",
                verdict="refused",
                technique="unclear",
                rationale="matched",
            )
        )
        if disagree:
            # Response text is only rendered where scorers disagree.
            session.add(
                Score(
                    result_id=row.id,
                    scorer_name="llm-judge:test",
                    verdict="complied",
                    technique="adopted",
                    rationale="differs",
                )
            )
        session.add(
            AgentResult(
                scenario_id="ag-001-webpage-exfil",
                category="data_exfiltration",
                target_model="m",
                task="t",
                compromised=True,
                violated_rule="Posted to the attacker endpoint.",
                tool_call_count=2,
                steps_used=2,
                final_text="done",
            )
        )


def _render(db_path: str, include_stale: bool = False) -> str:
    engine = make_engine(db_path)
    sf = make_session_factory(engine)
    with session_scope(sf) as session:
        return render(gather(session, include_stale))


def test_renders_self_contained_page(tmp_path):
    db_path = str(tmp_path / "d.db")
    _seed(db_path)
    page = _render(db_path)

    assert page.startswith("<!DOCTYPE html>")
    assert "Sentinel Report" in page
    assert "ag-001-webpage-exfil" in page
    assert "Compromised" in page
    # Self-contained: nothing fetched from the network.
    for marker in ("http://", "https://", "<script src", "<link rel=\"stylesheet\""):
        assert marker not in page, f"page must not reference {marker}"


def test_adversarial_response_is_escaped(tmp_path):
    """Responses come from the model under attack, so they are untrusted input.

    An unescaped response would turn the report into a delivery vehicle for
    whatever the target model was induced to emit.
    """
    db_path = str(tmp_path / "x.db")
    _seed(
        db_path,
        response="<script>alert('xss')</script><img src=x onerror=1>",
        disagree=True,
    )
    page = _render(db_path)

    # The property that matters is that no tag can form from the payload —
    # escaping leaves inert text like "onerror=1" behind, which is harmless.
    assert "<script>alert" not in page
    assert "<img src=x" not in page
    assert "&lt;script&gt;alert" in page
    assert "&lt;img src=x onerror=1&gt;" in page


def test_status_is_never_colour_alone(tmp_path):
    """Status red and green are near-indistinguishable under deuteranopia, so
    every state must also carry a glyph and a word."""
    db_path = str(tmp_path / "g.db")
    _seed(db_path)
    page = _render(db_path)

    for word in ("Refused", "Compromised"):
        assert word in page
    for glyph in ("✓", "✕"):
        assert glyph in page


def test_bar_length_encodes_count(tmp_path):
    """Normalising every bar to full width would make 6 and 7 look identical."""
    db_path = str(tmp_path / "b.db")
    engine = make_engine(db_path)
    sf = make_session_factory(engine)
    corpus = load_corpus()
    # Two categories with deliberately different totals.
    big = [a for a in corpus if str(a.category) == "prompt_injection"][:4]
    small = [a for a in corpus if str(a.category) == "multi_turn"][:1]
    with session_scope(sf) as session:
        for attack in big + small:
            row = Result(
                attack_id=attack.id,
                category=str(attack.category),
                prompt=attack.rendered_prompt,
                prompt_hash=attack.fingerprint,
                response="I can't help.",
                target_model="m",
                turn_count=1,
            )
            session.add(row)
            session.flush()
            session.add(
                Score(result_id=row.id, scorer_name="heuristic", verdict="refused")
            )

    page = _render(db_path)
    assert "width:100.0%" in page  # the largest category
    assert "width:25.0%" in page  # 1 of 4


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
