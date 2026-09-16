"""Sentinel scorer: judge stored results and record verdicts.

Reads prompt/response pairs from the database, classifies each with the chosen
scorer, and writes verdicts to the scores table. Raw results are never modified,
so a run can be re-scored or scored by multiple scorers.

Usage:
    python scoring/score.py --scorer heuristic
    python scoring/score.py --scorer llm-judge --model claude-haiku-4-5
"""

from __future__ import annotations

import argparse
import os
import sys
from collections import Counter

from dotenv import load_dotenv

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scoring.base_scorer import Scorer  # noqa: E402
from storage import (  # noqa: E402
    Result,
    Score,
    make_engine,
    make_session_factory,
    session_scope,
)


def build_scorer(name: str, model: str | None, max_tokens: int) -> Scorer:
    """Map a --scorer name to a concrete scorer. Add new scorers here."""
    if name == "heuristic":
        from scoring.heuristic_scorer import HeuristicScorer

        return HeuristicScorer()
    if name == "llm-judge":
        from scoring.llm_judge import DEFAULT_JUDGE_MODEL, LLMJudgeScorer

        return LLMJudgeScorer(model=model or DEFAULT_JUDGE_MODEL, max_tokens=max_tokens)
    raise ValueError(
        f"Unknown scorer {name!r}. Supported scorers: heuristic, llm-judge"
    )


def _already_scored(session, scorer_name: str) -> set[int]:
    rows = session.query(Score.result_id).filter(Score.scorer_name == scorer_name).all()
    return {r[0] for r in rows}


def run(scorer: Scorer, db_path: str, rescore: bool = False) -> Counter:
    """Score results not yet scored by this scorer. Returns a verdict tally."""
    engine = make_engine(db_path)
    session_factory = make_session_factory(engine)
    tally: Counter = Counter()

    with session_scope(session_factory) as session:
        results = session.query(Result).order_by(Result.id).all()
        skip = set() if rescore else _already_scored(session, scorer.name)

        todo = [r for r in results if r.id not in skip]
        print(
            f"Scorer: {scorer.name}\n"
            f"{len(results)} results in db, {len(todo)} to score "
            f"({len(results) - len(todo)} already scored, skipped).\n"
        )

        for i, result in enumerate(todo, start=1):
            print(f"[{i}/{len(todo)}] result#{result.id} {result.attack_id}", flush=True)
            outcome = scorer.score(result.prompt, result.response)
            tally[str(outcome.verdict)] += 1
            session.add(
                Score(
                    result_id=result.id,
                    scorer_name=scorer.name,
                    verdict=str(outcome.verdict),
                    confidence=outcome.confidence,
                    rationale=outcome.rationale,
                )
            )

    return tally


def main(argv: list[str] | None = None) -> int:
    load_dotenv()
    parser = argparse.ArgumentParser(description="Score stored Sentinel results.")
    parser.add_argument(
        "--scorer",
        default="heuristic",
        choices=["heuristic", "llm-judge"],
        help="Scoring strategy (default: heuristic).",
    )
    parser.add_argument(
        "--model",
        default=os.getenv("SENTINEL_JUDGE_MODEL"),
        help="Judge model id for --scorer llm-judge (default: provider default).",
    )
    parser.add_argument(
        "--db",
        default=os.getenv("SENTINEL_DB_PATH", "sentinel.db"),
        help="SQLite database path (default: sentinel.db or SENTINEL_DB_PATH).",
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=int(os.getenv("SENTINEL_JUDGE_MAX_TOKENS", "512")),
        help="Max tokens per judge response (default: 512).",
    )
    parser.add_argument(
        "--rescore",
        action="store_true",
        help="Re-score results even if this scorer already scored them.",
    )
    args = parser.parse_args(argv)

    try:
        scorer = build_scorer(args.scorer, args.model, args.max_tokens)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    tally = run(scorer, args.db, rescore=args.rescore)

    total = sum(tally.values())
    print(f"\nDone. {total} results scored. Verdicts:")
    for verdict, count in sorted(tally.items(), key=lambda kv: -kv[1]):
        print(f"  {verdict:10s} {count}")
    print(f"Scores saved to {args.db}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
