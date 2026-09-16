"""Read the Sentinel database and print human-readable summaries.

Replaces hand-written sqlite one-liners, which are painful to quote correctly
in most shells.

Usage:
    python reporting/report.py                  # overall summary
    python reporting/report.py --complied       # attacks the judge says succeeded
    python reporting/report.py --disagreements  # where scorers disagree
    python reporting/report.py --attack pi-004  # full detail for one attack
    python reporting/report.py --agent          # agent scenario detail
"""

from __future__ import annotations

import argparse
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from storage import (  # noqa: E402
    AgentResult,
    AgentToolCall,
    Result,
    Score,
    make_engine,
    make_session_factory,
    session_scope,
)

_RULE = "=" * 72


def _wrap(text: str, indent: str = "    ", limit: int | None = None) -> str:
    body = text if limit is None or len(text) <= limit else text[:limit] + " ..."
    return indent + body.replace("\n", "\n" + indent)


def _latest_agent_runs(session, all_runs: bool = False) -> list[AgentResult]:
    """Most recent run per scenario, so repeated runs don't look like duplicates."""
    rows = session.query(AgentResult).order_by(AgentResult.id).all()
    if all_runs:
        return rows
    newest: dict[str, AgentResult] = {}
    for row in rows:
        newest[row.scenario_id] = row  # later rows overwrite earlier ones
    return sorted(newest.values(), key=lambda r: r.scenario_id)


def summary(session) -> None:
    results = session.query(Result).filter(Result.error.is_(None)).all()
    errored = session.query(Result).filter(Result.error.isnot(None)).count()

    print(_RULE)
    print("PROMPT ATTACKS (phases 1-2)")
    print(_RULE)
    print(f"{len(results)} scored-eligible results ({errored} errored, excluded)\n")

    scores = session.query(Score).all()
    by_result = defaultdict(dict)
    for s in scores:
        by_result[s.result_id][s.scorer_name] = s.verdict

    scorers = sorted({s.scorer_name for s in scores})
    if not scorers:
        print("No scores yet — run: python scoring/score.py --scorer heuristic\n")
    for scorer in scorers:
        tally: dict[tuple[str, str], int] = defaultdict(int)
        for r in results:
            verdict = by_result.get(r.id, {}).get(scorer)
            if verdict:
                tally[(r.category, verdict)] += 1
        print(f"  scorer: {scorer}")
        categories = sorted({c for c, _ in tally})
        for category in categories:
            parts = [
                f"{v}={n}" for (c, v), n in sorted(tally.items()) if c == category
            ]
            print(f"    {category:24s} {'  '.join(parts)}")
        print()

    agent_rows = _latest_agent_runs(session)
    if agent_rows:
        print(_RULE)
        print("AGENT SCENARIOS (phase 3)")
        print(_RULE)
        compromised = sum(1 for r in agent_rows if r.compromised)
        inconclusive = sum(1 for r in agent_rows if r.inconclusive)
        errors = sum(1 for r in agent_rows if r.error)
        defended = len(agent_rows) - compromised - inconclusive - errors
        print(
            f"  {len(agent_rows)} scenarios (latest run each): {defended} defended, "
            f"{compromised} compromised, {inconclusive} inconclusive, {errors} errors\n"
        )
        for r in agent_rows:
            if r.compromised:
                print(f"  COMPROMISED  {r.scenario_id}: {r.violated_rule}")
            elif r.inconclusive:
                print(f"  inconclusive {r.scenario_id} (never reached the payload)")
        print()


def complied(session) -> None:
    """Attacks a judge scored as successful — the ones worth reading."""
    rows = (
        session.query(Result, Score)
        .join(Score, Score.result_id == Result.id)
        .filter(Score.verdict == "complied")
        .all()
    )
    if not rows:
        print("No results scored 'complied' by any scorer.")
        return
    for result, score in rows:
        print(_RULE)
        print(f"{result.attack_id}  [{result.category}]  scorer={score.scorer_name}")
        print(f"verdict: complied   technique: {score.technique or 'n/a'}")
        print(f"rationale: {score.rationale}")
        print("\nPROMPT:")
        print(_wrap(result.prompt, limit=600))
        print("\nRESPONSE:")
        print(_wrap(result.response, limit=900))
        print()


def disagreements(session) -> None:
    """Results where two scorers reached different verdicts.

    These are the most informative rows in the database: one of the scorers is
    wrong, and finding out which teaches you something about both.
    """
    scores = session.query(Score).all()
    by_result = defaultdict(dict)
    for s in scores:
        by_result[s.result_id][s.scorer_name] = s.verdict

    conflicts = {
        rid: verdicts
        for rid, verdicts in by_result.items()
        if len(set(verdicts.values())) > 1
    }
    if not conflicts:
        print("No scorer disagreements (or only one scorer has run).")
        return

    print(f"{len(conflicts)} result(s) where scorers disagree:\n")
    for rid, verdicts in conflicts.items():
        result = session.get(Result, rid)
        spread = ", ".join(f"{k}={v}" for k, v in sorted(verdicts.items()))
        print(_RULE)
        print(f"{result.attack_id}  [{result.category}]")
        print(f"  {spread}")
        print("\nRESPONSE:")
        print(_wrap(result.response, limit=600))
        print()


def attack_detail(session, needle: str) -> None:
    rows = session.query(Result).filter(Result.attack_id.like(f"%{needle}%")).all()
    if not rows:
        print(f"No attack matching {needle!r}.")
        return
    for result in rows:
        scores = session.query(Score).filter(Score.result_id == result.id).all()
        print(_RULE)
        print(f"{result.attack_id}  [{result.category}]  model={result.target_model}")
        for s in scores:
            technique = f", technique={s.technique}" if s.technique else ""
            print(f"  {s.scorer_name}: verdict={s.verdict}{technique}")
            print(f"      {s.rationale}")
        print("\nPROMPT:")
        print(_wrap(result.prompt))
        print("\nRESPONSE:")
        print(_wrap(result.response or "(none)"))
        if result.error:
            print(f"\nERROR: {result.error}")
        print()


def agent_detail(session, all_runs: bool = False) -> None:
    rows = _latest_agent_runs(session, all_runs=all_runs)
    if not rows:
        print("No agent runs yet — run: python agent/run_agent.py")
        return
    if not all_runs:
        print("(latest run per scenario; use --all for full history)\n")
    for r in rows:
        if r.compromised:
            state = "COMPROMISED"
        elif r.inconclusive:
            state = "INCONCLUSIVE"
        elif r.error:
            state = "ERROR"
        else:
            state = "defended"
        print(_RULE)
        stamp = r.timestamp.strftime("%Y-%m-%d %H:%M") if r.timestamp else "?"
        print(f"{r.scenario_id}  [{r.category}]  {state}   ({stamp})")
        if r.violated_rule:
            print(f"  violation: {r.violated_rule}")
        calls = (
            session.query(AgentToolCall)
            .filter(AgentToolCall.agent_result_id == r.id)
            .all()
        )
        for c in calls:
            flag = "  <-- VIOLATION" if c.violating else ""
            print(f"  [step {c.step}] {c.tool_name}({c.arguments}){flag}")
        print()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Summarize Sentinel results.")
    parser.add_argument(
        "--db",
        default=os.getenv("SENTINEL_DB_PATH", "sentinel.db"),
        help="SQLite database path (default: sentinel.db or SENTINEL_DB_PATH).",
    )
    parser.add_argument("--complied", action="store_true", help="Show successful attacks.")
    parser.add_argument(
        "--disagreements", action="store_true", help="Show scorer conflicts."
    )
    parser.add_argument("--attack", help="Show full detail for attacks matching this id.")
    parser.add_argument("--agent", action="store_true", help="Show agent run detail.")
    parser.add_argument(
        "--all",
        action="store_true",
        help="With --agent, show every historical run instead of the latest each.",
    )
    args = parser.parse_args(argv)

    engine = make_engine(args.db)
    session_factory = make_session_factory(engine)
    with session_scope(session_factory) as session:
        if args.complied:
            complied(session)
        elif args.disagreements:
            disagreements(session)
        elif args.attack:
            attack_detail(session, args.attack)
        elif args.agent:
            agent_detail(session, all_runs=args.all)
        else:
            summary(session)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
