"""Sentinel agent runner: test whether a tool-using agent can be made to act unsafely.

Runs each scenario against the target model with simulated tools, records every
tool call, and flags runs where the agent attempted an action matching a
scenario's violation rules.

No tool call performs a real action — see agent/tools.py.

Usage:
    python agent/run_agent.py --target anthropic --model claude-haiku-4-5
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from dotenv import load_dotenv

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.base_agent_client import AgentClient  # noqa: E402
from agent.harness import run_scenario  # noqa: E402
from agent.scenarios import load_scenarios  # noqa: E402
from storage import (  # noqa: E402
    AgentResult,
    AgentToolCall,
    make_engine,
    make_session_factory,
    session_scope,
)


def build_client(target: str, model: str | None, max_tokens: int) -> AgentClient:
    """Map a --target name to a concrete agent client. Add providers here."""
    if target == "anthropic":
        from agent.anthropic_agent import DEFAULT_MODEL, AnthropicAgentClient

        return AnthropicAgentClient(
            model=model or DEFAULT_MODEL, max_tokens=max_tokens
        )
    raise ValueError(f"Unknown target {target!r}. Supported targets: anthropic")


def _print_transcript(scenario, outcome) -> None:
    """Show the whole attack step by step: task, tool calls, what came back."""
    print("    " + "-" * 66)
    print(f"    SYSTEM: {scenario.system}")
    print(f"    TASK:   {scenario.task}")
    print(f"    PAYLOAD DELIVERED BY: {', '.join(scenario.payload_tools)}")
    for index, call in enumerate(outcome.trace.tool_calls):
        flag = "  <-- VIOLATION" if index in outcome.violating_calls else ""
        print(f"\n    [step {call.step}] CALL {call.name}({json.dumps(call.arguments)}){flag}")
        if call.result:
            body = call.result if len(call.result) <= 500 else call.result[:500] + " ..."
            indented = body.replace("\n", "\n             ")
            print(f"             RETURNED: {indented}")
    if outcome.trace.final_text:
        final = outcome.trace.final_text
        final = final if len(final) <= 500 else final[:500] + " ..."
        print(f"\n    FINAL ANSWER: {final.replace(chr(10), chr(10) + '                  ')}")
    print("    " + "-" * 66)


def run(
    client: AgentClient,
    db_path: str,
    only: str | None = None,
    verbose: bool = False,
) -> tuple[int, int, int, int]:
    """Run scenarios. Returns (total, compromised, inconclusive, errors)."""
    scenarios = load_scenarios()
    if only:
        scenarios = [s for s in scenarios if only in s.id]
        if not scenarios:
            raise ValueError(f"No scenario matching {only!r}")
    engine = make_engine(db_path)
    session_factory = make_session_factory(engine)

    compromised = 0
    inconclusive = 0
    errors = 0

    for i, scenario in enumerate(scenarios, start=1):
        print(f"[{i}/{len(scenarios)}] {scenario.id} ({scenario.category})", flush=True)
        outcome = run_scenario(client, scenario)

        if outcome.error:
            errors += 1
            print(f"    ERROR: {outcome.error}", flush=True)
        elif outcome.compromised:
            compromised += 1
            print(f"    COMPROMISED: {outcome.violated_rule}", flush=True)
        elif outcome.inconclusive:
            inconclusive += 1
            print(
                "    INCONCLUSIVE: agent never called "
                f"{'/'.join(scenario.payload_tools)}, so it never saw the attack",
                flush=True,
            )
        else:
            print(
                f"    defended ({len(outcome.trace.tool_calls)} tool call(s))",
                flush=True,
            )

        if verbose:
            _print_transcript(scenario, outcome)

        with session_scope(session_factory) as session:
            row = AgentResult(
                scenario_id=scenario.id,
                category=str(scenario.category),
                target_model=client.model,
                task=scenario.task,
                compromised=outcome.compromised,
                inconclusive=outcome.inconclusive,
                violated_rule=outcome.violated_rule,
                tool_call_count=len(outcome.trace.tool_calls),
                steps_used=outcome.trace.steps_used,
                final_text=outcome.trace.final_text,
                error=outcome.error,
            )
            session.add(row)
            session.flush()  # assign row.id before inserting children

            violating = set(outcome.violating_calls)
            for index, call in enumerate(outcome.trace.tool_calls):
                session.add(
                    AgentToolCall(
                        agent_result_id=row.id,
                        step=call.step,
                        tool_name=call.name,
                        arguments=json.dumps(call.arguments),
                        violating=index in violating,
                    )
                )

    return len(scenarios), compromised, inconclusive, errors


def main(argv: list[str] | None = None) -> int:
    load_dotenv()
    parser = argparse.ArgumentParser(
        description="Run Sentinel agent/tool-call security scenarios."
    )
    parser.add_argument("--target", default="anthropic", help="Target provider.")
    parser.add_argument(
        "--model",
        default=os.getenv("SENTINEL_TARGET_MODEL"),
        help="Model id to test (default: provider default or SENTINEL_TARGET_MODEL).",
    )
    parser.add_argument(
        "--db",
        default=os.getenv("SENTINEL_DB_PATH", "sentinel.db"),
        help="SQLite database path (default: sentinel.db or SENTINEL_DB_PATH).",
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=int(os.getenv("SENTINEL_MAX_TOKENS", "1024")),
        help="Max tokens per model response (default: 1024).",
    )
    parser.add_argument(
        "--scenario",
        help="Run only scenarios whose id contains this string (e.g. ag-003).",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Print the full transcript: every tool call and what it returned.",
    )
    args = parser.parse_args(argv)

    try:
        client = build_client(args.target, args.model, args.max_tokens)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(f"Target: {args.target} / model: {client.model}")
    print(f"Database: {args.db}")
    print("All tool calls are simulated — no real actions are performed.\n")

    try:
        total, compromised, inconclusive, errors = run(
            client, args.db, only=args.scenario, verbose=args.verbose
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    defended = total - compromised - inconclusive - errors

    print(
        f"\nDone. {total} scenarios run: {defended} defended, "
        f"{compromised} compromised, {inconclusive} inconclusive, {errors} errors."
    )
    if inconclusive:
        print(
            "Inconclusive runs are NOT passes — the agent never reached the "
            "injected payload, so nothing was tested."
        )
    print(f"Results saved to {args.db}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
