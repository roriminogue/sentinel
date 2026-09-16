"""Sentinel runner: fire the attack corpus at a target model and log results.

Usage:
    python runner/run.py --target anthropic --model claude-haiku-4-5
"""

from __future__ import annotations

import argparse
import os
import sys

from dotenv import load_dotenv

# Allow running as `python runner/run.py` from the repo root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from attacks import Attack, load_corpus  # noqa: E402
from runner.base_client import TargetClient  # noqa: E402
from storage import Result, make_engine, make_session_factory, session_scope  # noqa: E402


def build_client(target: str, model: str | None, max_tokens: int) -> TargetClient:
    """Factory mapping a --target name to a concrete client.

    Add new providers here (openai, ollama, ...) as they implement TargetClient.
    """
    if target == "anthropic":
        from runner.anthropic_client import DEFAULT_MODEL, AnthropicClient

        return AnthropicClient(model=model or DEFAULT_MODEL, max_tokens=max_tokens)
    raise ValueError(f"Unknown target {target!r}. Supported targets: anthropic")


def _format_prompt(attack: Attack) -> str:
    """Human-readable record of what was sent (labels turns for multi-turn)."""
    if attack.is_multi_turn:
        return "\n\n".join(
            f"[turn {i}] {t}" for i, t in enumerate(attack.messages, start=1)
        )
    return attack.messages[0]


def run(
    client: TargetClient,
    db_path: str,
) -> tuple[int, int]:
    """Run the full corpus. Returns (attacks_run, errors)."""
    corpus = load_corpus()
    engine = make_engine(db_path)
    session_factory = make_session_factory(engine)

    errors = 0
    for i, attack in enumerate(corpus, start=1):
        print(f"[{i}/{len(corpus)}] {attack.id} ({attack.category})", flush=True)
        response_text = ""
        error_text: str | None = None
        try:
            response_text = client.send(attack.messages)
        except Exception as exc:  # noqa: BLE001 - one failure must not kill the run
            error_text = f"{type(exc).__name__}: {exc}"
            errors += 1
            print(f"    ERROR: {error_text}", flush=True)

        with session_scope(session_factory) as session:
            session.add(
                Result(
                    attack_id=attack.id,
                    category=str(attack.category),
                    prompt=_format_prompt(attack),
                    response=response_text,
                    target_model=client.model,
                    turn_count=len(attack.messages),
                    error=error_text,
                )
            )

    return len(corpus), errors


def main(argv: list[str] | None = None) -> int:
    load_dotenv()
    parser = argparse.ArgumentParser(description="Run the Sentinel attack corpus.")
    parser.add_argument(
        "--target",
        default="anthropic",
        help="Target provider (default: anthropic).",
    )
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
    args = parser.parse_args(argv)

    try:
        client = build_client(args.target, args.model, args.max_tokens)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(f"Target: {args.target} / model: {client.model}")
    print(f"Database: {args.db}\n")

    total, errors = run(client, args.db)

    print(
        f"\nDone. {total} attacks run, {errors} errors. "
        f"Results saved to {args.db}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
