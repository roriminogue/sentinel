# Sentinel

An automated LLM red-teaming and guardrail-evaluation framework.

**Phase 1 (this repo):** a categorized corpus of adversarial prompts, a runner
that fires each one at a target LLM, and a local SQLite log of every
prompt/response pair. Scoring, agent/tool-call security, and a dashboard are
future phases.

## What it does

1. Stores a categorized library of adversarial prompts (jailbreaks, prompt
   injection, encoding/obfuscation tricks, multi-turn manipulation).
2. Fires each prompt at a target LLM via its API.
3. Logs every prompt + full response + metadata to a local SQLite database.
4. Is easy to extend with new attack categories and new target models.

## Project layout

```
sentinel/
├── attacks/          # attack corpus + category taxonomy
│   ├── categories.py # AttackCategory enum
│   └── corpus.py     # Attack definitions (single- and multi-turn)
├── runner/           # the pipeline
│   ├── base_client.py     # TargetClient abstract interface
│   ├── anthropic_client.py# Anthropic implementation
│   └── run.py             # CLI entrypoint
├── storage/          # SQLite persistence (SQLAlchemy)
│   ├── models.py     # Result schema
│   └── db.py         # engine/session handling
├── tests/            # smoke tests (no API key needed)
└── docs/methodology.md
```

## Setup

Requires Python 3.11+.

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# edit .env and set ANTHROPIC_API_KEY
```

## Running

```bash
python runner/run.py --target anthropic --model claude-haiku-4-5
```

Options:

| Flag           | Default                          | Meaning                          |
| -------------- | -------------------------------- | -------------------------------- |
| `--target`     | `anthropic`                      | Target provider                  |
| `--model`      | provider default / env           | Model id to test                 |
| `--db`         | `sentinel.db` / env              | SQLite output path               |
| `--max-tokens` | `1024` / env                     | Max tokens per model response    |

Defaults can also come from `.env` (`SENTINEL_TARGET_MODEL`,
`SENTINEL_DB_PATH`, `SENTINEL_MAX_TOKENS`).

The runner loops the full corpus, calls the target once per attack (threading
all turns for multi-turn attacks), retries transient API errors with
exponential backoff, and never lets one failure abort the run. It prints a
summary at the end: attacks run, errors, and the database path.

## Inspecting results

```bash
sqlite3 sentinel.db "SELECT attack_id, category, turn_count, error IS NOT NULL AS failed FROM results;"
```

Each row holds `attack_id`, `category`, `prompt`, full `response`,
`target_model`, `turn_count`, `error` (null on success), and `timestamp`.

## Extending

- **New attacks:** add `Attack(...)` entries in `attacks/corpus.py`. Multi-turn
  attacks set `turns=[...]`; single-turn attacks set `prompt=...`.
- **New categories:** add a member to `AttackCategory` in
  `attacks/categories.py` (append — don't rename existing values, which are
  persisted).
- **New target models:** implement `TargetClient` (see `runner/base_client.py`)
  and register it in `build_client()` in `runner/run.py`. No runner changes
  needed.

## Tests

```bash
python -m pytest tests/ -v
```

Tests use a fake in-memory client, so they run without an API key or network.

## Note on the corpus

The prompts in `attacks/corpus.py` are adversarial by design — they reference
publicly documented jailbreak and injection techniques so a defender can
measure whether their model refuses appropriately. This is a defensive
guardrail-evaluation tool.
