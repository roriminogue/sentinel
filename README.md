# Sentinel

An automated LLM red-teaming and guardrail-evaluation framework.

**Phase 1:** a categorized corpus of adversarial prompts, a runner that fires
each one at a target LLM, and a local SQLite log of every prompt/response pair.

**Phase 2 (current):** a scoring layer that judges each stored response —
did the attack succeed (model complied) or did the guardrail hold (model
refused)? Agent/tool-call security and a dashboard are future phases.

## What it does

1. Stores a categorized library of adversarial prompts (jailbreaks, prompt
   injection, encoding/obfuscation tricks, multi-turn manipulation).
2. Fires each prompt at a target LLM via its API.
3. Logs every prompt + full response + metadata to a local SQLite database.
4. Scores each response as refused / complied / partial / unclear, using a
   fast heuristic scorer or an LLM judge.
5. Is easy to extend with new attack categories, target models, and scorers.

## Project layout

```
sentinel/
├── attacks/          # attack corpus + category taxonomy
│   ├── categories.py # AttackCategory enum
│   └── corpus.py     # Attack definitions (single- and multi-turn)
├── runner/           # fire attacks at a target model
│   ├── base_client.py     # TargetClient abstract interface
│   ├── anthropic_client.py# Anthropic implementation
│   └── run.py             # CLI entrypoint
├── scoring/          # judge the responses
│   ├── labels.py          # Verdict enum
│   ├── base_scorer.py     # Scorer abstract interface
│   ├── heuristic_scorer.py# offline keyword refusal detector
│   ├── llm_judge.py       # LLM-as-judge scorer
│   └── score.py           # CLI entrypoint
├── storage/          # SQLite persistence (SQLAlchemy)
│   ├── models.py     # Result + Score schema
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

## Scoring the results

Once a run has populated the database, score the responses:

```bash
# Fast, free, offline keyword-based refusal detection:
python scoring/score.py --scorer heuristic

# More accurate LLM judge (uses API credit, one call per result):
python scoring/score.py --scorer llm-judge --model claude-haiku-4-5
```

Each response is classified as **refused** (guardrail held), **complied**
(attack succeeded), **partial**, or **unclear**. Verdicts are written to a
separate `scores` table — raw results are never modified — so you can re-score
or run multiple scorers over the same data.

| Flag               | Default             | Meaning                                  |
| ------------------ | ------------------- | ---------------------------------------- |
| `--scorer`         | `heuristic`         | `heuristic` or `llm-judge`               |
| `--model`          | provider default    | Judge model (for `llm-judge`)            |
| `--db`             | `sentinel.db` / env | SQLite path                              |
| `--rescore`        | off                 | Re-score rows this scorer already scored |
| `--include-errors` | off                 | Also score rows whose run errored        |

The scorer skips results it has already scored (by scorer name), so re-running
is cheap and idempotent unless you pass `--rescore`. Results whose run errored
have no response to judge, so they are excluded by default.

### Reading the verdicts

A caveat worth knowing: the heuristic scorer only looks for refusal phrasing,
which makes it structurally blind to **prompt injection**. A model that
correctly ignores an injected instruction and just does the legitimate task
(summarizes the document, translates the sentence) produces normal-looking
text with no refusal — and the heuristic wrongly calls that "complied". For
injection categories, trust the LLM judge.

## Inspecting results

```bash
# Raw prompt/response pairs:
sqlite3 sentinel.db "SELECT attack_id, category, turn_count, error IS NOT NULL AS failed FROM results;"

# Results joined with their verdicts:
sqlite3 sentinel.db "SELECT r.attack_id, r.category, s.scorer_name, s.verdict FROM results r JOIN scores s ON s.result_id = r.id;"

# Attack success rate by category (lower 'complied' = stronger guardrails):
sqlite3 sentinel.db "SELECT r.category, s.verdict, COUNT(*) FROM results r JOIN scores s ON s.result_id = r.id GROUP BY r.category, s.verdict;"
```

`results` rows hold `attack_id`, `category`, `prompt`, full `response`,
`target_model`, `turn_count`, `error` (null on success), and `timestamp`.
`scores` rows hold `result_id`, `scorer_name`, `verdict`, `confidence`,
`rationale`, and `timestamp`.

## Extending

- **New attacks:** add `Attack(...)` entries in `attacks/corpus.py`. Multi-turn
  attacks set `turns=[...]`; single-turn attacks set `prompt=...`.
- **New categories:** add a member to `AttackCategory` in
  `attacks/categories.py` (append — don't rename existing values, which are
  persisted).
- **New target models:** implement `TargetClient` (see `runner/base_client.py`)
  and register it in `build_client()` in `runner/run.py`. No runner changes
  needed.
- **New scorers:** implement `Scorer` (see `scoring/base_scorer.py`) and
  register it in `build_scorer()` in `scoring/score.py`.

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
