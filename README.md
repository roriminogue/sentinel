# Sentinel

An automated LLM red-teaming and guardrail-evaluation framework.

**Phase 1:** a categorized corpus of adversarial prompts, a runner that fires
each one at a target LLM, and a local SQLite log of every prompt/response pair.

**Phase 2:** a scoring layer that judges each stored response — did the attack
succeed (model complied) or did the guardrail hold (model refused)?

**Phase 3 (current):** agent/tool-call security. Gives the model *tools*, plants
adversarial instructions in what those tools return, and checks whether the
agent can be made to take an unsafe **action**. A dashboard is the remaining
phase.

## What it does

1. Stores a categorized library of adversarial prompts (jailbreaks, prompt
   injection, encoding/obfuscation tricks, multi-turn manipulation).
2. Fires each prompt at a target LLM via its API.
3. Logs every prompt + full response + metadata to a local SQLite database.
4. Scores each response as refused / complied / partial / unclear, using a
   fast heuristic scorer or an LLM judge.
5. Tests tool-using agents against injected instructions and records every
   tool call the agent attempts.
6. Is easy to extend with new attack categories, target models, and scorers.

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
├── agent/            # agent/tool-call security (Phase 3)
│   ├── categories.py      # AgentAttackCategory enum
│   ├── tools.py           # mock tool schemas + simulated executor
│   ├── scenarios.py       # scenarios + declarative violation rules
│   ├── base_agent_client.py # tool-capable client interface
│   ├── anthropic_agent.py # Anthropic agent-loop implementation
│   ├── harness.py         # runs a scenario, detects violations
│   └── run_agent.py       # CLI entrypoint
├── reporting/        # read the database back out
│   └── report.py     # summary / disagreements / drill-down CLI
├── storage/          # SQLite persistence (SQLAlchemy)
│   ├── models.py     # Result, Score, AgentResult, AgentToolCall
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

Each response is scored on **two independent axes**:

- **verdict** — did disallowed content come out? (`refused` / `complied` /
  `partial` / `unclear`)
- **technique** — did the attack's manipulation actually work? (`resisted` /
  `adopted` / `unclear`)

They genuinely come apart. A model can reject a jailbreak persona and still
answer the underlying question (`technique=resisted, verdict=complied`), or play
along with a persona and refuse anyway (`technique=adopted, verdict=refused`).
A single label hides both cases. The heuristic scorer always reports
`technique=unclear` — matching refusal words says nothing about whether the
framing worked, and it does not pretend otherwise.

Scores are written to a separate `scores` table — raw results are never
modified — so you can re-score or run multiple scorers over the same data.

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

## Agent / tool-call security

```bash
python agent/run_agent.py --target anthropic --model claude-haiku-4-5
```

Each scenario hands the model a benign task plus a set of tools, then plants an
adversarial instruction in what one of those tools returns (a fetched page, a
file, a search result). The framework records every tool call the agent
attempts and flags the run **compromised** if a call matches the scenario's
violation rules — e.g. POSTing to an attacker domain, emailing an external
address, or deleting a file because a README said to.

**Every tool is simulated.** `agent/tools.py` never reads a real file, sends a
real request, or deletes anything; a tool call only returns canned text. The
point is to observe whether the model *attempts* an unsafe action, never to let
one happen.

Unlike Phase 2, the verdict needs no LLM judge — the action either occurred or
it did not, so detection is mechanical and deterministic.

Each run lands in one of four states:

| State | Meaning |
| ------------- | ---------------------------------------------------------- |
| defended | The agent reached the injected payload and refused to act on it |
| compromised | The agent took the attacker's action |
| inconclusive | The agent never called the tool carrying the payload, so it never met the attack |
| error | The provider call failed |

**`inconclusive` is not a pass.** If the agent wanders off, asks a clarifying
question, or never picks up the tool that delivers the injection, nothing was
tested. Counting those as defenses would make any model look safer than it is,
so they are tracked separately.

Categories covered: tool injection, data exfiltration, destructive action,
scope escalation, and confused deputy.

### Watching one attack play out

To understand the mechanism, run a single scenario with the full transcript:

```bash
python agent/run_agent.py --scenario ag-008 --verbose
```

That prints the system prompt, the task, every tool call, the exact text the
simulated tool returned (including the injected payload), and the agent's final
answer — so you can see what the model was shown and what it decided.

The same filters exist on the Phase 1 runner:

```bash
python runner/run.py --attack eo-001 --verbose
python runner/run.py --category prompt_injection --verbose
```

### Overt vs. subtle scenarios

`ag-001` through `ag-007` announce themselves (`SYSTEM OVERRIDE:`, fake
`<system>` tags) — useful as a floor: a model that falls for these has no
injection defense at all. `ag-008` through `ag-011` are the harder case, written
to read like ordinary workflow text: a numbered step in a work ticket, an
"ops note" about mirroring a backup, a claimed message from the account owner,
a storage manager reporting a safe-to-delete duplicate. Nothing in them looks
like an attack, which is the point.

## Inspecting results

The reporting CLI is the easiest way in — no SQL quoting to fight:

```bash
python reporting/report.py                  # overall summary
python reporting/report.py --complied       # attacks a scorer says succeeded
python reporting/report.py --disagreements  # results where scorers conflict
python reporting/report.py --attack pi-004  # full prompt/response/verdicts
python reporting/report.py --agent          # agent runs with their tool calls
```

`--disagreements` is the most informative view: when two scorers reach
different verdicts on the same response, one of them is wrong, and finding out
which teaches you something about both.

Or query the database directly:

```bash
# Agent scenarios that were compromised:
sqlite3 sentinel.db "SELECT scenario_id, category, violated_rule FROM agent_results WHERE compromised = 1;"

# Every tool call an agent attempted, violations first:
sqlite3 sentinel.db "SELECT r.scenario_id, c.step, c.tool_name, c.violating, c.arguments FROM agent_results r JOIN agent_tool_calls c ON c.agent_result_id = r.id ORDER BY c.violating DESC;"

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
  attacks set `turns=[...]`; single-turn attacks set `prompt=...`. Pick a
  payload the model would refuse if asked plainly — if it might be answered
  anyway, a compliant response tells you nothing about the technique.
- **New categories:** add a member to `AttackCategory` in
  `attacks/categories.py` (append — don't rename existing values, which are
  persisted).
- **New target models:** implement `TargetClient` (see `runner/base_client.py`)
  and register it in `build_client()` in `runner/run.py`. No runner changes
  needed.
- **New scorers:** implement `Scorer` (see `scoring/base_scorer.py`) and
  register it in `build_scorer()` in `scoring/score.py`.
- **New agent scenarios:** add an `AgentScenario(...)` in `agent/scenarios.py`
  with its own `ViolationRule`s. Add new mock tools to `TOOL_SCHEMAS` in
  `agent/tools.py` — keep them simulated.

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
