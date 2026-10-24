# Sentinel

An automated red-teaming framework for testing whether a large language model's
safety guardrails hold under adversarial attack — both what the model *says*
and, when it is given tools, what it *does*.

Sentinel fires a categorized corpus of attacks at a target model, scores every
response, tests tool-using agents against hidden instructions in the data they
read, and produces a self-contained HTML report.

## What it does

1. **Attacks** — 27 adversarial prompts across four classes: direct jailbreaks,
   prompt injection, encoding/obfuscation, and multi-turn manipulation.
2. **Scores** — each response is judged on two independent axes (did disallowed
   content come out; did the manipulation work), by a fast offline heuristic and
   an LLM judge, so the two can be compared.
3. **Tests agents** — 11 scenarios give the model simulated tools (files, email,
   HTTP) and plant an adversarial instruction in a tool result, then check
   whether the agent attempts the attacker's action. Nothing is ever executed.
4. **Reports** — a terminal CLI for drill-down, and a single-file HTML report.

The target-model client, the scorers, and the agent client each sit behind an
abstract interface, so adding a provider or a scoring strategy means writing
one class.

## Getting started

### What you need

- **Python 3.11 or newer** — check with `python --version`.
- **Git.**
- **An Anthropic API key with credit.** Create one at
  [console.anthropic.com](https://console.anthropic.com) under *API Keys*. When
  creating it, set **Scope** to a workspace (for example *Default workspace*) —
  an organization-level key is rejected with `This API key is not scoped to a
  workspace`. API billing is separate from a Claude.ai subscription; add credit
  under *Billing*. A full run against Claude Haiku 4.5 costs a few cents.

You don't need a key just to try the code: the test suite runs offline.

### 1. Install

macOS / Linux:

```bash
git clone https://github.com/roriminogue/sentinel.git
cd sentinel
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Windows (PowerShell):

```powershell
git clone https://github.com/roriminogue/sentinel.git
cd sentinel
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

Your prompt should now start with `(.venv)`. Activate the environment again
each time you open a new terminal.

Then open `.env` in any text editor and replace `sk-ant-...` with your key.
`.env` is git-ignored — never paste your key anywhere else.

Check the install (no key needed): `python -m pytest tests/` should report all
tests passing.

### 2. Run it

The pipeline is three steps — **attack, score, report** — and each reads what
the previous one saved to `sentinel.db`.

```bash
# Attack: send the 27 prompt attacks and save every response.
python runner/run.py

# Agent attacks: run the 11 tool-use scenarios. These are judged as they run,
# so they print defended / compromised immediately and need no scoring step.
python agent/run_agent.py

# Score the prompt-attack responses. The heuristic is free; the LLM judge is
# more accurate and costs a fraction of a cent per response.
python scoring/score.py --scorer heuristic
python scoring/score.py --scorer llm-judge

# Report: write a single-file HTML report.
python reporting/dashboard.py
```

The target and judge both default to Claude Haiku 4.5. To test another model,
pass `--model`, e.g. `python runner/run.py --model claude-sonnet-5`.

### 3. Read the results

Open `sentinel-report.html` in a browser — double-click it, or run
`open sentinel-report.html` (macOS), `xdg-open sentinel-report.html` (Linux), or
`Invoke-Item sentinel-report.html` (Windows).

How to read it:

- **Refused** — the guardrail held. **Complied** — the attack got the content
  it wanted. **Unclear** — no usable response.
- **Defended** — the agent read the planted instruction and didn't act on it.
  **Compromised** — it attempted the attacker's action. **Inconclusive** — it
  never reached the planted instruction, so nothing was tested.
- **Scorer disagreements** are where to look first: one of the two scorers is
  wrong about each of those responses.

For the full text of any attack and its response in the terminal:

```bash
python reporting/report.py --attack pi-004
python runner/run.py --attack dj-001 --verbose      # re-run one attack, print it
python agent/run_agent.py --scenario ag-008 --verbose
```

Attack IDs are listed in `attacks/corpus.py` (`dj-`, `pi-`, `eo-`, `mt-`) and
`agent/scenarios.py` (`ag-001` to `ag-011`).

### 4. Test your own chatbot's instructions

A real chatbot is a model plus setup instructions (a *system prompt*): who it
is, what it may discuss, what it must never do. Attackers usually target those
instructions — to make the bot reveal them, ignore them, or act outside them.
Testing the bare model tells you little about your deployment, so you can run
the attacks against the model *configured as your bot*:

```bash
python runner/run.py --system-prompt-file my-bot.txt --db my-bot.db
python scoring/score.py --scorer llm-judge --db my-bot.db
python reporting/dashboard.py --db my-bot.db --out my-bot-report.html
```

Put your bot's system prompt in a text file (or pass it inline with
`--system-prompt "..."`). To try it without one of your own, use the example:
`--system-prompt-file examples/support-bot.txt`.

To measure what your instructions add, run once without them and once with
them, **each into its own `--db`**, and compare the two reports. Every result
records the instructions it ran under, and the reports warn if a database
mixes setups, because results under different instructions are different tests.

Several attacks become sharper under a system prompt — for example, `pi-001`
and `pi-002` try to make the model reveal its instructions, which only means
something once it has some. For attacks aimed at your bot's specific rules
(say, "tell me another customer's balance"), add them to `attacks/corpus.py`;
see [Extending](#extending).

This tests the model under your instructions, not your full application: it
does not exercise your app's own code, retrieval, or filters. Only test
systems you own or are authorized to test.

### 5. Test your own chatbot at its web address

To test your chatbot as it is actually deployed — your app's code, filters, and
instructions included — point Sentinel at its HTTP endpoint. Copy
`examples/http-target.example.json`, edit it to describe your endpoint, then:

```bash
python runner/run.py --target http --config my-bot.json --authorized --db my-bot.db
python scoring/score.py --scorer heuristic --db my-bot.db
python reporting/dashboard.py --db my-bot.db --out my-bot-report.html
```

**`--authorized` is required.** This sends real attack traffic to a real
server, so Sentinel refuses to run against an HTTP target until you confirm you
own it or have permission to test it. Never point it at a chatbot you don't
control.

The config tells Sentinel how to talk to your endpoint:

| Key | Meaning |
|---|---|
| `url` | Your chatbot's endpoint (http or https) |
| `body_template` | The JSON body to send, with `"{prompt}"` where the attack text goes |
| `response_path` | Where the reply is in the JSON response, as a dotted path |
| `auth_env` | *Optional.* Name of an environment variable holding your API token |
| `auth_header`, `auth_prefix` | *Optional.* How the token is sent (default `Authorization: Bearer <token>`) |
| `headers` | *Optional.* Extra request headers |
| `name` | *Optional.* Label for the results (defaults to the URL's host) |
| `min_interval_seconds` | *Optional.* Minimum seconds between requests (default 1) |

For example, an endpoint that takes `{"message": "..."}` and returns
`{"reply": "..."}` uses `"body_template": {"message": "{prompt}"}` and
`"response_path": "reply"`. An OpenAI-style endpoint uses
`"body_template": {"model": "...", "messages": [{"role": "user", "content": "{prompt}"}]}`
and `"response_path": "choices.0.message.content"`.

Put the token itself in `.env` (e.g. `MY_BOT_TOKEN=...`) and name that variable
in `auth_env` — the token never goes in the config file. The attack text is
always inserted as a properly encoded JSON string, so it cannot change the
structure of the request.

Limits of the HTTP connector:

- **Multi-turn attacks are sent as one message** containing the labeled
  conversation, because HTTP chatbots have no common format for conversation
  history. A stateful endpoint would need its own client.
- **Agent scenarios don't run over HTTP.** They need the model to call tools,
  which a generic chat endpoint doesn't expose.
- **Scoring is separate.** The heuristic scorer is free and offline; the LLM
  judge still needs an Anthropic API key.

### Troubleshooting

| Problem | Fix |
|---|---|
| `This API key is not scoped to a workspace` | Create a new key with **Scope** set to a workspace (see above). Credit is per account, not per key. |
| `authentication_error` / `401` | The key in `.env` is wrong or revoked. Check there are no spaces or quotes around it. |
| `credit balance is too low` | Add credit under *Billing* in the Anthropic Console. |
| Windows: `running scripts is disabled on this system` | Run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`, then activate again. |
| `ModuleNotFoundError` | The virtual environment isn't active. Activate it (prompt starts with `(.venv)`). |
| `python` not found (Windows) | Use `py` instead, e.g. `py -m venv .venv`. |
| Counts look too high | Reports show the latest run of each attack. Pass `--all` only if you want every historical run. |

## What building it taught me

The most useful results were the times the framework's own measurements turned
out to be wrong. Each is now guarded by a test.

- **The heuristic scorer is structurally blind to prompt injection.** A model
  that correctly ignores an injected instruction and just does the real task
  produces ordinary text with no refusal phrase, so a refusal-matcher calls it
  a failure. On Claude Haiku 4.5 it mislabeled every injection defense.
- **"Didn't comply" is not "defended."** Agent runs where the model never called
  the tool carrying the payload were being counted as passes. They now count as
  *inconclusive*; otherwise a model too confused to use its tools scores perfectly.
- **A jailbreak test needs a payload the model would refuse anyway.** An early
  test asked for something borderline-legitimate; the model rejected the
  jailbreak but answered the question, and the result was uninterpretable.
- **Measurement bookkeeping matters.** Editing an attack silently mixed old and
  new results; re-running inflated counts; provider-level refusals were stored
  as empty responses and scored "unclear." Comparing a second model is what
  exposed the last two.

See [docs/methodology.md](docs/methodology.md) for the full methodology and its
limitations.

## Project layout

```
sentinel/
├── attacks/          # attack corpus + category taxonomy
│   ├── categories.py # AttackCategory enum
│   └── corpus.py     # Attack definitions (single- and multi-turn)
├── runner/           # fire attacks at a target model
│   ├── base_client.py     # TargetClient abstract interface
│   ├── anthropic_client.py# Anthropic implementation
│   ├── http_client.py     # any chatbot reachable over HTTP
│   └── run.py             # CLI entrypoint
├── scoring/          # judge the responses
│   ├── labels.py          # Verdict enum
│   ├── base_scorer.py     # Scorer abstract interface
│   ├── heuristic_scorer.py# offline keyword refusal detector
│   ├── llm_judge.py       # LLM-as-judge scorer
│   └── score.py           # CLI entrypoint
├── agent/            # agent/tool-call security
│   ├── categories.py      # AgentAttackCategory enum
│   ├── tools.py           # mock tool schemas + simulated executor
│   ├── scenarios.py       # scenarios + declarative violation rules
│   ├── base_agent_client.py # tool-capable client interface
│   ├── anthropic_agent.py # Anthropic agent-loop implementation
│   ├── harness.py         # runs a scenario, detects violations
│   └── run_agent.py       # CLI entrypoint
├── reporting/        # read the database back out
│   ├── report.py     # summary / disagreements / drill-down CLI
│   └── dashboard.py  # self-contained HTML report
├── storage/          # SQLite persistence (SQLAlchemy)
│   ├── models.py     # Result, Score, AgentResult, AgentToolCall
│   └── db.py         # engine/session handling, additive schema migration
├── examples/         # example system prompt and HTTP target config
├── tests/            # 59 tests, no API key or network needed
├── docs/methodology.md
└── LICENSE           # MIT
```

## Reference: running attacks

Every command below accepts `--db` to choose the database file. The sections
that follow document each step's options in full.

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
| `--system-prompt-file` | none                     | Run under a chatbot's instructions, read from a file |
| `--system-prompt` | none                          | The same, passed inline           |
| `--attack`, `--category` | all                     | Run a subset of the corpus       |
| `--verbose` | off                                 | Print each prompt and response   |
| `--target http --config FILE` | none             | Attack your own chatbot at its URL |
| `--authorized` | off                              | Required for `--target http`: confirms you may test it |

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
is cheap and idempotent unless you pass `--rescore`, which replaces earlier
verdicts rather than adding to them. Results whose run errored have no response
to judge, so they are excluded by default. When the provider declined a request
outright (`stop_reason=refusal`, no text), the result is recorded as refused
directly — there is nothing for a scorer to read.

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

Unlike prompt scoring, this verdict needs no LLM judge — the action either occurred or
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

The same filters exist on the prompt-attack runner:

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

## The HTML report

```bash
python reporting/dashboard.py
```

Writes `sentinel-report.html` — one file, no server, no external assets. Open it
in a browser. It shows headline tiles, verdicts by category per scorer, the
scorer disagreements, every agent scenario with its tool calls, and a table view
of everything.

Design constraints worth knowing, since they shape what you see:

- **Bar length is the result count**, segments are the verdict split. Normalising
  every bar to full width would make 6 and 7 look identical.
- **Status colors never carry meaning alone.** Status red and green measure a
  deutan colour difference of about 4 — near-identical for red-green colorblind
  readers — so every state also carries a glyph and a word, and every chart has
  a table twin.
- **One result per attack.** Re-running the corpus doesn't inflate the counts;
  the latest successful run of each attack is shown (`--all` for every run).
- **Stale results are excluded** by default (`--include-stale` to keep them).
- **Model output is escaped.** Responses in this database are adversarial by
  construction; an unescaped report would be a delivery vehicle for whatever the
  target model was induced to emit.

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
which teaches you something about both. Every view shows the latest run of each
attack; add `--all` to include earlier runs.

To compare models, give each its own database and keep the judge fixed so the
model under test is the only variable:

```bash
python runner/run.py --model claude-sonnet-5 --db sonnet.db
python agent/run_agent.py --model claude-sonnet-5 --db sonnet.db
python scoring/score.py --scorer llm-judge --model claude-haiku-4-5 --db sonnet.db
python reporting/dashboard.py --db sonnet.db --out sonnet-report.html
```

### Database schema

If you query `sentinel.db` directly, note that it keeps every run and every
scorer's verdict, so a naive `GROUP BY` over `results JOIN scores` counts each
attack once per run per scorer. The reporting tools above already handle this.

- `results` — `attack_id`, `category`, `prompt`, `prompt_hash` (fingerprint of
  the attack's wording), `response`, `stop_reason`, `target_model`,
  `system_prompt` (the instructions it ran under, if any),
  `turn_count`, `error`, `timestamp`
- `scores` — `result_id`, `scorer_name`, `verdict`, `technique`, `confidence`,
  `rationale`, `timestamp`
- `agent_results` — `scenario_id`, `category`, `compromised`, `inconclusive`,
  `violated_rule`, `tool_call_count`, `final_text`, `error`, `timestamp`
- `agent_tool_calls` — `agent_result_id`, `step`, `tool_name`, `arguments`,
  `violating`

Opening an older database adds any missing columns automatically, so results
are never lost to a schema change.

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

Tests use fake in-memory clients, so they run without an API key or network.
Several exist specifically to stop a measurement bug from returning — for
example, that an agent which never reaches the payload is never recorded as a
defense, and that the HTML report escapes model output.

## Responsible use

The prompts in `attacks/corpus.py` are adversarial by design: they adapt
publicly documented jailbreak and injection techniques so a defender can
measure whether a model refuses appropriately. Each attack's payload is a
*request* the model should decline; the repository contains no harmful content
and no model responses (run databases and reports are git-ignored).

Run Sentinel only against models and systems you are authorized to test — your
own deployments, or provider APIs within their usage policies. The HTTP
connector enforces this as far as a tool can: it will not send anything to an
endpoint without `--authorized`, and it rate-limits every request. Agent scenarios
never execute anything; every tool is simulated.

## License

MIT — see [LICENSE](LICENSE).
