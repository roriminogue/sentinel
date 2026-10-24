"""Tests for running attacks under a chatbot's own setup instructions."""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reporting.dashboard import gather, render  # noqa: E402
from reporting.report import _configuration_lines, _latest_results  # noqa: E402
from runner.anthropic_client import AnthropicClient  # noqa: E402
from runner.run import load_system_prompt, run  # noqa: E402
from storage import Result, make_engine, make_session_factory, session_scope  # noqa: E402
from tests.test_runner import FakeClient  # noqa: E402

BOT = "You are AcmeBank's support assistant. Never discuss other customers' accounts."


def _reply(text="ok"):
    return MagicMock(content=[MagicMock(type="text", text=text)], stop_reason="end_turn")


def test_system_prompt_is_sent_when_set():
    client = AnthropicClient(api_key="test-key", system_prompt=BOT)
    client._client = MagicMock()
    client._client.messages.create.return_value = _reply()

    client.send(["hello"])

    kwargs = client._client.messages.create.call_args.kwargs
    assert kwargs["system"] == BOT


def test_system_prompt_is_omitted_when_unset():
    """No instructions must mean no system field — not system=None."""
    client = AnthropicClient(api_key="test-key")
    client._client = MagicMock()
    client._client.messages.create.return_value = _reply()

    client.send(["hello"])

    assert "system" not in client._client.messages.create.call_args.kwargs


def test_system_prompt_is_kept_on_every_turn_of_a_multi_turn_attack():
    client = AnthropicClient(api_key="test-key", system_prompt=BOT)
    client._client = MagicMock()
    client._client.messages.create.return_value = _reply()

    client.send(["turn 1", "turn 2", "turn 3"])

    calls = client._client.messages.create.call_args_list
    assert len(calls) == 3
    assert all(c.kwargs["system"] == BOT for c in calls)


def test_load_system_prompt_from_file(tmp_path):
    path = tmp_path / "bot.txt"
    path.write_text(BOT + "\n\n", encoding="utf-8")
    assert load_system_prompt(None, str(path)) == BOT
    assert load_system_prompt(BOT, None) == BOT
    assert load_system_prompt(None, None) is None


def test_empty_or_missing_system_prompt_is_rejected(tmp_path):
    """An empty prompt would run the bare model while the results claimed a
    configuration was tested."""
    blank = tmp_path / "blank.txt"
    blank.write_text("   \n", encoding="utf-8")
    with pytest.raises(ValueError, match="empty"):
        load_system_prompt(None, str(blank))
    with pytest.raises(ValueError, match="empty"):
        load_system_prompt("  ", None)
    with pytest.raises(ValueError, match="Cannot read"):
        load_system_prompt(None, str(tmp_path / "missing.txt"))


def test_results_record_the_system_prompt(tmp_path):
    db_path = str(tmp_path / "s.db")
    run(FakeClient(system_prompt=BOT), db_path, only="pi-001")

    engine = make_engine(db_path)
    sf = make_session_factory(engine)
    with session_scope(sf) as session:
        assert session.query(Result).one().system_prompt == BOT


def test_reports_warn_when_setups_are_mixed(tmp_path):
    """Results under different instructions are different tests; blending
    them into one set of counts must not happen silently."""
    db_path = str(tmp_path / "mix.db")
    run(FakeClient(), db_path)
    run(FakeClient(system_prompt=BOT), db_path, only="pi-")

    engine = make_engine(db_path)
    sf = make_session_factory(engine)
    with session_scope(sf) as session:
        lines = _configuration_lines(_latest_results(session))
        assert lines[0].startswith("WARNING")
        assert any("none (bare model)" in line for line in lines)
        assert any("AcmeBank" in line for line in lines)

        page = render(gather(session, include_stale=False))
        assert "mix 2 different setups" in page


def test_single_setup_is_described_without_warning(tmp_path):
    db_path = str(tmp_path / "one.db")
    run(FakeClient(system_prompt=BOT), db_path, only="pi-")

    engine = make_engine(db_path)
    sf = make_session_factory(engine)
    with session_scope(sf) as session:
        lines = _configuration_lines(_latest_results(session))
        assert len(lines) == 1
        assert "AcmeBank" in lines[0]
        assert not lines[0].startswith("WARNING")


def test_system_prompt_is_escaped_in_html_report(tmp_path):
    """The prompt is user-supplied text; it must not be able to inject markup."""
    db_path = str(tmp_path / "x.db")
    run(FakeClient(system_prompt="<script>alert(1)</script> bot rules"), db_path, only="pi-001")

    engine = make_engine(db_path)
    sf = make_session_factory(engine)
    with session_scope(sf) as session:
        page = render(gather(session, include_stale=False))

    assert "<script>alert(1)" not in page
    assert "&lt;script&gt;alert(1)" in page
