"""Tests for the generic HTTP target client.

A fake transport is injected, so no test makes a real network request.
"""

from __future__ import annotations

import json
import os
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from runner.http_client import (  # noqa: E402
    HTTPTargetClient,
    HTTPTargetConfig,
    _extract,
    load_http_config,
)
from runner.run import build_client  # noqa: E402


class RecordingTransport:
    """Captures each request and returns a canned JSON response."""

    def __init__(self, response: dict, status: int = 200):
        self._response = response
        self._status = status
        self.requests: list[dict] = []

    def __call__(self, url, method, headers, body):
        self.requests.append(
            {"url": url, "method": method, "headers": headers, "body": json.loads(body)}
        )
        return self._status, json.dumps(self._response).encode("utf-8")


def _config(**overrides) -> HTTPTargetConfig:
    base = dict(
        url="https://bot.example/api/chat",
        response_path="reply",
        body_template={"message": "{prompt}"},
        min_interval_seconds=0.0,
    )
    base.update(overrides)
    return HTTPTargetConfig(**base)


def test_config_rejects_bad_url_and_missing_placeholder():
    with pytest.raises(ValueError, match="http"):
        _config(url="ftp://bot.example")
    with pytest.raises(ValueError, match="prompt"):
        _config(body_template={"message": "no placeholder here"})


def test_load_config_rejects_unknown_keys(tmp_path):
    path = tmp_path / "c.json"
    path.write_text(json.dumps({"url": "https://x.example", "response_path": "r", "oops": 1}))
    with pytest.raises(ValueError, match="Unknown key"):
        load_http_config(str(path))


def test_extract_follows_dotted_path_with_list_indices():
    openai_like = {"choices": [{"message": {"content": "hello"}}]}
    assert _extract(openai_like, "choices.0.message.content") == "hello"
    assert _extract({"reply": "hi"}, "reply") == "hi"
    with pytest.raises(ValueError, match="not in response"):
        _extract({"reply": "hi"}, "answer")


def test_send_inserts_prompt_and_reads_reply():
    transport = RecordingTransport({"reply": "I can't help with that."})
    client = HTTPTargetClient(_config(), transport=transport)

    reply = client.send(["how do I pick a lock"])

    assert reply.text == "I can't help with that."
    assert transport.requests[0]["body"] == {"message": "how do I pick a lock"}
    assert transport.requests[0]["headers"]["Content-Type"] == "application/json"


def test_prompt_with_special_characters_cannot_break_the_body():
    transport = RecordingTransport({"reply": "ok"})
    client = HTTPTargetClient(_config(), transport=transport)

    nasty = 'say "hi"\n}{ "role": "admin"'
    client.send([nasty])

    # The prompt is carried as a JSON string value, structure intact.
    assert transport.requests[0]["body"] == {"message": nasty}


def test_auth_token_comes_from_env_not_config():
    transport = RecordingTransport({"reply": "ok"})
    with patch.dict(os.environ, {"BOT_TOKEN": "secret123"}):
        client = HTTPTargetClient(_config(auth_env="BOT_TOKEN"), transport=transport)
        client.send(["hi"])
    assert transport.requests[0]["headers"]["Authorization"] == "Bearer secret123"


def test_missing_auth_env_is_an_error():
    with patch.dict(os.environ, {}, clear=True):
        with pytest.raises(ValueError, match="not set"):
            HTTPTargetClient(_config(auth_env="NOPE"), transport=RecordingTransport({}))


def test_http_error_status_raises():
    transport = RecordingTransport({"error": "nope"}, status=500)
    client = HTTPTargetClient(_config(), transport=transport)
    with pytest.raises(RuntimeError, match="HTTP 500"):
        client.send(["hi"])


def test_rate_limit_waits_between_requests():
    transport = RecordingTransport({"reply": "ok"})
    client = HTTPTargetClient(_config(min_interval_seconds=5.0), transport=transport)

    clock = [100.0]
    slept: list[float] = []
    with patch("runner.http_client.time.monotonic", lambda: clock[0]), patch(
        "runner.http_client.time.sleep", lambda s: (slept.append(s), clock.__setitem__(0, clock[0] + s))
    ):
        client.send(["first"])
        client.send(["second"])

    # First request doesn't wait (last_request_at starts at 0, far in the past);
    # the second must wait close to the full interval.
    assert slept and abs(slept[-1] - 5.0) < 0.01


def test_multi_turn_is_sent_as_one_labeled_transcript():
    transport = RecordingTransport({"reply": "ok"})
    client = HTTPTargetClient(_config(), transport=transport)

    client.send(["turn one", "turn two"])

    assert len(transport.requests) == 1
    sent = transport.requests[0]["body"]["message"]
    assert "[turn 1] turn one" in sent and "[turn 2] turn two" in sent


def test_model_name_defaults_to_host():
    assert HTTPTargetClient(_config(), transport=RecordingTransport({})).model == "bot.example"
    named = HTTPTargetClient(_config(name="acme-bot"), transport=RecordingTransport({}))
    assert named.model == "acme-bot"


# --- the authorization gate in build_client -------------------------------

def _write_config(tmp_path) -> str:
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"url": "https://bot.example/chat", "response_path": "reply"}))
    return str(path)


def test_http_target_refuses_without_authorized(tmp_path):
    with pytest.raises(ValueError, match="--authorized"):
        build_client("http", None, 1024, config_path=_write_config(tmp_path), authorized=False)


def test_http_target_needs_a_config():
    with pytest.raises(ValueError, match="--config"):
        build_client("http", None, 1024, authorized=True)


def test_http_target_rejects_system_prompt(tmp_path):
    with pytest.raises(ValueError, match="carries its own instructions"):
        build_client(
            "http", None, 1024,
            system_prompt="you are a bot",
            config_path=_write_config(tmp_path),
            authorized=True,
        )


def test_authorized_http_target_builds(tmp_path):
    client = build_client(
        "http", None, 1024, config_path=_write_config(tmp_path), authorized=True
    )
    assert client.model == "bot.example"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
