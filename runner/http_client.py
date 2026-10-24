"""Generic HTTP target client.

Points Sentinel at a chatbot you run yourself, reached over HTTP. A small JSON
config describes how to talk to it — the URL, how to put the attack text into
the request body, and where the reply is in the response — so one connector
works with almost any endpoint without knowing what is behind it.

Safety rails (this sends real traffic to a real server):
- The runner requires an explicit --authorized flag before it will use this
  client. Only test systems you own or are permitted to test.
- Requests are rate limited (a minimum interval between them) so a run cannot
  flood the target.
- The auth token is read from an environment variable named in the config,
  never stored in the config file itself.
- Only http/https URLs are accepted.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

from .base_client import TargetClient, TargetReply

DEFAULT_MIN_INTERVAL = 1.0  # seconds between requests
DEFAULT_TIMEOUT = 30.0
PROMPT_PLACEHOLDER = "{prompt}"

# transport(url, method, headers, body) -> (status_code, response_bytes).
# Injectable so tests never touch the network.
Transport = Callable[[str, str, Dict[str, str], bytes], "tuple[int, bytes]"]


@dataclass(frozen=True)
class HTTPTargetConfig:
    url: str
    response_path: str
    name: Optional[str] = None
    method: str = "POST"
    headers: Dict[str, str] = field(default_factory=dict)
    body_template: Any = field(default_factory=lambda: {"message": PROMPT_PLACEHOLDER})
    auth_env: Optional[str] = None
    auth_header: str = "Authorization"
    auth_prefix: str = "Bearer "
    min_interval_seconds: float = DEFAULT_MIN_INTERVAL

    def __post_init__(self) -> None:
        scheme = urlparse(self.url).scheme
        if scheme not in ("http", "https"):
            raise ValueError(
                f"Target url must be http(s), got {self.url!r}."
            )
        if PROMPT_PLACEHOLDER not in json.dumps(self.body_template):
            raise ValueError(
                f"body_template must contain {PROMPT_PLACEHOLDER!r} so the "
                "attack text can be inserted."
            )
        if not self.response_path:
            raise ValueError("response_path is required (where the reply is).")


def load_http_config(path: str) -> HTTPTargetConfig:
    """Read and validate an HTTP target config file."""
    try:
        with open(path, encoding="utf-8") as handle:
            raw = json.load(handle)
    except OSError as exc:
        raise ValueError(f"Cannot read target config {path!r}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"Target config {path!r} is not valid JSON: {exc}") from exc

    known = set(HTTPTargetConfig.__dataclass_fields__)
    unknown = set(raw) - known
    if unknown:
        raise ValueError(
            f"Unknown key(s) in target config: {', '.join(sorted(unknown))}. "
            f"Allowed: {', '.join(sorted(known))}."
        )
    try:
        return HTTPTargetConfig(**raw)
    except TypeError as exc:
        raise ValueError(f"Invalid target config: {exc}") from exc


def _substitute(template: Any, prompt: str) -> Any:
    """Replace the prompt placeholder wherever it appears in the body template.

    The prompt is injected as a JSON string value, so it is always safely
    encoded — it can never alter the structure of the request body.
    """
    if isinstance(template, str):
        return template.replace(PROMPT_PLACEHOLDER, prompt)
    if isinstance(template, dict):
        return {k: _substitute(v, prompt) for k, v in template.items()}
    if isinstance(template, list):
        return [_substitute(v, prompt) for v in template]
    return template


def _extract(data: Any, path: str) -> str:
    """Follow a dotted path into a decoded JSON response (list indices allowed).

    e.g. "choices.0.message.content" for an OpenAI-style response, or "reply".
    """
    current = data
    for part in path.split("."):
        if isinstance(current, list):
            try:
                current = current[int(part)]
            except (ValueError, IndexError) as exc:
                raise ValueError(
                    f"response_path {path!r}: no index {part!r} in list."
                ) from exc
        elif isinstance(current, dict):
            if part not in current:
                raise ValueError(
                    f"response_path {path!r}: key {part!r} not in response "
                    f"(keys: {', '.join(map(str, current))})."
                )
            current = current[part]
        else:
            raise ValueError(
                f"response_path {path!r}: cannot descend into {type(current).__name__}."
            )
    if not isinstance(current, str):
        raise ValueError(
            f"response_path {path!r} pointed at a {type(current).__name__}, "
            "not the reply text."
        )
    return current


def _default_transport(
    url: str, method: str, headers: Dict[str, str], body: bytes
) -> "tuple[int, bytes]":
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=DEFAULT_TIMEOUT) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


class HTTPTargetClient(TargetClient):
    """Talks to a user-supplied chatbot endpoint over HTTP."""

    def __init__(
        self,
        config: HTTPTargetConfig,
        transport: Optional[Transport] = None,
        max_retries: int = 2,
        base_backoff: float = 2.0,
    ) -> None:
        self._config = config
        self._transport = transport or _default_transport
        self._max_retries = max_retries
        self._base_backoff = base_backoff
        self._last_request_at = 0.0

        self._auth_value: Optional[str] = None
        if config.auth_env:
            token = os.getenv(config.auth_env)
            if not token:
                raise ValueError(
                    f"Config names auth_env={config.auth_env!r} but that "
                    "environment variable is not set."
                )
            self._auth_value = f"{config.auth_prefix}{token}"

    @property
    def model(self) -> str:
        return self._config.name or urlparse(self._config.url).netloc or self._config.url

    def send(self, turns: List[str]) -> TargetReply:
        # A generic HTTP endpoint has no portable multi-turn protocol, so a
        # multi-turn attack is sent as one labeled transcript in a single
        # request. (See README — true multi-turn needs an endpoint-specific
        # client.)
        if len(turns) == 1:
            prompt = turns[0]
        else:
            prompt = "\n\n".join(
                f"[turn {i}] {t}" for i, t in enumerate(turns, start=1)
            )

        headers = {"Content-Type": "application/json", **self._config.headers}
        if self._auth_value:
            headers[self._config.auth_header] = self._auth_value
        body = json.dumps(_substitute(self._config.body_template, prompt)).encode("utf-8")

        status, raw = self._request_with_retry(headers, body)
        if status >= 400:
            snippet = raw[:200].decode("utf-8", "replace")
            raise RuntimeError(f"Target returned HTTP {status}: {snippet}")
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            snippet = raw[:200].decode("utf-8", "replace")
            raise RuntimeError(f"Target response was not JSON: {snippet}") from exc
        return TargetReply(text=_extract(data, self._config.response_path), stop_reason="end_turn")

    def _throttle(self) -> None:
        wait = self._config.min_interval_seconds - (time.monotonic() - self._last_request_at)
        if wait > 0:
            time.sleep(wait)
        self._last_request_at = time.monotonic()

    def _request_with_retry(
        self, headers: Dict[str, str], body: bytes
    ) -> "tuple[int, bytes]":
        attempt = 0
        while True:
            self._throttle()
            try:
                return self._transport(self._config.url, self._config.method, headers, body)
            except urllib.error.URLError as exc:
                if attempt >= self._max_retries:
                    raise RuntimeError(f"Could not reach target: {exc}") from exc
                time.sleep(self._base_backoff * (2**attempt))
                attempt += 1
