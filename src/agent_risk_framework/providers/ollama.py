"""Ollama-backed providers for live local runs.

Local-only by construction: the base URL must resolve to a loopback host, so a
misconfigured manifest cannot send prompts (or canary data) off the machine.
HTTP goes through an injectable `transport`, which is how the tests exercise this
module without any network access.
"""

from __future__ import annotations

import http.client
import json
import math
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Sequence
from typing import Any
from urllib.parse import urlsplit

from .base import Completion, GenerationParams, Message, ProviderError

DEFAULT_BASE_URL = "http://127.0.0.1:11434"
DEFAULT_CHAT_MODEL = "llama3.1:8b"
FAST_CHAT_MODEL = "llama3.2:3b"
DEFAULT_EMBED_MODEL = "nomic-embed-text"

LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})

# (url, json_payload, timeout_s) -> parsed JSON response
Transport = Callable[[str, dict[str, Any], float], dict[str, Any]]


def require_loopback(base_url: str) -> str:
    """Validate and normalize a base URL, rejecting anything not on loopback."""
    parts = urlsplit(base_url)
    if parts.scheme not in {"http", "https"}:
        raise ValueError(f"unsupported scheme in {base_url!r}")
    # Userinfo, backslashes, and semicolons in the authority parse differently
    # across URL parsers; refuse them rather than guess which host wins.
    if any(c in parts.netloc for c in ("@", "\\", ";")):
        raise ValueError(f"refusing ambiguous authority in {base_url!r}")
    if parts.hostname not in LOOPBACK_HOSTS:
        raise ValueError(
            f"refusing non-loopback host {parts.hostname!r}; this lab is local-only "
            f"(allowed: {sorted(LOOPBACK_HOSTS)})"
        )
    return base_url.rstrip("/")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect could point off-machine; treat it as an error instead."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        raise urllib.error.HTTPError(req.full_url, code, f"redirect refused: {msg}", headers, fp)


# No proxies (HTTP_PROXY etc. could route loopback traffic elsewhere) and no redirects.
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


def urllib_transport(url: str, payload: dict[str, Any], timeout_s: float) -> dict[str, Any]:
    """POST JSON with the standard library. Only reached via a validated loopback URL."""
    require_loopback(url)
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(  # noqa: S310 - scheme and host checked by require_loopback
        url, data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with _OPENER.open(request, timeout=timeout_s) as response:
            return json.loads(response.read().decode("utf-8"))
    except (OSError, http.client.HTTPException, ValueError) as exc:
        # OSError covers URLError, timeouts, and connection resets; ValueError covers
        # JSONDecodeError and UnicodeDecodeError from a malformed body.
        raise ProviderError(f"Ollama request to {url} failed: {exc}") from exc


class _OllamaBase:
    name = "ollama"

    def __init__(
        self,
        model: str,
        base_url: str,
        timeout_s: float,
        transport: Transport | None,
    ) -> None:
        self.model = model
        self.base_url = require_loopback(base_url)
        self.timeout_s = timeout_s
        self._transport = transport or urllib_transport


class OllamaLLMProvider(_OllamaBase):
    def __init__(
        self,
        model: str = DEFAULT_CHAT_MODEL,
        *,
        base_url: str = DEFAULT_BASE_URL,
        timeout_s: float = 120.0,
        transport: Transport | None = None,
    ) -> None:
        super().__init__(model, base_url, timeout_s, transport)

    @classmethod
    def fast(cls, **kwargs: Any) -> OllamaLLMProvider:
        """The smaller model, for quick iteration."""
        return cls(model=FAST_CHAT_MODEL, **kwargs)

    def build_payload(
        self, messages: Sequence[Message], params: GenerationParams
    ) -> dict[str, Any]:
        options: dict[str, Any] = {"temperature": params.temperature}
        if params.seed is not None:
            options["seed"] = params.seed
        if params.max_tokens is not None:
            options["num_predict"] = params.max_tokens
        return {
            "model": self.model,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "stream": False,
            "options": options,
        }

    def complete(
        self, messages: Sequence[Message], params: GenerationParams | None = None
    ) -> Completion:
        if not messages:
            raise ValueError("messages must not be empty")
        params = params or GenerationParams()
        payload = self.build_payload(messages, params)
        start = time.perf_counter()
        data = self._transport(f"{self.base_url}/api/chat", payload, self.timeout_s)
        latency_ms = (time.perf_counter() - start) * 1000
        try:
            text = data["message"]["content"]
        except (KeyError, TypeError) as exc:
            raise ProviderError(f"malformed /api/chat response: missing {exc}") from exc
        if not isinstance(text, str):
            raise ProviderError("malformed /api/chat response: content is not a string")
        return Completion(text=text, model=self.model, latency_ms=latency_ms, raw=data)


class OllamaEmbeddingProvider(_OllamaBase):
    def __init__(
        self,
        model: str = DEFAULT_EMBED_MODEL,
        *,
        base_url: str = DEFAULT_BASE_URL,
        timeout_s: float = 60.0,
        transport: Transport | None = None,
    ) -> None:
        super().__init__(model, base_url, timeout_s, transport)

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        if isinstance(texts, str):
            raise TypeError("embed() takes a sequence of strings, not a single string")
        if not texts:
            return []
        payload = {"model": self.model, "input": list(texts)}
        data = self._transport(f"{self.base_url}/api/embed", payload, self.timeout_s)
        vectors = data.get("embeddings") if isinstance(data, dict) else None
        if not isinstance(vectors, list) or len(vectors) != len(texts):
            raise ProviderError("malformed /api/embed response: embedding count mismatch")
        return _validate_vectors(vectors)


def _validate_vectors(vectors: list[Any]) -> list[list[float]]:
    """Every vector must be a non-empty list of finite numbers, all the same length."""
    out: list[list[float]] = []
    for v in vectors:
        if not isinstance(v, list) or not v:
            raise ProviderError("malformed /api/embed response: vector is not a list")
        if not all(isinstance(x, int | float) and not isinstance(x, bool) for x in v):
            raise ProviderError("malformed /api/embed response: non-numeric value")
        row = [float(x) for x in v]
        if not all(math.isfinite(x) for x in row):
            raise ProviderError("malformed /api/embed response: non-finite value")
        out.append(row)
    if len({len(v) for v in out}) > 1:
        raise ProviderError("malformed /api/embed response: ragged vectors")
    return out
