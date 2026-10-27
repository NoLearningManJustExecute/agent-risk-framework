"""Deterministic fake providers for offline tests and dry runs.

No model, no network, no randomness: the same inputs always give the same
outputs, which keeps CI reproducible on every OS.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections import deque
from collections.abc import Iterable, Sequence

from .base import Completion, GenerationParams, Message

_TOKEN_RE = re.compile(r"[a-z0-9]+")


class FakeLLMProvider:
    """Scriptable stand-in for a chat model.

    Response priority:
      1. `script`: queued responses, returned in order (one per call).
      2. `rules`: (trigger, response) pairs; the first trigger found anywhere in the
         conversation wins. Matching all messages, not just the last user turn, lets
         tests simulate a model hijacked by injected tool output.
      3. `default`, if given.
      4. Otherwise a stable digest of the conversation and seed.

    Every call is recorded in `calls` so tests can assert on what was sent.
    """

    name = "fake"

    def __init__(
        self,
        model: str = "fake-llm",
        *,
        rules: Iterable[tuple[str, str]] = (),
        script: Iterable[str] = (),
        default: str | None = None,
    ) -> None:
        self.model = model
        self.rules = list(rules)
        self.default = default
        self._script: deque[str] = deque(script)
        self.calls: list[tuple[tuple[Message, ...], GenerationParams]] = []

    def complete(
        self, messages: Sequence[Message], params: GenerationParams | None = None
    ) -> Completion:
        msgs = tuple(messages)
        if not msgs:
            raise ValueError("messages must not be empty")
        params = params or GenerationParams()
        self.calls.append((msgs, params))
        return Completion(text=self._respond(msgs, params), model=self.model, latency_ms=0.0)

    def _respond(self, msgs: tuple[Message, ...], params: GenerationParams) -> str:
        if self._script:
            return self._script.popleft()
        conversation = "\n".join(m.content for m in msgs)
        for trigger, response in self.rules:
            if trigger in conversation:
                return response
        if self.default is not None:
            return self.default
        material = f"{params.seed}|" + "|".join(f"{m.role}:{m.content}" for m in msgs)
        digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
        return f"fake-response-{digest}"


class FakeEmbeddingProvider:
    """Hashed bag-of-words embeddings.

    Texts that share words get similar vectors, so retrieval-style tests behave
    sensibly, while staying fully deterministic. Vectors are L2-normalized; text
    with no word tokens maps to the zero vector.
    """

    name = "fake"

    def __init__(self, model: str = "fake-embed", dimensions: int = 64) -> None:
        if dimensions < 1:
            raise ValueError("dimensions must be >= 1")
        self.model = model
        self.dimensions = dimensions

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        if isinstance(texts, str):
            raise TypeError("embed() takes a sequence of strings, not a single string")
        return [self._embed_one(t) for t in texts]

    def _embed_one(self, text: str) -> list[float]:
        vec = [0.0] * self.dimensions
        for token in _TOKEN_RE.findall(text.lower()):
            h = int.from_bytes(hashlib.sha256(token.encode("utf-8")).digest()[:8], "big")
            sign = 1.0 if (h >> 63) & 1 else -1.0
            vec[h % self.dimensions] += sign
        norm = math.sqrt(sum(v * v for v in vec))
        return vec if norm == 0 else [v / norm for v in vec]
