"""Provider interfaces shared by the real (Ollama) and fake backends.

Everything above this layer talks to `LLMProvider` / `EmbeddingProvider` only, so
experiments can swap a live local model for the deterministic fake without
changing any other code.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

VALID_ROLES = frozenset({"system", "user", "assistant", "tool"})


class ProviderError(RuntimeError):
    """Raised when a provider cannot produce a usable response."""


@dataclass(frozen=True)
class Message:
    role: str
    content: str

    def __post_init__(self) -> None:
        if self.role not in VALID_ROLES:
            raise ValueError(f"invalid role {self.role!r}; expected one of {sorted(VALID_ROLES)}")


@dataclass(frozen=True)
class GenerationParams:
    temperature: float = 0.0
    seed: int | None = None
    max_tokens: int | None = None

    def __post_init__(self) -> None:
        if not math.isfinite(self.temperature) or self.temperature < 0:
            raise ValueError("temperature must be finite and >= 0")
        if self.max_tokens is not None and self.max_tokens < 1:
            raise ValueError("max_tokens must be >= 1")


@dataclass(frozen=True)
class Completion:
    text: str
    model: str
    latency_ms: float
    raw: dict[str, Any] = field(default_factory=dict, compare=False)


@runtime_checkable
class LLMProvider(Protocol):
    name: str
    model: str

    def complete(
        self, messages: Sequence[Message], params: GenerationParams | None = None
    ) -> Completion: ...


@runtime_checkable
class EmbeddingProvider(Protocol):
    name: str
    model: str

    def embed(self, texts: Sequence[str]) -> list[list[float]]: ...
