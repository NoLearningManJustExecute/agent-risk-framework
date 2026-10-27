"""LLM and embedding providers: one interface, real and fake backends."""

from .base import (
    Completion,
    EmbeddingProvider,
    GenerationParams,
    LLMProvider,
    Message,
    ProviderError,
)
from .fake import FakeEmbeddingProvider, FakeLLMProvider
from .ollama import (
    DEFAULT_CHAT_MODEL,
    DEFAULT_EMBED_MODEL,
    FAST_CHAT_MODEL,
    OllamaEmbeddingProvider,
    OllamaLLMProvider,
)

__all__ = [
    "DEFAULT_CHAT_MODEL",
    "DEFAULT_EMBED_MODEL",
    "FAST_CHAT_MODEL",
    "Completion",
    "EmbeddingProvider",
    "FakeEmbeddingProvider",
    "FakeLLMProvider",
    "GenerationParams",
    "LLMProvider",
    "Message",
    "OllamaEmbeddingProvider",
    "OllamaLLMProvider",
    "ProviderError",
]
