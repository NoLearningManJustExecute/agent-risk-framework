"""Secret/PII egress filter (DLP): what leaves through tool arguments or tool output.

Two checks, both deterministic:

- **Outbound tool arguments.** Every string in a call's arguments (email `to`,
  `subject` and `body`, a search query, any argument of any tool, so a look-alike
  tool is covered too) is scanned before dispatch. A hit blocks the call.
- **Tool output.** A tool result is scanned before the model reads it. Each secret
  found in the raw text is replaced by a placeholder, `[REDACTED:<kind>:<fp>]`,
  where `fp` is the first 8 hex digits of the secret's SHA-256 (never the secret
  itself). A secret that is only visible after decoding (base64, hex, character
  spacing) cannot be cut out precisely, so the whole result is withheld instead.

What counts as a secret (the `kind` in a placeholder and in the decision log):

- `known_secret`: a value the deployment knows is secret: the system-prompt canary
  and every `key=value` value in the secret store (`secrets/`). Matched with the
  Phase 0 canary matcher, so case, spacing, punctuation, invisible characters and
  URL/HTML/base64/hex encodings do not hide it.
- `canary`: any `ARF-CANARY-<16 hex>` token, known or not.
- `api_key`: common provider key shapes (`AKIA...`, `ghp_...`, `xoxb-...`, `sk-...`,
  `AIza...`).
- `private_key`: a PEM private-key header.
- `jwt`: a three-part `eyJ...` token.
- `credential_assignment`: `password=`, `token:`, `api_key=` and similar, followed
  by a high-entropy value (12+ characters, letters and digits).
- `ssn`, `card_number`: a US SSN shape; a 13 to 19 digit card number that passes
  the Luhn check.

Scope, stated up front: the final answer to the user is not scanned (a leak to the
requester, AC04, is the input classifier's case), and a secret paraphrased into
words ("the token starts with A9C6…") gets through.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..agent.model import ToolCall
from ..agent.policy import RESTRICTED_PATHS, SYSTEM_CANARY
from ..scoring import CanaryLeakDetector, Observation
from .text import views

REDACTION_RE = re.compile(r"\[REDACTED:([a-z_]+):([0-9a-f]{8})\]")
_ASSIGNMENT_RE = re.compile(r"^\s*[\w.-]+\s*=\s*(\S+)\s*$")
_MIN_SECRET = 8

_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("canary", re.compile(r"\bARF-CANARY-[0-9A-F]{16}\b", re.IGNORECASE)),
    (
        "api_key",
        re.compile(
            r"\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,}|xox[abprs]-[A-Za-z0-9-]{10,}|"
            r"sk-[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{35})\b"
        ),
    ),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", re.IGNORECASE)),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    ),
    (
        "credential_assignment",
        re.compile(
            r"\b(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|"
            r"client[_-]?secret|service_token)\b\s*[:=]\s*['\"]?"
            r"((?=[A-Za-z0-9_\-+/=.]*\d)(?=[A-Za-z0-9_\-+/=.]*[A-Za-z])[A-Za-z0-9_\-+/=.]{12,})",
            re.IGNORECASE,
        ),
    ),
    ("ssn", re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")),
    ("card_number", re.compile(r"\b\d(?:[ -]?\d){12,18}\b")),
)


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]


def placeholder(kind: str, value: str) -> str:
    return f"[REDACTED:{kind}:{fingerprint(value)}]"


def _luhn(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


def _valid(kind: str, match: str) -> bool:
    if kind == "card_number":
        digits = re.sub(r"\D", "", match)
        return 13 <= len(digits) <= 19 and len(set(digits)) > 1 and _luhn(digits)
    return True


def secret_store_values(root: Path | str | None, restricted: Iterable[str] = RESTRICTED_PATHS):
    """Every `key=value` value (8+ characters) in the workspace's secret store."""
    if root is None:
        return ()
    found: list[str] = []
    for prefix in restricted:
        store = Path(root) / prefix
        if not store.is_dir():
            continue
        for path in sorted(p for p in store.rglob("*") if p.is_file()):
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            for line in text.splitlines():
                if line.lstrip().startswith("#"):
                    continue
                m = _ASSIGNMENT_RE.match(line)
                if m and len(m.group(1)) >= _MIN_SECRET:
                    found.append(m.group(1))
    return tuple(dict.fromkeys(found))


def _strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for k, v in value.items():
            yield from _strings(k)
            yield from _strings(v)
    elif isinstance(value, list | tuple):
        for item in value:
            yield from _strings(item)
    elif value is not None:
        yield str(value)


@dataclass(frozen=True)
class Redaction:
    text: str  # what the model may see
    hits: tuple[str, ...] = ()  # kinds found, in order, one per secret
    replacements: Mapping[str, str] = field(default_factory=dict)  # placeholder -> secret
    withheld: bool = False  # a secret was found only in a decoded view: nothing shown

    @property
    def changed(self) -> bool:
        return bool(self.hits)

    def reasons(self) -> tuple[str, ...]:
        if not self.hits:
            return ("no secret found",)
        if self.withheld:
            return (f"withheld: encoded secret ({', '.join(sorted(set(self.hits)))})",)
        return (f"redacted {len(self.replacements)} secret(s): {', '.join(self.replacements)}",)


class EgressFilter:
    """Scans outbound tool arguments and tool output for secrets and PII."""

    def __init__(self, known_secrets: Iterable[str] = (SYSTEM_CANARY,)) -> None:
        self.known = tuple(dict.fromkeys(s for s in known_secrets if len(s) >= _MIN_SECRET))
        self._detector = CanaryLeakDetector(self.known) if self.known else None

    @classmethod
    def for_workspace(
        cls,
        root: Path | str | None,
        *,
        restricted: Iterable[str] = RESTRICTED_PATHS,
        extra: Iterable[str] = (SYSTEM_CANARY,),
    ) -> EgressFilter:
        return cls((*extra, *secret_store_values(root, restricted)))

    def _known_hits(self, text: str) -> list[str]:
        if self._detector is None:
            return []
        found = self._detector.inspect(Observation(output=text)).reasons
        return [r.split(" found in ", 1)[0] for r in found]

    def kinds(self, text: str) -> list[str]:
        """Every kind of secret in `text`, over every normalized view."""
        kinds = ["known_secret"] if self._known_hits(text) else []
        all_views = [text, *views(text)]
        for kind, pattern in _PATTERNS:
            if any(_valid(kind, m.group(0)) for v in all_views for m in pattern.finditer(v)):
                kinds.append(kind)
        return kinds

    def arg_problems(self, call: ToolCall) -> list[str]:
        """Why this call's arguments may not leave (empty list: they may)."""
        strings = list(_strings(call.arguments)) or [call.raw_arguments]
        problems = []
        for kind in dict.fromkeys(k for s in strings for k in self.kinds(s)):
            problems.append(f"{call.name}: outbound argument carries a secret ({kind})")
        return problems

    def _raw_spans(self, text: str) -> list[tuple[int, int, str]]:
        spans: list[tuple[int, int, str]] = []
        folded = text.casefold()
        for secret in self.known:
            start = folded.find(secret.casefold())
            while start != -1:
                spans.append((start, start + len(secret), "known_secret"))
                start = folded.find(secret.casefold(), start + 1)
        for kind, pattern in _PATTERNS:
            # A pattern with a group redacts only the value, not the key name before it.
            group = 1 if pattern.groups else 0
            spans += [
                (*m.span(group), kind) for m in pattern.finditer(text) if _valid(kind, m.group(0))
            ]
        # Keep the longest span where two overlap (a canary inside a token assignment).
        spans.sort(key=lambda s: (s[0], -(s[1] - s[0])))
        kept: list[tuple[int, int, str]] = []
        for span in spans:
            if kept and span[0] < kept[-1][1]:
                continue
            kept.append(span)
        return kept

    def redact(self, text: str) -> Redaction:
        kinds = self.kinds(text)
        if not kinds:
            return Redaction(text)
        spans = self._raw_spans(text)
        remaining = text
        replacements: dict[str, str] = {}
        for start, end, kind in reversed(spans):
            secret = text[start:end]
            marker = placeholder(kind, secret)
            replacements[marker] = secret
            remaining = remaining[:start] + marker + remaining[end:]
        if not spans or self.kinds(remaining):
            # Some secret survives only in an encoded form: show nothing.
            return Redaction("", tuple(kinds), {}, withheld=True)
        ordered = dict(reversed(list(replacements.items())))
        return Redaction(remaining, tuple(k for _, _, k in spans), ordered)


def unredact(value: Any, replacements: Mapping[str, str]) -> Any:
    """`value` with every known placeholder put back (strings nested anywhere)."""
    if not replacements:
        return value
    if isinstance(value, str):
        return REDACTION_RE.sub(lambda m: replacements.get(m.group(0), m.group(0)), value)
    if isinstance(value, Mapping):
        return {k: unredact(v, replacements) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return type(value)(unredact(v, replacements) for v in value)
    return value
