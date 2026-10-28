"""Text normalization shared by the content-inspecting guardrails.

Attack text hides from keyword rules with invisible characters, compatibility
forms, character spacing and encodings. Every rule therefore runs over a set of
*views* of the input: the normalized text, the text with single-character spacing
collapsed, and the decoded form of any base64 token that decodes to readable text.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from collections.abc import Iterator

_SPACE_RE = re.compile(r"\s+")
_SPACED_RUN_RE = re.compile(r"(?<!\S)(?:\S ){2,}\S(?!\S)")
_BASE64_RE = re.compile(r"[A-Za-z0-9+/_-]{24,}={0,2}")
_MIN_PRINTABLE = 0.9


def hidden_characters(text: str) -> list[str]:
    """Invisible format characters (zero-width, bidi marks, soft hyphen) in `text`."""
    return [f"U+{ord(ch):04X}" for ch in text if unicodedata.category(ch) == "Cf"]


def _clean(text: str) -> str:
    folded = unicodedata.normalize("NFKC", text)
    return "".join(ch for ch in folded if unicodedata.category(ch) != "Cf").casefold()


def _collapse(text: str) -> str:
    return _SPACE_RE.sub(" ", text).strip()


def normalize(text: str) -> str:
    """NFKC, drop invisible format characters, case-fold, collapse whitespace."""
    return _collapse(_clean(text))


def _readable(raw: bytes) -> str | None:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text or " " not in text:
        return None
    printable = sum(ch.isprintable() or ch in "\n\t" for ch in text)
    return text if printable / len(text) >= _MIN_PRINTABLE else None


def decoded_payloads(text: str) -> list[str]:
    """Base64 tokens in `text` that decode to readable prose (an encoded instruction)."""
    out: list[str] = []
    for token in _BASE64_RE.findall(text):
        padded = token + "=" * (-len(token) % 4)
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                decoded = _readable(decoder(padded))
            except (binascii.Error, ValueError):
                continue
            if decoded is not None:
                out.append(decoded)
                break
    return out


def views(text: str) -> Iterator[str]:
    """Every normalized form of `text` a rule should be checked against."""
    clean = _clean(text)
    norm = _collapse(clean)
    yield norm
    # Collapse "i g n o r e" runs before whitespace is squeezed, so the wider gaps
    # between spaced-out words survive as word boundaries.
    despaced = _collapse(_SPACED_RUN_RE.sub(lambda m: m.group(0).replace(" ", ""), clean))
    if despaced != norm:
        yield despaced
    for payload in decoded_payloads(text):
        yield normalize(payload)
