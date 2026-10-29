#!/usr/bin/env python3
"""Leak guard: keep personal data, absolute local paths and secrets out of a public repository.

Standalone and standard library only, so this file can be copied into another repository as is.

Scopes (combinable):
  --tree          tracked files plus untracked files that are not ignored
  --history       every commit and annotated tag reachable from any ref: author, committer,
                  tagger, message, added lines, and every blob that the text diff does not show
  --range A..B    the same commit checks, limited to the commits in A..B (the blocking CI gate)
  --text FILE     one arbitrary file, for example a pull request body before it is posted
  --pr            the current pull request's title, body, reviews and comments (CI, REST API)
  --all           --tree and --history

Two kinds of check run on every scanned text:
  generic rules   patterns that hold nothing personal: absolute paths, non-allowlisted emails,
                  forbidden strings, secrets
  private list    salted SHA-256 hashes of private identifiers; the guard only learns that a
                  hash matched and never prints the matching text

History baseline (.leakguard-baseline): known generic hits in commits at or before a pinned cutoff
commit, stored as fingerprints only (commit, rule, line, path). It never applies to the working
tree, to commits after the cutoff, to private list hits or to email addresses. A range scan reads
the baseline and the allowlist from the range's base commit, so a change cannot approve itself.

Tools:
  --emit-baseline CUTOFF   print baseline candidates for review (fingerprints only)
  --strip-png FILE...      remove metadata chunks from PNG files in place

Exit codes: 0 clean, 1 at least one hit, 2 a usage or setup problem.
"""

from __future__ import annotations

import argparse
import bisect
import hashlib
import io
import json
import math
import os
import re
import string
import struct
import subprocess
import sys
import urllib.request
import zipfile
import zlib
from collections import Counter
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ALLOW_FILE = ".leakguard-allow"
BASELINE_FILE = ".leakguard-baseline"
PLANNING_DENYLIST = Path("_planning") / "private-denylist.hashes"
DENYLIST_CONFIG = "leakguard.denylist"
IMAGE_SUFFIXES = frozenset(
    {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".webp",
        ".svg",
        ".pdf",
        ".tif",
        ".tiff",
        ".heic",
        ".heif",
        ".avif",
        ".bmp",
        ".ico",
    }
)
IMAGE_MAGIC = (
    b"\x89PNG",
    b"\xff\xd8\xff",
    b"GIF8",
    b"%PDF",
    b"II*\x00",
    b"MM\x00*",
    b"BM",
    b"\x00\x00\x01\x00",
)
METADATA_MARKERS = (b"Exif", b"eXIf", b"EXIF", b"xmpmeta", b"XML:com.adobe.xmp", b"c2pa")
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
PNG_METADATA_CHUNKS = frozenset({b"eXIf", b"tEXt", b"iTXt", b"zTXt", b"caBX"})
PNG_KEEP_CHUNKS = frozenset(
    {
        b"IHDR",
        b"PLTE",
        b"tRNS",
        b"cHRM",
        b"gAMA",
        b"iCCP",
        b"sRGB",
        b"sBIT",
        b"pHYs",
        b"bKGD",
        b"acTL",
        b"fcTL",
        b"fdAT",
        b"IDAT",
    }
)
BINARY_SNIFF_BYTES = 8192


class GuardSetupError(Exception):
    """A configuration problem that stops the scan (exit 2)."""


# ---------------------------------------------------------------- generic rules


ALLOWED_EMAIL_DOMAINS = frozenset({"users.noreply.github.com", "noreply.github.com"})
RESERVED_EMAIL_DOMAINS = ("example.com", "example.net", "example.org")
ALLOWED_GITHUB_LOCAL_PARTS = frozenset({"noreply", "support"})
ALLOWED_EMAIL_SUFFIXES = (".example", ".test", ".invalid")

# Windows locations that hold no user name, and the usual documentation placeholder.
SYSTEM_PATH_ROOTS = frozenset(
    {"windows", "program files", "program files (x86)", "programdata", "path"}
)
USER_PATH_SEGMENTS = frozenset({"users", "documents and settings"})
FIXTURE_DIRECTORIES = ("tests", "test", "docs", "fixtures")
PLACEHOLDER_WORDS = ("example", "sample", "dummy", "fake", "placeholder", "redacted", "xxxx")


def email_allowed(address: str) -> bool:
    local, _, domain = address.rpartition("@")
    domain = domain.lower()
    if domain in ALLOWED_EMAIL_DOMAINS:
        return True
    if domain == "github.com":
        return local.lower() in ALLOWED_GITHUB_LOCAL_PARTS
    if any(domain == base or domain.endswith(f".{base}") for base in RESERVED_EMAIL_DOMAINS):
        return True
    return domain.endswith(ALLOWED_EMAIL_SUFFIXES)


def is_fixture_path(origin: str | None) -> bool:
    """Test fixtures and documentation, where generic probe values are expected."""
    if origin is None:
        return False
    parts = origin.lower().split("/")[:-1]
    return any(part in FIXTURE_DIRECTORIES for part in parts)


def _path_after(text: str, start: int) -> str:
    """The path written at ``start``, which may contain spaces (for example Program Files)."""
    end = start
    while end < len(text) and text[end] not in "\"'`<>|*?\n\r":
        end += 1
    return text[start:end]


def windows_path_exempt(match: re.Match[str], text: str, origin: str | None) -> bool:
    """System locations never name a user, and tests and docs may use one-segment probes.

    A path that climbs with ``..`` or passes through a user folder anywhere is never exempt.
    """
    segments = [
        part.strip().lower() for part in re.split(r"[\\/]+", _path_after(text, match.start())[2:])
    ]
    segments = [part for part in segments if part]
    if ".." in segments or USER_PATH_SEGMENTS.intersection(segments):
        return False
    if segments and segments[0] in SYSTEM_PATH_ROOTS:
        return True
    return is_fixture_path(origin) and len(segments) <= 1


def runner_home_exempt(match: re.Match[str], text: str, origin: str | None) -> bool:
    """The CI runner's home directory may appear in workflow files only."""
    found = match.group()
    return (
        origin is not None
        and origin.startswith(".github/")
        and re.fullmatch("/home/" + r"runner(/.*)?", found) is not None
        and ".." not in found.split("/")
    )


def email_exempt(match: re.Match[str], text: str, origin: str | None) -> bool:
    return email_allowed(match.group())


def entropy(text: str) -> float:
    """Shannon entropy in bits per character."""
    if not text:
        return 0.0
    counts = Counter(text)
    return -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values())


def looks_secret(body: str, min_classes: int = 2) -> bool:
    """A credential body is high entropy, mixes character classes and is not a placeholder."""
    lowered = body.lower()
    if any(word in lowered for word in PLACEHOLDER_WORDS):
        return False
    classes = sum(bool(re.search(p, body)) for p in ("[a-z]", "[A-Z]", "[0-9]"))
    return classes >= min_classes and entropy(body) >= 3.0


def secret_exempt(match: re.Match[str], text: str, origin: str | None) -> bool:
    return not looks_secret(match.group("body"))


def aws_key_exempt(match: re.Match[str], text: str, origin: str | None) -> bool:
    """AWS key ids are upper case and digits; a few real ones hold no digit at all."""
    return not looks_secret(match.group("body"), min_classes=1)


@dataclass(frozen=True)
class GenericRule:
    name: str
    pattern: re.Pattern[str]
    exempt: Callable[[re.Match[str], str, str | None], bool] | None = None


# Several patterns are assembled from pieces so that this file never matches its own rules.
GENERIC_RULES: tuple[GenericRule, ...] = (
    GenericRule(
        "windows-path",
        re.compile(r"(?<![A-Za-z])[A-Za-z]:[\\/][^\s\"'`<>|*?]*"),
        windows_path_exempt,
    ),
    GenericRule("unc-path", re.compile(r"(?<![\\\w])\\\\[A-Za-z0-9][\w.$-]*\\[\w.$-]+")),
    GenericRule("unc-path", re.compile(r"(?<![\\\w])\\{4}[A-Za-z0-9][\w.$-]*\\{2}[\w.$-]+")),
    GenericRule("macos-home-path", re.compile(r"/Users/[A-Za-z0-9._-]+")),
    GenericRule("windows-home-path", re.compile(r"/[A-Za-z]/users/[A-Za-z0-9._-]+", re.IGNORECASE)),
    GenericRule(
        "linux-home-path", re.compile(r"/home/[A-Za-z0-9._-]+[^\s\"'`<>|]*"), runner_home_exempt
    ),
    GenericRule("userprofile-variable", re.compile("%" + "USERPROFILE" + "%", re.IGNORECASE)),
    GenericRule("home-tilde-path", re.compile(r"~[\\/][A-Za-z0-9._-]+")),
    GenericRule(
        "email-address",
        re.compile(r"[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}"),
        email_exempt,
    ),
    GenericRule("forbidden-domain", re.compile(re.escape("anthropic" + ".com"), re.IGNORECASE)),
    GenericRule("forbidden-domain", re.compile(re.escape("claude" + ".ai"), re.IGNORECASE)),
    GenericRule("generated-footer", re.compile(r"\b" + "Generated" + r"\s+with", re.IGNORECASE)),
    GenericRule("session-id", re.compile("session" + r"_\w{20,}")),
    GenericRule("dash-character", re.compile("[" + chr(0x2013) + chr(0x2014) + "]")),
    # A key needs its header and a base64 body: a bare header line is not a key.
    GenericRule(
        "private-key",
        re.compile(
            "-{5}BEGIN "
            + r"(?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-{5}(?:[\s\"'+,]|\\+[nr])+"
            + r"(?:[A-Za-z-]+: [^\n]*(?:[\s\"'+,]|\\+[nr])+)*(?P<body>[A-Za-z0-9+/]{40,})"
        ),
        secret_exempt,
    ),
    GenericRule(
        "github-token",
        re.compile(r"(?<![A-Za-z0-9])gh[oprsu]_(?P<body>[A-Za-z0-9]{20,})"),
        secret_exempt,
    ),
    GenericRule(
        "github-token", re.compile("github" + r"_pat_(?P<body>[A-Za-z0-9_]{20,})"), secret_exempt
    ),
    GenericRule(
        "api-key", re.compile(r"(?<![A-Za-z0-9-])sk-(?P<body>[A-Za-z0-9_-]{20,})"), secret_exempt
    ),
    GenericRule(
        "slack-token",
        re.compile(r"(?<![A-Za-z0-9])xox[bp]-(?P<body>[A-Za-z0-9-]{10,})"),
        secret_exempt,
    ),
    GenericRule(
        "aws-access-key",
        re.compile(r"(?<![A-Z0-9])AKIA(?P<body>[0-9A-Z]{16})(?![0-9A-Z])"),
        aws_key_exempt,
    ),
)
GENERIC_RULE_NAMES = frozenset(rule.name for rule in GENERIC_RULES) | {"image-metadata"}
# Rules a baseline can never hold: private identifiers and email addresses must be fixed or
# reported, never silenced.
UNBASELINABLE_RULES = frozenset({"denylist", "email-address"})


def mask(text: str) -> str:
    """Show only the two characters at each end of a match."""
    if len(text) <= 6:
        return "*" * len(text)
    return f"{text[:2]}****{text[-2:]}"


# ---------------------------------------------------------------- private denylist


_EDGE_PUNCTUATION = string.punctuation + "".join(map(chr, (0x201C, 0x201D, 0x2018, 0x2019)))


@dataclass(frozen=True)
class Token:
    word: str
    line: int


@dataclass(frozen=True)
class Denylist:
    salt: str
    max_words: int
    entries: Mapping[str, int]

    @classmethod
    def parse(cls, text: str) -> Denylist:
        """Parse ``salt``, ``maxwords`` and ``hash`` lines. Errors never echo line content."""
        salt: str | None = None
        max_words: int | None = None
        entries: dict[str, int] = {}
        for number, raw in enumerate(text.splitlines(), start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            key, _, value = line.partition(" ")
            value = value.strip()
            if key == "salt" and re.fullmatch(r"[0-9a-fA-F]+", value) and salt is None:
                salt = value
            elif key == "maxwords" and value.isdigit() and int(value) >= 1 and max_words is None:
                max_words = int(value)
            elif key == "hash" and re.fullmatch(r"[0-9a-f]{64}", value):
                entries.setdefault(value, len(entries) + 1)
            else:
                raise GuardSetupError(f"denylist line {number} is not a valid entry")
        if salt is None or max_words is None:
            raise GuardSetupError("denylist needs exactly one salt line and one maxwords line")
        if not entries:
            raise GuardSetupError("denylist holds no hash lines")
        return cls(salt=salt, max_words=max_words, entries=entries)

    def digest(self, identifier: str) -> str:
        data = f"{self.salt}\n{identifier.strip().lower()}"
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    def matches(self, text: str) -> Iterator[tuple[int, int]]:
        """Yield (line, entry number) for each whole-word window whose hash is listed."""
        base = hashlib.sha256(f"{self.salt}\n".encode())
        seen: set[tuple[int, int]] = set()
        for tokens in token_streams(text):
            for start in range(len(tokens)):
                window: list[str] = []
                for token in tokens[start : start + self.max_words]:
                    window.append(token.word)
                    hasher = base.copy()
                    hasher.update(" ".join(window).encode("utf-8"))
                    entry = self.entries.get(hasher.hexdigest())
                    hit = (tokens[start].line, entry or 0)
                    if entry is not None and hit not in seen:
                        seen.add(hit)
                        yield hit


def token_streams(text: str) -> list[list[Token]]:
    """Three word streams over the lowercased text, each word tagged with its line.

    Whitespace words as written, the same words without edge punctuation, and runs of letters and
    digits. A window is always made of whole words, so a listed word inside a longer word does
    not match, while a listed word inside a path or an address still does.
    """
    lowered = text.lower()
    starts = [0] + [index + 1 for index, char in enumerate(lowered) if char == "\n"]

    def line_of(offset: int) -> int:
        return bisect.bisect_right(starts, offset)

    raw = [Token(m.group(), line_of(m.start())) for m in re.finditer(r"\S+", lowered)]
    stripped = [
        Token(word, token.line) for token in raw if (word := token.word.strip(_EDGE_PUNCTUATION))
    ]
    alnum = [Token(m.group(), line_of(m.start())) for m in re.finditer(r"[^\W_]+", lowered)]
    return [raw, stripped, alnum] if stripped != raw else [raw, alnum]


# ---------------------------------------------------------------- allowlist and baseline


@dataclass(frozen=True)
class Allowlist:
    values: frozenset[str] = frozenset()

    @classmethod
    def parse(cls, text: str, denylist: Denylist | None) -> Allowlist:
        values: set[str] = set()
        for number, raw in enumerate(text.splitlines(), start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            value, sep, reason = line.rpartition(" # ")
            value = value.rstrip()
            if not sep or not value or not reason.strip():
                raise GuardSetupError(
                    f"{ALLOW_FILE} line {number}: use '<exact string> # <reason>'"
                )
            if denylist is not None:
                for _, entry in denylist.matches(line):
                    raise GuardSetupError(
                        f"{ALLOW_FILE} line {number} contains a private identifier "
                        f"(hash #{entry}); the allowlist can never hold one"
                    )
            values.add(value)
        return cls(frozenset(values))

    def permits(self, found: str, whole_line: str, origin: str | None) -> bool:
        """A generic match passes when an entry equals the match or the whole trimmed line.

        Inside the allowlist file itself, a match that sits within an entry passes too. Denylist
        hits never consult this method.
        """
        if found in self.values or whole_line in self.values:
            return True
        return origin == ALLOW_FILE and any(found in value for value in self.values)


# Commit fields that are not files get a pseudo path starting with a colon.
FIELD_PATHS = frozenset(
    {":author name", ":author email", ":committer name", ":committer email", ":message"}
)
Fingerprint = tuple[str, str, int, str]


def _check_baseline_path(path: str) -> bool:
    if path in FIELD_PATHS:
        return True
    return not (
        not path
        or path.startswith("/")
        or "\\" in path
        or re.match(r"[A-Za-z]:", path)
        or any(part in ("", ".", "..") for part in path.split("/"))
    )


@dataclass(frozen=True)
class Baseline:
    """Known generic hits in history up to a pinned cutoff commit, as fingerprints only.

    Each entry is ``<commit> <rule> <line> <path>``. Private list hits cannot be entered: the
    rule name ``denylist`` is refused here, and the scanner only consults the baseline for
    generic rules.
    """

    cutoff: str
    entries: frozenset[Fingerprint] = frozenset()

    @classmethod
    def parse(cls, text: str, denylist: Denylist | None) -> Baseline:
        cutoff: str | None = None
        entries: set[Fingerprint] = set()
        for number, raw in enumerate(text.splitlines(), start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            where = f"{BASELINE_FILE} line {number}"
            if line.startswith("cutoff "):
                value = line[7:].strip()
                if cutoff is not None or not re.fullmatch(r"[0-9a-f]{40}", value):
                    raise GuardSetupError(f"{where}: one 'cutoff <40 hex commit>' line is allowed")
                cutoff = value
                continue
            parts = line.split(" ", 3)
            if len(parts) != 4:
                raise GuardSetupError(f"{where}: use '<commit> <rule> <line> <path>'")
            commit, rule, line_number, path = parts
            if rule in UNBASELINABLE_RULES:
                raise GuardSetupError(f"{where}: {rule} hits can never be baselined")
            if rule not in GENERIC_RULE_NAMES:
                raise GuardSetupError(f"{where}: unknown rule")
            if not re.fullmatch(r"[0-9a-f]{40}", commit) or not line_number.isdigit():
                raise GuardSetupError(f"{where}: commit must be 40 hex, line a number")
            if not _check_baseline_path(path):
                raise GuardSetupError(f"{where}: path must be repository-relative")
            if denylist is not None and any(denylist.matches(path)):
                raise GuardSetupError(f"{where}: path holds a private identifier")
            entries.add((commit, rule, int(line_number), path))
        if cutoff is None:
            raise GuardSetupError(f"{BASELINE_FILE} needs a cutoff line")
        return cls(cutoff, frozenset(entries))

    def verify(self, root: Path, anchor: str) -> None:
        """The cutoff must exist and lie at or before ``anchor``; every entry at or before it.

        ``anchor`` is the range base for range scans and the default branch otherwise, so a
        baseline can only describe history that is already on the protected line.
        """
        if not git_ok(root, "cat-file", "-e", f"{self.cutoff}^{{commit}}"):
            raise GuardSetupError(f"{BASELINE_FILE}: cutoff commit is not in this clone")
        if not git_ok(root, "merge-base", "--is-ancestor", self.cutoff, anchor):
            raise GuardSetupError(f"{BASELINE_FILE}: cutoff is not on the base or default branch")
        for commit in sorted({entry[0] for entry in self.entries}):
            if not git_ok(root, "merge-base", "--is-ancestor", commit, self.cutoff):
                raise GuardSetupError(
                    f"{BASELINE_FILE}: commit {commit[:12]} is not at or before the cutoff"
                )

    def covers(self, fingerprint: Fingerprint) -> bool:
        return fingerprint in self.entries


# ---------------------------------------------------------------- scanning


@dataclass(frozen=True)
class Hit:
    location: str
    rule: str
    shown: str
    fingerprint: Fingerprint | None = None

    def render(self, show_match: bool) -> str:
        """Private list hits always show their hash number, which is not matched content."""
        if show_match or self.rule == "denylist":
            return f"{self.location}: {self.rule}: {self.shown}"
        return f"{self.location}: {self.rule}"


@dataclass
class Scanner:
    denylist: Denylist | None
    allowlist: Allowlist = field(default_factory=Allowlist)
    baseline: Baseline | None = None
    hits: list[Hit] = field(default_factory=list)
    notices: list[str] = field(default_factory=list)
    baselined: int = 0

    def scan_text(
        self,
        text: str,
        label: str,
        *,
        origin: str | None = None,
        line_map: Sequence[int] | None = None,
        commit: str | None = None,
        path_key: str | None = None,
    ) -> None:
        """Scan ``text`` and record hits as ``label:line``.

        ``origin`` is the repository path the text belongs to, for path-scoped exceptions.
        ``line_map`` maps the 1-based line of ``text`` to the line number to report.
        ``commit`` and ``path_key`` identify history text, so its hits get fingerprints.
        """

        def line_number(line: int) -> int:
            return line_map[line - 1] if line_map is not None else line

        starts = [0] + [index + 1 for index, char in enumerate(text) if char == "\n"]
        key = path_key if path_key is not None else origin
        for rule in GENERIC_RULES:
            for match in rule.pattern.finditer(text):
                found = match.group()
                line = bisect.bisect_right(starts, match.start())
                end = text.find("\n", match.start())
                whole_line = text[starts[line - 1] : len(text) if end < 0 else end].strip()
                if self.allowlist.permits(found, whole_line, origin):
                    continue
                if rule.exempt is not None and rule.exempt(match, text, origin):
                    continue
                reported = line_number(line)
                fingerprint = (
                    (commit, rule.name, reported, key)
                    if commit is not None and key is not None
                    else None
                )
                if fingerprint and self.baseline and self.baseline.covers(fingerprint):
                    self.baselined += 1
                    continue
                private = self.denylist is not None and any(self.denylist.matches(found))
                shown = "****" if private else mask(found)
                self.hits.append(Hit(f"{label}:{reported}", rule.name, shown, fingerprint))
        # Private list hits never consult the allowlist or the baseline.
        if self.denylist is not None:
            for line, entry in self.denylist.matches(text):
                where = f"{label}:{line_number(line)}"
                self.hits.append(Hit(where, "denylist", f"private identifier (hash #{entry})"))

    def safe_label(self, path: str) -> str:
        """``path`` for use in output, or a stand-in when the path itself would leak.

        A path holding a private identifier or any generic match is never printed. The stand-in
        carries a short digest so separate hits on the same file can still be told apart.
        """
        private = self.denylist is not None and any(self.denylist.matches(path))
        if private or any(rule.pattern.search(path) for rule in GENERIC_RULES):
            return f"<path withheld {hashlib.sha256(path.encode('utf-8')).hexdigest()[:10]}>"
        return path

    def scan_path(self, path: str, label: str, commit: str | None = None) -> None:
        """Scan a file name. Hits are reported under ``label``, which must already be safe."""
        self.scan_text(path, f"{label} (file name)", origin=path, commit=commit, path_key=path)

    def scan_image(self, data: bytes, label: str, fingerprint: Fingerprint | None = None) -> None:
        """Flag metadata, and scan the text inside it with every rule.

        Text findings inside an image are never baselinable, and when there are any, the
        image-metadata hit itself loses its fingerprint so the baseline cannot cover it either.
        """
        self.notices.append(f"{label}: image, needs manual review")
        before = len(self.hits)
        self.scan_text(image_text(data), f"{label} (embedded text)")
        if not image_metadata(data):
            return
        # Only PNG text is fully parsed, so only a PNG metadata hit can ever be baselined.
        if len(self.hits) > before or not data.startswith(PNG_SIGNATURE):
            fingerprint = None
        if fingerprint and self.baseline and self.baseline.covers(fingerprint):
            self.baselined += 1
            return
        self.hits.append(Hit(label, "image-metadata", "metadata present", fingerprint))

    def scan_file_bytes(
        self, data: bytes, path: str, label: str | None = None, commit: str | None = None
    ) -> None:
        """Scan one file's bytes. ``path`` decides image handling and path-scoped exceptions."""
        shown = self.safe_label(path) if label is None else label
        # First bytes only count for binary content, so a text file starting "BM25" is text.
        image = Path(path).suffix.lower() in IMAGE_SUFFIXES or (
            data.startswith(IMAGE_MAGIC) and decode_text(data) is None
        )
        if image:
            fingerprint = (commit, "image-metadata", 0, path) if commit else None
            self.scan_image(data, shown, fingerprint)
        text = decode_text(data)
        if text is None:
            if not image:
                # Readable text inside other binaries is scanned too; its hits are never
                # baselinable, because they carry no line in a diff.
                self.notices.append(f"{shown}: binary, scanned for embedded text")
                self.scan_text(binary_text(data), f"{shown} (embedded text)")
            return
        self.scan_text(text, shown, origin=path, commit=commit, path_key=path)


def png_chunks(data: bytes) -> Iterator[tuple[bytes, bytes]]:
    """(type, raw chunk bytes) for each chunk of a PNG file."""
    offset = len(PNG_SIGNATURE)
    while offset + 8 <= len(data):
        (length,) = struct.unpack(">I", data[offset : offset + 4])
        kind = data[offset + 4 : offset + 8]
        end = offset + 12 + length
        yield kind, data[offset:end]
        if kind == b"IEND":
            return
        offset = end


def image_text(data: bytes) -> str:
    """Readable text an image carries: PNG text chunks (decompressed) and other non-pixel chunks,
    PDF dictionaries and XMP packets, and long printable runs in other formats."""
    pieces: list[bytes] = []
    if data.startswith(PNG_SIGNATURE):
        for kind, chunk in png_chunks(data):
            body = chunk[8:-4]
            if kind == b"IDAT":
                continue
            if kind == b"zTXt" and b"\0" in body:
                keyword, _, rest = body.partition(b"\0")
                pieces += [keyword, _inflate(rest[1:])]
            elif kind == b"iTXt" and body.count(b"\0") >= 3:
                keyword, _, rest = body.partition(b"\0")
                compressed, rest = rest[0], rest[2:]
                language, _, rest = rest.partition(b"\0")
                translated, _, text = rest.partition(b"\0")
                pieces += [keyword, language, translated, _inflate(text) if compressed else text]
            else:
                pieces.append(body)
        # Anything appended after the image end is read as well.
        end = data.rfind(b"IEND")
        trailing = binary_text(data[end + 8 :]) if end >= 0 else ""
    elif data.startswith(b"\xff\xd8"):
        pieces += jpeg_metadata_segments(data)
        # Text outside the parsed segments (after the image end, for example) is read as well.
        trailing = binary_text(data)
    elif data.startswith(b"%PDF"):
        # Stream bodies are mostly compressed; keep the dictionaries and any XMP packets.
        dictionaries = re.sub(rb"stream\r?\n.*?endstream", b"", data, flags=re.DOTALL)
        pieces.append(dictionaries)
        pieces += re.findall(rb"<x:xmpmeta.*?</x:xmpmeta>", data, flags=re.DOTALL)
        pieces += pdf_utf16_strings(dictionaries)
        trailing = ""
    else:
        # Unparsed formats: long runs only, so compressed bytes do not produce chance matches.
        return binary_text(data)
    joined = b"\n".join(pieces)
    runs = re.findall(rb"[\x20-\x7e]{4,}", joined) + utf16_runs(joined, 4)
    return "\n".join([*(run.decode("ascii") for run in runs), trailing])


def utf16_runs(data: bytes, shortest: int) -> list[bytes]:
    """Printable UTF-16 little endian runs, as ASCII bytes."""
    pattern = rb"(?:[\x20-\x7e]\x00){%d,}" % shortest
    return [run[::2] for run in re.findall(pattern, data)]


def binary_text(data: bytes) -> str:
    """Readable text inside a binary file: XML parts of Office and OpenDocument archives, and
    printable ASCII and UTF-16 runs of at least 10 characters."""
    pieces: list[str] = []
    if data.startswith(b"PK\x03\x04"):
        pieces += archive_xml_text(data)
    runs = re.findall(rb"[\x20-\x7e]{10,}", data) + utf16_runs(data, 10)
    pieces += [run.decode("ascii") for run in runs]
    return "\n".join(pieces)


ARCHIVE_TEXT_LIMIT = 16 << 20
ARCHIVE_ENTRY_LIMIT = 2000


def archive_xml_text(data: bytes) -> list[str]:
    """XML parts of an Office or OpenDocument archive, within a total size budget.

    A corrupt or hostile entry is skipped, never fatal: the caller still scans the raw runs.
    """
    texts: list[str] = []
    budget = ARCHIVE_TEXT_LIMIT
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for info in archive.infolist()[:ARCHIVE_ENTRY_LIMIT]:
                if not info.filename.endswith((".xml", ".rels")) or info.file_size > budget:
                    continue
                try:
                    with archive.open(info) as handle:
                        content = handle.read(budget + 1)
                except Exception:  # corrupt deflate, unsupported or encrypted entry
                    continue
                budget -= len(content)
                if budget < 0:
                    break
                texts.append(content.decode("utf-8", errors="replace"))
    except Exception:  # not a readable archive at all
        return texts
    return texts


def jpeg_metadata_segments(data: bytes) -> list[bytes]:
    """APP and comment segment payloads of a JPEG file (EXIF, XMP, IPTC, C2PA), not pixels."""
    segments: list[bytes] = []
    offset = 2
    while offset + 4 <= len(data) and data[offset] == 0xFF:
        if data[offset + 1] == 0xFF:  # fill byte before a marker
            offset += 1
            continue
        marker = data[offset + 1]
        if marker == 0xDA:
            break
        (length,) = struct.unpack(">H", data[offset + 2 : offset + 4])
        if length < 2:
            break
        if 0xE0 <= marker <= 0xEF or marker == 0xFE:
            segments.append(data[offset + 4 : offset + 2 + length])
        offset += 2 + length
    return segments


def pdf_utf16_strings(dictionaries: bytes) -> list[bytes]:
    """PDF text strings written in UTF-16 (hex or literal form), decoded to ASCII where possible."""
    found: list[bytes] = []
    for hex_text in re.findall(rb"<[Ff][Ee][Ff][Ff]([0-9A-Fa-f\s]+)>", dictionaries):
        try:
            raw = bytes.fromhex(hex_text.decode("ascii"))
        except ValueError:
            continue
        found.append(raw.decode("utf-16-be", errors="replace").encode("ascii", "replace"))
    for literal in re.findall(rb"\(((?:[^()\\]|\\.)*)\)", dictionaries, flags=re.DOTALL):
        raw = pdf_unescape(literal)
        if raw.startswith(b"\xfe\xff"):
            text = raw[2:].decode("utf-16-be", errors="replace")
            found.append(text.encode("ascii", "replace"))
    return found


_PDF_ESCAPES = {b"n": b"\n", b"r": b"\r", b"t": b"\t", b"b": b"\b", b"f": b"\f"}


def pdf_unescape(literal: bytes) -> bytes:
    """Bytes of a PDF literal string body: octal and backslash escapes resolved."""

    def replace(match: re.Match[bytes]) -> bytes:
        escaped = match.group(1)
        if escaped[:1].isdigit():
            return bytes([int(escaped, 8) & 0xFF])
        return _PDF_ESCAPES.get(escaped, escaped)

    return re.sub(rb"\\([0-7]{1,3}|.)", replace, literal, flags=re.DOTALL)


def _inflate(data: bytes) -> bytes:
    try:
        return zlib.decompressobj().decompress(data, 1 << 20)
    except zlib.error:
        return data


def image_metadata(data: bytes) -> bool:
    """EXIF, XMP, C2PA content credentials, or PNG text chunks."""
    if data.startswith(PNG_SIGNATURE) and any(
        kind in PNG_METADATA_CHUNKS for kind, _ in png_chunks(data)
    ):
        return True
    return any(marker in data for marker in METADATA_MARKERS)


def strip_png(data: bytes) -> tuple[bytes, int]:
    """The PNG with only image and color chunks kept, and the number of chunks removed."""
    if not data.startswith(PNG_SIGNATURE):
        raise GuardSetupError("not a PNG file")
    kept = [PNG_SIGNATURE]
    removed = 0
    for kind, chunk in png_chunks(data):
        if kind in PNG_KEEP_CHUNKS or kind == b"IEND":
            kept.append(chunk)
        else:
            removed += 1
    return b"".join(kept), removed


_BOMS = (
    (b"\xff\xfe\x00\x00", "utf-32-le"),
    (b"\x00\x00\xfe\xff", "utf-32-be"),
    (b"\xff\xfe", "utf-16-le"),
    (b"\xfe\xff", "utf-16-be"),
)


def decode_text(data: bytes) -> str | None:
    """Text of ``data``, honoring a UTF-16 or UTF-32 byte order mark, or None for binary data."""
    for bom, encoding in _BOMS:
        if data.startswith(bom):
            return data[len(bom) :].decode(encoding, errors="replace")
    if b"\0" in data[:BINARY_SNIFF_BYTES]:
        return None
    return data.decode("utf-8", errors="replace")


def redact(text: str) -> str:
    """Mask generic matches, for messages from other programs such as git."""
    for rule in GENERIC_RULES:
        text = rule.pattern.sub(lambda match: mask(match.group()), text)
    return text


def run_git(root: Path, *args: str) -> bytes:
    result = subprocess.run(
        ["git", "-c", "core.quotepath=off", *args], cwd=root, capture_output=True, check=False
    )
    if result.returncode != 0:
        message = result.stderr.decode("utf-8", errors="replace").strip().splitlines()
        first = redact(message[0]) if message else f"exit code {result.returncode}"
        raise GuardSetupError(f"git {args[0]} failed: {first}")
    return result.stdout


def git_ok(root: Path, *args: str) -> bool:
    return (
        subprocess.run(["git", *args], cwd=root, capture_output=True, check=False).returncode == 0
    )


def tree_files(root: Path) -> list[str]:
    output = run_git(root, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
    return sorted({os.fsdecode(name) for name in output.split(b"\0") if name})


def scan_tree(scanner: Scanner, root: Path) -> None:
    for name in tree_files(root):
        path = root / name
        if not path.is_file():
            continue
        label = scanner.safe_label(name)
        scanner.scan_path(name, label)
        scanner.scan_file_bytes(path.read_bytes(), name, label)


@dataclass
class FilePatch:
    path: str
    blob: str | None = None
    lines: list[str] = field(default_factory=list)
    numbers: list[int] = field(default_factory=list)


def _patch_path(header: str) -> str:
    name = header[4:].strip()
    if name.startswith('"') and name.endswith('"'):
        name = name[1:-1]
    return name[2:] if name.startswith("b/") else name


def parse_patch(patch: str) -> tuple[list[FilePatch], set[str]]:
    """Added lines of a unified diff, grouped by file, with their new-file line numbers.

    Also returns the blob ids whose content the diff showed as text, so the blob scan can skip
    them. A blob shown as binary (or hidden by a diff attribute) is left for the blob scan.
    """
    files: list[FilePatch] = []
    shown_as_text: set[str] = set()
    current: FilePatch | None = None
    blob: str | None = None
    in_hunk = False
    number = 0
    # Split on newlines only: a carriage return, form feed or other separator inside an added
    # line is content, and must not hide what follows it.
    for line in patch.split("\n"):
        header = line.rstrip("\r")
        if header.startswith("diff --git "):
            current, blob, in_hunk = None, None, False
        elif not in_hunk and header.startswith("index "):
            found = re.match(r"index [0-9a-f]+\.\.([0-9a-f]+)", header)
            blob = found.group(1) if found else None
        elif not in_hunk and header.startswith("+++ "):
            if header[4:].strip() != "/dev/null":
                current = FilePatch(_patch_path(header), blob)
                files.append(current)
                if blob is not None:
                    shown_as_text.add(blob)
        elif header.startswith("@@"):
            in_hunk = True
            found = re.search(r"\+(\d+)", header)
            number = int(found.group(1)) if found else 0
        elif in_hunk and current is not None and line.startswith("+"):
            current.lines.append(line[1:])
            current.numbers.append(number)
            number += 1
        elif in_hunk and line.startswith(" "):
            number += 1
    return files, shown_as_text


HISTORY_FORMAT = "%H%x00%an%x00%ae%x00%cn%x00%ce%x00%B%x00"
HISTORY_FIELDS = ("author name", "author email", "committer name", "committer email")
PATCH_OPTIONS = (
    "--format=",
    "-p",
    "--unified=0",
    "--full-index",
    "--no-color",
    "--no-ext-diff",
    "--no-textconv",
    "--no-renames",
    "--diff-merges=first-parent",
)
NAME_OPTIONS = ("--format=", "--name-only", "-z", "--no-renames", "--diff-merges=first-parent")


def commit_metadata(root: Path, revisions: Sequence[str]) -> list[list[str]]:
    """[sha, author name, author email, committer name, committer email, message] per commit.

    None of these fields can hold a NUL byte, so splitting on NUL is safe; file content is read
    separately, per commit. Any record that does not start with a full commit id fails closed.
    """
    output = run_git(root, "log", *revisions, f"--format={HISTORY_FORMAT}")
    parts = output.decode("utf-8", errors="replace").split("\0")
    records: list[list[str]] = []
    for index in range(0, len(parts) - 1, 6):
        record = parts[index : index + 6]
        record[0] = record[0].strip()
        if len(record) != 6 or not re.fullmatch(r"[0-9a-f]{40}", record[0]):
            raise GuardSetupError("git log output could not be parsed safely")
        records.append(record)
    return records


def scan_commits(scanner: Scanner, root: Path, revisions: Sequence[str]) -> None:
    """Commit metadata, added lines, and blobs the diff does not show, for ``revisions``."""
    shown_as_text: set[str] = set()
    for sha, *people, message in commit_metadata(root, revisions):
        commit = f"commit {sha[:12]}"
        for name, value in zip(HISTORY_FIELDS, people, strict=True):
            scanner.scan_text(value, f"{commit} {name}", commit=sha, path_key=f":{name}")
        scanner.scan_text(message, f"{commit} message", commit=sha, path_key=":message")
        # Every path the commit touches, including empty files and reused blobs with no diff.
        names = run_git(root, "show", *NAME_OPTIONS, sha).split(b"\0")
        for name in sorted({os.fsdecode(raw) for raw in names if raw.strip()}):
            scanner.scan_path(name, f"{commit} {scanner.safe_label(name)}", sha)
        patch = run_git(root, "show", *PATCH_OPTIONS, sha).decode("utf-8", errors="replace")
        file_patches, text_blobs = parse_patch(patch)
        shown_as_text |= text_blobs
        for file_patch in file_patches:
            label = f"{commit} {scanner.safe_label(file_patch.path)}"
            if file_patch.lines:
                scanner.scan_text(
                    "\n".join(file_patch.lines),
                    label,
                    origin=file_patch.path,
                    line_map=file_patch.numbers,
                    commit=sha,
                    path_key=file_patch.path,
                )
    scan_blobs(scanner, root, revisions, shown_as_text)


def scan_history(scanner: Scanner, root: Path) -> None:
    scan_commits(scanner, root, ["--all"])
    scan_tags(scanner, root)
    scan_refs(scanner, root)


def scan_refs(scanner: Scanner, root: Path) -> None:
    """Branch names, local and remote. Never baselined."""
    output = run_git(root, "for-each-ref", "--format=%(refname)", "refs/heads", "refs/remotes")
    for name in output.decode("utf-8", errors="replace").split("\n"):
        if name.strip():
            scanner.scan_text(name, f"ref {scanner.safe_label(name)} name")


TAG_FORMAT = "%00%(refname:short)%00%(taggername)%00%(taggeremail)%00%(contents)"
TAG_FIELDS = ("name", "tagger name", "tagger email", "message")


def scan_tags(scanner: Scanner, root: Path) -> None:
    """Tag names, and the tagger and message of every annotated tag. Never baselined."""
    output = run_git(root, "for-each-ref", f"--format={TAG_FORMAT}", "refs/tags")
    parts = output.decode("utf-8", errors="replace").split("\0")[1:]
    for index in range(0, len(parts) - 3, 4):
        label = f"tag {scanner.safe_label(parts[index].strip())}"
        for field_name, value in zip(TAG_FIELDS, parts[index : index + 4], strict=True):
            scanner.scan_text(value, f"{label} {field_name}")


def reachable_objects(root: Path, revisions: Sequence[str]) -> dict[str, str]:
    """Object id to one path, for every object reachable from ``revisions`` (trees included)."""
    listing = run_git(root, "rev-list", "--objects", *revisions)
    objects: dict[str, str] = {}
    for line in listing.decode("utf-8", errors="replace").splitlines():
        sha, _, name = line.partition(" ")
        if name:
            objects.setdefault(sha, name)
    return objects


def read_objects(root: Path, shas: Sequence[str]) -> Iterator[tuple[str, str, bytes]]:
    """(id, type, content) for each object, read with one ``git cat-file --batch`` call."""
    if not shas:
        return
    result = subprocess.run(
        ["git", "cat-file", "--batch"],
        cwd=root,
        input="".join(f"{sha}\n" for sha in shas).encode(),
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise GuardSetupError("git cat-file failed")
    data = result.stdout
    offset = 0
    while offset < len(data):
        header_end = data.index(b"\n", offset)
        sha, kind, size = data[offset:header_end].decode().split(" ")
        start = header_end + 1
        yield sha, kind, data[start : start + int(size)]
        offset = start + int(size) + 1


def introducing_commit(root: Path, blob: str, revisions: Sequence[str]) -> str | None:
    """The oldest commit in ``revisions`` that adds or changes a path to ``blob``."""
    output = run_git(root, "log", *revisions, "--reverse", "--format=%H", f"--find-object={blob}")
    lines = output.decode().split()
    return lines[0] if lines else None


def scan_blobs(
    scanner: Scanner, root: Path, revisions: Sequence[str], shown_as_text: set[str]
) -> None:
    """Every reachable blob the text diff did not show: binaries, UTF-16, diff attributes.

    Images are always checked for metadata, whether or not the diff showed them.
    """
    objects = reachable_objects(root, revisions)
    wanted = sorted(
        sha
        for sha, name in objects.items()
        if sha not in shown_as_text or Path(name).suffix.lower() in IMAGE_SUFFIXES
    )
    # Images are recognized by name or by content, as in the tree scan.
    for sha, kind, content in read_objects(root, wanted):
        if kind != "blob":
            continue
        name = objects[sha]
        label = f"history blob {scanner.safe_label(name)}"
        commit = introducing_commit(root, sha, revisions)
        if sha in shown_as_text:
            fingerprint = (commit, "image-metadata", 0, name) if commit else None
            scanner.scan_image(content, label, fingerprint)
        else:
            scanner.scan_file_bytes(content, name, label, commit)


# ---------------------------------------------------------------- pull request text


def http_get_json(url: str, token: str) -> Any:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def _all_pages(url: str, token: str) -> Iterator[dict[str, Any]]:
    page = 1
    while True:
        batch = http_get_json(f"{url}?per_page=100&page={page}", token)
        if not isinstance(batch, list):
            raise GuardSetupError("unexpected response from the GitHub API")
        yield from batch
        if len(batch) < 100:
            return
        page += 1


def pull_request_texts(env: Mapping[str, str]) -> list[tuple[str, str]]:
    """Title, body, reviews, review comments and comments of the pull request under test."""
    token = env.get("GITHUB_TOKEN", "")
    repository = env.get("GITHUB_REPOSITORY", "")
    event_path = env.get("GITHUB_EVENT_PATH", "")
    if not token or not repository or not event_path:
        raise GuardSetupError("--pr needs GITHUB_TOKEN, GITHUB_REPOSITORY and GITHUB_EVENT_PATH")
    event = json.loads(Path(event_path).read_text(encoding="utf-8"))
    number = event.get("pull_request", {}).get("number")
    issue = event.get("issue", {})
    if number is None and issue.get("pull_request"):
        number = issue.get("number")
    if not isinstance(number, int):
        raise GuardSetupError("--pr runs only on pull request events")
    base = f"{env.get('GITHUB_API_URL', 'https://api.github.com')}/repos/{repository}"
    pr = http_get_json(f"{base}/pulls/{number}", token)
    branch = (pr.get("head") or {}).get("ref") or ""
    texts = [
        ("pr title", str(pr.get("title") or "")),
        ("pr body", str(pr.get("body") or "")),
        ("pr branch", str(branch)),
    ]
    sources = (
        ("pr review", f"{base}/pulls/{number}/reviews"),
        ("pr review comment", f"{base}/pulls/{number}/comments"),
        ("pr comment", f"{base}/issues/{number}/comments"),
    )
    for kind, url in sources:
        for item in _all_pages(url, token):
            texts.append((f"{kind} {item.get('id')}", str(item.get("body") or "")))
    return texts


# ---------------------------------------------------------------- setup


def find_root(start: Path) -> Path:
    try:
        output = run_git(start, "rev-parse", "--show-toplevel")
    except (GuardSetupError, OSError):
        return Path(__file__).resolve().parents[1]
    return Path(output.decode("utf-8").strip())


def load_denylist(env: Mapping[str, str], root: Path) -> tuple[Denylist | None, str]:
    """Denylist and a description of its source, or (None, reason) when there is none.

    In CI only the environment counts, so the job always needs the repository secret. Locally the
    clone's git setting and a planning folder above the repository are used as well.
    """
    named = env.get("LEAK_DENYLIST_FILE", "")
    if named:
        path = Path(named)
        if not path.is_file():
            raise GuardSetupError("LEAK_DENYLIST_FILE does not name a readable file")
        return Denylist.parse(path.read_text(encoding="utf-8")), "LEAK_DENYLIST_FILE"
    inline = env.get("LEAK_DENYLIST", "")
    if inline.strip():
        return Denylist.parse(inline), "LEAK_DENYLIST"
    if env.get("CI", "").lower() == "true":
        return None, "no source"
    top = repository_top(root)
    if top is not None:
        configured = configured_denylist(top)
        if configured:
            path = top / Path(configured).expanduser()
            if not path.is_file():
                raise GuardSetupError(f"git config {DENYLIST_CONFIG} does not name a readable file")
            source = f"git config {DENYLIST_CONFIG}"
            return Denylist.parse(path.read_text(encoding="utf-8")), source
    for folder in (top or root.resolve()).parents:
        if folder == Path(folder.anchor):
            continue  # a drive or filesystem root can be writable by other users
        planning = folder / PLANNING_DENYLIST
        if planning.is_file():
            return Denylist.parse(planning.read_text(encoding="utf-8")), "private planning file"
    return None, "no source"


def repository_top(root: Path) -> Path | None:
    """The top folder of the git repository holding ``root``, or None outside one."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"], cwd=root, capture_output=True, check=False
        )
    except OSError:
        return None
    if result.returncode != 0:
        return None
    return Path(result.stdout.decode("utf-8", errors="replace").strip()).resolve()


def configured_denylist(top: Path) -> str:
    """The clone's own ``leakguard.denylist`` setting, or "" when it has none."""
    try:
        result = subprocess.run(
            ["git", "config", "--local", "--get", DENYLIST_CONFIG],
            cwd=top,
            capture_output=True,
            check=False,
        )
    except OSError:
        return ""
    if result.returncode == 1:
        return ""
    if result.returncode != 0:
        raise GuardSetupError(f"git config {DENYLIST_CONFIG} could not be read")
    return result.stdout.decode("utf-8", errors="replace").strip()


def display_name(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.name


def default_branch(root: Path) -> str:
    """The remote default branch when the clone knows it, else HEAD."""
    if git_ok(root, "rev-parse", "--verify", "--quiet", "refs/remotes/origin/HEAD"):
        return "refs/remotes/origin/HEAD"
    return "HEAD"


def file_at(root: Path, commit: str, name: str) -> str | None:
    """Text of ``name`` at ``commit``, or None when the commit has no such file."""
    if not git_ok(root, "cat-file", "-e", f"{commit}:{name}"):
        return None
    return run_git(root, "show", f"{commit}:{name}").decode("utf-8")


def config_at(
    root: Path, commit: str, denylist: Denylist | None
) -> tuple[Allowlist, Baseline | None]:
    """The allowlist and baseline as they were at ``commit``."""
    allow_text = file_at(root, commit, ALLOW_FILE)
    allowlist = Allowlist.parse(allow_text, denylist) if allow_text is not None else Allowlist()
    baseline_text = file_at(root, commit, BASELINE_FILE)
    if baseline_text is None:
        return allowlist, None
    baseline = Baseline.parse(baseline_text, denylist)
    baseline.verify(root, commit)
    return allowlist, baseline


def emit_baseline(scanner: Scanner, root: Path, cutoff: str) -> list[str]:
    """Baseline candidates: generic history hits at or before ``cutoff``, fingerprints only.

    A location that also has a private list hit, or whose path would itself leak, is never a
    candidate. Every candidate still needs a person to confirm it is a false positive.
    """
    full = run_git(root, "rev-parse", "--verify", f"{cutoff}^{{commit}}").decode().strip()
    scanner.baseline = None
    scan_commits(scanner, root, [full])
    private = {hit.location for hit in scanner.hits if hit.rule == "denylist"}
    lines = {
        f"{commit} {rule} {line} {path}"
        for hit in scanner.hits
        if hit.fingerprint is not None and hit.location not in private
        for commit, rule, line, path in [hit.fingerprint]
        if rule not in UNBASELINABLE_RULES
        if scanner.safe_label(path) == path or path in FIELD_PATHS
    }
    return [f"cutoff {full}", *sorted(lines)]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="leak_guard",
        description="Block personal data, absolute paths and secrets from reaching a remote.",
    )
    parser.add_argument("--tree", action="store_true", help="scan the working tree")
    parser.add_argument("--history", action="store_true", help="scan every reachable commit")
    parser.add_argument("--range", metavar="A..B", help="scan only the commits in A..B")
    parser.add_argument("--text", action="append", type=Path, default=[], metavar="FILE")
    parser.add_argument("--pr", action="store_true", help="scan the current pull request text")
    parser.add_argument("--all", action="store_true", help="same as --tree --history")
    parser.add_argument("--root", type=Path, help="repository root (default: from git)")
    parser.add_argument("--emit-baseline", metavar="CUTOFF", help="print baseline candidates")
    parser.add_argument("--strip-png", nargs="+", type=Path, metavar="FILE", default=[])
    return parser


def run(args: argparse.Namespace, env: Mapping[str, str]) -> int:
    root = (args.root or find_root(Path.cwd())).resolve()
    if args.strip_png:
        for path in args.strip_png:
            cleaned, removed = strip_png(path.read_bytes())
            path.write_bytes(cleaned)
            print(f"stripped {display_name(path, root)}: {removed} metadata chunk(s) removed")
        return 0
    tree = args.tree or args.all
    history = args.history or args.all
    if not (tree or history or args.range or args.text or args.pr or args.emit_baseline):
        raise GuardSetupError(
            "choose at least one scope: --tree, --history, --range, --text, --pr, --all"
        )

    in_ci = env.get("CI", "").lower() == "true"
    denylist, source = load_denylist(env, root)
    if denylist is None:
        banner = "!" * 72
        warning = [
            banner,
            "WARNING: no private denylist found. Private identifiers are NOT being checked.",
            f"Looked in: LEAK_DENYLIST_FILE, LEAK_DENYLIST, git config {DENYLIST_CONFIG}, and",
            f"{PLANNING_DENYLIST.as_posix()} in every folder above the repository.",
            f"Fix: git config {DENYLIST_CONFIG} <path to the list>",
            banner,
        ]
        print("\n".join(warning), file=sys.stderr)
        if in_ci:
            print("error: a denylist is required in CI", file=sys.stderr)
            return 2
    allow_path = root / ALLOW_FILE
    allowlist = (
        Allowlist.parse(allow_path.read_text(encoding="utf-8"), denylist)
        if allow_path.is_file()
        else Allowlist()
    )
    baseline: Baseline | None = None
    baseline_path = root / BASELINE_FILE
    if baseline_path.is_file() and history:
        baseline = Baseline.parse(baseline_path.read_text(encoding="utf-8"), denylist)
        baseline.verify(root, default_branch(root))
    scanner = Scanner(denylist=denylist, allowlist=allowlist, baseline=baseline)

    if args.emit_baseline:
        for line in emit_baseline(scanner, root, args.emit_baseline):
            print(line)
        return 0

    scopes: list[str] = []
    if tree:
        scopes.append("tree")
        scan_tree(scanner, root)
    if history:
        scopes.append("history")
        scan_history(scanner, root)
    if args.range:
        scopes.append("range")
        base, sep, tip = args.range.partition("..")
        if not sep or not base or not tip or tip.startswith(".") or base.startswith("-"):
            raise GuardSetupError("--range takes A..B")
        # The base commit's allowlist and baseline apply, never the ones the range adds.
        base_sha = run_git(root, "rev-parse", "--verify", f"{base}^{{commit}}").decode().strip()
        saved = (scanner.allowlist, scanner.baseline)
        scanner.allowlist, scanner.baseline = config_at(root, base_sha, denylist)
        scan_commits(scanner, root, [f"{base_sha}..{tip}"])
        if scanner.baseline is not None:
            baseline = scanner.baseline
        scanner.allowlist, scanner.baseline = saved
    for path in args.text:
        scopes.append("text")
        if not path.is_file():
            raise GuardSetupError(f"--text file not found: {display_name(path, root)}")
        scanner.scan_file_bytes(path.read_bytes(), display_name(path, root))
    if args.pr:
        scopes.append("pr")
        for label, text in pull_request_texts(env):
            scanner.scan_text(text, label)

    for notice in scanner.notices:
        print(f"notice: {notice}")
    for hit in scanner.hits:
        print(hit.render(show_match=not in_ci))
    entries = "no denylist" if denylist is None else f"denylist {len(denylist.entries)} entries"
    baselined = f"; {scanner.baselined} baselined" if baseline is not None else ""
    summary = f"({', '.join(dict.fromkeys(scopes))}; {entries} from {source}{baselined})"
    if scanner.hits:
        print(f"leak guard: {len(scanner.hits)} hit(s) {summary}", file=sys.stderr)
        return 1
    print(f"leak guard: clean {summary}")
    return 0


def main(argv: Sequence[str] | None = None, env: Mapping[str, str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return run(args, os.environ if env is None else env)
    except GuardSetupError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: {exc.strerror or exc.__class__.__name__}", file=sys.stderr)
        return 2
    except ValueError as exc:
        # Undecodable input or a malformed API response: a setup problem, never a silent pass.
        print(f"error: cannot process input ({exc.__class__.__name__})", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
