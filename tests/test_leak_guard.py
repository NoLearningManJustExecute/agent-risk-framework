"""Leak guard tests.

Every sample that a rule should catch is assembled from pieces at run time, so this file never
trips the guard itself when the repository is scanned.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import struct
import subprocess
import urllib.request
import zlib
from pathlib import Path
from typing import Any

import pytest

from tools import leak_guard
from tools.leak_guard import (
    Allowlist,
    Baseline,
    Denylist,
    GuardSetupError,
    Scanner,
    display_name,
    email_allowed,
    mask,
    parse_patch,
)

SALT = "a1b2c3"
SECRET_WORD = "zorb" + "latt"  # stands in for a private identifier
SECRET_PAIR = "quill" + " " + "marrow"
AT = "@"
BACKSLASH = chr(92)


def digest(identifier: str) -> str:
    return hashlib.sha256(f"{SALT}\n{identifier}".encode()).hexdigest()


DENYLIST_TEXT = (
    "# test denylist\n"
    f"salt {SALT}\n"
    "maxwords 3\n"
    f"hash {digest(SECRET_WORD)}\n"
    f"hash {digest(SECRET_PAIR)}\n"
)


def noise(length: int, seed: str = "a") -> str:
    """Deterministic high-entropy letters and digits, standing in for a real credential body."""
    raw = base64.b64encode(hashlib.sha512(seed.encode()).digest() * 2).decode()
    return "".join(char for char in raw if char.isalnum())[:length]


def pem(kind: str, suffix: str = "") -> str:
    """A key block with header and body, assembled so this file holds no literal key."""
    header = "-" * 5 + "BEGIN " + kind + "PRIVATE KEY" + suffix + "-" * 5
    return f"{header}\n{noise(64, kind)}\n{noise(64, kind + '2')}\n"


def denylist() -> Denylist:
    return Denylist.parse(DENYLIST_TEXT)


def rules_hit(text: str, origin: str | None = None, deny: Denylist | None = None) -> list[str]:
    scanner = Scanner(denylist=deny)
    scanner.scan_text(text, "sample", origin=origin)
    return [hit.rule for hit in scanner.hits]


def run_guard(
    args: list[str], env: dict[str, str] | None = None, capsys: Any = None
) -> tuple[int, str]:
    code = leak_guard.main(args, env or {})
    output = ""
    if capsys is not None:
        captured = capsys.readouterr()
        output = captured.out + captured.err
    return code, output


# ---------------------------------------------------------------- generic patterns


@pytest.mark.parametrize(
    ("text", "rule"),
    [
        ("C" + ":" + BACKSLASH + "Users" + BACKSLASH + "x", "windows-path"),
        ("open d" + ":/data/file.txt", "windows-path"),
        (BACKSLASH * 2 + "fileserver" + BACKSLASH + "share", "unc-path"),
        ("/" + "Users/alex/project", "macos-home-path"),
        ("cd /c/" + "Users/alex", "macos-home-path"),
        ("/" + "home/alex/project", "linux-home-path"),
        ("%" + "userprofile" + "%" + BACKSLASH + "x", "userprofile-variable"),
        ("~" + "/projects", "home-tilde-path"),
        ("~" + BACKSLASH + "projects", "home-tilde-path"),
        ("alex" + AT + "gmail.com", "email-address"),
        ("someone" + AT + "github.com", "email-address"),
        ("x" + AT + "example.co", "email-address"),
        ("a" + AT + "example.com.evil.org", "email-address"),
        ("see " + "anthropic" + ".com", "forbidden-domain"),
        ("Claude" + ".AI/x", "forbidden-domain"),
        ("Generated" + "  with a tool", "generated-footer"),
        ("session" + "_" + "a" * 24, "session-id"),
        ("a " + chr(0x2014) + " b", "dash-character"),
        ("2" + chr(0x2013) + "3", "dash-character"),
        (pem("OPENSSH "), "private-key"),
        (pem(""), "private-key"),
        (pem("RSA ").replace("\n", "\\n"), "private-key"),
        ("ghp" + "_" + noise(36), "github-token"),
        ("gho" + "_" + noise(36, "b"), "github-token"),
        ("github" + "_pat_" + noise(40, "c"), "github-token"),
        ("sk" + "-" + "proj_" + noise(30, "d"), "api-key"),
        ("xox" + "b-" + "1234567890-abc", "slack-token"),
        ("xox" + "p-" + "1234567890-abc", "slack-token"),
        ("AKIA" + hashlib.sha256(b"k").hexdigest()[:16].upper(), "aws-access-key"),
    ],
)
def test_generic_rule_catches(text: str, rule: str) -> None:
    assert rule in rules_hit(text)


@pytest.mark.parametrize(
    "text",
    [
        "https" + "://example.org/page",
        "file" + ":///etc/hosts",
        "error" + ":" + BACKSLASH + "n",
        "release notes for v1.0",
        "317904428+Name" + AT + "users.noreply.github.com",
        "noreply" + AT + "github.com",
        "support" + AT + "github.com",
        "x" + AT + "noreply.github.com",
        "dana" + AT + "example.com",
        "jordan" + AT + "example.net",
        "riley" + AT + "example.org",
        "a" + AT + "host.example",
        "a" + AT + "host.test",
        "a" + AT + "host.invalid",
        "@field_validator decorators and actions/checkout" + AT + "3d3c42e5",
        "task" + "-" + "x" * 30,
        "AKIA" + "ABCDEFGH123456789",
        "session" + "_" + "short",
        "a - b, plain hyphen",
        "regex [A-Za-z]" + ":" + "[x]",
    ],
)
def test_generic_rules_ignore_safe_text(text: str) -> None:
    assert rules_hit(text) == []


def test_runner_home_is_allowed_only_in_workflows() -> None:
    sample = "cd /" + "home/runner/work"
    assert rules_hit(sample, origin=".github/workflows/ci.yml") == []
    assert rules_hit(sample, origin="docs/notes.md") == ["linux-home-path"]
    other = "/" + "home/alex"
    assert rules_hit(other, origin=".github/workflows/ci.yml") == ["linux-home-path"]


def test_email_allowlist_rules() -> None:
    assert email_allowed("Noreply" + AT + "GitHub.com")
    assert not email_allowed("billing" + AT + "github.com")
    assert not email_allowed("a" + AT + "example.com.evil.org")


def test_mask_hides_the_middle() -> None:
    assert mask("abc") == "***"
    secret = "C" + ":/" + "Users/someone/Desktop"
    assert mask(secret) == "C:****op"
    assert "someone" not in mask(secret)


def test_generic_hit_reports_line_and_masked_match() -> None:
    scanner = Scanner(denylist=None)
    scanner.scan_text("ok\nmail " + "alex" + AT + "gmail.com\n", "notes.md")
    [hit] = scanner.hits
    assert hit.render(show_match=True) == "notes.md:2: email-address: al****om"
    assert hit.render(show_match=False) == "notes.md:2: email-address"


# ---------------------------------------------------------------- denylist


def test_denylist_blocks_and_never_prints_the_identifier(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sample = tmp_path / "body.md"
    sample.write_text(f"Thanks, {SECRET_WORD.title()}!\nsecond line\n", encoding="utf-8")
    code, output = run_guard(
        ["--root", str(tmp_path), "--text", str(sample)],
        {"LEAK_DENYLIST": DENYLIST_TEXT},
        capsys,
    )
    assert code == 1
    assert "body.md:1: denylist: private identifier (hash #1)" in output
    assert SECRET_WORD not in output.lower()


def test_denylist_matches_whole_word_windows_only() -> None:
    deny = denylist()
    assert list(deny.matches(f"a {SECRET_WORD} b")) == [(1, 1)]
    assert list(deny.matches(f"{SECRET_WORD}y and pre{SECRET_WORD}")) == []
    assert list(deny.matches("Quill   MARROW")) == [(1, 2)]
    assert list(deny.matches("quill\nmarrow wrapped")) == [(1, 2)]
    assert list(deny.matches("quill and marrow")) == []
    assert list(deny.matches(f"path/to/{SECRET_WORD}/file")) == [(1, 1)]
    assert list(deny.matches(f'"{SECRET_WORD}",')) == [(1, 1)]
    assert list(deny.matches(f"x\ny\n({SECRET_WORD}) {SECRET_WORD}")) == [(3, 1)]


def test_denylist_digest_follows_the_documented_formula() -> None:
    deny = denylist()
    assert deny.digest(f"  {SECRET_WORD.upper()} ") == digest(SECRET_WORD)
    assert deny.max_words == 3
    assert deny.entries[digest(SECRET_PAIR)] == 2


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("maxwords 2\nhash " + "0" * 64, "exactly one salt"),
        ("salt ab\nhash " + "0" * 64, "exactly one salt"),
        ("salt ab\nmaxwords 2\n", "no hash lines"),
        ("salt ab\nsalt cd\nmaxwords 2", "line 2 is not a valid entry"),
        ("salt ab\nmaxwords 0", "line 2 is not a valid entry"),
        ("salt ab\nmaxwords 2\nplain private text", "line 3 is not a valid entry"),
        ("salt zz\nmaxwords 2", "line 1 is not a valid entry"),
    ],
)
def test_denylist_parse_errors_do_not_echo_content(text: str, message: str) -> None:
    with pytest.raises(GuardSetupError, match=message) as caught:
        Denylist.parse(text)
    assert "private" not in str(caught.value)


def test_denylist_sources(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    sample = repo / "a.txt"
    sample.write_text(SECRET_WORD + "\n", encoding="utf-8")
    args = ["--root", str(repo), "--text", str(sample)]

    named = tmp_path / "named.hashes"
    named.write_text(DENYLIST_TEXT, encoding="utf-8")
    code, output = run_guard(args, {"LEAK_DENYLIST_FILE": str(named)}, capsys)
    assert (code, "from LEAK_DENYLIST_FILE" in output) == (1, True)

    code, output = run_guard(args, {"LEAK_DENYLIST_FILE": str(tmp_path / "nope")}, capsys)
    assert code == 2
    assert "does not name a readable file" in output

    planning = tmp_path / "_planning"
    planning.mkdir()
    (planning / "private-denylist.hashes").write_text(DENYLIST_TEXT, encoding="utf-8")
    code, output = run_guard(args, {"LEAK_DENYLIST": "  "}, capsys)
    assert (code, "from private planning file" in output) == (1, True)


def test_missing_denylist_warns_locally_and_fails_in_ci(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sample = tmp_path / "a.txt"
    sample.write_text("clean\n", encoding="utf-8")
    args = ["--root", str(tmp_path), "--text", str(sample)]
    code, output = run_guard(args, {}, capsys)
    assert code == 0
    assert "WARNING: no private denylist" in output
    code, output = run_guard(args, {"CI": "true"}, capsys)
    assert code == 2
    assert "a denylist is required in CI" in output


def test_generic_match_holding_a_private_identifier_is_fully_masked() -> None:
    scanner = Scanner(denylist=denylist())
    scanner.scan_text("C" + ":/" + "Users/" + SECRET_WORD + "/x", "a.md")
    shown = {hit.rule: hit.shown for hit in scanner.hits}
    assert shown["windows-path"] == "****"
    assert shown["denylist"] == "private identifier (hash #1)"


# ---------------------------------------------------------------- allowlist


def test_allowlist_accepts_exact_match_or_exact_line() -> None:
    path = "/" + "home/alex"
    allow = Allowlist.parse(f"# comment\n\n{path} # reason: documented example\n", None)
    scanner = Scanner(denylist=None, allowlist=allow)
    scanner.scan_text(f"see {path}\nsee {path}/more\n", "a.md")
    assert [hit.location for hit in scanner.hits] == ["a.md:2"]

    line = "x = 'C" + ":/" + "data'"
    allow = Allowlist.parse(f"{line} # reason: detector pattern definition\n", None)
    scanner = Scanner(denylist=None, allowlist=allow)
    scanner.scan_text(f"  {line}  \ny = 'C" + ":/" + "data'\n", "a.py")
    assert [hit.location for hit in scanner.hits] == ["a.py:2"]


def test_allowlist_file_does_not_flag_its_own_entries() -> None:
    path = "/" + "home/alex"
    text = f"{path} # reason: documented example\n"
    allow = Allowlist.parse(text, None)
    scanner = Scanner(denylist=None, allowlist=allow)
    scanner.scan_text(text, leak_guard.ALLOW_FILE, origin=leak_guard.ALLOW_FILE)
    assert scanner.hits == []


@pytest.mark.parametrize(
    "line",
    ["no reason here", "value #", "value # ", "value #reason"],
)
def test_allowlist_requires_a_reason(line: str) -> None:
    with pytest.raises(GuardSetupError, match="line 1"):
        Allowlist.parse(line, None)


def test_allowlist_can_never_hold_a_private_identifier(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(GuardSetupError, match=r"hash #1"):
        Allowlist.parse(f"{SECRET_WORD} # reason: test\n", denylist())
    with pytest.raises(GuardSetupError, match=r"hash #2"):
        Allowlist.parse("x # reason: about Quill Marrow\n", denylist())

    (tmp_path / leak_guard.ALLOW_FILE).write_text(f"{SECRET_WORD} # reason: x\n", "utf-8")
    sample = tmp_path / "a.txt"
    sample.write_text("clean\n", encoding="utf-8")
    code, output = run_guard(
        ["--root", str(tmp_path), "--text", str(sample)], {"LEAK_DENYLIST": DENYLIST_TEXT}, capsys
    )
    assert code == 2
    assert SECRET_WORD not in output


def test_allowlist_never_neutralizes_a_denylist_hit() -> None:
    # Built directly, bypassing the parser's own refusal, to show the scanner ignores it too.
    line = f"note about {SECRET_WORD}"
    scanner = Scanner(denylist=denylist(), allowlist=Allowlist(frozenset({line, SECRET_WORD})))
    scanner.scan_text(line, "a.md")
    assert [hit.rule for hit in scanner.hits] == ["denylist"]


# ---------------------------------------------------------------- tree, history, images


def git(repo: Path, *args: str) -> None:
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=ci" + AT + "example.com",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.autocrlf=false",
            *args,
        ],
        cwd=repo,
        check=True,
        capture_output=True,
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q")
    return root


PNG_HEADER = bytes([0x89]) + b"PNG\r\n\x1a\n"


def test_tree_scan(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (repo / ".gitignore").write_text("ignored.txt\n", encoding="utf-8")
    (repo / "clean.md").write_text("nothing to see\n", encoding="utf-8")
    (repo / "ignored.txt").write_text("alex" + AT + "gmail.com\n", encoding="utf-8")
    (repo / "untracked.md").write_text("contact alex" + AT + "gmail.com\n", encoding="utf-8")
    (repo / "plain.png").write_bytes(PNG_HEADER + b"\0\0IDAT")
    (repo / "photo.jpg").write_bytes(b"\xff\xd8\xff\xe1\0\x10Exif\0\0rest")
    (repo / "icon.svg").write_text("<svg><x:xmpmeta/></svg>\n", encoding="utf-8")
    (repo / "blob.bin").write_bytes(b"\0\x01" + ("alex" + AT + "gmail.com").encode())
    (repo / f"{SECRET_WORD}.md").write_text("fine\n", encoding="utf-8")
    git(repo, "add", "clean.md", ".gitignore", "plain.png", "photo.jpg", "icon.svg")
    git(repo, "add", "blob.bin", f"{SECRET_WORD}.md")
    git(repo, "commit", "-q", "-m", "init")
    (repo / "clean.md").unlink()

    code, output = run_guard(
        ["--root", str(repo), "--tree"], {"LEAK_DENYLIST": DENYLIST_TEXT}, capsys
    )
    assert code == 1
    assert "untracked.md:1: email-address" in output
    assert "ignored.txt" not in output
    assert "notice: blob.bin: binary, not scanned" in output
    assert "blob.bin:" not in output.replace("notice: blob.bin: binary", "")
    assert "notice: plain.png: image, needs manual review" in output
    assert "plain.png: image-metadata" not in output
    assert "photo.jpg: image-metadata: metadata present" in output
    assert "icon.svg: image-metadata" in output
    assert "<path withheld " in output
    assert "(file name):1: denylist: private identifier (hash #1)" in output
    assert SECRET_WORD not in output.lower()
    assert "hit(s) (tree; denylist 2 entries from LEAK_DENYLIST)" in output


def test_history_scan(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (repo / "a.md").write_text("one\ntwo\n", encoding="utf-8")
    git(repo, "add", "a.md")
    git(repo, "commit", "-q", "-m", "first")
    (repo / "a.md").write_text("one\ntwo\nthree " + "alex" + AT + "gmail.com\n", "utf-8")
    (repo / "pic.png").write_bytes(PNG_HEADER + b"eXIf data")
    git(repo, "add", "a.md", "pic.png")
    git(repo, "commit", "-q", "-m", f"second\n\nthanks {SECRET_WORD}")
    git(repo, "rm", "-q", "a.md")
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Alex",
            "-c",
            "user.email=alex" + AT + "gmail.com",
            "commit",
            "-q",
            "-m",
            "third",
        ],
        cwd=repo,
        check=True,
        capture_output=True,
    )

    code, output = run_guard(
        ["--root", str(repo), "--history"], {"LEAK_DENYLIST": DENYLIST_TEXT}, capsys
    )
    assert code == 1
    lines = output.splitlines()
    assert any(line.endswith(" a.md:3: email-address: al****om") for line in lines)
    assert any(" message:3: denylist: private identifier (hash #1)" in line for line in lines)
    assert any(" author email:1: email-address" in line for line in lines)
    assert any(" committer email:1: email-address" in line for line in lines)
    assert any("history blob pic.png: image-metadata" in line for line in lines)
    assert SECRET_WORD not in output


def test_all_scope_runs_tree_and_history(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (repo / "a.md").write_text("fine\n", encoding="utf-8")
    git(repo, "add", "a.md")
    git(repo, "commit", "-q", "-m", "clean")
    code, output = run_guard(
        ["--root", str(repo), "--all"], {"LEAK_DENYLIST": DENYLIST_TEXT}, capsys
    )
    assert code == 0
    assert "leak guard: clean (tree, history; denylist 2 entries from LEAK_DENYLIST)" in output


def test_parse_patch_tracks_new_file_line_numbers() -> None:
    patch = "\n".join(
        [
            "diff --git a/x.md b/x.md",
            "index 1111111..aaaaaaa 100644",
            "--- a/x.md",
            "+++ b/x.md",
            "@@ -1,0 +5,2 @@",
            "+five",
            "+six",
            " seven",
            "-gone",
            "+eight",
            "+++ looks like a header but is an added line",
            "diff --git a/old.md b/old.md",
            "--- a/old.md",
            "+++ /dev/null",
            "@@ -1 +0,0 @@",
            "-removed",
            "diff --git a/q b/q",
            '+++ "b/sp ace.md"',
            "@@ -0,0 +1 @@",
            "+new",
            "diff --git a/b.bin b/b.bin",
            "index 0000000..bbbbbbb",
            "Binary files /dev/null and b/b.bin differ",
        ]
    )
    files, shown_as_text = parse_patch(patch)
    assert [(f.path, f.blob, f.lines, f.numbers) for f in files] == [
        (
            "x.md",
            "aaaaaaa",
            ["five", "six", "eight", "++ looks like a header but is an added line"],
            [5, 6, 8, 9],
        ),
        ("sp ace.md", None, ["new"], [1]),
    ]
    assert shown_as_text == {"aaaaaaa"}


# ---------------------------------------------------------------- pull request text


def event_file(tmp_path: Path, payload: dict[str, Any]) -> str:
    path = tmp_path / "event.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


def test_pr_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    calls: list[str] = []
    many = [{"id": index, "body": "fine"} for index in range(100)]

    def fake_get(url: str, token: str) -> Any:
        calls.append(url)
        assert token == "t0ken"
        if url.endswith("/pulls/7"):
            return {"title": "Phase work", "body": "mail " + "alex" + AT + "gmail.com"}
        if "/issues/7/comments" in url:
            return many if url.endswith("page=1") else [{"id": 900, "body": SECRET_WORD}]
        if "/reviews" in url:
            return [{"id": 5, "body": None}]
        return [{"id": 6, "body": "C" + ":" + BACKSLASH + "x"}]

    monkeypatch.setattr(leak_guard, "http_get_json", fake_get)
    env = {
        "GITHUB_TOKEN": "t0ken",
        "GITHUB_REPOSITORY": "owner/repo",
        "GITHUB_EVENT_PATH": event_file(tmp_path, {"pull_request": {"number": 7}}),
        "GITHUB_API_URL": "https://api.example.com",
        "LEAK_DENYLIST": DENYLIST_TEXT,
    }
    code, output = run_guard(["--root", str(tmp_path), "--pr"], env, capsys)
    assert code == 1
    assert "pr body:1: email-address" in output
    assert "pr review comment 6:1: windows-path" in output
    assert "pr comment 900:1: denylist: private identifier (hash #1)" in output
    assert SECRET_WORD not in output
    assert calls[0] == "https://api.example.com/repos/owner/repo/pulls/7"
    assert sum("/issues/7/comments" in url for url in calls) == 2


def test_pr_scan_setup_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    base = {"LEAK_DENYLIST": DENYLIST_TEXT}
    args = ["--root", str(tmp_path), "--pr"]
    code, output = run_guard(args, base, capsys)
    assert (code, "needs GITHUB_TOKEN" in output) == (2, True)

    env = {
        **base,
        "GITHUB_TOKEN": "t",
        "GITHUB_REPOSITORY": "o/r",
        "GITHUB_EVENT_PATH": event_file(tmp_path, {"push": {}}),
    }
    code, output = run_guard(args, env, capsys)
    assert (code, "only on pull request events" in output) == (2, True)

    env["GITHUB_EVENT_PATH"] = event_file(tmp_path, {"pull_request": {"number": 1}})
    monkeypatch.setattr(leak_guard, "http_get_json", lambda url, token: {"title": "t"})
    code, output = run_guard(args, env, capsys)
    assert (code, "unexpected response" in output) == (2, True)


def test_http_get_json_sends_auth_header(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    class Response:
        def __enter__(self) -> Response:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self) -> bytes:
            return b'{"ok": true}'

    def fake_open(request: Any, timeout: float) -> Response:
        seen["auth"] = request.get_header("Authorization")
        seen["timeout"] = timeout
        return Response()

    monkeypatch.setattr(urllib.request, "urlopen", fake_open)
    assert leak_guard.http_get_json("https://api.example.com/x", "abc") == {"ok": True}
    assert seen == {"auth": "Bearer abc", "timeout": 30}


# ---------------------------------------------------------------- setup and exit codes


def test_usage_errors(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, output = run_guard(["--root", str(tmp_path)], {}, capsys)
    assert (code, "choose at least one scope" in output) == (2, True)
    code, output = run_guard(
        ["--root", str(tmp_path), "--text", str(tmp_path / "missing.md")], {}, capsys
    )
    assert (code, "--text file not found: missing.md" in output) == (2, True)


def test_git_failure_and_os_errors_exit_2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    plain = tmp_path / "plain"
    plain.mkdir()
    code, output = run_guard(["--root", str(plain), "--history"], {}, capsys)
    assert (code, "git log failed" in output) == (2, True)

    def broken(*args: object) -> None:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(leak_guard, "scan_tree", broken)
    code, output = run_guard(["--root", str(plain), "--tree"], {}, capsys)
    assert (code, "error: Permission denied" in output) == (2, True)


def test_find_root_and_display_name(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*args: object) -> bytes:
        raise GuardSetupError("not a repository")

    monkeypatch.setattr(leak_guard, "run_git", fail)
    assert leak_guard.find_root(tmp_path) == Path(leak_guard.__file__).resolve().parents[1]
    assert display_name(tmp_path / "a" / "b.md", tmp_path) == "a/b.md"
    assert display_name(tmp_path.parent / "c.md", tmp_path) == "c.md"


def test_repository_is_clean_under_its_own_guard(capsys: pytest.CaptureFixture[str]) -> None:
    # Uses the private list when it is available locally, generic rules only otherwise.
    code, output = run_guard(["--tree"], {}, capsys)
    assert code == 0, output


# ---------------------------------------------------------------- audit follow-ups


@pytest.mark.parametrize(
    ("text", "rule"),
    [
        (BACKSLASH * 4 + "fileserver" + BACKSLASH * 2 + "share", "unc-path"),
        ("cd /c/" + "users/alex", "windows-home-path"),
        ("/mnt/c/" + "Users/alex", "windows-home-path"),
        (pem("PGP ", " BLOCK"), "private-key"),
    ],
)
def test_audit_pattern_gaps_are_closed(text: str, rule: str) -> None:
    assert rule in rules_hit(text)


def test_runner_home_exception_rejects_parent_segments() -> None:
    sample = "/" + "home/runner/../alex"
    assert rules_hit(sample, origin=".github/workflows/ci.yml") == ["linux-home-path"]


def test_safe_label_withholds_leaky_paths() -> None:
    scanner = Scanner(denylist=denylist())
    assert scanner.safe_label("docs/a.md") == "docs/a.md"
    withheld = scanner.safe_label(f"docs/{SECRET_WORD}.md")
    assert withheld.startswith("<path withheld ")
    assert SECRET_WORD not in withheld
    assert scanner.safe_label("alex" + AT + "gmail.com.txt").startswith("<path withheld ")


def test_decode_text_handles_byte_order_marks() -> None:
    sample = "mail " + "alex" + AT + "gmail.com"
    assert leak_guard.decode_text(b"\xff\xfe" + sample.encode("utf-16-le")) == sample
    assert leak_guard.decode_text(b"\xfe\xff" + sample.encode("utf-16-be")) == sample
    assert leak_guard.decode_text(b"\xff\xfe\0\0" + sample.encode("utf-32-le")) == sample
    assert leak_guard.decode_text(b"\0\0\xfe\xff" + sample.encode("utf-32-be")) == sample
    assert leak_guard.decode_text(b"x\0y") is None


def test_history_scans_blobs_the_diff_hides_and_tags(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    address = "alex" + AT + "gmail.com"
    (repo / ".gitattributes").write_text("*.dat -diff\n", encoding="utf-8")
    (repo / "hidden.dat").write_text(f"contact {address}\n", encoding="utf-8")
    (repo / "wide.txt").write_bytes(b"\xff\xfe" + f"wide {address}".encode("utf-16-le"))
    (repo / f"{SECRET_WORD}-notes.md").write_text("fine\n", encoding="utf-8")
    (repo / "blob.bin").write_bytes(b"\0\x01\x02")
    git(repo, "add", ".")
    git(repo, "commit", "-q", "-m", "add files")
    git(repo, "rm", "-q", "hidden.dat", "wide.txt", f"{SECRET_WORD}-notes.md")
    git(repo, "commit", "-q", "-m", "remove them")
    git(repo, "tag", "-a", "v1", "-m", f"release by {address}")
    git(repo, "tag", "plain")

    code, output = run_guard(
        ["--root", str(repo), "--history"], {"LEAK_DENYLIST": DENYLIST_TEXT}, capsys
    )
    assert code == 1
    assert "history blob hidden.dat:1: email-address" in output
    assert "history blob wide.txt:1: email-address" in output
    assert "tag v1 message:1: email-address" in output
    assert "notice: history blob blob.bin: binary, not scanned" in output
    assert "(file name):1: denylist: private identifier (hash #1)" in output
    assert SECRET_WORD not in output.lower()


def test_pr_number_from_comment_event(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fake_get(url: str, token: str) -> Any:
        return {"title": "t", "body": ""} if url.endswith("/pulls/3") else []

    monkeypatch.setattr(leak_guard, "http_get_json", fake_get)
    env = {
        "GITHUB_TOKEN": "t",
        "GITHUB_REPOSITORY": "o/r",
        "LEAK_DENYLIST": DENYLIST_TEXT,
        "GITHUB_EVENT_PATH": event_file(
            tmp_path, {"issue": {"number": 3, "pull_request": {"url": "x"}}}
        ),
    }
    code, output = run_guard(["--root", str(tmp_path), "--pr"], env, capsys)
    assert (code, "clean (pr;" in output) == (0, True)

    env["GITHUB_EVENT_PATH"] = event_file(tmp_path, {"issue": {"number": 4}})
    code, output = run_guard(["--root", str(tmp_path), "--pr"], env, capsys)
    assert (code, "only on pull request events" in output) == (2, True)


def test_value_errors_exit_2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def broken(*args: object) -> None:
        raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")

    monkeypatch.setattr(leak_guard, "scan_tree", broken)
    code, output = run_guard(["--root", str(tmp_path), "--tree"], {}, capsys)
    assert (code, "cannot process input (UnicodeDecodeError)" in output) == (2, True)


def test_git_errors_are_redacted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = "C" + ":/" + "Users/someone/repo"

    class Result:
        returncode = 128
        stdout = b""
        stderr = f"fatal: not a git repository: {path}\nmore".encode()

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: Result())
    with pytest.raises(GuardSetupError) as caught:
        leak_guard.run_git(tmp_path, "status")
    assert "someone" not in str(caught.value)
    assert "more" not in str(caught.value)

    Result.stderr = b""
    with pytest.raises(GuardSetupError, match="exit code 128"):
        leak_guard.run_git(tmp_path, "status")


def test_read_objects_fails_closed(tmp_path: Path) -> None:
    assert list(leak_guard.read_objects(tmp_path, [])) == []
    with pytest.raises(GuardSetupError, match="cat-file failed"):
        list(leak_guard.read_objects(tmp_path, ["0" * 40]))


# ---------------------------------------------------------------- structure, scope, baseline


@pytest.mark.parametrize(
    "text",
    [
        "-" * 5 + "BEGIN RSA " + "PRIVATE KEY" + "-" * 5,
        "-" * 5 + "BEGIN " + "PRIVATE KEY" + "-" * 5 + "\n" + "A" * 64 + "\n",
        "AKIA" + "IOSFODNN7" + "EXAMPLE",
        "ghp" + "_" + "a1" * 18,
        "sk" + "-" + "proj_" + "x" * 30,
        "github" + "_pat_" + "dummy" + noise(30),
        "Evidence regen" + "erated with this code",
        "C" + ":/" + "Program Files/Google/Chrome/Application/chrome.exe",
        "C" + ":" + BACKSLASH + "Windows" + BACKSLASH + "win.ini",
        "C" + ":/" + "path/to/chrome.exe",
        "auditor" + AT + "exfil.example.com",
    ],
)
def test_structured_rules_ignore_placeholders_and_system_paths(text: str) -> None:
    assert rules_hit(text) == []


def test_entropy_and_looks_secret() -> None:
    assert leak_guard.entropy("") == 0.0
    assert leak_guard.entropy("aaaa") == 0.0
    assert leak_guard.entropy("abcd") == 2.0
    assert leak_guard.looks_secret(noise(32))
    assert not leak_guard.looks_secret("a" * 32)
    assert not leak_guard.looks_secret("abcdefghijklmnopqrstuvwxyzabcdef")
    assert not leak_guard.looks_secret(noise(20) + "EXAMPLE")


def test_windows_paths_are_scoped_in_fixtures_and_docs() -> None:
    probe = "C" + ":" + BACKSLASH + "x"
    personal = "C" + ":" + BACKSLASH + "Users" + BACKSLASH + "alex" + BACKSLASH + "a.txt"
    for origin in ("tests/test_a.py", "docs/guide.md", "pkg/tests/data.json", "a/fixtures/x.txt"):
        assert rules_hit(probe, origin=origin) == []
        assert rules_hit(personal, origin=origin) == ["windows-path"]
    for other in ("src/app.py", "tests.py", None):
        assert rules_hit(probe, origin=other) == ["windows-path"]
    assert not leak_guard.is_fixture_path("README.md")


def test_ci_output_shows_rule_and_location_only(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sample = tmp_path / "a.md"
    address = "alex" + AT + "gmail.com"
    sample.write_text(f"mail {address}\n{SECRET_WORD}\n", encoding="utf-8")
    env = {"CI": "true", "LEAK_DENYLIST": DENYLIST_TEXT}
    code, output = run_guard(["--root", str(tmp_path), "--text", str(sample)], env, capsys)
    assert code == 1
    assert "a.md:1: email-address\n" in output
    assert "al****om" not in output
    assert "a.md:2: denylist: private identifier (hash #1)" in output
    assert SECRET_WORD not in output


def png(*chunks: tuple[bytes, bytes]) -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(kind + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", crc)

    body = [(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0))]
    body += list(chunks)
    body += [(b"IDAT", zlib.compress(b"\0\0")), (b"IEND", b"")]
    return leak_guard.PNG_SIGNATURE + b"".join(chunk(kind, data) for kind, data in body)


def test_png_metadata_detection_and_stripping(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    clean = png((b"sRGB", b"\0"))
    credentials = png((b"caBX", b"jumb provenance"), (b"tEXt", b"Software\0tool"))
    assert not leak_guard.image_metadata(clean)
    assert leak_guard.image_metadata(credentials)
    assert leak_guard.image_metadata(png((b"iTXt", b"x")))
    assert leak_guard.image_metadata(b"\xff\xd8 jumbf c2pa manifest")
    stripped, removed = leak_guard.strip_png(credentials)
    assert removed == 2
    assert stripped == png()
    assert not leak_guard.image_metadata(stripped)

    target = tmp_path / "shot.png"
    target.write_bytes(credentials)
    code, output = run_guard(["--root", str(tmp_path), "--strip-png", str(target)], {}, capsys)
    assert code == 0
    assert "stripped shot.png: 2 metadata chunk(s) removed" in output
    assert target.read_bytes() == png()

    target.write_bytes(b"not a png")
    code, output = run_guard(["--root", str(tmp_path), "--strip-png", str(target)], {}, capsys)
    assert (code, "not a PNG file" in output) == (2, True)


def head(repo: Path) -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True, check=True
    ).stdout.strip()


def test_baseline_parse_rules() -> None:
    sha = "a" * 40
    good = f"# fingerprints only\ncutoff {sha}\n{sha} dash-character 3 docs/x.md\n"
    good += f"{sha} dash-character 1 :message\n{sha} windows-path 2 dir with space/a b.md\n"
    baseline = Baseline.parse(good, denylist())
    assert baseline.cutoff == sha
    assert baseline.covers((sha, "windows-path", 2, "dir with space/a b.md"))
    assert not baseline.covers((sha, "windows-path", 3, "dir with space/a b.md"))
    bad = {
        f"cutoff {sha}\n{sha} denylist 1 a.md": "denylist hits can never be baselined",
        f"cutoff {sha}\n{sha} email-address 1 :author email": "email-address hits can never",
        f"cutoff {sha}\n{sha} no-such-rule 1 a.md": "unknown rule",
        f"cutoff {sha}\n{sha} dash-character x a.md": "line a number",
        f"cutoff {sha}\nabc dash-character 1 a.md": "commit must be 40 hex",
        f"cutoff {sha}\n{sha} dash-character 1 /etc/a.md": "repository-relative",
        f"cutoff {sha}\n{sha} dash-character 1 ../a.md": "repository-relative",
        f"cutoff {sha}\n{sha} dash-character 1 a" + BACKSLASH + "b.md": "repository-relative",
        f"cutoff {sha}\n{sha} dash-character 1 C" + ":/a.md": "repository-relative",
        f"cutoff {sha}\n{sha} dash-character 1": "use '<commit>",
        f"cutoff {sha}\n{sha} dash-character 1 docs/{SECRET_WORD}.md": "private identifier",
        f"{sha} dash-character 1 a.md": "needs a cutoff",
        f"cutoff {sha}\ncutoff {sha}": "one 'cutoff",
        "cutoff abc": "one 'cutoff",
    }
    for text, message in bad.items():
        with pytest.raises(GuardSetupError, match=message):
            Baseline.parse(text, denylist())


def test_history_baseline_suppresses_only_pinned_generic_hits(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    dash = chr(0x2014)
    (repo / "a.md").write_text(f"one {dash} two\n{SECRET_WORD} {dash}\n", encoding="utf-8")
    git(repo, "add", "a.md")
    git(repo, "commit", "-q", "-m", "old")
    old = head(repo)
    env = {"LEAK_DENYLIST": DENYLIST_TEXT}

    code, output = run_guard(["--root", str(repo), "--emit-baseline", "HEAD"], env, capsys)
    assert code == 0
    lines = output.splitlines()
    assert lines[0] == f"cutoff {old}"
    # Line 2 also holds a private identifier, so it is never a candidate.
    assert lines[1:] == [f"{old} dash-character 1 a.md"]
    assert SECRET_WORD not in output
    (repo / ".leakguard-baseline").write_text("\n".join(lines) + "\n", encoding="utf-8")

    (repo / "b.md").write_text(f"new {dash}\n", encoding="utf-8")
    git(repo, "add", "b.md", ".leakguard-baseline")
    git(repo, "commit", "-q", "-m", "new")

    code, output = run_guard(["--root", str(repo), "--history"], env, capsys)
    assert code == 1
    assert f"commit {old[:12]} a.md:1: dash-character" not in output
    assert f"commit {old[:12]} a.md:2: dash-character" in output
    assert f"commit {old[:12]} a.md:2: denylist: private identifier (hash #1)" in output
    assert " b.md:1: dash-character" in output
    assert "1 baselined" in output

    # The working tree is never covered by the baseline.
    code, output = run_guard(["--root", str(repo), "--tree"], env, capsys)
    assert "a.md:1: dash-character" in output

    # A range after the cutoff sees only its own commits.
    code, output = run_guard(["--root", str(repo), "--range", f"{old}..HEAD"], env, capsys)
    assert code == 1
    assert " b.md:1: dash-character" in output
    assert " a.md" not in output
    assert "(range;" in output


def test_baseline_entries_must_precede_the_cutoff(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (repo / "a.md").write_text("x\n", encoding="utf-8")
    git(repo, "add", "a.md")
    git(repo, "commit", "-q", "-m", "one")
    first = head(repo)
    git(repo, "commit", "-q", "--allow-empty", "-m", "two")
    second = head(repo)
    baseline = repo / ".leakguard-baseline"
    env = {"LEAK_DENYLIST": DENYLIST_TEXT}

    baseline.write_text(f"cutoff {first}\n{second} dash-character 1 a.md\n", "utf-8")
    code, output = run_guard(["--root", str(repo), "--history"], env, capsys)
    assert (code, "is not at or before the cutoff" in output) == (2, True)

    baseline.write_text(f"cutoff {'b' * 40}\n", "utf-8")
    code, output = run_guard(["--root", str(repo), "--history"], env, capsys)
    assert (code, "cutoff commit is not in this clone" in output) == (2, True)

    # The baseline is not even read for scopes it cannot apply to.
    code, output = run_guard(["--root", str(repo), "--tree"], env, capsys)
    assert code == 0


def test_history_image_metadata_is_fingerprinted_and_baselinable(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (repo / "shot.png").write_bytes(png((b"caBX", b"provenance")))
    git(repo, "add", "shot.png")
    git(repo, "commit", "-q", "-m", "add image")
    sha = head(repo)
    env = {"LEAK_DENYLIST": DENYLIST_TEXT}
    code, output = run_guard(["--root", str(repo), "--emit-baseline", sha], env, capsys)
    assert f"{sha} image-metadata 0 shot.png" in output.splitlines()
    (repo / ".leakguard-baseline").write_text(output, encoding="utf-8")
    code, output = run_guard(["--root", str(repo), "--history"], env, capsys)
    assert (code, "1 baselined" in output) == (0, True)


def test_range_must_be_a_range(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, output = run_guard(["--root", str(tmp_path), "--range", "HEAD"], {}, capsys)
    assert (code, "--range takes A..B" in output) == (2, True)


# ---------------------------------------------------------------- review follow-ups


def test_range_reads_allowlist_and_baseline_from_the_base_commit(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (repo / "a.md").write_text("fine\n", encoding="utf-8")
    git(repo, "add", "a.md")
    git(repo, "commit", "-q", "-m", "base")
    base = head(repo)
    env = {"LEAK_DENYLIST": DENYLIST_TEXT}

    address = "alex" + AT + "gmail.com"
    (repo / "b.md").write_text(f"{address}\n", encoding="utf-8")
    git(repo, "add", "b.md")
    git(repo, "commit", "-q", "-m", "leak")
    leak = head(repo)
    # The same change tries to approve its own leak, both ways.
    (repo / ".leakguard-allow").write_text(f"{address} # reason: x\n", encoding="utf-8")
    (repo / ".leakguard-baseline").write_text(
        f"cutoff {leak}\n{leak} dash-character 1 b.md\n", encoding="utf-8"
    )
    git(repo, "add", ".leakguard-allow", ".leakguard-baseline")
    git(repo, "commit", "-q", "-m", "approve")

    code, output = run_guard(["--root", str(repo), "--range", f"{base}..HEAD"], env, capsys)
    assert code == 1
    assert f"commit {leak[:12]} b.md:1: email-address" in output
    assert "baselined" not in output

    # Once the allowlist is on the base, it applies to later ranges.
    git(repo, "commit", "-q", "--allow-empty", "-m", "later")
    code, output = run_guard(["--root", str(repo), "--range", "HEAD~1..HEAD"], env, capsys)
    assert code == 0


def test_history_baseline_cutoff_must_be_on_the_default_branch(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (repo / "a.md").write_text("x\n", encoding="utf-8")
    git(repo, "add", "a.md")
    git(repo, "commit", "-q", "-m", "main")
    git(repo, "switch", "-q", "-c", "side")
    git(repo, "commit", "-q", "--allow-empty", "-m", "side")
    side = head(repo)
    git(repo, "switch", "-q", "-")
    (repo / ".leakguard-baseline").write_text(f"cutoff {side}\n", encoding="utf-8")
    code, output = run_guard(
        ["--root", str(repo), "--history"], {"LEAK_DENYLIST": DENYLIST_TEXT}, capsys
    )
    assert (code, "cutoff is not on the base or default branch" in output) == (2, True)


def test_nul_bytes_in_file_content_cannot_desync_history(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (repo / ".gitattributes").write_text("*.dat diff\n", encoding="utf-8")
    (repo / "x.dat").write_bytes(b"hello\0world\0" + ("a" + AT + "gmail.com").encode() + b"\n")
    git(repo, "add", ".")
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Alex",
            "-c",
            "user.email=alex" + AT + "gmail.com",
            "commit",
            "-q",
            "-m",
            "binary-ish",
        ],
        cwd=repo,
        check=True,
        capture_output=True,
    )
    sha = head(repo)
    code, output = run_guard(
        ["--root", str(repo), "--history"], {"LEAK_DENYLIST": DENYLIST_TEXT}, capsys
    )
    assert code == 1
    assert f"commit {sha[:12]} author email:1: email-address" in output
    assert "commit world" not in output
    assert "commit hello" not in output


def test_commit_metadata_fails_closed_on_unexpected_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(leak_guard, "run_git", lambda *args: b"not a sha\0a\0b\0c\0d\0m\0")
    with pytest.raises(GuardSetupError, match="could not be parsed safely"):
        leak_guard.commit_metadata(tmp_path, ["--all"])


def test_range_includes_merge_commits(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (repo / "a.md").write_text("x\n", encoding="utf-8")
    git(repo, "add", "a.md")
    git(repo, "commit", "-q", "-m", "base")
    base = head(repo)
    git(repo, "switch", "-q", "-c", "side")
    (repo / "b.md").write_text("alex" + AT + "gmail.com\n", encoding="utf-8")
    git(repo, "add", "b.md")
    git(repo, "commit", "-q", "-m", "side work")
    git(repo, "switch", "-q", "-")
    git(repo, "commit", "-q", "--allow-empty", "-m", "main work")
    git(repo, "merge", "-q", "--no-ff", "-m", "merge side", "side")
    code, output = run_guard(
        ["--root", str(repo), "--range", f"{base}..HEAD"], {"LEAK_DENYLIST": DENYLIST_TEXT}, capsys
    )
    assert code == 1
    assert " b.md:1: email-address" in output


def test_image_metadata_text_is_scanned_and_never_baselinable(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    compressed = b"Author\0\0" + zlib.compress(f"by {SECRET_WORD}".encode())
    (repo / "shot.png").write_bytes(png((b"zTXt", compressed)))
    (repo / "plain.png").write_bytes(
        png((b"tEXt", b"Comment\0mail alex" + AT.encode() + b"gmail.com"))
    )
    git(repo, "add", ".")
    git(repo, "commit", "-q", "-m", "images")
    sha = head(repo)
    env = {"LEAK_DENYLIST": DENYLIST_TEXT}
    code, output = run_guard(["--root", str(repo), "--emit-baseline", sha], env, capsys)
    assert "image-metadata" not in output
    code, output = run_guard(["--root", str(repo), "--tree"], env, capsys)
    assert code == 1
    assert re.search(
        r"shot\.png \(embedded text\):\d+: denylist: private identifier \(hash #1\)", output
    )
    assert re.search(r"plain\.png \(embedded text\):\d+: email-address", output)
    assert SECRET_WORD not in output
    assert "Comment" in leak_guard.image_text(png((b"tEXt", b"Comment\0x")))
    itxt = b"Title\0\x01\0en\0\0" + zlib.compress(b"hidden words")
    assert "hidden words" in leak_guard.image_text(png((b"iTXt", itxt)))
    assert "plain run" in leak_guard.image_text(b"\xff\xd8 plain run \x00")
    short = "~" + "/ab"
    assert short not in leak_guard.image_text(b"\xff\xd8\x00" + short.encode() + b"\x00")
    in_stream = "~" + "/zz"
    pdf = b"%PDF-1.7\n<< /Author (alex) >>\nstream\nx " + in_stream.encode() + b" y\nendstream\n"
    text = leak_guard.image_text(pdf + b"<x:xmpmeta>m</x:xmpmeta>")
    assert "/Author (alex)" in text
    assert in_stream not in text
    assert "<x:xmpmeta>m</x:xmpmeta>" in text


@pytest.mark.parametrize(
    ("text", "origin"),
    [
        (
            "C"
            + ":"
            + BACKSLASH
            + "Windows"
            + BACKSLASH
            + ".."
            + BACKSLASH
            + "Users"
            + BACKSLASH
            + "alex",
            None,
        ),
        ("C" + ":" + BACKSLASH + "path" + BACKSLASH + "Users" + BACKSLASH + "alex", None),
        (
            "D" + ":" + BACKSLASH + "work" + BACKSLASH + "clientco" + BACKSLASH + "a.txt",
            "tests/test_a.py",
        ),
        ("C" + ":/" + "x/../y", "docs/a.md"),
    ],
)
def test_windows_exemptions_do_not_cover_real_paths(text: str, origin: str | None) -> None:
    assert rules_hit(text, origin=origin) == ["windows-path"]


def test_split_literal_private_key_and_letter_only_aws_key() -> None:
    key = "-" * 5 + "BEGIN RSA " + "PRIVATE KEY" + "-" * 5
    split = f'key = ("{key}\\n"\n    "{noise(64)}")'
    assert "private-key" in rules_hit(split)
    letters = "".join(char for char in noise(80).upper() if char.isalpha())[:16]
    assert "aws-access-key" in rules_hit("AKIA" + letters)


def test_strip_png_keeps_color_profile_and_animation() -> None:
    animated = png((b"iCCP", b"sRGB\0\0x"), (b"acTL", b"\0" * 8), (b"tEXt", b"a\0b"))
    stripped, removed = leak_guard.strip_png(animated)
    assert removed == 1
    kinds = [kind for kind, _ in leak_guard.png_chunks(stripped)]
    assert kinds == [b"IHDR", b"iCCP", b"acTL", b"IDAT", b"IEND"]
