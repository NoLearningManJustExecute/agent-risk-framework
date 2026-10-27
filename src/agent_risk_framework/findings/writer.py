"""Write findings as machine-readable JSON plus a human-readable markdown page."""

from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path

from .schema import Finding

DEFAULT_FINDINGS_DIR = Path("findings")

_BACKTICK_RUN_RE = re.compile(r"`+")
_LINE_BREAK_RE = re.compile(r"[\r\n\u2028\u2029\x0b\x0c\x85]+")


def _fence(content: str) -> str:
    """Wrap untrusted text in a code fence it cannot break out of."""
    longest = max((len(m) for m in _BACKTICK_RUN_RE.findall(content)), default=0)
    ticks = "`" * max(3, longest + 1)
    return f"{ticks}text\n{content}\n{ticks}"


def _inline(value: str) -> str:
    """Make a value safe on a single markdown line: no line breaks, no raw HTML."""
    value = _LINE_BREAK_RE.sub(" ", value)
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _cell(value: str) -> str:
    """Make a value safe inside a markdown table cell."""
    return _inline(value).replace("\\", "\\\\").replace("|", "\\|")


def render_markdown(finding: Finding) -> str:
    f = finding
    rows = [
        ("Severity", str(f.severity)),
        ("Status", str(f.status)),
        ("Category", f.category),
        ("OWASP Agentic (primary)", f.asi_id),
        ("OWASP LLM 2026", f.llm_id),
        ("OWASP MCP (beta)", f.mcp_id or "n/a"),
        ("MITRE ATLAS", f.atlas_technique),
        ("Attack case", f.attack_case),
        ("Detection result", str(f.detection_result)),
        ("Guardrail action", str(f.guardrail_action)),
        ("Timestamp", f.timestamp),
    ]
    lines = [
        f"# {f.finding_id}: {_inline(f.title)}",
        "",
        "| Field | Value |",
        "| --- | --- |",
        *(f"| {k} | {_cell(v)} |" for k, v in rows),
        "",
        "## Description",
        "",
        f.description,
        "",
        "## Impact",
        "",
        f.impact,
        "",
        "## Evidence",
        "",
    ]
    if not f.evidence:
        lines += ["_No evidence attached._", ""]
    for i, ev in enumerate(f.evidence, start=1):
        run = f" (run {ev.run_id})" if ev.run_id is not None else ""
        lines += [f"{i}. **{ev.kind}**{run}", "", _fence(ev.content), ""]
    lines += ["## Recommendation", "", f.recommendation, ""]
    return "\n".join(lines)


def _atomic_write(path: Path, data: bytes) -> None:
    """Write to a temp file in the same directory, then rename over the target."""
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def write_finding(
    finding: Finding,
    out_dir: Path | str = DEFAULT_FINDINGS_DIR,
    *,
    overwrite: bool = False,
) -> tuple[Path, Path]:
    """Write `<finding_id>.json` and `<finding_id>.md`; return both paths.

    Both documents are fully rendered and encoded before anything touches disk,
    and each file is replaced atomically, so a failure never leaves a truncated
    finding behind. An existing finding is only replaced with `overwrite=True`.
    finding_id is validated against ^ARF-[0-9]{4,8}$, so it is always a safe filename.
    """
    out = Path(out_dir)
    json_path = out / f"{finding.finding_id}.json"
    md_path = out / f"{finding.finding_id}.md"
    if not overwrite and (json_path.exists() or md_path.exists()):
        raise FileExistsError(f"{finding.finding_id} already exists in {out}")
    json_bytes = (json.dumps(finding.to_dict(), indent=2, ensure_ascii=False) + "\n").encode(
        "utf-8"
    )
    md_bytes = render_markdown(finding).encode("utf-8")
    out.mkdir(parents=True, exist_ok=True)
    _atomic_write(json_path, json_bytes)
    _atomic_write(md_path, md_bytes)
    return json_path, md_path


def load_finding(path: Path | str) -> Finding:
    return Finding.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))
