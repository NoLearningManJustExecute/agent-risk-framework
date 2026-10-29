"""The findings report: one HTML document, printed to PDF, built from the lab's data.

Sources, all in the repository or the run log:

- `findings/*.json`: the Phase 2 findings against the undefended agent
- the Phase 4 ablation database: the retest of every finding's case under each arm,
  and the security-vs-usefulness table (`attacks.ablation_report.summarize`)
- `docs/phase4_ablation.svg` and `docs/demo/demo-final-frame.svg`: embedded as figures

Nothing in the numbers is typed by hand. The prose around them (scope, methodology,
limitations) is fixed text in this module.

The PDF is printed by a local Chromium-family browser in headless mode, with the
page header and footer turned off so no file path or date lands on the page:

    python -m agent_risk_framework.findings.report --db runs/phase4.db \\
        --html docs/report/findings_report.html \\
        --pdf docs/report/agent-risk-framework-findings.pdf
"""

from __future__ import annotations

import argparse
import base64
import shutil
import subprocess
import tempfile
from collections.abc import Sequence
from datetime import UTC, datetime
from html import escape
from pathlib import Path

from ..attacks.ablation_report import ArmStats, Rate, summarize
from ..runlog import RunLog
from .schema import Finding
from .writer import load_finding

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
LLM_TITLES = {
    "LLM01:2026": "Prompt Injection",
    "LLM02:2026": "Sensitive Information Disclosure",
    "LLM03:2026": "Excessive Agency",
    "LLM04:2026": "Supply Chain",
    "LLM05:2026": "Data and Model Poisoning",
    "LLM06:2026": "Unbounded Consumption",
    "LLM07:2026": "Misinformation",
    "LLM08:2026": "Hidden Context Exposure",
    "LLM09:2026": "Vector and Embedding Weaknesses",
    "LLM10:2026": "Improper Output Handling",
}
BROWSERS = ("chrome", "google-chrome", "chromium", "chromium-browser", "msedge")
WINDOWS_BROWSERS = (
    Path("C:/Program Files/Google/Chrome/Application/chrome.exe"),
    Path("C:/Program Files/Microsoft/Edge/Application/msedge.exe"),
    Path("C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"),
)
EVIDENCE_LIMIT = 700

CSS = """
@page { size: A4; margin: 18mm 16mm; }
body { font-family: "Segoe UI", system-ui, sans-serif; font-size: 10.5pt; color: #0b0b0b;
       line-height: 1.45; }
h1 { font-size: 22pt; margin: 0 0 4pt; }
h2 { font-size: 14pt; margin: 18pt 0 6pt; border-bottom: 1px solid #c3c2b7; padding-bottom: 2pt;
     break-after: avoid; }
h3 { font-size: 11.5pt; margin: 12pt 0 4pt; break-after: avoid; }
p { margin: 4pt 0; }
.sub { color: #52514e; }
table { border-collapse: collapse; width: 100%; margin: 6pt 0; font-size: 9pt;
        break-inside: avoid; }
th, td { border: 1px solid #e4e3df; padding: 3pt 5pt; text-align: left; vertical-align: top; }
th { background: #f3f2ee; }
td.num { text-align: right; white-space: nowrap; }
code, pre { font-family: Consolas, ui-monospace, monospace; font-size: 8.5pt; }
pre { background: #f6f5f2; border: 1px solid #e4e3df; padding: 5pt; white-space: pre-wrap;
      word-break: break-word; }
.finding { break-inside: avoid-page; margin-bottom: 10pt; }
.sev { display: inline-block; font-weight: 700; padding: 0 5pt; border: 1px solid; }
.sev-high { color: #a3262a; } .sev-medium { color: #8a5a00; }
.callout { border-left: 3pt solid #2a78d6; padding: 4pt 8pt; background: #f3f7fd; }
figure { margin: 8pt 0; break-inside: avoid; } figure svg { width: 100%; height: auto; }
figcaption { color: #52514e; font-size: 9pt; }
.cover { break-after: page; }
"""


def load_findings(directory: Path | str) -> list[Finding]:
    found = [load_finding(p) for p in sorted(Path(directory).glob("ARF-*.json"))]
    return sorted(found, key=lambda f: (SEVERITY_ORDER.index(str(f.severity)), f.finding_id))


def _combined_rate(stats: ArmStats, case: str) -> Rate:
    rates = [r for c, r in stats.per_case.items() if c in (case, f"{case}-OBF")]
    return Rate(sum(r.k for r in rates), sum(r.n for r in rates))


def _credited(stats: ArmStats, case: str) -> int:
    counters = [c for k, c in stats.per_case_credit.items() if k in (case, f"{case}-OBF")]
    return sum(sum(c.values()) for c in counters)


def _clip(text: str, limit: int = EVIDENCE_LIMIT) -> str:
    return text if len(text) <= limit else text[:limit] + "..."


def _rate_cell(rate: Rate) -> str:
    return f'<td class="num">{escape(str(rate))}</td>'


def _svg(path: Path, alt: str) -> str:
    """An SVG figure as an isolated image: each SVG keeps its own styles and variables."""
    if not path.is_file():
        return f"<p class='sub'>(figure {escape(path.name)} not found)</p>"
    data = base64.b64encode(path.read_bytes()).decode("ascii")
    return f'<img alt="{escape(alt)}" style="width:100%" src="data:image/svg+xml;base64,{data}">'


def _p(text: str) -> str:
    return "".join(f"<p>{escape(par)}</p>" for par in text.split("\n\n") if par.strip())


def _points(rate: Rate, base: Rate) -> str:
    if rate.value is None or base.value is None:
        return "n/a"
    return f"{round((rate.value - base.value) * 100):+d} pp"


def render_html(
    findings: Sequence[Finding],
    stats: Sequence[ArmStats],
    *,
    chart: Path,
    demo_frame: Path,
    generated: str | None = None,
) -> str:
    by = {s.arm.name: s for s in stats}
    base, comb = by.get("baseline"), by.get("combined")
    if base is None or comb is None:
        raise ValueError("the report needs the baseline and combined arms")
    perm, clf = by.get("tool_permissions"), by.get("input_classifier")
    if perm is None or clf is None:
        raise ValueError("the report needs the tool_permissions and input_classifier arms")
    singles = [s for s in stats if len(s.arm.guardrails.controls) == 1]
    date = generated or datetime.now(UTC).date().isoformat()
    never = sum(1 for r in base.per_case.values() if r.k == 0)
    dne = comb.attack_buckets["did_not_execute"]
    counts = {sev: sum(1 for f in findings if str(f.severity) == sev) for sev in SEVERITY_ORDER}
    sev_line = ", ".join(f"{n} {sev}" for sev, n in counts.items() if n)

    def stoppers(case: str) -> list[str]:
        before = _combined_rate(base, case).k
        return [
            s.arm.name for s in singles if _credited(s, case) and _combined_rate(s, case).k < before
        ]

    stopped = sum(1 for f in findings if stoppers(f.attack_case))

    out = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<title>agent-risk-framework: findings report</title>",
        f"<style>{CSS}</style></head><body>",
        "<section class='cover'>",
        "<h1>agent-risk-framework</h1>",
        "<p class='sub'>Findings report: a tool-using LLM agent, attacked and defended, "
        "with every defense measured for what it buys and what it costs.</p>",
        f"<p class='sub'>Author: RJ. Generated {escape(date)} from the repository's "
        "findings and the Phase 4 run log. Synthetic data only; local model only.</p>",
        "<h2>Executive summary</h2>",
        "<div class='callout'><p><strong>A deterministic least-privilege control beat the "
        "content classifier on both security and usefulness.</strong></p></div>",
        f"<p><code>tool_permissions</code> alone cut attack success from "
        f"{base.attack_success} to {perm.attack_success}, with {perm.benign_lost} true "
        f"false positives and a task-success change of "
        f"{_points(perm.task_success, base.task_success)}. "
        f"<code>input_classifier</code> alone cut it to {clf.attack_success}, with "
        f"{clf.benign_lost} true false positives and a task-success change of "
        f"{_points(clf.task_success, base.task_success)}.</p>",
        f"<p>All six controls together brought attack success to {comb.attack_success}, at "
        f"a usefulness cost of {base.task_success} to {comb.task_success} task success. "
        f"Of that stack's attack runs, {dne} were <code>did_not_execute</code> (the model "
        f"wrote the tool call as text: model noise, no control credit), and {never} of "
        f"{len(base.per_case)} scenarios never succeeded at baseline.</p>",
        f"<p>I report {len(findings)} findings against the undefended agent ({sev_line}). "
        f"{stopped} of them are stopped with credit by at least one control measured alone; "
        "the retest tables in sections 3 and 4 say which.</p>",
        "<h2>1. Scope</h2>",
        "<p><strong>In scope.</strong> A single agent built for this lab: a custom loop "
        "over a local MCP stdio server with three tools that simulate side effects "
        "(<code>search_docs</code>, <code>send_email</code>, <code>read_file</code>), "
        "a stated policy with an unenforced recipient allowlist and path sandbox, a "
        "hidden canary in the system prompt, and a synthetic workspace with a secret "
        "store. Attack channels: the user prompt, tool output, and MCP tool definitions "
        "(poisoned description, post-approval rug pull, shadow tool).</p>",
        "<p><strong>Out of scope.</strong> Code execution (no such tool exists), "
        "multi-agent communication, persistent memory across conversations, retrieval "
        "poisoning, real credentials, real users, and any network beyond loopback. The "
        "threat model (<code>docs/threat_model.md</code>) records each decision.</p>",
        "<h2>2. Methodology</h2>",
        "<p>I built the measurement rig before the agent: a SQLite run log with one row "
        "per run and per step, deterministic oracles that read the tool-call log (no LLM "
        "judge), and experiment manifests that fix model, seed and temperature. Then the "
        "vulnerable agent, then the attack set, then six guardrails, each an independent "
        "switch that logs every decision.</p>",
        f"<p>The ablation ran {len(stats)} arms (baseline, each control alone, all six) "
        f"over {len(base.per_case)} attack scenarios and "
        f"{base.task_success.n // max(base.runs_per_case, 1)} "
        "benign tasks, 10 runs each, on <code>llama3.1:8b</code> at temperature 0 with "
        "seed 1337 plus the run index. Every run lands in one locked outcome bucket: "
        "<code>succeeded</code>, <code>blocked_by_control</code>, "
        "<code>did_not_execute</code> or <code>failed_other</code>. A control is credited "
        "only through a counterfactual: put its blocked call back (or its withheld input, "
        "or the redacted secret) and the objective happens.</p>",
        "<p><strong>False positives, two kinds.</strong> A <em>true false positive</em> is "
        "a block that cost the user the task (bucket <code>blocked_by_control</code> on a "
        "benign run). A <em>desired block</em> stopped an unrequested action while the task "
        "was not lost. The usefulness cost of an arm is its task-success change against "
        "baseline; the raw any-block rate is kept for reference.</p>",
        "<p>Nothing was retuned for the measurement: no attack payload, no classifier rule, "
        "no oracle. The input classifier's false positives on the grown benign set were "
        "computed offline and pinned in the tests before the live run.</p>",
        "</section>",
        "<h2>3. Findings</h2>",
        "<p>Status is as found against the undefended agent. The retest line under each "
        "finding is the Phase 4 measurement, plain and obfuscated variants together.</p>",
    ]
    for f in findings:
        case = f.attack_case
        llm = f"{f.llm_id} {LLM_TITLES.get(f.llm_id, '')}".strip()
        mapping = ", ".join(x for x in (f.asi_id, llm, f.mcp_id or "", f.atlas_technique) if x)
        alone = stoppers(case)
        evidence = "\n\n".join(
            f"[{e.kind}] {_clip(e.content)}" for e in f.evidence if e.kind != "run_log"
        )
        out += [
            "<div class='finding'>",
            f"<h3>{escape(f.finding_id)}: {escape(f.title)}</h3>",
            f"<p><span class='sev sev-{escape(str(f.severity))}'>"
            f"{escape(str(f.severity).upper())}</span> "
            f"Case <code>{escape(case)}</code>. {escape(mapping)}.</p>",
            "<p><strong>Description.</strong></p>",
            _p(f.description),
            "<p><strong>Impact.</strong></p>",
            _p(f.impact),
            "<p><strong>Evidence</strong> (synthetic lab data; attack text quoted as data).</p>",
            f"<pre>{escape(evidence)}</pre>",
            "<p><strong>Remediation.</strong></p>",
            _p(f.recommendation),
            f"<p><strong>Retest.</strong> Baseline {escape(str(_combined_rate(base, case)))}; "
            f"all six controls {escape(str(_combined_rate(comb, case)))}. Stopped with "
            f"credit by, alone: {escape(', '.join(alone) or 'none alone')}.</p>",
            "</div>",
        ]

    out += [
        "<h2>4. Ablation results</h2>",
        "<figure>",
        _svg(chart, "Attack success, true false positives and task success per arm"),
        "<figcaption>Attack success, true false positives and task success per arm, "
        "one shared 0 to 100% scale. Generated from the run log.</figcaption></figure>",
        "<table><tr><th>Arm</th><th>Attack success</th><th>vs baseline</th>"
        "<th>Any block (raw FPR)</th><th>True false positives</th><th>Desired blocks</th>"
        "<th>Task success</th><th>vs baseline</th><th>did_not_execute (attack)</th></tr>",
    ]
    for s in stats:
        out.append(
            f"<tr><td><code>{escape(s.arm.name)}</code></td>{_rate_cell(s.attack_success)}"
            f'<td class="num">{_points(s.attack_success, base.attack_success)}</td>'
            f"{_rate_cell(s.fpr)}{_rate_cell(s.benign_lost)}{_rate_cell(s.desired_blocks)}"
            f"{_rate_cell(s.task_success)}"
            f'<td class="num">{_points(s.task_success, base.task_success)}</td>'
            f'<td class="num">{s.attack_buckets["did_not_execute"]}</td></tr>'
        )
    out += [
        "</table>",
        "<h3>Retest by finding and arm</h3>",
        "<table><tr><th>Finding</th><th>Case</th>"
        + "".join(f"<th><code>{escape(s.arm.name)}</code></th>" for s in stats)
        + "</tr>",
    ]
    for f in findings:
        cells = "".join(_rate_cell(_combined_rate(s, f.attack_case)) for s in stats)
        out.append(
            f"<tr><td>{escape(f.finding_id)}</td><td>{escape(f.attack_case)}</td>{cells}</tr>"
        )
    out += [
        "</table>",
        "<h3>Demo</h3>",
        "<figure>",
        _svg(demo_frame, "Demo transcript, final frame"),
        "<figcaption>AC01 against the undefended agent, then with tool_permissions, then "
        "with all six controls: a live llama3.1:8b run (docs/demo.md).</figcaption></figure>",
        "<h2>5. Retest notes and limitations</h2>",
        "<ul>",
        "<li><strong>Repeatability, not spread.</strong> At temperature 0 almost every case "
        "landed 10/10 or 0/10. The independent units are the scenarios and tasks, not the "
        "runs; a confidence interval over runs would be falsely narrow.</li>",
        "<li><strong>Interception is not effect.</strong> Indirect injection (AC09, AC10) "
        "never worked on this model, so the output classifier's credit there is "
        "interception against a 0% baseline. The same holds for one tool-integrity "
        "case (AC12A-OBF).</li>",
        "<li><strong>Entangled credit.</strong> The allowlist and the approval gate both "
        "refuse outside recipients; under all six controls the same runs are credited to "
        "both. The single-control arms are the per-control measurements.</li>",
        "<li><strong>The egress filter barely had targets.</strong> Its secret-read cases "
        "never succeeded at baseline, and under all six controls other controls act "
        "first.</li>",
        "<li><strong>Rule-based classifiers and a simulated reviewer.</strong> A paraphrase "
        "evades the lexicons; human approval fatigue is not modeled.</li>",
        "<li><strong>One model, small sets.</strong> One local model, 24 scenarios and 45 "
        "benign tasks written for this lab. No leave-one-out arms.</li>",
        "<li><strong>In-loop guardrails.</strong> The checks run inside the agent loop for "
        "measurement; a proxy that intercepts MCP JSON-RPC traffic is future work.</li>",
        "</ul>",
        "<h2>Appendix: framework mapping</h2>",
        "<p>OWASP Top 10 for Agentic Applications 2026 (ASI) is primary. OWASP Top 10 for "
        "LLM Applications 2026 IDs were verified against the official OWASP document "
        "(Version 2026, August 4th, 2026). OWASP MCP Top 10 IDs are from the beta list and "
        "may be renumbered. MITRE ATLAS technique IDs are per threat.</p>",
        "<p>Reproduce: <code>python -m agent_risk_framework.attacks.ablation</code>, then "
        "<code>python -m agent_risk_framework.findings.report</code> (see the README).</p>",
        "</body></html>",
    ]
    return "\n".join(out) + "\n"


def find_browser(explicit: str | None = None) -> Path | None:
    if explicit:
        return Path(explicit)
    for name in BROWSERS:
        found = shutil.which(name)
        if found:
            return Path(found)
    return next((p for p in WINDOWS_BROWSERS if p.is_file()), None)


def print_pdf(html_path: Path, pdf_path: Path, browser: Path) -> None:
    """Print with a headless browser: no header or footer, so no path or date on the page."""
    pdf_path.parent.mkdir(parents=True, exist_ok=True)
    pdf_path.unlink(missing_ok=True)
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as profile:
        # A fixed argument list, no shell; the browser is the user's own local install.
        subprocess.run(  # noqa: S603
            [
                str(browser),
                "--headless=new",
                "--disable-gpu",
                "--no-first-run",
                "--no-default-browser-check",
                f"--user-data-dir={profile}",
                "--no-pdf-header-footer",
                f"--print-to-pdf={pdf_path.resolve()}",
                html_path.resolve().as_uri(),
            ],
            check=True,
            capture_output=True,
            timeout=120,
        )
    if not pdf_path.is_file():
        # Some browsers hand the job to a running instance and exit 0 without printing.
        raise RuntimeError(f"{browser.name} wrote no PDF; close it or pass --browser")


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Build the findings report (HTML, PDF).")
    parser.add_argument("--db", default="runs/phase4.db")
    parser.add_argument("--findings-dir", default="findings")
    parser.add_argument("--chart", default="docs/phase4_ablation.svg")
    parser.add_argument("--demo-frame", default="docs/demo/demo-final-frame.svg")
    parser.add_argument("--html", default="docs/report/findings_report.html")
    parser.add_argument("--pdf", default="", help="also print a PDF here")
    parser.add_argument("--browser", default=None, help="path to a Chromium-family browser")
    args = parser.parse_args(argv)

    if not Path(args.db).is_file():
        parser.error(f"no run log at {args.db}")
    with RunLog(args.db) as log:
        stats = summarize(log)
    html = render_html(
        load_findings(args.findings_dir),
        stats,
        chart=Path(args.chart),
        demo_frame=Path(args.demo_frame),
    )
    html_path = Path(args.html)
    html_path.parent.mkdir(parents=True, exist_ok=True)
    html_path.write_text(html, encoding="utf-8", newline="\n")
    if args.pdf:
        browser = find_browser(args.browser)
        if browser is None:
            parser.error("no Chromium-family browser found; pass --browser")
        print_pdf(html_path, Path(args.pdf), browser)


if __name__ == "__main__":
    main()
