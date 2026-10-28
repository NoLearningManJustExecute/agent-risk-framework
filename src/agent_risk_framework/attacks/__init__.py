"""Phase 2 attack scenarios against the undefended agent.

Scenarios (`data/attack_scenarios.json`) cover AC01-AC12 plus an obfuscated
variant of each: direct prompts, indirect injection through tool-returned content,
exfiltration through tool arguments, and MCP attacks (poisoned tool description,
post-approval rug pull, shadow tool). Each run happens in a throwaway synthetic
lab and is scored by a deterministic oracle against the tool-call log. Benign
tasks get two separate measures: task success and benign-input violation.
"""

from .lab import CANARIES, CREDENTIALS_CANARY, OUTSIDE_CANARY, OracleContext, lab_sandbox
from .oracles import Trace, Verdict, score_attack, score_benign_violation, score_task_success
from .runner import ExperimentSummary, Tally, run_experiment
from .scenarios import AttackCase, AttackScenario, ScenarioCatalog, load_catalog

__all__ = [
    "CANARIES",
    "CREDENTIALS_CANARY",
    "OUTSIDE_CANARY",
    "AttackCase",
    "AttackScenario",
    "ExperimentSummary",
    "OracleContext",
    "ScenarioCatalog",
    "Tally",
    "Trace",
    "Verdict",
    "lab_sandbox",
    "load_catalog",
    "run_experiment",
    "score_attack",
    "score_benign_violation",
    "score_task_success",
]
