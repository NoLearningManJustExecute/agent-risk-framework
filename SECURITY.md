# Security Policy

## Scope

`agent-risk-framework` is a local, offline research lab. It deliberately builds a
vulnerable tool-using agent (in later phases) so that attacks and defenses can be
measured. The intentionally vulnerable configurations (for example `baseline`) are
**not** bugs; they are the control group of each experiment.

In scope for reports:

- A defense, detector, or measurement component that silently mis-reports results
  (for example a run logged as `not_detected` when the detector fired).
- Any code path that makes a network call to a non-loopback host. The real provider
  only talks to a local Ollama server, and the test suite blocks sockets entirely.
- Any real secret, credential, or personal data committed to the repository.
- Vulnerable dependencies not caught by `pip-audit` in CI.

Out of scope:

- Successful attacks against the `baseline` configuration. That is the point.
- Model behavior of third-party local models (report those upstream).

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting
(**Security → Report a vulnerability**) on this repository once it is public. Until
then, contact the maintainer through their GitHub profile. Do not open a public issue
for anything that could expose real data.

You can expect an acknowledgement within 7 days.

## Data handling rules

- Synthetic data only. Canary tokens, users, documents, and "secrets" used in
  attack cases are fabricated and carry no value outside this lab.
- No real API keys, tokens, or credentials anywhere: code, tests, fixtures, or docs.
- No network calls in code or tests other than the optional local Ollama endpoint
  on `127.0.0.1` / `localhost` / `::1`.
