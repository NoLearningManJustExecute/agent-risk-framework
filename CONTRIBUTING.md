# Contributing

## Setup

```sh
python -m venv .venv
. .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
git config core.hooksPath .githooks
```

The last line turns on the repository's git hooks for your clone. Run it once.

## Checks

```sh
ruff format --check . && ruff check .
python -m pytest
python tools/leak_guard.py --all
```

CI runs all of these. Every job must pass before a change is merged.

## Leak guard

`tools/leak_guard.py` blocks personal data, absolute local paths and secrets in the tree, the
history, pull request text and committed outputs. How it works, the history baseline and the CI
layout are in [tools/LEAK_GUARD.md](tools/LEAK_GUARD.md).

- Hooks: `.githooks/pre-commit` runs `--tree`, `.githooks/pre-push` runs `--all`.
- The private identifier list is never committed. The guard finds your local copy in a
  `_planning` folder above the clone, or point it there once per clone with
  `git config leakguard.denylist <path to the list>` (or the `LEAK_DENYLIST_FILE` environment
  variable). Without a list the hooks print a boxed warning. CI reads it from the
  `LEAK_DENYLIST` secret.
- To remove metadata from a PNG before committing it: `python tools/leak_guard.py --strip-png FILE`.
