# Leak guard

`tools/leak_guard.py` keeps personal data, absolute local paths and secrets out of the
repository, its history, pull request text and generated outputs. It uses the Python standard
library only, so the same file runs in every repository that carries it.

Turn on the git hooks once per clone:

```sh
git config core.hooksPath .githooks
```

## Scopes

| Flag | Scans |
| --- | --- |
| `--tree` | Every tracked file and every untracked file that is not ignored, including file names. |
| `--history` | Every commit reachable from any ref: author and committer names and emails, the full message and every added line. Every annotated tag: name, tagger and message. Every reachable blob the text diff does not show (binary, UTF-16, or hidden by a diff attribute), and every image blob. |
| `--range A..B` | The same commit checks as `--history`, limited to the commits in `A..B`. This is the blocking CI gate. |
| `--text FILE` | One file. Use it for a pull request body before posting it, and for generated outputs. |
| `--pr` | In CI: the current pull request's title, body, reviews, review comments and comments, read with the GitHub REST API. |
| `--all` | `--tree` and `--history`. |

Exit codes: `0` clean, `1` at least one hit, `2` a setup or usage problem.

Tools: `--emit-baseline CUTOFF` prints baseline candidates (see below) and `--strip-png FILE...`
removes metadata chunks from PNG files in place, keeping only image and color chunks.

## Generic rules

These patterns contain nothing personal and live in the guard itself.

- **Absolute paths.** Windows drive paths (a drive letter, a colon, then a slash or backslash,
  not preceded by a letter, so web addresses do not match), UNC paths (plain and escaped), macOS
  home directories, Git Bash and WSL user folders, Linux home directories (the CI runner's home
  directory is accepted only inside `.github/`, never with `..`), the Windows user profile
  variable, and a tilde followed by a folder.
  - Windows system locations (the Windows folder, Program Files, ProgramData) and the usual
    documentation placeholder never name a user and do not fire.
  - In test fixtures and docs (any path with a `tests`, `test`, `docs` or `fixtures` folder), a
    drive path fires only when it goes through a user folder, so deliberate probe paths in tests
    stay quiet while a real personal path is still caught.
- **Email addresses**, except the GitHub noreply domains, `noreply` and `support` at github.com,
  the reserved example.com, example.net and example.org domains and their subdomains, and domains
  ending in `.example`, `.test` or `.invalid`.
- **Forbidden strings:** assistant vendor domains, generated-by footers (as a whole word),
  session identifiers, and em and en dash characters.
- **Secrets need structure.** A private key needs its header followed by a base64 body, so a bare
  header line does not fire. Token prefixes (GitHub, API keys, Slack, AWS access key ids) fire
  only when the token body mixes character classes, has at least 3 bits of entropy per character,
  and holds no placeholder word such as example, sample, dummy or fake.
- **Image metadata:** EXIF, XMP, C2PA content credentials, and PNG text chunks. Every image is
  also listed for manual review.

A hit prints the location and rule. Locally it also shows the match with its middle masked; in CI
(`CI=true`) it shows the rule and location only. A file whose own name holds a match or a private
identifier is shown as `<path withheld ...>` with a short digest instead of its name.

## Private denylist

Private identifiers are stored only as salted SHA-256 hashes, so no personal text sits in any
file. The guard lowercases the scanned text, hashes every window of 1 up to `maxwords` whole
words with the salt, and blocks on any listed hash. It never prints the matching text, only
`private identifier (hash #N)`.

```text
salt <hex>
maxwords <n>
hash <sha256 hex>
```

The hash of an identifier is the SHA-256 of the salt, a newline, and the identifier trimmed and
lowercased. Lines starting with `#` are comments. Personal email addresses are never stored,
even as hashes: the generic email rule blocks every address outside the allowlisted domains.

The guard loads the list from, in order: the file named by `LEAK_DENYLIST_FILE`, the text of
`LEAK_DENYLIST`, or a private file kept outside the repository next to it. In CI the list comes
from the `LEAK_DENYLIST` repository secret. With no list, the guard prints a warning and exits
`2` when `CI=true`, or continues with generic rules only when run locally.

## Allowlist

`.leakguard-allow` lists exact strings that are known to be safe for generic rules in the
working tree, one per line as `<exact string> # <reason>`. An entry accepts a generic match when
it equals the match or the whole trimmed line holding it. The reason is required. The allowlist
can never hold a private identifier (the guard refuses to start if it does) and never affects
denylist hits.

## History baseline

Pushed history cannot change, so known generic false positives in it are recorded in
`.leakguard-baseline`:

```text
cutoff <40 hex commit>
<commit> <rule> <line> <path>
```

- **History only.** Entries apply to history and range scans, never to the working tree, which
  must be clean on its own.
- **Pinned cutoff.** Every entry's commit must be the cutoff or an ancestor of it, or the guard
  refuses to start. Commits after the cutoff are always scanned in full.
- **Fingerprints only:** commit, rule, line number and repository-relative path. No matched
  text, names, emails or absolute paths. Commit fields that are not files use the pseudo paths
  `:message`, `:author name`, `:author email`, `:committer name` and `:committer email`.
- **No private list hits, by construction.** The parser refuses the `denylist` rule and any path
  holding a private identifier, and the scanner consults the baseline only for generic rules.
  `--emit-baseline` also drops any location that holds a private list hit.
- **Review.** `--emit-baseline CUTOFF` prints candidates. A person confirms each one as a false
  positive before it goes in. Changes to the file go through a pull request like code, CI flags
  them, and CODEOWNERS asks for the owner's review.

## Hooks and CI

- `.githooks/pre-commit` runs `--tree` and `.githooks/pre-push` runs `--all`. Hooks are a local
  safety net and can be skipped.
- The blocking `leak-guard` CI job scans only what a change adds: `--range base..head` and `--pr`
  on pull requests, `--range before..after` on pushes to main.
- The `Leak guard full scan` workflow runs `--all` against the baseline every week and on demand.
  It does not block merges.
- The `PR text guard` workflow runs `--pr` again whenever a comment or review is posted or edited.
