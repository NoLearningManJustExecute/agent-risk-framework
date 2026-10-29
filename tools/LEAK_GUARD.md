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
| `--history` | Every commit reachable from any ref: author and committer names and emails, the full message, every path it touches and every added line. Every annotated tag: name, tagger and message. Every branch name. Every reachable blob the text diff does not show (binary, UTF-16, or hidden by a diff attribute), and every image blob. |
| `--range A..B` | The same commit checks as `--history`, limited to the commits in `A..B`. This is the blocking CI gate. |
| `--text FILE` | One file. Use it for a pull request body before posting it, and for generated outputs. |
| `--pr` | In CI: the current pull request's title, body, branch name, reviews, review comments and comments, read with the GitHub REST API. |
| `--all` | `--tree` and `--history`. |

Exit codes: `0` clean, `1` at least one hit, `2` a setup or usage problem.

Tools: `--emit-baseline CUTOFF` prints baseline candidates (see below) and `--strip-png FILE...`
removes metadata chunks from PNG files in place, keeping image, color and animation chunks.

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
    one-segment probe such as a drive plus one name does not fire. Longer paths still do.
  - A path that climbs with `..` or passes through a user folder anywhere always fires.
- **Email addresses**, except the GitHub noreply domains, `noreply` and `support` at github.com,
  the reserved example.com, example.net and example.org domains and their subdomains, and domains
  ending in `.example`, `.test` or `.invalid`.
- **Forbidden strings:** assistant vendor domains, generated-by footers (as a whole word),
  session identifiers, and em and en dash characters.
- **Secrets need structure.** A private key needs its header followed by a base64 body, so a bare
  header line does not fire. Token prefixes (GitHub, API keys, Slack, AWS access key ids) fire
  only when the token body mixes character classes (AWS key ids: any), has at least 3 bits of
  entropy per character, and holds no placeholder word such as example, sample, dummy or fake.
  A key split across string literals is still matched.
- **Image metadata:** EXIF, XMP, C2PA content credentials, and PNG text chunks. Images are
  recognized by name or by their first bytes. The readable text inside an image is scanned with
  every rule: decompressed PNG text chunks and other non-pixel chunks, JPEG APP and comment
  segments, PDF dictionaries, XMP packets and UTF-16 strings, and long printable runs in other
  formats. Every image is also listed for manual review. Only a PNG's metadata hit can be
  baselined, and only when its text has no finding. `--strip-png` keeps image, color profile and
  animation chunks and drops everything else.
- **Other binaries:** the XML parts of Office and OpenDocument files and printable ASCII and
  UTF-16 runs of at least 10 characters are scanned with every rule. These hits cannot be
  baselined.

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

`.leakguard-allow` lists exact strings that are known to be safe for generic rules, one per line
as `<exact string> # <reason>`. An entry accepts a generic match when it equals the match or the
whole trimmed line holding it. The reason is required. The allowlist can never hold a private
identifier (the guard refuses to start if it does) and never affects denylist hits. It applies to
every scope; a range scan reads it from the range's base commit (see below). Prefer fixing the
source: the guard itself needs no allowlist, because it assembles its patterns from pieces.

## History baseline

Pushed history cannot change, so known generic false positives in it are recorded in
`.leakguard-baseline`:

```text
cutoff <40 hex commit>
<commit> <rule> <line> <path>
```

- **History only.** Entries apply to history and range scans, never to the working tree, which
  must be clean on its own.
- **Pinned cutoff.** The cutoff must be on the default branch (or, for a range scan, at or before
  the range base), and every entry's commit must be the cutoff or an ancestor of it, or the guard
  refuses to start. Commits after the cutoff are always scanned in full.
- **No self-approval.** A range scan reads `.leakguard-baseline` and `.leakguard-allow` from the
  range's base commit, never from the commits being scanned. A change to either file therefore
  takes effect only after it lands on the base branch, in its own pull request.
- **Fingerprints only:** commit, rule, line number and repository-relative path. No matched
  text, names, emails or absolute paths. Commit fields that are not files use the pseudo paths
  `:message`, `:author name`, `:author email`, `:committer name` and `:committer email`.
- **No private list hits or emails, by construction.** The parser refuses the `denylist` and
  `email-address` rules and any path holding a private identifier, and the scanner consults the
  baseline only for generic rules. `--emit-baseline` also drops any location that holds a private
  list hit. Text inside image metadata is scanned with every rule; when it has any finding, the
  image's metadata hit cannot be baselined either.
- **Granularity.** One entry covers every match of its rule on that line of that commit.
- **Review.** `--emit-baseline CUTOFF` prints candidates. A person confirms each one as a false
  positive before it goes in. Changes to the file go through a pull request like code, CI flags
  them, and CODEOWNERS asks for the owner's review.

## Hooks and CI

- `.githooks/pre-commit` runs `--tree` and `.githooks/pre-push` runs `--all`. Hooks are a local
  safety net and can be skipped.
- The blocking `leak-guard` CI job scans only what a change adds: `--range base..head` and `--pr`
  on pull requests, `--range before..after` on pushes to main.
- That job runs the guard copy from the default branch on pull requests and from the previous
  main on pushes, so editing `tools/leak_guard.py` cannot weaken the guard that checks the edit.
  It uses the change's own copy only when that commit has no guard with range support (the first
  install, or the upgrade that adds it), and says which copy it ran.
- Limit: the workflow files themselves are read from the change, so a change to `.github/` could
  still alter the gate. CI flags such changes with a warning and CODEOWNERS assigns them to the
  owner; review them like code.
- The `Leak guard full scan` workflow runs `--all` against the baseline every week and on demand.
  It does not block merges.
- The `PR text guard` workflow runs `--pr` again whenever a comment or review is posted or edited,
  always with the default branch's copy of the guard.
- Pull requests from forks get no secrets, so the CI guard fails closed (exit 2) on them.
- Every push to main runs in its own concurrency group, so no pushed range is cancelled or
  skipped while queued. Pull request runs replace each other.
