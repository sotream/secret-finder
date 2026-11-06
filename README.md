# secret-finder

[![ci](https://github.com/sotream/secret-finder/actions/workflows/ci.yaml/badge.svg)](https://github.com/sotream/secret-finder/actions/workflows/ci.yaml)
![python](https://img.shields.io/badge/python-3.9%2B-blue)
![dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)

A tiny, dependency-free CLI that catches **passwords and API keys you are about to commit**. It reads a git diff, looks only at the lines a change *adds*, and fails the build (exit code `1`) if something looks like a credential.

One file, Python 3.9+ standard library only. It runs the same on macOS, Linux, a pre-commit hook, GitHub Actions and GitLab CI.

```text
$ python3 secret_finder.py --staged
CRITICAL: AWS access key ID
  File:   src/aws.py:2
  Match:  AKIA**** (20 chars)

CRITICAL: Stripe live key
  File:   .env.local:1
  Match:  sk_l**** (34 chars)

Found 2 potential secret(s) in change.
```

Matches are always **masked** (prefix and length only), so the tool never writes a full secret into your CI logs.

## Quick start

```bash
curl -O https://raw.githubusercontent.com/sotream/secret-finder/main/secret_finder.py
python3 secret_finder.py --help
```

No install step, no virtualenv. Copy the file into your repo, or into `/usr/local/bin`.

## What it scans

| You want to scan | Command |
|---|---|
| Everything uncommitted (staged + unstaged) | `python3 secret_finder.py` |
| Only what is staged (pre-commit) | `python3 secret_finder.py --staged` |
| One commit | `python3 secret_finder.py --commit HEAD~1` |
| A branch or PR against its target | `python3 secret_finder.py --base origin/main` |
| A patch from a file or a pipe | `git diff \| python3 secret_finder.py -` (or `--file x.patch`) |

Options: `--ignore-path GLOB` (repeatable), `--format json`, `--no-github-annotations`.

Stdin is read **only when you pass `-`**. This is deliberate: CI runners usually have a non-TTY, empty stdin, and silently scanning "nothing" would turn the check into a green rubber stamp.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Clean, nothing found |
| `1` | Potential secrets found: fail the pipeline or the commit |
| `2` | Operational error: bad git ref, unreadable file, not a git repository, git missing |

Operational problems never return `0`. A broken check must not look like a passing one.

## CI/CD and hooks

### GitHub Actions

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0          # the base branch must be available for the diff
- name: Scan for secrets
  run: python3 secret_finder.py --base "origin/${{ github.base_ref }}"
```

When `GITHUB_ACTIONS=true` the tool also prints `::error file=...,line=...::` workflow commands, so findings show up **inline on the pull request diff**.

### GitLab CI

```yaml
secret-scan:
  image: python:3.13-slim
  variables:
    GIT_DEPTH: 0
  before_script: [apt-get update -qq && apt-get install -y -qq git]
  script:
    - git fetch origin "$CI_MERGE_REQUEST_TARGET_BRANCH_NAME"
    - python3 secret_finder.py --base "origin/$CI_MERGE_REQUEST_TARGET_BRANCH_NAME"
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
```

### Local pre-commit hook

```bash
# .git/hooks/pre-commit  (chmod +x)
#!/bin/sh
exec python3 path/to/secret_finder.py --staged
```

With the [pre-commit](https://pre-commit.com) framework:

```yaml
repos:
  - repo: local
    hooks:
      - id: secret-finder
        name: secret-finder
        entry: python3 secret_finder.py --staged
        language: system
        pass_filenames: false
```

## What it detects

**Tier 1: structured tokens** (severity `CRITICAL`, very few false positives)

| Rule | Shape |
|---|---|
| Private key | `-----BEGIN [RSA/EC/DSA/OPENSSH/PGP/ENCRYPTED] PRIVATE KEY-----` |
| AWS access key ID | `AKIA`, `ASIA`, `ABIA`, `ACCA` + 16 chars |
| GitHub token | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_` |
| Slack token | `xox[baprs]-...` |
| Stripe live key | `sk_live_...`, `rk_live_...` |
| Anthropic / OpenAI API key | `sk-ant-...`, `sk-...`, `sk-proj-...` |
| Google API key | `AIza...` |

**Tier 2: generic assignments** (severity `HIGH`, heuristic)

- `password`, `passwd`, `pwd`, `secret`, `token`, `api_key`, `access_key`, `private_key` assigned a quoted literal of 8+ characters, in code, YAML, `.env` or JSON style (`"api_key": "..."`).
- `Bearer <20+ chars>` authorization headers.

**What is deliberately skipped**

- Values containing `example`, `dummy`, `placeholder`, `changeme`, `<...>`, `xxx`, `redacted`, `TODO` (and, for Tier 2 only, `test`, `sample`, `fake`, `mock`).
- Lines that read from the environment (`os.environ`, `process.env`, `System.getenv`, `$ENV`, ...), and values that are references (`${VAR}`, `{{ var }}`, `%VAR%`).
- Files matching `--ignore-path`, and any line carrying the pragma `secret-finder:ignore`.
- Deleted files and removed lines.

## How it works

```
git diff / git show / stdin / file
              |
              v
   unified diff parser  -->  (file, line number, added text)
              |
              v
   Tier 1 regexes --(hit)--> finding
        | no hit
        v
   Tier 2 assignment/bearer heuristics + filters --> finding
              |
              v
   reporter: text | json | GitHub annotations   -->  exit 0 / 1 / 2
```

The parser uses the `@@ -a,b +c,d @@` hunk counters to know exactly where each hunk ends, so line numbers stay accurate with or without context lines, and an added line that merely *looks* like a diff header (`+++ b/...`) cannot confuse it. Git is invoked with `-U0`, `--no-color`, `--no-ext-diff` and `core.quotepath=false` for stable, parseable output.

## Where this tool fails

Read this before trusting a green check. It is a fast tripwire, not a vault.

| Limit | What happens | What to do |
|---|---|---|
| **Pre-existing secrets** | Only the *diff* is scanned. A key committed a year ago is never reported, and a secret that was committed and later removed still lives in history. | Run a full-history scanner once ([gitleaks](https://github.com/gitleaks/gitleaks), [trufflehog](https://github.com/trufflesecurity/trufflehog)), then rotate anything found. |
| **Multi-line secrets** | Matching is line by line. A PEM body, a key split across lines, or `"sec" + "ret"` concatenation is invisible. Only the `-----BEGIN ... PRIVATE KEY-----` header line is caught. | The header is enough to block a PEM. For the rest, use a multi-line-aware scanner. |
| **Encoding and obfuscation** | Base64, hex, URL-encoding, reversed or XOR-ed strings are not decoded. Kubernetes `Secret` manifests store values in base64, so they pass. | Not solvable with regex. Keep secrets out of manifests entirely. |
| **Unknown formats** | Only the token shapes listed above are recognised. A custom internal token, or a plain high-entropy string with no telling variable name, is not flagged. There is no entropy detector on purpose: it flags every UUID, commit SHA and hash in test data. | Add a rule to `TIER1_RULES` for your own token format. |
| **Tier 2 is a guess** | Names drive detection. `db = "hunter2hunter2"` slips through; `secret_name = "prod/db/credentials"` (a *name* of a secret) is flagged. | Use the `secret-finder:ignore` pragma or `--ignore-path` for known noise. |
| **Placeholder filters can hide real secrets** | A real password that happens to contain `test` or `sample` is skipped in Tier 2. | Accepted trade-off to keep the false-positive rate tolerable. |
| **Context blindness** | The tool does not know that `tests/fixtures/sample.json` is a fixture. | `--ignore-path 'tests/fixtures/*'`. |
| **Untracked files** | `git diff HEAD` does not include files that were never `git add`-ed. | Scan at `--staged`, in CI, or after `git add`. |
| **Merge commits** | `--commit` on a merge shows the diff against the first parent only. | In CI prefer `--base`, which compares the whole branch. |
| **Binary files and very large diffs** | Binary content is not scanned. The whole diff is held in memory. | Fine for normal PRs; not built for multi-GB patches. |
| **A finding means "rotate", not "delete"** | Once a secret is pushed it should be considered leaked, even if a later commit removes it. | Revoke and rotate first, clean history second. |

False negatives are the dangerous direction. Treat a clean result as "no obvious secrets were added", never as "no secrets".

## Development

```bash
python3 -m unittest -v       # 26 tests, standard library only
python3 secret_finder.py --staged   # the repo scans itself in CI
```

Test fixtures assemble their fake secrets from fragments at runtime, so the repository itself contains no literal credential and passes its own scan.

Adding a rule is one line in `TIER1_RULES` plus one test.
