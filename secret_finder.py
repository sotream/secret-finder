#!/usr/bin/env python3
"""secret-finder: detect accidentally committed secrets in git changes.

Scans only the *added* lines of a unified diff, so it is fast, has no
dependencies beyond the Python 3.9+ standard library, and only complains about
what a change introduces. See README.md for usage and known limits.

Exit codes: 0 clean, 1 secrets found, 2 operational error.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import Iterable, Iterator, List, Optional, Pattern, Sequence, Tuple

EXIT_CLEAN = 0
EXIT_FOUND = 1
EXIT_ERROR = 2

IGNORE_PRAGMA = "secret-finder:ignore"


class OperationalError(Exception):
    """Raised for problems that are not findings (bad ref, not a repo, ...)."""


# --------------------------------------------------------------------------- #
# Diff parsing
# --------------------------------------------------------------------------- #

_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


@dataclass(frozen=True)
class AddedLine:
    path: str
    line: int
    text: str


def _clean_path(raw: str) -> Optional[str]:
    """Turn the part after '+++ ' into a repo-relative path (None = deleted)."""
    raw = raw.rstrip("\t").rstrip("\r")
    if raw == "/dev/null":
        return None
    if len(raw) >= 2 and raw.startswith('"') and raw.endswith('"'):
        raw = raw[1:-1]
    return raw[2:] if raw.startswith("b/") else raw


def parse_added_lines(diff_text: str) -> Iterator[AddedLine]:
    """Yield every added line with its file path and new-file line number.

    Hunk header counts are used to know when a hunk ends, so an added line whose
    content happens to start with "++ b/..." can never be mistaken for a header.
    """
    current: Optional[str] = None
    old_left = new_left = 0
    new_no = 0

    for raw in diff_text.splitlines():
        if old_left > 0 or new_left > 0:
            tag = raw[:1]
            if tag == "+":
                new_left -= 1
                if current is not None:
                    yield AddedLine(current, new_no, raw[1:])
                new_no += 1
                continue
            if tag == "-":
                old_left -= 1
                continue
            if tag == " " or raw == "":
                old_left -= 1
                new_left -= 1
                new_no += 1
                continue
            if tag == "\\":  # "\ No newline at end of file"
                continue
            old_left = new_left = 0  # malformed hunk: resync on the next header

        if raw.startswith("+++ "):
            current = _clean_path(raw[4:])
        elif raw.startswith("diff --git "):
            current = None
        else:
            m = _HUNK_RE.match(raw)
            if m:
                old_left = int(m.group(2)) if m.group(2) is not None else 1
                new_left = int(m.group(4)) if m.group(4) is not None else 1
                new_no = int(m.group(3))


# --------------------------------------------------------------------------- #
# Detection rules
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Rule:
    name: str
    severity: str
    pattern: Pattern[str]
    group: int = 0  # which regex group holds the secret value


TIER1_RULES: Tuple[Rule, ...] = (
    Rule("Private key", "CRITICAL", re.compile(
        r"-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED) )?PRIVATE KEY(?: BLOCK)?-----")),
    Rule("AWS access key ID", "CRITICAL", re.compile(
        r"\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b")),
    Rule("GitHub token", "CRITICAL", re.compile(
        r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b")),
    Rule("GitHub fine-grained token", "CRITICAL", re.compile(
        r"\bgithub_pat_[A-Za-z0-9_]{50,}\b")),
    Rule("Slack token", "CRITICAL", re.compile(
        r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*\b")),
    Rule("Stripe live key", "CRITICAL", re.compile(
        r"\b[sr]k_live_[0-9a-zA-Z]{24,}\b")),
    Rule("Anthropic API key", "CRITICAL", re.compile(
        r"\bsk-ant-[A-Za-z0-9_-]{32,}\b")),
    Rule("OpenAI API key", "CRITICAL", re.compile(
        r"\bsk-(?:proj-)?(?=[A-Za-z0-9_-]*\d)[A-Za-z0-9_-]{32,}\b")),  # digit required: skips sk-kebab-slugs
    Rule("Google API key", "CRITICAL", re.compile(
        r"\bAIza[0-9A-Za-z_-]{35}\b")),
    Rule("GitLab token", "CRITICAL", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}")),
    Rule("npm token", "CRITICAL", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    Rule("SendGrid API key", "CRITICAL", re.compile(
        r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b")),
    Rule("Slack webhook URL", "CRITICAL", re.compile(
        r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,}")),
    Rule("Azure storage account key", "CRITICAL", re.compile(
        r"AccountKey=([A-Za-z0-9+/]{60,}={0,2})"), group=1),
    Rule("JSON Web Token", "HIGH", re.compile(
        r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
)

# `password = "..."`, `"api_key": "..."`, `token: '...'` -- value must be a
# quoted literal of 8+ non-space characters.
_ASSIGNMENT_RE = re.compile(
    r"""(?ix)
    [\w.-]*(?:passw(?:or)?d|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)[\w.-]*
    ["'`]?\s*[:=]\s*
    ["'`](?P<value>[^"'`\s]{8,})["'`]
    """
)
# `DB_PASSWORD=abc123...` in .env / YAML / ini: unquoted, and the value must be
# the rest of the line and contain a digit or symbol (so `password = self.pw`
# and `token: some-css-class` are not flagged).
_UNQUOTED_ASSIGNMENT_RE = re.compile(
    r"""(?ix)
    [\w.-]*(?:passw(?:or)?d|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)[\w.-]*
    \s*[:=]\s*
    (?P<value>(?=[A-Za-z0-9_@%^&*+/!~-]*[0-9@%^&*+!~])[A-Za-z0-9_@%^&*+/!~-]{8,}=*)\s*$
    """
)
# credentials embedded in a URL authority
_URL_CRED_RE = re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^\s:/@\"'`]+:(?P<value>[^\s:/@\"'`]{4,})@")
_BEARER_RE = re.compile(r"(?i)\bbearer\s+(?P<value>[A-Za-z0-9._~+/-]{20,}=*)")

TIER2_RULES: Tuple[Rule, ...] = (
    Rule("Hard-coded credential assignment", "HIGH", _ASSIGNMENT_RE, group=1),
    Rule("Hard-coded credential assignment", "HIGH", _UNQUOTED_ASSIGNMENT_RE),
    Rule("Credentials in URL", "HIGH", _URL_CRED_RE),
    Rule("Bearer token", "HIGH", _BEARER_RE, group=1),
)

# Values containing any of these are treated as obvious non-secrets.
_PLACEHOLDER_RE = re.compile(
    r"(?i)example|dummy|placeholder|changeme|change[-_]me|your[-_ ]?(?:key|token|secret|password)"
    r"|<[^>]*>|redacted|\bxxx+|todo|fixme"
)
_TIER2_ONLY_PLACEHOLDER_RE = re.compile(r"(?i)test|sample|fake|mock")
# Values that are references to a secret, not the secret itself.
_REFERENCE_VALUE_RE = re.compile(r"^(?:\$|%|\{|<|\*{3,})")
# Identifier/slug-like values (`get_password_from_vault`, `some-css-class`).
_WORDLIKE_RE = re.compile(r"^[A-Za-z]+(?:[_.-][A-Za-z]+)+$")
# A line that reads the secret from the environment is the *right* pattern.
_ENV_ACCESS_RE = re.compile(
    r"process\.env\b|os\.environ|os\.getenv|System\.getenv|\$ENV\b|ENV\[|getenv\(|\$\{[A-Z_]+\}"
)


def mask(value: str) -> str:
    """Never echo a full secret into logs: keep a short prefix only."""
    if value.startswith("-----BEGIN"):
        return value
    if len(value) <= 8:
        return value[:2] + "****"
    return value[:4] + "****" + f" ({len(value)} chars)"


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    rule: str
    severity: str
    match: str  # already masked


def scan_line(text: str) -> List[Tuple[Rule, str]]:
    """Return (rule, raw_value) hits for one line of added code."""
    if IGNORE_PRAGMA in text:
        return []

    hits: List[Tuple[Rule, str]] = []
    for rule in TIER1_RULES:
        for m in rule.pattern.finditer(text):
            value = m.group(rule.group)
            if _PLACEHOLDER_RE.search(value):
                continue
            hits.append((rule, value))
    if hits:
        return hits  # a structured token already explains this line

    if _ENV_ACCESS_RE.search(text):
        return []
    for rule in TIER2_RULES:
        for m in rule.pattern.finditer(text):
            value = m.group("value")
            if _PLACEHOLDER_RE.search(value) or _TIER2_ONLY_PLACEHOLDER_RE.search(value):
                continue
            if _REFERENCE_VALUE_RE.match(value) or _WORDLIKE_RE.match(value):
                continue
            hits.append((rule, value))
    return hits


def scan_diff(diff_text: str, ignore_paths: Sequence[str] = ()) -> List[Finding]:
    findings: List[Finding] = []
    seen = set()
    for added in parse_added_lines(diff_text):
        if any(fnmatch.fnmatch(added.path, pat) for pat in ignore_paths):
            continue
        for rule, value in scan_line(added.text):
            key = (added.path, added.line, rule.name)
            if key in seen:
                continue
            seen.add(key)
            findings.append(Finding(added.path, added.line, rule.name, rule.severity, mask(value)))
    return findings


# --------------------------------------------------------------------------- #
# Ingestion
# --------------------------------------------------------------------------- #

_GIT_DIFF_BASE = ["git", "-c", "core.quotepath=false", "diff", "-U0", "--no-color", "--no-ext-diff"]


def _git(args: Sequence[str]) -> str:
    try:
        proc = subprocess.run(list(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    except FileNotFoundError:
        raise OperationalError("git executable not found on PATH")
    if proc.returncode != 0:
        msg = proc.stderr.decode("utf-8", "replace").strip() or f"exit code {proc.returncode}"
        raise OperationalError(f"{' '.join(args[:4])}...: {msg}")
    return proc.stdout.decode("utf-8", "replace")


def _has_head() -> bool:
    return subprocess.run(
        ["git", "rev-parse", "--verify", "--quiet", "HEAD"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    ).returncode == 0


def _untracked_diff() -> str:
    """Diff of untracked, non-ignored files: `git diff HEAD` never shows them."""
    names = _git(["git", "ls-files", "--others", "--exclude-standard", "-z"]).split("\0")
    parts = []
    for name in filter(None, names):
        # --no-index exits 1 when the files differ, which is the normal case here.
        proc = subprocess.run(
            ["git", "-c", "core.quotepath=false", "diff", "--no-index", "-U0", "--no-color",
             "--no-ext-diff", "--", os.devnull, name],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)
        if proc.returncode in (0, 1):
            parts.append(proc.stdout.decode("utf-8", "replace"))
    return "".join(parts)


def read_diff(args: argparse.Namespace) -> str:
    if args.file:
        if args.file == "-":
            return sys.stdin.read()
        try:
            with open(args.file, encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except OSError as exc:
            raise OperationalError(f"cannot read {args.file}: {exc.strerror or exc}")
    if args.commit:
        return _git(["git", "-c", "core.quotepath=false", "show", "-m", "--first-parent",
                     "--format=", "-U0", "--no-color", "--no-ext-diff", args.commit])
    if args.base:
        return _git(_GIT_DIFF_BASE + [f"{args.base}...HEAD"])
    if args.staged:
        return _git(_GIT_DIFF_BASE + ["--cached"])
    # Default: everything uncommitted (staged + unstaged) against HEAD.
    tracked = _git(_GIT_DIFF_BASE + (["HEAD"] if _has_head() else ["--cached"]))
    return tracked + _untracked_diff()


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #


def _gha_escape(value: str, prop: bool = False) -> str:
    value = value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    if prop:
        value = value.replace(":", "%3A").replace(",", "%2C")
    return value


def format_text(findings: Iterable[Finding]) -> str:
    findings = list(findings)
    out: List[str] = []
    for f in findings:
        out.append(f"{f.severity}: {f.rule}")
        out.append(f"  File:   {f.path}:{f.line}")
        out.append(f"  Match:  {f.match}")
        out.append("")
    out.append(f"Found {len(findings)} potential secret(s) in change." if findings
               else "No secrets found in change.")
    return "\n".join(out)


def format_github(findings: Iterable[Finding]) -> str:
    return "\n".join(
        f"::error file={_gha_escape(f.path, True)},line={f.line},"
        f"title={_gha_escape('Secret detected', True)}::{_gha_escape(f.rule)} ({_gha_escape(f.match)})"
        for f in findings
    )


def format_json(findings: Iterable[Finding]) -> str:
    return json.dumps(
        [{"file": f.path, "line": f.line, "rule": f.rule, "severity": f.severity, "match": f.match}
         for f in findings],
        indent=2,
    )


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="secret_finder.py",
        description="Detect accidentally committed secrets in git changes (added lines only).",
        epilog="Exit codes: 0 clean, 1 secrets found, 2 operational error.",
    )
    src = p.add_mutually_exclusive_group()
    src.add_argument("--commit", metavar="REV", help="scan the changes introduced by a commit")
    src.add_argument("--base", metavar="REF", help="scan REF...HEAD (a PR/MR against its target branch)")
    src.add_argument("--staged", action="store_true", help="scan staged changes only (pre-commit)")
    src.add_argument("--file", "-f", metavar="PATH", help="read a unified diff from PATH, or '-' for stdin")
    p.add_argument("--ignore-path", action="append", default=[], metavar="GLOB",
                   help="skip files matching GLOB (repeatable), e.g. 'tests/fixtures/*'")
    p.add_argument("--format", choices=("text", "json"), default="text")
    p.add_argument("--no-github-annotations", action="store_true",
                   help="do not emit ::error annotations even when GITHUB_ACTIONS=true")
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # A bare "-" is shorthand for "--file -" so `git diff | secret_finder.py -` works.
    argv = ["--file=-" if a == "-" else a for a in argv]
    args = build_parser().parse_args(argv)

    try:
        diff_text = read_diff(args)
    except OperationalError as exc:
        print(f"secret-finder: error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    findings = scan_diff(diff_text, args.ignore_path)

    if args.format == "json":
        print(format_json(findings))
    else:
        print(format_text(findings))
    if (findings and args.format == "text" and not args.no_github_annotations
            and os.environ.get("GITHUB_ACTIONS") == "true"):
        print(format_github(findings))
    return EXIT_FOUND if findings else EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
