"""Tests for secret_finder. Standard library only: python3 -m unittest -v

Fixture secrets are assembled from fragments at runtime so this file contains
no literal secret and passes its own scan (and GitHub push protection).
"""
import contextlib
import io
import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

import secret_finder as sf

AWS_KEY = "AKIA" + "QYLPMN5HHHFPZAM2"
GH_TOKEN = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
PASSWORD = "Zx9" + "!qW4rT7yU2"
PEM_HEADER = "-----BEGIN OPENSSH " + "PRIVATE KEY-----"


JWT = "eyJ" + "hbGciOiJIUzI1NiJ9." + "eyJ" + "zdWIiOiIxMjM0NTY3ODkw." + "dozjgNryP4J3jVmNHl0w5N"
GITLAB = "glpat-" + "abcdefghij0123456789"
NPM = "npm_" + "abcdefghijklmnopqrstuvwxyz0123456789"


def make_diff(path, added, start=1, extra_hunks=""):
    body = "".join(f"+{line}\n" for line in added)
    return (
        f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n"
        f"@@ -0,0 +{start},{len(added)} @@\n{body}{extra_hunks}"
    )


class ParserTests(unittest.TestCase):
    def test_line_numbers_across_hunks_and_context(self):
        diff = (
            "diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n"
            "@@ -1,2 +10,3 @@\n context\n+added one\n context2\n"
            "@@ -20 +30,2 @@\n-removed\n+added two\n+added three\n"
        )
        got = [(a.path, a.line, a.text) for a in sf.parse_added_lines(diff)]
        self.assertEqual(got, [("app.py", 11, "added one"), ("app.py", 30, "added two"),
                               ("app.py", 31, "added three")])

    def test_deleted_file_is_ignored(self):
        diff = ("diff --git a/old.py b/old.py\n--- a/old.py\n+++ /dev/null\n"
                "@@ -1 +0,0 @@\n-password = 'x'\n")
        self.assertEqual(list(sf.parse_added_lines(diff)), [])

    def test_added_line_that_looks_like_a_file_header(self):
        diff = make_diff("a.txt", ["++ b/evil.txt"])
        paths = {a.path for a in sf.parse_added_lines(diff)}
        self.assertEqual(paths, {"a.txt"})

    def test_multiple_files_and_no_newline_marker(self):
        diff = (make_diff("a.py", ["x = 1"])
                + "\\ No newline at end of file\n"
                + make_diff("b/c.py", ["y = 2"], start=5))
        got = [(a.path, a.line) for a in sf.parse_added_lines(diff)]
        self.assertEqual(got, [("a.py", 1), ("b/c.py", 5)])

    def test_path_with_space_and_quotes(self):
        diff = ('diff --git "a/my file.py" "b/my file.py"\n'
                '--- "a/my file.py"\n+++ "b/my file.py"\n@@ -0,0 +1 @@\n+x = 1\n')
        self.assertEqual([a.path for a in sf.parse_added_lines(diff)], ["my file.py"])


class DetectionTests(unittest.TestCase):
    def scan(self, *lines, **kw):
        return sf.scan_diff(make_diff("src/config.py", list(lines)), **kw)

    def test_finds_aws_key_with_file_and_line(self):
        f = self.scan("import os", f'KEY = "{AWS_KEY}"')
        self.assertEqual(len(f), 1)
        self.assertEqual((f[0].path, f[0].line, f[0].rule), ("src/config.py", 2, "AWS access key ID"))

    def test_finds_github_token_and_private_key(self):
        f = self.scan(f"token {GH_TOKEN}", PEM_HEADER)
        self.assertEqual({x.rule for x in f}, {"GitHub token", "Private key"})

    def test_finds_generic_assignments(self):
        f = self.scan(f'db_password = "{PASSWORD}"', f'{{"api_key": "{PASSWORD}"}}')
        self.assertEqual([x.rule for x in f], ["Hard-coded credential assignment"] * 2)

    def test_clean_diff(self):
        self.assertEqual(self.scan("def add(a, b):", "    return a + b"), [])

    def test_ignores_placeholders(self):
        self.assertEqual(self.scan(
            'password = "changeme-please"',
            'api_key = "<your-key-here>"',
            'secret = "dummy_secret_value"',
            'token = "test_token_12345"',
            'KEY = "AKIAIOSFODNN7EXAMPLE"',
        ), [])

    def test_ignores_environment_lookups_and_references(self):
        self.assertEqual(self.scan(
            'password = os.environ.get("DATABASE_PASSWORD_VALUE")',
            'const token = process.env.GITHUB_TOKEN_VALUE;',
            'password: "${DB_PASSWORD_SECRET}"',
            'password: "{{ vault_db_password }}"',
        ), [])

    def test_short_values_are_not_flagged(self):
        self.assertEqual(self.scan('password = "short"'), [])

    def test_inline_ignore_pragma(self):
        self.assertEqual(self.scan(f'KEY = "{AWS_KEY}"  # secret-finder:ignore'), [])

    def test_ignore_path_glob(self):
        diff = make_diff("tests/fixtures/sample.json", [f'"k": "{AWS_KEY}"'])
        self.assertEqual(sf.scan_diff(diff, ["tests/fixtures/*"]), [])
        self.assertEqual(len(sf.scan_diff(diff)), 1)

    def test_removed_lines_are_not_scanned(self):
        diff = ("diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1 +1 @@\n"
                f'-KEY = "{AWS_KEY}"\n+KEY = os.environ["KEY"]\n')
        self.assertEqual(sf.scan_diff(diff), [])

    def test_output_never_contains_full_secret(self):
        f = self.scan(f'KEY = "{AWS_KEY}"', f'x_password = "{PASSWORD}"')
        rendered = sf.format_text(f) + sf.format_json(f) + sf.format_github(f)
        self.assertNotIn(AWS_KEY, rendered)
        self.assertNotIn(PASSWORD, rendered)


class ExtendedDetectionTests(unittest.TestCase):
    def rules(self, line):
        return [r.name for r, _ in sf.scan_line(line)]

    def test_new_token_formats(self):
        self.assertEqual(self.rules(f"t = {JWT}"), ["JSON Web Token"])
        self.assertEqual(self.rules(f"t: {GITLAB}"), ["GitLab token"])
        self.assertEqual(self.rules(f"//registry/:_authToken={NPM}"), ["npm token"])

    def test_url_credentials(self):
        self.assertEqual(self.rules(f"u = 'postgres://admin:{PASSWORD}@db.internal/app'"),
                         ["Credentials in URL"])
        self.assertEqual(self.rules("u = 'postgres://admin:${DB_PASS}@db/app'"), [])

    def test_unquoted_and_backtick_assignments(self):
        for line in (f"DB_PASSWORD={PASSWORD}", f"password: {PASSWORD}", f"const password = `{PASSWORD}`"):
            self.assertEqual(self.rules(line), ["Hard-coded credential assignment"], line)

    def test_false_positives_stay_quiet(self):
        for line in ("sk-learn-compatible-estimator-wrapper-class-name",
                     'password = "get_password_from_vault"',
                     'token_class = "some-long-css-class"',
                     "password = self.password_value",
                     "token: some-long-css-class",
                     "password: ${DB_PASSWORD}"):
            self.assertEqual(self.rules(line), [], line)


class CliTests(unittest.TestCase):
    def run_cli(self, argv, env=None):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, env or {}, clear=False), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = sf.main(argv)
        return code, out.getvalue(), err.getvalue()

    def write_diff(self, text):
        fd, path = tempfile.mkstemp(suffix=".diff")
        self.addCleanup(os.remove, path)
        with os.fdopen(fd, "w") as fh:
            fh.write(text)
        return path

    def test_exit_1_when_secret_found(self):
        path = self.write_diff(make_diff("a.py", [f'K = "{AWS_KEY}"']))
        code, out, _ = self.run_cli(["--file", path])
        self.assertEqual(code, 1)
        self.assertIn("a.py:1", out)
        self.assertIn("Found 1 potential secret(s)", out)

    def test_exit_0_when_clean(self):
        path = self.write_diff(make_diff("a.py", ["x = 1"]))
        self.assertEqual(self.run_cli(["--file", path])[0], 0)

    def test_exit_2_on_missing_file(self):
        code, _, err = self.run_cli(["--file", "/nonexistent/x.diff"])
        self.assertEqual(code, 2)
        self.assertIn("cannot read", err)

    def test_stdin_dash(self):
        with mock.patch("sys.stdin", io.StringIO(make_diff("a.py", [f'K = "{AWS_KEY}"']))):
            self.assertEqual(self.run_cli(["-"])[0], 1)

    def test_github_annotation_only_in_actions(self):
        path = self.write_diff(make_diff("a.py", [f'K = "{AWS_KEY}"']))
        _, out, _ = self.run_cli(["--file", path], env={"GITHUB_ACTIONS": "true"})
        self.assertIn("::error file=a.py,line=1,title=Secret detected::", out)
        _, out, _ = self.run_cli(["--file", path], env={"GITHUB_ACTIONS": "false"})
        self.assertNotIn("::error", out)

    def test_json_format(self):
        path = self.write_diff(make_diff("a.py", [f'K = "{AWS_KEY}"']))
        code, out, _ = self.run_cli(["--file", path, "--format", "json"], env={"GITHUB_ACTIONS": "true"})
        import json
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out)[0]["line"], 1)


@unittest.skipUnless(shutil.which("git"), "git not installed")
class GitIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.repo = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.repo, True)
        self.prev = os.getcwd()
        os.chdir(self.repo)
        self.addCleanup(os.chdir, self.prev)
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.email", "t@example.invalid")
        self.git("config", "user.name", "t")
        self.git("config", "commit.gpgsign", "false")

    def git(self, *args):
        subprocess.run(["git", *args], check=True, stdout=subprocess.DEVNULL)

    def write(self, name, content):
        with open(os.path.join(self.repo, name), "w") as fh:
            fh.write(content)

    def run_cli(self, argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            return sf.main(argv), out.getvalue()

    def test_working_tree_staged_commit_and_base(self):
        self.write("app.py", "x = 1\n")
        self.git("add", ".")
        self.git("commit", "-qm", "init")
        self.git("checkout", "-qb", "feature")

        self.write("app.py", f'x = 1\nKEY = "{AWS_KEY}"\n')
        code, out = self.run_cli([])  # unstaged change vs HEAD
        self.assertEqual(code, 1)
        self.assertIn("app.py:2", out)
        self.assertEqual(self.run_cli(["--staged"])[0], 0)  # nothing staged yet

        self.git("add", ".")
        self.assertEqual(self.run_cli(["--staged"])[0], 1)
        self.git("commit", "-qm", "oops")

        self.assertEqual(self.run_cli([])[0], 0)  # tree is clean now
        self.assertEqual(self.run_cli(["--commit", "HEAD"])[0], 1)
        self.assertEqual(self.run_cli(["--commit", "HEAD~1"])[0], 0)
        self.assertEqual(self.run_cli(["--base", "main"])[0], 1)

    def test_untracked_files_are_scanned_by_default(self):
        self.write("a.txt", "x\n")
        self.git("add", ".")
        self.git("commit", "-qm", "init")
        self.write(".env", f"DB_PASSWORD={PASSWORD}\n")
        self.write("my file.py", f'K = "{AWS_KEY}"\n')
        code, out = self.run_cli([])
        self.assertEqual(code, 1)
        self.assertIn(".env:1", out)
        self.assertIn("my file.py:1", out)
        self.assertEqual(self.run_cli(["--staged"])[0], 0)  # explicit modes stay scoped

    def test_gitignored_untracked_files_are_skipped(self):
        self.write("a.txt", "x\n")
        self.write(".gitignore", ".env\n")
        self.git("add", ".")
        self.git("commit", "-qm", "init")
        self.write(".env", f"DB_PASSWORD={PASSWORD}\n")
        self.assertEqual(self.run_cli([])[0], 0)

    def test_bad_ref_is_operational_error(self):
        self.write("a.txt", "x\n")
        self.git("add", ".")
        self.git("commit", "-qm", "init")
        self.assertEqual(self.run_cli(["--commit", "does-not-exist"])[0], 2)

    def test_not_a_git_repo(self):
        outside = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, outside, True)
        os.chdir(outside)
        with mock.patch.dict(os.environ, {"GIT_CEILING_DIRECTORIES": os.path.dirname(outside)}):
            self.assertEqual(self.run_cli([])[0], 2)

    def test_repo_without_commits_scans_staged(self):
        self.write("a.py", f'K = "{AWS_KEY}"\n')
        self.git("add", ".")
        self.assertEqual(self.run_cli([])[0], 1)


if __name__ == "__main__":
    unittest.main()
