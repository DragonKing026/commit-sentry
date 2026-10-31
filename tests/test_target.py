import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "commit_sentry", Path(__file__).resolve().parent.parent / "hooks" / "commit_sentry.py")
cs = importlib.util.module_from_spec(_SPEC)
sys.modules["commit_sentry"] = cs  # dataclasses needs the module registered
_SPEC.loader.exec_module(cs)


def git(repo, *args):
    cfg = ["-c", "user.name=T", "-c", "user.email=t@example.invalid",
           "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null"]
    r = subprocess.run(["git", "-C", repo, *cfg, *args], check=True, capture_output=True, text=True)
    return r.stdout.strip()


def make_repo(root):
    subprocess.run(["git", "init", "-q", "-b", "main", root], check=True)
    return root


def commit_file(repo, name, content="x\n"):
    p = Path(repo, name)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    git(repo, "add", name)
    git(repo, "commit", "-q", "-m", f"add {name}")
    return git(repo, "rev-parse", "HEAD")


class TargetTests(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.tmp = os.path.realpath(self._td.name)

    def test_parse_commit_output(self):
        self.assertEqual(cs.parse_commit_output("[main 1a2b3c4] msg\n 1 file changed"), "1a2b3c4")
        self.assertEqual(cs.parse_commit_output("[zadanie/331-x (root-commit) 1a2b3c4] m"), "1a2b3c4")
        self.assertIsNone(cs.parse_commit_output("hook failed\nnothing to commit, working tree clean"))
        self.assertIsNone(cs.parse_commit_output(""))

    def test_target_repo_cd_and_C(self):
        sub = make_repo(os.path.join(self.tmp, "sub"))
        make_repo(os.path.join(self.tmp, "other"))
        self.assertEqual(cs.target_repo("cd sub && git commit -m x", self.tmp), sub)
        self.assertEqual(cs.target_repo("git -C sub commit -m x", self.tmp), sub)
        self.assertEqual(cs.target_repo("cd other; cd ../sub && git add . && git commit -m x", self.tmp), sub)
        main = make_repo(os.path.join(self.tmp, "main"))
        self.assertEqual(cs.target_repo("git commit -m x", main), main)
        # not a repo: returns the directory itself
        plain = os.path.join(self.tmp, "plain")
        os.mkdir(plain)
        self.assertEqual(cs.target_repo("cd plain && git commit -m x", self.tmp), plain)

    def test_target_repo_newlines_subshell_env(self):
        sub = make_repo(os.path.join(self.tmp, "sub"))
        main = make_repo(os.path.join(self.tmp, "main"))
        self.assertEqual(cs.target_repo("cd ../sub\ngit commit -m x", main), sub)
        self.assertEqual(cs.target_repo("git add a\ngit -C ../sub commit -m x", main), sub)
        self.assertEqual(cs.target_repo("(cd ../sub && git commit -m x)", main), sub)
        self.assertEqual(cs.target_repo("{ cd ../sub; git commit -m x; }", main), sub)
        self.assertEqual(cs.target_repo("FOO=1 git -C ../sub commit -m x", main), sub)
        self.assertEqual(cs.target_repo("FOO=1 git commit -m x", main), main)
        # newline inside a quoted message / heredoc body is not a separator
        msg = "git commit -m \"$(cat <<'EOF'\ncd ../sub\nEOF\n)\""
        self.assertEqual(cs.target_repo(msg, main), main)

    def test_target_repo_nul_byte_falls_back_to_cwd(self):
        make_repo(os.path.join(self.tmp, "sub"))
        main = make_repo(os.path.join(self.tmp, "main"))
        # found by fuzzing: expanduser("~x\0y") raised ValueError; a NUL in a path would break git too
        self.assertEqual(cs.target_repo("cd ~nouser\0x && git commit -m x", main), main)
        self.assertEqual(cs.target_repo("cd ../sub\0x && git commit -m x", main), main)
        self.assertEqual(cs.target_repo("cd ../sub; git -C a\0b commit -m x", main), main)

    def test_target_repo_git_global_options(self):
        sub = make_repo(os.path.join(self.tmp, "sub"))
        main = make_repo(os.path.join(self.tmp, "main"))
        self.assertEqual(cs.target_repo("git --git-dir=x commit -m x", main), main)
        self.assertEqual(cs.target_repo("git --work-tree ../sub commit -m x", main), main)
        self.assertEqual(cs.target_repo("git -c a=b -C ../sub commit -m x", main), sub)

    def test_root_commit_files(self):
        repo = make_repo(os.path.join(self.tmp, "r"))
        sha = commit_file(repo, "a.py")
        c = cs.resolve_commit(repo, sha[:7])
        self.assertEqual(c.sha, sha)
        self.assertEqual(c.parents, [])
        self.assertEqual(c.files, ["a.py"])
        self.assertIsNone(cs.resolve_commit(repo, "deadbee"))

    def test_skip_merge(self):
        repo = make_repo(os.path.join(self.tmp, "m"))
        commit_file(repo, "a.py")
        git(repo, "checkout", "-q", "-b", "side")
        commit_file(repo, "b.py")
        git(repo, "checkout", "-q", "main")
        commit_file(repo, "c.py")
        git(repo, "merge", "-q", "--no-ff", "-m", "merge", "side")
        c = cs.resolve_commit(repo, git(repo, "rev-parse", "--short", "HEAD"))
        self.assertEqual(len(c.parents), 2)
        self.assertEqual(cs.skip_reason(c, cs.load_rules(repo)), "merge")

    def test_docs_only(self):
        rules = cs.load_rules(self.tmp)

        def reason(files):
            return cs.skip_reason(cs.Commit("a" * 40, ["b" * 40], files), rules)

        self.assertEqual(reason(["README.md", "TODO/x/todo.md"]), "docs-only")
        self.assertIsNone(reason(["README.md", "Skills/x/SKILL.md"]))
        self.assertIsNone(reason(["a.py"]))
        self.assertIsNone(reason([".claude/settings.json"]))
        self.assertEqual(reason([]), "empty")
        self.assertIsNone(reason(["requirements.txt"]))
        self.assertIsNone(reason(["TODO/x/run.sh"]))
        self.assertEqual(reason(["TODO/x/todo.md"]), "docs-only")
        self.assertIsNone(reason(["CHANGELOG/x.py"]))
        self.assertIsNone(reason(["pkg/.claude/commands/x.md"]))
        self.assertIsNone(reason([".mcp.json"]))
        self.assertEqual(reason(["docs/guide.md"]), "docs-only")

    def test_rules_header_appends(self):
        Path(self.tmp, ".claude").mkdir()
        Path(self.tmp, ".claude", "commit-sentry.md").write_text(
            "---\ndocs-only: TODO/**, notes/*.txt\nalways-review: Skills/**/*.md\n"
            "deny-read: private/**\n---\nFree-text rules appended to the review prompt.\n")
        r = cs.load_rules(self.tmp)
        self.assertIn("*.md", r.docs_only)
        self.assertIn("TODO/**", r.docs_only)
        self.assertIn("notes/*.txt", r.docs_only)
        self.assertIn("SKILL.md", r.always_review)
        self.assertIn("Skills/**/*.md", r.always_review)
        self.assertIn("private/**", r.deny_read)
        self.assertIn(".env*", r.deny_read)
        self.assertEqual(r.text.strip(), "Free-text rules appended to the review prompt.")

    def test_rules_missing_file_and_plain_text(self):
        self.assertEqual(cs.load_rules(self.tmp).text, "")
        Path(self.tmp, ".claude").mkdir()
        Path(self.tmp, ".claude", "commit-sentry.md").write_text("Just text, no header.\n")
        self.assertEqual(cs.load_rules(self.tmp).text.strip(), "Just text, no header.")

    def test_matches(self):
        self.assertTrue(cs.matches("a/b/SKILL.md", ["SKILL.md"]))
        self.assertTrue(cs.matches("TODO/x/y.md", ["TODO/*"]))
        self.assertFalse(cs.matches("CHANGELOG/x.py", ["CHANGELOG*"]))
        self.assertFalse(cs.matches("a/b.txt/c.py", ["*.txt"]))
        self.assertFalse(cs.matches("src/a.py", ["*.md"]))


if __name__ == "__main__":
    unittest.main()
