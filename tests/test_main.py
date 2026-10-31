import io
import json
import os
import unittest
from pathlib import Path

from test_reviewer import CAND, ReviewerTestBase, cs, fenced, git, ok_reply

EXTRA_KEYS = ("COMMIT_SENTRY_DISABLE", "COMMIT_SENTRY_STATE_DIR", "COMMIT_SENTRY_MAX_PER_HOUR")
CONFIRM = [{"index": 0, "verdict": "confirmed", "severity": "HIGH", "reason": "reachable from input"}]
LOW = dict(CAND, severity="LOW", description="minor thing")


class MainTestBase(ReviewerTestBase):
    def setUp(self):
        super().setUp()
        saved = {k: os.environ.get(k) for k in EXTRA_KEYS}
        self.addCleanup(self._restore, saved)
        for k in EXTRA_KEYS:
            os.environ.pop(k, None)
        self.state = self.tmp / "state"
        os.environ["COMMIT_SENTRY_STATE_DIR"] = str(self.state)

    def hook_input(self, session="s1", stdout=None, command="git commit -m c", response=None):
        self.n = getattr(self, "n", 0) + 1
        c = self.commit({"a.py": f"import os\nos.system(input())  # {self.n}\n"})
        out = stdout if stdout is not None else f"[main {c.sha[:7]}] c\n 1 file changed\n"
        return json.dumps({
            "session_id": session, "cwd": self.repo, "tool_input": {"command": command},
            "tool_response": response if response is not None else {"stdout": out, "stderr": ""},
        })

    def run_hook(self, payload):
        err = io.StringIO()
        code = cs.main(["--hook"], io.StringIO(payload), err)
        return code, err.getvalue()

    def log(self):
        p = self.state / "reviews.jsonl"
        if not p.exists():
            return []
        return [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines()]


class HookTests(MainTestBase):
    def test_hook_findings_exit2(self):
        self.reply(ok_reply(fenced([CAND, LOW])), ok_reply(fenced(CONFIRM)))
        code, err = self.run_hook(self.hook_input())
        self.assertEqual(code, 2)
        self.assertIn("user input reaches os.system", err)
        rec = self.log()[-1]
        self.assertEqual(rec["outcome"], "findings")
        self.assertEqual(rec["session_id"], "s1")
        self.assertEqual(len(rec["candidates"]), 2)
        self.assertEqual(len(rec["confirmed"]), 1)
        self.assertEqual([s["name"] for s in rec["stages"]], ["investigate", "refute"])
        self.assertAlmostEqual(rec["cost_usd"], 1.0)
        self.assertEqual(rec["files"], 1)
        # only HIGH/MEDIUM candidates go to stage 2
        self.assertNotIn("minor thing", self.calls()[1]["stdin"])

    def test_hook_uses_git_operation_sha(self):
        self.reply(ok_reply(fenced([])))
        c = self.commit({"a.py": "x = 1\n"})
        payload = json.dumps({"session_id": "s", "cwd": self.repo, "tool_input": {"command": "git commit"},
                              "tool_response": {"stdout": "nothing useful",
                                                "gitOperation": {"commit": {"sha": c.sha[:9]}}}})
        self.assertEqual(self.run_hook(payload)[0], 0)
        self.assertEqual(self.log()[-1]["outcome"], "clean")

    def test_hook_string_tool_response(self):
        self.reply(ok_reply(fenced([])))
        c = self.commit({"a.py": "x = 1\n"})
        payload = json.dumps({"session_id": "s", "cwd": self.repo, "tool_input": {"command": "git commit"},
                              "tool_response": f"[main {c.sha[:7]}] c"})
        self.assertEqual(self.run_hook(payload)[0], 0)
        self.assertEqual(self.log()[-1]["sha"], c.sha)

    def test_hook_clean_silent(self):
        self.reply(ok_reply(fenced([LOW])))
        code, err = self.run_hook(self.hook_input())
        self.assertEqual((code, err), (0, ""))
        rec = self.log()[-1]
        self.assertEqual(rec["outcome"], "clean")
        self.assertEqual(len(rec["candidates"]), 1)
        self.assertEqual(len(self.calls()), 1)

    def test_hook_clean_after_refute(self):
        refuted = [{"index": 0, "verdict": "refuted", "reason": "sanitised"}]
        self.reply(ok_reply(fenced([CAND])), ok_reply(fenced(refuted)))
        code, err = self.run_hook(self.hook_input())
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(self.log()[-1]["outcome"], "clean")

    def test_hook_failed_once_per_session(self):
        os.environ["FAKE_CLAUDE_REPLY"] = ""
        self.reply(json.dumps({"is_error": True, "result": "x", "terminal_reason": "not logged in"}))
        code, err = self.run_hook(self.hook_input())
        self.assertEqual(code, 2)
        self.assertRegex(err, r"^commit-sentry: review of [0-9a-f]{7} failed \(.*\); log: .*reviews\.jsonl\n$")
        code2, err2 = self.run_hook(self.hook_input())
        self.assertEqual((code2, err2), (0, ""))
        recs = self.log()
        self.assertEqual([r["outcome"] for r in recs], ["failed", "failed"])
        self.assertTrue(recs[0]["error"])

    def test_hook_rate_limited(self):
        os.environ["COMMIT_SENTRY_MAX_PER_HOUR"] = "0"
        self.reply(ok_reply(fenced([])))
        code, err = self.run_hook(self.hook_input())
        self.assertEqual(code, 2)
        self.assertIn("failed", err)
        rec = self.log()[-1]
        self.assertEqual((rec["outcome"], rec["reason"]), ("skipped", "rate"))
        self.assertFalse(self.record.exists())
        self.assertEqual(self.run_hook(self.hook_input())[0], 0)

    def test_hook_disabled_and_recursion(self):
        self.reply(ok_reply(fenced([CAND])))
        payload = self.hook_input()
        for key in ("COMMIT_SENTRY_DISABLE", "COMMIT_SENTRY_ACTIVE"):
            os.environ[key] = "1"
            self.assertEqual(self.run_hook(payload), (0, ""))
            os.environ.pop(key)
        self.assertFalse(self.record.exists())

    def test_hook_failed_git_commit(self):
        self.reply(ok_reply(fenced([CAND])))
        payload = self.hook_input(stdout="On branch main\nnothing to commit, working tree clean\n")
        self.assertEqual(self.run_hook(payload), (0, ""))
        self.assertEqual(self.log(), [])
        self.assertFalse(self.record.exists())

    def test_hook_unknown_sha_silent(self):
        payload = json.dumps({"session_id": "s", "cwd": self.repo, "tool_input": {"command": "git commit"},
                              "tool_response": {"stdout": "[main deadbee] c"}})
        git(self.repo, "commit", "-q", "--allow-empty", "-m", "x")
        self.assertEqual(self.run_hook(payload), (0, ""))
        self.assertEqual(self.log(), [])

    def test_hook_invalid_json(self):
        code, err = self.run_hook("not json")
        self.assertEqual(code, 2)
        self.assertIn("commit-sentry: review of ? failed", err)
        self.assertEqual(self.log()[-1]["outcome"], "failed")
        self.assertEqual(self.run_hook("")[0], 0)  # once per session ("unknown")

    def test_hook_state_io_failure_never_raises(self):
        blocker = self.tmp / "file"
        blocker.write_text("x")
        os.environ["COMMIT_SENTRY_STATE_DIR"] = str(blocker / "sub")
        self.reply(ok_reply(fenced([])))
        code, _ = self.run_hook(self.hook_input())
        self.assertIn(code, (0, 2))

    def test_hook_docs_only_skipped(self):
        c = self.commit({"README.md": "hi\n"})
        payload = json.dumps({"session_id": "s", "cwd": self.repo, "tool_input": {"command": "git commit"},
                              "tool_response": {"stdout": f"[main {c.sha[:7]}] c"}})
        self.assertEqual(self.run_hook(payload), (0, ""))
        rec = self.log()[-1]
        self.assertEqual((rec["outcome"], rec["reason"]), ("skipped", "docs-only"))
        self.assertFalse(self.record.exists())

    def test_repo_disabled_by_git_config(self):
        self.reply(ok_reply(fenced([CAND])))
        git(self.repo, "config", "commit-sentry.enabled", "false")
        self.assertEqual(self.run_hook(self.hook_input()), (0, ""))
        self.assertEqual(self.log(), [])
        self.assertFalse(self.record.exists())


class ReviewModeTests(MainTestBase):
    def review(self, *args):
        out = io.StringIO()
        code = cs.main(["--review", *args], io.StringIO(""), io.StringIO(), out)
        return code, out.getvalue()

    def test_review_mode_stdout(self):
        c = self.commit({"a.py": "import os\nos.system(input())\n"})
        self.reply(ok_reply(fenced([CAND])), ok_reply(fenced(CONFIRM)))
        code, out = self.review(c.sha[:7], "--repo", self.repo)
        self.assertEqual(code, 1)
        self.assertIn("user input reaches os.system", out)
        rec = json.loads((self.state / "reviews.jsonl").read_text().splitlines()[-1])
        self.assertEqual((rec["session_id"], rec["outcome"]), ("manual", "findings"))

    def test_review_mode_clean_and_failed(self):
        c = self.commit({"a.py": "x = 1\n"})
        self.reply(ok_reply(fenced([])))
        self.assertEqual(self.review(c.sha, "--repo", self.repo), (0, "No confirmed findings.\n"))
        self.reply(json.dumps({"is_error": True, "result": "x"}))
        code, out = self.review(c.sha, "--repo", self.repo)
        self.assertEqual(code, 2)
        self.assertTrue(out.startswith("Review failed: "))

    def test_review_mode_skip_and_force(self):
        c = self.commit({"README.md": "hi\n"})
        self.reply(ok_reply(fenced([])))
        self.assertEqual(self.review(c.sha, "--repo", self.repo), (0, "Skipped: docs-only\n"))
        self.assertFalse(self.record.exists())
        self.assertEqual(self.review(c.sha, "--repo", self.repo, "--force"), (0, "No confirmed findings.\n"))

    def test_review_mode_ignores_rate_limit(self):
        os.environ["COMMIT_SENTRY_MAX_PER_HOUR"] = "0"
        c = self.commit({"a.py": "x = 1\n"})
        self.reply(ok_reply(fenced([])))
        self.assertEqual(self.review(c.sha, "--repo", self.repo)[0], 0)

    def test_review_unknown_commit(self):
        self.commit({"a.py": "x = 1\n"})
        self.assertEqual(self.review("deadbeef", "--repo", self.repo)[0], 2)


if __name__ == "__main__":
    unittest.main()
