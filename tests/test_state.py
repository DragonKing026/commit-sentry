import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "commit_sentry", Path(__file__).resolve().parent.parent / "hooks" / "commit_sentry.py")
cs = importlib.util.module_from_spec(_SPEC)
sys.modules["commit_sentry"] = cs
_SPEC.loader.exec_module(cs)


class StateTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name) / "state"
        saved = {k: os.environ.get(k) for k in
                 ("COMMIT_SENTRY_STATE_DIR", "CLAUDE_PLUGIN_DATA", "XDG_STATE_HOME")}
        self.addCleanup(self._restore, saved)
        os.environ["COMMIT_SENTRY_STATE_DIR"] = str(self.dir)

    @staticmethod
    def _restore(saved):
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_state_dir_priority_and_mode(self):
        d = cs.state_dir()
        self.assertEqual(d, self.dir)
        self.assertEqual(d.stat().st_mode & 0o777, 0o700)
        del os.environ["COMMIT_SENTRY_STATE_DIR"]
        os.environ["CLAUDE_PLUGIN_DATA"] = str(Path(self._tmp.name) / "plugin")
        self.assertEqual(cs.state_dir(), Path(self._tmp.name) / "plugin")
        del os.environ["CLAUDE_PLUGIN_DATA"]
        os.environ["XDG_STATE_HOME"] = str(Path(self._tmp.name) / "xdg")
        self.assertEqual(cs.state_dir(), Path(self._tmp.name) / "xdg" / "commit-sentry")

    def test_rate_limit(self):
        self.assertTrue(cs.take_rate_slot(1000.0, 2, 3600))
        self.assertTrue(cs.take_rate_slot(1001.0, 2, 3600))
        self.assertFalse(cs.take_rate_slot(1002.0, 2, 3600))
        self.assertTrue(cs.take_rate_slot(1000.0 + 3601, 2, 3600))

    def test_rate_limit_corrupt_file(self):
        self.dir.mkdir(parents=True)
        (self.dir / "rate.json").write_text("{not json")
        self.assertTrue(cs.take_rate_slot(10.0, 1, 3600))
        self.assertFalse(cs.take_rate_slot(11.0, 1, 3600))

    def test_first_failure_once(self):
        self.assertTrue(cs.first_failure("s1"))
        self.assertFalse(cs.first_failure("s1"))
        self.assertTrue(cs.first_failure("s2"))
        self.assertTrue(cs.first_failure(""))

    def test_append_log_lines(self):
        cs.append_log({"outcome": "clean", "note": "zażółć"})
        cs.append_log({"outcome": "failed", "ts": "custom"})
        lines = cs.log_path().read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 2)
        recs = [json.loads(x) for x in lines]
        self.assertIn("ts", recs[0])
        self.assertEqual(recs[0]["note"], "zażółć")
        self.assertEqual(recs[1]["ts"], "custom")

    def test_log_path(self):
        self.assertEqual(cs.log_path(), self.dir / "reviews.jsonl")


if __name__ == "__main__":
    unittest.main()
