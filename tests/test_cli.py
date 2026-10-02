import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from lockwatch.cli import main
from lockwatch.paths import app_dir


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


class CliTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.base = ["--config", str(self.dir / "lockwatch.json"), "--data", str(self.dir / "data")]

    def tearDown(self):
        self.tmp.cleanup()

    def test_report_without_results(self):
        code, _, err = run([*self.base, "report"])
        self.assertEqual(code, 2)
        self.assertIn("先に scan", err)

    def test_report_hide_rejects_typos(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as cm:
            main([*self.base, "report", "--hide", "unmaintaned"])
        self.assertEqual(cm.exception.code, 2)

    def test_config_set_show(self):
        self.assertEqual(run([*self.base, "config", "set", "online_public", "false"])[0], 0)
        self.assertEqual(run([*self.base, "config", "set", "parallel", "0"])[0], 2)  # 1 以上
        shown = json.loads(run([*self.base, "config", "show"])[1])
        self.assertFalse(shown["online_public"])
        self.assertEqual(shown["parallel"], 4)
        self.assertEqual(Path(shown["_effective_targets"]), self.dir / "data" / "targets.json")

    def test_targets_check(self):
        local = self.dir / "repo"
        local.mkdir()
        t = self.dir / "targets.json"
        t.write_text(json.dumps({"format": 1, "repos": [
            {"id": "pub", "visibility": "public", "local_path": str(local)},
            {"id": "priv", "visibility": "private", "fetched_path": "incoming/priv"},
        ]}), encoding="utf-8")
        code, out, err = run([*self.base, "targets", "check", str(t)])
        self.assertEqual(code, 0)
        self.assertIn("online   pub", out)
        self.assertIn("offline  priv（private）", out)
        self.assertIn("フォルダがありません: priv", err)

    def test_targets_check_bad_file(self):
        t = self.dir / "targets.json"
        t.write_text('{"format": 1, "repos": [{"id": "x"}]}', encoding="utf-8")
        code, _, err = run([*self.base, "targets", "check", str(t)])
        self.assertEqual(code, 2)
        self.assertIn("local_path と fetched_path", err)

    def test_piped_output_is_utf8(self):
        # 日本語の Windows の既定 (cp932) では「—」を書けずに落ちていた (2026-10-02)
        data = self.dir / "data"
        latest = {"format": 1, "scanned_at": "2026-10-02T09:00:00+09:00", "osv_scanner": "2.6.0", "db_downloaded_at": None,
                  "repos": {"r": {"status": "ok", "mode": "offline", "scanned_at": "2026-10-02T09:00:00+09:00", "lockfiles": ["uv.lock"],
                                  "findings": [{"lockfile": "uv.lock", "ecosystem": "PyPI", "package": "p", "version": "1",
                                                "id": "PYSEC-1", "aliases": [], "severity": "low", "score": None, "fixed": [],
                                                "informational": None, "summary": "a — b 日本語"}]}},
                  "new": []}
        (data / "results").mkdir(parents=True)
        (data / "results" / "latest.json").write_text(json.dumps(latest, ensure_ascii=False), encoding="utf-8")
        env = {k: v for k, v in os.environ.items() if not k.startswith("PYTHONIO") and k != "PYTHONUTF8"}
        env["PYTHONPATH"] = str(app_dir() / "src")
        for argv, want in ((["report", "--json"], "a — b 日本語"), (["report"], "直る版")):
            with self.subTest(argv=argv):
                p = subprocess.run([sys.executable, "-m", "lockwatch", *self.base, *argv], capture_output=True, env=env)
                self.assertEqual(p.returncode, 0, p.stderr.decode("utf-8", "replace"))
                self.assertIn(want, p.stdout.decode("utf-8"))

    def test_app_dir_is_repo_root(self):
        self.assertTrue((app_dir() / "pyproject.toml").is_file())


if __name__ == "__main__":
    unittest.main()
