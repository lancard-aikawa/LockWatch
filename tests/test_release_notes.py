"""Release の本文を作るスクリプト（.github/release_notes.py）を、GitHub のランナーと同じ条件で動かす"""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from lockwatch import __version__

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / ".github" / "release_notes.py"


def run(tag: str, out: Path, encoding: str):
    env = {**os.environ, "PYTHONIOENCODING": encoding}
    env.pop("PYTHONUTF8", None)
    return subprocess.run([sys.executable, str(SCRIPT), tag, str(out)], capture_output=True, env=env, timeout=60)


class ReleaseNotesTest(unittest.TestCase):
    def test_runs_on_a_console_that_cannot_show_japanese(self):
        # ランナーのコンソールは cp1252。表示の 1 行で落ちて、v0.3.0 の Release が作られなかった（2026-10-05）
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "dist" / "body.md"
            p = run(f"v{__version__}", out, "cp1252")
            self.assertEqual(p.returncode, 0, p.stderr.decode("utf-8", "replace"))
            body = out.read_text(encoding="utf-8")
        self.assertTrue(body.startswith(f"## {__version__} の変更点\n"))
        self.assertIn("## 入れ方・更新の仕方", body)   # release-intro.md が付く
        self.assertNotIn("<!--", body)

    def test_version_mismatch_exits_1_with_a_readable_reason(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "body.md"
            p = run("v999.0.0", out, "cp1252")
            self.assertEqual(p.returncode, 1)
            self.assertIn("999.0.0", p.stdout.decode("utf-8"))
            self.assertFalse(out.exists())


if __name__ == "__main__":
    unittest.main()
