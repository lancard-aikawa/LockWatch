"""scripts/ のファイルの文字コードと改行（Windows の cmd・PowerShell 5.1 が読み違えないように）と、exe で配る形"""
import importlib.util
import re
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
class ScriptEncodingTest(unittest.TestCase):
    def test_ps1_is_ascii_crlf(self):
        # Windows PowerShell 5.1 は BOM の無いファイルを cp932 として読み、日本語が化けて構文エラーになる (2026-10-02)。
        # BOM を付けても、書き直したときに落ちれば同じことになるので、日本語を書かない
        for p in SCRIPTS.glob("*.ps1"):
            raw = p.read_bytes()
            with self.subTest(p.name):
                self.assertTrue(raw.isascii(), f"{p.name} は ASCII だけにする（コメントも英語）")
                self.assertNotIn(b"\n", raw.replace(b"\r\n", b""), f"{p.name} は CRLF にする")

    def test_cmd_is_ascii_crlf(self):
        # cmd は UTF-8 や LF だけのバッチを読み違える。リポジトリ直下の起動用の .bat（run-lockwatch.bat）も同じ
        root = SCRIPTS.parent
        batches = [*SCRIPTS.glob("*.cmd"), *SCRIPTS.glob("*.bat"), *root.glob("*.cmd"), *root.glob("*.bat")]
        self.assertIn(root / "run-lockwatch.bat", batches)
        for p in batches:
            raw = p.read_bytes()
            with self.subTest(p.name):
                self.assertTrue(raw.isascii(), f"{p.name} は ASCII だけにする")
                self.assertNotIn(b"\n", raw.replace(b"\r\n", b""), f"{p.name} は CRLF にする")


class ExeBuildTest(unittest.TestCase):
    """exe で配る形（design.md §9.1）"""

    def test_release_pins_the_locked_pyinstaller(self):
        # Release で固める PyInstaller は、手元の scripts/build-exe.cmd（uv.lock の build の組）と同じ版にする
        root = SCRIPTS.parent
        lock = (root / "uv.lock").read_text(encoding="utf-8")
        m = re.search(r'\[\[package\]\]\r?\nname = "pyinstaller"\r?\nversion = "([^"]+)"', lock)
        self.assertIsNotNone(m, "uv.lock に pyinstaller が無い（uv add --group build pyinstaller）")
        wf = (root / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        self.assertIn(f"pyinstaller=={m.group(1)}", wf)

    def test_package_lists_existing_files(self):
        spec = importlib.util.spec_from_file_location("package_exe", SCRIPTS / "package_exe.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        for name in mod.EXTRA:
            self.assertTrue((SCRIPTS.parent / name).is_file(), name)
        for name in mod.SCRIPTS:
            self.assertTrue((SCRIPTS / name).is_file(), name)
        # 設定とデータは配らない
        self.assertIn("lockwatch.json", mod.NOT_SHIPPED)
        self.assertIn("data", mod.NOT_SHIPPED)

    def test_spec_makes_console_and_windowless_exes(self):
        text = (SCRIPTS / "lockwatch.spec").read_text(encoding="utf-8")
        self.assertIn('exe("lockwatch", True)', text)
        self.assertIn('exe("lockwatchw", False)', text)
        # 定期実行の登録は、隣の lockwatchw.exe を使う
        self.assertIn("lockwatchw.exe", (SCRIPTS / "register-task.ps1").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
