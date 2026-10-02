"""scripts/ のファイルの文字コードと改行（Windows の cmd・PowerShell 5.1 が読み違えないように）"""
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
        # cmd は UTF-8 や LF だけのバッチを読み違える
        for p in SCRIPTS.glob("*.cmd"):
            raw = p.read_bytes()
            with self.subTest(p.name):
                self.assertTrue(raw.isascii(), f"{p.name} は ASCII だけにする")
                self.assertNotIn(b"\n", raw.replace(b"\r\n", b""), f"{p.name} は CRLF にする")


if __name__ == "__main__":
    unittest.main()
