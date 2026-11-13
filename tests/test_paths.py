"""exe で動くときの置き場所（design.md §9.1）"""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from lockwatch import osv, paths


class FrozenTest(unittest.TestCase):
    def test_self_command_from_source_is_python_m(self):
        self.assertEqual(paths.self_command(), [sys.executable, "-m", "lockwatch"])

    def test_self_command_when_frozen_is_the_console_exe(self):
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(sys, "frozen", True, create=True), \
                mock.patch.object(sys, "executable", str(Path(d) / "lockwatchw.exe")):
            self.assertEqual(paths.app_dir(), Path(d).resolve())
            self.assertEqual(paths.self_command(), [str(Path(d).resolve() / "lockwatch.exe")])

    def test_scanner_beside_the_program_comes_before_path(self):
        with tempfile.TemporaryDirectory() as d:
            beside = Path(d) / "osv-scanner.exe"
            beside.write_bytes(b"")
            with mock.patch.object(osv, "app_dir", return_value=Path(d)), \
                    mock.patch.object(osv.shutil, "which", return_value=r"C:\elsewhere\osv-scanner.exe"):
                self.assertEqual(osv.find_scanner(None), str(beside))
                # 設定があればそれが先
                self.assertEqual(osv.find_scanner(str(beside)), str(beside))
            beside.unlink()
            with mock.patch.object(osv, "app_dir", return_value=Path(d)), \
                    mock.patch.object(osv.shutil, "which", return_value=r"C:\elsewhere\osv-scanner.exe"):
                self.assertEqual(osv.find_scanner(None), r"C:\elsewhere\osv-scanner.exe")


if __name__ == "__main__":
    unittest.main()
