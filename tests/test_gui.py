"""lockwatch gui（design.md §9）。絞り込みなどの中身と、窓を作っての通し（画面には出さない）"""
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from lockwatch import config as cfgmod
from lockwatch import gui


def finding(pkg, vid, severity, informational=None):
    return {"lockfile": "uv.lock", "ecosystem": "PyPI", "package": pkg, "version": "1.0", "id": vid, "aliases": [],
            "severity": severity, "score": None, "fixed": ["1.1"], "informational": informational, "summary": ""}


LATEST = {
    "format": 1, "scanned_at": "2026-10-02T09:00:00+09:00", "osv_scanner": "2.6.0", "db_downloaded_at": None,
    "repos": {
        "github.com/example/web-app": {"status": "ok", "mode": "online", "lockfiles": ["uv.lock"],
                                       "findings": [finding("requests", "PYSEC-1", "high"), finding("urllib3", "PYSEC-2", "critical")]},
        "local:C:/Repos/tool": {"status": "ok", "mode": "offline", "lockfiles": ["Cargo.lock"],
                                "findings": [finding("unic-common", "RUSTSEC-1", "unknown", "unmaintained")]},
        "local:C:/Repos/broken": {"status": "error", "mode": "offline", "lockfiles": [], "findings": [], "error": "x"},
    },
    "new": [{"repo": "local:C:/Repos/tool", "package": "unic-common", "id": "RUSTSEC-1", "severity": "unknown", "informational": "unmaintained"}],
}


class RowsTest(unittest.TestCase):
    def test_heaviest_first_and_filters(self):
        rows = gui.result_rows(LATEST, set(), False, "")
        self.assertEqual([r[1] for r in rows], ["urllib3", "requests", "unic-common"])
        self.assertEqual(rows[0][5], "1.1")
        self.assertEqual([r[1] for r in gui.result_rows(LATEST, {"unmaintained"}, False, "")], ["urllib3", "requests"])
        self.assertEqual([r[1] for r in gui.result_rows(LATEST, {"critical", "high"}, False, "")], ["unic-common"])
        self.assertEqual([r[1] for r in gui.result_rows(LATEST, set(), True, "")], ["unic-common"])
        self.assertEqual([r[1] for r in gui.result_rows(LATEST, set(), False, "WEB-APP")], ["urllib3", "requests"])
        self.assertEqual(gui.result_rows(None, set(), False, ""), [])

    def test_validate_uses_config_rules(self):
        good = {"online_public": "false", "data_dir": "", "targets": "", "osv_scanner": "C:/x/osv-scanner.exe",
                "parallel": "2", "db_max_age_days": "7", "cache_max_age_hours": "20", "keep_results": "30"}
        values, errors = gui.validate(good)
        self.assertEqual(errors, [])
        self.assertEqual((values["online_public"], values["parallel"], values["data_dir"]), (False, 2, None))
        _, errors = gui.validate({**good, "parallel": "0", "keep_results": "abc"})
        self.assertEqual(len(errors), 2)
        self.assertIn("オンラインの並列数", errors[0])

    def test_every_setting_has_a_field(self):
        self.assertEqual({k for k, *_ in gui.CONFIG_FIELDS}, set(cfgmod.keys()))


class AppTest(unittest.TestCase):
    """窓を作って（出さずに）読み込み・絞り込み・保存を通す"""

    def setUp(self):
        try:
            self.root = gui.tk.Tk()
        except gui.tk.TclError as e:
            self.skipTest(f"Tk が使えません: {e}")
        self.root.withdraw()
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        self.config = d / "lockwatch.json"
        cfgmod.save(self.config, {**cfgmod.DEFAULTS, "osv_scanner": str(d / "nope.exe"), "future_key": 1})
        (d / "data" / "results").mkdir(parents=True)
        (d / "data" / "results" / "latest.json").write_text(json.dumps(LATEST), encoding="utf-8")
        patcher = mock.patch("lockwatch.status.task_registered", return_value=False)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.app = gui.App(self.root, self.config, str(d / "data"), None)

    def tearDown(self):
        self.app.close()
        self.tmp.cleanup()

    def pump(self, until, seconds=10):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            self.root.update()
            if until():
                return
            time.sleep(0.02)
        self.fail("時間内に終わりませんでした")

    def test_status_and_results_load(self):
        self.assertEqual(len(self.app.tree.get_children()), 3)
        self.pump(lambda: len(self.app.status_frame.winfo_children()) > 0)
        texts = [w.cget("text") for w in self.app.status_frame.winfo_children()]
        self.assertTrue(any("使えません" in t for t in texts), texts)  # osv-scanner が無い
        self.assertIn("未登録", texts)
        self.app.hide_vars["unmaintained"].set(True)
        self.app.show_results()
        self.assertEqual(len(self.app.tree.get_children()), 2)

    def test_save_settings(self):
        self.app.fields["online_public"].set(False)
        self.app.fields["parallel"].set("8")
        self.assertTrue(self.app.save_settings())
        saved = json.loads(self.config.read_text(encoding="utf-8"))
        self.assertEqual((saved["online_public"], saved["parallel"]), (False, 8))
        self.assertEqual(saved["future_key"], 1)  # 知らないキーは残す
        self.app.fields["parallel"].set("0")
        self.assertFalse(self.app.save_settings())
        self.assertIn("保存しませんでした", self.app.settings_message.cget("text"))
        self.assertEqual(json.loads(self.config.read_text(encoding="utf-8"))["parallel"], 8)


if __name__ == "__main__":
    unittest.main()
