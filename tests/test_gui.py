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


INVENTORY = {
    "format": 1,
    "repos": {
        "github.com/example/web-app": {"scanned_at": "2026-10-02T09:00:00+09:00", "packages": [
            ["pnpm-lock.yaml", "npm", "esbuild", "0.21.5"], ["pnpm-lock.yaml", "npm", "esbuild", "0.24.0"],
            ["pnpm-lock.yaml", "npm", "vite", "6.0.1"]]},
        "local:C:/Repos/tool": {"scanned_at": "2026-10-03T09:00:00+09:00", "packages": [
            ["Cargo.lock", "crates.io", "serde", "1.0.210"], ["package-lock.json", "npm", "esbuild", "0.24.0"]]},
    },
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

    def test_malicious_is_shown_in_the_notice_column(self):
        mal = {**finding("evil-pkg", "MAL-2026-1", "critical"), "malicious": True}
        latest = {**LATEST, "repos": {"r": {"status": "ok", "mode": "offline", "lockfiles": ["uv.lock"], "findings": [mal]}}}
        self.assertEqual([(r[1], r[3], r[6]) for r in gui.result_rows(latest, set(), False, "")], [("evil-pkg", "critical", "malicious")])
        self.assertEqual(gui.result_rows(LATEST, set(), False, "")[0][6], "")  # malicious の無い古い結果も読める

    def test_notice_rows(self):
        notices = [{"lockfile": "requirements.txt", "kind": "unpinned", "package": "jinja2", "version": "", "detail": ""},
                   {"lockfile": "uv.lock", "kind": "recent", "package": "fresh", "version": "2.0.0", "detail": "2026-10-03T08:00:00Z"}]
        latest = {**LATEST, "repos": {**LATEST["repos"], "r": {"status": "ok", "findings": [], "notices": notices}}}
        rows = gui.notice_rows(latest, set(), "")
        self.assertEqual([(r[0], r[1], r[2], r[3], r[5]) for r in rows],
                         [("r", "unpinned", "jinja2", "", "requirements.txt"), ("r", "recent", "fresh", "2.0.0", "uv.lock")])
        self.assertIn("照合されていません", rows[0][4])
        self.assertEqual([r[2] for r in gui.notice_rows(latest, {"unpinned"}, "")], ["fresh"])
        self.assertEqual([r[2] for r in gui.notice_rows(latest, set(), "UV.LOCK")], ["fresh"])
        self.assertEqual(gui.notice_rows(LATEST, set(), ""), [])  # notices の無い古い結果
        self.assertEqual(gui.notice_rows(None, set(), ""), [])

    def test_package_rows(self):
        rows, n = gui.package_rows(INVENTORY, "ESB", "")  # 部分一致。大文字小文字は区別しない
        self.assertEqual(rows, [("esbuild", "0.21.5", "npm", "github.com/example/web-app", "pnpm-lock.yaml"),
                                ("esbuild", "0.24.0", "npm", "github.com/example/web-app", "pnpm-lock.yaml"),
                                ("esbuild", "0.24.0", "npm", "local:C:/Repos/tool", "package-lock.json")])
        self.assertEqual(n, 2)
        self.assertEqual([r[0] for r in gui.package_rows(INVENTORY, "*build", " 0.24.0 ")[0]], ["esbuild", "esbuild"])
        self.assertEqual(gui.package_rows(INVENTORY, "build", "")[0][0][0], "esbuild")
        self.assertEqual(gui.package_rows(INVENTORY, "build*", "")[0], [])  # * ? を書いたら全体の一致
        self.assertEqual([r[0] for r in gui.package_rows(INVENTORY, "", "1.0.210")[0]], ["serde"])  # 版だけでも引ける
        self.assertEqual(gui.package_rows(INVENTORY, "left-pad", ""), ([], 0))
        self.assertEqual(gui.package_rows(INVENTORY, "  ", ""), (None, 0))  # 何も入れなければ出さない

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
        self.data = d / "data"
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

    def test_packages_tab(self):
        tree, count = self.app.package_tree, self.app.package_count
        self.assertIn("台帳がまだありません", count.cget("text"))
        (self.data / "results" / "packages.json").write_text(json.dumps(INVENTORY), encoding="utf-8")
        self.app.reload()
        self.assertEqual(len(tree.get_children()), 0)  # 何も入れなければ出さない
        self.assertIn("2 リポジトリ・5 件の台帳", count.cget("text"))
        self.app.package_name.set("esbuild")
        self.assertEqual(len(tree.get_children()), 3)
        self.assertIn("3 件 (2 リポジトリ)", count.cget("text"))
        self.assertIn("2026-10-02T09:00:00+09:00 〜 2026-10-03T09:00:00+09:00", count.cget("text"))
        self.app.package_version.set("0.21.5")
        self.assertEqual([tree.item(i, "values")[3] for i in tree.get_children()], ["github.com/example/web-app"])
        self.app.package_name.set("left-pad")
        self.assertIn("使っているリポジトリはありません", count.cget("text"))
        with mock.patch.object(gui, "PACKAGE_ROWS_MAX", 2):
            self.app.package_version.set("")
            self.app.package_name.set("e")
        self.assertEqual(len(tree.get_children()), 2)
        self.assertIn("5 件 (2 リポジトリ)。先頭の 2 件だけを表示", count.cget("text"))  # e を含むのは esbuild 3・serde・vite
        # 件数の行が窓の中に収まっている（下の行は表より先に置く）
        self.app.notebook.select(2)
        self.root.deiconify()
        self.root.update()
        self.assertLessEqual(count.winfo_rooty() + count.winfo_height(), self.root.winfo_rooty() + self.root.winfo_height())
        self.assertEqual(self.app.notebook.tab(2, "text"), "台帳")
        self.root.withdraw()

    def test_notices_tab(self):
        self.assertEqual([self.app.notebook.tab(i, "text") for i in self.app.notebook.tabs()], ["状態", "結果", "台帳", "注意", "設定"])
        self.assertIn("0 件を表示 (全体 0 件)", self.app.notice_count.cget("text"))
        notices = [{"lockfile": "requirements.txt", "kind": "unpinned", "package": "jinja2", "version": "", "detail": ""},
                   {"lockfile": "uv.lock", "kind": "recent", "package": "fresh", "version": "2.0.0", "detail": "2026-10-03T08:00:00Z"}]
        latest = {**LATEST, "repos": {"r": {"status": "ok", "mode": "offline", "lockfiles": [], "findings": [], "notices": notices}}}
        (self.data / "results" / "latest.json").write_text(json.dumps(latest), encoding="utf-8")
        self.app.reload()
        tree = self.app.notice_tree
        self.assertEqual([tree.item(i, "values")[1] for i in tree.get_children()], ["版を固定していない", "公開直後の版"])
        self.app.notice_hide_vars["unpinned"].set(True)
        self.app.show_notices()
        self.assertEqual(len(tree.get_children()), 1)
        self.assertIn("1 件を表示 (全体 2 件)", self.app.notice_count.cget("text"))

    def test_report_argv_passes_hide(self):
        self.app.hide_vars["unmaintained"].set(True)
        self.app.hide_vars["low"].set(True)
        argv = self.app.report_argv()
        self.assertEqual(argv[argv.index("report"):], ["report", "--html", "--hide", "low", "--hide", "unmaintained"])
        self.assertIn(self.app.report_button, self.app.buttons)  # 仕事の最中は押せない

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
