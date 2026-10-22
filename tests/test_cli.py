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

    def test_config_exclude_dirs(self):
        shown = json.loads(run([*self.base, "config", "show"])[1])
        self.assertIn("vendor", shown["exclude_dirs"])  # 既定で、取り込んだコードのフォルダを外す
        self.assertEqual(run([*self.base, "config", "set", "exclude_dirs", " vendor , examples,, "])[0], 0)
        self.assertEqual(json.loads(run([*self.base, "config", "show"])[1])["exclude_dirs"], ["vendor", "examples"])
        code, _, err = run([*self.base, "config", "set", "exclude_dirs", "app/Vendor"])
        self.assertEqual(code, 2)  # フォルダ名だけ
        self.assertIn("フォルダ名だけ", err)
        self.assertEqual(run([*self.base, "config", "set", "exclude_dirs", ""])[0], 0)
        self.assertEqual(json.loads(run([*self.base, "config", "show"])[1])["exclude_dirs"], [])  # 空は「何も外さない」

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

    def test_report_share(self):
        data = self.dir / "data"

        def entry(*findings):
            return {"status": "ok", "visibility": "private", "mode": "offline", "scanned_at": "2026-10-22T09:00:00+09:00",
                    "lockfiles": ["uv.lock"], "findings": list(findings), "notices": []}

        def finding(pkg, vid, sev, published):
            return {"lockfile": "uv.lock", "ecosystem": "PyPI", "package": pkg, "version": "1", "id": vid, "aliases": [],
                    "severity": sev, "score": None, "fixed": ["2"], "informational": None, "malicious": False,
                    "summary": "<b>x</b>", "published": published, "modified": None}

        latest = {"format": 1, "scanned_at": "2026-10-22T09:00:00+09:00", "osv_scanner": "2.6.0", "db_downloaded_at": None,
                  "repos": {"gogs.example.com/a/web": entry(finding("p", "PYSEC-1", "high", "2026-10-20T00:00:00Z"),
                                                            finding("q", "PYSEC-2", "low", "2025-01-02T00:00:00Z")),
                            "github.com/org/api": entry(),
                            "github.com/me/private-tool": entry(finding("r", "PYSEC-3", "critical", None))},
                  "new": [{"repo": "gogs.example.com/a/web", "package": "p", "id": "PYSEC-1", "severity": "high"}]}
        (data / "results").mkdir(parents=True)
        (data / "results" / "latest.json").write_text(json.dumps(latest), encoding="utf-8")
        t = {"format": 1, "repos": [
            {"id": "gogs.example.com/a/web", "visibility": "private", "local_path": "C:/w", "share": "gogs.example.com"},
            {"id": "github.com/org/api", "visibility": "private", "local_path": "C:/a", "share": "github.com/org"},
            {"id": "github.com/org/new", "visibility": "private", "local_path": "C:/n", "share": "github.com/org"},
            {"id": "github.com/org/old", "visibility": "private", "local_path": "C:/o", "share": "github.com/org", "retired": True},
            {"id": "github.com/me/private-tool", "visibility": "private", "local_path": "C:/p"}]}
        (data / "targets.json").write_text(json.dumps(t), encoding="utf-8")
        out = self.dir / "share"
        out.mkdir()
        (out / "github.com_me_private-tool.html").write_text('<meta name="generator" content="LockWatch 0.1">', encoding="utf-8")

        code, stdout, err = run([*self.base, "report", "--share", "--out", str(out)])
        self.assertEqual(code, 0, err)
        self.assertEqual(sorted(p.name for p in out.glob("*.html")),
                         ["github.com_org_api.html", "gogs.example.com_a_web.html", "index.html"])  # 載せないものの古いページは消す
        index = (out / "index.html").read_text(encoding="utf-8")
        self.assertIn("このページについて", index)
        self.assertNotIn("private-tool", index)  # share の無いものは載せない
        self.assertIn('data-grp="github.com/org"', index)
        self.assertIn("まだ照合していません", index)  # github.com/org/new
        self.assertIn("2026-10-20", index)  # 最新の発行日
        self.assertIn("廃止（照合していません）", index)
        self.assertIn("github.com/org/old", index)
        self.assertIn("前回から新規", index)
        self.assertNotIn("<b>x</b>", (out / "gogs.example.com_a_web.html").read_text(encoding="utf-8"))  # 文字はエスケープ

        self.assertEqual(run([*self.base, "report", "--share", "--html"])[0], 2)

    def test_app_dir_is_repo_root(self):
        self.assertTrue((app_dir() / "pyproject.toml").is_file())


if __name__ == "__main__":
    unittest.main()
