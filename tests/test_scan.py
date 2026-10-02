"""scan の通し（osv-scanner は subprocess.run を差し替えた偽物。ネットも本物の osv-scanner も使わない）"""
import io
import json
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import timedelta
from pathlib import Path
from unittest import mock

from lockwatch import fold, osv, store
from lockwatch.cli import main

FIXTURES = Path(__file__).parent / "fixtures"
_real_run = subprocess.run


class FakeOsv:
    """osv-scanner の偽物。-L で渡されたファイルの分だけ、fixture から結果を返す"""

    def __init__(self, root: Path):
        self.root = root
        self.fixture = "osv_basic.json"
        self.exit_code = None      # None なら 0 / 1 を中身で決める
        self.calls: list[list[str]] = []

    def __call__(self, argv, *args, **kwargs):
        if Path(argv[0]).name != "osv-scanner.exe":
            return _real_run(argv, *args, **kwargs)  # git など
        if "--version" in argv:
            return subprocess.CompletedProcess(argv, 0, "osv-scanner version: 2.6.0\nosv-scalibr version: 0.5.2\n", "")
        self.calls.append(list(argv))
        given = {fold.path_key(argv[i + 1]) for i, a in enumerate(argv) if a == "-L"}
        text = (FIXTURES / self.fixture).read_text(encoding="utf-8").replace("@", self.root.as_posix())
        data = json.loads(text)
        data["results"] = [r for r in data["results"] if fold.path_key(r["source"]["path"]) in given]
        code = self.exit_code if self.exit_code is not None else (1 if data["results"] else 0)
        if code in (0, 1):
            out = argv[argv.index("--output-file") + 1]
            with open(out, "w", encoding="utf-8") as f:
                json.dump(data, f)
        return subprocess.CompletedProcess(argv, code, "", "Scanned ...\nboom" if code not in (0, 1, 128) else "")

    def scans(self):
        return [c for c in self.calls if "scan" in c]


class ScanTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name).resolve()
        self.repos = self.dir / "repos"
        self.data = self.dir / "data"
        exe = self.dir / "osv-scanner.exe"
        exe.write_text("", encoding="utf-8")
        cfg = self.dir / "lockwatch.json"
        cfg.write_text(json.dumps({"osv_scanner": str(exe)}), encoding="utf-8")
        self.base = ["--config", str(cfg), "--data", str(self.data)]
        self.mkrepo("pub", {"pnpm-lock.yaml": "a", "node_modules/x/package-lock.json": "ignored"})
        self.mkrepo("priv", {"uv.lock": "b"})
        self.mkrepo("unk", {"sub/requirements-dev.txt": "c", ".venv/requirements.txt": "ignored"})
        self.mkrepo("empty", {"README.md": "no lock"})
        self.write_targets([
            {"id": "pub", "visibility": "public", "local_path": str(self.repos / "pub")},
            {"id": "priv", "visibility": "private", "local_path": str(self.repos / "priv")},
            {"id": "unk", "visibility": "unknown", "local_path": str(self.repos / "unk")},
            {"id": "empty", "visibility": "public", "local_path": str(self.repos / "empty")},
            {"id": "gone", "visibility": "private", "fetched_path": "incoming/gone"},
        ])
        self.fake = FakeOsv(self.repos)
        patcher = mock.patch.object(subprocess, "run", self.fake)
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        self.tmp.cleanup()

    def mkrepo(self, name, files):
        for rel, text in files.items():
            p = self.repos / name / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text, encoding="utf-8")

    def write_targets(self, repos):
        self.data.mkdir(parents=True, exist_ok=True)
        (self.data / "targets.json").write_text(json.dumps({"format": 1, "repos": repos}), encoding="utf-8")

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main([*self.base, *argv])
        return code, out.getvalue(), err.getvalue()

    def latest(self):
        return json.loads((self.data / "results" / "latest.json").read_text(encoding="utf-8"))

    def given(self, argv):
        return sorted(Path(argv[i + 1]).relative_to(self.repos).as_posix() for i, a in enumerate(argv) if a == "-L")

    # ---- private を外に送らない（design.md §4）

    def test_only_public_goes_online_and_offline_has_all_flags(self):
        code, _, err = self.run_cli("scan")
        self.assertEqual(code, 0, err)
        scans = self.fake.scans()
        online = [c for c in scans if "--offline" not in c]
        offline = [c for c in scans if "--offline" in c]
        self.assertEqual([self.given(c) for c in online], [["pub/pnpm-lock.yaml"]])
        self.assertIn("--no-resolve", online[0])
        # private と unknown はまとめて 1 回、手元の DB で
        self.assertEqual(len(offline), 1)
        self.assertEqual(self.given(offline[0]), ["priv/uv.lock", "unk/sub/requirements-dev.txt"])
        for flag in osv.OFFLINE_FLAGS:
            self.assertIn(flag, offline[0])

    def test_online_public_false_keeps_everything_offline(self):
        self.run_cli("config", "set", "online_public", "false")
        self.assertEqual(self.run_cli("scan")[0], 0)
        scans = self.fake.scans()
        self.assertTrue(all("--offline" in c for c in scans))
        self.assertEqual(len(scans), 1)
        self.assertEqual(self.latest()["repos"]["pub"]["mode"], "offline")

    def test_scan_online_refuses_non_public(self):
        from lockwatch.targets import PrivacyViolation, Target
        t = Target("priv", "private", self.repos / "priv", False)
        with self.assertRaises(PrivacyViolation):
            osv.scan_online("osv-scanner.exe", t, [self.repos / "priv" / "uv.lock"])
        self.assertEqual(self.fake.scans(), [])

    # ---- 結果の形（design.md §3.3）

    def test_latest_json(self):
        self.run_cli("scan")
        doc = self.latest()
        self.assertEqual(doc["format"], 1)
        self.assertEqual(doc["osv_scanner"], "2.6.0")
        self.assertIsNotNone(doc["db_downloaded_at"])
        self.assertEqual(list(doc["repos"]), ["pub", "priv", "unk", "empty", "gone"])
        r = doc["repos"]
        self.assertEqual((r["pub"]["status"], r["pub"]["mode"]), ("ok", "online"))
        self.assertEqual(r["pub"]["lockfiles"], ["pnpm-lock.yaml"])  # node_modules の中は数えない
        self.assertEqual(r["pub"]["findings"][0]["lockfile"], "pnpm-lock.yaml")
        self.assertEqual(r["unk"]["lockfiles"], ["sub/requirements-dev.txt"])  # .venv の中は数えない
        self.assertEqual(r["unk"]["findings"][0]["severity"], "critical")
        self.assertEqual((r["priv"]["status"], r["priv"]["mode"]), ("ok", "offline"))
        self.assertEqual(r["empty"]["status"], "no-lockfile")
        self.assertEqual(r["gone"]["status"], "error")
        self.assertIn("フォルダがありません", r["gone"]["error"])
        # 診断書の見出しに使う（mode だけでは online_public: false のときに区別できない）
        self.assertEqual({k: e["visibility"] for k, e in r.items()},
                         {"pub": "public", "priv": "private", "unk": "unknown", "empty": "public", "gone": "private"})
        self.assertEqual(doc["new"], [])  # 初回は空
        self.assertEqual(len(list((self.data / "results").glob("2*.json"))), 1)

    def test_new_lists_only_what_was_not_there_before(self):
        self.run_cli("scan")
        self.fake.fixture = "osv_more.json"
        (self.repos / "pub" / "pnpm-lock.yaml").write_text("a2", encoding="utf-8")  # 中身が変わればキャッシュは効かない
        code, out, _ = self.run_cli("scan")
        self.assertEqual(code, 0)
        self.assertEqual(self.latest()["new"],
                         [{"repo": "pub", "package": "vite", "id": "GHSA-cccc-cccc-cccc", "severity": "medium", "informational": None}])
        self.assertIn("新しく出たもの: 1 件", out)

    def test_informational_is_still_new(self):
        self.run_cli("scan")
        self.mkrepo("priv", {"Cargo.lock": "d"})
        code, out, _ = self.run_cli("scan")
        self.assertEqual(code, 0)
        new = {n["package"]: n for n in self.latest()["new"]}
        self.assertEqual(set(new), {"unic-common", "h2"})  # unmaintained も new から外さない
        self.assertEqual(new["unic-common"]["informational"], "unmaintained")
        self.assertIsNone(new["h2"]["informational"])
        self.assertIn("RUSTSEC-2025-0080  [unmaintained]", out)

    def test_repo_added_later_is_not_all_new(self):
        self.write_targets([{"id": "pub", "visibility": "public", "local_path": str(self.repos / "pub")}])
        self.run_cli("scan")
        self.write_targets([{"id": "pub", "visibility": "public", "local_path": str(self.repos / "pub")},
                            {"id": "priv", "visibility": "private", "local_path": str(self.repos / "priv")}])
        self.run_cli("scan")
        self.assertEqual(self.latest()["new"], [])

    def test_keep_results(self):
        self.run_cli("config", "set", "keep_results", "2")
        rdir = self.data / "results"
        rdir.mkdir(parents=True)
        for name in ("20200101T000000Z.json", "20200102T000000Z.json", "20200103T000000Z.json"):
            (rdir / name).write_text("{}", encoding="utf-8")
        self.run_cli("scan")
        names = sorted(p.name for p in rdir.glob("2*.json"))
        self.assertEqual(len(names), 2)
        self.assertEqual(names[0], "20200103T000000Z.json")

    # ---- キャッシュと DB（design.md §5.3・§6）

    def test_second_scan_uses_cache(self):
        self.run_cli("scan")
        first = self.latest()["repos"]
        n = len(self.fake.scans())
        self.run_cli("scan")
        self.assertEqual(len(self.fake.scans()), n)
        self.assertEqual(self.latest()["repos"]["pub"]["findings"], first["pub"]["findings"])
        self.assertEqual(self.latest()["repos"]["pub"]["scanned_at"], first["pub"]["scanned_at"])

    def test_expired_cache_is_not_used(self):
        self.run_cli("scan")
        old = (store.now() - timedelta(hours=21)).timestamp()
        for p in (self.data / "cache").glob("*.json"):
            obj = json.loads(p.read_text(encoding="utf-8"))
            obj["saved_at"] = store.iso(store.now() - timedelta(hours=21))
            p.write_text(json.dumps(obj), encoding="utf-8")
            os.utime(p, (old, old))
        n = len(self.fake.scans())
        self.run_cli("scan")
        self.assertEqual(len(self.fake.scans()), n + 2)

    def test_db_is_downloaded_when_missing_or_old(self):
        self.run_cli("scan")
        offline = [c for c in self.fake.scans() if "--offline" in c]
        self.assertIn(osv.DOWNLOAD_FLAG, offline[0])
        state = store.load_db_state(self.data)
        self.assertEqual(set(state), {"PyPI"})

        # 新しければ取り直さない（キャッシュを消して、もう一度呼ばせる）
        for p in (self.data / "cache").glob("*.json"):
            p.unlink()
        self.run_cli("scan")
        offline = [c for c in self.fake.scans() if "--offline" in c]
        self.assertNotIn(osv.DOWNLOAD_FLAG, offline[-1])

        # 古くなったら、キャッシュがあっても取り直して照合し直す
        store.save_db_state(self.data, {"PyPI": store.iso(store.now() - timedelta(days=8))})
        n = len(offline)
        self.run_cli("scan")
        offline = [c for c in self.fake.scans() if "--offline" in c]
        self.assertEqual(len(offline), n + 1)
        self.assertIn(osv.DOWNLOAD_FLAG, offline[-1])

    def test_new_ecosystem_triggers_download(self):
        self.run_cli("scan")
        self.mkrepo("priv", {"Cargo.lock": "d"})
        self.run_cli("scan")
        offline = [c for c in self.fake.scans() if "--offline" in c]
        self.assertIn(osv.DOWNLOAD_FLAG, offline[-1])
        self.assertEqual(set(store.load_db_state(self.data)), {"PyPI", "crates.io"})

    # ---- 失敗（design.md §7）

    def test_scanner_failure_marks_error_and_exits_4(self):
        self.fake.exit_code = 127
        code, _, _ = self.run_cli("scan")
        self.assertEqual(code, 4)
        r = self.latest()["repos"]
        for rid in ("pub", "priv", "unk"):
            self.assertEqual(r[rid]["status"], "error", rid)
            self.assertIn("127", r[rid]["error"])
        self.assertFalse((self.data / "db.json").exists())  # 失敗した取り直しは取ったことにしない

    def test_exit_128_is_no_lockfile(self):
        self.fake.exit_code = 128
        self.assertEqual(self.run_cli("scan")[0], 0)
        self.assertEqual(self.latest()["repos"]["priv"]["status"], "no-lockfile")

    def test_missing_scanner_exits_4(self):
        self.run_cli("config", "set", "osv_scanner", str(self.dir / "nope.exe"))
        code, _, err = self.run_cli("scan")
        self.assertEqual(code, 4)
        self.assertIn("osv-scanner がありません", err)

    def test_busy_exits_3(self):
        with store.exclusive(self.data):
            code, _, err = self.run_cli("scan")
        self.assertEqual(code, 3)
        self.assertIn("実行中", err)
        self.assertEqual(self.run_cli("scan")[0], 0)  # 外れたら走れる（lock ファイルが残っていても）

    def test_missing_targets_exits_2(self):
        (self.data / "targets.json").unlink()
        code, _, err = self.run_cli("scan")
        self.assertEqual(code, 2)
        self.assertIn("--repo", err)

    # ---- --repo と --id

    def test_repo_is_offline_and_writes_no_results(self):
        code, out, _ = self.run_cli("scan", "--repo", str(self.repos / "pub"))
        self.assertEqual(code, 0)
        scans = self.fake.scans()
        self.assertEqual(len(scans), 1)
        for flag in osv.OFFLINE_FLAGS:
            self.assertIn(flag, scans[0])
        self.assertFalse((self.data / "results").exists())
        self.assertIn("GHSA-aaaa-aaaa-aaaa", out)
        self.assertIn("直る版 6.0.9, 5.4.12", out)

    def test_id_replaces_only_that_repo(self):
        self.run_cli("scan")
        before = self.latest()
        self.fake.fixture = "osv_more.json"
        (self.repos / "pub" / "pnpm-lock.yaml").write_text("a2", encoding="utf-8")
        self.assertEqual(self.run_cli("scan", "--id", "pub")[0], 0)
        after = self.latest()
        self.assertEqual(len(after["repos"]["pub"]["findings"]), 2)
        self.assertEqual(after["repos"]["priv"], before["repos"]["priv"])
        self.assertEqual(after["scanned_at"], before["scanned_at"])
        self.assertEqual([n["id"] for n in after["new"]], ["GHSA-cccc-cccc-cccc"])
        self.assertEqual(len(list((self.data / "results").glob("2*.json"))), 1)  # 過去の結果は増えない

    def test_unknown_id_exits_2(self):
        self.assertEqual(self.run_cli("scan", "--id", "nope")[0], 2)

    # ---- 事前チェックと --no-cache（design.md §7）

    def check(self, rid):
        code, out, err = self.run_cli("scan", "--id", rid, "--check")
        self.assertEqual(code, 0, err)
        return json.loads(out)

    def test_check_tells_whether_cache_would_be_used(self):
        self.assertEqual(self.check("pub")["reason"], "no-cache")       # まだ照合していない
        self.assertEqual(self.check("priv")["reason"], "db-update")     # 手元の DB をまだ取っていない
        self.assertEqual(self.check("empty")["reason"], "no-lockfile")
        self.assertEqual(self.check("gone")["reason"], "error")
        self.run_cli("scan")
        n = len(self.fake.scans())
        for rid, mode in (("pub", "online"), ("priv", "offline")):
            c = self.check(rid)
            self.assertTrue(c["cached"], rid)
            self.assertEqual((c["reason"], c["mode"]), ("cached", mode))
            self.assertEqual(c["scanned_at"], self.latest()["repos"][rid]["scanned_at"])
        self.assertEqual(len(self.fake.scans()), n)  # チェックでは osv-scanner を呼ばない
        # lock ファイルが変われば、キャッシュは効かない
        (self.repos / "pub" / "pnpm-lock.yaml").write_text("a2", encoding="utf-8")
        self.assertEqual(self.check("pub")["reason"], "no-cache")

    def test_check_works_while_busy_and_needs_one_target(self):
        with store.exclusive(self.data):
            self.assertEqual(self.check("pub")["reason"], "no-cache")
        self.assertEqual(self.run_cli("scan", "--check")[0], 2)

    def test_no_cache_scans_again(self):
        self.run_cli("scan")
        first = self.latest()["repos"]["pub"]["scanned_at"]
        n = len(self.fake.scans())
        self.run_cli("scan", "--id", "pub")
        self.assertEqual(len(self.fake.scans()), n)  # キャッシュが効く
        with mock.patch.object(store, "now", return_value=store.now() + timedelta(minutes=5)):
            self.assertEqual(self.run_cli("scan", "--id", "pub", "--no-cache")[0], 0)
        self.assertEqual(len(self.fake.scans()), n + 1)
        self.assertGreater(self.latest()["repos"]["pub"]["scanned_at"], first)
        self.assertTrue(self.check("pub")["cached"])  # 照合し直した結果がキャッシュに入る

    # ---- status（RepoTether の「確かめる」、design.md §7）

    def status(self):
        with mock.patch("lockwatch.status.task_registered", return_value=False):
            code, out, err = self.run_cli("status", "--json")
        self.assertEqual(code, 0, err)
        return json.loads(out)

    def test_status_before_and_after_scan(self):
        s = self.status()
        self.assertEqual(s["osv_scanner"]["version"], "2.6.0")
        self.assertEqual((s["targets_count"], s["targets_error"]), (5, None))
        self.assertIsNone(s["latest"])
        self.assertEqual(s["db"], {})
        self.assertEqual(s["task"], {"name": "LockWatch scan", "registered": False})
        self.run_cli("scan")
        s = self.status()
        self.assertEqual(s["latest"]["repos"], 5)
        self.assertEqual(s["latest"]["errors"], 1)  # gone（フォルダが無い）
        self.assertEqual(set(s["db"]), {"PyPI"})
        self.assertEqual(len(self.fake.scans()), 2)  # status では照合しない

    def test_status_without_scanner_or_targets(self):
        (self.data / "targets.json").unlink()
        self.run_cli("config", "set", "osv_scanner", str(self.dir / "nope.exe"))
        s = self.status()
        self.assertIn("osv-scanner がありません", s["osv_scanner"]["error"])
        self.assertEqual(s["targets_error"], "ありません")
        with mock.patch("lockwatch.status.task_registered", return_value=None):
            code, out, _ = self.run_cli("status")
        self.assertEqual(code, 0)
        self.assertIn("osv-scanner    使えません", out)

    # ---- --log（定期実行の pythonw 用、design.md §7）

    def test_log_writes_output_to_file(self):
        code, out, err = self.run_cli("--log", "scan")
        self.assertEqual(code, 0)
        self.assertEqual((out, err), ("", ""))
        log = (self.data / "last-run.log").read_text(encoding="utf-8")
        self.assertIn("lockwatch ", log)
        self.assertIn("ok          online  pub", log)
        self.assertIn("フォルダがありません", log)
        self.assertTrue(log.rstrip().endswith("終了コード 0"))
        self.run_cli("--log", "report", "--new")
        log = (self.data / "last-run.log").read_text(encoding="utf-8")
        self.assertNotIn("online  pub", log)  # 毎回上書き

    def test_log_records_unexpected_errors(self):
        with mock.patch("lockwatch.cli._cmd_report", side_effect=RuntimeError("boom")):
            code, _, _ = self.run_cli("--log", "report")
        self.assertEqual(code, 1)
        log = (self.data / "last-run.log").read_text(encoding="utf-8")
        self.assertIn("RuntimeError: boom", log)
        self.assertIn("終了コード 1", log)

    # ---- report（design.md §7）

    def test_report_table_and_hide(self):
        self.mkrepo("priv", {"Cargo.lock": "d"})
        self.run_cli("scan")
        code, out, _ = self.run_cli("report")
        self.assertEqual(code, 0)
        self.assertIn("RUSTSEC-2025-0080  [unmaintained]", out)
        self.assertIn("error       offline gone", out)
        code, out, _ = self.run_cli("report", "--hide", "unmaintained", "--hide", "critical")
        self.assertEqual(code, 0)
        self.assertNotIn("RUSTSEC-2025-0080", out)
        self.assertNotIn("PYSEC-2019-132", out)        # critical
        self.assertIn("RUSTSEC-2026-0258", out)        # unknown だが知らせではないので残る
        self.assertIn("2 件を消しています", out)

    def test_report_json_and_new(self):
        self.run_cli("scan")
        self.mkrepo("priv", {"Cargo.lock": "d"})
        self.run_cli("scan")
        doc = json.loads(self.run_cli("report", "--json", "--hide", "unmaintained")[1])
        self.assertEqual(set(doc), set(self.latest()))
        pkgs = [f["package"] for f in doc["repos"]["priv"]["findings"]]
        self.assertNotIn("unic-common", pkgs)
        self.assertIn("h2", pkgs)
        self.assertEqual([n["package"] for n in doc["new"]], ["h2"])
        new = json.loads(self.run_cli("report", "--json", "--new")[1])
        self.assertEqual(sorted(n["package"] for n in new), ["h2", "unic-common"])
        code, out, _ = self.run_cli("report", "--new", "--hide", "unmaintained")
        self.assertIn("新しく出たもの: 1 件", out)
        self.assertIn("1 件を消しています", out)

    # ---- db-update（design.md §5.3）

    def test_db_update_scans_only_offline_with_download(self):
        self.run_cli("scan")
        n = len(self.fake.scans())
        code, out, err = self.run_cli("db-update")
        self.assertEqual(code, 0, err)
        scans = self.fake.scans()[n:]
        self.assertEqual(len(scans), 1)  # キャッシュがあっても取り直す。オンラインは呼ばない
        self.assertIn(osv.DOWNLOAD_FLAG, scans[0])
        for flag in osv.OFFLINE_FLAGS:
            self.assertIn(flag, scans[0])
        self.assertEqual(self.given(scans[0]), ["priv/uv.lock", "unk/sub/requirements-dev.txt"])
        self.assertIn("取り直しました: PyPI", out)
        before = self.latest()
        self.run_cli("db-update")
        self.assertEqual(self.latest(), before)  # results/ は書かない

    def test_db_update_with_nothing_offline(self):
        self.write_targets([{"id": "pub", "visibility": "public", "local_path": str(self.repos / "pub")}])
        code, out, _ = self.run_cli("db-update")
        self.assertEqual(code, 0)
        self.assertIn("取り直しませんでした", out)
        self.assertEqual(self.fake.scans(), [])

    def test_db_update_failure_exits_4(self):
        self.fake.exit_code = 127
        code, _, err = self.run_cli("db-update")
        self.assertEqual(code, 4)
        self.assertIn("取り直せませんでした", err)
        self.assertFalse((self.data / "db.json").exists())


if __name__ == "__main__":
    unittest.main()
