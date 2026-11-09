"""診断の後に増えた脆弱性を自動で調べる（design.md §7.4）。Claude Code は呼ばず、run_claude を差し替える"""
import io
import json
import os
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from lockwatch import assess, autoassess, store
from lockwatch.cli import main
from lockwatch.targets import Target


def finding(package, version, vid, severity="high", **kw):
    return {"lockfile": "pnpm-lock.yaml", "ecosystem": "npm", "package": package, "version": version, "id": vid, "aliases": [],
            "severity": severity, "score": None, "fixed": kw.pop("fixed", []), "last_affected": [], "informational": None,
            "malicious": False, "summary": f"{package} の問題 {vid}", "published": None, "modified": None, "kev": None, "epss": None, **kw}


GH = "github.com/me/app"
BASE_FINDINGS = [finding("vite", "6.0.1", "GHSA-1", "critical", fixed=["6.0.9"]), finding("express", "4.0.0", "GHSA-3", "high")]


def entry(findings, visibility="public"):
    return {"status": "ok", "visibility": visibility, "mode": "online", "scanned_at": "2026-11-01T09:00:00+09:00",
            "lockfiles": ["pnpm-lock.yaml"], "findings": findings, "runtimes": []}


def claude_result(items, cost=0.3):
    return {"is_error": False, "subtype": "success", "total_cost_usd": cost, "modelUsage": {"claude-test": {}},
            "structured_output": {"summary": "まとめ", "release": "Web", "items": items, "unknowns": []}}


def answer(ref, where, urgency, reason="理由"):
    return {"ref": ref, "where": where, "urgency": urgency, "reason": reason, "evidence": ["package.json:3"], "action": "上げる"}


class EligibleTest(unittest.TestCase):
    def test_only_public_github_with_clone(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self.assertTrue(autoassess.eligible(Target(GH, "public", root, False)))
            self.assertFalse(autoassess.eligible(Target(GH, "private", root, False)))
            self.assertFalse(autoassess.eligible(Target("gogs.example.com/me/app", "public", root, False)))  # 判定の誤りに備えて id でも絞る
            self.assertFalse(autoassess.eligible(Target(GH, "public", root, True)))  # lock ファイルしか無い
            self.assertFalse(autoassess.eligible(Target(GH, "public", root, False, retired=True)))
            self.assertFalse(autoassess.eligible(Target(GH, "public", root / "nope", False)))


class StatusTextTest(unittest.TestCase):
    def test_on_without_task_says_it_does_not_run(self):
        from lockwatch.status import auto_assess_text
        task = {"name": "LockWatch assess", "registered": False}
        self.assertIn("切", auto_assess_text({"enabled": False, "max_repos": 3, "task": task}))
        on = auto_assess_text({"enabled": True, "max_repos": 3, "task": task})
        self.assertIn("入", on)
        self.assertIn("動かない", on)  # 設定だけ入れてタスクが無いと動かない
        self.assertIn("登録済み", auto_assess_text({"enabled": True, "max_repos": 3, "task": {**task, "registered": True}}))


class CliNewTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.data = self.dir / "data"
        self.repo = self.dir / "repo"
        self.repo.mkdir()
        (self.data / "results").mkdir(parents=True)
        self.config = self.dir / "lockwatch.json"
        self.config.write_text(json.dumps({"auto_assess": True}), encoding="utf-8")
        self.targets = [
            {"id": GH, "visibility": "public", "local_path": str(self.repo)},
            {"id": "github.com/me/secret", "visibility": "private", "local_path": str(self.repo)},
        ]
        self.write_targets()
        self.write_latest({GH: entry(BASE_FINDINGS), "github.com/me/secret": entry(BASE_FINDINGS, "private")})
        self.base = ["--config", str(self.config), "--data", str(self.data)]
        # 人が一度 assess した（重い順に p1 = vite は開発だけ、p2 = express はリリースに入る）
        items = [answer("p1", "dev", "later", "開発サーバーだけ"), answer("p2", "release", "now", "本番で動く")]
        self.assess_once(GH, items)
        self.assess_once("github.com/me/secret", items)

    def tearDown(self):
        self.tmp.cleanup()

    def write_targets(self):
        (self.data / "targets.json").write_text(json.dumps({"format": 1, "repos": self.targets}), encoding="utf-8")

    def write_latest(self, repos):
        latest = {"format": 1, "scanned_at": "2026-11-01T09:00:00+09:00", "repos": repos, "new": []}
        (self.data / "results" / "latest.json").write_text(json.dumps(latest), encoding="utf-8")

    def run_cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main([*self.base, *argv])
        return code, out.getvalue(), err.getvalue()

    def assess_once(self, rid, items):
        with mock.patch.object(assess, "find_claude", return_value="claude.exe"), \
                mock.patch.object(assess, "run_claude", return_value=claude_result(items)):
            self.assertEqual(self.run_cli(["assess", "--id", rid])[0], 0)

    def run_new(self, results):
        """assess --new を動かす。results は run_claude が順に返すもの（例外も入れられる）"""
        with mock.patch.object(assess, "find_claude", return_value="claude.exe"), \
                mock.patch.object(assess, "run_claude", side_effect=results) as run:
            code, out, err = self.run_cli(["assess", "--new"])
        return code, out, err, run

    def grow(self, extra, rid=GH):
        latest = json.loads((self.data / "results" / "latest.json").read_text(encoding="utf-8"))
        latest["repos"][rid] = entry([*BASE_FINDINGS, *extra], latest["repos"][rid]["visibility"])
        self.write_latest(latest["repos"])

    def new_doc(self):
        return json.loads((self.data / "assess" / "new.json").read_text(encoding="utf-8"))

    def test_off_by_default(self):
        self.config.write_text("{}", encoding="utf-8")
        self.grow([finding("lodash", "4.0.0", "GHSA-7")])
        code, out, _, run = self.run_new([])
        self.assertEqual(code, 0)
        self.assertIn("何もしません", out)
        run.assert_not_called()
        self.assertFalse((self.data / "assess" / "new.json").exists())

    def test_nothing_new(self):
        code, out, _, run = self.run_new([])
        self.assertEqual(code, 0)
        self.assertIn("増えた脆弱性はありません", out)
        run.assert_not_called()

    def test_reuses_dev_and_asks_the_rest(self):
        self.grow([
            finding("vite", "6.0.1", "GHSA-9", "critical", fixed=["6.0.12"]),   # 前回 dev → 聞かない
            finding("express", "4.0.0", "GHSA-8", "medium"),                     # 前回 release → 聞く
            finding("lodash", "4.0.0", "GHSA-7", "low"),                         # 前回に無い → 聞く
            finding("ring", "0.16.0", "RUSTSEC-1", "unknown", informational="unmaintained"),  # 知らせは入れない
        ])
        evil = "<script>alert(1)</script>"
        code, out, _, run = self.run_new([claude_result([answer("p1", "release", "soon", evil), answer("p2", "dev", "later")])])
        self.assertEqual(code, 0, out)
        self.assertEqual(run.call_count, 1)
        prompt = run.call_args.args[1]
        data = json.loads(prompt[prompt.index("{\n"):])
        self.assertEqual([(p["package"], p["ids"]) for p in data["packages"]], [("express", ["GHSA-8"]), ("lodash", ["GHSA-7"])])
        self.assertEqual(data["packages"][0]["previous"], {"where": "release", "reason": "本番で動く"})
        self.assertNotIn("previous", data["packages"][1])
        self.assertEqual(data["runtimes"], [])
        self.assertIn("前回の調べ", prompt)
        self.assertEqual(run.call_args.kwargs["root"], self.repo)
        self.assertEqual(run.call_args.kwargs["cwd"], self.data / "assess")

        st = self.new_doc()["repos"][GH]
        got = {it["package"]: (it["source"], it["where"], it["urgency"], it["ids"]) for it in st["items"]}
        self.assertEqual(got, {
            "vite": ("reused", "dev", "later", ["GHSA-9"]),
            "express": ("claude", "release", "soon", ["GHSA-8"]),
            "lodash": ("claude", "dev", "later", ["GHSA-7"]),
        })
        vite = next(it for it in st["items"] if it["package"] == "vite")
        self.assertEqual(vite["upgrade_to"], "6.0.12")  # 上げる先は増えた分だけでなく全部から
        self.assertAlmostEqual(st["cost_usd"], 0.3)
        self.assertEqual(list(self.new_doc()["repos"]), [GH])  # 非公開は自動で調べない。調べるものの無かったリポジトリも書かない
        page = (self.data / "assess" / "github.com_me_app.new.html").read_text(encoding="utf-8")
        self.assertNotIn(evil, page)
        self.assertIn("&lt;script&gt;", page)
        self.assertIn("前回の判断を使った", page)
        self.assertEqual(list(self.repo.iterdir()), [])  # リポジトリには何も書かない

        # 調べ終わったものは、もう聞かない。assess --last も「変わった」と言わない
        code, out, _, run = self.run_new([])
        self.assertEqual(code, 0)
        run.assert_not_called()
        self.assertIn("増えた脆弱性はありません", out)
        self.assertFalse(json.loads(self.run_cli(["assess", "--id", GH, "--last"])[1])["changed"])

    def test_kev_and_malicious_are_always_asked(self):
        self.grow([finding("vite", "6.0.1", "GHSA-9", kev={"cve": "CVE-2026-1", "added": "2026-11-01", "ransomware": False})])
        code, _, _, run = self.run_new([claude_result([answer("p1", "dev", "soon")])])
        self.assertEqual(code, 0)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(self.new_doc()["repos"][GH]["items"][0]["source"], "claude")

    def test_failure_is_retried(self):
        self.grow([finding("lodash", "4.0.0", "GHSA-7")])
        code, _, err, _ = self.run_new([assess.AssessError("Error: not logged in")])
        self.assertEqual(code, 5)
        self.assertIn("not logged in", err)
        code, _, _, run = self.run_new([claude_result([answer("p1", "dev", "later")])])
        self.assertEqual(code, 0)
        self.assertEqual(run.call_count, 1)  # 失敗した分は次の回にもう一度聞く

    def test_missing_answer_is_retried(self):
        self.grow([finding("lodash", "4.0.0", "GHSA-7")])
        self.assertEqual(self.run_new([claude_result([])])[0], 0)
        self.assertEqual(self.new_doc()["repos"][GH]["items"], [])
        self.assertEqual(self.run_new([claude_result([answer("p1", "dev", "later")])])[3].call_count, 1)

    def test_limit_and_order(self):
        other = "github.com/me/lib"
        self.targets.append({"id": other, "visibility": "public", "local_path": str(self.repo)})
        self.write_targets()
        latest = json.loads((self.data / "results" / "latest.json").read_text(encoding="utf-8"))
        latest["repos"][other] = entry(BASE_FINDINGS)
        self.write_latest(latest["repos"])
        self.assess_once(other, [answer("p1", "dev", "later"), answer("p2", "release", "now")])
        self.grow([finding("lodash", "4.0.0", "GHSA-7", "low")])
        self.grow([finding("lodash", "4.0.0", "GHSA-6", "critical")], rid=other)
        self.config.write_text(json.dumps({"auto_assess": True, "auto_assess_max_repos": 1}), encoding="utf-8")
        code, out, _, run = self.run_new([claude_result([answer("p1", "dev", "later")])])
        self.assertEqual(code, 0)
        self.assertEqual(run.call_count, 1)
        self.assertIn(other, self.new_doc()["repos"])            # critical の方から
        self.assertEqual(self.new_doc()["repos"].get(GH, {}).get("items", []), [])
        self.assertIn("次の回に回します", out)
        self.assertIn(GH, out)

    def test_reassess_discards_auto_items(self):
        self.grow([finding("vite", "6.0.1", "GHSA-9")])
        self.run_new([])
        self.assertEqual(len(self.new_doc()["repos"][GH]["items"]), 1)
        # 人が assess をし直した（HTML の時刻が変わる）。新しい HTML が全部を含むので、自動の分は捨てる
        html = self.data / "assess" / "github.com_me_app.html"
        t = time.time() + 5
        os.utime(html, (t, t))
        self.grow([finding("vite", "6.0.1", "GHSA-9"), finding("vite", "6.0.1", "GHSA-10")])
        self.run_new([])
        items = self.new_doc()["repos"][GH]["items"]
        self.assertEqual(sorted(i for it in items for i in it["ids"]), ["GHSA-10", "GHSA-9"])

    def test_last_counts_and_new_html(self):
        got = json.loads(self.run_cli(["assess", "--id", GH, "--last"])[1])
        self.assertEqual((got["changed"], got["added"], got["removed"], got["new_html"]), (False, 0, 0, None))
        # 1 つ増えて、1 つ消えた（express を上げた）
        latest = json.loads((self.data / "results" / "latest.json").read_text(encoding="utf-8"))
        latest["repos"][GH] = entry([BASE_FINDINGS[0], finding("lodash", "4.0.0", "GHSA-7")])
        self.write_latest(latest["repos"])
        got = json.loads(self.run_cli(["assess", "--id", GH, "--last"])[1])
        self.assertEqual((got["changed"], got["added"], got["removed"], got["new_html"]), (True, 1, 1, None))
        # 増えた分を自動で調べると、増えたものは 0 になり、自動の分の HTML を答える。消えた分は残る
        self.run_new([claude_result([answer("p1", "dev", "later")])])
        got = json.loads(self.run_cli(["assess", "--id", GH, "--last"])[1])
        self.assertEqual((got["changed"], got["added"], got["removed"]), (True, 0, 1))
        self.assertEqual(Path(got["new_html"]), self.data / "assess" / "github.com_me_app.new.html")

    def test_assess_again_discards_auto_part(self):
        self.grow([finding("lodash", "4.0.0", "GHSA-7")])
        self.run_new([claude_result([answer("p1", "dev", "later")])])
        new_html = self.data / "assess" / "github.com_me_app.new.html"
        self.assertTrue(new_html.is_file())
        # 人が assess をし直すと、その場で自動の分を消す（RepoTether が new.json をそのまま読めるように）
        self.assess_once(GH, [answer("p1", "dev", "later"), answer("p2", "release", "now"), answer("p3", "dev", "later")])
        self.assertFalse(new_html.exists())
        self.assertNotIn(GH, self.new_doc()["repos"])

    def test_busy(self):
        with store.exclusive(self.data):
            code, _, err, run = self.run_new([])
        self.assertEqual(code, 3)
        self.assertIn("実行中", err)

    def test_last_needs_id(self):
        self.assertEqual(self.run_cli(["assess", "--new", "--last"])[0], 2)


if __name__ == "__main__":
    unittest.main()
