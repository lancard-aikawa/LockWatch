"""診断書（report --html、design.md §7.1）"""
import io
import json
import re
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from pathlib import Path

from lockwatch import htmlreport
from lockwatch.cli import main


def finding(pkg, vid, severity, *, fixed=("1.1",), informational=None, summary="", score=None):
    return {"lockfile": "uv.lock", "ecosystem": "PyPI", "package": pkg, "version": "1.0", "id": vid, "aliases": ["CVE-2026-1"],
            "severity": severity, "score": score, "fixed": list(fixed), "informational": informational, "summary": summary}


LATEST = {
    "format": 1, "scanned_at": "2026-10-02T09:00:00+09:00", "osv_scanner": "2.6.0", "db_downloaded_at": "2026-10-01T09:00:00+09:00",
    "repos": {
        "github.com/example/web-app": {
            "status": "ok", "visibility": "public", "mode": "online", "scanned_at": "2026-10-02T09:00:00+09:00", "lockfiles": ["uv.lock"],
            "findings": [finding("requests", "PYSEC-1", "high", score=7.5),
                         finding("urllib3", "GHSA-aaaa-bbbb-cccc", "critical", fixed=()),
                         finding("evil", "PYSEC-9", "low", summary='<script>alert("x")</script> & co')]},
        "github.com/example/private-app": {
            "status": "ok", "visibility": "private", "mode": "offline", "scanned_at": "2026-10-02T09:00:00+09:00", "lockfiles": ["Cargo.lock"],
            "findings": [finding("unic-common", "RUSTSEC-1", "unknown", informational="unmaintained", fixed=())]},
        "local:C:/Repos/broken": {"status": "error", "mode": "offline", "lockfiles": [], "findings": [], "error": "フォルダがありません: <C:/x>"},
        "local:C:/Repos/empty": {"status": "no-lockfile", "visibility": "unknown", "mode": "offline", "lockfiles": [], "findings": []},
    },
    "new": [{"repo": "github.com/example/web-app", "package": "requests", "id": "PYSEC-1", "severity": "high", "informational": None},
            {"repo": "github.com/example/private-app", "package": "unic-common", "id": "RUSTSEC-1", "severity": "unknown",
             "informational": "unmaintained"}],
}


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


class RenderTest(unittest.TestCase):
    made_at = datetime(2026, 10, 2, 10, 0, tzinfo=timezone.utc)

    def render(self, rid, **kw):
        return htmlreport.render_repo(rid, LATEST["repos"][rid], LATEST, new_ids=kw.get("new_ids", set()),
                                      n_hidden=0, hide=set(), made_at=self.made_at)

    def test_file_names(self):
        names = htmlreport.file_names(["github.com/example/web-app", "local:C:/Repos/x y", "local:C:/Repos/x_y", "index"])
        self.assertEqual(names["github.com/example/web-app"], "github.com_example_web-app")
        self.assertEqual(names["local:C:/Repos/x y"], "local_C_Repos_x_y")
        self.assertRegex(names["local:C:/Repos/x_y"], r"^local_C_Repos_x_y-[0-9a-f]{8}$")  # 同じ名前になったので付ける
        self.assertNotEqual(names["index"], "index")  # 一覧と取り合わない

    def test_escapes_osv_strings(self):
        page = self.render("github.com/example/web-app")
        self.assertNotIn('<script>alert("x")', page)
        self.assertIn("&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt; &amp; co", page)

    def test_self_contained(self):
        page = self.render("github.com/example/web-app")
        self.assertNotRegex(page, r"<link|@import|src=|https?://[^\"' ]*\.(js|css)|fetch\(|XMLHttpRequest")
        self.assertEqual(page.count("<script>"), 1)  # 埋め込みの 1 つだけ
        # 外へのリンクは osv.dev の ID だけ
        self.assertEqual(set(re.findall(r'href="(https?://[^/"]+)', page)), {"https://osv.dev"})
        self.assertTrue(htmlreport.GENERATOR in page)

    def test_heaviest_first_and_marks(self):
        page = self.render("github.com/example/web-app", new_ids={("requests", "PYSEC-1")})
        order = [page.index(x) for x in ("GHSA-aaaa-bbbb-cccc", "PYSEC-1", "PYSEC-9")]
        self.assertEqual(order, sorted(order))
        self.assertIn('<span class="tag new">新規</span>', page)
        self.assertIn('href="https://osv.dev/vulnerability/GHSA-aaaa-bbbb-cccc"', page)
        self.assertIn("オンライン（api.osv.dev）", page)
        self.assertNotIn("社外に出さないでください", page)  # 公開のもの
        self.assertNotIn("脆弱性 DB の取得", page)

    def test_rows_carry_filter_and_sort_keys(self):
        page = self.render("github.com/example/web-app", new_ids={("requests", "PYSEC-1")})
        self.assertIn('<tr data-sev="high" data-info="" data-new="1" data-fixed="1" data-rank="1025">', page)  # 高・7.5
        self.assertIn('data-sev="critical" data-info="" data-new="0" data-fixed="0" data-rank="100"', page)  # 点数なしは 0 点扱い
        self.assertIn('<div class="filters" hidden>', page)  # JS が動かなければ出さない
        # 隠すの候補は、その診断書にある深刻度だけ
        self.assertIn('data-hide="sev" value="low"', page)
        self.assertNotIn('data-hide="sev" value="medium"', page)
        self.assertNotIn('data-hide="info"', page)
        self.assertIn('<th data-sort="rank"><button type="button">深刻度</button></th>', page)
        self.assertIn('data-hide="info" value="unmaintained"', self.render("github.com/example/private-app"))

    def test_malicious_is_marked_and_counted(self):
        entry = {"status": "ok", "visibility": "private", "mode": "offline", "lockfiles": ["uv.lock"],
                 "findings": [{**finding("evil-pkg", "MAL-2026-1", "critical", fixed=()), "malicious": True},
                              finding("requests", "PYSEC-1", "high")]}
        page = htmlreport.render_repo("r", entry, LATEST, new_ids=set(), n_hidden=0, hide=set(), made_at=self.made_at)
        self.assertIn('<span class="tag mal">悪意あるコード</span>', page)
        self.assertIn("悪意あるコードとして報告されたパッケージが 1 件あります", page)
        self.assertNotIn("悪意あるコード", self.render("github.com/example/web-app"))  # malicious の無い古い結果

    def test_notices_table(self):
        entry = {"status": "ok", "visibility": "private", "mode": "offline", "lockfiles": ["requirements.txt"], "findings": [],
                 "notices": [{"lockfile": "requirements.txt", "kind": "unpinned", "package": "<b>jinja2</b>", "version": "", "detail": ""},
                             {"lockfile": "package-lock.json", "kind": "not-registry", "package": "forked", "version": "1.3.0",
                              "detail": "git+ssh://github.com/x/forked.git#abc"}]}
        page = htmlreport.render_repo("r", entry, LATEST, new_ids=set(), n_hidden=0, hide=set(), made_at=self.made_at)
        self.assertIn("<h2>lock ファイルの注意</h2>", page)
        self.assertIn("版の指定がありません。照合されていません", page)
        self.assertIn("レジストリ以外から取得: git+ssh://github.com/x/forked.git#abc", page)
        self.assertIn("&lt;b&gt;jinja2&lt;/b&gt;", page)
        self.assertNotIn("<b>jinja2</b>", page)
        self.assertEqual(page.count("<table data-lw>"), 0)  # findings が無いので、絞り込みの対象の表は無い
        self.assertNotIn("lock ファイルの注意", self.render("github.com/example/web-app"))  # notices の無い古い結果
        index = htmlreport.render_index({"r": entry}, LATEST, {"r": "r"}, n_new=0, n_hidden=0, hide=set(), made_at=self.made_at)
        self.assertIn(">注意</button></th>", index)
        self.assertIn('<td class="num">2</td></tr>', index)

    def test_private_is_marked(self):
        page = self.render("github.com/example/private-app")
        self.assertIn("社外に出さないでください", page)
        self.assertIn("手元の脆弱性 DB", page)
        self.assertIn("保守終了", page)

    def test_error_and_no_lockfile(self):
        page = self.render("local:C:/Repos/broken")
        self.assertIn("照合できませんでした", page)
        self.assertIn("&lt;C:/x&gt;", page)
        self.assertIn("公開か不明", page)  # visibility の無い古い latest.json
        self.assertIn("lock ファイルがありませんでした", self.render("local:C:/Repos/empty"))

    def test_visibility_fallback(self):
        self.assertEqual(htmlreport.visibility_of({"mode": "online"}), "public")
        self.assertEqual(htmlreport.visibility_of({"mode": "offline"}), "unknown")
        self.assertEqual(htmlreport.visibility_of({"mode": "offline", "visibility": "private"}), "private")


class CliHtmlTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.data = self.dir / "data"
        self.base = ["--config", str(self.dir / "lockwatch.json"), "--data", str(self.data)]
        (self.data / "results").mkdir(parents=True)
        (self.data / "results" / "latest.json").write_text(json.dumps(LATEST, ensure_ascii=False), encoding="utf-8")
        self.reports = self.data / "reports"

    def tearDown(self):
        self.tmp.cleanup()

    def test_writes_all_and_index(self):
        code, out, _ = run([*self.base, "report", "--html"])
        self.assertEqual(code, 0)
        names = sorted(p.name for p in self.reports.glob("*.html"))
        self.assertEqual(names, ["github.com_example_private-app.html", "github.com_example_web-app.html", "index.html",
                                 "local_C_Repos_broken.html", "local_C_Repos_empty.html"])
        index = (self.reports / "index.html").read_text(encoding="utf-8")
        self.assertIn('href="github.com_example_web-app.html"', index)
        self.assertIn("社外に出さないでください", index)
        self.assertIn('<tr data-vis="public" data-has="1">', index)
        self.assertIn('<tr data-vis="unknown" data-has="0">', index)  # visibility の無い古い結果
        self.assertIn('data-only="has"', index)
        self.assertIn("4 件の診断書を書きました", out)

    def test_removes_only_our_stale_reports(self):
        self.reports.mkdir(parents=True)
        (self.reports / "gone-repo.html").write_text('<!doctype html>\n<meta name="generator" content="LockWatch 0.1.0">', encoding="utf-8")
        (self.reports / "notes.html").write_text("<p>手で書いたもの</p>", encoding="utf-8")
        code, out, _ = run([*self.base, "report", "--html"])
        self.assertEqual(code, 0)
        self.assertFalse((self.reports / "gone-repo.html").exists())
        self.assertTrue((self.reports / "notes.html").exists())
        self.assertIn("古い診断書を消しました", out)

    def test_one_repo_and_out(self):
        out_dir = self.dir / "share"
        code, _, _ = run([*self.base, "report", "--html", "--id", "github.com/example/web-app", "--out", str(out_dir)])
        self.assertEqual(code, 0)
        self.assertEqual([p.name for p in out_dir.glob("*.html")], ["github.com_example_web-app.html"])

    def test_hide(self):
        run([*self.base, "report", "--html", "--hide", "low", "--hide", "unmaintained"])
        page = (self.reports / "github.com_example_web-app.html").read_text(encoding="utf-8")
        self.assertNotIn("PYSEC-9", page)
        self.assertIn("の 1 件をこの診断書から除いています", page)
        index = (self.reports / "index.html").read_text(encoding="utf-8")
        self.assertIn("の 2 件をこの診断書から除いています", index)

    def test_usage_errors(self):
        self.assertEqual(run([*self.base, "report", "--html", "--json"])[0], 2)
        self.assertEqual(run([*self.base, "report", "--html", "--new"])[0], 2)
        self.assertEqual(run([*self.base, "report", "--out", str(self.dir)])[0], 2)
        code, _, err = run([*self.base, "report", "--html", "--id", "nope"])
        self.assertEqual(code, 2)
        self.assertIn("結果にありません", err)

    def test_text_report_hidden_count_is_not_doubled(self):
        # new の項目は findings にも入っている。両方で数えて 2 回になっていた (2026-10-02)
        _, out, _ = run([*self.base, "report", "--hide", "unmaintained"])
        self.assertIn("で 1 件を消しています", out)
        _, out, _ = run([*self.base, "report", "--new", "--hide", "unmaintained"])
        self.assertIn("で 1 件を消しています", out)

    def test_text_report_one_repo(self):
        _, out, _ = run([*self.base, "report", "--id", "github.com/example/private-app"])
        self.assertIn("unic-common", out)
        self.assertNotIn("requests", out)
        self.assertIn("新しく出たもの: 1 件", out)


if __name__ == "__main__":
    unittest.main()
