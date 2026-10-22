import json
import tempfile
import unittest
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from lockwatch import htmlreport, runtimes
from lockwatch import targets as T

# 本家などの形をまねた小さなデータ（ネットは使わない）
EOL_PHP = [{"cycle": "8.3", "eol": "2027-12-31", "latest": "8.3.36"}, {"cycle": "8.2", "eol": "2026-12-31", "latest": "8.2.35"},
           {"cycle": "8.1", "eol": "2025-12-31", "latest": "8.1.34"}]
EOL_NODE = [{"cycle": "22", "eol": "2027-04-30", "latest": "22.23.4"}, {"cycle": "18", "eol": "2025-04-30", "latest": "18.20.8"}]
PHP8 = {"8.2.35": {"date": "21 Oct 2026", "tags": ["security"]}, "8.2.34": {"date": "24 Sep 2026", "tags": []},
        "8.2.30": {"date": "02 Jul 2026", "tags": ["security"]}, "8.3.36": {"date": "21 Oct 2026", "tags": ["security"]}}
PHP7 = {"7.4.33": {"date": "03 Nov 2022", "tags": ["security"]}}
NODE = [{"version": "v22.23.4", "date": "2026-10-21", "security": True}, {"version": "v22.23.3", "date": "2026-10-01", "security": False},
        {"version": "v22.23.2", "date": "2026-07-29", "security": True}]
ATOM = b"""<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
<entry><title>Security advisory: Critical remote code execution vulnerabilities, update now</title><updated>2026-10-21T00:35:26+00:00</updated>
<link href="https://www.php.net/index.php#2026-10-21-5" rel="alternate"/></entry>
<entry><title>PHP 8.5.12 Released!</title><updated>2026-10-21T00:24:52+00:00</updated><link href="https://www.php.net/x"/></entry>
</feed>"""
RSS = b"""<?xml version="1.0"?><rss><channel>
<item><title><![CDATA[October 2026 Security Releases]]></title><pubDate>Wed, 21 Oct 2026 22:00:00 GMT</pubDate>
<link>https://nodejs.org/en/blog/vulnerability/october-2026-security-releases</link></item>
<item><title>Old</title><pubDate>Tue, 24 Mar 2025 20:50:00 GMT</pubDate><link>https://nodejs.org/old</link></item>
</channel></rss>"""


def fake_get(url: str) -> bytes:
    if "endoflife.date/api/php" in url:
        return json.dumps(EOL_PHP).encode()
    if "endoflife.date/api/nodejs" in url:
        return json.dumps(EOL_NODE).encode()
    if "version=8" in url:
        return json.dumps(PHP8).encode()
    if "version=7" in url:
        return json.dumps(PHP7).encode()
    if "version=5" in url:
        return b"{}"
    if "dist/index.json" in url:
        return json.dumps(NODE).encode()
    if url.endswith("feed.atom"):
        return ATOM
    if url.endswith("vulnerability.xml"):
        return RSS
    raise AssertionError(url)


TODAY = date(2026, 10, 22)


class VersionTest(unittest.TestCase):
    def test_parse_and_constraints(self):
        self.assertEqual(runtimes.parse("v22.23.1"), (22, 23, 1))
        self.assertEqual(runtimes.parse("8.2.0-dev"), (8, 2, 0))
        self.assertIsNone(runtimes.parse("lts/*"))
        self.assertEqual(runtimes.lowest_in_constraint("^7.4 || ^8.0"), "7.4")
        self.assertEqual(runtimes.lowest_in_constraint(">=8.1 <9"), "8.1")
        self.assertEqual(runtimes.lowest_in_constraint("~8.2.0"), "8.2.0")
        self.assertIsNone(runtimes.lowest_in_constraint("*"))
        self.assertIsNone(runtimes.cycle_of("php", (8,)))  # 8 だけでは系列が決まらない
        self.assertEqual(runtimes.cycle_of("node", (22, 1)), "22")


class DetectTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, text):
        (self.root / name).write_text(text, encoding="utf-8")

    def test_fixed_versions_win_over_constraints(self):
        self.write("composer.json", json.dumps({"require": {"php": "^8.1", "laravel/framework": "^11"}}))
        self.write("package.json", json.dumps({"engines": {"node": ">=18"}}))
        self.assertEqual(runtimes.detect(self.root),
                         {"php": ("8.1", "composer.json の require.php（^8.1）", True), "node": ("18", "package.json の engines.node（>=18）", True)})
        self.write("Dockerfile", "FROM docker.io/library/php:8.3-fpm\nFROM node:22-alpine AS build\n")
        self.write(".nvmrc", "v22.23.1\n")
        found = runtimes.detect(self.root)
        self.assertEqual(found["php"], ("8.3", "Dockerfile", False))
        self.assertEqual(found["node"], ("22.23.1", ".nvmrc", False))

    def test_nothing_and_broken_files(self):
        self.write("composer.json", "{broken")
        self.write(".nvmrc", "lts/*\n")
        self.assertEqual(runtimes.detect(self.root), {})


class CheckTest(unittest.TestCase):
    rt = runtimes.fetch(fake_get)

    def test_fetch_shape(self):
        self.assertEqual(self.rt["php"]["cycles"]["8.2"], {"eol": "2026-12-31", "latest": "8.2.35"})
        self.assertEqual(self.rt["php"]["security"]["8.2.35"], "2026-10-21")
        self.assertNotIn("8.2.34", self.rt["php"]["security"])  # security の印の無いものは入れない
        self.assertEqual(self.rt["node"]["security"], {"22.23.4": "2026-10-21", "22.23.2": "2026-07-29"})
        self.assertEqual([a["title"] for a in self.rt["php"]["advisories"]],
                         ["Security advisory: Critical remote code execution vulnerabilities, update now"])
        self.assertEqual(self.rt["node"]["advisories"][0]["date"], "2026-10-21")

    def test_feeds_with_dtd_are_refused(self):
        evil = b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "aaaa">]><rss><channel></channel></rss>'
        with self.assertRaises(ValueError):
            runtimes.fetch(lambda u: evil if u.endswith("vulnerability.xml") else fake_get(u))

    def test_exact_version_behind(self):
        r = runtimes.check("php", "8.2.20", "x", True, self.rt, TODAY)
        # 8.2 は 2026-12-31 で終わる（あと 70 日）ので「終了が近い」
        self.assertEqual((r["cycle"], r["status"], r["exact"], r["upgrade_to"]), ("8.2", "soon", True, "8.2.35"))
        self.assertEqual([s["version"] for s in r["security"]], ["8.2.30", "8.2.35"])
        self.assertTrue(runtimes.needs_attention(r))
        latest = runtimes.check("php", "8.3.36", "x", True, self.rt, TODAY)
        self.assertEqual((latest["status"], latest["security"], latest["upgrade_to"]), ("ok", [], None))
        self.assertFalse(runtimes.needs_attention(latest))

    def test_eol_states(self):
        self.assertEqual(runtimes.check("php", "8.1", "x", False, self.rt, TODAY)["status"], "ended")
        self.assertEqual(runtimes.check("php", "8.2", "x", False, self.rt, date(2026, 11, 1))["status"], "soon")
        self.assertEqual(runtimes.check("node", "18.0.0", "x", False, self.rt, TODAY)["status"], "ended")
        unknown = runtimes.check("php", "5.6", "x", False, self.rt, TODAY)
        self.assertEqual((unknown["status"], unknown["cycle"]), ("unknown", "5.6"))
        # 系列だけ（推定）なら、修正版の有無は出さない
        only_cycle = runtimes.check("node", "22", "x", False, self.rt, TODAY)
        self.assertEqual((only_cycle["exact"], only_cycle["security"], only_cycle["latest"]), (False, [], "22.23.4"))
        self.assertEqual(runtimes.check("node", "22.23.1", "x", False, None, TODAY)["status"], "unknown")  # データが無い
        # 下限（^7.2.5 など）から推したものは、3 桁でも修正版の有無を言わない
        lower = runtimes.check("php", "8.2.5", "composer.json", False, self.rt, TODAY, lower_bound=True)
        self.assertEqual((lower["exact"], lower["security"], lower["cycle"]), (False, [], "8.2"))

    def test_confirmed_wins_and_html_escapes(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / ".php-version").write_text("8.1.2\n", encoding="utf-8")
            at = datetime(2026, 10, 22, 9, tzinfo=timezone.utc)
            rs = runtimes.check_target(Path(d), {"node": "22.23.1"}, self.rt, at)
        self.assertEqual([(r["name"], r["version"], r["confirmed"]) for r in rs], [("php", "8.1.2", False), ("node", "22.23.1", True)])
        html = htmlreport._runtimes_section(rs) + htmlreport._runtime_brief(rs)
        self.assertIn("サポート終了", html)
        self.assertIn("https://nodejs.org/en/blog/release/v22.23.4", html)
        self.assertIn("PHP 8.1 終了", html)
        bad = [{**rs[0], "source": "<script>x</script>"}]
        self.assertNotIn("<script>x", htmlreport._runtimes_section(bad))


class CacheTest(unittest.TestCase):
    def test_load_or_fetch(self):
        with tempfile.TemporaryDirectory() as d:
            data, cfg = Path(d), {"cache_max_age_hours": 20, "runtime_check": True}
            at = datetime(2026, 10, 22, 9, tzinfo=timezone.utc)
            rt, warn = runtimes.load_or_fetch(data, cfg, at, get=fake_get)
            self.assertIsNone(warn)
            self.assertTrue(runtimes.path(data).is_file())
            calls = []
            # 新しいうちは取りに行かない
            runtimes.load_or_fetch(data, cfg, at + timedelta(hours=1), get=lambda u: calls.append(u) or fake_get(u))
            self.assertEqual(calls, [])

            def down(u):
                raise OSError("network is down")
            rt2, warn = runtimes.load_or_fetch(data, cfg, at + timedelta(hours=30), get=down)
            self.assertEqual(rt2["php"], rt["php"])  # 取れなければ前のものを使う
            self.assertIn("前に取ったもの", warn)
            self.assertEqual(runtimes.load_or_fetch(data, {**cfg, "runtime_check": False}, at, get=down), (None, None))
            self.assertEqual([a["name"] for a in runtimes.recent_advisories(rt, at)], ["php", "node"])


class TargetsTest(unittest.TestCase):
    def test_runtimes_in_targets(self):
        doc = {"format": 1, "repos": [{"id": "a", "local_path": "C:/a", "runtimes": {"php": " 8.2.20 "}}]}
        self.assertEqual(T.parse(doc, Path("D:/d"))[0].runtimes, {"php": "8.2.20"})
        for bad in ({"python": "3.12"}, {"php": ""}, ["php"]):
            with self.subTest(bad), self.assertRaises(T.TargetsError):
                T.parse({"format": 1, "repos": [{"id": "a", "local_path": "C:/a", "runtimes": bad}]}, Path("D:/d"))
