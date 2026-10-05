import json
import unittest
from pathlib import Path

from lockwatch import fold

FIXTURES = Path(__file__).parent / "fixtures"


def load(name, root="C:/r"):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8").replace("@", root))


class SeverityTest(unittest.TestCase):
    def test_thresholds(self):
        cases = [(9.0, "critical"), (8.99, "high"), (7.0, "high"), (6.9, "medium"), (4.0, "medium"),
                 (3.9, "low"), (0.0, "low"), (None, "unknown")]
        for score, want in cases:
            with self.subTest(score):
                self.assertEqual(fold.severity(score), want)


class BySourceTest(unittest.TestCase):
    def setUp(self):
        self.out = fold.by_source(load("osv_basic.json"))

    def one(self, rel):
        found = self.out[fold.path_key("C:/r/" + rel)]
        self.assertEqual(len(found), 1)
        return found[0]

    def test_keys_are_normalized_paths(self):
        self.assertIn(fold.path_key(r"C:\r\pub\pnpm-lock.yaml"), self.out)

    def test_finding_shape(self):
        f = self.one("pub/pnpm-lock.yaml")
        self.assertEqual(set(f), {"lockfile", "ecosystem", "package", "version", "id", "aliases",
                                  "severity", "score", "fixed", "informational", "malicious", "summary"})
        self.assertIsNone(f["informational"])
        self.assertIs(f["malicious"], False)
        self.assertEqual((f["package"], f["version"], f["ecosystem"]), ("vite", "6.0.1", "npm"))
        self.assertEqual(f["id"], "GHSA-aaaa-aaaa-aaaa")
        self.assertEqual(f["aliases"], ["CVE-2026-0001"])
        # 区分（MODERATE）を点数（7.5 = high）より優先する。点数は score に残す
        self.assertEqual((f["severity"], f["score"]), ("medium", 7.5))
        # ほかのパッケージの fixed（vite-plugin-other の 9.9.9）は混ぜない
        self.assertEqual(f["fixed"], ["6.0.9", "5.4.12"])

    def test_group_of_aliases_is_one_finding(self):
        f = self.one("priv/uv.lock")
        self.assertEqual(f["id"], "PYSEC-2018-28")
        self.assertEqual(f["aliases"], ["CVE-2018-18074", "GHSA-bbbb-bbbb-bbbb"])
        self.assertEqual(f["fixed"], ["2.20.0"])  # GIT の範囲のコミットハッシュは入れない
        self.assertEqual(f["summary"], "requests sends credentials on redirect")  # 2 つ目の記録にだけある
        # 点数が無くても、束の中の GHSA の区分で決まる
        self.assertEqual((f["severity"], f["score"]), ("low", None))

    def test_score_is_used_when_there_is_no_label(self):
        f = self.one("unk/sub/requirements-dev.txt")  # PYSEC だけ（区分なし）
        self.assertEqual((f["severity"], f["score"]), ("critical", 9.8))

    def test_informational_is_kept_and_severity_is_untouched(self):
        found = {f["package"]: f for f in self.out[fold.path_key("C:/r/priv/Cargo.lock")]}
        self.assertEqual((found["unic-common"]["informational"], found["unic-common"]["severity"]), ("unmaintained", "unknown"))
        self.assertEqual(found["unic-common"]["fixed"], [])
        self.assertEqual((found["h2"]["informational"], found["h2"]["severity"]), (None, "unknown"))

    def test_heaviest_label_wins_and_nothing_is_unknown(self):
        def label(*raws):
            return fold._label([{"database_specific": {"severity": r}} for r in raws])
        self.assertEqual(label("LOW", "HIGH", "MODERATE"), "high")
        self.assertEqual(label("MODERATE"), "medium")
        self.assertIsNone(label())
        self.assertIsNone(fold._label([{"database_specific": None}, {}]))

    def test_malicious_is_flagged_and_does_not_sink_to_unknown(self):
        out = fold.by_source(load("osv_all.json"))
        found = {f["package"]: f for f in out[fold.path_key("C:/r/pub/pnpm-lock.yaml")]}
        self.assertEqual(set(found), {"evil-pkg", "vite"})  # 脆弱性の無い esbuild は findings に入れない
        mal = found["evil-pkg"]
        # MAL- には区分も点数も無い。unknown のままにせず critical にする（score は無いまま）
        self.assertEqual((mal["malicious"], mal["severity"], mal["score"]), (True, "critical", None))
        self.assertEqual((mal["id"], mal["aliases"], mal["fixed"]), ("MAL-2026-0001", ["GHSA-mmmm-mmmm-mmmm"], []))
        self.assertEqual((found["vite"]["malicious"], found["vite"]["severity"]), (False, "medium"))
        self.assertEqual(out[fold.path_key("C:/r/priv/uv.lock")], [])
        self.assertNotIn("long text", json.dumps(out))

    def test_malicious_is_found_by_alias_and_keeps_its_own_severity(self):
        data = {"results": [{"source": {"path": "C:/r/x/package-lock.json"}, "packages": [{
            "package": {"name": "p", "version": "1", "ecosystem": "npm"},
            "groups": [{"ids": ["GHSA-x"], "aliases": ["GHSA-x", "MAL-2026-2"], "max_severity": "5.0"}],
            "vulnerabilities": [{"id": "GHSA-x"}]}]}]}
        (f,) = fold.by_source(data)[fold.path_key("C:/r/x/package-lock.json")]
        self.assertEqual((f["malicious"], f["severity"], f["score"]), (True, "medium", 5.0))

    def test_packages_by_source_lists_everything(self):
        out = fold.packages_by_source(load("osv_all.json"))
        self.assertEqual(out[fold.path_key("C:/r/priv/uv.lock")],
                         [("PyPI", "Requests", "2.32.0"), ("PyPI", "certifi", "2024.8.30")])
        self.assertIn(("npm", "evil-pkg", "9.9.9"), out[fold.path_key("C:/r/pub/pnpm-lock.yaml")])
        self.assertIn(("npm", "esbuild", "0.21.5"), out[fold.path_key("C:/r/pub/pnpm-lock.yaml")])

    def test_details_are_not_copied(self):
        self.assertNotIn("long text", json.dumps(self.out))

    def test_dedupe_sorts(self):
        a = dict(self.one("pub/pnpm-lock.yaml"), lockfile="b")
        b = dict(a, lockfile="a")
        self.assertEqual([f["lockfile"] for f in fold.dedupe([a, b, dict(a)])], ["a", "b"])


if __name__ == "__main__":
    unittest.main()
