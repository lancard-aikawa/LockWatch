"""対応の節の中身（design.md §7.1）"""
import unittest

from lockwatch import advice


def finding(pkg, version, vid, severity, fixed, *, lockfile="requirements.txt", **more):
    return {"lockfile": lockfile, "ecosystem": "PyPI", "package": pkg, "version": version, "id": vid, "aliases": [],
            "severity": severity, "score": None, "fixed": list(fixed), "informational": None, "malicious": False, "summary": "", **more}


def notice(kind, pkg, detail="", *, lockfile="requirements.txt", version=""):
    return {"lockfile": lockfile, "kind": kind, "package": pkg, "version": version, "detail": detail}


class VersionTest(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(advice.parse_version("2.2.10"), (2, 2, 10))
        self.assertEqual(advice.parse_version("v1.0.0"), (1,))        # 末尾の 0 は落とす（1.0 と 1.0.0 は同じ）
        self.assertEqual(advice.parse_version("12.2.0"), (12, 2))
        for odd in ("1.2b1", "1.0.0-rc.1", "", "abc", "1.0+local"):
            self.assertIsNone(advice.parse_version(odd), odd)
        self.assertLess(advice.parse_version("2.9"), advice.parse_version("2.10"))  # 数として比べる


class UpgradeTest(unittest.TestCase):
    def one(self, findings, notices=()):
        ups = [a for a in advice.actions(findings, list(notices)) if a["action"] == "upgrade"]
        self.assertEqual(len(ups), 1)
        return ups[0]

    def test_target_covers_every_finding(self):
        # 1 件ごとに「今の版より新しい一番小さい直る版」を取り、全件の中で一番大きいものにする
        a = self.one([finding("django", "2.2.0", "A", "high", ["1.11.28", "2.2.10", "3.0.3"]),
                      finding("django", "2.2.0", "B", "critical", ["5.2.8", "5.1.14", "4.2.26"]),
                      finding("django", "2.2.0", "C", "medium", ["2.2.4"])])
        self.assertEqual((a["package"], a["version"], a["target"], a["count"]), ("django", "2.2.0", "4.2.26", 3))
        self.assertEqual(a["severities"], {"critical": 1, "high": 1, "medium": 1})
        self.assertEqual((a["unfixed"], a["unclear"], a["unpinned"]), ([], [], False))

    def test_numbers_are_compared_as_numbers(self):
        a = self.one([finding("p", "2.9.0", "A", "high", ["2.10.0"]), finding("p", "2.9.0", "B", "high", ["2.9.1"])])
        self.assertEqual(a["target"], "2.10.0")

    def test_unfixed_and_unclear_are_listed(self):
        a = self.one([finding("p", "1.0", "NOFIX", "high", []),
                      finding("p", "1.0", "OLDER", "high", ["0.9"]),       # 直る版が今の版より古い
                      finding("p", "1.0", "ODD", "high", ["1.1rc1"])])     # 比べられない版
        self.assertEqual((a["target"], a["unfixed"], a["unclear"]), (None, ["NOFIX"], ["ODD", "OLDER"]))
        b = self.one([finding("q", "main", "A", "high", ["1.0"])])         # 今の版が比べられない
        self.assertEqual((b["target"], b["unclear"]), (None, ["A"]))

    def test_same_package_in_two_lockfiles_is_two_actions(self):
        acts = advice.actions([finding("p", "1.0", "A", "low", ["1.1"]),
                               finding("p", "1.0", "A", "low", ["1.1"], lockfile="sub/uv.lock"),
                               finding("z", "1.0", "B", "critical", ["2.0"])], [])
        self.assertEqual([(a["package"], a["lockfile"]) for a in acts],
                         [("z", "requirements.txt"), ("p", "requirements.txt"), ("p", "sub/uv.lock")])  # 重い順

    def test_informational_is_not_an_upgrade(self):
        acts = advice.actions([finding("old", "1.0", "RUSTSEC-1", "unknown", [], informational="unmaintained")], [])
        self.assertEqual(acts, [])

    def test_unpinned_package_is_flagged(self):
        a = self.one([finding("pillow", "12.2.0", "A", "high", ["12.3.0"])], [notice("unpinned", "Pillow", ">=12.2.0")])
        self.assertTrue(a["unpinned"])  # 名前の大文字小文字は区別しない
        b = self.one([finding("pillow", "12.2.0", "A", "high", ["12.3.0"])],
                     [notice("unpinned", "Pillow", ">=12.2.0", lockfile="other/requirements.txt")])
        self.assertFalse(b["unpinned"])  # 別の lock ファイルの注意は関係しない


class OrderTest(unittest.TestCase):
    def test_remove_then_pin_then_upgrade_then_review(self):
        findings = [finding("vite", "6.0.1", "GHSA-a", "high", ["6.0.9"], lockfile="package-lock.json"),
                    finding("evil", "9.9.9", "MAL-2", "critical", [], lockfile="package-lock.json", malicious=True),
                    finding("evil", "9.9.9", "MAL-1", "critical", [], lockfile="package-lock.json", malicious=True)]
        notices = [notice("unpinned", "jinja2"), notice("unpinned", "urllib3", ">=1.24.1"),
                   notice("unpinned", "pytest", ">=8", lockfile="requirements-test.txt"),
                   notice("recent", "fresh", "2026-10-03T08:00:00Z", lockfile="uv.lock", version="2.0.0")]
        acts = advice.actions(findings, notices)
        self.assertEqual([a["action"] for a in acts], ["remove", "pin", "pin", "upgrade", "review"])
        self.assertEqual((acts[0]["package"], acts[0]["ids"]), ("evil", ["MAL-1", "MAL-2"]))  # 同じパッケージは 1 つにまとめる
        self.assertEqual(acts[1], {"action": "pin", "lockfile": "requirements.txt",
                                   "packages": [{"package": "jinja2", "spec": ""}, {"package": "urllib3", "spec": ">=1.24.1"}]})
        self.assertEqual(acts[3]["package"], "vite")  # 悪意あるコードは「上げる」に入れない
        self.assertEqual((acts[4]["kind"], acts[4]["package"]), ("recent", "fresh"))

    def test_nothing_to_do(self):
        self.assertEqual(advice.actions([], []), [])


if __name__ == "__main__":
    unittest.main()
