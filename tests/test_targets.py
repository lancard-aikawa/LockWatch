import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from lockwatch import lockfiles
from lockwatch import targets as T
from lockwatch.lockfiles import is_lockfile


def doc(*repos):
    return {"format": 1, "repos": list(repos)}


def repo(rid, vis="public", **kw):
    r = {"id": rid, "visibility": vis}
    r.update(kw or {"local_path": f"C:/Repos/{rid}"})
    return r


class ParseTest(unittest.TestCase):
    data = Path("D:/lw-data")

    def test_local_wins_over_fetched_and_relative_fetched_is_under_data(self):
        ts = T.parse(doc(repo("a", local_path="C:/a", fetched_path="incoming/a"),
                         repo("b", "private", fetched_path="incoming/b")), self.data)
        self.assertEqual(ts[0].root, Path("C:/a"))
        self.assertFalse(ts[0].fetched)
        self.assertEqual(ts[1].root, self.data / "incoming/b")
        self.assertTrue(ts[1].fetched)

    def test_missing_visibility_is_unknown(self):
        r = {"id": "x", "local_path": "C:/x"}
        self.assertEqual(T.parse(doc(r), self.data)[0].visibility, "unknown")

    def test_errors_name_the_entry(self):
        cases = {
            "format": ({"format": 2, "repos": []}, "format"),
            "no path": (doc({"id": "x", "visibility": "public"}), "x"),
            "bad visibility": (doc(repo("x", "internal")), "visibility"),
            "duplicate": (doc(repo("x"), repo("x")), "重複"),
            "no id": (doc({"visibility": "public", "local_path": "C:/x"}), "repos[0].id"),
        }
        for name, (obj, needle) in cases.items():
            with self.subTest(name), self.assertRaises(T.TargetsError) as cm:
                T.parse(obj, self.data)
            self.assertIn(needle, str(cm.exception))

    def test_unknown_keys_are_ignored(self):
        obj = doc(repo("x", local_path="C:/x", future_field=1))
        obj["generator"] = "RepoTether 9"
        self.assertEqual(len(T.parse(obj, self.data)), 1)

    def test_load_reports_broken_json(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "t.json"
            p.write_text("{", encoding="utf-8")
            with self.assertRaises(T.TargetsError):
                T.load(p, Path(d))


class PrivacyTest(unittest.TestCase):
    """private を api.osv.dev に送らない約束（design.md §4）"""

    def setUp(self):
        self.ts = T.parse(doc(repo("pub"), repo("priv", "private"), repo("unk", "unknown")), Path("D:/d"))

    def test_only_public_goes_online(self):
        online, offline = T.split_by_privacy(self.ts)
        self.assertEqual([t.id for t in online], ["pub"])
        self.assertEqual([t.id for t in offline], ["priv", "unk"])

    def test_online_public_false_keeps_everything_offline(self):
        online, offline = T.split_by_privacy(self.ts, online_public=False)
        self.assertEqual(online, [])
        self.assertEqual(len(offline), 3)

    def test_assert_all_public_rejects_any_non_public(self):
        T.assert_all_public(self.ts[:1])
        for t in self.ts[1:]:
            with self.subTest(t.id), self.assertRaises(T.PrivacyViolation):
                T.assert_all_public([self.ts[0], t])


class LockfilesTest(unittest.TestCase):
    def test_names(self):
        for name in ("uv.lock", "pnpm-lock.yaml", "requirements.txt", "requirements-dev.txt", "go.mod"):
            self.assertTrue(is_lockfile(name), name)
        for name in ("package.json", "pyproject.toml", "requirements.in", "Cargo.toml"):
            self.assertFalse(is_lockfile(name), name)

    def test_every_name_has_an_ecosystem(self):
        self.assertEqual(set(lockfiles.ECOSYSTEMS), set(lockfiles.NAMES))
        self.assertEqual(lockfiles.ecosystem_of("requirements-dev.txt"), "PyPI")

    def _tree(self, root, files):
        for rel in files:
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("x", encoding="utf-8")

    def test_find_walks_without_git(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self._tree(root, ["a/uv.lock", "node_modules/x/package-lock.json", ".venv/requirements.txt", "go.mod", "README.md"])
            self.assertEqual(lockfiles.find(root), ["a/uv.lock", "go.mod"])

    @unittest.skipUnless(shutil.which("git"), "git がありません")
    def test_find_counts_only_tracked_files_in_git(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            self._tree(root, ["uv.lock", "ignored/yarn.lock", "untracked/Cargo.lock"])
            (root / ".gitignore").write_text("ignored/\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(root), "add", "uv.lock", ".gitignore"], check=True)
            self.assertEqual(lockfiles.find(root), ["uv.lock"])
            # 取り込み場所は git を見ない
            self.assertEqual(lockfiles.find(root, use_git=False), ["ignored/yarn.lock", "untracked/Cargo.lock", "uv.lock"])


if __name__ == "__main__":
    unittest.main()
