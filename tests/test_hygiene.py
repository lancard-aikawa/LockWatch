"""lock ファイルの健全性の注意（design.md §3.5）"""
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from lockwatch import hygiene

AT = datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc)


def brief(notices):
    return [(n["kind"], n["package"], n["version"], n["detail"]) for n in notices]


class RequirementsTest(unittest.TestCase):
    def test_pinned_lines_are_fine(self):
        text = "\n".join([
            "# comment",
            "requests==2.19.0",
            "PyYAML == 5.3 ; python_version >= '3.6'  # trailing comment",
            "uvicorn[standard]==0.30.0",
            "torch===2.4.0",
            "cryptography==43.0.0 \\",
            "    --hash=sha256:aaaa \\",
            "    --hash=sha256:bbbb",
            "-r other.txt",
            "--index-url https://pypi.org/simple",
            "",
        ])
        self.assertEqual(hygiene.requirements(text), [])

    def test_unpinned(self):
        # osv-scanner は >= や ~= を書かれた版で照合し、指定なしや ==1.* は照合しない（2026-10-05 確認）
        text = "urllib3>=1.24.1\njinja2\ndjango~=2.2.0\nflask==1.*\nnumpy >= 1.26, < 2\nclick[extra]\n"
        self.assertEqual(brief(hygiene.requirements(text)), [
            ("unpinned", "urllib3", "", ">=1.24.1"), ("unpinned", "jinja2", "", ""), ("unpinned", "django", "", "~=2.2.0"),
            ("unpinned", "flask", "", "==1.*"), ("unpinned", "numpy", "", ">=1.26,<2"), ("unpinned", "click", "", "")])

    def test_direct_sources(self):
        text = "\n".join([
            "six @ https://files.pythonhosted.org/packages/six-1.16.0.tar.gz ; python_version < '3'",
            "git+https://user:token@github.com/psf/black.git@23.1.0#egg=black",
            "-e git+ssh://git@github.com/me/tool.git#egg=tool",
            "https://example.invalid/pkg-1.0-py3-none-any.whl",
            "-e ./local-package",
            "./vendor/thing",
            "mine @ file:///C:/src/mine",
            "dist/built-1.0-py3-none-any.whl",
        ])
        self.assertEqual(brief(hygiene.requirements(text)), [
            ("not-registry", "six", "", "https://files.pythonhosted.org/packages/six-1.16.0.tar.gz"),
            # URL の中の利用者名とパスワードは残さない
            ("not-registry", "black", "", "git+https://github.com/psf/black.git@23.1.0#egg=black"),
            ("not-registry", "tool", "", "git+ssh://github.com/me/tool.git#egg=tool"),
            ("not-registry", "", "", "https://example.invalid/pkg-1.0-py3-none-any.whl")])  # 手元のフォルダは入れない


class PackageLockTest(unittest.TestCase):
    def test_v3(self):
        doc = {"lockfileVersion": 3, "packages": {
            "": {"name": "app", "version": "1.0.0"},
            "node_modules/lodash": {"version": "4.17.21", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz", "integrity": "sha512-x"},
            "node_modules/yarn-mirror": {"version": "1.0.0", "resolved": "https://registry.yarnpkg.com/y/-/y-1.0.0.tgz", "integrity": "sha512-x"},
            "node_modules/a/node_modules/@scope/nohash": {"version": "2.0.0", "resolved": "https://registry.npmjs.org/@scope/nohash/-/nohash-2.0.0.tgz"},
            "node_modules/forked": {"version": "1.3.0", "resolved": "git+ssh://git@github.com/x/forked.git#abc"},
            "node_modules/plain": {"version": "0.1.0", "resolved": "http://registry.npmjs.org/plain/-/plain-0.1.0.tgz", "integrity": "sha512-x"},
            "node_modules/mirror": {"version": "3.0.0", "resolved": "https://user:pw@npm.example.invalid/mirror-3.0.0.tgz", "integrity": "sha512-x"},
            "node_modules/alias": {"name": "real-name", "version": "1.0.0", "resolved": "https://example.invalid/real.tgz"},
            "node_modules/workspace": {"resolved": "packages/workspace", "link": True},
            "packages/workspace": {"version": "1.0.0"},
            "node_modules/local": {"version": "1.0.0", "resolved": "file:../local"},
            "node_modules/bundled": {"version": "1.0.0", "inBundle": True},
        }}
        self.assertEqual(brief(hygiene.package_lock(json.dumps(doc))), [
            ("no-integrity", "@scope/nohash", "2.0.0", ""),
            ("not-registry", "forked", "1.3.0", "git+ssh://github.com/x/forked.git#abc"),
            ("not-registry", "plain", "0.1.0", "http://registry.npmjs.org/plain/-/plain-0.1.0.tgz"),  # http は別物
            ("not-registry", "mirror", "3.0.0", "https://npm.example.invalid/mirror-3.0.0.tgz"),
            ("not-registry", "real-name", "1.0.0", "https://example.invalid/real.tgz")])

    def test_v1_is_nested(self):
        doc = {"lockfileVersion": 1, "dependencies": {
            "a": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz", "integrity": "sha1-x",
                  "dependencies": {"b": {"version": "2.0.0", "resolved": "https://registry.npmjs.org/b/-/b-2.0.0.tgz"}}},
            "c": {"version": "github:x/c#abc", "from": "github:x/c"},
        }}
        self.assertEqual(brief(hygiene.package_lock(json.dumps(doc))), [("no-integrity", "b", "2.0.0", "")])

    def test_old_format_without_hashes_is_one_notice(self):
        # npm 4 までの shrinkwrap はハッシュを書かない（2026-10-05、実物の 1 ファイルから 577 件出た）
        def deps(n):
            return {f"p{i}": {"version": "1.0.0", "resolved": f"https://registry.npmjs.org/p{i}/-/p{i}-1.0.0.tgz"} for i in range(n)}
        many = {"dependencies": {**deps(hygiene.NO_INTEGRITY_MAX + 1), "forked": {"version": "1", "resolved": "git://github.com/x/forked.git#abc"}}}
        self.assertEqual(brief(hygiene.package_lock(json.dumps(many))), [
            ("not-registry", "forked", "1", "git://github.com/x/forked.git#abc"),
            ("no-integrity", "", "", str(hygiene.NO_INTEGRITY_MAX + 1))])
        self.assertEqual(len(hygiene.package_lock(json.dumps({"dependencies": deps(hygiene.NO_INTEGRITY_MAX)}))), hygiene.NO_INTEGRITY_MAX)
        self.assertIn("21 個のパッケージ", hygiene.describe({"kind": "no-integrity", "detail": "21"}))

    def test_odd_shapes_do_not_raise(self):
        self.assertEqual(hygiene.package_lock("[]"), [])
        self.assertEqual(hygiene.package_lock('{"packages": {"node_modules/x": "oops"}}'), [])


UV_LOCK = """
version = 1
requires-python = ">=3.11"

[[package]]
name = "fresh"
version = "2.0.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/fresh-2.0.0.tar.gz", hash = "sha256:a", size = 1, upload-time = "2026-10-03T08:00:05Z" }
wheels = [
    { url = "https://files.pythonhosted.org/fresh-2.0.0-py3-none-any.whl", hash = "sha256:b", size = 1, upload-time = "2026-10-03T08:00:00Z" },
]

[[package]]
name = "settled"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
wheels = [
    { url = "https://files.pythonhosted.org/settled-1.0.0-py3-none-any.whl", hash = "sha256:c", size = 1, upload-time = "2026-09-28T11:59:59Z" },
]

[[package]]
name = "no-time"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/no-time-1.0.0.tar.gz", hash = "sha256:d", size = 1 }

[[package]]
name = "from-git"
version = "0.1.0"
source = { git = "https://token@github.com/me/from-git?rev=abc#abc" }

[[package]]
name = "from-url"
version = "0.2.0"
source = { url = "https://example.invalid/from-url-0.2.0.tar.gz" }

[[package]]
name = "mine"
version = "0.1.0"
source = { editable = "." }
"""


class UvLockTest(unittest.TestCase):
    def test_recent_and_direct_sources(self):
        self.assertEqual(brief(hygiene.uv_lock(UV_LOCK, AT)), [
            ("recent", "fresh", "2.0.0", "2026-10-03T08:00:00Z"),  # ファイルの中で一番古い時刻
            ("not-registry", "from-git", "0.1.0", "https://github.com/me/from-git?rev=abc#abc"),
            ("not-registry", "from-url", "0.2.0", "https://example.invalid/from-url-0.2.0.tar.gz")])

    def test_boundary_is_seven_days(self):
        # settled は 7 日と 1 秒前。1 秒前に戻すと、まだ 7 日たっていない
        early = AT.replace(hour=11, minute=59, second=58)
        self.assertIn(("recent", "settled", "1.0.0", "2026-09-28T11:59:59Z"), brief(hygiene.uv_lock(UV_LOCK, early)))


class CheckTest(unittest.TestCase):
    def test_reads_what_it_can_and_skips_the_rest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "sub").mkdir()
            (root / "sub" / "requirements-dev.txt").write_text("\ufeffjinja2\nrequests==2.0\njinja2\n", encoding="utf-8")
            (root / "uv.lock").write_text(UV_LOCK, encoding="utf-8")
            (root / "package-lock.json").write_text("{ broken", encoding="utf-8")       # 壊れている
            (root / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n", encoding="utf-8")  # 読まない
            got = hygiene.check(root, ["package-lock.json", "pnpm-lock.yaml", "sub/requirements-dev.txt", "uv.lock", "gone/uv.lock"], AT)
        self.assertEqual([(n["lockfile"], n["kind"], n["package"]) for n in got], [
            ("sub/requirements-dev.txt", "unpinned", "jinja2"),  # 同じ行が 2 つあっても 1 件
            ("uv.lock", "not-registry", "from-git"), ("uv.lock", "not-registry", "from-url"), ("uv.lock", "recent", "fresh")])
        self.assertEqual(set(got[0]), {"lockfile", "kind", "package", "version", "detail"})

    def test_every_kind_has_a_label_and_a_sentence(self):
        self.assertEqual(set(hygiene.KIND_LABEL), set(hygiene.KINDS))
        for kind in hygiene.KINDS:
            for detail in ("", "x"):
                self.assertTrue(hygiene.describe({"kind": kind, "detail": detail}))
        self.assertIn("照合されていません", hygiene.describe({"kind": "unpinned", "detail": ""}))


if __name__ == "__main__":
    unittest.main()
