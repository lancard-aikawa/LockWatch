"""Release の本文を作る（.github/workflows/release.yml から呼ぶ。手元でも試せる）

  python .github/release_notes.py v0.2.0 dist/release-body.md

- タグの版と、pyproject.toml・src/lockwatch/__init__.py の版がそろっているかを検査する（食い違えば終了コード 1）
- CHANGELOG.md のその版の節に、.github/release-intro.md（入れ方・更新の仕方）を付けて書き出す
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def main(tag: str, out: str) -> int:
    version = tag.removeprefix("v")
    found = {
        "pyproject.toml": re.search(r'^version\s*=\s*"([^"]+)"', read("pyproject.toml"), re.M),
        "src/lockwatch/__init__.py": re.search(r'^__version__\s*=\s*"([^"]+)"', read("src/lockwatch/__init__.py"), re.M),
    }
    bad = {k: (m.group(1) if m else None) for k, m in found.items() if not m or m.group(1) != version}
    if bad:
        print(f"タグ {tag} は版 {version} を意味しますが、コードは {bad} です。版を上げてからタグを打ち直してください")
        return 1
    m = re.search(rf"^## {re.escape(version)}\s*$(.*?)(?=^## |\Z)", read("CHANGELOG.md"), re.M | re.S)
    if not m or not m.group(1).strip():
        print(f"CHANGELOG.md に {version} の節がありません。変更点を書いてからタグを打ち直してください")
        return 1
    intro = re.sub(r"<!--.*?-->", "", read(".github/release-intro.md"), flags=re.S).strip()
    body = f"## {version} の変更点\n\n{m.group(1).strip()}\n\n{intro}\n"
    path = Path(out)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8", newline="\n")
    print(f"{path} に {version} の本文を書きました（{len(body)} 文字）")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1], sys.argv[2]))
