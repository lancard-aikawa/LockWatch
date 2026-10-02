"""targets.json（RepoTether → LockWatch）の読み込みと、公開・非公開の振り分け（docs/design.md §3.1・§4）

private（public 以外）を api.osv.dev に送らない約束は、ここの 2 つの関数で守る:
  split_by_privacy  … オンラインで照合してよいものと、手元の DB で照合するものに分ける
  assert_all_public … オンラインで osv-scanner を呼ぶ直前に必ず通す。public 以外が混ざっていたら例外
"""
import json
from dataclasses import dataclass
from pathlib import Path

FORMAT = 1
VISIBILITIES = ("public", "private", "unknown")


class TargetsError(ValueError):
    """targets.json の形が違う"""


class PrivacyViolation(RuntimeError):
    """public でないリポジトリをオンラインで照合しようとした（プログラムの誤り）"""


@dataclass(frozen=True)
class Target:
    id: str
    visibility: str
    root: Path            # osv-scanner に渡すフォルダ（local_path か fetched_path）
    fetched: bool         # RepoTether が取ってきたもの（クローンしていない）

    @property
    def is_public(self) -> bool:
        return self.visibility == "public"


def _resolve(value: str, data: Path) -> Path:
    p = Path(value).expanduser()
    return p if p.is_absolute() else data / p


def parse(obj, data: Path) -> list[Target]:
    """targets.json の中身を読む。形が違えば TargetsError（どの項目が違うかを書く）"""
    if not isinstance(obj, dict):
        raise TargetsError("targets.json の中身がオブジェクトではありません")
    fmt = obj.get("format")
    if fmt != FORMAT:
        raise TargetsError(f"format が {FORMAT} ではありません: {fmt!r}")
    repos = obj.get("repos")
    if not isinstance(repos, list):
        raise TargetsError("repos が配列ではありません")
    out: list[Target] = []
    seen: set[str] = set()
    for i, r in enumerate(repos):
        where = f"repos[{i}]"
        if not isinstance(r, dict):
            raise TargetsError(f"{where} がオブジェクトではありません")
        rid = r.get("id")
        if not isinstance(rid, str) or not rid:
            raise TargetsError(f"{where}.id がありません")
        where = f"{where}（{rid}）"
        if rid in seen:
            raise TargetsError(f"{where}: id が重複しています")
        seen.add(rid)
        vis = r.get("visibility", "unknown")
        if vis not in VISIBILITIES:
            # 知らない値は、送らない側に倒すのではなく誤りにする（RepoTether の書き間違いを早く見つける）
            raise TargetsError(f"{where}.visibility が {'/'.join(VISIBILITIES)} のどれでもありません: {vis!r}")
        local, fetched = r.get("local_path"), r.get("fetched_path")
        if local:
            root, is_fetched = _resolve(local, data), False
        elif fetched:
            root, is_fetched = _resolve(fetched, data), True
        else:
            raise TargetsError(f"{where}: local_path と fetched_path のどちらもありません")
        out.append(Target(rid, vis, root, is_fetched))
    return out


def load(path: Path, data: Path) -> list[Target]:
    with open(path, encoding="utf-8") as f:
        try:
            obj = json.load(f)
        except json.JSONDecodeError as e:
            raise TargetsError(f"JSON として読めません: {e}") from e
    return parse(obj, data)


def split_by_privacy(targets: list[Target], online_public: bool = True) -> tuple[list[Target], list[Target]]:
    """(オンラインで照合してよいもの, 手元の DB で照合するもの) に分ける。
    public だけがオンライン側に入りうる。online_public が False なら全部手元"""
    online = [t for t in targets if online_public and t.is_public]
    offline = [t for t in targets if t not in online]
    return online, offline


def assert_all_public(targets: list[Target]) -> None:
    """オンラインで osv-scanner を呼ぶ直前に必ず通す"""
    bad = [t.id for t in targets if not t.is_public]
    if bad:
        raise PrivacyViolation(f"public でないリポジトリをオンラインで照合しようとしました: {', '.join(bad)}")
