"""全依存の台帳（results/packages.json、docs/design.md §3.4）を引く

台帳の 1 件は [lock ファイル, 生態系, 名前, 版]。CLI（lockwatch packages）と画面（台帳のタブ）が使う。
"""
import fnmatch

WILDCARDS = "*?["


def select(doc: dict, *, name: str | None = None, version: str | None = None, ecosystem: str | None = None,
           only_id: str | None = None) -> dict[str, dict]:
    """絞り込んだ後の repos（台帳と同じ形）。当てはまるものが無いリポジトリも、空の packages で残す。
    name は大文字小文字を区別せず、* ? を書ける。version は文字どおり。ecosystem は大文字小文字を区別しない"""
    pattern = name.lower() if name else None
    eco = ecosystem.lower() if ecosystem else None
    out: dict[str, dict] = {}
    for rid, e in doc["repos"].items():
        if only_id and rid != only_id:
            continue
        kept = [p for p in e.get("packages") or []
                if (pattern is None or fnmatch.fnmatchcase(p[2].lower(), pattern))
                and (eco is None or p[1].lower() == eco)
                and (version is None or p[3] == version)]
        out[rid] = {**e, "packages": kept}
    return out


def hits(repos: dict[str, dict]) -> list[dict]:
    """[{"repo", "lockfile", "ecosystem", "package", "version"}, ...]。名前・版・リポジトリ・lock ファイルの順"""
    rows = [{"repo": rid, "lockfile": p[0], "ecosystem": p[1], "package": p[2], "version": p[3]}
            for rid, e in repos.items() for p in e["packages"]]
    rows.sort(key=lambda h: (h["package"].lower(), h["version"], h["repo"], h["lockfile"], h["ecosystem"]))
    return rows


def scanned(repos: dict[str, dict]) -> str:
    """台帳を作った照合の時刻（リポジトリごとに違えば、古いもの 〜 新しいもの）"""
    times = sorted(t for t in (e.get("scanned_at") for e in repos.values()) if t)
    if not times:
        return "-"
    return times[0] if times[0] == times[-1] else f"{times[0]} 〜 {times[-1]}"


def contains(text: str) -> str | None:
    """画面の入力 → select の name。* ? が無ければ部分一致にする。空なら None"""
    text = text.strip()
    if not text:
        return None
    return text if any(c in text for c in WILDCARDS) else f"*{text}*"
