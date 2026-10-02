"""osv-scanner の JSON を、結果の findings の形に畳む（docs/design.md §3.3）

OSV の記録から要るものだけを抜く。説明文（details）・参照（references）は入れない。
"""
import os

SEVERITIES = ("critical", "high", "medium", "low", "unknown")
INFORMATIONAL = ("unmaintained", "unsound", "notice")   # RustSec の知らせの種類（report --hide に書ける値）


def hidden(f: dict, hide: set[str]) -> bool:
    """report --hide で消すものか（severity か informational が hide に入っている）"""
    return f.get("severity") in hide or f.get("informational") in hide

# 畳み方の版。finding の作り方を変えたら上げる（キャッシュの鍵に入り、古い畳み方のキャッシュを使わなくなる）
SHAPE = 4


def severity(score: float | None) -> str:
    """CVSS の点数から区分する。点数なしは unknown"""
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


# 記録の database_specific.severity（GitHub の勧告の区分）→ severity。PYSEC・RUSTSEC には無い
_LABELS = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}


def _label(vulns: list[dict]) -> str | None:
    """記録に付いた区分。複数あれば一番重いもの"""
    found = set()
    for v in vulns:
        ds = v.get("database_specific")
        raw = ds.get("severity") if isinstance(ds, dict) else None
        if isinstance(raw, str) and raw.upper() in _LABELS:
            found.add(_LABELS[raw.upper()])
    return next((s for s in SEVERITIES if s in found), None)


def _informational(vulns: list[dict], name: str) -> str | None:
    """脆弱性ではない知らせの種類（RustSec の unmaintained・unsound・notice など）。知らせでなければ None"""
    affected = [a for v in vulns for a in v.get("affected") or []]
    mine = [a for a in affected if (a.get("package") or {}).get("name") == name] or affected
    for a in mine:
        ds = a.get("database_specific")
        kind = ds.get("informational") if isinstance(ds, dict) else None
        if isinstance(kind, str) and kind:
            return kind
    return None


def _score(raw) -> float | None:
    try:
        return float(raw) if raw not in (None, "") else None
    except (TypeError, ValueError):
        return None


def _unique(items) -> list:
    seen, out = set(), []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _fixed(vulns: list[dict], name: str) -> list[str]:
    """直る版。そのパッケージの affected の ranges から fixed を集める。
    GIT の範囲の fixed はコミットのハッシュなので入れない"""
    affected = [a for v in vulns for a in v.get("affected") or []]
    mine = [a for a in affected if (a.get("package") or {}).get("name") == name] or affected
    return _unique(ev["fixed"] for a in mine for r in a.get("ranges") or [] if r.get("type") != "GIT"
                   for ev in r.get("events") or [] if "fixed" in ev)


def path_key(path: str | os.PathLike) -> str:
    """source.path と、渡した lock ファイルのパスを突き合わせるための形（区切り・大文字小文字をそろえる）"""
    return os.path.normcase(os.path.normpath(os.fspath(path)))


def by_source(data: dict) -> dict[str, list[dict]]:
    """{path_key(source.path): [finding, ...]}。finding の lockfile は空のまま（呼ぶ側で入れる）"""
    out: dict[str, list[dict]] = {}
    for result in data.get("results") or []:
        src = (result.get("source") or {}).get("path")
        if not src:
            continue
        found = out.setdefault(path_key(src), [])
        for pkg in result.get("packages") or []:
            info = pkg.get("package") or {}
            name = info.get("name", "")
            vulns = {v.get("id"): v for v in pkg.get("vulnerabilities") or []}
            groups = pkg.get("groups") or [{"ids": [i], "aliases": [], "max_severity": ""} for i in vulns]
            for g in groups:
                ids = g.get("ids") or []
                if not ids:
                    continue
                vid = ids[0]
                mine = [vulns[i] for i in ids if i in vulns]
                score = _score(g.get("max_severity"))
                found.append({
                    "lockfile": "",
                    "ecosystem": info.get("ecosystem", ""),
                    "package": name,
                    "version": info.get("version", ""),
                    "id": vid,
                    "aliases": [a for a in _unique([*(g.get("aliases") or []), *ids]) if a != vid],
                    "severity": _label(mine) or severity(score),  # 区分を優先し、無ければ点数から
                    "score": score,
                    "fixed": _fixed(mine, name),
                    "informational": _informational(mine, name),
                    "summary": next((v["summary"] for v in mine if v.get("summary")), ""),
                })
    return out


def sort_key(f: dict):
    return (f["lockfile"], f["package"], f["version"], f["id"])


def dedupe(findings: list[dict]) -> list[dict]:
    seen, out = set(), []
    for f in sorted(findings, key=sort_key):
        k = sort_key(f)
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out
