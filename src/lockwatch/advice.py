"""結果から「何をどう直すか」を作る（docs/design.md §7.1 の対応の節）

診断書をそのリポジトリで作業する人や AI に渡せば直し始められるように、直す順に並べた対応にする。
上げる先の版は目安（新しい版は古い修正も含む、という前提）。保証ではない。
"""
import re

from . import fold

_VERSION = re.compile(r"v?(\d+(?:\.\d+)*)")


def parse_version(v: str) -> tuple[int, ...] | None:
    """数字と . だけの版 → 比べられる形（末尾の 0 は落とす）。1.2b1 などは None"""
    m = _VERSION.fullmatch((v or "").strip())
    if not m:
        return None
    parts = [int(x) for x in m.group(1).split(".")]
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


def _needed(current: tuple[int, ...] | None, fixed: list[str]) -> str | None:
    """その 1 件が直る版のうち、今の版より新しい一番小さいもの"""
    if current is None:
        return None
    newer = [(p, v) for v in fixed for p in [parse_version(v)] if p is not None and p > current]
    return min(newer)[1] if newer else None


def _upgrades(findings: list[dict], unpinned: set[tuple[str, str]]) -> list[dict]:
    order = {s: i for i, s in enumerate(fold.SEVERITIES)}
    groups: dict[tuple, list[dict]] = {}
    for f in findings:
        if f.get("malicious") or f.get("informational"):
            continue  # 取り除くもの・上げても直らない知らせ
        groups.setdefault((f.get("lockfile", ""), f.get("ecosystem", ""), f.get("package", ""), f.get("version", "")), []).append(f)
    out = []
    for (lockfile, ecosystem, package, version), items in groups.items():
        current = parse_version(version)
        needs, unfixed, unclear = [], [], []
        for f in items:
            fixed = f.get("fixed") or []
            need = _needed(current, fixed)
            if need is not None:
                needs.append(need)
            elif not fixed:
                unfixed.append(f.get("id", ""))
            else:
                unclear.append(f.get("id", ""))
        counts = {s: sum(1 for f in items if f.get("severity") == s) for s in fold.SEVERITIES}
        out.append({
            "action": "upgrade", "lockfile": lockfile, "ecosystem": ecosystem, "package": package, "version": version,
            "target": max(needs, key=parse_version) if needs else None,
            "count": len(items), "severities": {s: n for s, n in counts.items() if n},
            "unfixed": sorted(unfixed), "unclear": sorted(unclear),
            "unpinned": (lockfile, package.lower()) in unpinned,
        })
    out.sort(key=lambda a: (min(order.get(s, 99) for s in a["severities"]), -a["count"], a["lockfile"], a["package"].lower()))
    return out


def actions(findings: list[dict], notices: list[dict]) -> list[dict]:
    """直す順の対応。remove（悪意あるコード）→ pin（版の固定）→ upgrade（版を上げる）→ review（残りの注意）"""
    out: list[dict] = []
    seen = set()
    for f in findings:
        k = (f.get("lockfile"), f.get("package"), f.get("version"))
        if f.get("malicious") and k not in seen:
            seen.add(k)
            ids = sorted({g.get("id", "") for g in findings if g.get("malicious") and (g.get("lockfile"), g.get("package"), g.get("version")) == k})
            out.append({"action": "remove", "lockfile": f.get("lockfile", ""), "ecosystem": f.get("ecosystem", ""),
                        "package": f.get("package", ""), "version": f.get("version", ""), "ids": ids})

    pins: dict[str, list[dict]] = {}
    for n in notices:
        if n.get("kind") == "unpinned":
            pins.setdefault(n.get("lockfile", ""), []).append({"package": n.get("package", ""), "spec": n.get("detail", "")})
    out += [{"action": "pin", "lockfile": lockfile, "packages": pkgs} for lockfile, pkgs in pins.items()]

    unpinned = {(lockfile, p["package"].lower()) for lockfile, pkgs in pins.items() for p in pkgs}
    out += _upgrades(findings, unpinned)

    out += [{"action": "review", "lockfile": n.get("lockfile", ""), "kind": n.get("kind", ""), "package": n.get("package", ""),
             "version": n.get("version", ""), "detail": n.get("detail", "")}
            for n in notices if n.get("kind") != "unpinned"]
    return out
