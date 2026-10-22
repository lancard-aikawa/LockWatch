"""言語そのもの（PHP・Node.js）の版を調べる（docs/design.md §3.6）

lock ファイルの照合とは別に、リポジトリの言語の版を見当付けし（確定した版があればそれを使う）、
系列のサポート終了と、入れた版より新しいセキュリティリリースがあるかを出す。

言語そのものの脆弱性は OSV には本家の版ではまとまって載らない（2026-10-22 に api.osv.dev で確かめた。php-src は 1 件、
nodejs/node は 2025-01 で止まっている）ので、本家と endoflife.date が出しているものを使う。送るのは言語の名前だけで、
リポジトリの情報は外に出さない（§4 の約束と両立する）:
  endoflife.date … 系列ごとのサポート終了日と最新の版
  php.net        … 版ごとの公開日と security の印（releases の JSON）、セキュリティのお知らせ（ニュースの Atom）
  nodejs.org     … 版ごとの公開日と security の印（dist/index.json）、脆弱性のお知らせ（RSS）
取ったものは <data>/runtimes.json に置き、cache_max_age_hours より新しければ取り直さない。取れなければ前のものを使う。
"""
import json
import re
import urllib.request
import xml.etree.ElementTree as ET
from datetime import date, datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

from . import __version__, store

LANGS = ("php", "node")
LABEL = {"php": "PHP", "node": "Node.js"}
SOON_DAYS = 90            # サポート終了が近いとみなす日数
ADVISORY_KEEP = 20        # お知らせを残す件数（言語ごと）
TIMEOUT = 30
USER_AGENT = f"LockWatch/{__version__} (+https://github.com/lancard-aikawa/LockWatch)"

SOURCES = {
    "php": {
        "eol": "https://endoflife.date/api/php.json",
        "releases": ["https://www.php.net/releases/index.php?json&version=8&max=1000",
                     "https://www.php.net/releases/index.php?json&version=7&max=1000",
                     "https://www.php.net/releases/index.php?json&version=5&max=1000"],
        "advisories": "https://www.php.net/feed.atom",
    },
    "node": {
        "eol": "https://endoflife.date/api/nodejs.json",
        "releases": ["https://nodejs.org/dist/index.json"],
        "advisories": "https://nodejs.org/en/feed/vulnerability.xml",
    },
}


# ---- 版 ----

def parse(v) -> tuple[int, ...] | None:
    """"8.2.20" → (8, 2, 20)。先頭の v と、- / + より後（8.2.0-dev など）は落とす。数字で始まらなければ None"""
    if not isinstance(v, str):
        return None
    m = re.match(r"\s*v?(\d+(?:\.\d+){0,2})", v)
    return tuple(int(x) for x in m.group(1).split(".")) if m else None


def cycle_of(lang: str, v: tuple[int, ...]) -> str | None:
    """系列。PHP は 8.2、Node.js は 22。PHP で 8 だけなら決まらない"""
    if lang == "php":
        return f"{v[0]}.{v[1]}" if len(v) >= 2 else None
    return str(v[0])


def lowest_in_constraint(s: str) -> str | None:
    """composer の require.php や engines.node の書き方（^8.1 / >=7.4 / ~8.2.0 / ^7.4 || ^8.0）から、一番低い版。
    動いている版ではなく「この版でも動く」という下限なので、推定にしか使わない"""
    if not isinstance(s, str):
        return None
    found = [m.group(1) for part in re.split(r"\|\|?", s) for m in [re.search(r"(\d+(?:\.\d+){0,2})", part)] if m]
    return min(found, key=lambda x: parse(x)) if found else None


# ---- リポジトリから見当を付ける ----

def _read(p: Path, limit: int = 200_000) -> str | None:
    try:
        if p.is_file() and p.stat().st_size <= limit:
            return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        pass
    return None


def _json(p: Path) -> dict:
    text = _read(p)
    if text is None:
        return {}
    try:
        obj = json.loads(text)
    except ValueError:
        return {}
    return obj if isinstance(obj, dict) else {}


def _first_line(p: Path) -> str | None:
    text = _read(p, 1000)
    line = text.strip().splitlines()[0].strip() if text and text.strip() else None
    return line if line and parse(line) else None


def _docker(root: Path, image: str) -> str | None:
    text = _read(root / "Dockerfile")
    if not text:
        return None
    m = re.search(rf"^\s*FROM\s+(?:\S+/)?{image}:v?(\d+(?:\.\d+){{0,2}})", text, re.I | re.M)
    return m.group(1) if m else None


def detect(root: Path) -> dict[str, tuple[str, str, bool]]:
    """{言語: (版, どこから, 下限か)}。版を決め打ちしているファイルを先に見て、無ければ書き方（下限）から推す。
    下限（composer の require.php・engines.node）から推したものは、系列だけを見る（修正版の有無は言えない）。
    見るのはリポジトリの直下だけ"""
    out: dict[str, tuple[str, str, bool]] = {}
    composer = _json(root / "composer.json")
    pkg = _json(root / "package.json")
    php_req = ((composer.get("require") or {}) if isinstance(composer.get("require"), dict) else {}).get("php")
    candidates = {
        "php": [
            (_first_line(root / ".php-version"), ".php-version"),
            (_docker(root, "php"), "Dockerfile"),
            (lowest_in_constraint(php_req), f"composer.json の require.php（{php_req}）" if php_req else "", True),
        ],
        "node": [
            (_first_line(root / ".nvmrc"), ".nvmrc"),
            (_first_line(root / ".node-version"), ".node-version"),
            ((pkg.get("volta") or {}).get("node") if isinstance(pkg.get("volta"), dict) else None, "package.json の volta.node"),
            (_docker(root, "node"), "Dockerfile"),
            (lowest_in_constraint((pkg.get("engines") or {}).get("node") if isinstance(pkg.get("engines"), dict) else None),
             f"package.json の engines.node（{(pkg.get('engines') or {}).get('node')}）" if isinstance(pkg.get("engines"), dict) else "", True),
        ],
    }
    for lang, cands in candidates.items():
        for v, src, *lower in cands:
            if v and parse(v):
                out[lang] = (v.lstrip("v").strip(), src, bool(lower and lower[0]))
                break
    return out


# ---- 本家などのデータ ----

def _get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:  # noqa: S310 (https の決まった URL だけ)
        return r.read()


def _cycles(raw: list) -> dict[str, dict]:
    out = {}
    for c in raw if isinstance(raw, list) else []:
        if not isinstance(c, dict) or "cycle" not in c:
            continue
        eol = c.get("eol")
        out[str(c["cycle"])] = {"eol": eol if isinstance(eol, str) else None, "latest": c.get("latest")}
    return out


def _php_releases(blobs: list[bytes]) -> dict[str, str]:
    """{版: 公開日}。security の印の付いたものだけ"""
    out = {}
    for blob in blobs:
        obj = json.loads(blob)
        for ver, info in (obj.items() if isinstance(obj, dict) else []):
            if not isinstance(info, dict) or "security" not in (info.get("tags") or []):
                continue
            try:
                out[ver] = datetime.strptime(str(info.get("date", "")).strip(), "%d %b %Y").date().isoformat()
            except ValueError:
                out[ver] = None
    return out


def _node_releases(blobs: list[bytes]) -> dict[str, str]:
    out = {}
    for blob in blobs:
        for r in json.loads(blob):
            if isinstance(r, dict) and r.get("security") and isinstance(r.get("version"), str):
                out[r["version"].lstrip("v")] = r.get("date")
    return out


def _xml(blob: bytes) -> ET.Element:
    """フィードを読む。defusedxml は使えない（実行時の依存を足さない）ので、DTD・実体の宣言があれば読まずに断る。
    標準の ElementTree は外部の実体を読まないが、実体の展開（billion laughs）を元から断つ"""
    head = blob[:4096].lower()
    if b"<!doctype" in head or b"<!entity" in blob.lower():
        raise ValueError("フィードに DTD か実体の宣言があります")
    return ET.fromstring(blob)


def _text(el) -> str:
    return "".join(el.itertext()).strip() if el is not None else ""


def _php_advisories(blob: bytes) -> list[dict]:
    """ニュースの Atom のうち、題に Security の入ったもの（お知らせと予告）"""
    ns = {"a": "http://www.w3.org/2005/Atom"}
    out = []
    for e in _xml(blob).findall("a:entry", ns):
        title = _text(e.find("a:title", ns))
        if not re.search(r"security", title, re.I):
            continue
        link = next((l.get("href") for l in e.findall("a:link", ns) if l.get("rel") in (None, "alternate")), None)
        out.append({"title": title, "date": _text(e.find("a:updated", ns))[:10] or None, "url": link})
    return out[:ADVISORY_KEEP]


def _node_advisories(blob: bytes) -> list[dict]:
    out = []
    for it in _xml(blob).iter("item"):
        try:
            when = parsedate_to_datetime(_text(it.find("pubDate"))).date().isoformat()
        except (TypeError, ValueError):
            when = None
        out.append({"title": _text(it.find("title")), "date": when, "url": _text(it.find("link")) or None})
    return out[:ADVISORY_KEEP]


def fetch(get=_get) -> dict:
    """本家などから取って、runtimes.json の形にする。get はテストで差し替える"""
    out = {}
    for lang, src in SOURCES.items():
        releases = [get(u) for u in src["releases"]]
        out[lang] = {
            "cycles": _cycles(json.loads(get(src["eol"]))),
            "security": _php_releases(releases) if lang == "php" else _node_releases(releases),
            "advisories": _php_advisories(get(src["advisories"])) if lang == "php" else _node_advisories(get(src["advisories"])),
        }
    return out


def path(data: Path) -> Path:
    return data / "runtimes.json"


def load(data: Path) -> dict | None:
    try:
        with open(path(data), encoding="utf-8") as f:
            obj = json.load(f)
        return obj if isinstance(obj, dict) else None
    except (OSError, ValueError):
        return None


def load_or_fetch(data: Path, cfg: dict, at: datetime, get=_get) -> tuple[dict | None, str | None]:
    """(データ, 注意)。新しければ置いてあるものを使い、古ければ取り直す。取れなければ前のものを使い、その旨を返す"""
    old = load(data)
    if not cfg.get("runtime_check", True):
        return None, None
    fetched = store.parse_time((old or {}).get("fetched_at"))
    if old and fetched and at - fetched < timedelta(hours=cfg["cache_max_age_hours"]):
        return old, None
    try:
        new = {"fetched_at": store.iso(at), **fetch(get)}
    except Exception as e:  # 通信・形の誤りのどれでも、照合そのものは止めない
        msg = f"言語のデータを取れませんでした（{type(e).__name__}: {e}）"
        return old, msg + ("。前に取ったものを使います" if old else "")
    p = path(data)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        json.dump(new, f, ensure_ascii=False, indent=1)
    tmp.replace(p)
    return new, None


# ---- 照合 ----

def check(lang: str, version: str, source: str, confirmed: bool, rt: dict | None, today: date, lower_bound: bool = False) -> dict:
    """1 つの言語の結果。rt は runtimes.json の中身（無ければ版だけ返す）。
    lower_bound なら version は「この版以上で動く」という下限で、系列だけを見る"""
    v = parse(version)
    out = {"name": lang, "version": version, "source": source, "confirmed": confirmed, "cycle": None, "eol": None,
           "status": "unknown", "latest": None, "exact": bool(v and len(v) == 3 and not lower_bound), "security": [],
           "upgrade_to": None, "lower_bound": lower_bound}
    if v is None or not rt or lang not in rt:
        return out
    cyc = cycle_of(lang, v)
    out["cycle"] = cyc
    info = (rt[lang].get("cycles") or {}).get(cyc) if cyc else None
    if info:
        out["latest"] = info.get("latest")
        out["eol"] = info.get("eol")
        try:
            eol = date.fromisoformat(info["eol"]) if info.get("eol") else None
        except ValueError:
            eol = None
        out["status"] = "ok" if eol is None else "ended" if eol <= today else "soon" if eol - today <= timedelta(days=SOON_DAYS) else "ok"
    if out["exact"] and cyc:
        newer = sorted(((parse(s), s, d) for s, d in (rt[lang].get("security") or {}).items()
                        if parse(s) and len(parse(s)) == 3 and cycle_of(lang, parse(s)) == cyc and parse(s) > v),
                       key=lambda x: x[0])
        out["security"] = [{"version": s, "date": d} for _, s, d in newer]
        latest = parse(out["latest"]) if out["latest"] else None
        if newer or (latest and latest > v):
            out["upgrade_to"] = out["latest"] or newer[-1][1]
    return out


def check_target(root: Path, confirmed: dict[str, str], rt: dict | None, at: datetime) -> list[dict]:
    """そのリポジトリの言語の結果（PHP・Node.js の順）。確定した版（RepoTether で入れたもの）があればそれを使う"""
    found = detect(root) if root.is_dir() else {}
    today = at.astimezone(timezone.utc).date() if at.tzinfo else at.date()
    out = []
    for lang in LANGS:
        if confirmed.get(lang):
            out.append(check(lang, confirmed[lang], "RepoTether で確定", True, rt, today))
        elif lang in found:
            v, src, lower = found[lang]
            out.append(check(lang, v, src, False, rt, today, lower_bound=lower))
    return out


def needs_attention(r: dict) -> bool:
    """一覧で印を付けるもの: サポート終了・終了が近い・修正版がある"""
    return r.get("status") in ("ended", "soon") or bool(r.get("security"))


def recent_advisories(rt: dict | None, at: datetime, days: int = 30) -> list[dict]:
    """最近のセキュリティのお知らせ（言語ごとに新しい順）"""
    if not rt:
        return []
    since = (at - timedelta(days=days)).date().isoformat()
    out = []
    for lang in LANGS:
        for a in (rt.get(lang) or {}).get("advisories") or []:
            if a.get("date") and a["date"] >= since:
                out.append({"name": lang, **a})
    return sorted(out, key=lambda a: (a["date"], a["name"]), reverse=True)
