"""lock ファイルの健全性の注意（docs/design.md §3.5）

脆弱性の照合（osv-scanner）とは別に、lock ファイルそのものを読んで分かることを拾う。通信はしない。
読めるのは requirements*.txt・package-lock.json・npm-shrinkwrap.json・uv.lock。壊れていて読めないファイルは飛ばす。
"""
import json
import re
import tomllib
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

KINDS = ("unpinned", "not-registry", "no-integrity", "recent")
KIND_LABEL = {"unpinned": "版を固定していない", "not-registry": "レジストリ以外から取得",
              "no-integrity": "ハッシュなし", "recent": "公開直後の版"}

RECENT_DAYS = 7
NO_INTEGRITY_MAX = 20   # 1 つの lock ファイルでこれを超えたら、1 件にまとめる（detail に件数）
NPM_REGISTRIES = ("https://registry.npmjs.org/", "https://registry.yarnpkg.com/")


def _notice(kind: str, package: str, version: str = "", detail: str = "") -> dict:
    return {"lockfile": "", "kind": kind, "package": package, "version": version, "detail": detail}


def redact(url: str) -> str:
    """URL の中の利用者名とパスワードを除く（結果や診断書にトークンを残さない）"""
    try:
        parts = urlsplit(url)
        if "@" not in parts.netloc:
            return url
        return urlunsplit(parts._replace(netloc=parts.netloc.rsplit("@", 1)[1]))
    except ValueError:
        return url


# ---- requirements*.txt

_NAME = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$")
_PINNED = re.compile(r"^===?\s*[^\s,*]+$")    # == か === が 1 つだけで、* を含まない
_EGG = re.compile(r"[#&]egg=([A-Za-z0-9._-]+)")
_DIRECT = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*@\s*(\S+)")   # 名前 @ 取得元


def _is_remote(target: str) -> bool:
    return ("://" in target or target.startswith("git+")) and not target.startswith("file:")


def _requirement_lines(text: str):
    """コメントと行の継続を片付けた、意味のある行"""
    joined = re.sub(r"\\\r?\n", " ", text)
    for raw in joined.splitlines():
        line = re.sub(r"(^|\s)#.*$", "", raw).strip()
        if line:
            yield line


def requirements(text: str) -> list[dict]:
    out = []
    for line in _requirement_lines(text):
        if line.startswith("-"):
            m = re.match(r"^(?:-e|--editable)[\s=]+(.+)$", line)
            if not m:
                continue  # -r・--index-url などのオプション
            line = m.group(1).strip()
        line = re.split(r"\s--", line, maxsplit=1)[0].strip()   # --hash=... など
        # 取得元を直に書いた行: 「名前 @ 取得元」か、取得元だけ
        target = None
        m = _DIRECT.match(line)
        if m:
            name, target = m.group(1), m.group(2)
        elif _is_remote(line):
            target = line.split()[0]
            egg = _EGG.search(target)
            name = egg.group(1) if egg else ""
        if target is not None:
            if _is_remote(target):
                out.append(_notice("not-registry", name, detail=redact(target.rstrip(";"))))
            continue  # 手元のフォルダは自分のコード
        line = line.split(";", 1)[0].strip()   # 環境の条件（; python_version >= "3.8"）
        m = _NAME.match(line)
        if not m or "/" in line or "\\" in line or re.search(r"\.(whl|zip|tar\.gz)$", line):
            continue  # ./local・dist/x.whl のようなパス
        name, spec = m.group(1), m.group(2).strip()
        if not _PINNED.match(spec):
            out.append(_notice("unpinned", name, detail=re.sub(r"\s+", "", spec)))
    return out


# ---- package-lock.json / npm-shrinkwrap.json

def _npm_entry(name: str, e: dict) -> dict | None:
    resolved = e.get("resolved")
    if not isinstance(resolved, str) or not resolved or e.get("link") or resolved.startswith("file:"):
        return None  # 手元のフォルダ・ワークスペース・同梱されたもの
    version = e.get("version") if isinstance(e.get("version"), str) else ""
    if not resolved.startswith(NPM_REGISTRIES):
        return _notice("not-registry", name, version, redact(resolved))
    if not e.get("integrity"):
        return _notice("no-integrity", name, version)
    return None


def _npm_v1(deps: dict):
    """lockfileVersion 1 の dependencies（入れ子）"""
    for name, e in deps.items():
        if not isinstance(e, dict):
            continue
        yield name, e
        if isinstance(e.get("dependencies"), dict):
            yield from _npm_v1(e["dependencies"])


def package_lock(text: str) -> list[dict]:
    doc = json.loads(text)
    if not isinstance(doc, dict):
        return []
    entries = []
    if isinstance(doc.get("packages"), dict):
        for key, e in doc["packages"].items():
            if key and isinstance(e, dict):
                name = e.get("name") if isinstance(e.get("name"), str) else key.rsplit("node_modules/", 1)[-1]
                entries.append((name, e))
    elif isinstance(doc.get("dependencies"), dict):
        entries = list(_npm_v1(doc["dependencies"]))
    found = [n for n in (_npm_entry(name, e) for name, e in entries) if n is not None]
    bare = [n for n in found if n["kind"] == "no-integrity"]
    if len(bare) > NO_INTEGRITY_MAX:
        # ハッシュを書かない古い形式（npm 4 までの shrinkwrap など）。1 つずつ並べず、ファイルごとに 1 件にまとめる
        count = len({(n["package"], n["version"]) for n in bare})   # 入れ子で同じものが何度も出る
        found = [n for n in found if n["kind"] != "no-integrity"] + [_notice("no-integrity", "", detail=str(count))]
    return found


# ---- uv.lock

def _uploaded(pkg: dict) -> datetime | None:
    """その版が最初に公開された時刻（ファイルの upload-time の一番古いもの）"""
    files = [pkg.get("sdist"), *(pkg.get("wheels") or [])]
    times = []
    for f in files:
        raw = f.get("upload-time") if isinstance(f, dict) else None
        if isinstance(raw, str):
            try:
                times.append(datetime.fromisoformat(raw))
            except ValueError:
                pass
    return min(times) if times else None


def uv_lock(text: str, at: datetime) -> list[dict]:
    out = []
    for pkg in tomllib.loads(text).get("package") or []:
        name, version, source = pkg.get("name", ""), pkg.get("version", ""), pkg.get("source") or {}
        if not isinstance(source, dict):
            continue
        remote = source.get("git") or source.get("url")
        if isinstance(remote, str):
            out.append(_notice("not-registry", name, version, redact(remote)))
        elif "registry" in source:
            t = _uploaded(pkg)
            if t is not None and t.tzinfo is not None and at - t < timedelta(days=RECENT_DAYS):
                out.append(_notice("recent", name, version, t.isoformat(timespec="seconds").replace("+00:00", "Z")))
    return out


# ---- まとめ

def _read(name: str, text: str, at: datetime) -> list[dict]:
    if name in ("package-lock.json", "npm-shrinkwrap.json"):
        return package_lock(text)
    if name == "uv.lock":
        return uv_lock(text, at)
    if name.startswith("requirements") and name.endswith(".txt"):
        return requirements(text)
    return []


def check(root: Path, lockfiles: list[str], at: datetime) -> list[dict]:
    """root の lock ファイル（root からの相対、/ 区切り）の注意。at は照合の時刻（タイムゾーン付き）"""
    out = []
    for rel in lockfiles:
        try:
            with open(root / rel, encoding="utf-8-sig") as f:
                found = _read(rel.rsplit("/", 1)[-1], f.read(), at)
        except (OSError, ValueError, RecursionError):  # 読めない・壊れている（TOML と JSON の誤りは ValueError）
            continue
        for n in found:
            n["lockfile"] = rel
        out.extend(found)
    seen, unique = set(), []
    for n in sorted(out, key=lambda n: (n["lockfile"], KINDS.index(n["kind"]), n["package"].lower(), n["version"], n["detail"])):
        k = tuple(n.values())
        if k not in seen:
            seen.add(k)
            unique.append(n)
    return unique


def describe(n: dict) -> str:
    """表示用の 1 つの文（CLI・画面・診断書が使う）"""
    kind, detail = n.get("kind"), n.get("detail") or ""
    if kind == "unpinned":
        # osv-scanner は >=1.24.1 を 1.24.1 として照合し、==1.* や指定なしは照合しない（design.md §3.5）
        return f"版を固定していません（{detail}）。照合は不正確か、行われていません" if detail else "版の指定がありません。照合されていません"
    if kind == "not-registry":
        return f"レジストリ以外から取得: {detail}"
    if kind == "no-integrity":
        if detail:
            return f"{detail} 個のパッケージにハッシュ（integrity）がありません（ハッシュを書かない古い形式の lock ファイル）"
        return "ハッシュ（integrity）がありません"
    if kind == "recent":
        return f"公開から {RECENT_DAYS} 日たっていません（公開 {detail}）"
    return detail
