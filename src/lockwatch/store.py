"""データフォルダの読み書き（docs/design.md §3.3・§5.3・§6・§7）

  results/latest.json, results/<YYYYMMDDTHHMMSSZ>.json, cache/<key>.json, db.json, lock
"""
import hashlib
import json
import os
import re
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

FORMAT = 1
_HISTORY = re.compile(r"^\d{8}T\d{6}Z\.json$")


class Busy(RuntimeError):
    """ほかの LockWatch が実行中"""


def now() -> datetime:
    return datetime.now().astimezone()


def iso(t: datetime) -> str:
    return t.isoformat(timespec="seconds")


def parse_time(s) -> datetime | None:
    try:
        return datetime.fromisoformat(s) if isinstance(s, str) else None
    except ValueError:
        return None


def write_json(path: Path, obj) -> None:
    """一時ファイルに書いてから入れ替える（読む側に書きかけを見せない）"""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
        f.write("\n")
    os.replace(tmp, path)


def read_json(path: Path):
    """読めなければ None（壊れたキャッシュや前回の結果で止まらない）"""
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


# ---- 排他（§7）

@contextmanager
def exclusive(data: Path):
    """<data>/lock を OS のファイルロックで押さえる。取れなければ Busy。
    落ちたプロセスのロックは OS が外すので、ファイルが残っても止まらない"""
    data.mkdir(parents=True, exist_ok=True)
    f = open(data / "lock", "a+b")
    try:
        try:
            if os.name == "nt":
                import msvcrt
                f.seek(0)
                msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as e:
            raise Busy(f"ほかの LockWatch が実行中です（{data / 'lock'}）") from e
        try:
            yield
        finally:
            if os.name == "nt":
                import msvcrt
                f.seek(0)
                msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
    finally:
        f.close()


# ---- 脆弱性 DB の取得時刻（§5.3）

def load_db_state(data: Path) -> dict[str, str]:
    obj = read_json(data / "db.json")
    eco = obj.get("ecosystems") if isinstance(obj, dict) else None
    return {k: v for k, v in eco.items() if isinstance(v, str)} if isinstance(eco, dict) else {}


def save_db_state(data: Path, ecosystems: dict[str, str]) -> None:
    write_json(data / "db.json", {"format": FORMAT, "ecosystems": dict(sorted(ecosystems.items()))})


def db_needs_update(state: dict[str, str], needed: set[str], max_age_days: int, at: datetime) -> bool:
    """要る生態系のどれかが、まだ取っていないか古い"""
    for eco in needed:
        t = parse_time(state.get(eco))
        if t is None or at - t > timedelta(days=max_age_days):
            return True
    return False


# ---- キャッシュ（§6）

def cache_key(**parts) -> str:
    return hashlib.sha256(json.dumps(parts, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()


def cache_get(data: Path, key: str, max_age_hours: int, at: datetime) -> dict | None:
    obj = read_json(data / "cache" / f"{key}.json")
    if not isinstance(obj, dict) or obj.get("key") != key:
        return None
    t = parse_time(obj.get("saved_at"))
    if t is None or at - t > timedelta(hours=max_age_hours) or not isinstance(obj.get("findings"), list):
        return None
    return obj


def cache_put(data: Path, key: str, findings: list[dict], at: datetime) -> None:
    write_json(data / "cache" / f"{key}.json", {"key": key, "saved_at": iso(at), "findings": findings})


def cache_prune(data: Path, max_age_hours: int, at: datetime) -> None:
    limit = (at - timedelta(hours=max_age_hours)).timestamp()
    for p in (data / "cache").glob("*.json"):
        try:
            if p.stat().st_mtime < limit:
                p.unlink()
        except OSError:
            pass


# ---- 結果（§3.3）

def results_dir(data: Path) -> Path:
    return data / "results"


def load_latest(data: Path) -> dict | None:
    obj = read_json(results_dir(data) / "latest.json")
    return obj if isinstance(obj, dict) and isinstance(obj.get("repos"), dict) else None


def new_findings(prev: dict | None, repos: dict[str, dict]) -> list[dict]:
    """前回の latest.json に無かった (repo, package, id)。前回が無い・前回 ok でなかったリポジトリは比べない"""
    if prev is None:
        return []
    out = []
    for rid, cur in repos.items():
        old = prev["repos"].get(rid)
        if not isinstance(old, dict) or old.get("status") != "ok" or cur.get("status") != "ok":
            continue
        known = {(f.get("package"), f.get("id")) for f in old.get("findings") or []}
        seen = set()
        for f in cur["findings"]:
            k = (f["package"], f["id"])
            if k not in known and k not in seen:
                seen.add(k)
                out.append({"repo": rid, "package": f["package"], "id": f["id"], "severity": f["severity"],
                            "informational": f.get("informational")})
    return out


def write_results(data: Path, doc: dict, at: datetime, history: bool, keep: int) -> None:
    rdir = results_dir(data)
    if history:
        name = at.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + ".json"
        write_json(rdir / name, doc)
        old = sorted(p for p in rdir.iterdir() if _HISTORY.match(p.name))
        for p in old[:-keep] if keep > 0 else []:
            p.unlink(missing_ok=True)
    write_json(rdir / "latest.json", doc)
