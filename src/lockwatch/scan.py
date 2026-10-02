"""照合の本体（docs/design.md §4〜§6）

対象ごとに lock ファイルを数え、キャッシュに無いものだけ osv-scanner にかける。
public（かつ online_public）はリポジトリごとにオンラインで、それ以外はまとめて 1 回、手元の DB で照合する。
"""
import hashlib
import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from . import fold, lockfiles, osv, store
from .targets import Target, split_by_privacy


@dataclass
class Job:
    target: Target
    mode: str                                  # online / offline
    root: Path                                 # 絶対パス
    lockfiles: list[str] = field(default_factory=list)   # root からの相対、/ 区切り
    hashes: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def ecosystems(self) -> set[str]:
        return {lockfiles.ecosystem_of(rel.rsplit("/", 1)[-1]) for rel in self.lockfiles}

    def paths(self) -> list[Path]:
        return [self.root / rel for rel in self.lockfiles]


@dataclass
class Outcome:
    repos: dict[str, dict]                     # targets の順
    db_downloaded_at: str | None               # 手元の DB で照合したときの、使った DB の一番古い取得時刻
    scanner_failed: bool                       # osv-scanner が 1 回でも失敗した
    warnings: list[str]


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _prepare(t: Target, mode: str) -> Job:
    root = Path(os.path.abspath(t.root))
    job = Job(t, mode, root)
    if not root.is_dir():
        job.error = f"フォルダがありません: {root}"
        return job
    try:
        job.lockfiles = lockfiles.find(root, use_git=not t.fetched)
        job.hashes = [_sha256(p) for p in job.paths()]
    except OSError as e:
        job.error = f"lock ファイルを読めません: {e}"
    return job


def _entry(job: Job, at: datetime | str, status: str, findings: list[dict], error: str | None = None) -> dict:
    """at はキャッシュから返すときは保存した時刻（照合した時刻）"""
    e = {"status": status, "mode": job.mode, "scanned_at": at if isinstance(at, str) else store.iso(at), "lockfiles": job.lockfiles, "findings": findings}
    if error:
        e["error"] = error
    return e


def _assign(jobs: list[Job], data: dict) -> tuple[dict[str, list[dict]], list[str]]:
    """osv-scanner の結果を source.path でリポジトリに振り分ける"""
    where = {fold.path_key(job.root / rel): (job.target.id, rel) for job in jobs for rel in job.lockfiles}
    out: dict[str, list[dict]] = {job.target.id: [] for job in jobs}
    warnings = []
    for key, found in fold.by_source(data).items():
        hit = where.get(key)
        if hit is None:
            warnings.append(f"どのリポジトリのものか分からない結果を捨てました: {key}")
            continue
        rid, rel = hit
        for f in found:
            f["lockfile"] = rel
        out[rid].extend(found)
    return {rid: fold.dedupe(fs) for rid, fs in out.items()}, warnings


def _jobs(targets: list[Target], cfg: dict) -> list[Job]:
    online, _ = split_by_privacy(targets, cfg["online_public"])
    online_ids = {t.id for t in online}
    return [_prepare(t, "online" if t.id in online_ids else "offline") for t in targets]


def _key(job: Job, scanner_version: str, db_state: dict[str, str]) -> str:
    """キャッシュの鍵（design.md §6）。手元の DB で照合するものは、その生態系の DB の取得時刻も入れる"""
    db = {e: db_state.get(e) for e in sorted(job.ecosystems)} if job.mode == "offline" else None
    return store.cache_key(id=job.target.id, mode=job.mode, osv_scanner=scanner_version, shape=fold.SHAPE,
                           lockfiles=list(zip(job.lockfiles, job.hashes)), db=db)


def check(target: Target, *, data: Path, cfg: dict, scanner_version: str, at: datetime) -> dict:
    """事前チェック（design.md §7 の scan --check）。照合はせず、今 scan したらキャッシュの結果が返るかを答える。
    reason: cached（前回の結果がそのまま返る）/ no-cache（lock ファイルが変わった・期限切れ・まだ照合していない）/
            db-update（手元の DB を取り直してから照合する）/ no-lockfile / error"""
    job = _jobs([target], cfg)[0]
    out = {"id": target.id, "mode": job.mode, "cached": False, "scanned_at": None, "lockfiles": job.lockfiles}
    if job.error:
        return {**out, "reason": "error", "error": job.error}
    if not job.lockfiles:
        return {**out, "reason": "no-lockfile"}
    db_state = store.load_db_state(data)
    if job.mode == "offline" and store.db_needs_update(db_state, job.ecosystems, cfg["db_max_age_days"], at):
        return {**out, "reason": "db-update"}
    hit = store.cache_get(data, _key(job, scanner_version, db_state), cfg["cache_max_age_hours"], at)
    if hit is None:
        return {**out, "reason": "no-cache"}
    return {**out, "cached": True, "scanned_at": hit["saved_at"], "reason": "cached"}


def run(targets: list[Target], *, data: Path, cfg: dict, exe: str, scanner_version: str,
        at: datetime, force_db_update: bool = False, use_cache: bool = True) -> Outcome:
    """use_cache が False なら、キャッシュを読まずに照合し直す（書くのはいつもどおり）"""
    jobs = _jobs(targets, cfg)
    entries: dict[str, dict] = {}
    warnings: list[str] = []
    failed = False

    def key_of(job: Job, db_state: dict[str, str]) -> str:
        return _key(job, scanner_version, db_state)

    def cached(k: str) -> dict | None:
        return store.cache_get(data, k, cfg["cache_max_age_hours"], at) if use_cache else None

    todo: list[Job] = []
    for job in jobs:
        if job.error:
            entries[job.target.id] = _entry(job, at, "error", [], job.error)
        elif not job.lockfiles:
            entries[job.target.id] = _entry(job, at, "no-lockfile", [])
        else:
            todo.append(job)

    # ---- 手元の DB（まとめて 1 回）
    offline_jobs = [j for j in todo if j.mode == "offline"]
    db_state = store.load_db_state(data)
    db_used: set[str] = set()
    if offline_jobs:
        needed = set().union(*(j.ecosystems for j in offline_jobs))
        db_used = needed
        download = force_db_update or store.db_needs_update(db_state, needed, cfg["db_max_age_days"], at)
        batch = []
        for job in offline_jobs:
            hit = None if download else cached(key_of(job, db_state))
            if hit is not None:
                entries[job.target.id] = _entry(job, hit["saved_at"], "ok", hit["findings"])
            else:
                batch.append(job)
        if batch:
            try:
                res = osv.scan_offline(exe, [p for j in batch for p in j.paths()], download=download)
            except osv.ScannerError as e:
                failed = True
                for job in batch:
                    entries[job.target.id] = _entry(job, at, "error", [], str(e))
            else:
                if download:
                    for eco in needed:
                        db_state[eco] = store.iso(at)
                    store.save_db_state(data, db_state)
                if res.nothing:
                    for job in batch:
                        entries[job.target.id] = _entry(job, at, "no-lockfile", [])
                else:
                    found, w = _assign(batch, res.data)
                    warnings += w
                    for job in batch:
                        entries[job.target.id] = _entry(job, at, "ok", found[job.target.id])
                        # 取り直した DB の時刻で鍵を作る
                        store.cache_put(data, key_of(job, db_state), found[job.target.id], at)

    # ---- オンライン（リポジトリごと、並列）
    online_jobs = []
    for job in (j for j in todo if j.mode == "online"):
        k = key_of(job, db_state)  # オンラインは DB の時刻を鍵に入れない（_key が見る）
        hit = cached(k)
        if hit is not None:
            entries[job.target.id] = _entry(job, hit["saved_at"], "ok", hit["findings"])
        else:
            online_jobs.append((job, k))

    def one(item):
        job, k = item
        try:
            res = osv.scan_online(exe, job.target, job.paths())
        except osv.ScannerError as e:
            return job, k, None, str(e)
        return job, k, res, None

    if online_jobs:
        with ThreadPoolExecutor(max_workers=cfg["parallel"]) as pool:
            for job, k, res, err in pool.map(one, online_jobs):
                if err is not None:
                    failed = True
                    entries[job.target.id] = _entry(job, at, "error", [], err)
                elif res.nothing:
                    entries[job.target.id] = _entry(job, at, "no-lockfile", [])
                else:
                    found, w = _assign([job], res.data)
                    warnings += w
                    entries[job.target.id] = _entry(job, at, "ok", found[job.target.id])
                    store.cache_put(data, k, found[job.target.id], at)

    times = [t for t in (store.parse_time(db_state.get(e)) for e in db_used) if t is not None]
    return Outcome(repos={j.target.id: entries[j.target.id] for j in jobs},
                   db_downloaded_at=store.iso(min(times)) if times else None,
                   scanner_failed=failed, warnings=warnings)
