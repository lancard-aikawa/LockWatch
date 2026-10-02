"""lockwatch status: 使える状態かをまとめて答える（docs/design.md §7）。RepoTether の設定の「確かめる」が使う

読むだけ。osv-scanner は --version だけ呼び、通信はしない。
"""
import os
import subprocess
from pathlib import Path

from . import __version__, osv, store
from .targets import TargetsError, load as load_targets

TASK_NAME = "LockWatch scan"
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def task_registered(name: str = TASK_NAME) -> bool | None:
    """タスクスケジューラに定期実行が登録されているか。Windows 以外は None"""
    if os.name != "nt":
        return None
    try:
        p = subprocess.run(["schtasks", "/Query", "/TN", name], capture_output=True, creationflags=_NO_WINDOW, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return p.returncode == 0


def collect(cfg: dict, data: Path, targets_path: Path) -> dict:
    out: dict = {"lockwatch": __version__, "data_dir": str(data), "targets": str(targets_path)}

    try:
        exe = osv.find_scanner(cfg["osv_scanner"])
        out["osv_scanner"] = {"path": exe, "version": osv.version(exe), "error": None}
    except osv.ScannerError as e:
        out["osv_scanner"] = {"path": None, "version": None, "error": str(e)}

    try:
        ts = load_targets(targets_path, data)
        out["targets_count"], out["targets_error"] = len(ts), None
    except FileNotFoundError:
        out["targets_count"], out["targets_error"] = None, "ありません"
    except TargetsError as e:
        out["targets_count"], out["targets_error"] = None, str(e)

    latest = store.load_latest(data)
    out["latest"] = None if latest is None else {
        "scanned_at": latest.get("scanned_at"),
        "repos": len(latest["repos"]),
        "errors": sum(1 for e in latest["repos"].values() if isinstance(e, dict) and e.get("status") == "error"),
    }
    out["db"] = store.load_db_state(data)
    out["task"] = {"name": TASK_NAME, "registered": task_registered()}
    return out


def lines(s: dict) -> list[str]:
    """人が読む形"""
    o = s["osv_scanner"]
    task = s["task"]["registered"]
    latest = s["latest"]
    return [
        f"LockWatch      {s['lockwatch']}",
        f"osv-scanner    {o['version']}（{o['path']}）" if o["version"] else f"osv-scanner    使えません: {o['error']}",
        f"データ          {s['data_dir']}",
        f"targets.json   {s['targets_count']} 件" if s["targets_error"] is None else f"targets.json   {s['targets_error']}（{s['targets']}）",
        f"最後の照合      {latest['scanned_at']}（{latest['repos']} 件、エラー {latest['errors']}）" if latest else "最後の照合      まだありません",
        "手元の DB       " + (", ".join(f"{k} {v}" for k, v in s["db"].items()) or "まだ取っていません"),
        f"定期実行        {'登録済み' if task else '未登録（scripts/register-task.ps1）' if task is False else '-'}（{s['task']['name']}）",
    ]
