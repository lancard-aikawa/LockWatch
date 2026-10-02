"""osv-scanner の呼び出し（docs/design.md §5.1）

オンライン（api.osv.dev）で呼ぶのは scan_online だけで、呼ぶ前に必ず targets.assert_all_public を通す。
手元の DB で呼ぶ scan_offline は、OFFLINE_FLAGS を必ず全部付ける（--no-resolve が無いと deps.dev に送られる）。
"""
import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .targets import Target, assert_all_public

OFFLINE_FLAGS = ("--offline", "--offline-vulnerabilities", "--no-resolve")
ONLINE_FLAGS = ("--no-resolve",)
DOWNLOAD_FLAG = "--download-offline-databases"

EXIT_NONE, EXIT_FOUND, EXIT_NOTHING = 0, 1, 128
TIMEOUT_SECONDS = 1800

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


class ScannerError(RuntimeError):
    """osv-scanner が無い・失敗した"""


@dataclass
class Outcome:
    nothing: bool          # 終了コード 128（調べるものが無い）
    data: dict | None      # 出力の JSON（nothing のときは None）


def find_scanner(configured: str | None) -> str:
    """osv-scanner の場所。設定が空なら PATH から探す"""
    if configured:
        if not Path(configured).is_file():
            raise ScannerError(f"osv-scanner がありません: {configured}")
        return configured
    found = shutil.which("osv-scanner")
    if not found:
        raise ScannerError("osv-scanner が PATH にありません（設定 osv_scanner で場所を指定できます）")
    return found


def version(exe: str) -> str:
    """osv-scanner --version の版（例: 2.6.0）"""
    try:
        p = subprocess.run([exe, "--version"], capture_output=True, text=True, encoding="utf-8",
                           errors="replace", creationflags=_NO_WINDOW, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise ScannerError(f"osv-scanner を起動できません: {e}") from e
    m = re.search(r"osv-scanner version:\s*(\S+)", p.stdout)
    if p.returncode != 0 or not m:
        raise ScannerError(f"osv-scanner の版を読めません（終了コード {p.returncode}）: {(p.stdout + p.stderr).strip()[:200]}")
    return m.group(1)


def _run(exe: str, flags: tuple[str, ...], lockfiles: list[Path]) -> Outcome:
    if not lockfiles:
        raise ValueError("lock ファイルが 1 つもありません")
    fd, out_name = tempfile.mkstemp(prefix="lockwatch-osv-", suffix=".json")
    os.close(fd)
    out = Path(out_name)
    try:
        out.unlink()  # 128 のときは作られない。前の中身を読み違えないように消しておく
        argv = [exe, "scan", "source", *flags, "--format", "json", "--output-file", str(out)]
        for f in lockfiles:
            argv += ["-L", str(f)]
        try:
            p = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace",
                               creationflags=_NO_WINDOW, timeout=TIMEOUT_SECONDS)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise ScannerError(f"osv-scanner を実行できません: {e}") from e
        if p.returncode == EXIT_NOTHING:
            return Outcome(True, None)
        if p.returncode not in (EXIT_NONE, EXIT_FOUND):
            tail = "\n".join(p.stderr.strip().splitlines()[-5:])
            raise ScannerError(f"osv-scanner が失敗しました（終了コード {p.returncode}）: {tail}")
        try:
            with open(out, encoding="utf-8") as f:
                return Outcome(False, json.load(f))
        except (OSError, ValueError) as e:
            raise ScannerError(f"osv-scanner の出力を読めません: {e}") from e
    finally:
        out.unlink(missing_ok=True)


def scan_online(exe: str, target: Target, lockfiles: list[Path]) -> Outcome:
    """public のリポジトリ 1 つを api.osv.dev で照合する"""
    assert_all_public([target])
    return _run(exe, ONLINE_FLAGS, lockfiles)


def scan_offline(exe: str, lockfiles: list[Path], download: bool = False) -> Outcome:
    """手元の DB で照合する（何も外に送らない）。download なら、読んだ生態系の DB を先に取り直す"""
    flags = OFFLINE_FLAGS + ((DOWNLOAD_FLAG,) if download else ())
    return _run(exe, flags, lockfiles)
