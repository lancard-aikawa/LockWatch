"""PyInstaller の出力（dist/LockWatch）に配るファイルを足し、動くかを確かめて zip にする（docs/design.md §9.1）

  python scripts/package_exe.py            dist/LockWatch-<版>-win-x64.zip を作り、場所と SHA-256 を出す

設定（lockwatch.json）とデータ（data/）は入れない。入っていたら止める（手元で動かした跡を配らない）。
"""
import hashlib
import shutil
import subprocess
import sys
import tomllib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "dist" / "LockWatch"
EXTRA = ["README.md", "LICENSE", "CHANGELOG.md", "lockwatch.sample.json"]
SCRIPTS = ["register-task.ps1", "find-pythonw.ps1"]
NOT_SHIPPED = ["lockwatch.json", "data", "osv-scanner.exe"]


def version() -> str:
    with open(ROOT / "pyproject.toml", "rb") as f:
        return tomllib.load(f)["project"]["version"]


def main() -> int:
    v = version()
    for name in ("lockwatch.exe", "lockwatchw.exe", "_internal"):
        if not (APP / name).exists():
            print(f"{APP / name} がありません（先に PyInstaller で固める）", file=sys.stderr)
            return 1
    for name in NOT_SHIPPED:
        if (APP / name).exists():
            print(f"{APP / name} があります。配る前に消してください（設定とデータは zip に入れない）", file=sys.stderr)
            return 1
    for name in EXTRA:
        shutil.copy2(ROOT / name, APP / name)
    (APP / "scripts").mkdir(exist_ok=True)
    for name in SCRIPTS:
        shutil.copy2(ROOT / "scripts" / name, APP / "scripts" / name)

    # 固めた exe が起動して、自分の版を答えること（Tcl/Tk の取りこぼしは画面を開くまで出ないので、画面は手で開いて確かめる）
    p = subprocess.run([str(APP / "lockwatch.exe"), "--version"], capture_output=True, text=True, encoding="utf-8")
    if p.returncode != 0 or v not in p.stdout:
        print(f"lockwatch.exe --version が {v} を答えません: {p.stdout!r} {p.stderr!r}", file=sys.stderr)
        return 1

    out = ROOT / "dist" / f"LockWatch-{v}-win-x64.zip"
    out.unlink(missing_ok=True)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for f in sorted(APP.rglob("*")):
            if f.is_file():
                z.write(f, Path("LockWatch") / f.relative_to(APP))
    digest = hashlib.sha256(out.read_bytes()).hexdigest()
    print(out)
    print(f"sha256 {digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
