# PyInstaller spec (docs/design.md section 9.1). Build with scripts\build-exe.cmd.
# One onedir folder "LockWatch" with two exes that share _internal\:
#   lockwatch.exe   console: commands whose output is read (RepoTether, the window's jobs)
#   lockwatchw.exe  no console: the window ("gui") and the scheduled tasks ("--log scan")
from pathlib import Path

ROOT = Path(SPECPATH).parent

a = Analysis(
    [str(ROOT / "scripts" / "exe_entry.py")],
    pathex=[str(ROOT / "src")],
    hiddenimports=["lockwatch.gui"],
    excludes=["unittest", "pydoc", "test"],
)
pyz = PYZ(a.pure)


def exe(name, console):
    return EXE(pyz, a.scripts, [], exclude_binaries=True, name=name, console=console,
               upx=False, version=None, icon=None)


coll = COLLECT(exe("lockwatch", True), exe("lockwatchw", False), a.binaries, a.datas,
               name="LockWatch", upx=False)
