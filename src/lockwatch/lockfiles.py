"""lock ファイルの名前と数え方（docs/design.md §5.2）。RepoTether が取ってくるファイルもこの表に合わせる"""
import fnmatch
import os
import subprocess
from pathlib import Path

NAMES = frozenset({
    "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock",
    "uv.lock", "poetry.lock", "Pipfile.lock", "pdm.lock",
    "Cargo.lock", "pubspec.lock", "composer.lock", "Gemfile.lock", "go.mod",
})

# lock ファイルの名前 → osv-scanner の DB の生態系（%LOCALAPPDATA%\osv-scalibr\<生態系>）。design.md §5.3
ECOSYSTEMS = {
    "package-lock.json": "npm", "npm-shrinkwrap.json": "npm", "pnpm-lock.yaml": "npm", "yarn.lock": "npm", "bun.lock": "npm",
    "uv.lock": "PyPI", "poetry.lock": "PyPI", "Pipfile.lock": "PyPI", "pdm.lock": "PyPI",
    "Cargo.lock": "crates.io", "pubspec.lock": "Pub", "composer.lock": "Packagist", "Gemfile.lock": "RubyGems", "go.mod": "Go",
}

# フォルダを歩いて数えるときに入らないフォルダ（. で始まるものも入らない）
SKIP_DIRS = frozenset({"node_modules", "venv", "__pycache__", "target", "build", "dist"})

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def is_lockfile(name: str) -> bool:
    """ファイル名（パスの最後）が lock ファイルか。requirements*.txt も含める"""
    return name in NAMES or (name.startswith("requirements") and name.endswith(".txt"))


def ecosystem_of(name: str) -> str:
    """lock ファイルの名前（パスの最後）から生態系を決める"""
    return ECOSYSTEMS.get(name, "PyPI")  # 表に無いのは requirements*.txt だけ


def split_excluded(found: list[str], exclude_dirs) -> tuple[list[str], list[str]]:
    """(対象にするもの, 外すもの)。相対パスのフォルダ名のどれかが exclude_dirs のどれかと同じなら外す
    （大文字小文字は区別しない。* ? を書ける。ファイル名は見ない）。design.md §5.2"""
    patterns = [p.lower() for p in exclude_dirs or [] if isinstance(p, str) and p]
    kept, excluded = [], []
    for rel in found:
        dirs = rel.lower().split("/")[:-1]
        hit = any(fnmatch.fnmatchcase(d, p) for d in dirs for p in patterns)
        (excluded if hit else kept).append(rel)
    return kept, excluded


def _git_ls_files(root: Path) -> list[str] | None:
    """git が管理しているファイル（root からの相対、/ 区切り）。git のリポジトリでなければ None"""
    try:
        p = subprocess.run(["git", "-C", str(root), "ls-files", "-z"], capture_output=True,
                           creationflags=_NO_WINDOW, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if p.returncode != 0:
        return None
    return [s for s in p.stdout.decode("utf-8", "surrogateescape").split("\0") if s]


def _walk(root: Path) -> list[str]:
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not d.startswith(".") and d not in SKIP_DIRS]
        for name in filenames:
            if is_lockfile(name):
                out.append(Path(dirpath, name).relative_to(root).as_posix())
    return out


def find(root: Path, use_git: bool = True) -> list[str]:
    """root の中の lock ファイル（root からの相対、/ 区切り、並べ替え済み）。
    use_git なら git が管理しているものだけ（git のリポジトリでなければ歩いて数える）"""
    listed = _git_ls_files(root) if use_git else None
    if listed is None:
        return sorted(_walk(root))
    return sorted(rel for rel in listed if is_lockfile(rel.rsplit("/", 1)[-1]) and (root / rel).is_file())
