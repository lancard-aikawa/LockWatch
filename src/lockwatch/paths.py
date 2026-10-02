"""プログラムの置き場所と、設定・データの場所を決める（docs/design.md §8）"""
import sys
from pathlib import Path

CONFIG_NAME = "lockwatch.json"


def app_dir() -> Path:
    """プログラムの置き場所。exe ならそのフォルダ、リポジトリからならリポジトリのルート"""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[2]


def default_config_path() -> Path:
    return app_dir() / CONFIG_NAME


def data_dir(cli_value: str | None, config_value: str | None) -> Path:
    """データの場所。--data、設定、既定値（<app>/data）の順"""
    for v in (cli_value, config_value):
        if v:
            return Path(v).expanduser()
    return app_dir() / "data"


def targets_path(cli_value: str | None, config_value: str | None, data: Path) -> Path:
    """targets.json の場所。--targets、設定、既定値（<data>/targets.json）の順"""
    for v in (cli_value, config_value):
        if v:
            return Path(v).expanduser()
    return data / "targets.json"
