"""設定ファイル (lockwatch.json) の読み書き。形は docs/design.md §8（SessionVault の config.py と同じ作り）"""
import copy
import json
from pathlib import Path

DEFAULTS: dict = {
    "data_dir": None,
    "targets": None,
    "osv_scanner": None,
    "online_public": True,
    "parallel": 4,
    "db_max_age_days": 7,
    "cache_max_age_hours": 20,
    "keep_results": 30,
    "exclude_dirs": ["vendor", "vendors", "third_party", "third-party", "bower_components", "node_modules"],
}


def _parse_names(s: str) -> list[str]:
    """, で区切ったフォルダ名の並び。空なら何も外さない"""
    names = [x.strip() for x in s.split(",") if x.strip()]
    bad = [x for x in names if "/" in x or "\\" in x]
    if bad:
        raise ValueError(f"フォルダ名だけを書いてください（/ や \\ は使えません）: {', '.join(bad)}")
    return names


def _parse_bool(s: str) -> bool:
    if s.lower() in ("true", "1", "yes", "on"):
        return True
    if s.lower() in ("false", "0", "no", "off"):
        return False
    raise ValueError(f"true か false を指定してください: {s}")


def _parse_positive_int(s: str) -> int:
    n = int(s)
    if n < 1:
        raise ValueError(f"1 以上を指定してください: {s}")
    return n


# config set で受け付けるキーと、値の読み方
_PARSERS = {
    "data_dir": lambda s: s or None,
    "targets": lambda s: s or None,
    "osv_scanner": lambda s: s or None,
    "online_public": _parse_bool,
    "parallel": _parse_positive_int,
    "db_max_age_days": _parse_positive_int,
    "cache_max_age_hours": _parse_positive_int,
    "keep_results": _parse_positive_int,
    "exclude_dirs": _parse_names,
}


def keys() -> list[str]:
    return list(_PARSERS)


def _merge(base: dict, over: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def load(path: Path) -> dict:
    """設定を読む。ファイルが無ければ既定値。知らないキーは残す（新しい版の設定を壊さない）"""
    if not path.is_file():
        return copy.deepcopy(DEFAULTS)
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"設定ファイルの中身がオブジェクトではありません: {path}")
    return _merge(DEFAULTS, data)


def save(path: Path, cfg: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
        f.write("\n")
    tmp.replace(path)


def set_value(cfg: dict, key: str, raw: str) -> dict:
    """key に raw を読んだ値を入れた新しい設定を返す。知らないキーは KeyError"""
    if key not in _PARSERS:
        raise KeyError(key)
    out = copy.deepcopy(cfg)
    out[key] = _PARSERS[key](raw)
    return out
