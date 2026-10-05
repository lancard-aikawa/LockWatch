"""コマンドライン。サブコマンドの中身は docs/design.md に沿って順に書く"""
import argparse
import contextlib
import json
import sys
import traceback
from pathlib import Path

from . import __version__
from . import config as cfgmod
from . import fold, htmlreport, osv, store
from . import packages as pkgmod
from . import scan as scanmod
from . import status as statusmod
from . import targets as targetsmod
from .paths import data_dir, default_config_path, targets_path

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_BUSY = 3
EXIT_SCANNER = 4


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="lockwatch", description="自分のリポジトリの lock ファイルを osv-scanner にかけ、脆弱性の一覧にする")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("--config", help="設定ファイル（既定: プログラムの置き場所の lockwatch.json）")
    p.add_argument("--data", help="データの場所（設定より優先）")
    p.add_argument("--targets", help="targets.json の場所（設定より優先）")
    p.add_argument("--log", action="store_true", help="今回の出力を <data>/last-run.log に書く（定期実行の pythonw 用）")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="targets.json の全部（か 1 つ）を照合する")
    one = s.add_mutually_exclusive_group()
    one.add_argument("--repo", help="このフォルダだけを照合する（公開か分からないので手元の DB で照合）")
    one.add_argument("--id", help="targets.json のうち、この id のリポジトリだけ")
    s.add_argument("--check", action="store_true",
                   help="照合はせず、今照合したら前回の結果（キャッシュ）がそのまま返るかを JSON で答える（--id か --repo と一緒に）")
    s.add_argument("--no-cache", action="store_true", help="キャッシュを使わずに照合し直す")

    r = sub.add_parser("report", help="最新の結果を表示する")
    r.add_argument("--new", action="store_true", help="前回から新しく出たものだけ")
    r.add_argument("--json", action="store_true", help="JSON で出す")
    r.add_argument("--hide", action="append", default=[], choices=[*fold.SEVERITIES, *fold.INFORMATIONAL],
                   help="この深刻度か知らせの種類を消す（重ねて書ける）")
    r.add_argument("--id", help="このリポジトリだけ")
    r.add_argument("--html", action="store_true", help="リポジトリごとの診断書（HTML）と一覧（index.html）を書く")
    r.add_argument("--out", help="診断書を書くフォルダ（既定: <data>/reports）")

    k = sub.add_parser("packages", help="全依存の台帳を引く（どのリポジトリが、そのパッケージのどの版を使っているか）")
    k.add_argument("name", nargs="?", help="パッケージの名前（大文字小文字は区別しない。* ? を書ける）。省略するとリポジトリごとの件数")
    k.add_argument("--version", dest="pkg_version", metavar="VERSION", help="この版だけ")
    k.add_argument("--ecosystem", help="この生態系だけ（npm・PyPI・crates.io など）")
    k.add_argument("--id", help="このリポジトリだけ")
    k.add_argument("--json", action="store_true", help="JSON で出す")

    sub.add_parser("db-update", help="脆弱性 DB を取り直す")

    sub.add_parser("gui", help="状態・結果・台帳・設定の画面を開く（pythonw -m lockwatch gui なら黒い窓が出ない）")

    st = sub.add_parser("status", help="使える状態か（osv-scanner・受け渡し・最後の照合・定期実行）を表示する")
    st.add_argument("--json", action="store_true", help="JSON で出す")

    t = sub.add_parser("targets", help="受け渡しのファイルを扱う")
    tsub = t.add_subparsers(dest="targets_command", required=True)
    tc = tsub.add_parser("check", help="targets.json の形を検査し、オンライン・手元の振り分けを表示する")
    tc.add_argument("file", nargs="?", help="検査するファイル（省略時は設定の場所）")

    c = sub.add_parser("config", help="設定を見る・変える")
    csub = c.add_subparsers(dest="config_command", required=True)
    csub.add_parser("show", help="今の設定（既定値込み）と、実際に使う場所を表示する")
    csub.add_parser("path", help="設定ファイルの場所を表示する")
    cs = csub.add_parser("set", help="設定を 1 つ変える")
    cs.add_argument("key", choices=cfgmod.keys())
    cs.add_argument("value", help="空文字で既定に戻す（場所の設定）")

    return p


def _cmd_config(args, config_path: Path, cfg: dict) -> int:
    if args.config_command == "path":
        print(config_path)
        return EXIT_OK
    if args.config_command == "show":
        data = data_dir(args.data, cfg["data_dir"])
        shown = dict(cfg)
        shown["_effective_data_dir"] = str(data)
        shown["_effective_targets"] = str(targets_path(args.targets, cfg["targets"], data))
        shown["_config_file"] = str(config_path) + ("" if config_path.is_file() else "（まだ無い）")
        print(json.dumps(shown, ensure_ascii=False, indent=2))
        return EXIT_OK
    try:
        new_cfg = cfgmod.set_value(cfg, args.key, args.value)
    except ValueError as e:
        print(f"値が読めません: {e}", file=sys.stderr)
        return EXIT_USAGE
    cfgmod.save(config_path, new_cfg)
    print(f"{args.key} = {json.dumps(new_cfg[args.key], ensure_ascii=False)}（{config_path}）")
    return EXIT_OK


def _cmd_targets_check(args, cfg: dict) -> int:
    data = data_dir(args.data, cfg["data_dir"])
    path = Path(args.file) if args.file else targets_path(args.targets, cfg["targets"], data)
    try:
        targets = targetsmod.load(path, data)
    except FileNotFoundError:
        print(f"ありません: {path}", file=sys.stderr)
        return EXIT_USAGE
    except targetsmod.TargetsError as e:
        print(f"形が違います（{path}）: {e}", file=sys.stderr)
        return EXIT_USAGE
    online, offline = targetsmod.split_by_privacy(targets, cfg["online_public"])
    missing = [t for t in targets if not t.root.is_dir()]
    print(f"{path}: {len(targets)} 件（オンライン {len(online)}、手元の DB {len(offline)}）")
    for t in online:
        print(f"  online   {t.id}")
    for t in offline:
        print(f"  offline  {t.id}（{t.visibility}）")
    for t in missing:
        print(f"  注意: フォルダがありません: {t.id} → {t.root}", file=sys.stderr)
    return EXIT_OK


def _counts(findings: list[dict]) -> str:
    n = {s: 0 for s in fold.SEVERITIES}
    for f in findings:
        n[f["severity"]] = n.get(f["severity"], 0) + 1
    return " / ".join(f"{s} {n[s]}" for s in fold.SEVERITIES if n[s])


def _note(f: dict) -> str:
    """悪意あるコード・知らせの種類の印"""
    return ("  [malicious]" if f.get("malicious") else "") + (f"  [{f['informational']}]" if f.get("informational") else "")


def _print_findings(findings: list[dict]) -> None:
    order = {s: i for i, s in enumerate(fold.SEVERITIES)}
    for f in sorted(findings, key=lambda f: (order.get(f["severity"], 99), f["package"], f["id"])):
        fixed = ", ".join(f["fixed"]) or "-"
        note = _note(f)
        print(f"  {f['severity']:<8} {f['package']} {f['version']}  {f['id']}{note}  直る版 {fixed}  （{f['lockfile']}）")


def _print_repo(rid: str, e: dict) -> None:
    if e["status"] == "ok":
        detail = f"{len(e['findings'])} 件" + (f"（{_counts(e['findings'])}）" if e["findings"] else "")
    elif e["status"] == "error":
        detail = e.get("error", "")
    else:
        detail = "lock ファイルなし"
    print(f"{e['status']:<11} {e['mode']:<7} {rid}  {detail}")


def _print_new(new: list[dict]) -> None:
    for n in new:
        note = _note(n)
        print(f"  {n['severity']:<8} {n['repo']}  {n['package']}  {n['id']}{note}")


def _scanner(cfg: dict) -> tuple[str, str] | None:
    """(osv-scanner の場所, 版)。無ければ理由を出して None"""
    try:
        exe = osv.find_scanner(cfg["osv_scanner"])
        return exe, osv.version(exe)
    except osv.ScannerError as e:
        print(e, file=sys.stderr)
        return None


def _load_targets(args, cfg: dict, data: Path) -> list | None:
    """targets.json を読む。読めなければ理由を出して None"""
    path = targets_path(args.targets, cfg["targets"], data)
    try:
        return targetsmod.load(path, data)
    except FileNotFoundError:
        print(f"targets.json がありません: {path}（1 つだけ照合するなら scan --repo）", file=sys.stderr)
    except targetsmod.TargetsError as e:
        print(f"形が違います（{path}）: {e}", file=sys.stderr)
    return None


def _cmd_scan(args, cfg: dict) -> int:
    data = data_dir(args.data, cfg["data_dir"])
    if args.check and not (args.id or args.repo):
        print("--check は --id か --repo と一緒に使います", file=sys.stderr)
        return EXIT_USAGE
    found = _scanner(cfg)
    if found is None:
        return EXIT_SCANNER
    exe, ver = found

    if args.repo:
        root = Path(args.repo).expanduser().resolve()
        if not root.is_dir():
            print(f"フォルダがありません: {root}", file=sys.stderr)
            return EXIT_USAGE
        # 公開か分からないので unknown（= 手元の DB で照合）。design.md §4
        targets = [targetsmod.Target(f"local:{root.as_posix()}", "unknown", root, False)]
    else:
        targets = _load_targets(args, cfg, data)
        if targets is None:
            return EXIT_USAGE
        if args.id:
            targets = [t for t in targets if t.id == args.id]
            if not targets:
                print(f"targets.json にありません: {args.id}", file=sys.stderr)
                return EXIT_USAGE

    if args.check:
        # 読むだけなので排他は取らない（定期実行の最中でも答えられる）
        result = scanmod.check(targets[0], data=data, cfg=cfg, scanner_version=ver, at=store.now())
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return EXIT_OK

    try:
        with store.exclusive(data):
            at = store.now()
            out = scanmod.run(targets, data=data, cfg=cfg, exe=exe, scanner_version=ver, at=at, use_cache=not args.no_cache)
            if not args.repo:
                _write_scan_results(data, cfg, out, ver, at, only_id=args.id)
            store.cache_prune(data, cfg["cache_max_age_hours"], at)
    except store.Busy as e:
        print(e, file=sys.stderr)
        return EXIT_BUSY

    for w in out.warnings:
        print(f"注意: {w}", file=sys.stderr)
    for rid, e in out.repos.items():
        _print_repo(rid, e)
        if args.repo:
            _print_findings(e["findings"])
    if not args.repo:
        latest = store.load_latest(data) or {}
        new = [n for n in latest.get("new", []) if not args.id or n.get("repo") == args.id]
        print(f"新しく出たもの: {len(new)} 件（{store.results_dir(data) / 'latest.json'}）")
        _print_new(new)
    return EXIT_SCANNER if out.scanner_failed else EXIT_OK


def _cmd_report(args, cfg: dict) -> int:
    data = data_dir(args.data, cfg["data_dir"])
    latest = store.load_latest(data)
    if latest is None:
        print(f"結果がまだありません: {store.results_dir(data) / 'latest.json'}（先に scan）", file=sys.stderr)
        return EXIT_USAGE
    if args.html and (args.json or args.new):
        print("--html は --json / --new と一緒に使えません", file=sys.stderr)
        return EXIT_USAGE
    if args.out and not args.html:
        print("--out は --html と一緒に使います", file=sys.stderr)
        return EXIT_USAGE
    if args.id and args.id not in latest["repos"]:
        print(f"結果にありません: {args.id}", file=sys.stderr)
        return EXIT_USAGE
    hide = set(args.hide)
    all_new = [n for n in latest.get("new") or [] if not args.id or n.get("repo") == args.id]
    new = [n for n in all_new if not fold.hidden(n, hide)]
    # 消した件数。new の項目は findings にも入っているので、--new のときだけ new の側で数える（両方で数えると 2 回になる）
    n_hidden = len(all_new) - len(new) if args.new else 0
    repos = {}
    for rid, e in latest["repos"].items():
        if args.id and rid != args.id:
            continue
        kept = [f for f in e.get("findings") or [] if not fold.hidden(f, hide)]
        if not args.new:
            n_hidden += len(e.get("findings") or []) - len(kept)
        repos[rid] = {**e, "findings": kept}

    if args.html:
        return _write_html(args, cfg, data, latest, repos, new, n_hidden, hide)
    if args.json:
        obj = new if args.new else {**latest, "repos": repos, "new": new}
        print(json.dumps(obj, ensure_ascii=False, indent=2))
        return EXIT_OK

    print(f"{latest.get('scanned_at')} 照合（osv-scanner {latest.get('osv_scanner')}、手元の DB {latest.get('db_downloaded_at') or '-'}）")
    if args.new:
        print(f"新しく出たもの: {len(new)} 件")
        _print_new(new)
    else:
        for rid, e in repos.items():
            _print_repo(rid, e)
            _print_findings(e["findings"])
        print(f"新しく出たもの: {len(new)} 件")
    if hide:
        print(f"（--hide {' '.join(sorted(hide))} で {n_hidden} 件を消しています）")
    return EXIT_OK


def _write_html(args, cfg: dict, data: Path, latest: dict, repos: dict, new: list[dict], n_hidden: int, hide: set[str]) -> int:
    """診断書を書く（design.md §7.1）。--id ならそのリポジトリだけで、index.html は書き直さない"""
    out_dir = Path(args.out).expanduser() if args.out else data / "reports"
    made_at = store.now()
    names = htmlreport.file_names(latest["repos"])  # --id のときも、全部を書いたときと同じ名前にする
    written = []
    for rid, e in repos.items():
        n_h = len(latest["repos"][rid].get("findings") or []) - len(e["findings"])
        new_ids = {(n.get("package"), n.get("id")) for n in new if n.get("repo") == rid}
        path = out_dir / f"{names[rid]}.html"
        htmlreport.write_text(path, htmlreport.render_repo(rid, e, latest, new_ids=new_ids, n_hidden=n_h, hide=hide, made_at=made_at))
        written.append(path)
    if not args.id:
        index = out_dir / "index.html"
        htmlreport.write_text(index, htmlreport.render_index(repos, latest, names, n_new=len(new), n_hidden=n_hidden, hide=hide, made_at=made_at))
        written.append(index)
        # 対象から外したリポジトリの古い診断書を消す。LockWatch が書いたもの以外には触れない
        keep = {p.name.lower() for p in written}
        for old in out_dir.glob("*.html"):
            if old.name.lower() not in keep and htmlreport.is_ours(old):
                old.unlink()
                print(f"古い診断書を消しました: {old}")
    print(f"{len(repos)} 件の診断書を書きました: {written[-1]}")
    if hide:
        print(f"（--hide {' '.join(sorted(hide))} で {n_hidden} 件を除いています）")
    return EXIT_OK


def _cmd_packages(args, cfg: dict) -> int:
    """全依存の台帳を引く（design.md §7）。照合はしない"""
    data = data_dir(args.data, cfg["data_dir"])
    doc = store.load_packages(data)
    if doc is None:
        print(f"台帳がまだありません: {store.packages_path(data)}（先に scan）", file=sys.stderr)
        return EXIT_USAGE
    if args.id and args.id not in doc["repos"]:
        print(f"台帳にありません: {args.id}", file=sys.stderr)
        return EXIT_USAGE
    repos = pkgmod.select(doc, name=args.name, version=args.pkg_version, ecosystem=args.ecosystem, only_id=args.id)
    hits = pkgmod.hits(repos)

    if args.json:
        if args.name:
            print(json.dumps(hits, ensure_ascii=False, indent=2))
        else:
            print(json.dumps({**doc, "repos": repos}, ensure_ascii=False))
        return EXIT_OK

    print(f"台帳: {store.packages_path(data)}（照合 {pkgmod.scanned(repos)}）")
    if not args.name:
        for rid, e in repos.items():
            print(f"{len(e['packages']):>7}  {rid}")
        print(f"{len(hits)} 件（{len(repos)} リポジトリ）")
        return EXIT_OK
    for h in hits:
        print(f"  {h['package']} {h['version']}  {h['ecosystem']}  {h['repo']}  （{h['lockfile']}）")
    print(f"{len(hits)} 件（{len({h['repo'] for h in hits})} リポジトリ）" if hits else "使っているリポジトリはありません")
    return EXIT_OK


def _cmd_db_update(args, cfg: dict) -> int:
    """手元の DB で照合するリポジトリを、取り直し付きで 1 回照合する（design.md §5.3）。results/ は書かない"""
    data = data_dir(args.data, cfg["data_dir"])
    found = _scanner(cfg)
    if found is None:
        return EXIT_SCANNER
    exe, ver = found
    targets = _load_targets(args, cfg, data)
    if targets is None:
        return EXIT_USAGE
    _, offline = targetsmod.split_by_privacy(targets, cfg["online_public"])
    try:
        with store.exclusive(data):
            at = store.now()
            out = scanmod.run(offline, data=data, cfg=cfg, exe=exe, scanner_version=ver, at=at, force_db_update=True)
    except store.Busy as e:
        print(e, file=sys.stderr)
        return EXIT_BUSY
    if out.scanner_failed:
        err = next(e.get("error") for e in out.repos.values() if e["status"] == "error")
        print(f"取り直せませんでした: {err}", file=sys.stderr)
        return EXIT_SCANNER
    if out.db_downloaded_at is None:
        print("手元の DB で照合するリポジトリ（lock ファイルのあるもの）がありません。取り直しませんでした")
        return EXIT_OK
    state = store.load_db_state(data)
    print("取り直しました: " + ", ".join(f"{k} {v}" for k, v in state.items() if v == store.iso(at)))
    return EXIT_OK


def _write_packages(data: Path, out, only_id: str | None) -> None:
    """全依存の台帳（design.md §3.4）。--id なら、そのリポジトリの分だけ差し替える"""
    prev = store.load_packages(data) if only_id else None
    repos = dict(prev["repos"]) if prev else {}
    for rid, e in out.repos.items():
        if rid in out.packages:
            repos[rid] = {"scanned_at": e["scanned_at"], "packages": out.packages[rid]}
        else:
            repos.pop(rid, None)  # ok でなくなったものの古い台帳を残さない
    store.write_packages(data, repos)


def _write_scan_results(data: Path, cfg: dict, out, ver: str, at, only_id: str | None) -> None:
    _write_packages(data, out, only_id)
    prev = store.load_latest(data)
    if only_id and prev is not None:
        # latest.json のそのリポジトリだけ差し替える。過去の結果は書かない（design.md §7）
        doc = dict(prev)
        doc["repos"] = {**prev["repos"], **out.repos}
        doc["new"] = [n for n in prev.get("new") or [] if n.get("repo") != only_id] + store.new_findings(prev, out.repos)
        doc["osv_scanner"] = ver
        if out.db_downloaded_at:
            doc["db_downloaded_at"] = out.db_downloaded_at
        store.write_results(data, doc, at, history=False, keep=cfg["keep_results"])
        return
    doc = {
        "format": store.FORMAT,
        "scanned_at": store.iso(at),
        "osv_scanner": ver,
        "db_downloaded_at": out.db_downloaded_at,
        "repos": out.repos,
        "new": store.new_findings(prev, out.repos),
    }
    store.write_results(data, doc, at, history=not only_id, keep=cfg["keep_results"])


def _utf8_when_piped() -> None:
    """コンソールでなく、パイプやファイルに出すときは UTF-8 にする（SessionVault と同じ）。
    日本語の Windows の既定は cp932 で、脆弱性の要約の「—」などを書けずに落ちる。RepoTether も UTF-8 として読む"""
    for stream in (sys.stdout, sys.stderr):
        if stream is not None and hasattr(stream, "reconfigure") and not stream.isatty():
            stream.reconfigure(encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    _utf8_when_piped()
    args = _build_parser().parse_args(argv)
    config_path = Path(args.config) if args.config else default_config_path()
    try:
        cfg = cfgmod.load(config_path)
    except (OSError, ValueError) as e:
        print(f"設定ファイルを読めません: {e}", file=sys.stderr)
        return EXIT_USAGE

    if not args.log:
        return _dispatch(args, config_path, cfg)
    # pythonw では標準出力が捨てられるので、今回の出力をファイルに残す（design.md §7）
    data = data_dir(args.data, cfg["data_dir"])
    data.mkdir(parents=True, exist_ok=True)
    with open(data / "last-run.log", "w", encoding="utf-8", newline="\n") as log, \
            contextlib.redirect_stdout(log), contextlib.redirect_stderr(log):
        print(f"{store.iso(store.now())} lockwatch {' '.join(argv if argv is not None else sys.argv[1:])}")
        try:
            code = _dispatch(args, config_path, cfg)
        except Exception:
            traceback.print_exc()
            code = 1
        print(f"{store.iso(store.now())} 終了コード {code}")
    return code


def _dispatch(args, config_path: Path, cfg: dict) -> int:
    if args.command == "config":
        return _cmd_config(args, config_path, cfg)
    if args.command == "targets":
        return _cmd_targets_check(args, cfg)
    if args.command == "scan":
        return _cmd_scan(args, cfg)
    if args.command == "report":
        return _cmd_report(args, cfg)
    if args.command == "packages":
        return _cmd_packages(args, cfg)
    if args.command == "status":
        return _cmd_status(args, cfg)
    if args.command == "gui":
        from .gui import run  # tkinter は画面を開くときだけ読む
        return run(config_path, args.data, args.targets)
    return _cmd_db_update(args, cfg)


def _cmd_status(args, cfg: dict) -> int:
    data = data_dir(args.data, cfg["data_dir"])
    s = statusmod.collect(cfg, data, targets_path(args.targets, cfg["targets"], data))
    if args.json:
        print(json.dumps(s, ensure_ascii=False, indent=2))
    else:
        print("\n".join(statusmod.lines(s)))
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
