"""lockwatch gui: 状態・結果・台帳・注意・設定の画面（docs/design.md §9）

tkinter で作る（実行時の依存を足さない）。グローバルの CLAUDE.md にある tkinter の落とし穴の対策:
  - タブは選ばれたものがはっきり分かるスタイル（ensure_notebook_style）
  - 下のボタン行は本体より先に side=BOTTOM で置く
  - 絵文字は使わない（起動が約 1 秒遅れ、白黒になる）
照合などの重い仕事は別のプロセス（python -m lockwatch ...）で動かす。排他は CLI のものがそのまま効く。
"""
import os
import queue
import shutil
import subprocess
import sys
import threading
import webbrowser
from pathlib import Path

import tkinter as tk
from tkinter import filedialog, ttk

from . import __version__
from . import config as cfgmod
from . import fold, hygiene, store
from . import packages as pkgmod
from . import status as statusmod
from .paths import app_dir, data_dir, targets_path

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

SEVERITY_LABEL = {"critical": "緊急", "high": "高", "medium": "中", "low": "低", "unknown": "不明"}
INFORMATIONAL_LABEL = {"unmaintained": "保守終了", "unsound": "安全性の欠陥", "notice": "お知らせ"}
MALICIOUS_LABEL = "悪意あるコード"
PACKAGE_ROWS_MAX = 2000   # 台帳のタブに出す行の上限（件数は全部を数える）

# 設定の項目: (キー, 表示名, 種類, 説明)。種類は dir / file / bool / int
CONFIG_FIELDS = [
    ("online_public", "公開リポジトリをオンラインで照合", "bool",
     "切ると、公開リポジトリも手元の脆弱性 DB で照合し、何も外 (api.osv.dev) に送らない。非公開のものはどちらでも外に送らない"),
    ("data_dir", "データの場所", "dir", "空ならこのプログラムの置き場所の data"),
    ("targets", "targets.json の場所", "file", "空ならデータの場所の targets.json (RepoTether がここに書く)"),
    ("osv_scanner", "osv-scanner の場所", "file", "空なら PATH の osv-scanner"),
    ("parallel", "オンラインの並列数", "int", "公開リポジトリをいくつ同時に照合するか"),
    ("db_max_age_days", "手元の DB を取り直す日数", "int", "これより古ければ、照合の前に取り直す"),
    ("cache_max_age_hours", "キャッシュの有効時間 (時間)", "int", "lock ファイルが同じなら、この時間内は前回の結果を使う"),
    ("keep_results", "残す過去の結果の数", "int", "results/ に残す数"),
]


def ensure_notebook_style(name: str = "LockWatch.TNotebook") -> str:
    """選ばれたタブがはっきり分かるスタイル（Windows の vista テーマでは見分けにくいため）。何度呼んでもよい"""
    style = ttk.Style()
    try:
        style.configure(f"{name}.Tab", padding=[14, 6])
        style.map(
            f"{name}.Tab",
            background=[("selected", "#ffffff"), ("!selected", "#e8e8e8")],
            foreground=[("selected", "#000000"), ("!selected", "#757575")],
            font=[("selected", ("", 10, "bold")), ("!selected", ("", 9))],
        )
    except tk.TclError:
        pass
    return name


def result_rows(latest: dict | None, hide: set[str], new_only: bool, text: str) -> list[tuple]:
    """結果のタブの行: (repo, package, version, severity, id, fixed, informational, lockfile)。重い順。
    悪意あるコード（design.md §3.3 の malicious）は、informational の位置に "malicious" を入れる。
    hide は深刻度か知らせの種類。text はリポジトリ・パッケージ・ID の部分一致（大文字小文字を区別しない）"""
    if not latest:
        return []
    new = {(n.get("repo"), n.get("package"), n.get("id")) for n in latest.get("new") or []}
    needle = text.strip().lower()
    order = {s: i for i, s in enumerate(fold.SEVERITIES)}
    rows = []
    for rid, entry in (latest.get("repos") or {}).items():
        for f in (entry or {}).get("findings") or []:
            if fold.hidden(f, hide):
                continue
            if new_only and (rid, f.get("package"), f.get("id")) not in new:
                continue
            if needle and not any(needle in str(x).lower() for x in (rid, f.get("package"), f.get("id"))):
                continue
            rows.append((rid, f.get("package", ""), f.get("version", ""), f.get("severity", "unknown"), f.get("id", ""),
                         ", ".join(f.get("fixed") or []), "malicious" if f.get("malicious") else f.get("informational") or "",
                         f.get("lockfile", "")))
    rows.sort(key=lambda r: (order.get(r[3], 99), r[0], r[1], r[4]))
    return rows


def notice_rows(latest: dict | None, hide: set[str], text: str) -> list[tuple]:
    """注意のタブの行: (repo, kind, package, version, 詳細の文, lockfile)。latest.json の並びのまま。
    hide は種類（design.md §3.5 の kind）。text はどの列でも部分一致（大文字小文字を区別しない）"""
    needle = text.strip().lower()
    rows = []
    for rid, entry in ((latest or {}).get("repos") or {}).items():
        for n in (entry or {}).get("notices") or []:
            if n.get("kind") in hide:
                continue
            row = (rid, n.get("kind", ""), n.get("package", ""), n.get("version", ""), hygiene.describe(n), n.get("lockfile", ""))
            if needle and not any(needle in str(x).lower() for x in row):
                continue
            rows.append(row)
    return rows


def package_rows(inventory: dict, name: str, version: str) -> tuple[list[tuple] | None, int]:
    """台帳のタブの行: ([(package, version, ecosystem, repo, lockfile), ...], リポジトリの数)。
    名前も版も空なら (None, 0)（全件は多すぎるので出さない）。名前は部分一致（* ? を書けば全体の一致）"""
    pattern, ver = pkgmod.contains(name), version.strip() or None
    if pattern is None and ver is None:
        return None, 0
    hits = pkgmod.hits(pkgmod.select(inventory, name=pattern, version=ver))
    return ([(h["package"], h["version"], h["ecosystem"], h["repo"], h["lockfile"]) for h in hits],
            len({h["repo"] for h in hits}))


def status_lines(s: dict) -> list[tuple[str, str]]:
    """状態のタブの (見出し, 中身)"""
    o, latest, task = s["osv_scanner"], s["latest"], s["task"]["registered"]
    return [
        ("LockWatch", s["lockwatch"]),
        ("osv-scanner", f"{o['version']}  ({o['path']})" if o["version"] else f"使えません: {o['error']}"),
        ("データ", s["data_dir"]),
        ("targets.json", f"{s['targets_count']} 件  ({s['targets']})" if s["targets_error"] is None
         else f"{s['targets_error']}  ({s['targets']})"),
        ("最後の照合", f"{latest['scanned_at']}  ({latest['repos']} 件、照合できなかったもの {latest['errors']} 件)" if latest
         else "まだありません"),
        ("手元の脆弱性 DB", ", ".join(f"{k} {v}" for k, v in s["db"].items()) or "まだ取っていません"),
        ("定期実行", {True: f"登録済み (タスク「{s['task']['name']}」)", False: "未登録"}.get(task, "分かりません")),
    ]


def validate(values: dict[str, str]) -> tuple[dict, list[str]]:
    """設定の画面の文字列を、config set と同じ規則で読む。(読めた値, 誤り) を返す"""
    out, errors = {}, []
    for key, label, _, _ in CONFIG_FIELDS:
        try:
            out[key] = cfgmod.set_value({}, key, values.get(key, ""))[key]
        except ValueError as e:
            errors.append(f"{label}: {e}")
    return out, errors


class App:
    def __init__(self, root: tk.Tk, config_path: Path, data_override: str | None, targets_override: str | None):
        self.root = root
        self.config_path = config_path
        self.data_override = data_override
        self.targets_override = targets_override
        self.cfg = cfgmod.load(config_path)
        self.jobs: queue.Queue = queue.Queue()
        self.running = False
        self.latest: dict | None = None
        self.inventory: dict | None = None   # 全依存の台帳（packages.json）

        root.title(f"LockWatch {__version__}")
        root.geometry("1000x640")
        root.minsize(720, 420)

        # 下のステータス行を、本体より先に置く（落とし穴: 本体が場所を食ってフッターが消える）
        bar = ttk.Frame(root)
        bar.pack(side=tk.BOTTOM, fill=tk.X, padx=8, pady=6)
        ttk.Button(bar, text="閉じる", command=self.close).pack(side=tk.RIGHT)
        root.protocol("WM_DELETE_WINDOW", self.close)
        self.message = ttk.Label(bar, text="")
        self.message.pack(side=tk.LEFT, fill=tk.X, expand=True)

        nb = ttk.Notebook(root, style=ensure_notebook_style())
        nb.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=8, pady=(8, 0))
        self.notebook = nb
        self._build_status(nb)
        self._build_results(nb)
        self._build_packages(nb)
        self._build_notices(nb)
        self._build_settings(nb)

        self._after = self.root.after(100, self._poll)
        self.reload()

    def close(self) -> None:
        """予約した処理を取り消し、溜まっている描画を済ませてから閉じる（閉じたあとに走ると Tcl のエラーが出る）"""
        self.root.after_cancel(self._after)
        self.root.update_idletasks()
        self.root.destroy()

    # ---- 場所

    @property
    def data(self) -> Path:
        return data_dir(self.data_override, self.cfg["data_dir"])

    @property
    def targets(self) -> Path:
        return targets_path(self.targets_override, self.cfg["targets"], self.data)

    def _global_args(self) -> list[str]:
        args = ["--config", str(self.config_path)]
        if self.data_override:
            args += ["--data", self.data_override]
        if self.targets_override:
            args += ["--targets", self.targets_override]
        return args

    # ---- 裏の仕事（別スレッド → キュー → 画面のスレッドで受け取る）

    def _run_in_background(self, label: str, work, done) -> None:
        """work() を別スレッドで動かし、終わったら画面のスレッドで done(結果, 例外) を呼ぶ"""
        def body():
            try:
                self.jobs.put((done, work(), None))
            except Exception as e:  # 画面に理由を出す
                self.jobs.put((done, None, e))
        if label:
            self.message.config(text=label)
        threading.Thread(target=body, daemon=True).start()

    def _poll(self) -> None:
        try:
            while True:
                done, result, error = self.jobs.get_nowait()
                done(result, error)
        except queue.Empty:
            pass
        self._after = self.root.after(100, self._poll)

    def run_command(self, label: str, argv: list[str], then=None) -> None:
        """LockWatch のコマンドを別のプロセスで動かし、出力を状態のタブの下に出す。終わったら読み直す。
        then があれば、終了コード 0 のときに呼ぶ"""
        if self.running:
            self.message.config(text="ほかの仕事が終わるまで待ってください")
            return
        self.running = True
        self._set_buttons(False)
        self.output.delete("1.0", tk.END)
        self.output.insert(tk.END, f"> {' '.join(argv)}\n")

        def work():
            p = subprocess.run(argv, capture_output=True, creationflags=_NO_WINDOW, cwd=str(app_dir()))
            text = (p.stdout + p.stderr).decode("utf-8", "replace")
            return p.returncode, text

        def done(result, error):
            self.running = False
            self._set_buttons(True)
            if error:
                self.output.insert(tk.END, f"起動できません: {error}\n")
                self.message.config(text=f"{label}: 起動できません")
                return
            code, text = result
            self.output.insert(tk.END, text + f"\n(終了コード {code})\n")
            self.output.see(tk.END)
            note = {0: "終わりました", 3: "ほかの LockWatch が実行中です", 4: "osv-scanner が失敗しました"}.get(code, "失敗しました")
            self.message.config(text=f"{label}: {note}")
            self.reload()
            if then is not None and code == 0:
                then()

        self._run_in_background(f"{label}…", work, done)

    def lockwatch(self, *args: str) -> list[str]:
        return [sys.executable, "-m", "lockwatch", *self._global_args(), *args]

    # ---- 状態のタブ

    def _build_status(self, nb: ttk.Notebook) -> None:
        tab = ttk.Frame(nb, padding=10)
        nb.add(tab, text="状態")

        buttons = ttk.Frame(tab)
        buttons.pack(side=tk.TOP, fill=tk.X)
        self.buttons = [
            ttk.Button(buttons, text="全体を照合", command=lambda: self.run_command("全体を照合", self.lockwatch("scan"))),
            ttk.Button(buttons, text="DB を取り直す", command=lambda: self.run_command("DB を取り直す", self.lockwatch("db-update"))),
            ttk.Button(buttons, text="定期実行を登録", command=lambda: self.register_task(False)),
            ttk.Button(buttons, text="定期実行を解除", command=lambda: self.register_task(True)),
            ttk.Button(buttons, text="前回のログを開く", command=self.open_log),
            ttk.Button(buttons, text="読み直す", command=self.reload),
        ]
        for b in self.buttons:
            b.pack(side=tk.LEFT, padx=(0, 6))

        self.status_frame = ttk.Frame(tab)
        self.status_frame.pack(side=tk.TOP, fill=tk.X, pady=10)

        ttk.Label(tab, text="動かした仕事の出力").pack(side=tk.TOP, anchor=tk.W)
        out = ttk.Frame(tab)
        out.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        scroll = ttk.Scrollbar(out, orient=tk.VERTICAL)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.output = tk.Text(out, height=8, wrap=tk.WORD, yscrollcommand=scroll.set, font=("Consolas", 9))
        self.output.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.config(command=self.output.yview)

    def _set_buttons(self, enabled: bool) -> None:
        for b in self.buttons:
            b.state(["!disabled"] if enabled else ["disabled"])

    def _show_status(self, s: dict | None, error: Exception | None) -> None:
        for w in self.status_frame.winfo_children():
            w.destroy()
        if error:
            ttk.Label(self.status_frame, text=f"状態を読めません: {error}").grid(row=0, column=0, sticky=tk.W)
            return
        for i, (head, body) in enumerate(status_lines(s)):
            ttk.Label(self.status_frame, text=head, foreground="#555555").grid(row=i, column=0, sticky=tk.NW, padx=(0, 16), pady=2)
            ttk.Label(self.status_frame, text=body, wraplength=760, justify=tk.LEFT).grid(row=i, column=1, sticky=tk.W, pady=2)

    def register_task(self, unregister: bool) -> None:
        shell = shutil.which("pwsh") or shutil.which("powershell")
        if not shell:
            self.message.config(text="PowerShell が見つかりません")
            return
        script = app_dir() / "scripts" / "register-task.ps1"
        argv = [shell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script)]
        if unregister:
            argv.append("-Unregister")
        elif self.data_override:
            argv += ["-Data", self.data_override]
        self.run_command("定期実行を解除" if unregister else "定期実行を登録", argv)

    def open_log(self) -> None:
        log = self.data / "last-run.log"
        if not log.is_file():
            self.message.config(text=f"ログがありません: {log}")
            return
        os.startfile(log)  # noqa: S606  既定のアプリで開く（Windows）

    # ---- 結果のタブ

    def _build_results(self, nb: ttk.Notebook) -> None:
        tab = ttk.Frame(nb, padding=10)
        nb.add(tab, text="結果")

        filters = ttk.Frame(tab)
        filters.pack(side=tk.TOP, fill=tk.X)
        ttk.Label(filters, text="隠す:").pack(side=tk.LEFT)
        self.hide_vars: dict[str, tk.BooleanVar] = {}
        for key, label in [*SEVERITY_LABEL.items(), *INFORMATIONAL_LABEL.items()]:
            v = tk.BooleanVar(value=False)
            self.hide_vars[key] = v
            ttk.Checkbutton(filters, text=label, variable=v, command=self.show_results).pack(side=tk.LEFT, padx=(4, 0))
        self.new_only = tk.BooleanVar(value=False)
        ttk.Checkbutton(filters, text="新しく出たものだけ", variable=self.new_only, command=self.show_results).pack(side=tk.LEFT, padx=(16, 0))
        self.search = tk.StringVar()
        self.search.trace_add("write", lambda *_: self.show_results())
        ttk.Entry(filters, textvariable=self.search, width=24).pack(side=tk.RIGHT)
        ttk.Label(filters, text="絞り込み").pack(side=tk.RIGHT, padx=(0, 4))

        # 件数の行を、表より先に下に置く
        foot = ttk.Frame(tab)
        foot.pack(side=tk.BOTTOM, fill=tk.X, pady=(6, 0))
        self.report_button = ttk.Button(foot, text="診断書を出す", command=self.write_reports)
        self.report_button.pack(side=tk.RIGHT)
        self.buttons.append(self.report_button)
        self.result_count = ttk.Label(foot, text="")
        self.result_count.pack(side=tk.LEFT, anchor=tk.W)

        table = ttk.Frame(tab)
        table.pack(side=tk.TOP, fill=tk.BOTH, expand=True, pady=(8, 0))
        cols = [("repo", "リポジトリ", 230), ("package", "パッケージ", 140), ("version", "版", 80), ("severity", "深刻度", 60),
                ("id", "ID", 150), ("fixed", "直る版", 110), ("info", "知らせ", 80), ("lockfile", "lock ファイル", 150)]
        self.tree = ttk.Treeview(table, columns=[c[0] for c in cols], show="headings")
        for key, label, width in cols:
            self.tree.heading(key, text=label)
            self.tree.column(key, width=width, stretch=key in ("repo", "lockfile"))
        scroll = ttk.Scrollbar(table, orient=tk.VERTICAL, command=self.tree.yview)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.tree.bind("<Double-1>", self.open_vulnerability)

    def show_results(self) -> None:
        hide = {k for k, v in self.hide_vars.items() if v.get()}
        rows = result_rows(self.latest, hide, self.new_only.get(), self.search.get())
        self.tree.delete(*self.tree.get_children())
        for r in rows:
            info = MALICIOUS_LABEL if r[6] == "malicious" else INFORMATIONAL_LABEL.get(r[6], r[6])
            shown = (*r[:3], SEVERITY_LABEL.get(r[3], r[3]), r[4], r[5], info, r[7])
            self.tree.insert("", tk.END, values=shown)
        if self.latest is None:
            self.result_count.config(text=f"結果がまだありません ({self.data / 'results' / 'latest.json'})。「状態」の「全体を照合」で作れます")
        else:
            total = sum(len((e or {}).get("findings") or []) for e in self.latest.get("repos", {}).values())
            self.result_count.config(
                text=f"{len(rows)} 件を表示 (全体 {total} 件)。照合 {self.latest.get('scanned_at')}。行をダブルクリックすると osv.dev で詳しく見られます")

    def report_argv(self) -> list[str]:
        """診断書を書くコマンド。「隠す」で選んだものは --hide で渡す"""
        argv = self.lockwatch("report", "--html")
        for key in sorted(k for k, v in self.hide_vars.items() if v.get()):
            argv += ["--hide", key]
        return argv

    def write_reports(self) -> None:
        index = self.data / "reports" / "index.html"
        self.run_command("診断書を出す", self.report_argv(), then=lambda: os.startfile(index))  # noqa: S606

    def open_vulnerability(self, _event=None) -> None:
        sel = self.tree.selection()
        if sel:
            vid = self.tree.item(sel[0], "values")[4]
            webbrowser.open(f"https://osv.dev/vulnerability/{vid}")

    # ---- 台帳のタブ

    def _build_packages(self, nb: ttk.Notebook) -> None:
        tab = ttk.Frame(nb, padding=10)
        nb.add(tab, text="台帳")

        query = ttk.Frame(tab)
        query.pack(side=tk.TOP, fill=tk.X)
        self.package_name = tk.StringVar()
        self.package_version = tk.StringVar()
        ttk.Label(query, text="パッケージ").pack(side=tk.LEFT)
        ttk.Entry(query, textvariable=self.package_name, width=32).pack(side=tk.LEFT, padx=(4, 16))
        ttk.Label(query, text="版").pack(side=tk.LEFT)
        ttk.Entry(query, textvariable=self.package_version, width=14).pack(side=tk.LEFT, padx=(4, 16))
        ttk.Label(query, text="名前は部分一致 (* ? を書くと全体の一致)。版は同じものだけ").pack(side=tk.LEFT)
        for var in (self.package_name, self.package_version):
            var.trace_add("write", lambda *_: self.show_packages())

        # 件数の行を、表より先に下に置く
        self.package_count = ttk.Label(tab, text="")
        self.package_count.pack(side=tk.BOTTOM, fill=tk.X, pady=(6, 0))

        table = ttk.Frame(tab)
        table.pack(side=tk.TOP, fill=tk.BOTH, expand=True, pady=(8, 0))
        cols = [("package", "パッケージ", 200), ("version", "版", 100), ("ecosystem", "生態系", 80),
                ("repo", "リポジトリ", 280), ("lockfile", "lock ファイル", 200)]
        self.package_tree = ttk.Treeview(table, columns=[c[0] for c in cols], show="headings")
        for key, label, width in cols:
            self.package_tree.heading(key, text=label)
            self.package_tree.column(key, width=width, stretch=key in ("repo", "lockfile"))
        scroll = ttk.Scrollbar(table, orient=tk.VERTICAL, command=self.package_tree.yview)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.package_tree.configure(yscrollcommand=scroll.set)
        self.package_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    def show_packages(self) -> None:
        self.package_tree.delete(*self.package_tree.get_children())
        if self.inventory is None:
            self.package_count.config(text=f"台帳がまだありません ({store.packages_path(self.data)})。「状態」の「全体を照合」で作れます")
            return
        when = pkgmod.scanned(self.inventory["repos"])
        total = sum(len(e.get("packages") or []) for e in self.inventory["repos"].values())
        rows, n_repos = package_rows(self.inventory, self.package_name.get(), self.package_version.get())
        if rows is None:
            self.package_count.config(
                text=f"{len(self.inventory['repos'])} リポジトリ・{total} 件の台帳 (照合 {when})。パッケージの名前か版を入れてください")
            return
        for r in rows[:PACKAGE_ROWS_MAX]:
            self.package_tree.insert("", tk.END, values=r)
        cut = f"。先頭の {PACKAGE_ROWS_MAX} 件だけを表示" if len(rows) > PACKAGE_ROWS_MAX else ""
        found = f"{len(rows)} 件 ({n_repos} リポジトリ){cut}" if rows else "使っているリポジトリはありません"
        self.package_count.config(text=f"{found}。台帳は照合 {when} のもの")

    # ---- 注意のタブ

    def _build_notices(self, nb: ttk.Notebook) -> None:
        tab = ttk.Frame(nb, padding=10)
        nb.add(tab, text="注意")

        filters = ttk.Frame(tab)
        filters.pack(side=tk.TOP, fill=tk.X)
        ttk.Label(filters, text="隠す:").pack(side=tk.LEFT)
        self.notice_hide_vars: dict[str, tk.BooleanVar] = {}
        for key, label in hygiene.KIND_LABEL.items():
            v = tk.BooleanVar(value=False)
            self.notice_hide_vars[key] = v
            ttk.Checkbutton(filters, text=label, variable=v, command=self.show_notices).pack(side=tk.LEFT, padx=(4, 0))
        self.notice_search = tk.StringVar()
        self.notice_search.trace_add("write", lambda *_: self.show_notices())
        ttk.Entry(filters, textvariable=self.notice_search, width=24).pack(side=tk.RIGHT)
        ttk.Label(filters, text="絞り込み").pack(side=tk.RIGHT, padx=(0, 4))

        # 件数の行を、表より先に下に置く
        self.notice_count = ttk.Label(tab, text="")
        self.notice_count.pack(side=tk.BOTTOM, fill=tk.X, pady=(6, 0))

        table = ttk.Frame(tab)
        table.pack(side=tk.TOP, fill=tk.BOTH, expand=True, pady=(8, 0))
        cols = [("repo", "リポジトリ", 220), ("kind", "種類", 130), ("package", "パッケージ", 140), ("version", "版", 70),
                ("detail", "詳細", 260), ("lockfile", "lock ファイル", 140)]
        self.notice_tree = ttk.Treeview(table, columns=[c[0] for c in cols], show="headings")
        for key, label, width in cols:
            self.notice_tree.heading(key, text=label)
            self.notice_tree.column(key, width=width, stretch=key in ("repo", "detail"))
        scroll = ttk.Scrollbar(table, orient=tk.VERTICAL, command=self.notice_tree.yview)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.notice_tree.configure(yscrollcommand=scroll.set)
        self.notice_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    def show_notices(self) -> None:
        hide = {k for k, v in self.notice_hide_vars.items() if v.get()}
        rows = notice_rows(self.latest, hide, self.notice_search.get())
        self.notice_tree.delete(*self.notice_tree.get_children())
        for r in rows:
            self.notice_tree.insert("", tk.END, values=(r[0], hygiene.KIND_LABEL.get(r[1], r[1]), *r[2:]))
        if self.latest is None:
            self.notice_count.config(text="結果がまだありません")
        else:
            total = sum(len((e or {}).get("notices") or []) for e in self.latest.get("repos", {}).values())
            self.notice_count.config(text=f"{len(rows)} 件を表示 (全体 {total} 件)。脆弱性の照合とは別に、lock ファイルを読んで分かったこと")

    # ---- 設定のタブ

    def _build_settings(self, nb: ttk.Notebook) -> None:
        tab = ttk.Frame(nb, padding=10)
        nb.add(tab, text="設定")

        # 保存のボタン行を、項目より先に下に置く
        actions = ttk.Frame(tab)
        actions.pack(side=tk.BOTTOM, fill=tk.X, pady=(8, 0))
        ttk.Button(actions, text="保存", command=self.save_settings).pack(side=tk.RIGHT)
        ttk.Button(actions, text="元に戻す", command=self.fill_settings).pack(side=tk.RIGHT, padx=(0, 6))
        self.settings_message = ttk.Label(actions, text=f"設定ファイル: {self.config_path}", wraplength=640, justify=tk.LEFT)
        self.settings_message.pack(side=tk.LEFT, fill=tk.X, expand=True)

        form = ttk.Frame(tab)
        form.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        form.columnconfigure(1, weight=1)
        self.fields: dict[str, tk.Variable] = {}
        for i, (key, label, kind, note) in enumerate(CONFIG_FIELDS):
            ttk.Label(form, text=label).grid(row=i * 2, column=0, sticky=tk.W, padx=(0, 12), pady=(6, 0))
            if kind == "bool":
                var: tk.Variable = tk.BooleanVar()
                ttk.Checkbutton(form, variable=var).grid(row=i * 2, column=1, sticky=tk.W, pady=(6, 0))
            else:
                var = tk.StringVar()
                ttk.Entry(form, textvariable=var).grid(row=i * 2, column=1, sticky=tk.EW, pady=(6, 0))
                if kind in ("dir", "file"):
                    ttk.Button(form, text="参照", command=lambda k=key, d=kind == "dir": self.pick(k, d)).grid(
                        row=i * 2, column=2, padx=(6, 0), pady=(6, 0))
            self.fields[key] = var
            ttk.Label(form, text=note, foreground="#666666", wraplength=640, justify=tk.LEFT).grid(
                row=i * 2 + 1, column=1, columnspan=2, sticky=tk.W)
        self.fill_settings()

    def fill_settings(self) -> None:
        for key, _, kind, _ in CONFIG_FIELDS:
            v = self.cfg.get(key)
            if kind == "bool":
                self.fields[key].set(bool(v))
            else:
                self.fields[key].set("" if v is None else str(v))

    def pick(self, key: str, directory: bool) -> None:
        current = self.fields[key].get() or None
        p = filedialog.askdirectory(initialdir=current) if directory else filedialog.askopenfilename(initialdir=current and str(Path(current).parent))
        if p:
            self.fields[key].set(p)

    def setting_strings(self) -> dict[str, str]:
        out = {}
        for key, _, kind, _ in CONFIG_FIELDS:
            v = self.fields[key].get()
            out[key] = ("true" if v else "false") if kind == "bool" else str(v).strip()
        return out

    def save_settings(self) -> bool:
        values, errors = validate(self.setting_strings())
        if errors:
            self.settings_message.config(text="保存しませんでした: " + " / ".join(errors))
            return False
        new_cfg = {**self.cfg, **values}  # 知らないキーは残す
        cfgmod.save(self.config_path, new_cfg)
        self.cfg = cfgmod.load(self.config_path)
        self.settings_message.config(text=f"保存しました: {self.config_path}")
        self.reload()
        return True

    # ---- 読み直し

    def reload(self) -> None:
        """状態と結果を読み直す。状態は osv-scanner の --version などで 1 秒ほどかかるので裏で"""
        self.latest = store.load_latest(self.data)
        self.show_results()
        self.show_notices()
        self.inventory = store.load_packages(self.data)
        self.show_packages()
        cfg, data, targets = dict(self.cfg), self.data, self.targets
        self._run_in_background("", lambda: statusmod.collect(cfg, data, targets), self._show_status)


def run(config_path: Path, data_override: str | None = None, targets_override: str | None = None) -> int:
    root = tk.Tk()
    App(root, config_path, data_override, targets_override)
    root.mainloop()
    return 0
