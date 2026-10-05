"""診断書（HTML）を作る（docs/design.md §7.1）

latest.json から、リポジトリごとの診断書と一覧（index.html）を作る。照合はし直さない。
1 ファイルで完結させる（CSS は埋め込み、JS・外部の読み込みなし）。OSV から来た文字列はすべてエスケープする。
"""
import hashlib
import html
import json
import os
import re
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

from . import __version__, advice, fold, hygiene, store

GENERATOR = f"LockWatch {__version__}"
_GENERATOR_MARK = '<meta name="generator" content="LockWatch'

SEVERITY_LABEL = {"critical": "緊急", "high": "高", "medium": "中", "low": "低", "unknown": "不明"}
INFORMATIONAL_LABEL = {"unmaintained": "保守終了", "unsound": "安全性の欠陥", "notice": "お知らせ"}
MALICIOUS_LABEL = "悪意あるコード"
VISIBILITY_LABEL = {"public": "公開", "private": "非公開", "unknown": "公開か不明"}
STATUS_LABEL = {"ok": "照合済み", "no-lockfile": "lock ファイルなし", "error": "照合できず"}

_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")


def _e(v) -> str:
    return html.escape("" if v is None else str(v), quote=True)


def visibility_of(entry: dict) -> str:
    """0.2.0 までの latest.json には visibility が無い。オンラインで照合したものは公開と分かる"""
    v = entry.get("visibility")
    if v in VISIBILITY_LABEL:
        return v
    return "public" if entry.get("mode") == "online" else "unknown"


def file_names(ids) -> dict[str, str]:
    """id → ファイル名（拡張子なし）。同じ名前になったら、後のものに id のハッシュを付ける"""
    out: dict[str, str] = {}
    used = {"index"}
    for rid in ids:
        name = _UNSAFE.sub("_", rid).strip("._") or "repo"
        if name.lower() in used:
            name = f"{name}-{hashlib.sha256(rid.encode('utf-8')).hexdigest()[:8]}"
        used.add(name.lower())
        out[rid] = name
    return out


def _time(s) -> str:
    t = store.parse_time(s)
    return t.strftime("%Y-%m-%d %H:%M") if t else "-"


def _sorted(findings: list[dict]) -> list[dict]:
    order = {s: i for i, s in enumerate(fold.SEVERITIES)}
    return sorted(findings, key=lambda f: (order.get(f.get("severity"), 99), -(f.get("score") or 0), f.get("package", ""), f.get("id", "")))


def _counts(findings: list[dict]) -> dict[str, int]:
    n = {s: 0 for s in fold.SEVERITIES}
    for f in findings:
        n[f.get("severity", "unknown")] = n.get(f.get("severity", "unknown"), 0) + 1
    return n


_CSS = """
:root { --fg:#1f2328; --muted:#59636e; --line:#d1d9e0; --bg:#ffffff; --panel:#f6f8fa;
  --critical:#a40e26; --high:#d1242f; --medium:#bc4c00; --low:#9a6700; --unknown:#59636e; --ok:#1a7f37; }
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--fg);
  font: 14px/1.6 "Yu Gothic UI", "Meiryo", "Hiragino Sans", system-ui, sans-serif; }
main { max-width: 1100px; margin: 0 auto; padding: 32px 16px 48px; }
h1 { font-size: 22px; margin: 0 0 4px; }
h2 { font-size: 16px; margin: 32px 0 8px; padding-bottom: 4px; border-bottom: 1px solid var(--line); }
.sub { color: var(--muted); margin: 0 0 16px; }
.notice { border: 1px solid var(--high); background: #fff5f5; color: var(--critical); padding: 8px 12px; border-radius: 6px; margin: 12px 0; }
dl.meta { display: grid; grid-template-columns: max-content 1fr; gap: 2px 16px; margin: 0; }
dl.meta dt { color: var(--muted); }
dl.meta dd { margin: 0; word-break: break-all; }
.tiles { display: flex; flex-wrap: wrap; gap: 8px; margin: 8px 0; }
.tile { border: 1px solid var(--line); border-radius: 6px; padding: 6px 12px; min-width: 84px; background: var(--panel); }
.tile b { display: block; font-size: 20px; }
.tile span { color: var(--muted); font-size: 12px; }
.tile span.sev { color: #fff; }
.scroll { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; font-size: 13px; }
td.path { min-width: 14em; }
th, td { border-bottom: 1px solid var(--line); padding: 6px 8px; text-align: left; vertical-align: top; }
th { background: var(--panel); white-space: nowrap; }
tr { break-inside: avoid; }
td.num { text-align: right; white-space: nowrap; }
.sev { display: inline-block; min-width: 3em; text-align: center; color: #fff; border-radius: 4px; padding: 0 6px; font-weight: bold; }
.sev.critical { background: var(--critical); } .sev.high { background: var(--high); } .sev.medium { background: var(--medium); }
.sev.low { background: var(--low); } .sev.unknown { background: var(--unknown); }
.tag { display: inline-block; border: 1px solid var(--muted); color: var(--muted); border-radius: 4px; padding: 0 4px; font-size: 12px; white-space: nowrap; }
.tag.new { border-color: var(--high); color: var(--high); font-weight: bold; }
.tag.mal { border-color: var(--critical); background: var(--critical); color: #fff; font-weight: bold; }
p.mal { color: var(--critical); font-weight: bold; }
ol.actions { padding-left: 1.6em; }
ol.actions li { margin: 0 0 8px; break-inside: avoid; }
.mono { font-family: Consolas, "BIZ UDGothic", monospace; font-size: 12px; }
.path { word-break: break-all; }
.nowrap { white-space: nowrap; }
.muted { color: var(--muted); }
.ok { color: var(--ok); font-weight: bold; }
a { color: #0969da; }
footer { margin-top: 40px; color: var(--muted); font-size: 12px; }
[hidden] { display: none !important; }
.filters { display: flex; flex-wrap: wrap; gap: 6px 16px; align-items: center; margin: 8px 0; font-size: 13px; }
.filters .group { display: inline-flex; flex-wrap: wrap; gap: 4px 10px; align-items: center; }
.filters label { white-space: nowrap; cursor: pointer; }
.filters input[type=checkbox] { margin: 0 3px 0 0; vertical-align: -2px; }
.filters input[type=search] { font: inherit; padding: 3px 8px; border: 1px solid var(--line); border-radius: 4px; min-width: 14em; }
.shown { color: var(--muted); font-size: 12px; margin: 0 0 4px; }
.shown.filtered { color: var(--high); font-weight: bold; }
th button { all: unset; cursor: pointer; font-weight: bold; }
th button:focus-visible { outline: 2px solid #0969da; outline-offset: 2px; }
th button::after { content: " \\2195"; color: var(--line); }
th[aria-sort=ascending] button::after { content: " \\25B2"; color: var(--fg); }
th[aria-sort=descending] button::after { content: " \\25BC"; color: var(--fg); }
@media print {
  * { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  main { max-width: none; padding: 0; }
  .scroll { overflow: visible; }
  .filters, .shown:not(.filtered) { display: none !important; }
  th button::after { content: none !important; }
  a { color: inherit; text-decoration: none; }
  thead { display: table-header-group; }
}
"""


# 絞り込みと並べ替え（design.md §7.1）。両方のページで同じものを使う。JS が動かなければ絞り込みの欄は出ない（hidden のまま）。
#   絞り込み: input[data-hide=<属性>] の value と行の data-<属性> が同じなら隠す。input[data-only=<属性>] は data-<属性>="1" の行だけ。
#            input[data-text] は行の文字に含むものだけ
#   並べ替え: th[data-sort] のボタン。rank は行の data-rank（深刻度の重さ）、num は数、text は文字の順
_JS = """
(function () {
  var table = document.querySelector("table[data-lw]");
  var panel = document.querySelector(".filters");
  if (!table || !panel) return;
  panel.hidden = false;
  var body = table.tBodies[0];
  var rows = Array.prototype.slice.call(body.rows);
  var shown = document.querySelector("[data-shown]");
  function apply() {
    var hide = {};
    panel.querySelectorAll("input[data-hide]:checked").forEach(function (c) {
      (hide[c.dataset.hide] = hide[c.dataset.hide] || {})[c.value] = true;
    });
    var only = Array.prototype.map.call(panel.querySelectorAll("input[data-only]:checked"), function (c) { return c.dataset.only; });
    var q = panel.querySelector("input[data-text]").value.trim().toLowerCase();
    var n = 0;
    rows.forEach(function (r) {
      var ok = true;
      for (var k in hide) { if (hide[k][r.dataset[k] || ""]) ok = false; }
      only.forEach(function (k) { if (r.dataset[k] !== "1") ok = false; });
      if (ok && q && r.textContent.toLowerCase().indexOf(q) < 0) ok = false;
      r.hidden = !ok;
      if (ok) n++;
    });
    shown.textContent = n + " / 全 " + rows.length + " 件を表示" + (table.querySelector("th[aria-sort]") ? "" : (shown.dataset.order || ""));
    shown.classList.toggle("filtered", n !== rows.length);
  }
  panel.addEventListener("input", apply);
  panel.addEventListener("change", apply);
  var ths = table.tHead.rows[0].cells;
  Array.prototype.forEach.call(ths, function (th, i) {
    var button = th.querySelector("button");
    if (!button) return;
    button.addEventListener("click", function () {
      var dir = th.getAttribute("aria-sort") === "ascending" ? -1 : 1;
      Array.prototype.forEach.call(ths, function (h) { h.removeAttribute("aria-sort"); });
      th.setAttribute("aria-sort", dir === 1 ? "ascending" : "descending");
      var kind = th.dataset.sort;
      var keyed = Array.prototype.map.call(body.rows, function (r, j) {
        var k;
        if (kind === "rank") k = Number(r.dataset.rank);
        else {
          var t = r.cells[i].textContent.trim();
          if (kind === "num") { k = parseFloat(t); if (isNaN(k)) k = -Infinity; } else k = t.toLowerCase();
        }
        return [k, j, r];
      });
      keyed.sort(function (a, b) {
        var c = kind === "text" ? a[0].localeCompare(b[0], "ja") : (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0);
        return c * dir || a[1] - b[1];
      });
      keyed.forEach(function (x) { body.appendChild(x[2]); });
      apply();
    });
  });
  apply();
})();
"""


def _page(title: str, body: str) -> str:
    return (
        "<!doctype html>\n"
        '<html lang="ja">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f'<meta name="generator" content="{_e(GENERATOR)}">\n'
        f"<title>{_e(title)}</title>\n<style>{_CSS}</style>\n</head>\n<body>\n<main>\n{body}\n</main>\n"
        f"<script>{_JS}</script>\n</body>\n</html>\n"
    )


def _filters(groups: list[tuple[str, list[tuple[str, str]]]], only: list[tuple[str, str]], order: str = "") -> str:
    """絞り込みの欄。groups は (属性, [(値, 表示名)]) で「隠す」、only は (属性, 表示名) で「〜だけ」。
    order は最初の並びの説明（並べ替えるまで件数の後ろに出す）"""
    parts = []
    for attr, items in groups:
        if items:
            parts.append('<span class="group"><span class="muted">隠す:</span>' + "".join(
                f'<label><input type="checkbox" data-hide="{_e(attr)}" value="{_e(v)}">{_e(label)}</label>' for v, label in items) + "</span>")
    if only:
        parts.append('<span class="group">' + "".join(
            f'<label><input type="checkbox" data-only="{_e(attr)}">{_e(label)}</label>' for attr, label in only) + "</span>")
    parts.append('<input type="search" data-text placeholder="文字で絞り込み" aria-label="文字で絞り込み">')
    return f'<div class="filters" hidden>{"".join(parts)}</div>\n<p class="shown" data-shown data-order="{_e(order)}"></p>'


def _th(label: str, sort: str, cls: str = "") -> str:
    c = f' class="{cls}"' if cls else ""
    return f'<th data-sort="{sort}"{c}><button type="button">{label}</button></th>'


def _tiles(n: dict[str, int], extra: list[tuple[str, int]]) -> str:
    items = [f'<div class="tile"><b>{n[s]}</b><span class="sev {s}">{SEVERITY_LABEL[s]}</span></div>' for s in fold.SEVERITIES]
    items += [f'<div class="tile"><b>{v}</b><span>{_e(k)}</span></div>' for k, v in extra]
    return f'<div class="tiles">{"".join(items)}</div>'


def _footer(made_at: datetime, n_hidden: int, hide: set[str]) -> str:
    parts = [f"{_e(GENERATOR)} が {_e(made_at.strftime('%Y-%m-%d %H:%M'))} に作成。"
             "脆弱性の情報は OSV（https://osv.dev）による。詳しい説明は ID のリンク先を参照。"]
    if hide:
        labels = "・".join(SEVERITY_LABEL.get(h) or INFORMATIONAL_LABEL.get(h, h) for h in sorted(hide))
        parts.append(f"「{_e(labels)}」の {n_hidden} 件をこの診断書から除いています。")
    return f"<footer>{' '.join(parts)}</footer>"


def render_repo(rid: str, entry: dict, latest: dict, *, new_ids: set[tuple[str, str]], n_hidden: int,
                hide: set[str], made_at: datetime) -> str:
    """1 つのリポジトリの診断書。entry の findings は --hide を当てた後のもの。new_ids は (package, id)"""
    vis = visibility_of(entry)
    status = entry.get("status", "error")
    findings = _sorted(entry.get("findings") or [])
    online = entry.get("mode") == "online"

    meta = [
        ("リポジトリ", f'<span class="mono path">{_e(rid)}</span>'),
        ("公開の区分", _e(VISIBILITY_LABEL[vis])),
        ("照合の方法", "オンライン（api.osv.dev）" if online else "手元の脆弱性 DB（外部に送信していません）"),
        ("照合した時刻", _e(_time(entry.get("scanned_at") or latest.get("scanned_at")))),
        ("osv-scanner", _e(latest.get("osv_scanner") or "-")),
    ]
    if not online:
        meta.append(("脆弱性 DB の取得", _e(_time(latest.get("db_downloaded_at")))))
    meta.append(("状態", _e(STATUS_LABEL.get(status, status))))

    out = [f"<h1>脆弱性診断書</h1>\n<p class=\"sub mono path\">{_e(rid)}</p>"]
    if vis != "public":
        out.append('<div class="notice">非公開のリポジトリの依存の一覧を含みます。社外に出さないでください。</div>')
    out.append('<dl class="meta">' + "".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in meta) + "</dl>")

    if status == "error":
        out.append(f"<h2>照合できませんでした</h2>\n<p class=\"mono\">{_e(entry.get('error') or '理由が記録されていません')}</p>")
    elif status == "no-lockfile":
        out.append("<h2>結果</h2>\n<p>調べる対象の lock ファイルがありませんでした。</p>")
    else:
        n_new = sum(1 for f in findings if (f.get("package"), f.get("id")) in new_ids)
        n_fixed = sum(1 for f in findings if f.get("fixed"))
        n_mal = sum(1 for f in findings if f.get("malicious"))
        out.append("<h2>要約</h2>")
        if n_mal:
            out.append(f'<p class="mal">悪意あるコードとして報告されたパッケージが {n_mal} 件あります。'
                       "その版を入れた環境は、侵害されたものとして扱ってください。</p>")
        if findings:
            out.append(f"<p>{len(findings)} 件の脆弱性・知らせが見つかりました。</p>")
        else:
            out.append('<p class="ok">既知の脆弱性は見つかりませんでした。</p>')
        out.append(_tiles(_counts(findings), [("直る版あり", n_fixed), ("前回から新規", n_new)]))
        acts = advice.actions(findings, entry.get("notices") or [])
        if acts:
            out.append(_actions_section(acts))
        if findings:
            out.append("<h2>見つかったもの</h2>")
            present = {f.get("severity") for f in findings}
            infos = {f.get("informational") for f in findings}
            out.append(_filters(
                [("sev", [(s, SEVERITY_LABEL[s]) for s in fold.SEVERITIES if s in present]),
                 ("info", [(k, v) for k, v in INFORMATIONAL_LABEL.items() if k in infos])],
                [("new", "新規だけ"), ("fixed", "直る版があるものだけ")], "（重い順。見出しを押すと並べ替え）"))
            out.append(_findings_table(findings, new_ids))

    notices = entry.get("notices") or []
    if status == "ok" and notices:
        out.append(f"<h2>lock ファイルの注意</h2>\n<p>脆弱性の照合とは別に、lock ファイルを読んで分かった {len(notices)} 件です。</p>")
        fresh = {store.notice_key(n) for n in latest.get("new_notices") or [] if n.get("repo") == rid}
        out.append(_notices_table(notices, fresh))

    lockfiles = entry.get("lockfiles") or []
    if lockfiles:
        out.append("<h2>調べた lock ファイル</h2>\n<ul>" + "".join(f'<li class="mono path">{_e(p)}</li>' for p in lockfiles) + "</ul>")
    excluded = entry.get("excluded") or []
    if excluded:
        out.append(f"<h2>対象から外した lock ファイル</h2>\n<p>次の {len(excluded)} 個は、ほかの人のコードを取り込んだフォルダの中にあるため、"
                   '調べていません（設定 <span class="mono">exclude_dirs</span>）。</p>\n<ul>'
                   + "".join(f'<li class="mono path">{_e(p)}</li>' for p in excluded) + "</ul>")
    out.append(_footer(made_at, n_hidden, hide))
    if status == "ok":
        out.append(_data_block({
            "format": store.FORMAT, "generator": GENERATOR, "repo": rid, "visibility": vis, "mode": entry.get("mode"),
            "scanned_at": entry.get("scanned_at") or latest.get("scanned_at"),
            "actions": advice.actions(findings, notices), "findings": findings, "notices": notices}))
    return _page(f"脆弱性診断書 {rid}", "\n".join(out))


def _data_block(obj: dict) -> str:
    """機械で読むためのデータ（design.md §7.1）。実行されるスクリプトではない。HTML の中に置くので < は \\u003c にする"""
    text = json.dumps(obj, ensure_ascii=False, indent=1).replace("<", "\\u003c")
    return f'<script type="application/json" id="lockwatch-report">\n{text}\n</script>'


def _pkg(a: dict) -> str:
    name = " ".join(x for x in (a.get("package"), a.get("version")) if x) or "（名前なし）"
    return f'<span class="mono">{_e(name)}</span>'


def _action_item(a: dict) -> str:
    where = f'<span class="muted">（<span class="mono">{_e(a.get("lockfile"))}</span>）</span>'
    kind = a["action"]
    if kind == "remove":
        ids = "、".join(_e(i) for i in a["ids"])
        return (f'<li><span class="tag mal">取り除く</span> {_pkg(a)} を依存から取り除く {where}。悪意あるコードとして報告されています（{ids}）。'
                "すでに入れた環境は、侵害されたものとして扱ってください（鍵やトークンの入れ替えを含む）。</li>")
    if kind == "pin":
        pkgs = "、".join(f'<span class="mono">{_e(p["package"])}{_e(p["spec"])}</span>' for p in a["packages"])
        return (f'<li><span class="tag">版を固定する</span> <span class="mono">{_e(a.get("lockfile"))}</span> の次の {len(a["packages"])} 行を、'
                f'<span class="mono">==</span> で 1 つの版に固定する: {pkgs}。</li>')
    if kind == "upgrade":
        counts = "・".join(f"{SEVERITY_LABEL.get(s, s)} {n}" for s, n in a["severities"].items())
        target = f'<strong class="mono">{_e(a["target"])}</strong>' if a["target"] else ""
        extra = []
        if a["unpinned"]:
            # 版は書かれた下限で、実際に入っている版ではない。「この版から上げる」とは書かない
            name = f'<span class="mono">{_e(a.get("package"))}</span>（書かれた下限は <span class="mono">{_e(a.get("version"))}</span>）'
            head = f"{name}は、実際の版が {target} より古ければ {target} 以上に上げる" if target else f"{name}は、上げる先の版を確かめる"
            extra.append("版が固定されていないので、先に上の「版を固定する」を行い、実際の版を確かめる")
        elif target:
            head = f"{_pkg(a)} を {target} 以上に上げる"
        else:
            head = f"{_pkg(a)} は、上げる先の版を確かめる"
        if a["unclear"]:
            extra.append("直る版を確かめるもの: " + "、".join(_e(i) for i in a["unclear"]))
        if a["unfixed"]:
            extra.append("直る版がまだ無いもの: " + "、".join(_e(i) for i in a["unfixed"]))
        return (f'<li><span class="tag">版を上げる</span> {head} {where}。{a["count"]} 件（{_e(counts)}）'
                + "".join(f"<br><span class=\"muted\">{x}</span>" for x in extra) + "</li>")
    label = hygiene.KIND_LABEL.get(a.get("kind"), a.get("kind"))
    todo = {"not-registry": "取得元が意図したものかを確かめる", "no-integrity": "lock ファイルを作り直してハッシュを入れる",
            "recent": "公開から日が浅いので、様子を見るか前の版に戻す"}.get(a.get("kind"), "確かめる")
    return (f'<li><span class="tag">確かめる</span> {_pkg(a) if a.get("package") else ""} {_e(label)}: {_e(hygiene.describe(a))} {where}。'
            f"{_e(todo)}。</li>")


def _actions_section(acts: list[dict]) -> str:
    """対応の節（design.md §7.1）。指示はすべて見える文字で書く"""
    return (
        '<h2 id="actions">対応</h2>\n'
        "<p>上から順に行ってください。この診断書を、このリポジトリで作業する人や AI（Claude など）に渡せば、ここに書いた内容で直し始められます。"
        "上げる先の版は目安です（新しい版は古い修正も含む、という前提）。上げたあとは動作を確かめ、照合し直してください。"
        '同じ内容を、このファイルの中の <span class="mono">&lt;script type="application/json" id="lockwatch-report"&gt;</span> にも入れています。</p>\n'
        + (PIN_NOTE if any(a["action"] == "pin" for a in acts) else "")
        + '<ol class="actions">\n' + "\n".join(_action_item(a) for a in acts) + "\n</ol>"
    )


# 「版を固定する」が 1 つでもあるときに、一覧の前に 1 回だけ書く
PIN_NOTE = (
    "<p><strong>「版を固定する」について:</strong> 固定する版は、実際に使っている環境で "
    '<span class="mono">pip freeze</span>（uv なら <span class="mono">uv pip freeze</span>）を実行して確かめてください。'
    "<strong>固定するまで、その行のパッケージについてのこの診断書の結果は、実際に入っている版のものではありません</strong>"
    "（書かれた下限の版で照合しているか、照合していません）。固定したあとで照合し直してください。</p>\n"
)


def _findings_table(findings: list[dict], new_ids: set[tuple[str, str]]) -> str:
    rows = []
    for f in findings:
        sev = f.get("severity") if f.get("severity") in SEVERITY_LABEL else "unknown"
        score = f.get("score")
        vid = f.get("id") or ""
        aliases = ", ".join(f.get("aliases") or [])
        tags = []
        if (f.get("package"), vid) in new_ids:
            tags.append('<span class="tag new">新規</span>')
        if f.get("malicious"):
            tags.append(f'<span class="tag mal">{MALICIOUS_LABEL}</span>')
        if f.get("informational"):
            tags.append(f'<span class="tag">{_e(INFORMATIONAL_LABEL.get(f["informational"], f["informational"]))}</span>')
        fixed = ", ".join(f.get("fixed") or [])
        # 深刻度の列の並べ替えの鍵: 重い順、同じ深刻度なら点数の高い順
        rank = fold.SEVERITIES.index(sev) * 1000 + round((10 - (score if isinstance(score, (int, float)) else 0)) * 10)
        is_new = (f.get("package"), vid) in new_ids
        rows.append(
            f'<tr data-sev="{sev}" data-info="{_e(f.get("informational") or "")}" data-new="{int(is_new)}"'
            f' data-fixed="{int(bool(fixed))}" data-rank="{rank}">'
            f'<td><span class="sev {sev}">{SEVERITY_LABEL[sev]}</span></td>'
            f'<td class="num">{_e(f"{score:.1f}") if isinstance(score, (int, float)) else "-"}</td>'
            f'<td class="nowrap"><span class="mono">{_e(f.get("package"))}</span><br><span class="muted mono">{_e(f.get("version"))}</span></td>'
            f'<td class="mono">{_e(fixed) if fixed else "<span class=muted>なし</span>"}</td>'
            f'<td class="nowrap"><a class="mono" href="https://osv.dev/vulnerability/{quote(vid, safe="")}">{_e(vid)}</a>'
            + (f'<br><span class="muted mono">{_e(aliases)}</span>' if aliases else "") + "</td>"
            f'<td>{" ".join(tags)} {_e(f.get("summary"))}</td>'
            f'<td class="mono path">{_e(f.get("lockfile"))}</td>'
            "</tr>"
        )
    head = ("<tr>" + _th("深刻度", "rank") + _th("点数", "num", "num") + _th("パッケージ / 版", "text") + _th("直る版", "text")
            + _th("ID", "text") + _th("概要", "text") + _th("lock ファイル", "text") + "</tr>")
    return _table(head, rows)


def _notices_table(notices: list[dict], fresh: set[tuple] = frozenset()) -> str:
    """lock ファイルの健全性の注意（design.md §3.5）。絞り込みと並べ替えの対象にはしない（data-lw を付けない）。
    fresh は前回から新しく出たもの（store.notice_key）"""
    new_tag = '<span class="tag new">新規</span> '
    rows = [
        f'<tr><td class="nowrap">{new_tag if store.notice_key(n) in fresh else ""}{_e(hygiene.KIND_LABEL.get(n.get("kind"), n.get("kind")))}</td>'
        f'<td class="nowrap"><span class="mono">{_e(n.get("package") or "-")}</span>'
        + (f'<br><span class="muted mono">{_e(n.get("version"))}</span>' if n.get("version") else "") + "</td>"
        f'<td>{_e(hygiene.describe(n))}</td><td class="mono path">{_e(n.get("lockfile"))}</td></tr>'
        for n in notices
    ]
    head = "<tr><th>種類</th><th>パッケージ / 版</th><th>詳細</th><th>lock ファイル</th></tr>"
    return f'<div class="scroll"><table>\n<thead>{head}</thead>\n<tbody>\n' + "\n".join(rows) + "\n</tbody>\n</table></div>"


def _table(head: str, rows: list[str]) -> str:
    """狭い画面では表だけを横にスクロールさせる（ページ全体をはみ出させない）。data-lw は絞り込みと並べ替えの対象の印"""
    return f'<div class="scroll"><table data-lw>\n<thead>{head}</thead>\n<tbody>\n' + "\n".join(rows) + "\n</tbody>\n</table></div>"


def render_index(repos: dict[str, dict], latest: dict, names: dict[str, str], *, n_new: int, n_hidden: int,
                 hide: set[str], made_at: datetime) -> str:
    """全リポジトリの一覧。repos の findings は --hide を当てた後のもの"""
    total = _counts([f for e in repos.values() for f in e.get("findings") or []])
    rows = []
    for rid, e in repos.items():
        n = _counts(e.get("findings") or [])
        status = e.get("status", "error")
        cells = "".join(f'<td class="num">{n[s] or "<span class=muted>0</span>"}</td>' for s in fold.SEVERITIES)
        vis = visibility_of(e)
        rows.append(
            f'<tr data-vis="{vis}" data-has="{int(bool(e.get("findings")))}">'
            f'<td><a class="mono path" href="{_e(quote(names[rid]))}.html">{_e(rid)}</a></td>'
            f"<td>{_e(VISIBILITY_LABEL[vis])}</td><td>{_e(STATUS_LABEL.get(status, status))}</td>{cells}"
            f'<td class="num">{len(e.get("notices") or []) or "<span class=muted>0</span>"}</td></tr>'
        )
    head = ("<tr>" + _th("リポジトリ", "text") + _th("公開の区分", "text") + _th("状態", "text") + "".join(
        _th(f'<span class="sev {s}">{SEVERITY_LABEL[s]}</span>', "num", "num") for s in fold.SEVERITIES)
        + _th("注意", "num", "num") + "</tr>")
    present = {visibility_of(e) for e in repos.values()}
    private = present != {"public"} and bool(present)
    body = [
        "<h1>脆弱性診断書 一覧</h1>",
        f'<p class="sub">{len(repos)} リポジトリ。照合 {_e(_time(latest.get("scanned_at")))}（osv-scanner {_e(latest.get("osv_scanner") or "-")}）</p>',
    ]
    if private:
        body.append('<div class="notice">非公開のリポジトリの依存の一覧を含みます。社外に出さないでください。</div>')
    body += [
        "<h2>全体</h2>",
        _tiles(total, [("前回から新規", n_new)]),
        "<h2>リポジトリ</h2>",
        _filters([("vis", [(v, label) for v, label in VISIBILITY_LABEL.items() if v in present])],
                 [("has", "見つかったものがあるリポジトリだけ")], "（見出しを押すと並べ替え）"),
        _table(head, rows),
        _footer(made_at, n_hidden, hide),
    ]
    return _page("脆弱性診断書 一覧", "\n".join(body))


def write_text(path: Path, text: str) -> None:
    """一時ファイルに書いてから入れ替える"""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    os.replace(tmp, path)


def is_ours(path: Path) -> bool:
    """LockWatch が書いた診断書か（先頭に generator の印がある）"""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return _GENERATOR_MARK in f.read(4096)
    except OSError:
        return False
