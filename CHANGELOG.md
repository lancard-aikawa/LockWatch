# 変更履歴

<!-- 見出しは `## <版番号>` の形にする。まだ出していない変更は「## 未公開」に書き、リリースのときに版番号へ書き換える -->

## 未公開

- 診断書（`report --html`）に「対応」の節を足す。何をどう直すかを、直す順に書く: 悪意あるコードを取り除く、`requirements*.txt` の版を固定する、
  パッケージごとに上げる先の版の目安、残りの注意を確かめる。診断書をそのリポジトリで作業する人や AI（Claude など）に渡せば、これだけで直し始められる。
  同じ内容を、機械で読める JSON（`<script type="application/json" id="lockwatch-report">`）としてもファイルの中に入れる。
  指示はすべて見える文字で書く（AI だけに読ませる隠した文は入れない）
- **Python 3.11 以上が要る**（これまでは 3.10 以上）。`uv.lock` を読むのに標準ライブラリの `tomllib` を使うため
- lock ファイルの健全性の「注意」を足す。脆弱性の照合とは別に lock ファイルそのものを読み、結果のリポジトリごとの `notices` に入れる（通信はしない）。
  `lockwatch report`・診断書・画面の「注意」タブに出る
  - 版を固定していない `requirements*.txt` の行。osv-scanner は `>=1.24.1` を 1.24.1 として照合し、版の指定が無い行は照合せずに 0 件とするため、
    結果が当てにならないことを知らせる
  - レジストリ以外（URL・git）から取るパッケージ（`requirements*.txt`・`package-lock.json`・`npm-shrinkwrap.json`・`uv.lock`）。URL の中の利用者名とパスワードは結果に残さない
  - ハッシュ（`integrity`）の無いパッケージ（`package-lock.json`・`npm-shrinkwrap.json`。古い形式で 20 件を超えるファイルは 1 件にまとめる）
  - 公開から 7 日たっていない版（`uv.lock`）
  - `pnpm-lock.yaml`・`yarn.lock` は見ない
  - 前回から新しく出た注意を、結果の `new_notices` に入れる（脆弱性の `new` とは別）。`scan` と `report` の最後に件数を出し、
    `report --new` で一覧を出す。診断書では「新規」の印、画面の「注意」タブでは「新しく出たものだけ」で絞れる
- 悪意あるコードとして報告されたパッケージ（OSV の `MAL-` の記録）を見分ける。結果の各項目に `malicious` を足し、
  区分も点数も無いものは深刻度を `critical` にする（これまでは `unknown` で、一覧の一番下に沈んでいた）。
  表示では `[malicious]`、画面と診断書では「悪意あるコード」の印を付ける
- 全依存の台帳: 照合のたびに、脆弱性の無いものも含めた全パッケージを `data\results\packages.json` に書く（osv-scanner の `--all-packages`）。
  `lockwatch packages <名前>` で、どのリポジトリがそのパッケージのどの版を使っているかを引ける（`--version`・`--ecosystem`・`--id`・`--json`。名前に `*` `?` を書ける）。
  照合はしないので、侵害された版の知らせが出たときにすぐ確かめられる。台帳は次の照合から作られる（キャッシュは作り直しになる）
  - 画面に「台帳」タブを足す。パッケージの名前（部分一致）と版を入れると、使っているリポジトリと lock ファイルを出す
- `lockwatch report --html`: リポジトリごとの診断書（HTML）と一覧（`index.html`）を `data\reports\` に書く（`--out` で場所を変えられる）。
  社内で渡すためのもの。1 ファイルで完結し、開いても外に通信しない。公開でないリポジトリには「社外に出さないでください」と書く。
  ブラウザの「PDF に保存」でそのまま印刷できる。`--hide` で除いたものは件数を書き添える
  - 診断書と一覧の表は、ブラウザで絞り込める（深刻度・知らせの種類・公開の区分を隠す、新規だけ、直る版があるものだけ、文字）。
    見出しを押すとその列で並べ替える。絞り込んだまま印刷すると、表示している行だけが印刷される
  - 画面の「結果」タブの「診断書を出す」からも作れる（「隠す」の選択を引き継ぎ、終わったら一覧を開く）
- `scripts\lockwatch-gui.cmd`: 画面を開く（ダブルクリックで開ける）
- `run-lockwatch.bat`: リポジトリの直下に置いた、画面を開くための入口（ダブルクリックで開く。`scripts\lockwatch-gui.cmd` を呼ぶだけ）
- 定期実行で黒い窓が開いていたのを直す。uv 0.11 の `.venv\Scripts\pythonw.exe` はコンソール用だったため、
  本体の Python の `pythonw.exe` で `scripts\lockwatch-launch.py` を動かすようにした。**`scripts\register-task.ps1` で登録し直す**
- `scripts\register-task.ps1` と `scripts\lockwatch-gui.cmd` が `.venv` の無い環境で止まっていたのを直す。`scripts\find-pythonw.ps1` が Python 3.10 以上を探す（`.venv`、`uv python find`、`py`、PATH の `python` の順）
- `scripts\register-task.ps1` が Windows PowerShell 5.1（`powershell`）で構文エラーになっていたのを直す（日本語を含む BOM の無い UTF-8 を cp932 として読まれていた）。
  スクリプトは英語だけにした（表示も英語になる）。使い方の例を `pwsh` から `powershell -NoProfile -ExecutionPolicy Bypass -File` に変えた（`pwsh` は入っていない環境がある）
- `lockwatch report --id <id>`: そのリポジトリだけを表示する
- 結果（`latest.json`）のリポジトリごとに `visibility`（公開の区分）を書く
- 直したこと: `report --hide` の「〜件を消しています」が、前回から新しく出たものを 2 回数えていた

## 0.2.0

- 画面（`lockwatch gui`）を足す。`.venv\Scripts\pythonw.exe -m lockwatch gui` で開く（黒い窓は出ない）
  - **状態**: LockWatch・osv-scanner の版、受け渡しのファイル、最後の照合、手元の脆弱性 DB、定期実行の登録。
    全体の照合・DB の取り直し・定期実行の登録 / 解除・前回のログもここから
  - **結果**: 脆弱性の一覧（重い順）。深刻度や「保守終了」などの知らせの種類で隠せる。新しく出たものだけ・文字でも絞れる。
    行をダブルクリックすると osv.dev が開く
  - **設定**: `lockwatch.json` の項目を編集して保存する（`config set` と同じ検査）
- RepoTether 0.7.0 の設定の「脆弱性」タブの「LockWatch を開く」から開ける

## 0.1.0

最初の公開。

- `lockwatch scan`: RepoTether が渡すリポジトリの一覧（`targets.json`）の lock ファイルを osv-scanner 2.6.0 にかけ、結果を `data\results\latest.json` に書く
  - **非公開と、公開か分からないリポジトリは、手元の脆弱性 DB で照合し、パッケージ名を外に出さない**（通信しないことを確かめてある）。
    公開リポジトリだけを api.osv.dev で照合する（`online_public: false` で全部を手元で照合できる）
  - 前回から新しく出たものを `new` に書く。lock ファイルが変わっていなければ、20 時間は前回の結果を使う
  - 深刻度は GitHub の勧告の区分を優先し、無ければ CVSS の点数から。RustSec の「保守終了」などの知らせは種類を付けて残す
  - `--repo <フォルダ>` で 1 つだけ照合する（結果は書かずに表示）。`--id <id>` で一覧のうち 1 つだけ照合し直す
  - `--check` で、照合せずに前回の結果がそのまま返るかを答える。`--no-cache` で前回の結果を使わずに照合し直す
- `lockwatch report`: 結果を表で出す（`--new`、`--json`、`--hide <深刻度や知らせの種類>`）
- `lockwatch db-update`: 手元の脆弱性 DB を取り直す
- `lockwatch status`: 使える状態か（osv-scanner・受け渡し・最後の照合・手元の DB・定期実行）
- `scripts\register-task.ps1`: タスクスケジューラに毎日 1 回の照合を登録する（窓を出さない、優先度を下げる、`--log` で `data\last-run.log` に出力を残す）
