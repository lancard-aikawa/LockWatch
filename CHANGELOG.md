# 変更履歴

<!-- 見出しは `## <版番号>` の形にする。まだ出していない変更は「## 未公開」に書き、リリースのときに版番号へ書き換える -->

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
