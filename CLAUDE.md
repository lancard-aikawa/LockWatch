# LockWatch

設計は `docs/design.md` が正。仕様を変えたら先にそちらを直す。

- 実行時の依存は足さない（標準ライブラリだけ）。テストも `unittest`
- ファイルは必ず `encoding="utf-8"` で開く。JSON を書くときは `newline="\n"`、一時ファイルに書いてから `os.replace`
- **private（`visibility` が `public` 以外）を api.osv.dev に送らない。**振り分けは `targets.split_by_privacy` で行い、
  オンラインで osv-scanner を呼ぶ処理は `assert_all_public` を通してから呼ぶ。この 2 つを迂回する呼び出しを書かない
- オフラインで osv-scanner を呼ぶときは `--offline --offline-vulnerabilities --no-resolve` を全部付ける（`--no-resolve` が無いと deps.dev に送られる）
- テストで本物の osv-scanner やネットを使わない。osv-scanner の JSON は `tests/fixtures/` に小さく作って読ませる
- GitHub などのトークンを扱う処理を入れない（それは RepoTether の役目）
- 設定のキーを足したら `config.py` の `DEFAULTS` と `_PARSERS`、`lockwatch.sample.json`、design.md §8、`gui.py` の `CONFIG_FIELDS` を一緒に直す
  （`tests/test_gui.py` が `CONFIG_FIELDS` の漏れを検査する）
- 画面（`gui.py`）は tkinter。絵文字を使わない、下のボタン行は本体より先に `side=BOTTOM` で置く、タブは `ensure_notebook_style` を使う。
  照合などの重い仕事は画面のスレッドで動かさない（別のプロセスで CLI を呼ぶ）。窓は `App.close` で閉じる（予約した処理を取り消すため）
- `scripts/*.cmd` を作るときは ASCII だけ・CRLF（cmd は UTF-8 や LF だけのバッチを読み違える）
- `scripts/*.ps1` も ASCII だけ・CRLF（コメントもメッセージも英語）。Windows PowerShell 5.1 は BOM の無いファイルを cp932 として読み、
  日本語が化けて構文エラーになる（2026-10-02、別環境で register-task.ps1 が失敗）。`pwsh` は入っていない環境があるので、
  使い方は `powershell -NoProfile -ExecutionPolicy Bypass -File ...` で書き、5.1 で動くものにする。`.cmd` と合わせて `tests/test_scripts.py` が検査する
- **`.venv\Scripts\pythonw.exe` では窓が消えない。**uv 0.11 の venv では `python.exe` と同じコンソール用の起動役で、黒い窓（Windows Terminal のタブ）が開く
  （2026-10-02 確認。PE の subsystem が console）。窓を出さずに動かすときは、`scripts/find-pythonw.ps1` が探す本体の `pythonw.exe` で `scripts/lockwatch-launch.py` を動かす（`lockwatch-gui.cmd`・`register-task.ps1`）。**`.venv` があることを前提にしない**（使う側の PC には無いことがある。2026-10-02 に別環境で失敗）
