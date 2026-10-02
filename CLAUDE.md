# LockWatch

設計は `docs/design.md` が正。仕様を変えたら先にそちらを直す。

- 実行時の依存は足さない（標準ライブラリだけ）。テストも `unittest`
- ファイルは必ず `encoding="utf-8"` で開く。JSON を書くときは `newline="\n"`、一時ファイルに書いてから `os.replace`
- **private（`visibility` が `public` 以外）を api.osv.dev に送らない。**振り分けは `targets.split_by_privacy` で行い、
  オンラインで osv-scanner を呼ぶ処理は `assert_all_public` を通してから呼ぶ。この 2 つを迂回する呼び出しを書かない
- オフラインで osv-scanner を呼ぶときは `--offline --offline-vulnerabilities --no-resolve` を全部付ける（`--no-resolve` が無いと deps.dev に送られる）
- テストで本物の osv-scanner やネットを使わない。osv-scanner の JSON は `tests/fixtures/` に小さく作って読ませる
- GitHub などのトークンを扱う処理を入れない（それは RepoTether の役目）
- 設定のキーを足したら `config.py` の `DEFAULTS` と `_PARSERS`、`lockwatch.sample.json`、design.md §8 を一緒に直す
- `scripts/*.cmd` を作るときは ASCII だけ・CRLF（cmd は UTF-8 や LF だけのバッチを読み違える）
