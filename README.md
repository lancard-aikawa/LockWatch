# LockWatch

自分のリポジトリ全部の lock ファイルを [osv-scanner](https://github.com/google/osv-scanner) にかけ、
脆弱性を「リポジトリ × パッケージ × 深刻度 × 直る版」の一覧にする CLI。裏で定期的に回し、前回から新しく出たものを知らせる。

- **非公開のリポジトリのパッケージ名は外に出さない。**公開リポジトリだけを api.osv.dev で照合し、非公開と公開か分からないものは
  手元の脆弱性 DB で照合する（通信しないことは確かめてある。[docs/design.md](docs/design.md) §4）
- 脆弱性を探す部分は自作せず osv-scanner に任せる。LockWatch が作るのは、呼び分け・結果の畳み方・キャッシュ・前回との差分
- 対象のリポジトリの一覧（公開・非公開の別つき）は [RepoTether](https://github.com/lancard-aikawa/RepoTether) が渡し、
  結果も RepoTether の画面で見られる。RepoTether が無くても、`--repo` で 1 つずつ調べられる
- Python 標準ライブラリだけで動く。Windows 10 / 11 で使っている（定期実行の登録はタスクスケジューラ）

## 入れ方

1. osv-scanner 2.6.0 を入れる（版を固定する。新しい版で JSON の形が変わることがあるため）

   ```cmd
   winget install --id Google.OSVScanner --version 2.6.0 --exact
   winget pin add --id Google.OSVScanner --version 2.6.0
   ```

2. Python 3.10 以上と [uv](https://docs.astral.sh/uv/) を入れ、このリポジトリを置いて依存を入れる（実行時の依存は無い）

   ```cmd
   git clone https://github.com/lancard-aikawa/LockWatch.git
   cd LockWatch
   uv sync
   ```

3. 動くかを確かめる

   ```cmd
   uv run lockwatch status
   ```

4. RepoTether と使うなら、RepoTether の設定「脆弱性」タブで、このフォルダを指定する。
   RepoTether が更新のたびに `data\targets.json` を書き、結果を詳細パネルに出す

5. 定期実行を登録する（下の「定期実行」）

## 使い方

```cmd
uv run lockwatch scan                         :: targets.json の全部を照合
uv run lockwatch scan --repo C:\Repos\x       :: 1 つだけ（公開か分からないので手元の DB で照合）。結果は書かずに表示する
uv run lockwatch scan --id <id> --check       :: 照合はせず、前回の結果がそのまま返るかを答える
uv run lockwatch report --new                 :: 前回から新しく出たもの
uv run lockwatch report --hide unmaintained   :: 保守されていないだけの知らせを消して表示（重ねて書ける）
uv run lockwatch db-update                    :: 脆弱性 DB を取り直す
uv run lockwatch status                       :: 使える状態か（osv-scanner・受け渡し・最後の照合・定期実行）
uv run lockwatch targets check targets.json   :: 受け渡しのファイルを検査し、オンライン・手元の振り分けを表示
uv run lockwatch config show
```

- 設定はこのフォルダの `lockwatch.json`（無ければ既定値。見本は `lockwatch.sample.json`）。結果などは `data\` に置く
- 手元の脆弱性 DB は初回に取る（使う生態系の分だけ。npm だけで約 200 MB）。その後は 7 日ごとに取り直す
- 結果（`data\results\latest.json`）の形と、RepoTether との受け渡しの約束は [docs/design.md](docs/design.md) §3

## 定期実行

タスクスケジューラに毎日 1 回の scan を登録する。リポジトリの `.venv` の `pythonw.exe` で動くので窓は開かない。
優先度は「通常より低い」。PC が止まっていて逃した回は、次に起動したときに動く。

```cmd
pwsh -File scripts\register-task.ps1                :: 登録（毎日 9:00。-At 13:30 で時刻を変える）
pwsh -File scripts\register-task.ps1 -Unregister    :: 消す
```

結果は `data\last-run.log`（毎回上書き）と、タスクの「前回の実行結果」
（0 = 終わった、1 = LockWatch の誤り、2 = targets.json が無いなど、3 = 実行中、4 = osv-scanner が失敗）で見る。

## 開発

```cmd
uv sync
uv run python -m unittest discover -s tests
```

テストは osv-scanner もネットも使わない（osv-scanner の JSON は `tests/fixtures/` に小さく作ってある）。

## ライセンス

MIT
