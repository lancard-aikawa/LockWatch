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

2. Python 3.11 以上と [uv](https://docs.astral.sh/uv/) を入れ、このリポジトリを置いて依存を入れる（実行時の依存は無い）

   ```cmd
   git clone https://github.com/lancard-aikawa/LockWatch.git
   cd LockWatch
   uv sync
   ```

   画面（`scripts\lockwatch-gui.cmd`）と定期実行（`scripts\register-task.ps1`）だけなら、`uv sync` をしていなくても動く（Python 3.11 以上と tkinter があればよい）。

3. 動くかを確かめる

   ```cmd
   uv run lockwatch status
   ```

4. RepoTether と使うなら、RepoTether の設定「脆弱性」タブで、このフォルダを指定する。
   RepoTether が更新のたびに `data\targets.json` を書き、結果を詳細パネルに出す

5. 定期実行を登録する（下の「定期実行」）

## 使い方

画面で使うなら:

```cmd
run-lockwatch.bat            :: 状態・結果・台帳・注意・設定の画面（このフォルダの直下。ダブルクリックで開く。黒い窓は残らない）
scripts\lockwatch-gui.cmd    :: 同じもの（run-lockwatch.bat はこれを呼ぶだけ）
```

uv 0.11 が作る `.venv\Scripts\pythonw.exe` はコンソール用の `python.exe` と同じもので、そこから開くと黒い窓も開く。
`lockwatch-gui.cmd` は本体の Python の `pythonw.exe` で `scripts\lockwatch-launch.py` を動かす（`src` を読み込み先に足す）。`scripts\find-pythonw.ps1` が Python 3.11 以上を探す（`.venv` の `home`、`uv python find`、`py`、PATH の `python` の順。venv の中のものは本体に置き換える）。実行時の依存が無いので `.venv` は要らない。

- **状態**: LockWatch・osv-scanner の版、受け渡し、最後の照合、手元の DB、定期実行。全体の照合・DB の取り直し・定期実行の登録 / 解除もここから
- **結果**: 脆弱性の一覧（重い順）。深刻度や「保守終了」などで隠せる。行をダブルクリックすると osv.dev が開く。「診断書を出す」でリポジトリごとの診断書（HTML）を書いて一覧を開く
- **台帳**: どのリポジトリが、そのパッケージのどの版を使っているかを引く（脆弱性の無いものも含めた全依存。名前は部分一致、版は同じものだけ）。照合はしない
- **注意**: lock ファイルそのものを読んで分かったこと（版を固定していない `requirements.txt`、レジストリ以外から取るパッケージ、ハッシュなし、公開直後の版）。種類ごとに隠せる
- **設定**: `lockwatch.json` の項目を編集して保存（`config set` と同じ検査）

RepoTether の設定の「脆弱性」タブの「LockWatch を開く」からも開ける。

コマンドで使うなら:

```cmd
uv run lockwatch scan                         :: targets.json の全部を照合
uv run lockwatch scan --repo C:\Repos\x       :: 1 つだけ（公開か分からないので手元の DB で照合）。結果は書かずに表示する
uv run lockwatch scan --id <id> --check       :: 照合はせず、前回の結果がそのまま返るかを答える
uv run lockwatch report --new                 :: 前回から新しく出たもの
uv run lockwatch report --hide unmaintained   :: 保守されていないだけの知らせを消して表示（重ねて書ける）
uv run lockwatch report --html                :: リポジトリごとの診断書（HTML）を data\reports\ に書く（一覧は index.html。ブラウザで絞り込み・並べ替えができる）
uv run lockwatch packages lodash              :: 全依存の台帳を引く（どのリポジトリが lodash のどの版を使っているか。照合はしない）
uv run lockwatch packages "@babel/*" --version 7.26.0   :: 名前に * ? を書ける。--version・--ecosystem・--id で絞れる。--json でも出せる
uv run lockwatch db-update                    :: 脆弱性 DB を取り直す
uv run lockwatch status                       :: 使える状態か（osv-scanner・受け渡し・最後の照合・定期実行）
uv run lockwatch targets check targets.json   :: 受け渡しのファイルを検査し、オンライン・手元の振り分けを表示
uv run lockwatch config show
```

- 設定はこのフォルダの `lockwatch.json`（無ければ既定値。見本は `lockwatch.sample.json`）。結果などは `data\` に置く
- 手元の脆弱性 DB は初回に取る（使う生態系の分だけ。npm だけで約 200 MB）。その後は 7 日ごとに取り直す
- 脆弱性とは別に、lock ファイルの健全性の「注意」を出す（`lockwatch report`・診断書・画面の「注意」タブ）。とくに、版を `==` で固定していない
  `requirements*.txt` の行は、osv-scanner が書かれた下限の版で照合するか、照合せずに 0 件とするので、その結果は当てにならない。
  ほかに、レジストリ以外（URL・git）から取るパッケージ、ハッシュの無い `package-lock.json`、公開から 7 日たっていない版（`uv.lock`）。
  `pnpm-lock.yaml` と `yarn.lock` は見ない（[docs/design.md](docs/design.md) §3.5）
- 診断書（`report --html`）には「対応」の節がある。何をどう直すか（取り除く・版を固定する・どの版まで上げるか・確かめる）を直す順に書くので、
  そのリポジトリで作業する人や AI（Claude など）に診断書を渡せば、そのまま直し始められる。同じ内容を JSON でもファイルの中に入れている
- 悪意あるコードとして報告されたパッケージ（OSV の `MAL-` の記録）は、深刻度を「緊急」にして `[malicious]`（画面と診断書では「悪意あるコード」）の印を付ける。
  手元の DB にも入っているので、非公開のリポジトリでも検出する
- 照合のたびに、脆弱性の無いものも含めた全依存の台帳（`data\results\packages.json`）を書く。「この版が侵害された」という知らせが出たときに、
  `lockwatch packages <名前> --version <版>` で、使っているリポジトリをその場で引ける。非公開のリポジトリの依存の一覧を含むので、外に出さない
- 結果（`data\results\latest.json`）の形と、RepoTether との受け渡しの約束は [docs/design.md](docs/design.md) §3

## 定期実行

タスクスケジューラに毎日 1 回の scan を登録する。本体の Python の `pythonw.exe` と `scripts\lockwatch-launch.py` で動くので窓は開かない。`scripts\find-pythonw.ps1` が Python 3.11 以上を探す（`.venv` の `home`、`uv python find`、`py`、PATH の `python` の順。venv の中のものは本体に置き換える）。実行時の依存が無いので `.venv` は要らない。
優先度は「通常より低い」。PC が止まっていて逃した回は、次に起動したときに動く。

```cmd
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\register-task.ps1                :: 登録（毎日 9:00。-At 13:30 で時刻を変える）
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\register-task.ps1 -Unregister    :: 消す
```

結果は `data\last-run.log`（毎回上書き）と、タスクの「前回の実行結果」
（0 = 終わった、1 = LockWatch の誤り、2 = targets.json が無いなど、3 = 実行中、4 = osv-scanner が失敗）で見る。

## 開発

```cmd
uv sync
uv run python -m unittest discover -s tests
```

テストは osv-scanner もネットも使わない（osv-scanner の JSON は `tests/fixtures/` に小さく作ってある）。

### リリース

`pyproject.toml` と `src/lockwatch/__init__.py` の版を上げ（`uv lock` で `uv.lock` も）、`CHANGELOG.md` にその版の節を書いてから、
`v<版>` のタグを push する。GitHub Actions が版の一致と CHANGELOG の節を検査し、テストを通してから、
その節と「入れ方・更新の仕方」（`.github/release-intro.md`）を本文にした Release をそのまま公開する（下書きにはしない）。
GitHub のタグのページから Release を作る操作は要らない（作ってしまっても、Actions がそこへ題と本文を入れる）。
本文は `python .github/release_notes.py v<版> dist/release-body.md` で手元でも作れる。

## ライセンス

MIT
