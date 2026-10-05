# LockWatch 設計

2026-10-02 時点の案。実装しながら直す。
数字の出どころは、作者の手元の下調べ（osv-scanner の性質の実測、非公開のメモ）。

## 1. 何をするか

自分のリポジトリ全部の依存（lock ファイル）を osv-scanner にかけ、脆弱性を「リポジトリ × パッケージ × 深刻度 × 直る版」の表にする。
裏で定期的に回し、前回から**新しく出たもの**を知らせる。
あわせて、脆弱性の無いものも含めた**全依存の台帳**（どのリポジトリが何のどの版を使っているか）を残す。
「この版が侵害された」という知らせが出た日に、照合し直さずに手元で引くため（§3.4）。

脆弱性を探す部分は自作しない（lock ファイルの健全性の注意 §3.5 だけが例外）。osv-scanner（2.6.0、winget で版固定）に任せ、LockWatch はその周りだけを作る:
対象の受け取り、osv-scanner の呼び分け、結果の畳み方、キャッシュ、前回との差分。

## 2. 役割の分け方

| | RepoTether | LockWatch |
|---|---|---|
| リポジトリの一覧と、公開・非公開 | 持っている。`targets.json` に書く | 読む |
| クローンしていないリポジトリの lock ファイル | トークンで取ってきて、取り込み場所に置く | 置かれたファイルを読む |
| osv-scanner の実行 | — | する |
| キャッシュ・前回との差分・結果 | `results/latest.json` を読んで表示する | 書く |

- **LockWatch は GitHub などのトークンに触れない。**外への通信は、公開リポジトリについての api.osv.dev への問い合わせと、脆弱性 DB の取り直しだけ
- RepoTether は「読むだけ」の方針のまま。書くのは LockWatch の受け渡し場所（`targets.json` と取り込み場所）だけ
- `targets.json` が無くても、`--repo <フォルダ>` で手元のリポジトリを直接渡せる（公開か分からないので private 扱い、§4）

## 3. 受け渡しの形

### 3.1 targets.json（RepoTether → LockWatch）

```json
{
  "format": 1,
  "generated_at": "2026-10-02T09:00:00+09:00",
  "generator": "RepoTether 0.6.0",
  "repos": [
    {
      "id": "github.com/example/web-app",
      "visibility": "public",
      "local_path": "C:/Repos/web-app",
      "fetched_path": null
    },
    {
      "id": "github.com/example/private-app",
      "visibility": "private",
      "local_path": null,
      "fetched_path": "incoming/github.com/example/private-app",
      "fetched_at": "2026-10-02T08:59:58+09:00"
    },
    {
      "id": "local:C:/Repos/work/tool",
      "visibility": "unknown",
      "local_path": "C:/Repos/work/tool",
      "fetched_path": null
    }
  ]
}
```

- `id` はリポジトリを一意に表す文字列。リモートがあれば `<ホスト>/<owner>/<name>`、無ければ `local:<パス>`。結果と差分はこの `id` で突き合わせる
- `visibility` は `public` / `private` / `unknown`。**`public` 以外はすべて private 扱い**（§4）
- `local_path` と `fetched_path` のどちらか一方を持つ。両方あれば `local_path` を使う（手元のものが新しいことが多い）
- `fetched_path` はデータフォルダからの相対パスか絶対パス。中身は元のリポジトリと同じパスで lock ファイルだけを置く
  （osv-scanner はファイル名で形式を決めるので、名前もパスも変えない）
- 知らないキーは無視する（RepoTether が先に新しい項目を書いても壊れない）

RepoTether 側の決め方（RepoTether の `core/lockwatch.rs`）:

- 対象は手元のリポジトリだけ（クローンしていないものを取ってくる処理は、まだ作っていない）。RepoTether で非表示にしたものは入れない
- `id`: 主なリモート（`origin`、無ければ最初のリモート）の `<ホスト>/<owner>/<name>`（小文字）。リモートが無ければ `local:<パス>`（区切りは `/`）。
  同じリモートのクローンが 2 つ以上あれば、パスの順で 2 つ目からは `local:<パス>` にする（`id` の重複は §3.1 の誤り）
- `visibility`: RepoTether が取ったリモート一覧で決める。そのリポジトリのリモートのどれかが一覧で private なら `private`。
  主なリモートが一覧にあって public なら `public`。それ以外（リモートが無い、一覧に無い、一覧をまだ取っていない）は `unknown`
  - **`public` になりうるのは github.com のリポジトリだけ。**Gogs・Gitea・GitHub Enterprise など自前のサーバーは、そこで「公開」でも
    社内などの中での公開なので `private` とみなす（2026-10-02、社内 Gogs の「公開」リポジトリ 13 件が `public` と判定されていたのを照合の前に見つけた）
- 書くのは中身（`repos`）が変わったときだけ。一時ファイルに書いてから入れ替える

### 3.2 取り込み場所（`<data>/incoming/`）

RepoTether がクローンしていないリポジトリの lock ファイルを置く場所。

- RepoTether は tree API（1 リポジトリ 1 回）で lock ファイルのパスと blob の sha を取り、sha が前回と同じなら取り直さない
- 書き方: リポジトリごとに一時フォルダへ全部書いてから、`incoming/<id>` と入れ替える（書きかけを LockWatch に読ませない）
- 対象のファイル名は §5.2 の表と同じにする（LockWatch の `lockfiles.NAMES` を正とする）

### 3.3 結果（LockWatch → RepoTether）

```
<data>/
  results/latest.json            最新の結果（RepoTether はこれを読む）
  results/<YYYYMMDDTHHMMSSZ>.json 過去の結果（差分の元。間引きは設定）
  results/packages.json          全依存の台帳（§3.4。RepoTether は読まない）
  cache/<key>.json               リポジトリごとの osv-scanner の結果を畳んだもの（§6）
  incoming/...                   §3.2
  lock                           実行中の印（§7）
```

`latest.json`:

```json
{
  "format": 1,
  "scanned_at": "2026-10-02T09:01:30+09:00",
  "osv_scanner": "2.6.0",
  "db_downloaded_at": "2026-09-30T03:00:00+09:00",
  "repos": {
    "github.com/example/web-app": {
      "status": "ok",
      "visibility": "public",
      "mode": "online",
      "lockfiles": ["pnpm-lock.yaml", "src-tauri/Cargo.lock"],
      "findings": [
        {
          "lockfile": "pnpm-lock.yaml",
          "ecosystem": "npm",
          "package": "vite",
          "version": "6.0.1",
          "id": "GHSA-xxxx-xxxx-xxxx",
          "aliases": ["CVE-2026-0000"],
          "severity": "high",
          "score": 7.5,
          "fixed": ["6.0.9"],
          "informational": null,
          "malicious": false,
          "summary": "..."
        }
      ]
    }
  },
  "new": [
    {"repo": "github.com/example/web-app", "package": "vite", "id": "GHSA-xxxx-xxxx-xxxx", "severity": "high", "informational": null, "malicious": false}
  ]
}
```

- `status`: `ok` / `no-lockfile`（lock ファイルが無い、または osv-scanner の終了コード 128）/ `error`（理由の文を `error` に入れる。RepoTether はそれを出す）
- `visibility`: `targets.json` の値（`--repo` なら `unknown`）。`mode` だけでは、`online_public: false` のときに公開か非公開かが分からないため（診断書の見出しに使う、§7.1）。
  0.2.0 までの `latest.json` には無い。無ければ `mode` が `online` なら `public`、それ以外は分からないとして扱う
- `mode`: `online` / `offline`（どちらで照合したか。§4 の約束を後から確かめられるように残す）
- `scanned_at`（リポジトリごと）: そのリポジトリを照合した時刻。`scan --id` で 1 つだけ差し替えたときに、ほかと時刻がずれるため
- `findings` は OSV の記録から必要なものだけを抜く。説明文（`details`）・参照（`references`）は入れない
  （そのまま入れると 180 MB になった）。詳しくは `https://osv.dev/vulnerability/<id>` を開けば済む
- 1 件は osv-scanner の `groups` の 1 つ（別名どうしの記録をまとめたもの）。`id` は `groups.ids` の先頭、`aliases` は残りの別名
- `fixed` は、そのパッケージの `affected.ranges` の `fixed` を集めたもの。`GIT` の範囲（値がコミットのハッシュ）は入れない
- `score` は osv-scanner が CVSS から計算した `groups.max_severity`（空なら `null`）
- `severity` は、記録に付いた区分（`database_specific.severity`、GitHub の勧告の `CRITICAL` / `HIGH` / `MODERATE` / `LOW`）を優先する。
  `MODERATE` は `medium`。束の中に複数あれば一番重いもの
- 区分の無いもの（PYSEC・RUSTSEC など）は CVSS の点数から区分する: 9.0 以上 critical、7.0 以上 high、4.0 以上 medium、それ未満 low。どちらも無ければ `unknown`
- 区分と点数がずれるのは両方あるものの 3%（2026-10-01 の `C:\Repos` 全体、3,205 件中 96 件。ほぼ点数の方が 1 段高い）。点数は `score` に残すので、気になれば見比べられる
- `informational`: 脆弱性ではない「知らせ」の種類。RustSec の `affected[].database_specific.informational` の値をそのまま入れる
  （`unmaintained` = 保守されていない、`unsound` = 安全な API でメモリ安全性が崩れうる、`notice` など）。知らせでなければ `null`。
  2026-10-01 の自分のリポジトリ全体では RUSTSEC 67 件中 `unmaintained` 30・`unsound` 13
  - severity は変えない（区分も点数も無ければ `unknown` のまま）。`new` からも外さない
  - 消すかどうかは表示する側が決める（`report --hide`、RepoTether のフィルタ）。`unsound` は実際のバグなので、`unmaintained` と一緒に既定で消さない
- `malicious`: 悪意あるコードの記録か（OpenSSF の malicious-packages。束の `ids` か `aliases` に `MAL-` で始まるものがある）。
  手元の DB にも入っていて、オフラインの照合でも検出する（2026-10-05 確認。npm の DB 23 万件のうち 22 万件が `MAL-`）
  - `MAL-` の記録には区分も点数も無い。`unknown` のままだと一覧の一番下に沈み、`--hide unknown` で消えるので、
    **区分も点数も無い `malicious` は `severity` を `critical` にする**（`score` は `null` のまま。区分か点数があればそちらを使う）
  - 直る版は無いのが普通（その版を入れた時点で実行されている）。表示では「悪意あるコード」の印を付ける。`--hide` の種類には入れない（まとめて消せるものにしない）
  - 0.2.0 までの `latest.json` には無い。無ければ `false` として扱う
- `new` は前回の `latest.json` に無かった `(repo, package, id)` の組。前回が無ければ空（初回にすべてを「新しい」と言わない）。
  各項目にも `severity`・`informational`・`malicious` を入れる（表示する側が `latest.json` を引き直さずにフィルタできるように）。
  リポジトリ単位でも同じで、前回の `latest.json` に無かったリポジトリと、前回 `ok` でなかったリポジトリは比べない
  （対象に足したとき・エラーから戻ったときに、全部を「新しい」と言わない）

### 3.4 全依存の台帳（`results/packages.json`）

```json
{
  "format": 1,
  "repos": {
    "github.com/example/web-app": {
      "scanned_at": "2026-10-02T09:01:30+09:00",
      "packages": [
        ["pnpm-lock.yaml", "npm", "vite", "6.0.1"],
        ["src-tauri/Cargo.lock", "crates.io", "serde", "1.0.210"]
      ]
    }
  }
}
```

- osv-scanner の `--all-packages` が出す、lock ファイルの中の全パッケージ（脆弱性の有無は問わない）。1 件は `[lock ファイル, 生態系, 名前, 版]`。並びはこの 4 つの順で、重複は除く
- 入るのは `status` が `ok` のリポジトリだけ。`scan` が `latest.json` と一緒に書く（`scan --id` はそのリポジトリの分だけ差し替える。`scan --repo` は書かない）
- `latest.json` に入れないのは、大きくなるため（RepoTether が毎回読む。過去の結果にも 30 回分残る）。台帳は最新の 1 つだけで、過去の分は残さない
- 字下げなしで書く（1 件が 1 行に収まらず、字下げすると 5 倍の行数になる）
- 非公開のリポジトリの依存の一覧を含む。データフォルダの外に出さない（`latest.json` と同じ）
- 引くのは `lockwatch packages`（§7）

### 3.5 注意（lock ファイルの健全性、`notices`）

脆弱性の照合とは別に、lock ファイルそのものを読んで分かることを、リポジトリごとの `notices` に入れる。
**ここだけは osv-scanner に任せず自前で読む**（§1 の「自作しない」の例外。osv-scanner は見ないため）。通信はしない。

```json
"notices": [
  {"lockfile": "requirements.txt", "kind": "unpinned", "package": "urllib3", "version": "", "detail": ">=1.24.1"},
  {"lockfile": "package-lock.json", "kind": "not-registry", "package": "left-pad", "version": "1.3.0", "detail": "git+ssh://git@github.com/x/left-pad.git#abc"},
  {"lockfile": "uv.lock", "kind": "recent", "package": "requests", "version": "2.33.0", "detail": "2026-10-03T08:00:00Z"}
]
```

| `kind` | 対象 | 意味 | `detail` |
|---|---|---|---|
| `unpinned` | `requirements*.txt` | 版を `==` で 1 つに固定していない | 書かれている指定（無ければ空） |
| `not-registry` | `requirements*.txt`・`package-lock.json`・`npm-shrinkwrap.json`・`uv.lock` | レジストリ以外（URL・git など）から取る | 取得元（URL の中の利用者名とパスワードは除く） |
| `no-integrity` | `package-lock.json`・`npm-shrinkwrap.json` | レジストリから取るのに、ハッシュ（`integrity`）が無い | 空。まとめたときは件数（下） |
| `recent` | `uv.lock` | 公開から 7 日たっていない版（`hygiene.RECENT_DAYS`） | 公開の時刻（その版のファイルの `upload-time` の一番古いもの） |

- `unpinned` が要る理由: osv-scanner は、固定していない行を黙って不正確に扱う（2026-10-05 確認）。
  `urllib3>=1.24.1`・`django~=2.2.0` は書かれた下限の版（1.24.1・2.2.0）として照合し、実際に入る版より古い版の脆弱性を出す。
  `jinja2`（指定なし）・`flask==1.*` は版が空になり、**照合されずに 0 件になる**。URL・git の行は対象から外される
- `not-registry` の「レジストリ」: npm は `https://registry.npmjs.org/` と `https://registry.yarnpkg.com/`。`uv.lock` は `source` が `git` か `url` のもの。
  手元のフォルダ（`file:`、`link`、`-e ./x`、editable・virtual）は自分のコードなので入れない。社内のレジストリは今は `not-registry` になる（設定で足せるようにするかは §10）
- `no-integrity` が 1 つの lock ファイルで 20 件（`hygiene.NO_INTEGRITY_MAX`）を超えたら、そのファイルで 1 件にまとめる（`package` は空、`detail` に件数）。
  ハッシュを書かない古い形式（npm 4 までの shrinkwrap など）で、パッケージごとに並べても意味が無いため（2026-10-05、手元の 1 ファイルから 577 件出た）
- `recent` は、手元の cooldown（uv の `exclude-newer`）が効いている PC で作った lock ファイルでは出ない。別の PC や他の人が作った lock ファイルの見張り
- 読めるものだけ読む: `pnpm-lock.yaml`・`yarn.lock` は見ない（標準ライブラリに YAML の読み手が無い）。壊れていて読めないファイルは飛ばす（照合の側で osv-scanner が失敗する）
- 入れるのは `status` が `ok` のリポジトリだけ（ほかは空）。**キャッシュには入れず、照合のたびに読み直す**（`recent` は日がたつと消えるため。読むだけなので速い）
- 前回から新しく出た注意は、`latest.json` の `new_notices` に入れる（脆弱性の `new` とは別の配列。`new` の形は変えない）:
  `[{"repo", "lockfile", "kind", "package", "version"}, ...]`。前回の `latest.json` に無かった `(repo, lockfile, kind, package, version)` の組
  - 比べ方は `new` と同じ: 前回が無ければ空。前回 `ok` でなかったリポジトリは比べない。加えて、前回の結果に `notices` が無い
    （注意を入れる前の版で書いた）リポジトリも比べない（初回にすべてを「新しい」と言わない）
  - `scan --id` はそのリポジトリの分だけ入れ替える
  - 見張りとして入れた `not-registry`・`recent` は、新しく現れたことに気づけなければ意味が無いため
- `--hide` は効かない
- 並びは lock ファイル・`kind`・名前・版の順
- 0.2.0 までの `latest.json` には無い。無ければ空として扱う

## 4. private は外に送らない

**`visibility` が `public` のリポジトリだけを、オンライン（api.osv.dev）で照合する。**
`private` と `unknown` は、手元の DB（`--offline --offline-vulnerabilities`）で照合する。パッケージ名と版を外に出さない。

- この振り分けは**コードで保証する**（`targets.split_by_privacy`）。オンラインで osv-scanner を呼ぶ関数は、
  `public` 以外が 1 つでも混ざっていたら呼ぶ前に例外にする。設定やプロンプトの約束に頼らない
- `--repo` で直接渡したリポジトリは公開か分からないので `unknown`（= オフライン）
- 設定 `online_public: false` で、公開のものもオフラインにできる（全部手元で照合）
- 手元の DB で照合するには DB が要る。DB の取得（`--download-offline-databases`）は生態系ごとの zip を取るだけで、パッケージ名は送らない
- `--offline --offline-vulnerabilities --no-resolve`（取り直しなし）で**通信しないことを確かめた**（2026-10-02、RESULTS.md §7）。
  npm・crates.io・PyPI・Go の lock ファイルを 1 回で照合する 15 秒の間、osv-scanner と子プロセスの TCP/UDP の接続は 0、
  プロキシ（`HTTPS_PROXY`）の罠への接続も 0。同じ見張りで、オンラインの照合と DB の取り直しの通信は検出できた（見張りが効いている対照）
  - 確かめていないこと: Go 本体が入っている環境（この環境には無いので、Go の呼び出し解析が動かない）。名前解決（DNS）は Windows の DNS クライアントのサービスが行うので、プロセスごとには見えない（ただし続く接続は無い）

## 5. osv-scanner の呼び方

### 5.1 決まりごと

- 必ず `--no-resolve`。付けないと 6 倍遅く、増えるのは推移依存を外部（deps.dev）で解決した分。
  **private で付け忘れると、deps.dev にパッケージ名が送られる**ので、オフラインの呼び出しでは必ず付ける
- `--format json --output-file <一時ファイル>`。標準出力は使わない
- `--all-packages`（脆弱性の無いパッケージも JSON に出す。全依存の台帳 §3.4 の元）。出力に載せるものが増えるだけで、
  オフラインでもそのまま動く（2026-10-05 確認。脆弱性の無いパッケージは `package` だけを持ち、`groups` と `vulnerabilities` が無い）
- フォルダ（`-r`）ではなく、LockWatch が数えた lock ファイルを `-L <絶対パス>` で 1 つずつ渡す（§5.2）。
  キャッシュの鍵（§6）と osv-scanner が読むものを一致させるため（フォルダで渡すと `pom.xml` なども読む）。
  `requirements-dev.txt` のような名前も `-L` で読める（2026-10-02 確認）
- 終了コード: 0 = 無し、1 = 脆弱性あり（どちらも成功）、128 = 調べるものが無い（中身が空の lock ファイルだけ、など。出力ファイルは作られない）、それ以外（127 など）= 失敗
- 除外（`--experimental-exclude`）は使わない。対象は `targets.json` で絞る（フォルダ名だけの書き方は効かず、2 つのドライブで失敗した）
- 公開: リポジトリごとに 1 回（並列数は設定、既定 4）。1 つ 2〜4 秒
- private: まとめて 1 回（`-L` を並べる）。DB の読み込み（約 10 秒）が 1 回で済む。結果は `source.path`（絶対パス、区切りは `/`）でリポジトリに振り分ける。
  この 1 回が失敗したら、まとめたリポジトリ全部を `error` にする
- 窓を出さない（Windows では `CREATE_NO_WINDOW` で起動する）
- osv-scanner の場所は設定 `osv_scanner`（空なら PATH）。起動時に `--version` を読み、結果に残す

### 5.2 lock ファイルの名前

`package-lock.json` `npm-shrinkwrap.json` `pnpm-lock.yaml` `yarn.lock` `bun.lock`
`uv.lock` `poetry.lock` `Pipfile.lock` `pdm.lock` `requirements*.txt`
`Cargo.lock` `pubspec.lock` `composer.lock` `Gemfile.lock` `go.mod`

- 手元のリポジトリでは `git ls-files` に出るもの（git が管理しているもの）だけを数える。osv-scanner も `.gitignore` を尊重するので、数え方をそろえる。
  git のリポジトリでないフォルダ（`--repo` で渡したものなど）と取り込み場所（§3.2）は、フォルダを歩いて数える（`node_modules`・`.venv` など、`.` で始まるフォルダは入らない）
- lock ファイルが 1 つも無いリポジトリは osv-scanner を呼ばずに `no-lockfile`

### 5.3 脆弱性 DB

- 置き場所は osv-scanner が決める（`%LOCALAPPDATA%\osv-scalibr\<生態系>\all.zip`、全部で約 470 MB）
- `--download-offline-databases` は、**その回に読んだパッケージの生態系の分だけ**取る（PyPI 1 つで約 30 秒。2026-10-02 確認）。
  `--offline` と一緒に付けても取れる。なので取り直しは、private の照合の呼び出しにこのフラグを足して行う（別の呼び出しにしない）
- 生態系は lock ファイルの名前で決まる（`lockfiles.ECOSYSTEMS`）。生態系ごとに最後に取った時刻を `<data>/db.json` に残す:
  `{"format": 1, "ecosystems": {"npm": "2026-10-02T09:00:00+09:00", ...}}`
- 照合に要る生態系のどれかが、まだ取っていないか、設定 `db_max_age_days`（既定 7）を過ぎていたら、その回で取り直す
  （新しい生態系の lock ファイルが増えたときに、DB の無いまま照合しない）
- 取り直しは `lockwatch db-update` で単独でも行える（private の照合を、取り直し付きで 1 回走らせる）

## 6. キャッシュ

- 鍵: リポジトリの `id` ＋ lock ファイルの（パス, SHA-256）の並び ＋ 照合の方法（online / offline）＋ osv-scanner の版 ＋ 畳み方の版（`fold.SHAPE`。畳み方を変えたら上げる）
- 有効期限: 設定 `cache_max_age_hours`（既定 20）。脆弱性の情報は日々増えるので、毎日の定期実行では取り直しになる。
  キャッシュが効くのは、RepoTether の「今すぐ調べる」で同じ日に何度も呼ばれたとき。
  ただし押した人には「照合し直したのに時刻が変わらない」と見えるので、RepoTether は先に `scan --check` で確かめ、
  キャッシュが効くときは照合し直すかを選ばせる（§7）
- オフラインの照合は、そのリポジトリの生態系の DB の取得時刻も鍵に入れる（DB を取り直したら照合し直す）
- 中身は findings と、そのリポジトリの全パッケージ（§3.4 の `packages`）
- 残すのは `ok` だけ。ファイル名は鍵の SHA-256。期限を過ぎたものは `scan` の終わりに消す

## 7. 実行

| コマンド | 動き |
|---|---|
| `lockwatch scan` | `targets.json` の全部を照合し、`results/` を書く |
| `lockwatch scan --repo <フォルダ>` | そのリポジトリだけ（`unknown` 扱い）。`results/` は書かず、結果を表示する |
| `lockwatch scan --id <id>` | `targets.json` のうちその 1 つ。`latest.json` のそのリポジトリだけ差し替える（`new` もそのリポジトリの分だけ入れ替える。過去の結果は書かない） |
| `lockwatch scan --id <id> --check` | 事前チェック。照合はせず、今照合したら前回の結果（キャッシュ）がそのまま返るかを JSON で答える（`--repo` とも使える。読むだけなので排他は取らない） |
| `lockwatch scan --no-cache` | キャッシュを読まずに照合し直す（書くのはいつもどおり）。`--id` / `--repo` とも使える |
| `lockwatch report` | `latest.json` を表にして表示（`--new` で新しいものだけ、`--json`。`--hide <種類>` を重ねて消す: `unmaintained` などの `informational` の値か、`low` などの `severity` の値。`--id <id>` でそのリポジトリだけ） |
| `lockwatch report --html` | リポジトリごとの診断書（HTML）を書く（§7.1） |
| `lockwatch packages [<名前>]` | 全依存の台帳（§3.4）を引く。照合はしない |
| `lockwatch status` | 使える状態かを表示する（`--json`）。LockWatch の版、osv-scanner の場所と版（`--version` だけ呼ぶ）、データと targets.json の場所と件数、最後の照合、手元の DB の取得時刻、定期実行（タスク「LockWatch scan」）が登録されているか。RepoTether の設定の「確かめる」が使う |
| `lockwatch db-update` | 脆弱性 DB を取り直す。手元の DB で照合するリポジトリ（§4）を、取り直し付きで 1 回照合する。結果はキャッシュにだけ入れ、`results/` は書かない |
| `lockwatch config show / set` | 設定（SessionVault と同じ作り） |

- `scan --check` の答え: `{"id", "mode", "cached", "scanned_at", "lockfiles", "reason"}`（`error` のときは `error` も）。
  `reason` は `cached`（前回の結果がそのまま返る。`scanned_at` はその照合の時刻）/ `no-cache`（lock ファイルが変わった・期限切れ・まだ照合していない）/
  `db-update`（手元の DB を取り直してから照合する）/ `no-lockfile` / `error`。
  RepoTether の「今すぐ調べる」はこれを先に呼び、`cached` なら照合せずに「前回から変わっていない」と出して、照合し直すか（`--no-cache`）を選ばせる
- `report`:
  - `--hide` に書けるのは `critical` `high` `medium` `low` `unknown` と `unmaintained` `unsound` `notice`（書き間違いで何も消えないのを防ぐため、これ以外は引数の誤り）。
    消した件数は表示の最後に出す（消したことを忘れない）
  - 表は、リポジトリごとに 1 行（状態・件数）と、その下に重い順の findings、続けて注意（§3.5）。`--new` は `new` の一覧だけ
  - `--json` は `latest.json` と同じ形で、`--hide` を当てた後のもの。`--new` と一緒なら `new` の配列だけ（形を変えないため、`new_notices` は入れない）
  - `--new` と最後の行には、新しく出た注意（`new_notices`）も出す
  - `--id` はそのリポジトリだけにする（`new` もそのリポジトリの分だけ）。`latest.json` に無ければ終了コード 2
  - `latest.json` がまだ無ければ、その旨を出して終了コード 2
- `packages`:
  - `<名前>` があれば、その名前のパッケージを使っているところを「リポジトリ・版・生態系・lock ファイル」で出す。
    大文字小文字は区別しない。`*` `?` を書ける（`@babel/*`）。PyPI の名前の `-` `_` `.` の違いはそろえない
  - `--version <版>`（その版だけ。文字どおりの一致）、`--ecosystem <生態系>`（`npm` `PyPI` `crates.io` など。大文字小文字は区別しない）、`--id <id>`（そのリポジトリだけ）で絞る
  - `<名前>` が無ければ、リポジトリごとの件数だけを出す（絞り込みは効く）
  - `--json`: `<名前>` があれば `[{"repo", "lockfile", "ecosystem", "package", "version"}, ...]`、無ければ `packages.json` と同じ形（絞り込んだ後のもの）
  - 見つからなくても終了コードは 0（「使っていない」は答えの 1 つ）。`packages.json` がまだ無ければ、その旨を出して終了コード 2
  - 台帳は最後に照合したときのもの。照合した時刻を一緒に出す（lock ファイルをその後に変えていれば、照合し直すまで反映されない）
- 同時に 2 つ走らせない。`<data>/lock` を OS のファイルロック（Windows は `msvcrt.locking`）で押さえ、取れなければ「実行中」で終わる（終了コード 3）。
  ファイルがあるだけでは実行中としない（落ちたあとに残ったファイルで止まらないように）
- 終了コード: 0 = 終わった（脆弱性の有無は問わない）、1 = 想定外の失敗（LockWatch の誤り。`--log` なら例外の内容を書く）、2 = 引数の誤り、3 = 実行中、4 = osv-scanner が無い・失敗した
  （1 回でも失敗したら 4。結果はそれでも書き、失敗したリポジトリは `error` にする。フォルダが無いだけの `error` は 0）
- 定期実行はタスクスケジューラで 1 日 1 回（`scripts/register-task.ps1`。SessionVault と同じ作り）
  - `<home>\pythonw.exe scripts\lockwatch-launch.py --log scan` を、既定で毎日 9:00 に（`<home>\pythonw.exe` は `scripts\find-pythonw.ps1` が探す Python 3.11 以上の本体の `pythonw.exe`。順に `.venv\pyvenv.cfg` の `home`、`uv python find`、`py`、PATH の `python`。venv の中のものは `sys.base_prefix` の本体に置き換える。`.venv` が無くても動く。
    uv 0.11 の `.venv\Scripts\pythonw.exe` はコンソール用で黒い窓が開くため、使わない。`lockwatch-launch.py` が `src` を読み込み先に足す）。止まっていて逃した回は、次に起動したときに動かす
  - 窓を出さない（`pythonw`、osv-scanner は `CREATE_NO_WINDOW`）。優先度は 7（通常より低い。子の osv-scanner も引き継ぐ）
  - ログオンしているときだけ動かす（パスワードを預けない）。ネットにつながっていないときは動かさない（公開のものの照合が失敗するため）
  - 同時に 2 つは動かさない（タスクの設定と §7 の排他の両方）。1 回は 1 時間まで（DB の取り直しが重なっても足りる）
  - `--log`（どのサブコマンドにも付く）: 今回の出力（標準出力と標準エラー）を `<data>/last-run.log` に書く（毎回上書き）。
    `pythonw` では出力が捨てられるため。結果は `last-run.log` と、タスクの「前回の実行結果」（終了コード、上の表）で見る

### 7.1 診断書（`report --html`）

社内でほかの人に渡すための成果物。`latest.json` から作り、照合し直さない。

- 書く場所: `--out <フォルダ>`、無ければ `<data>/reports/`。リポジトリごとに `<名前>.html` と、一覧の `index.html`
  - `<名前>` は `id` の英数字と `.` `_` `-` 以外を `_` にしたもの（`github.com/example/web-app` → `github.com_example_web-app`）。
    2 つの `id` が同じ名前になったら、後のものに `-<id の SHA-256 の先頭 8 桁>` を付ける
  - `--id <id>` ならそのリポジトリの 1 つだけを書き、`index.html` は書き直さない
  - 全部を書くときは、前に LockWatch が書いた診断書（`<meta name="generator" content="LockWatch ...">` の入った `.html`）のうち、
    今回書かなかったものを消す（対象から外したリポジトリの古い診断書を残さない）。それ以外のファイルには触れない
  - 1 つずつ一時ファイルに書いてから入れ替える
- `--hide` はそのまま効く（消した件数を診断書に書く）。`--json` / `--new` とは一緒に使えない（引数の誤り）
- 1 ファイルで完結させる: CSS と JS は埋め込み、外部の JS・CSS・フォント・画像は読み込まない。開いても外に通信しない（リンクを押したときだけ osv.dev を開く）
- 表の絞り込みと並べ替え（埋め込みの JS。JS が動かなくても表はすべて読め、絞り込みの欄は出さない）:
  - 診断書: 深刻度・知らせの種類ごとに「隠す」、「新規だけ」「直る版があるものだけ」、文字で絞り込み（画面の結果のタブと同じ考え方）
  - 一覧: 公開の区分ごとに「隠す」、「見つかったものがあるリポジトリだけ」、文字で絞り込み
  - 見出しを押すとその列で並べ替える（押すたびに昇順・降順。深刻度の列は重さの順、点数と件数の列は数の順）
  - 表示している件数を「n / 全 m 件」で出す。絞り込んだまま印刷すると、表示している行だけが印刷され、その件数も印刷される（絞り込みの欄は印刷しない）
- OSV から来た文字列（`summary`・パッケージ名・版など）はすべてエスケープする
- 中身:
  1. 見出し: リポジトリの `id`、公開の区分、照合の方法（オンライン = api.osv.dev / 手元の DB）、照合した時刻、osv-scanner の版、
     手元の DB の取得時刻（手元の DB で照合したときだけ）、診断書を作った時刻と LockWatch の版
  2. 公開でないリポジトリには「非公開のリポジトリの依存の一覧を含みます。社外に出さないでください」と書く
  3. 要約: 深刻度ごとの件数、直る版があるものの件数、前回から新しく出たものの件数
  4. findings の表（重い順）: 深刻度・点数・パッケージ・版・直る版・ID（osv.dev へのリンク）と別名・要約・知らせの種類・lock ファイル・新規の印。
     悪意あるコード（`malicious`）には印を付け、1 件でもあれば要約の最初に件数を書く
  5. 注意（§3.5）の表: 種類・パッケージ・版・詳細・lock ファイル。新しく出たもの（`new_notices`）には新規の印。1 件も無ければ出さない。一覧（`index.html`）には件数の列を出す
  6. 調べた lock ファイルの一覧
  7. `no-lockfile` / `error` のときは、その状態と理由だけ
- 説明文（`details`）は載せない（`latest.json` に無い、§3.3）。詳しくは ID のリンク先で見る
- 印刷（ブラウザの「PDF に保存」）でそのまま渡せる形にする（深刻度の色を印刷でも残す、表の行を途中で切らない）

## 8. 設定（`<app>/lockwatch.json`）

SessionVault と同じく、プログラムの置き場所（exe ならそのフォルダ、リポジトリから動かすならリポジトリ直下）に置く。

```json
{
  "data_dir": null,
  "targets": null,
  "osv_scanner": null,
  "online_public": true,
  "parallel": 4,
  "db_max_age_days": 7,
  "cache_max_age_hours": 20,
  "keep_results": 30
}
```

- `data_dir`: 空なら `<app>/data`
- `targets`: 空なら `<data>/targets.json`
- `keep_results`: `results/` に残す過去の結果の数

## 9. 画面（`lockwatch gui`）

設定の編集・状態の確認・結果の閲覧・台帳の検索を 1 つの窓でできるようにする。RepoTether の設定の「脆弱性」タブの「LockWatch を開く」からも開く。

- tkinter で作る（実行時の依存を足さない）。`scripts\lockwatch-gui.cmd` で開けば黒い窓は出ない（§7 と同じく本体の `pythonw.exe` と `lockwatch-launch.py` を使う）
- tkinter の落とし穴の対策（グローバルの CLAUDE.md）: タブは選ばれたものがはっきり分かるスタイル、下のボタン行は本体より先に `side=BOTTOM` で置く、絵文字は使わない
- 照合などの重い仕事は、画面とは別の LockWatch のプロセス（`python -m lockwatch scan` など。同じ `--config` / `--data`）で動かし、
  終わったら状態と結果を読み直す。排他（§7）は CLI のものがそのまま効く（定期実行と重なれば「実行中」と出る）

| タブ | 中身 |
|---|---|
| 状態 | `status` の内容。ボタン: 全体を照合（`scan`）・DB を取り直す（`db-update`）・定期実行を登録 / 解除（`scripts/register-task.ps1`）・前回のログを開く（`last-run.log`）。動かした仕事の出力を下に出す |
| 結果 | `latest.json` の一覧（リポジトリ・パッケージ・版・深刻度・ID・直る版・知らせの種類・lock ファイル）。重い順。悪意あるコード（`malicious`）は知らせの列に「悪意あるコード」と出す。「隠す」（深刻度・知らせの種類）、「新しく出たものだけ」、文字で絞り込み。行をダブルクリックすると `https://osv.dev/vulnerability/<id>` を開く |
| 台帳 | 全依存の台帳（`packages.json`、§3.4）を引く。名前と版を入れると、使っているところを「パッケージ・版・生態系・リポジトリ・lock ファイル」で出す。名前は大文字小文字を区別しない部分一致（`*` `?` を書いたときは、`lockwatch packages` と同じく全体の一致）。版は文字どおりの一致。名前も版も空なら何も出さない（全件は多すぎる）。出すのは先頭 2,000 行までで、件数は全部を数える。照合はしない |
| 注意 | `latest.json` の注意（§3.5）の一覧（リポジトリ・種類・パッケージ・版・詳細・lock ファイル）。種類ごとに「隠す」、「新しく出たものだけ」、文字で絞り込み |
| 設定 | §8 の項目を編集して保存する。値は `config set` と同じ規則で検査し、誤りがあれば保存しない。`online_public` には、切ると何も外に送らないことを書き添える。保存は `config.save`（一時ファイルから入れ替え） |

- 画面を開いているあいだに定期実行が結果を書いても、自動では読み直さない（「読み直す」ボタン）
- 結果のタブの「診断書を出す」: `report --html` を別のプロセスで動かし（「隠す」で選んだものは `--hide` で渡す）、終わったら `index.html` を開く

## 10. 決めていないこと

- RepoTether に画面なしで動く入口を作るか（クローンしていないリポジトリの lock ファイルを、RepoTether を開いていない時間にも取るため）
- PkgUpdater の Audit（lock の無いプロジェクトの直接依存）の結果を、同じ表に入れるか
- 所属する組織のリポジトリを対象に入れるか（入れても private なのでオフライン）
- 新しく出たものの知らせ方（RepoTether の表示だけか、Windows の通知も出すか）
- Gogs で木の一覧を再帰的に取れるか（RepoTether 側の話）
- 注意（§3.5）: 社内の npm レジストリを「レジストリ」に足す設定、`recent` の日数の設定、
  `pnpm-lock.yaml`・`yarn.lock` を読むか、ほかの人のコードを取り込んだフォルダ（`app/Vendor/` など）の lock ファイルを対象から外すか
- **保留（2026-10-03）**: Flutter の Android 側（Gradle の依存）を照合するか。osv-scanner は `gradle.lockfile`（Maven）を読めて、検出も確かめた。
  ただし Flutter の雛形は依存を固定しないので、各プロジェクトで `gradle.lockfile` を作って git に入れるか、LockWatch が Gradle を動かして作る必要がある
  （1 つ 1〜4 分、オフラインでは作れず Google・Maven Central への通信が要る）。今の手元のプロジェクトでは見つかるものが無く、効果が限られるので見送った。
  再開するなら、まず `lockfiles.NAMES` に `gradle.lockfile` を足して生態系を Maven にする（読むだけ）。Pub（`pubspec.lock`）は照合しているが、OSV の勧告は 13 件しかない
