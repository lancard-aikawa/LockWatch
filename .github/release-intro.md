<!-- release.yml が Release の本文の後ろに付ける「入れ方・更新の仕方」 -->
## 入れ方・更新の仕方

**[RepoTether](https://github.com/lancard-aikawa/RepoTether) を使っているなら、RepoTether から入れるのがいちばん楽です**
（脆弱性タブの LockWatch の欄の「入れる」。Python は要りません。更新も同じ欄から）。

自分で入れるなら、どちらかで（Windows 10 / 11、64 bit）。osv-scanner 2.6.0 も要ります（RepoTether から入れれば一緒に入ります。自分で入れるなら `winget install --id Google.OSVScanner --version 2.6.0 --exact`、または `osv-scanner.exe` を exe の隣に置く）。

- **`LockWatch-<版>-win-x64.zip`** — 展開するだけで動きます（Python は要りません）。`lockwatch.exe status` がコマンド、`lockwatchw.exe gui` が画面。
  設定とデータは exe の隣にできます。更新は、新しい zip の中身で上書きします（設定 `lockwatch.json` と `data` フォルダは zip に入っていないので残ります）
- **ソースコード** — Python 3.11 以上で動かします。`git clone https://github.com/lancard-aikawa/LockWatch.git` して、更新は `git pull`

署名していないので、初回は SmartScreen が出ることがあります。詳しくは [README](https://github.com/lancard-aikawa/LockWatch#readme)。
