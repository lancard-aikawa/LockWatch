<!-- release.yml が Release の本文の後ろに付ける「入れ方・更新の仕方」 -->
## 入れ方・更新の仕方

LockWatch は Python のソースのまま動かす道具なので、配るファイルはソースコードだけです（ビルドしたファイルはありません）。
Windows 10 / 11、Python 3.10 以上、[uv](https://docs.astral.sh/uv/)、osv-scanner 2.6.0 が要ります。

```cmd
winget install --id Google.OSVScanner --version 2.6.0 --exact
git clone https://github.com/lancard-aikawa/LockWatch.git
cd LockWatch
uv sync
uv run lockwatch status
```

更新は、そのフォルダで `git pull` と `uv sync`。ソースコードの zip を展開して使うこともできますが、更新は git の方が楽です。
詳しくは [README](https://github.com/lancard-aikawa/LockWatch#readme)。
