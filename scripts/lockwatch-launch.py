"""窓を出さずに LockWatch を動かすための起動役（scripts/lockwatch-gui.cmd と register-task.ps1 が使う）

uv 0.11 の .venv\\Scripts\\pythonw.exe は python.exe と同じコンソール用の起動役で、黒い窓が開く。
そこで本体の Python の pythonw.exe（.venv\\pyvenv.cfg の home）でこのファイルを動かす。
LockWatch は標準ライブラリしか使わないので、src を読み込み先に足せば .venv は要らない。

  <home>\\pythonw.exe scripts\\lockwatch-launch.py gui
  <home>\\pythonw.exe scripts\\lockwatch-launch.py --log scan
"""
import os
import sys
from pathlib import Path

SRC = str(Path(__file__).resolve().parents[1] / "src")
sys.path.insert(0, SRC)
# 画面が別のプロセスで呼ぶ python -m lockwatch にも src を見せる
os.environ["PYTHONPATH"] = os.pathsep.join(p for p in (SRC, os.environ.get("PYTHONPATH")) if p)

from lockwatch.cli import main  # noqa: E402

sys.exit(main())
