"""PyInstaller の入口（docs/design.md §9.1）。lockwatch.exe / lockwatchw.exe <サブコマンド> として動く"""
import sys

from lockwatch.cli import main

sys.exit(main())
