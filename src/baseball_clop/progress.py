"""長時間処理の進捗をcmd/ターミナルへ\r上書き表示するための小さなユーティリティ。"""

from __future__ import annotations

import sys
import time


class ConsoleProgress:
    """total に対する現在値の割合(%)を、一定間隔でのみ同じ行に上書き表示する。"""

    def __init__(self, label: str, total: float, min_interval_sec: float = 2.0) -> None:
        self.label = label
        self.total = total
        self.min_interval_sec = min_interval_sec
        self._last_print_time = float("-inf")

    def update(self, current: float) -> None:
        now = time.monotonic()
        if now - self._last_print_time < self.min_interval_sec:
            return
        self._last_print_time = now
        self._print(current)

    def finish(self) -> None:
        self._print(self.total)
        print(file=sys.stderr)

    def _print(self, current: float) -> None:
        pct = 0.0 if self.total <= 0 else min(100.0, max(0.0, current / self.total * 100.0))
        print(f"\r{self.label}: {pct:5.1f}%", end="", flush=True, file=sys.stderr)
