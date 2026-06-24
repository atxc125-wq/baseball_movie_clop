"""ROI調整結果(MainCameraROIs)をJSONファイルとして保存・読み込みする。

カメラの位置や画角は撮影ごとに変わるため、config.py のデフォルト値をソース
コード編集で直すのではなく、Web UIで調整した結果をプロジェクトごとのJSONに
保存して使い回せるようにする。
"""

from __future__ import annotations

import json
from pathlib import Path

from .config import MainCameraROIs


def load(path: str | Path) -> MainCameraROIs | None:
    p = Path(path)
    if not p.exists():
        return None
    return MainCameraROIs.from_dict(json.loads(p.read_text(encoding="utf-8")))


def save(rois: MainCameraROIs, path: str | Path) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(rois.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
