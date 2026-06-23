"""ROI(投手/捕手/打者など)を映像フレーム上に描画し、目視で配置を確認するためのツール。

検出ロジックはconfig.pyのROI(画面比率)に強く依存するため、新しい映像・カメラ位置を
使う際は本番の検出を走らせる前に必ずこれで枠が実際の投手・捕手・打者の位置に合っているか
確認すること。OpenCVの標準描画フォントは日本語を描画できないため、ラベルは英語表記にしている。
"""

from __future__ import annotations

import cv2
import numpy as np

from .config import ROI, MainCameraROIs
from .video_io import iter_frames

_LABELS = {
    "pitcher": "PITCHER",
    "batter_box": "BATTER",
    "catcher": "CATCHER",
    "strike_zone": "STRIKE ZONE",
    "base_first": "PICKOFF 1B",
    "base_third": "PICKOFF 3B",
}

_COLORS_BGR = {
    "pitcher": (0, 0, 255),
    "batter_box": (0, 200, 0),
    "catcher": (255, 0, 0),
    "strike_zone": (0, 220, 220),
    "base_first": (255, 0, 255),
    "base_third": (255, 180, 0),
}


def draw_rois(frame: np.ndarray, rois: MainCameraROIs) -> np.ndarray:
    """frame上にROIの矩形とラベルを描画した画像を返す(元のframeは変更しない)。"""

    out = frame.copy()
    h, w = out.shape[:2]
    for name, color in _COLORS_BGR.items():
        roi: ROI = getattr(rois, name)
        x0, y0, x1, y1 = roi.to_pixels(w, h)
        cv2.rectangle(out, (x0, y0), (x1, y1), color, 2)
        label_y = y0 - 8 if y0 - 8 > 10 else y1 + 18
        cv2.putText(out, _LABELS[name], (x0 + 2, label_y), cv2.FONT_HERSHEY_SIMPLEX, 0.55, color, 2, cv2.LINE_AA)
    return out


def save_roi_preview(video_path: str, rois: MainCameraROIs, output_path: str, t_sec: float = 5.0) -> str:
    """指定時刻に最も近いフレームにROIを描画し、画像として保存する。"""

    for _, frame in iter_frames(video_path, start_sec=t_sec):
        annotated = draw_rois(frame, rois)
        cv2.imwrite(str(output_path), annotated)
        return str(output_path)
    raise ValueError(f"指定時刻 {t_sec}s のフレームを取得できませんでした: {video_path}")
