"""OpenCVを使った動画の読み込みユーティリティ。"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

import cv2
import numpy as np


@dataclass
class VideoInfo:
    path: str
    fps: float
    frame_count: int
    width: int
    height: int

    @property
    def duration_sec(self) -> float:
        return self.frame_count / self.fps if self.fps else 0.0


def get_video_info(path: str | Path) -> VideoInfo:
    cap = cv2.VideoCapture(str(path))
    if not cap.isOpened():
        raise FileNotFoundError(f"動画を開けません: {path}")
    try:
        fps = cap.get(cv2.CAP_PROP_FPS) or 30.0
        frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        return VideoInfo(path=str(path), fps=fps, frame_count=frame_count, width=width, height=height)
    finally:
        cap.release()


def iter_frames(
    path: str | Path,
    start_sec: float = 0.0,
    end_sec: float | None = None,
    target_width: int | None = None,
) -> Iterator[tuple[float, np.ndarray]]:
    """(再生時刻[sec], フレーム) を順に返す。target_width指定時はアスペクト比を保って縮小する。"""

    cap = cv2.VideoCapture(str(path))
    if not cap.isOpened():
        raise FileNotFoundError(f"動画を開けません: {path}")
    try:
        fps = cap.get(cv2.CAP_PROP_FPS) or 30.0
        if start_sec > 0:
            cap.set(cv2.CAP_PROP_POS_MSEC, start_sec * 1000.0)

        frame_idx = round(start_sec * fps)
        while True:
            ok, frame = cap.read()
            if not ok:
                break
            t = frame_idx / fps
            if end_sec is not None and t > end_sec:
                break
            if target_width is not None and frame.shape[1] != target_width:
                scale = target_width / frame.shape[1]
                target_height = max(1, round(frame.shape[0] * scale))
                frame = cv2.resize(frame, (target_width, target_height), interpolation=cv2.INTER_AREA)
            yield t, frame
            frame_idx += 1
    finally:
        cap.release()
