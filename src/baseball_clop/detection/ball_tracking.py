"""簡易ボール追跡。

色・サイズだけでは硬式/軟式球とユニフォームの白などを判別しきれないため、
「小さく・速く動き・背景から際立つ、ある程度円形のブロブ」を1フレーム1個だけ
探す程度の実装にとどめる。これは打球判定全体の中でも最も精度が出にくい部分
であり、実映像で最初にチューニング/差し替えが必要になりやすい箇所。
"""

from __future__ import annotations

from dataclasses import dataclass

import cv2
import numpy as np

from ..config import ROI, MainCameraROIs
from ..video_io import iter_frames
from .motion import is_quiet_from, roi_motion_series


@dataclass
class BallPosition:
    t: float
    x: float  # フレーム幅に対する比率 (0..1)
    y: float  # フレーム高さに対する比率 (0..1)
    radius_px: float


def track_small_fast_blobs(
    path: str,
    start_sec: float,
    end_sec: float | None,
    analysis_width: int = 480,
    min_radius_px: float = 2.0,
    max_radius_px: float = 18.0,
    diff_threshold: int = 18,
    min_circularity: float = 0.3,
) -> list[BallPosition]:
    positions: list[BallPosition] = []
    prev_gray: np.ndarray | None = None

    for t, frame in iter_frames(path, start_sec, end_sec, target_width=analysis_width):
        h, w = frame.shape[:2]
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        gray = cv2.GaussianBlur(gray, (5, 5), 0)

        if prev_gray is not None:
            diff = cv2.absdiff(gray, prev_gray)
            _, mask = cv2.threshold(diff, diff_threshold, 255, cv2.THRESH_BINARY)
            mask = cv2.dilate(mask, None, iterations=1)
            contours, _ = cv2.findContours(mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)

            best: tuple[float, float, float] | None = None
            for c in contours:
                (cx, cy), radius = cv2.minEnclosingCircle(c)
                if not (min_radius_px <= radius <= max_radius_px):
                    continue
                circle_area = np.pi * radius * radius
                if circle_area <= 0:
                    continue
                if cv2.contourArea(c) / circle_area < min_circularity:
                    continue
                if best is None or radius > best[2]:
                    best = (cx, cy, radius)

            if best is not None:
                cx, cy, radius = best
                positions.append(BallPosition(t=t, x=cx / w, y=cy / h, radius_px=radius))

        prev_gray = gray

    return positions


def estimate_throw_target(
    path: str,
    search_start: float,
    search_end: float,
    rois: MainCameraROIs,
    analysis_width: int = 480,
) -> tuple[str, float]:
    """投球/牽制の送球方向を推定する。戻り値は ("home"|"1B"|"3B"|"unknown", confidence)。"""

    positions = track_small_fast_blobs(path, search_start, search_end, analysis_width=analysis_width)
    if len(positions) < 2:
        return "unknown", 0.0

    last = positions[-1]
    candidates = {"home": rois.catcher, "1B": rois.base_first, "3B": rois.base_third}
    for name, roi in candidates.items():
        if roi.x0 <= last.x <= roi.x1 and roi.y0 <= last.y <= roi.y1:
            confidence = min(1.0, len(positions) / 8.0)
            return name, confidence

    return "unknown", 0.2


def detect_play_end(
    path: str,
    after_sec: float,
    still_threshold: float,
    min_still_sec: float,
    max_search_sec: float,
    analysis_width: int = 480,
) -> tuple[float, bool]:
    """打球処理(プレー)が終わったとみなせる時刻を返す。

    動き(フィールド全体)が一定時間落ち着いた瞬間を「プレー終了」とみなす
    粗いヒューリスティック。max_search_secまでに落ち着きが見られない場合は
    探索上限を終了時刻として返し、needs_review相当のFalseを第2要素で示す。
    """

    full_frame = ROI(0.0, 0.0, 1.0, 1.0)
    samples = roi_motion_series(
        path, full_frame, start_sec=after_sec, end_sec=after_sec + max_search_sec, analysis_width=analysis_width
    )
    quiet_start = is_quiet_from(samples, after_sec, still_threshold, min_still_sec)
    if quiet_start is not None:
        return quiet_start, True
    return after_sec + max_search_sec, False


def max_radial_distance_from_point(
    positions: list[BallPosition], origin_x: float, origin_y: float
) -> float:
    if not positions:
        return 0.0
    return max(((p.x - origin_x) ** 2 + (p.y - origin_y) ** 2) ** 0.5 for p in positions)
