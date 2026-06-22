"""打球発生後、main(マウンド-ホーム)カメラに収まり続けるか、wide(広角)へ
切り替えるべきかを判定する。

デフォルトはwide。バント・極端な浅いポップフライなどホームベース付近から
大きく離れないことが追跡できた場合のみmainに留める。追跡が途切れる、または
判定が難しい場合は安全側(wide)に倒し、needs_review=Trueで要確認とする。
これはPitchEvent.camera_overrideで常に手動上書きできる。
"""

from __future__ import annotations

from dataclasses import dataclass

from ..config import DetectionConfig
from .ball_tracking import max_radial_distance_from_point, track_small_fast_blobs


@dataclass
class CameraDecision:
    camera: str  # "main" or "wide"
    confidence: float
    needs_review: bool
    reason: str


def decide_camera_for_play(
    main_video_path: str,
    contact_sec: float,
    config: DetectionConfig,
    search_sec: float = 2.0,
) -> CameraDecision:
    rois = config.main_rois
    home_x = (rois.catcher.x0 + rois.catcher.x1) / 2
    home_y = (rois.catcher.y0 + rois.catcher.y1) / 2

    positions = track_small_fast_blobs(
        main_video_path, contact_sec, contact_sec + search_sec, analysis_width=config.analysis_width
    )
    if len(positions) < 3:
        return CameraDecision(
            camera="wide", confidence=0.3, needs_review=True, reason="打球の追跡ができず安全側でwideを選択"
        )

    max_dist = max_radial_distance_from_point(positions, home_x, home_y)
    if max_dist <= config.camera_switch_radius_frac:
        return CameraDecision(
            camera="main", confidence=0.5, needs_review=True, reason="打球がmainカメラの範囲内に収まったと推定"
        )

    return CameraDecision(
        camera="wide", confidence=0.6, needs_review=False, reason="打球がmainカメラの範囲を超えたためwideへ切替"
    )
