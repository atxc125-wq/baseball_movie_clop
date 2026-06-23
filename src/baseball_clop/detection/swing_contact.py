"""見逃し/空振り/打球の判定と、見逃し・空振り時のクリップ終了点(捕手到達直前)の推定。

打球(in_play)の場合、ここでは「接触したらしい時刻(contact_sec)」を返すのみで、
クリップ終了点(打球処理が終わるまで)は detection/ball_tracking.detect_play_end
が別途、広角(wide)映像側で求める。本モジュールはmainカメラ(マウンド-ホーム)側の
解析に限定している。

ストライク/ボールの自動判定は本質的に難しいため、見逃し(take)の判定は常に
needs_review=True とし、タイムラインJSON/CSVでの手動修正を前提とする。
"""

from __future__ import annotations

from dataclasses import dataclass

from ..config import DetectionConfig, ROI
from ..scoring.models import PitchCall, PitchOutcome
from .ball_tracking import BallPosition, track_small_fast_blobs
from .motion import find_local_peak, roi_motion_series


@dataclass
class PitchResult:
    outcome: PitchOutcome
    pitch_call: PitchCall
    clip_end_sec: float
    contact_sec: float | None
    confidence: float
    needs_review: bool
    # 捕手到達(捕球)の推定時刻(バッファ加算前の生値)。take/swing_missクリップの
    # 開始点をここから逆算するために、バッファ込みのclip_end_secとは別に保持する。
    catch_reference_sec: float | None = None


def analyze_pitch_result(main_video_path: str, release_sec: float, config: DetectionConfig) -> PitchResult:
    rois = config.main_rois
    search_end = release_sec + config.pitch_flight_max_sec

    swing_samples = roi_motion_series(
        main_video_path, rois.batter_box, start_sec=release_sec, end_sec=search_end, analysis_width=config.analysis_width
    )
    win_lo, win_hi = config.swing_reaction_window_sec
    swing_peak = find_local_peak(swing_samples, release_sec + win_lo, release_sec + win_hi)
    swing_detected = swing_peak is not None and swing_peak.score >= config.swing_motion_threshold

    positions = track_small_fast_blobs(main_video_path, release_sec, search_end, analysis_width=config.analysis_width)
    catcher_arrival_sec = _find_catcher_arrival(positions, rois.catcher)
    contact_sec = _find_trajectory_break(positions) if swing_detected else None

    if swing_detected and contact_sec is not None:
        return PitchResult(
            outcome=PitchOutcome.IN_PLAY,
            pitch_call=PitchCall.IN_PLAY,
            clip_end_sec=contact_sec,  # pipeline側でplay_end_secにより上書きされる
            contact_sec=contact_sec,
            confidence=0.4,
            needs_review=True,  # 打球の結果(ヒット/アウト等)は人手確認が前提
        )

    if swing_detected and contact_sec is None:
        end = catcher_arrival_sec if catcher_arrival_sec is not None else search_end
        return PitchResult(
            outcome=PitchOutcome.SWING_MISS,
            pitch_call=PitchCall.STRIKE,
            clip_end_sec=end + config.catch_buffer_sec,
            contact_sec=None,
            confidence=0.7 if catcher_arrival_sec is not None else 0.3,
            needs_review=catcher_arrival_sec is None,
            catch_reference_sec=end,
        )

    end = catcher_arrival_sec if catcher_arrival_sec is not None else search_end
    call = _estimate_ball_or_strike(positions, rois.strike_zone)
    return PitchResult(
        outcome=PitchOutcome.TAKE,
        pitch_call=call,
        clip_end_sec=end + config.catch_buffer_sec,
        contact_sec=None,
        confidence=0.2,
        needs_review=True,
        catch_reference_sec=end,
    )


def _find_catcher_arrival(positions: list[BallPosition], catcher_roi: ROI) -> float | None:
    for p in positions:
        if catcher_roi.x0 <= p.x <= catcher_roi.x1 and catcher_roi.y0 <= p.y <= catcher_roi.y1:
            return p.t
    return None


def _find_trajectory_break(positions: list[BallPosition]) -> float | None:
    """捕手方向への単調な動きから外れた最初の時刻を「打球(接触)」の目安として返す。"""

    if len(positions) < 4:
        return None
    for i in range(2, len(positions)):
        if positions[i].y < positions[i - 1].y - 0.02:
            return positions[i].t
    return None


def _estimate_ball_or_strike(positions: list[BallPosition], strike_zone: ROI) -> PitchCall:
    if not positions:
        return PitchCall.UNKNOWN
    last = positions[-1]
    if strike_zone.x0 <= last.x <= strike_zone.x1 and strike_zone.y0 <= last.y <= strike_zone.y1:
        return PitchCall.STRIKE
    return PitchCall.BALL
