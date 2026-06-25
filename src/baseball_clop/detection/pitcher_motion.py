"""投球動作(ワインドアップ/セットポジション)開始の検出と、牽制との切り分け。

検出の考え方:
1. マウンド付近ROIのモーション時系列から「静止が一定時間続いた後に動き出す」
   イベントを全て候補として拾う(find_motion_rises)。この時点ではワインドアップ
   開始・セットからのクイック投球・牽制の予備動作が全て混在している。
2. 各候補について、直後にボールらしきブロブがどちら方向へ飛んだかを
   estimate_throw_target で推定し、
     - home方向 → 投球
     - 1B/3B方向 → 牽制(セットに入る前の牽制もここで自然に分離される)
     - unknown  → 安全側で投球扱いにし、needs_review=True で要確認とする
3. 投球候補の「動き出した時刻」から pre_roll_sec 前を clip_start とする。
"""

from __future__ import annotations

from dataclasses import dataclass

from ..config import DetectionConfig
from ..progress import ConsoleProgress
from ..scoring.models import PickoffEvent
from ..video_io import get_video_info
from .ball_tracking import estimate_throw_target
from .motion import find_local_peak, find_motion_rises, roi_motion_series


@dataclass
class PitchCandidate:
    motion_start_sec: float
    release_sec: float
    confidence: float
    needs_review: bool


def detect_pitch_and_pickoff_candidates(
    main_video_path: str,
    config: DetectionConfig,
    start_sec: float = 0.0,
    end_sec: float | None = None,
) -> tuple[list[PitchCandidate], list[PickoffEvent]]:
    rois = config.main_rois
    total_sec = (end_sec if end_sec is not None else get_video_info(main_video_path).duration_sec) - start_sec
    scan_progress = ConsoleProgress("投手モーション検出(動画スキャン)", total=total_sec)
    samples = roi_motion_series(
        main_video_path,
        rois.pitcher,
        start_sec=start_sec,
        end_sec=end_sec,
        analysis_width=config.analysis_width,
        progress=scan_progress,
    )
    scan_progress.finish()
    rise_times = find_motion_rises(
        samples,
        config.pitcher_motion_threshold,
        config.pitcher_motion_min_rise,
        config.pitcher_still_min_sec,
        max_rise_threshold=config.pitcher_motion_max_rise,
        min_consecutive_rise=config.pitcher_motion_min_consecutive_rise,
    )

    pitches: list[PitchCandidate] = []
    pickoffs: list[PickoffEvent] = []

    cand_progress = ConsoleProgress("投球/牽制候補を分析中", total=len(rise_times)) if rise_times else None
    for cand_idx, motion_start in enumerate(rise_times, start=1):
        if cand_progress is not None:
            cand_progress.update(cand_idx)
        search_end = motion_start + config.pickoff_max_sec_after_motion
        peak = find_local_peak(samples, motion_start, search_end)
        release_sec = peak.t if peak else motion_start + 0.3

        target, confidence = estimate_throw_target(
            main_video_path, motion_start, search_end, rois, analysis_width=config.analysis_width
        )

        if target in ("1B", "3B"):
            pickoffs.append(
                PickoffEvent(
                    sec=motion_start,
                    target_base=target,
                    detection_confidence=confidence,
                    needs_review=confidence < 0.5,
                    notes="モーション検出による牽制候補(要確認)",
                )
            )
            continue

        # home方向、または方向不明(安全側で投球候補として残す)
        pitches.append(
            PitchCandidate(
                motion_start_sec=motion_start,
                release_sec=release_sec,
                confidence=confidence,
                needs_review=(target == "unknown") or confidence < 0.5,
            )
        )

    if cand_progress is not None:
        cand_progress.finish()

    return pitches, pickoffs
