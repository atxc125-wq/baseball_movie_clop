"""フレーム差分による汎用モーション検出ユーティリティ。

ここにある関数は「ROI内の動きの大きさの時系列」を作ることと、その時系列から
特徴的な変化点(静止→動き出し、ピーク)を取り出すことだけを担当する。
投球動作・スイング・打球処理など意味づけは上位の detection/*.py が行う。

ポーズ推定など、より高精度な検出器に差し替えたい場合は、この時系列ベースの
実装を置き換えて同じ関数シグネチャ(List[MotionSample]を返す)を維持すればよい。
"""

from __future__ import annotations

from dataclasses import dataclass

import cv2
import numpy as np

from ..config import ROI
from ..progress import ConsoleProgress
from ..video_io import iter_frames


@dataclass
class MotionSample:
    t: float
    score: float


def roi_motion_series(
    path: str,
    roi: ROI,
    start_sec: float = 0.0,
    end_sec: float | None = None,
    analysis_width: int = 480,
    progress: ConsoleProgress | None = None,
) -> list[MotionSample]:
    """ROI内の連続フレーム間の平均絶対輝度差分を時系列として返す。"""

    samples: list[MotionSample] = []
    prev_gray: np.ndarray | None = None

    for t, frame in iter_frames(path, start_sec, end_sec, target_width=analysis_width):
        if progress is not None:
            progress.update(t - start_sec)
        h, w = frame.shape[:2]
        x0, y0, x1, y1 = roi.to_pixels(w, h)
        x0, y0 = max(0, x0), max(0, y0)
        x1, y1 = min(w, x1), min(h, y1)
        if x1 <= x0 or y1 <= y0:
            continue
        crop = frame[y0:y1, x0:x1]
        gray = cv2.cvtColor(crop, cv2.COLOR_BGR2GRAY)
        gray = cv2.GaussianBlur(gray, (5, 5), 0)

        score = 0.0 if prev_gray is None else float(np.mean(cv2.absdiff(gray, prev_gray)))
        samples.append(MotionSample(t=t, score=score))
        prev_gray = gray

    return samples


def find_motion_rises(
    samples: list[MotionSample],
    still_threshold: float,
    rise_threshold: float,
    min_still_sec: float,
    max_rise_threshold: float | None = None,
    peak_lookahead_sec: float = 0.4,
    min_consecutive_rise: int = 1,
) -> list[float]:
    """静止状態が min_still_sec 続いた後に rise_threshold を超えた時刻の一覧を返す。

    ヒステリシス(still_threshold < rise_threshold)を設けることで、閾値付近の
    揺らぎによる誤検出を抑える。

    max_rise_threshold を指定すると、立ち上がり直後 peak_lookahead_sec 以内の
    ピークがそれを超えるイベントは「対象(投手等)にしては動きすぎ」とみなして
    除外する。カメラ近くを人が横切る、打球処理後の乱戦などの大きな動きは、対象
    本来の動作よりずっと大きな差分を生むため、上限で弾き分けられる。

    min_consecutive_rise(>=2)を指定すると、rise_threshold超えが単発1フレームだけの
    ノイズ(圧縮アーティファクトや虫・埃などの一瞬の写り込み)を「動き出し」から除外する。
    実映像では本物の投球動作は複数フレームに渡って閾値を超え続けるのに対し、ノイズは
    1フレームだけ跳ねて即座に元の値へ戻るため、この条件で明確に弾き分けられる。
    条件を満たさない場合は静止期間を継続したものとみなし(still_startは更新しない)、
    そのまま次の本物の立ち上がりを待つ。
    """

    if not samples:
        return []

    events: list[float] = []
    state = "still"
    still_start = samples[0].t

    for i, s in enumerate(samples):
        if state == "still":
            if s.score > rise_threshold and (s.t - still_start) >= min_still_sec:
                if max_rise_threshold is not None:
                    window = [s2 for s2 in samples[i:] if s2.t <= s.t + peak_lookahead_sec]
                    peak = max((s2.score for s2 in window), default=s.score)
                    if peak > max_rise_threshold:
                        state = "moving"
                        continue
                if min_consecutive_rise > 1:
                    run = samples[i : i + min_consecutive_rise]
                    if len(run) < min_consecutive_rise or any(s2.score <= rise_threshold for s2 in run):
                        continue
                events.append(s.t)
                state = "moving"
        else:
            if s.score <= still_threshold:
                state = "still"
                still_start = s.t

    return events


def find_local_peak(samples: list[MotionSample], start_t: float, end_t: float) -> MotionSample | None:
    window = [s for s in samples if start_t <= s.t <= end_t]
    if not window:
        return None
    return max(window, key=lambda s: s.score)


def is_quiet_from(
    samples: list[MotionSample],
    after_t: float,
    quiet_threshold: float,
    min_quiet_sec: float,
) -> float | None:
    """after_t以降で、quiet_threshold以下が min_quiet_sec 続いた最初の開始時刻を返す。"""

    quiet_start: float | None = None
    for s in samples:
        if s.t < after_t:
            continue
        if s.score <= quiet_threshold:
            if quiet_start is None:
                quiet_start = s.t
            elif s.t - quiet_start >= min_quiet_sec:
                return quiet_start
        else:
            quiet_start = None
    return None
