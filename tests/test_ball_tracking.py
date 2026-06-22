import cv2
import numpy as np

from baseball_clop.config import MainCameraROIs, ROI
from baseball_clop.detection.ball_tracking import estimate_throw_target, track_small_fast_blobs

FPS = 20
SIZE = (320, 240)
DURATION_SEC = 1.5


def _write_moving_dot_video(path, start_xy, end_xy):
    n_frames = int(DURATION_SEC * FPS)
    writer = cv2.VideoWriter(str(path), cv2.VideoWriter_fourcc(*"mp4v"), FPS, SIZE)
    for i in range(n_frames):
        frac = i / max(1, n_frames - 1)
        x = int(start_xy[0] + (end_xy[0] - start_xy[0]) * frac)
        y = int(start_xy[1] + (end_xy[1] - start_xy[1]) * frac)
        frame = np.zeros((SIZE[1], SIZE[0], 3), dtype=np.uint8)
        cv2.circle(frame, (x, y), 5, (255, 255, 255), -1)
        writer.write(frame)
    writer.release()


def _rois():
    return MainCameraROIs(
        pitcher=ROI(0.3, 0.05, 0.7, 0.35),
        batter_box=ROI(0.15, 0.55, 0.85, 0.85),
        catcher=ROI(0.35, 0.75, 0.65, 1.0),
        strike_zone=ROI(0.40, 0.62, 0.60, 0.80),
        base_first=ROI(0.75, 0.1, 1.0, 0.6),
        base_third=ROI(0.0, 0.1, 0.25, 0.6),
    )


def test_track_small_fast_blobs_follows_moving_dot(tmp_path):
    path = tmp_path / "pitch.mp4"
    _write_moving_dot_video(path, start_xy=(160, 20), end_xy=(160, 220))

    positions = track_small_fast_blobs(str(path), 0.0, DURATION_SEC, analysis_width=SIZE[0])

    assert len(positions) > 5
    assert positions[0].y < positions[-1].y  # 上から下へ動いている


def test_estimate_throw_target_detects_home_direction(tmp_path):
    path = tmp_path / "pitch_home.mp4"
    _write_moving_dot_video(path, start_xy=(160, 20), end_xy=(160, 220))

    target, confidence = estimate_throw_target(str(path), 0.0, DURATION_SEC, _rois(), analysis_width=SIZE[0])

    assert target == "home"
    assert confidence > 0


def test_estimate_throw_target_detects_first_base_direction(tmp_path):
    path = tmp_path / "pickoff_1b.mp4"
    _write_moving_dot_video(path, start_xy=(160, 20), end_xy=(300, 100))

    target, confidence = estimate_throw_target(str(path), 0.0, DURATION_SEC, _rois(), analysis_width=SIZE[0])

    assert target == "1B"
    assert confidence > 0
