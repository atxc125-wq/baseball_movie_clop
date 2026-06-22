import cv2
import numpy as np
import pytest

from baseball_clop.config import ClipConfig
from baseball_clop.editor.clipper import cut_pitch_clip
from baseball_clop.video_io import get_video_info

FPS = 10
SIZE = (160, 120)


def _write_color_video(path, n_frames, channel):
    writer = cv2.VideoWriter(str(path), cv2.VideoWriter_fourcc(*"mp4v"), FPS, SIZE)
    for i in range(n_frames):
        t = i / FPS
        value = int(min(255, t * 40))
        frame = np.zeros((SIZE[1], SIZE[0], 3), dtype=np.uint8)
        frame[:, :, channel] = value
        writer.write(frame)
    writer.release()


@pytest.fixture()
def videos(tmp_path):
    main_path = tmp_path / "main.mp4"
    wide_path = tmp_path / "wide.mp4"
    _write_color_video(main_path, n_frames=50, channel=2)  # R channel = main
    _write_color_video(wide_path, n_frames=50, channel=0)  # B channel = wide
    return str(main_path), str(wide_path)


def _sample_mean(video_path, t):
    cap = cv2.VideoCapture(video_path)
    cap.set(cv2.CAP_PROP_POS_FRAMES, round(t * FPS))
    ok, frame = cap.read()
    cap.release()
    assert ok
    return frame.mean(axis=(0, 1))  # B, G, R


def test_single_segment_duration(videos, tmp_path):
    main_path, _ = videos
    out_path = tmp_path / "out.mp4"
    config = ClipConfig(output_width=SIZE[0], output_height=SIZE[1], output_fps=FPS, crf=23, preset="ultrafast")

    cut_pitch_clip([(main_path, 1.0, 2.5)], out_path, config)

    info = get_video_info(out_path)
    assert abs(info.duration_sec - 1.5) < 0.3


def test_multi_segment_concat_switches_camera_in_order(videos, tmp_path):
    main_path, wide_path = videos
    out_path = tmp_path / "out.mp4"
    config = ClipConfig(output_width=SIZE[0], output_height=SIZE[1], output_fps=FPS, crf=23, preset="ultrafast")

    # main[1.0-2.0] (1秒) に続けて wide[0.5-1.5] (1秒) を連結
    cut_pitch_clip([(main_path, 1.0, 2.0), (wide_path, 0.5, 1.5)], out_path, config)

    info = get_video_info(out_path)
    assert abs(info.duration_sec - 2.0) < 0.3

    early = _sample_mean(str(out_path), 0.2)  # mainセグメント側
    late = _sample_mean(str(out_path), 1.7)  # wideセグメント側

    b_early, _, r_early = early
    b_late, _, r_late = late

    assert r_early > b_early  # 前半はmain(R)が支配的
    assert b_late > r_late  # 後半はwide(B)が支配的
