from pathlib import Path

import cv2
import numpy as np

from baseball_clop.pipeline import _analysis_video
from baseball_clop.video_io import get_video_info

FPS = 10


def _write_video(path, size, n_frames=20):
    writer = cv2.VideoWriter(str(path), cv2.VideoWriter_fourcc(*"mp4v"), FPS, size)
    for i in range(n_frames):
        writer.write(np.full((size[1], size[0], 3), i % 256, dtype=np.uint8))
    writer.release()


def test_analysis_video_skips_proxy_when_narrow_enough(tmp_path):
    main_path = tmp_path / "main.mp4"
    _write_video(main_path, size=(160, 120))

    with _analysis_video(str(main_path), width=160, analysis_width=480) as analysis_path:
        assert analysis_path == str(main_path)


def test_analysis_video_creates_proxy_and_cleans_up_when_wider(tmp_path):
    main_path = tmp_path / "main.mp4"
    _write_video(main_path, size=(640, 480))

    captured_path = None
    with _analysis_video(str(main_path), width=640, analysis_width=320) as analysis_path:
        captured_path = analysis_path
        assert analysis_path != str(main_path)
        assert Path(analysis_path).exists()

        info = get_video_info(analysis_path)
        assert info.width == 320
        assert abs(info.duration_sec - get_video_info(main_path).duration_sec) < 0.2

    assert not Path(captured_path).parent.exists()
