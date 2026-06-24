import json

import cv2
import numpy as np

from baseball_clop import roi_store
from baseball_clop.web.app import create_app

FPS = 10
SIZE = (160, 120)


def _write_video(path, n_frames=10):
    writer = cv2.VideoWriter(str(path), cv2.VideoWriter_fourcc(*"mp4v"), FPS, SIZE)
    for i in range(n_frames):
        frame = np.full((SIZE[1], SIZE[0], 3), i * 10 % 256, dtype=np.uint8)
        writer.write(frame)
    writer.release()


def test_setup_page_renders():
    client = create_app().test_client()
    res = client.get("/")
    assert res.status_code == 200


def test_roi_page_redirects_before_setup():
    client = create_app().test_client()
    res = client.get("/roi")
    assert res.status_code == 302


def test_api_setup_rejects_missing_video(tmp_path):
    client = create_app().test_client()
    res = client.post(
        "/api/setup",
        json={"main_path": str(tmp_path / "missing.mp4"), "wide_path": "", "out_dir": str(tmp_path)},
    )
    assert res.status_code == 400


def test_setup_frame_and_save_rois_roundtrip(tmp_path):
    video_path = tmp_path / "main.mp4"
    _write_video(video_path)
    out_dir = tmp_path / "out"

    client = create_app().test_client()

    res = client.post(
        "/api/setup",
        json={"main_path": str(video_path), "wide_path": "", "out_dir": str(out_dir)},
    )
    assert res.status_code == 200

    res = client.get("/roi")
    assert res.status_code == 200

    res = client.get("/api/frame.png?t_sec=0")
    assert res.status_code == 200
    assert res.content_type == "image/png"
    assert len(res.data) > 0

    res = client.get("/api/rois")
    default_rois = res.get_json()
    assert "pitcher" in default_rois

    updated = json.loads(json.dumps(default_rois))
    updated["pitcher"] = {"x0": 0.1, "y0": 0.1, "x1": 0.2, "y1": 0.2}
    res = client.post("/api/rois", json=updated)
    assert res.status_code == 200

    saved = roi_store.load(out_dir / "rois.json")
    assert saved.pitcher.x0 == 0.1
    assert saved.pitcher.x1 == 0.2


def test_frame_png_out_of_range_returns_404(tmp_path):
    video_path = tmp_path / "main.mp4"
    _write_video(video_path, n_frames=5)
    out_dir = tmp_path / "out"

    client = create_app().test_client()
    client.post(
        "/api/setup",
        json={"main_path": str(video_path), "wide_path": "", "out_dir": str(out_dir)},
    )

    res = client.get("/api/frame.png?t_sec=999")
    assert res.status_code == 404
