import json
import time

import cv2
import numpy as np

from baseball_clop import roi_store
from baseball_clop.scoring import timeline_io
from baseball_clop.scoring.models import GameTimeline, PitchCall, PitchEvent, PitchOutcome, VideoSources
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


def test_api_setup_stores_wide_offset_sec(tmp_path):
    video_path = tmp_path / "main.mp4"
    _write_video(video_path)
    out_dir = tmp_path / "out"

    app = create_app()
    client = app.test_client()
    res = client.post(
        "/api/setup",
        json={
            "main_path": str(video_path),
            "wide_path": "",
            "out_dir": str(out_dir),
            "wide_offset_sec": "1.25",
        },
    )
    assert res.status_code == 200
    assert app.config["STATE"].wide_offset_sec == 1.25


def test_api_sync_audio_rejects_missing_files(tmp_path):
    client = create_app().test_client()
    res = client.post(
        "/api/sync-audio",
        json={"main_path": str(tmp_path / "missing_main.mp4"), "wide_path": str(tmp_path / "missing_wide.mp4")},
    )
    assert res.status_code == 400


def test_api_sync_audio_rejects_video_without_audio(tmp_path):
    main_path = tmp_path / "main.mp4"
    wide_path = tmp_path / "wide.mp4"
    _write_video(main_path)
    _write_video(wide_path)

    client = create_app().test_client()
    res = client.post(
        "/api/sync-audio",
        json={"main_path": str(main_path), "wide_path": str(wide_path)},
    )
    assert res.status_code == 400
    assert "音声" in res.get_json()["error"]


def test_api_detect_rejects_before_setup():
    client = create_app().test_client()
    res = client.post("/api/detect")
    assert res.status_code == 400


def test_api_detect_rejects_without_wide_path(tmp_path):
    video_path = tmp_path / "main.mp4"
    _write_video(video_path)
    out_dir = tmp_path / "out"

    client = create_app().test_client()
    client.post(
        "/api/setup",
        json={"main_path": str(video_path), "wide_path": "", "out_dir": str(out_dir)},
    )

    res = client.post("/api/detect")
    assert res.status_code == 400


def _wait_for_detect_done(client, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        data = client.get("/api/detect-status").get_json()
        if data["state"] != "running":
            return data
        time.sleep(0.1)
    raise AssertionError("detect did not finish in time")


def test_api_detect_runs_and_reports_done(tmp_path):
    main_path = tmp_path / "main.mp4"
    wide_path = tmp_path / "wide.mp4"
    _write_video(main_path)
    _write_video(wide_path)
    out_dir = tmp_path / "out"

    client = create_app().test_client()
    res = client.post(
        "/api/setup",
        json={"main_path": str(main_path), "wide_path": str(wide_path), "out_dir": str(out_dir)},
    )
    assert res.status_code == 200

    res = client.post("/api/detect")
    assert res.status_code == 200

    data = _wait_for_detect_done(client)
    assert data["state"] == "done"
    timeline_path = out_dir / "events" / "game.json"
    assert str(timeline_path) == data["timeline_path"]
    assert timeline_path.exists()
    json.loads(timeline_path.read_text())


def test_api_detect_rejects_concurrent_run(tmp_path):
    main_path = tmp_path / "main.mp4"
    wide_path = tmp_path / "wide.mp4"
    _write_video(main_path)
    _write_video(wide_path)
    out_dir = tmp_path / "out"

    client = create_app().test_client()
    client.post(
        "/api/setup",
        json={"main_path": str(main_path), "wide_path": str(wide_path), "out_dir": str(out_dir)},
    )

    res = client.post("/api/detect")
    assert res.status_code == 200

    res = client.post("/api/detect")
    assert res.status_code == 409

    _wait_for_detect_done(client)


def _pitch(id_, clip_start, clip_end, outcome=PitchOutcome.TAKE, pitch_call=PitchCall.BALL, inning=1, half="top"):
    return PitchEvent(
        id=id_,
        inning=inning,
        half=half,
        clip_start_sec=clip_start,
        clip_end_sec=clip_end,
        outcome=outcome,
        pitch_call=pitch_call,
    )


def _setup_with_timeline(client, tmp_path, pitches, main_path=None, wide_path=""):
    main_path = main_path or (tmp_path / "main.mp4")
    if not main_path.exists():
        _write_video(main_path)
    out_dir = tmp_path / "out"
    res = client.post(
        "/api/setup",
        json={"main_path": str(main_path), "wide_path": wide_path, "out_dir": str(out_dir)},
    )
    assert res.status_code == 200

    timeline = GameTimeline(video=VideoSources(main_path=str(main_path)), pitches=pitches, pickoffs=[])
    timeline_io.save_json(timeline, out_dir / "events" / "game.json")
    return out_dir


def test_review_page_redirects_before_setup():
    client = create_app().test_client()
    res = client.get("/review")
    assert res.status_code == 302


def test_review_page_redirects_without_timeline(tmp_path):
    video_path = tmp_path / "main.mp4"
    _write_video(video_path)
    out_dir = tmp_path / "out"

    client = create_app().test_client()
    client.post(
        "/api/setup",
        json={"main_path": str(video_path), "wide_path": "", "out_dir": str(out_dir)},
    )

    res = client.get("/review")
    assert res.status_code == 302


def test_review_page_renders_with_timeline(tmp_path):
    client = create_app().test_client()
    _setup_with_timeline(client, tmp_path, [_pitch("p0001", 1.0, 2.0)])

    res = client.get("/review")
    assert res.status_code == 200


def test_api_pitches_lists_after_timeline_exists(tmp_path):
    client = create_app().test_client()
    _setup_with_timeline(client, tmp_path, [_pitch("p0002", 5.0, 6.0), _pitch("p0001", 1.0, 2.0)])

    res = client.get("/api/pitches")
    assert res.status_code == 200
    data = res.get_json()
    assert [p["id"] for p in data] == ["p0001", "p0002"]
    assert "count_after" in data[0]
    assert "runners_after" in data[0]


def test_api_get_pitch_returns_pitch_and_404_for_missing(tmp_path):
    client = create_app().test_client()
    _setup_with_timeline(client, tmp_path, [_pitch("p0001", 1.0, 2.0)])

    res = client.get("/api/pitches/p0001")
    assert res.status_code == 200
    assert res.get_json()["id"] == "p0001"

    res = client.get("/api/pitches/missing")
    assert res.status_code == 404


def test_api_update_pitch_recomputes_count(tmp_path):
    client = create_app().test_client()
    _setup_with_timeline(
        client, tmp_path, [_pitch("p0001", 1.0, 2.0, outcome=PitchOutcome.TAKE, pitch_call=PitchCall.BALL)]
    )

    body = {
        "clip_start_sec": 1.0,
        "clip_end_sec": 2.0,
        "outcome": "take",
        "pitch_call": "strike",
        "in_play": {"result": "none", "outs_on_play": 0, "resolved_runners": None},
        "inning": 1,
        "half": "top",
        "needs_review": False,
        "notes": "",
    }
    res = client.post("/api/pitches/p0001", json=body)
    assert res.status_code == 200
    data = res.get_json()
    assert data["count_after"]["strikes"] == 1
    assert data["forward_filled_count"] == 0

    res2 = client.get("/api/pitches/p0001")
    assert res2.get_json()["pitch_call"] == "strike"


def test_api_update_pitch_rejects_invalid_time_range(tmp_path):
    client = create_app().test_client()
    _setup_with_timeline(client, tmp_path, [_pitch("p0001", 1.0, 2.0)])

    body = {
        "clip_start_sec": 2.0,
        "clip_end_sec": 1.0,
        "outcome": "take",
        "pitch_call": "ball",
        "in_play": {},
        "inning": 1,
        "half": "top",
    }
    res = client.post("/api/pitches/p0001", json=body)
    assert res.status_code == 400


def test_api_update_pitch_rejects_invalid_enum(tmp_path):
    client = create_app().test_client()
    _setup_with_timeline(client, tmp_path, [_pitch("p0001", 1.0, 2.0)])

    body = {
        "clip_start_sec": 1.0,
        "clip_end_sec": 2.0,
        "outcome": "not_a_real_outcome",
        "pitch_call": "ball",
        "in_play": {},
        "inning": 1,
        "half": "top",
    }
    res = client.post("/api/pitches/p0001", json=body)
    assert res.status_code == 400


def test_api_update_pitch_forward_fills_inning_half(tmp_path):
    client = create_app().test_client()
    _setup_with_timeline(
        client,
        tmp_path,
        [
            _pitch("p0001", 1.0, 2.0, inning=1, half="top"),
            _pitch("p0002", 3.0, 4.0, inning=1, half="top"),
            _pitch("p0003", 5.0, 6.0, inning=1, half="top"),
        ],
    )

    body = {
        "clip_start_sec": 1.0,
        "clip_end_sec": 2.0,
        "outcome": "take",
        "pitch_call": "ball",
        "in_play": {},
        "inning": 2,
        "half": "bottom",
        "apply_inning_half_forward": True,
    }
    res = client.post("/api/pitches/p0001", json=body)
    assert res.status_code == 200
    assert res.get_json()["forward_filled_count"] == 2

    p2 = client.get("/api/pitches/p0002").get_json()
    assert p2["inning"] == 2
    assert p2["half"] == "bottom"

    p3 = client.get("/api/pitches/p0003").get_json()
    assert p3["inning"] == 2
    assert p3["half"] == "bottom"


def test_api_video_main_returns_200_and_range_206(tmp_path):
    client = create_app().test_client()
    video_path = tmp_path / "main.mp4"
    _write_video(video_path)
    out_dir = tmp_path / "out"
    client.post(
        "/api/setup",
        json={"main_path": str(video_path), "wide_path": "", "out_dir": str(out_dir)},
    )

    res = client.get("/api/video/main")
    assert res.status_code == 200

    res2 = client.get("/api/video/main", headers={"Range": "bytes=0-"})
    assert res2.status_code == 206
