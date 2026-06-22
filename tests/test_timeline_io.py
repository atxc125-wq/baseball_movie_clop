from baseball_clop.scoring import count_state, timeline_io
from baseball_clop.scoring.models import (
    CameraName,
    GameTimeline,
    InPlayInfo,
    PickoffEvent,
    PitchCall,
    PitchEvent,
    PitchOutcome,
    PlayResult,
    VideoSources,
)


def _sample_timeline() -> GameTimeline:
    pitches = [
        PitchEvent(
            id="p1",
            clip_start_sec=9.0,
            clip_end_sec=12.0,
            pitcher_motion_start_sec=10.0,
            pitch_release_sec=10.8,
            outcome=PitchOutcome.TAKE,
            pitch_call=PitchCall.BALL,
            detection_confidence=0.4,
            needs_review=True,
            notes="自動検出",
        ),
        PitchEvent(
            id="p2",
            clip_start_sec=20.0,
            clip_end_sec=24.0,
            outcome=PitchOutcome.IN_PLAY,
            pitch_call=PitchCall.IN_PLAY,
            in_play=InPlayInfo(contact_sec=21.5, play_end_sec=24.0, result=PlayResult.SINGLE),
            camera_override=CameraName.MAIN,
        ),
    ]
    timeline = GameTimeline(
        video=VideoSources(main_path="m.mp4", wide_path="w.mp4", wide_offset_sec=1.2),
        pitches=pitches,
        pickoffs=[PickoffEvent(sec=5.0, target_base="1B")],
    )
    count_state.recompute(timeline)
    return timeline


def test_json_round_trip(tmp_path):
    timeline = _sample_timeline()
    path = tmp_path / "timeline.json"
    timeline_io.save_json(timeline, path)
    loaded = timeline_io.load_json(path)

    assert loaded.video.wide_offset_sec == 1.2
    assert len(loaded.pitches) == 2
    assert loaded.pitches[1].camera_override == CameraName.MAIN
    assert loaded.pitches[1].in_play.result == PlayResult.SINGLE
    assert loaded.pickoffs[0].target_base == "1B"


def test_csv_export_then_import_applies_corrections(tmp_path):
    timeline = _sample_timeline()
    csv_path = tmp_path / "timeline.csv"
    timeline_io.export_csv(timeline, csv_path)

    rows = csv_path.read_text(encoding="utf-8-sig").splitlines()
    assert rows[0].split(",")[0] == "id"

    # p1 の判定を ball -> strike に手動修正する想定をシミュレートする
    corrected = rows[0] + "\n" + "\n".join(
        line.replace("ball", "strike") if line.startswith("p1,") else line for line in rows[1:]
    )
    csv_path.write_text(corrected, encoding="utf-8-sig")

    updated = timeline_io.import_csv(timeline, csv_path)
    count_state.recompute(updated)

    p1 = next(p for p in updated.pitches if p.id == "p1")
    assert p1.pitch_call == PitchCall.STRIKE
    assert p1.count_after.strikes == 1
    assert p1.count_after.balls == 0
