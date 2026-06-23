"""検出器を組み合わせて GameTimeline を構築する(detect)/編集後のタイムラインから
クリップとオーバーレイファイルを書き出す(render)、全体のオーケストレーション。

detect() はベストエフォートの自動検出結果を書き出すだけで確定値にはしない。
利用者がタイムラインJSON(またはCSVエクスポート→編集→インポート)を直接修正し、
render() を再実行すれば、修正内容を反映したクリップ/オーバーレイが再生成される。
"""

from __future__ import annotations

from pathlib import Path

from .config import PipelineConfig
from .detection.camera_selector import decide_camera_for_play
from .detection.pitcher_motion import detect_pitch_and_pickoff_candidates
from .detection.swing_contact import analyze_pitch_result
from .editor.clipper import cut_pitch_clip
from .overlay.overlay_writer import write_overlay_for_pitch
from .scoring import count_state
from .scoring.models import (
    CameraName,
    CameraSegment,
    GameTimeline,
    InPlayInfo,
    PitchEvent,
    PitchOutcome,
    VideoSources,
)
from .video_io import get_video_info


def detect(
    main_path: str,
    wide_path: str,
    config: PipelineConfig | None = None,
    wide_offset_sec: float = 0.0,
    start_sec: float = 0.0,
    end_sec: float | None = None,
) -> GameTimeline:
    config = config or PipelineConfig()

    main_info = get_video_info(main_path)
    wide_info = get_video_info(wide_path)
    video = VideoSources(
        main_path=str(main_path),
        wide_path=str(wide_path),
        main_fps=main_info.fps,
        wide_fps=wide_info.fps,
        wide_offset_sec=wide_offset_sec,
    )

    candidates, pickoffs = detect_pitch_and_pickoff_candidates(
        main_path, config.detection, start_sec=start_sec, end_sec=end_sec
    )

    pitches: list[PitchEvent] = []
    for i, cand in enumerate(candidates, start=1):
        result = analyze_pitch_result(main_path, cand.release_sec, config.detection)
        # 見逃し/空振りは捕球、打球は打音(コンタクト)を基準点として、その手前から
        # 切り出す(motion_start基準だとセット/ワインドアップの途中からしか映らないことがある)。
        anchor_sec = result.catch_reference_sec if result.catch_reference_sec is not None else result.contact_sec
        if anchor_sec is not None:
            clip_start = max(0.0, anchor_sec - config.detection.pre_roll_anchor_sec)
        else:
            clip_start = max(0.0, cand.motion_start_sec - config.detection.pre_roll_sec)

        pitch = PitchEvent(
            id=f"p{i:04d}",
            pitcher_motion_start_sec=cand.motion_start_sec,
            pitch_release_sec=cand.release_sec,
            clip_start_sec=clip_start,
            outcome=result.outcome,
            pitch_call=result.pitch_call,
            detection_confidence=min(cand.confidence, result.confidence),
            needs_review=cand.needs_review or result.needs_review,
        )

        if result.outcome == PitchOutcome.IN_PLAY:
            _fill_in_play(pitch, main_path, result.contact_sec or cand.release_sec, config)
        else:
            pitch.clip_end_sec = result.clip_end_sec
            pitch.segments = [
                CameraSegment(camera=CameraName.MAIN, start_sec=clip_start, end_sec=pitch.clip_end_sec)
            ]

        pitches.append(pitch)

    timeline = GameTimeline(video=video, pitches=pitches, pickoffs=pickoffs)
    count_state.recompute(timeline)
    return timeline


def _fill_in_play(
    pitch: PitchEvent,
    main_path: str,
    contact_sec: float,
    config: PipelineConfig,
) -> None:
    """打球発生後のカメラ選択を行う。プレー終了点は暫定的にcontact_sec+固定長とする。

    打球処理にかかる時間はプレーの種類(内野安打/長打/エラー処理等)で大きく異なり、
    静止検出ベースの自動推定(detect_play_end)は信頼性が低いため、当面は固定長
    (in_play_clip_duration_sec)を採用する。実際の試合映像で精度を確認しながら再検討する。
    """

    decision = decide_camera_for_play(main_path, contact_sec, config.detection)
    play_end_sec = contact_sec + config.detection.in_play_clip_duration_sec

    pitch.in_play = InPlayInfo(contact_sec=contact_sec, play_end_sec=play_end_sec)
    pitch.clip_end_sec = play_end_sec
    pitch.segments = [
        CameraSegment(camera=CameraName.MAIN, start_sec=pitch.clip_start_sec, end_sec=contact_sec),
        CameraSegment(camera=CameraName(decision.camera), start_sec=contact_sec, end_sec=play_end_sec),
    ]


def render(timeline: GameTimeline, output_dir: str, config: PipelineConfig | None = None) -> list[str]:
    config = config or PipelineConfig()
    count_state.recompute(timeline)

    output_root = Path(output_dir)
    clips_dir = output_root / "clips"
    overlays_dir = output_root / "overlays"
    clips_dir.mkdir(parents=True, exist_ok=True)
    overlays_dir.mkdir(parents=True, exist_ok=True)

    written = []
    for pitch in timeline.pitches:
        segments = _resolve_segments(pitch, timeline.video)
        clip_path = clips_dir / f"{pitch.id}.mp4"
        cut_pitch_clip(segments, clip_path, config.clip)
        write_overlay_for_pitch(pitch, clip_path, overlays_dir / f"{pitch.id}.overlay.json")
        written.append(str(clip_path))

    return written


def _resolve_segments(pitch: PitchEvent, video: VideoSources) -> list[tuple[str, float, float]]:
    """game_sec基準のsegmentsを、各カメラファイル上の実際の再生時刻に変換する。

    camera_override が指定されている場合は、区間全体を単一カメラに置き換える
    (例: 打球がまれにmainカメラで収まる場合に、wideへの自動切替を無効化できる)。
    """

    if pitch.camera_override is not None:
        segments = [
            CameraSegment(camera=pitch.camera_override, start_sec=pitch.clip_start_sec, end_sec=pitch.clip_end_sec)
        ]
    else:
        segments = pitch.segments or [
            CameraSegment(camera=CameraName.MAIN, start_sec=pitch.clip_start_sec, end_sec=pitch.clip_end_sec)
        ]

    resolved = []
    for seg in segments:
        if seg.camera == CameraName.MAIN:
            resolved.append((video.main_path, seg.start_sec, seg.end_sec))
        else:
            resolved.append(
                (video.wide_path, seg.start_sec + video.wide_offset_sec, seg.end_sec + video.wide_offset_sec)
            )
    return resolved
