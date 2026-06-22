"""イベントタイムラインのデータモデル。

このタイムライン(JSON/CSV)が全パイプラインの「正本(source of truth)」になる。
検出器はこのファイルを書き出すだけで、カウントやランナーの最終確定値は
scoring.count_state.recompute() が決定的に再計算する。そのため、利用者は
pitch_call や play_result など「判定」フィールドだけを手で直せば、カウント/
ランナーの伝播は自動的に整合する。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class PitchOutcome(str, Enum):
    TAKE = "take"  # 見逃し(ストライク/ボールは pitch_call で判定)
    SWING_MISS = "swing_miss"  # 空振り
    FOUL = "foul"
    IN_PLAY = "in_play"
    UNKNOWN = "unknown"


class PitchCall(str, Enum):
    BALL = "ball"
    STRIKE = "strike"
    FOUL = "foul"
    IN_PLAY = "in_play"
    UNKNOWN = "unknown"


class PlayResult(str, Enum):
    NONE = "none"  # まだプレーが続いている/該当しない
    OUT = "out"
    SINGLE = "single"
    DOUBLE = "double"
    TRIPLE = "triple"
    HOME_RUN = "home_run"
    WALK = "walk"
    STRIKEOUT = "strikeout"
    ERROR = "error"
    FIELDERS_CHOICE = "fielders_choice"
    SACRIFICE = "sacrifice"
    UNKNOWN = "unknown"


class CameraName(str, Enum):
    MAIN = "main"
    WIDE = "wide"


@dataclass
class Count:
    balls: int = 0
    strikes: int = 0
    outs: int = 0

    def to_dict(self) -> dict[str, int]:
        return {"balls": self.balls, "strikes": self.strikes, "outs": self.outs}

    @staticmethod
    def from_dict(d: Optional[dict[str, Any]]) -> "Count":
        d = d or {}
        return Count(balls=d.get("balls", 0), strikes=d.get("strikes", 0), outs=d.get("outs", 0))


@dataclass
class Runners:
    first: bool = False
    second: bool = False
    third: bool = False

    def to_dict(self) -> dict[str, bool]:
        return {"1B": self.first, "2B": self.second, "3B": self.third}

    @staticmethod
    def from_dict(d: Optional[dict[str, Any]]) -> "Runners":
        d = d or {}
        return Runners(first=d.get("1B", False), second=d.get("2B", False), third=d.get("3B", False))

    def copy(self) -> "Runners":
        return Runners(self.first, self.second, self.third)


@dataclass
class CameraSegment:
    """1区間の映像ソース。game_sec は main カメラの再生時刻を基準にした共通時間軸。"""

    camera: CameraName
    start_sec: float
    end_sec: float
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "camera": self.camera.value,
            "start_sec": self.start_sec,
            "end_sec": self.end_sec,
            "note": self.note,
        }

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "CameraSegment":
        return CameraSegment(
            camera=CameraName(d["camera"]),
            start_sec=d["start_sec"],
            end_sec=d["end_sec"],
            note=d.get("note", ""),
        )


@dataclass
class InPlayInfo:
    contact_sec: Optional[float] = None
    play_end_sec: Optional[float] = None
    result: PlayResult = PlayResult.NONE
    # このプレーで記録するアウト数。検出側の暫定値で、誤りがあればそのまま上書きしてよい。
    outs_on_play: int = 0
    # 確定済みのランナー配置。None なら result から簡易ヒューリスティックで自動推定する。
    # 通常と違う進塁(タッチアップ、走者間の判断ミス等)があった場合はここを直接指定する。
    resolved_runners: Optional[Runners] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "contact_sec": self.contact_sec,
            "play_end_sec": self.play_end_sec,
            "result": self.result.value,
            "outs_on_play": self.outs_on_play,
            "resolved_runners": self.resolved_runners.to_dict() if self.resolved_runners else None,
        }

    @staticmethod
    def from_dict(d: Optional[dict[str, Any]]) -> "InPlayInfo":
        d = d or {}
        resolved = d.get("resolved_runners")
        return InPlayInfo(
            contact_sec=d.get("contact_sec"),
            play_end_sec=d.get("play_end_sec"),
            result=PlayResult(d.get("result", "none")),
            outs_on_play=d.get("outs_on_play", 0),
            resolved_runners=Runners.from_dict(resolved) if resolved else None,
        )


@dataclass
class PitchEvent:
    id: str
    inning: int = 1
    half: str = "top"  # "top" or "bottom"

    pitcher_motion_start_sec: Optional[float] = None
    pitch_release_sec: Optional[float] = None
    clip_start_sec: float = 0.0
    clip_end_sec: float = 0.0

    outcome: PitchOutcome = PitchOutcome.UNKNOWN
    pitch_call: PitchCall = PitchCall.UNKNOWN
    in_play: InPlayInfo = field(default_factory=InPlayInfo)

    # 切り出しに使う映像ソース区間。複数あれば自動で連結される(カメラ切替対応)。
    segments: list[CameraSegment] = field(default_factory=list)
    camera_override: Optional[CameraName] = None  # 設定すると segments のカメラ選択を上書き

    count_before: Count = field(default_factory=Count)
    count_after: Count = field(default_factory=Count)
    runners_before: Runners = field(default_factory=Runners)
    runners_after: Runners = field(default_factory=Runners)

    detection_confidence: float = 0.0
    needs_review: bool = True
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "inning": self.inning,
            "half": self.half,
            "pitcher_motion_start_sec": self.pitcher_motion_start_sec,
            "pitch_release_sec": self.pitch_release_sec,
            "clip_start_sec": self.clip_start_sec,
            "clip_end_sec": self.clip_end_sec,
            "outcome": self.outcome.value,
            "pitch_call": self.pitch_call.value,
            "in_play": self.in_play.to_dict(),
            "segments": [s.to_dict() for s in self.segments],
            "camera_override": self.camera_override.value if self.camera_override else None,
            "count_before": self.count_before.to_dict(),
            "count_after": self.count_after.to_dict(),
            "runners_before": self.runners_before.to_dict(),
            "runners_after": self.runners_after.to_dict(),
            "detection_confidence": self.detection_confidence,
            "needs_review": self.needs_review,
            "notes": self.notes,
        }

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "PitchEvent":
        override = d.get("camera_override")
        return PitchEvent(
            id=d["id"],
            inning=d.get("inning", 1),
            half=d.get("half", "top"),
            pitcher_motion_start_sec=d.get("pitcher_motion_start_sec"),
            pitch_release_sec=d.get("pitch_release_sec"),
            clip_start_sec=d.get("clip_start_sec", 0.0),
            clip_end_sec=d.get("clip_end_sec", 0.0),
            outcome=PitchOutcome(d.get("outcome", "unknown")),
            pitch_call=PitchCall(d.get("pitch_call", "unknown")),
            in_play=InPlayInfo.from_dict(d.get("in_play")),
            segments=[CameraSegment.from_dict(s) for s in d.get("segments", [])],
            camera_override=CameraName(override) if override else None,
            count_before=Count.from_dict(d.get("count_before")),
            count_after=Count.from_dict(d.get("count_after")),
            runners_before=Runners.from_dict(d.get("runners_before")),
            runners_after=Runners.from_dict(d.get("runners_after")),
            detection_confidence=d.get("detection_confidence", 0.0),
            needs_review=d.get("needs_review", True),
            notes=d.get("notes", ""),
        )


@dataclass
class PickoffEvent:
    """セットに入る前/入った後の牽制球。カウントには影響しないため別リストで管理する。"""

    sec: float
    target_base: str = "unknown"  # "1B" / "2B" / "3B" / "unknown"
    detection_confidence: float = 0.0
    needs_review: bool = True
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "sec": self.sec,
            "target_base": self.target_base,
            "detection_confidence": self.detection_confidence,
            "needs_review": self.needs_review,
            "notes": self.notes,
        }

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "PickoffEvent":
        return PickoffEvent(
            sec=d["sec"],
            target_base=d.get("target_base", "unknown"),
            detection_confidence=d.get("detection_confidence", 0.0),
            needs_review=d.get("needs_review", True),
            notes=d.get("notes", ""),
        )


@dataclass
class VideoSources:
    main_path: str = ""
    wide_path: str = ""
    main_fps: float = 30.0
    wide_fps: float = 30.0
    # wide_file_sec = game_sec + wide_offset_sec (game_sec は main の再生時刻が基準)
    wide_offset_sec: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "main_path": self.main_path,
            "wide_path": self.wide_path,
            "main_fps": self.main_fps,
            "wide_fps": self.wide_fps,
            "wide_offset_sec": self.wide_offset_sec,
        }

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "VideoSources":
        return VideoSources(
            main_path=d.get("main_path", ""),
            wide_path=d.get("wide_path", ""),
            main_fps=d.get("main_fps", 30.0),
            wide_fps=d.get("wide_fps", 30.0),
            wide_offset_sec=d.get("wide_offset_sec", 0.0),
        )


@dataclass
class GameTimeline:
    video: VideoSources = field(default_factory=VideoSources)
    pitches: list[PitchEvent] = field(default_factory=list)
    pickoffs: list[PickoffEvent] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "video": self.video.to_dict(),
            "pitches": [p.to_dict() for p in self.pitches],
            "pickoffs": [p.to_dict() for p in self.pickoffs],
        }

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "GameTimeline":
        return GameTimeline(
            video=VideoSources.from_dict(d.get("video", {})),
            pitches=[PitchEvent.from_dict(p) for p in d.get("pitches", [])],
            pickoffs=[PickoffEvent.from_dict(p) for p in d.get("pickoffs", [])],
        )
