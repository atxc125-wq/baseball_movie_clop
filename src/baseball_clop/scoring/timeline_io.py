"""タイムライン(GameTimeline)のJSON/CSV入出力。

JSON が正本フォーマット(segments・全フィールドを保持)。
CSV は「判定が難しく、人間が直したいフィールド」だけを抜き出した編集用ビュー。
Excel/スプレッドシートで pitch_call や in_play の結果を直し、import_csv() で
JSONへ反映してから count_state.recompute() を呼び直す、という運用を想定する。
カメラ切替の詳細な区間(segments)はCSVでは表現しないため、JSONを直接編集する。
"""

from __future__ import annotations

import csv
import json
import os
import tempfile
from pathlib import Path

from .models import GameTimeline, InPlayInfo, PitchCall, PitchOutcome, PlayResult, Runners

CSV_FIELDS = [
    "id",
    "inning",
    "half",
    "clip_start_sec",
    "clip_end_sec",
    "pitcher_motion_start_sec",
    "pitch_release_sec",
    "outcome",
    "pitch_call",
    "contact_sec",
    "play_end_sec",
    "in_play_result",
    "outs_on_play",
    "resolved_runner_1b",
    "resolved_runner_2b",
    "resolved_runner_3b",
    "camera_override",
    "needs_review",
    "detection_confidence",
    "notes",
    # 以下は参考表示専用。import_csv() では読み取らない(recompute()が再計算する)。
    "ref_count_after",
    "ref_runners_after",
]


def save_json(timeline: GameTimeline, path: str | Path) -> None:
    """正本JSONを書き出す。書き込み中のクラッシュでファイルが壊れないよう、
    同一ディレクトリの一時ファイルに書いてから os.replace() で原子的に置き換える。
    """

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(timeline.to_dict(), ensure_ascii=False, indent=2)

    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp_name, path)
    except BaseException:
        Path(tmp_name).unlink(missing_ok=True)
        raise


def load_json(path: str | Path) -> GameTimeline:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return GameTimeline.from_dict(data)


def _bool_str(v: bool) -> str:
    return "1" if v else "0"


def _parse_bool(s: str) -> bool:
    return s.strip().lower() in ("1", "true", "yes", "y", "on")


def export_csv(timeline: GameTimeline, path: str | Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for p in sorted(timeline.pitches, key=lambda x: x.clip_start_sec):
            resolved = p.in_play.resolved_runners
            writer.writerow(
                {
                    "id": p.id,
                    "inning": p.inning,
                    "half": p.half,
                    "clip_start_sec": p.clip_start_sec,
                    "clip_end_sec": p.clip_end_sec,
                    "pitcher_motion_start_sec": p.pitcher_motion_start_sec,
                    "pitch_release_sec": p.pitch_release_sec,
                    "outcome": p.outcome.value,
                    "pitch_call": p.pitch_call.value,
                    "contact_sec": p.in_play.contact_sec,
                    "play_end_sec": p.in_play.play_end_sec,
                    "in_play_result": p.in_play.result.value,
                    "outs_on_play": p.in_play.outs_on_play,
                    "resolved_runner_1b": _bool_str(resolved.first) if resolved else "",
                    "resolved_runner_2b": _bool_str(resolved.second) if resolved else "",
                    "resolved_runner_3b": _bool_str(resolved.third) if resolved else "",
                    "camera_override": p.camera_override.value if p.camera_override else "",
                    "needs_review": _bool_str(p.needs_review),
                    "detection_confidence": p.detection_confidence,
                    "notes": p.notes,
                    "ref_count_after": f"{p.count_after.balls}-{p.count_after.strikes}-{p.count_after.outs}",
                    "ref_runners_after": (
                        f"1B={_bool_str(p.runners_after.first)} "
                        f"2B={_bool_str(p.runners_after.second)} "
                        f"3B={_bool_str(p.runners_after.third)}"
                    ),
                }
            )


def import_csv(timeline: GameTimeline, path: str | Path) -> GameTimeline:
    """CSVの編集内容をタイムラインへマージする。id列でマッチし、判定系フィールドのみ上書きする。"""

    by_id = {p.id: p for p in timeline.pitches}
    with Path(path).open(newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            pitch = by_id.get(row["id"])
            if pitch is None:
                continue  # 未知のidは無視(削除/追加はJSON側で行う想定)

            pitch.inning = int(row["inning"])
            pitch.half = row["half"]
            pitch.clip_start_sec = float(row["clip_start_sec"])
            pitch.clip_end_sec = float(row["clip_end_sec"])
            pitch.pitcher_motion_start_sec = _opt_float(row.get("pitcher_motion_start_sec"))
            pitch.pitch_release_sec = _opt_float(row.get("pitch_release_sec"))
            pitch.outcome = PitchOutcome(row["outcome"])
            pitch.pitch_call = PitchCall(row["pitch_call"])

            pitch.in_play = InPlayInfo(
                contact_sec=_opt_float(row.get("contact_sec")),
                play_end_sec=_opt_float(row.get("play_end_sec")),
                result=PlayResult(row["in_play_result"]),
                outs_on_play=int(row["outs_on_play"] or 0),
                resolved_runners=_parse_resolved_runners(row),
            )

            camera_override = (row.get("camera_override") or "").strip()
            from .models import CameraName  # 局所importで循環を避ける

            pitch.camera_override = CameraName(camera_override) if camera_override else None

            pitch.needs_review = _parse_bool(row.get("needs_review", "0"))
            pitch.detection_confidence = float(row.get("detection_confidence") or 0.0)
            pitch.notes = row.get("notes", "")

    return timeline


def _opt_float(s: str | None) -> float | None:
    if s is None or s.strip() == "":
        return None
    return float(s)


def _parse_resolved_runners(row: dict[str, str]) -> Runners | None:
    cols = ("resolved_runner_1b", "resolved_runner_2b", "resolved_runner_3b")
    if all((row.get(c) or "").strip() == "" for c in cols):
        return None
    return Runners(
        first=_parse_bool(row.get("resolved_runner_1b", "")),
        second=_parse_bool(row.get("resolved_runner_2b", "")),
        third=_parse_bool(row.get("resolved_runner_3b", "")),
    )
