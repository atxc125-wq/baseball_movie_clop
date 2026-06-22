"""切り出したクリップに対して、SBO/ランナー等の表示用オーバーレイ情報を
クリップ自身の時間軸(0=クリップ開始)で別ファイルに出力する。

動画への焼き込みは行わない。後段の編集/再生ツールがこのタイムスタンプ付き
JSON/CSVを読み、クリップと同期させてオーバーレイ表示することを想定している。
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from ..scoring.models import PitchEvent


def build_overlay_keyframes(pitch: PitchEvent) -> list[dict[str, Any]]:
    duration = max(0.0, pitch.clip_end_sec - pitch.clip_start_sec)

    keyframes = [
        {
            "t": 0.0,
            "inning": pitch.inning,
            "half": pitch.half,
            "balls": pitch.count_before.balls,
            "strikes": pitch.count_before.strikes,
            "outs": pitch.count_before.outs,
            "runners": pitch.runners_before.to_dict(),
        }
    ]

    count_changed = pitch.count_after.to_dict() != pitch.count_before.to_dict()
    runners_changed = pitch.runners_after.to_dict() != pitch.runners_before.to_dict()
    if count_changed or runners_changed:
        change_t = duration
        if pitch.in_play.contact_sec is not None:
            change_t = max(0.0, min(duration, pitch.in_play.contact_sec - pitch.clip_start_sec))
        keyframes.append(
            {
                "t": change_t,
                "inning": pitch.inning,
                "half": pitch.half,
                "balls": pitch.count_after.balls,
                "strikes": pitch.count_after.strikes,
                "outs": pitch.count_after.outs,
                "runners": pitch.runners_after.to_dict(),
            }
        )

    return keyframes


def write_overlay_for_pitch(pitch: PitchEvent, clip_path: str | Path, overlay_json_path: str | Path) -> None:
    keyframes = build_overlay_keyframes(pitch)
    overlay_json_path = Path(overlay_json_path)
    overlay_json_path.parent.mkdir(parents=True, exist_ok=True)

    payload = {
        "clip_file": Path(clip_path).name,
        "pitch_id": pitch.id,
        "pitch_call": pitch.pitch_call.value,
        "outcome": pitch.outcome.value,
        "needs_review": pitch.needs_review,
        "keyframes": keyframes,
    }
    overlay_json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    csv_path = overlay_json_path.with_suffix(".csv")
    with csv_path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(["t", "inning", "half", "balls", "strikes", "outs", "1B", "2B", "3B"])
        for kf in keyframes:
            runners = kf["runners"]
            writer.writerow(
                [
                    kf["t"], kf["inning"], kf["half"], kf["balls"], kf["strikes"], kf["outs"],
                    int(runners["1B"]), int(runners["2B"]), int(runners["3B"]),
                ]
            )
