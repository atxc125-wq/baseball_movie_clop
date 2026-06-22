"""ffmpegを使ったクリップ切り出し。

segments は [(入力ファイルパス, 開始秒, 終了秒), ...] で、各カメラの
ファイル上の実際の秒数(game_sec→ファイル秒への変換済み)を渡す。

mainは4K・wideはHDなど解像度が異なるため、複数区間(カメラ切替を含む)は
output_width/height/fpsへ揃えてからconcatフィルタで1本に結合する。
ffmpegの `-ss`(入力オプション)はデフォルトで accurate_seek が有効なため、
追加のtrimフィルタなしで `-ss/-t` のみでフレーム精度のカットが得られる。
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from ..config import ClipConfig

Segment = tuple[str, float, float]


def cut_pitch_clip(segments: list[Segment], output_path: str | Path, config: ClipConfig) -> None:
    if not segments:
        raise ValueError("segmentsが空です")

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if len(segments) == 1 and not config.accurate_seek:
        _cut_single_fast(segments[0], output_path)
        return

    _cut_with_filter_complex(segments, output_path, config)


def _ffmpeg_bin() -> str:
    path = shutil.which("ffmpeg")
    if path is None:
        raise RuntimeError("ffmpegが見つかりません。インストールしてください。")
    return path


def _has_audio_stream(path: str) -> bool:
    ffprobe = shutil.which("ffprobe")
    if ffprobe is None:
        return False
    result = subprocess.run(
        [
            ffprobe, "-v", "error", "-select_streams", "a",
            "-show_entries", "stream=index", "-of", "json", str(path),
        ],
        capture_output=True, text=True, check=False,
    )
    try:
        return bool(json.loads(result.stdout or "{}").get("streams"))
    except json.JSONDecodeError:
        return False


def _cut_single_fast(segment: Segment, output_path: Path) -> None:
    src, start, end = segment
    duration = max(0.0, end - start)
    cmd = [
        _ffmpeg_bin(), "-y",
        "-ss", f"{start:.3f}", "-i", str(src), "-t", f"{duration:.3f}",
        "-c", "copy", str(output_path),
    ]
    subprocess.run(cmd, check=True, capture_output=True)


def _cut_with_filter_complex(segments: list[Segment], output_path: Path, config: ClipConfig) -> None:
    include_audio = config.include_audio and all(_has_audio_stream(s[0]) for s in segments)

    cmd = [_ffmpeg_bin(), "-y"]
    for src, start, end in segments:
        duration = max(0.01, end - start)
        cmd += ["-ss", f"{start:.3f}", "-t", f"{duration:.3f}", "-i", str(src)]

    filter_parts = []
    concat_inputs = []
    for i in range(len(segments)):
        scale = (
            f"[{i}:v]scale={config.output_width}:{config.output_height}:force_original_aspect_ratio=decrease,"
            f"pad={config.output_width}:{config.output_height}:(ow-iw)/2:(oh-ih)/2,"
            f"setsar=1,fps={config.output_fps}[v{i}]"
        )
        filter_parts.append(scale)
        concat_inputs.append(f"[v{i}]")
        if include_audio:
            filter_parts.append(f"[{i}:a]asetpts=PTS-STARTPTS[a{i}]")
            concat_inputs.append(f"[a{i}]")

    n = len(segments)
    a_flag = 1 if include_audio else 0
    concat_outputs = "[outv][outa]" if include_audio else "[outv]"
    concat_str = "".join(concat_inputs) + f"concat=n={n}:v=1:a={a_flag}{concat_outputs}"
    filter_complex = ";".join(filter_parts) + ";" + concat_str

    cmd += ["-filter_complex", filter_complex, "-map", "[outv]"]
    if include_audio:
        cmd += ["-map", "[outa]"]

    cmd += ["-c:v", config.video_codec, "-crf", str(config.crf), "-preset", config.preset]
    if include_audio:
        cmd += ["-c:a", "aac"]
    cmd += [str(output_path)]

    subprocess.run(cmd, check=True, capture_output=True)
