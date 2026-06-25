"""音声波形の相互相関によるメイン/ワイド映像の時刻ズレ(wide_offset_sec)推定。

メインとワイドのカメラは録画開始タイミングが毎回ズレるため、`wide_offset_sec` を
都度手動で目合わせするのは手間がかかり精度も出にくい。両方の映像に同じ試合の
環境音が入っている前提で、先頭付近の音声波形を相互相関させ、最も一致するラグを
探すことでオフセットを推定する。

ffmpegで低サンプルレートのモノラルPCMに変換してから比較することで、解析対象の
データ量を抑えつつ、ffmpeg/ffprobeという既存の必須外部依存だけで実現する。
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import numpy as np

from .editor.clipper import _ffmpeg_bin, _has_audio_stream

SAMPLE_RATE = 8000


@dataclass
class AudioSyncResult:
    offset_sec: float
    confidence: float  # 0.0〜1.0の目安。相関ピークが基準線からどれだけ突出しているか。


def estimate_offset(
    main_path: str | Path,
    wide_path: str | Path,
    duration_sec: float = 30.0,
    max_offset_sec: float = 20.0,
) -> AudioSyncResult:
    """main/wide映像の先頭付近の音声を相互相関し、wide_offset_secを推定する。

    wide_offset_secの定義(scoring.models.VideoSources): wide_file_sec = main_game_sec
    + wide_offset_sec。両映像の音声波形が一致するラグからこれを直接計算する。
    """
    if shutil.which("ffprobe") is None:
        # _has_audio_streamはffprobe未インストール時にもFalseを返す(render側では音声無しとして
        # 静かに縮退させたいため)。ここでは「音声トラックが無い」と誤解させないよう先に区別する。
        raise ValueError("ffprobeが見つかりません。ffmpeg(ffprobeを含む)をインストールしてください。")
    if not _has_audio_stream(str(main_path)) or not _has_audio_stream(str(wide_path)):
        raise ValueError("メインまたはワイド映像に音声トラックがありません")

    main_audio = _extract_audio(main_path, duration_sec)
    wide_audio = _extract_audio(wide_path, duration_sec)

    if len(main_audio) < SAMPLE_RATE or len(wide_audio) < SAMPLE_RATE:
        raise ValueError("音声データが短すぎて同期を推定できません")

    main_audio = main_audio - main_audio.mean()
    wide_audio = wide_audio - wide_audio.mean()

    correlation = _full_correlate(main_audio, wide_audio)
    lags = np.arange(-(len(wide_audio) - 1), len(main_audio))

    max_lag_samples = int(max_offset_sec * SAMPLE_RATE)
    in_range = np.abs(lags) <= max_lag_samples
    window = correlation[in_range]
    window_lags = lags[in_range]

    abs_window = np.abs(window)
    best_idx = int(np.argmax(abs_window))
    best_lag = int(window_lags[best_idx])

    peak = float(abs_window[best_idx])
    baseline = float(np.median(abs_window))
    confidence = float(np.clip((peak - baseline) / (peak + 1e-9), 0.0, 1.0))

    return AudioSyncResult(offset_sec=-best_lag / SAMPLE_RATE, confidence=confidence)


def _extract_audio(path: str | Path, duration_sec: float) -> np.ndarray:
    """先頭からduration_sec秒分のモノラルPCM(float32, SAMPLE_RATE Hz)を取り出す。"""
    cmd = [
        _ffmpeg_bin(), "-y", "-i", str(path),
        "-t", f"{duration_sec:.3f}",
        "-ac", "1", "-ar", str(SAMPLE_RATE),
        "-f", "f32le", "-",
    ]
    result = subprocess.run(cmd, capture_output=True, check=True)
    return np.frombuffer(result.stdout, dtype=np.float32)


def _full_correlate(a: np.ndarray, v: np.ndarray) -> np.ndarray:
    """np.correlate(a, v, mode="full") と同義のFFTベース実装(大きな配列でも高速)。"""
    n = len(a) + len(v) - 1
    size = 1 << (n - 1).bit_length()
    fa = np.fft.rfft(a, size)
    fv = np.fft.rfft(v[::-1], size)
    return np.fft.irfft(fa * fv, size)[:n]
