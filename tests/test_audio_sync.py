import wave

import cv2
import numpy as np
import pytest

from baseball_clop import audio_sync

SAMPLE_RATE = audio_sync.SAMPLE_RATE


def _write_wav(path, samples: np.ndarray, sample_rate: int) -> None:
    pcm = np.clip(samples * 32767, -32768, 32767).astype(np.int16)
    with wave.open(str(path), "wb") as f:
        f.setnchannels(1)
        f.setsampwidth(2)
        f.setframerate(sample_rate)
        f.writeframes(pcm.tobytes())


def _write_silent_video(path, n_frames=5):
    writer = cv2.VideoWriter(str(path), cv2.VideoWriter_fourcc(*"mp4v"), 10, (160, 120))
    for i in range(n_frames):
        writer.write(np.full((120, 160, 3), i, dtype=np.uint8))
    writer.release()


def test_full_correlate_matches_numpy():
    rng = np.random.default_rng(1)
    a = rng.standard_normal(173)
    b = rng.standard_normal(96)

    expected = np.correlate(a, b, mode="full")
    actual = audio_sync._full_correlate(a, b)

    assert np.allclose(actual, expected, atol=1e-6)


def test_estimate_offset_recovers_known_shift(tmp_path):
    rng = np.random.default_rng(0)
    base = (rng.standard_normal(SAMPLE_RATE * 12) * 0.5).astype(np.float32)

    # ワイドが本編(main)より2.5秒遅れて録画を始めた = wide_offset_sec は -2.5 になるはず。
    shift_samples = int(2.5 * SAMPLE_RATE)
    main_samples = base[: SAMPLE_RATE * 10]
    wide_samples = base[shift_samples : shift_samples + SAMPLE_RATE * 8]

    main_wav = tmp_path / "main.wav"
    wide_wav = tmp_path / "wide.wav"
    _write_wav(main_wav, main_samples, SAMPLE_RATE)
    _write_wav(wide_wav, wide_samples, SAMPLE_RATE)

    result = audio_sync.estimate_offset(main_wav, wide_wav, duration_sec=10.0, max_offset_sec=10.0)

    assert abs(result.offset_sec - (-2.5)) < 0.05
    assert result.confidence > 0.3


def test_estimate_offset_raises_without_audio_track(tmp_path):
    video_path = tmp_path / "video.mp4"
    _write_silent_video(video_path)

    wav_path = tmp_path / "audio.wav"
    _write_wav(wav_path, np.zeros(SAMPLE_RATE, dtype=np.float32), SAMPLE_RATE)

    with pytest.raises(ValueError):
        audio_sync.estimate_offset(video_path, wav_path)


def test_estimate_offset_raises_distinct_error_when_ffprobe_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(audio_sync.shutil, "which", lambda name: None)

    with pytest.raises(ValueError, match="ffprobe"):
        audio_sync.estimate_offset(tmp_path / "main.mp4", tmp_path / "wide.mp4")
