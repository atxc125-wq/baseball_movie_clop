from baseball_clop.detection.motion import MotionSample, find_local_peak, find_motion_rises, is_quiet_from


def _samples(scores, dt=0.1):
    return [MotionSample(t=i * dt, score=s) for i, s in enumerate(scores)]


def test_find_motion_rises_requires_minimum_still_period():
    # 0.0-0.5sは静止、0.6sで急上昇 -> 1イベント検出されるはず
    scores = [1, 1, 1, 1, 1, 1, 20, 20, 1, 1]
    samples = _samples(scores)
    events = find_motion_rises(samples, still_threshold=5, rise_threshold=15, min_still_sec=0.4)
    assert len(events) == 1
    assert abs(events[0] - 0.6) < 1e-6


def test_find_motion_rises_ignores_rise_before_minimum_still_period():
    # 静止期間が短すぎる(0.1s)ため、立ち上がりを検出しない
    scores = [1, 20, 20, 1, 1]
    samples = _samples(scores)
    events = find_motion_rises(samples, still_threshold=5, rise_threshold=15, min_still_sec=0.4)
    assert events == []


def test_find_motion_rises_detects_two_separate_bursts():
    scores = [1, 1, 1, 1, 1, 20, 20, 1, 1, 1, 1, 1, 20, 20, 1]
    samples = _samples(scores)
    events = find_motion_rises(samples, still_threshold=5, rise_threshold=15, min_still_sec=0.4)
    assert len(events) == 2


def test_find_local_peak_returns_max_within_window():
    samples = _samples([1, 5, 9, 3, 1])
    peak = find_local_peak(samples, start_t=0.1, end_t=0.3)
    assert peak.score == 9


def test_is_quiet_from_finds_sustained_low_motion():
    scores = [20, 20, 1, 1, 1, 1, 20]
    samples = _samples(scores)
    quiet_start = is_quiet_from(samples, after_t=0.0, quiet_threshold=5, min_quiet_sec=0.3)
    assert quiet_start is not None
    assert abs(quiet_start - 0.2) < 1e-6


def test_is_quiet_from_returns_none_when_never_settles():
    scores = [20, 20, 20, 20]
    samples = _samples(scores)
    quiet_start = is_quiet_from(samples, after_t=0.0, quiet_threshold=5, min_quiet_sec=0.3)
    assert quiet_start is None
