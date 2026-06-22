"""カウント(S/B/O)とランナー状況の決定的な再計算。

検出器(detection/*)はタイムラインに pitch_call や in_play.result といった
「判定」だけを書き込み、count_before/after・runners_before/after は常にこの
モジュールが先頭から順に再計算する。これにより、利用者がタイムラインJSON/CSVの
判定フィールドを修正して recompute() を再実行するだけで、以降のカウント/ランナー
表示がすべて整合した状態に直る。
"""

from __future__ import annotations

from .models import Count, GameTimeline, PitchCall, PitchEvent, PitchOutcome, PlayResult, Runners

_BASES_ADVANCED = {
    PlayResult.SINGLE: 1,
    PlayResult.DOUBLE: 2,
    PlayResult.TRIPLE: 3,
    PlayResult.HOME_RUN: 4,
    PlayResult.ERROR: 1,
    PlayResult.FIELDERS_CHOICE: 1,
    PlayResult.SACRIFICE: 0,
}


def _advance_runners_simple(runners: Runners, batter_bases: int) -> Runners:
    """打者と同じ進塁数だけ既存ランナーも進める簡易ヒューリスティック。

    実際の進塁は打球方向・タッチアップ判断などで異なるため、これは
    あくまで暫定値。特殊なプレーは PitchEvent.in_play.resolved_runners で
    直接指定して上書きすること。
    """

    occupied = [runners.first, runners.second, runners.third]
    new_bases = [False, False, False]  # index 0=1B,1=2B,2=3B
    for base_idx, was_on in enumerate(occupied):
        if not was_on:
            continue
        dest = base_idx + batter_bases  # 0-indexedの塁 + 進塁数
        if dest < 3:
            new_bases[dest] = True
        # dest >= 3 ならホームイン(得点。本パイプラインでは得点は追跡しない)
    if 0 <= batter_bases - 1 < 3:
        new_bases[batter_bases - 1] = True
    return Runners(first=new_bases[0], second=new_bases[1], third=new_bases[2])


def _apply_pitch(pitch: PitchEvent, count: Count, runners: Runners) -> tuple[Count, Runners]:
    count = Count(count.balls, count.strikes, count.outs)
    runners = runners.copy()

    if pitch.outcome == PitchOutcome.IN_PLAY:
        runners, outs_delta = _apply_in_play(pitch, runners)
        count.outs += outs_delta
        count.balls = 0
        count.strikes = 0
        return count, runners

    if pitch.outcome in (PitchOutcome.SWING_MISS,) or pitch.pitch_call == PitchCall.STRIKE:
        count.strikes += 1
    elif pitch.outcome == PitchOutcome.FOUL or pitch.pitch_call == PitchCall.FOUL:
        if count.strikes < 2:
            count.strikes += 1
    elif pitch.pitch_call == PitchCall.BALL:
        count.balls += 1
    # PitchCall.UNKNOWN: 判定待ちのため何も加算しない(needs_review で要確認扱い)

    if count.strikes >= 3:
        count.outs += 1
        count.balls = 0
        count.strikes = 0
    elif count.balls >= 4:
        runners = _walk_force(runners)
        count.balls = 0
        count.strikes = 0

    return count, runners


def _walk_force(runners: Runners) -> Runners:
    """満塁押し出し等、四球による強制進塁。"""
    first, second, third = runners.first, runners.second, runners.third
    new_third = third or (second and first)
    new_second = second or first
    new_first = True
    return Runners(first=new_first, second=new_second, third=new_third)


def _apply_in_play(pitch: PitchEvent, runners: Runners) -> tuple[Runners, int]:
    info = pitch.in_play
    outs_delta = info.outs_on_play

    if info.resolved_runners is not None:
        return info.resolved_runners.copy(), outs_delta

    if info.result == PlayResult.SACRIFICE:
        return _advance_runners_simple(runners, batter_bases=0), outs_delta
    if info.result in _BASES_ADVANCED:
        return _advance_runners_simple(runners, batter_bases=_BASES_ADVANCED[info.result]), outs_delta

    # OUT / UNKNOWN / NONE 等: ランナーは現状維持(要レビュー)
    return runners, outs_delta


def recompute(timeline: GameTimeline) -> GameTimeline:
    """全投球を時系列順に走査し、count_before/after・runners_before/after を確定する。"""

    pitches = sorted(timeline.pitches, key=lambda p: p.clip_start_sec)

    count = Count()
    runners = Runners()
    prev_half_key: tuple[int, str] | None = None
    prev_outs_after = 0

    for pitch in pitches:
        half_key = (pitch.inning, pitch.half)
        if half_key != prev_half_key or prev_outs_after >= 3:
            count = Count()
            runners = Runners()

        pitch.count_before = Count(count.balls, count.strikes, count.outs)
        pitch.runners_before = runners.copy()

        count, runners = _apply_pitch(pitch, count, runners)

        pitch.count_after = Count(count.balls, count.strikes, count.outs)
        pitch.runners_after = runners.copy()

        prev_half_key = half_key
        prev_outs_after = count.outs

    timeline.pitches = pitches
    return timeline
