from baseball_clop.scoring import count_state
from baseball_clop.scoring.models import (
    GameTimeline,
    InPlayInfo,
    PitchCall,
    PitchEvent,
    PitchOutcome,
    PlayResult,
    Runners,
)


def _pitch(id_, t, outcome, pitch_call=PitchCall.UNKNOWN, in_play=None, inning=1, half="top"):
    return PitchEvent(
        id=id_,
        clip_start_sec=t,
        clip_end_sec=t + 2,
        outcome=outcome,
        pitch_call=pitch_call,
        in_play=in_play or InPlayInfo(),
        inning=inning,
        half=half,
    )


def test_strikeout_resets_count_and_adds_out():
    pitches = [
        _pitch("p1", 0, PitchOutcome.TAKE, PitchCall.STRIKE),
        _pitch("p2", 10, PitchOutcome.TAKE, PitchCall.STRIKE),
        _pitch("p3", 20, PitchOutcome.SWING_MISS, PitchCall.STRIKE),
    ]
    timeline = GameTimeline(pitches=pitches)
    count_state.recompute(timeline)

    assert pitches[0].count_after.strikes == 1
    assert pitches[1].count_after.strikes == 2
    assert pitches[2].count_after.outs == 1
    assert pitches[2].count_after.balls == 0
    assert pitches[2].count_after.strikes == 0


def test_foul_does_not_strike_out_batter():
    pitches = [
        _pitch("p1", 0, PitchOutcome.TAKE, PitchCall.STRIKE),
        _pitch("p2", 10, PitchOutcome.TAKE, PitchCall.STRIKE),
        _pitch("p3", 20, PitchOutcome.FOUL, PitchCall.FOUL),
        _pitch("p4", 30, PitchOutcome.FOUL, PitchCall.FOUL),
    ]
    timeline = GameTimeline(pitches=pitches)
    count_state.recompute(timeline)

    assert pitches[2].count_after.strikes == 2
    assert pitches[3].count_after.strikes == 2  # 2巡目以降のファウルは増えない
    assert pitches[3].count_after.outs == 0


def test_consecutive_walks_load_the_bases_and_force_a_run():
    # 4者連続四球: 1人目は1塁、2人目で1-2塁、3人目で満塁、4人目(満塁押し出し)で
    # 3塁ランナーが得点して退き、1-2-3塁は埋まったまま継続する。
    pitches = []
    t = 0
    for batter in range(4):
        for _ in range(4):
            pitches.append(_pitch(f"p{t}", t, PitchOutcome.TAKE, PitchCall.BALL))
            t += 10

    timeline = GameTimeline(pitches=pitches)
    count_state.recompute(timeline)

    last = pitches[-1]
    assert last.count_after.balls == 0
    assert last.runners_after.first is True
    assert last.runners_after.second is True
    assert last.runners_after.third is True
    assert last.count_after.outs == 0


def test_single_advances_runner_and_resolves_count():
    pitches = [
        _pitch("p1", 0, PitchOutcome.TAKE, PitchCall.BALL),
        _pitch("p2", 10, PitchOutcome.TAKE, PitchCall.BALL),
        _pitch("p3", 20, PitchOutcome.TAKE, PitchCall.BALL),
        _pitch("p4", 30, PitchOutcome.TAKE, PitchCall.BALL),  # walk -> runner on 1B
        _pitch(
            "p5",
            40,
            PitchOutcome.IN_PLAY,
            PitchCall.IN_PLAY,
            in_play=InPlayInfo(contact_sec=41, result=PlayResult.SINGLE, outs_on_play=0),
        ),
    ]
    timeline = GameTimeline(pitches=pitches)
    count_state.recompute(timeline)

    assert pitches[3].runners_after.first is True
    assert pitches[4].runners_after.first is True  # 打者が1塁へ
    assert pitches[4].runners_after.second is True  # 前の走者が2塁へ進塁
    assert pitches[4].count_after.balls == 0
    assert pitches[4].count_after.strikes == 0


def test_third_out_resets_count_and_runners_for_next_pitch_same_half():
    pitches = [
        _pitch("p1", 0, PitchOutcome.IN_PLAY, in_play=InPlayInfo(result=PlayResult.OUT, outs_on_play=1)),
        _pitch("p2", 10, PitchOutcome.IN_PLAY, in_play=InPlayInfo(result=PlayResult.OUT, outs_on_play=1)),
        _pitch("p3", 20, PitchOutcome.IN_PLAY, in_play=InPlayInfo(result=PlayResult.OUT, outs_on_play=1)),
        _pitch("p4", 30, PitchOutcome.TAKE, PitchCall.BALL),
    ]
    timeline = GameTimeline(pitches=pitches)
    count_state.recompute(timeline)

    assert pitches[2].count_after.outs == 3
    assert pitches[3].count_before.outs == 0
    assert pitches[3].count_before.balls == 0
    assert pitches[3].runners_before.first is False


def test_resolved_runners_override_wins_over_heuristic():
    pitches = [
        _pitch(
            "p1",
            0,
            PitchOutcome.IN_PLAY,
            in_play=InPlayInfo(
                result=PlayResult.ERROR,
                outs_on_play=0,
                resolved_runners=Runners(first=False, second=False, third=True),
            ),
        ),
    ]
    timeline = GameTimeline(pitches=pitches)
    count_state.recompute(timeline)

    assert pitches[0].runners_after.third is True
    assert pitches[0].runners_after.first is False


def test_half_inning_change_resets_state_even_without_three_outs():
    pitches = [
        _pitch("p1", 0, PitchOutcome.TAKE, PitchCall.BALL, inning=1, half="top"),
        _pitch("p2", 10, PitchOutcome.TAKE, PitchCall.BALL, inning=1, half="bottom"),
    ]
    timeline = GameTimeline(pitches=pitches)
    count_state.recompute(timeline)

    assert pitches[1].count_before.balls == 0
