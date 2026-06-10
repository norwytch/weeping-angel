from quantumlock.paradox import Outcome, WorldState, prove_no_paradox_free_move, step


def test_stone_when_believes_observed():
    assert step(WorldState(believes_observed=True, actually_observed=True)) is Outcome.STONE


def test_recorded_when_acts_under_observation():
    assert step(WorldState(believes_observed=False, actually_observed=True)) is Outcome.RECORDED


def test_unrecorded_move_only_without_observation():
    s = WorldState(believes_observed=False, actually_observed=False)
    assert step(s) is Outcome.UNRECORDED_MOVE


def test_paradox_holds_with_out_of_band_observation():
    proof = prove_no_paradox_free_move(actually_observed=True)
    assert proof.holds
    assert not proof.unsafe_state_reachable


def test_paradox_fails_without_out_of_band_observation():
    proof = prove_no_paradox_free_move(actually_observed=False)
    assert not proof.holds
