from quantumlock.arena import (
    CAUGHT,
    CORRUPTED,
    ArenaConfig,
    BlueAgent,
    RandomBlue,
    RushRed,
    SpreadRed,
    play,
    tournament,
)
from quantumlock.detector import DivergenceDetector
from quantumlock.ledger import Ledger
from quantumlock.witnesses import MACE, DisplayWitness, JournalWitness, MFTWitness


class CoverAll(BlueAgent):
    """Covers as many files as the budget allows, lowest indices first."""

    def coverage(self, tick, observations):
        return range(self.config.coverage_budget)


class CoverNothing(BlueAgent):
    def coverage(self, tick, observations):
        return []


def test_deterministic_for_seed():
    cfg = ArenaConfig(seed=7)
    a = play(RandomBlue(), RushRed(), cfg)
    b = play(RandomBlue(), RushRed(), cfg)
    assert (a.caught, a.corrupted, a.time_to_corruption) == (
        b.caught,
        b.corrupted,
        b.time_to_corruption,
    )


def test_every_angel_resolves_or_stays_dormant():
    cfg = ArenaConfig()
    r = play(RandomBlue(), RushRed(), cfg)
    assert r.caught + r.corrupted + r.dormant == cfg.n_angels


def test_no_coverage_means_every_move_corrupts():
    # Rush moves all angels at tick 0; with zero coverage none can be caught.
    cfg = ArenaConfig(coverage_budget=0)
    r = play(CoverNothing(), RushRed(), cfg)
    assert r.caught == 0
    assert r.corrupted == cfg.n_angels
    assert r.time_to_corruption == 0


def test_full_coverage_of_angel_files_catches_rush():
    # All angels sit on distinct files; budget >= n_files guarantees the whole
    # filesystem is covered, so a tick-0 rush is fully caught.
    cfg = ArenaConfig(n_files=5, n_angels=5, coverage_budget=5)
    r = play(CoverAll(), RushRed(), cfg)
    assert r.caught == 5
    assert r.corrupted == 0


def test_budget_is_enforced_even_if_agent_overreaches():
    class Greedy(BlueAgent):
        def coverage(self, tick, observations):
            return range(self.config.n_files * 2)  # ask for everything, twice

    cfg = ArenaConfig(n_files=10, n_angels=6, coverage_budget=2)
    # With only 2 of 10 files covered, most of a rush must get through.
    r = play(Greedy(), RushRed(), cfg)
    assert r.corrupted >= cfg.n_angels - cfg.coverage_budget


def test_spread_delays_corruption_more_than_rush():
    cfg = ArenaConfig(seed=1)
    rush = play(RandomBlue(), RushRed(), cfg)
    spread = play(RandomBlue(), SpreadRed(), cfg)
    assert spread.time_to_corruption >= rush.time_to_corruption


def test_tournament_aggregates_all_pairs():
    blues = {"random": RandomBlue}
    reds = {"rush": RushRed, "spread": SpreadRed}
    out = tournament(blues, reds, base=ArenaConfig(), episodes=5)
    assert set(out) == {("random", "rush"), ("random", "spread")}
    for res in out.values():
        assert 0.0 <= res.blue_detection_rate <= 1.0


def test_caught_stomp_corresponds_to_an_r4_finding():
    # The arena's "caught iff covered at the stomp tick" maps to the real engine:
    # a covered stomp puts the setinfo in the journal, and R4 fires. An uncovered
    # stomp leaves no journal record, so nothing fires.
    display = DisplayWitness()
    display.set_times("f", MACE(modified=1.5, created=1.0))
    mft = MFTWitness()
    mft.record_birth("f", 1.0)

    covered = Ledger()
    covered.append({"file_id": "f", "op": "create"}, recorded_at=1.0)
    covered.append({"file_id": "f", "op": "write"}, recorded_at=5.0)
    covered.append(
        {"file_id": "f", "op": "setinfo", "written_modified": 1.5, "written_created": 1.0},
        recorded_at=9.0,
    )
    det = DivergenceDetector(display, mft, JournalWitness(covered), now=10.0)
    assert any(f.rule == "R4_setinfo_captured" for f in det.scan("f"))

    uncovered = Ledger()
    uncovered.append({"file_id": "f", "op": "create"}, recorded_at=1.0)
    uncovered.append({"file_id": "f", "op": "write"}, recorded_at=5.0)
    det2 = DivergenceDetector(display, mft, JournalWitness(uncovered), now=10.0)
    assert not any(f.rule == "R4_setinfo_captured" for f in det2.scan("f"))


def test_status_constants_used():
    cfg = ArenaConfig(n_files=4, n_angels=4, coverage_budget=4)
    r = play(CoverAll(), RushRed(), cfg)
    # sanity: constants are the documented strings
    assert (CAUGHT, CORRUPTED) == ("caught", "corrupted")
    assert r.caught == 4
