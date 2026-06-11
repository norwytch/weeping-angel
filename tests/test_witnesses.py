from weeping_angel.ledger import Ledger
from weeping_angel.witnesses import MACE, DisplayWitness, JournalWitness, MFTWitness


def test_display_witness_roundtrip():
    w = DisplayWitness()
    assert w.observe("x") is None
    w.set_times("x", MACE(modified=5.0, created=1.0))
    assert w.observe("x").modified == 5.0


def test_mft_birth_is_write_once():
    w = MFTWitness()
    w.record_birth("x", 2.0)
    w.record_birth("x", 99.0)  # ignored
    assert w.observe("x").created == 2.0


def test_journal_reconstructs_true_timeline():
    led = Ledger()
    led.append({"file_id": "x", "op": "create"}, recorded_at=1.0)
    led.append({"file_id": "x", "op": "write"}, recorded_at=4.0)
    led.append(
        {"file_id": "x", "op": "setinfo", "written_modified": 1.5, "written_created": 1.0},
        recorded_at=5.0,
    )
    j = JournalWitness(led)
    mace = j.observe("x")
    assert mace.created == 1.0
    assert mace.modified == 4.0  # setinfo does not move the true modified time
    events = j.setinfo_events("x")
    assert len(events) == 1
    assert events[0]["real_time"] == 5.0
    assert events[0]["written_modified"] == 1.5
