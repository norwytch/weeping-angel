from quantumlock.detector import DivergenceDetector
from quantumlock.ledger import Ledger
from quantumlock.witnesses import MACE, DisplayWitness, JournalWitness, MFTWitness


def make(display_mace, birth, journal_events, trusted_setinfo_actors=None):
    d = DisplayWitness()
    d.set_times("x", display_mace)
    m = MFTWitness()
    if birth is not None:
        m.record_birth("x", birth)
    led = Ledger()
    for ev, t in journal_events:
        led.append({"file_id": "x", **ev}, recorded_at=t)
    j = JournalWitness(led)
    return DivergenceDetector(d, m, j, now=1000.0, trusted_setinfo_actors=trusted_setinfo_actors)


def rules(findings):
    return {f.rule for f in findings}


def test_r1_birth_divergence():
    det = make(MACE(modified=1.5, created=1.0), birth=2.0, journal_events=[({"op": "create"}, 2.0)])
    assert "R1_si_fn_birth_divergence" in rules(det.scan("x"))


def test_r2_modified_rollback():
    det = make(
        MACE(modified=1.5, created=1.0),
        birth=1.0,
        journal_events=[({"op": "create"}, 1.0), ({"op": "write"}, 5.0)],
    )
    assert "R2_si_journal_rollback" in rules(det.scan("x"))


def test_r3_internal_ordering():
    det = make(MACE(modified=1.0, created=5.0), birth=5.0, journal_events=[({"op": "create"}, 5.0)])
    assert "R3_internal_ordering" in rules(det.scan("x"))


def test_r4_setinfo_captured():
    # setinfo backdates created below the kernel-set birth -> contradicts truth.
    det = make(
        MACE(modified=1.5, created=1.0),
        birth=1.0,
        journal_events=[
            ({"op": "create"}, 1.0),
            ({"op": "write"}, 5.0),
            ({"op": "setinfo", "written_modified": 1.5, "written_created": 0.5}, 9.0),
        ],
    )
    assert "R4_setinfo_captured" in rules(det.scan("x"))


def test_r4_benign_setinfo_not_flagged():
    # A setinfo that writes a plausible time (>= true last write, >= birth,
    # <= now) is what archivers / `cp -p` / restore do -- not a forgery.
    det = make(
        MACE(modified=6.0, created=1.0),
        birth=1.0,
        journal_events=[
            ({"op": "create"}, 1.0),
            ({"op": "write"}, 5.0),
            ({"op": "setinfo", "written_modified": 6.0, "written_created": 1.0}, 9.0),
        ],
    )
    assert det.scan("x") == []


def test_r4_trusted_actor_exempt():
    # Same backdating write, but from a known-legitimate timestamp setter.
    det = make(
        MACE(modified=1.5, created=1.0),
        birth=1.0,
        journal_events=[
            ({"op": "create"}, 1.0),
            ({"op": "write"}, 5.0),
            ({"op": "setinfo", "written_modified": 1.5, "written_created": 0.5,
              "actor": "C:\\Windows\\System32\\robocopy.exe"}, 9.0),
        ],
        trusted_setinfo_actors={"C:\\Windows\\System32\\robocopy.exe"},
    )
    assert "R4_setinfo_captured" not in rules(det.scan("x"))


def test_r5_future_timestamp():
    det = make(
        MACE(modified=99999.0, created=1.0), birth=1.0, journal_events=[({"op": "create"}, 1.0)]
    )
    assert "R5_future_timestamp" in rules(det.scan("x"))


def test_r6_subsecond_truncation():
    # $SI zeroed to whole seconds while the kernel-set $FN birth keeps 100ns precision.
    det = make(
        MACE(modified=5.0, created=2.0),
        birth=2.0000731,
        journal_events=[({"op": "create"}, 2.0000731), ({"op": "write"}, 5.0000044)],
    )
    assert "R6_subsecond_truncation" in rules(det.scan("x"))


def test_r6_not_flagged_when_si_has_subsecond():
    det = make(
        MACE(modified=5.0000044, created=2.0000731),
        birth=2.0000731,
        journal_events=[({"op": "create"}, 2.0000731), ({"op": "write"}, 5.0000044)],
    )
    assert "R6_subsecond_truncation" not in rules(det.scan("x"))


def test_r7_si_fn_modified_divergence():
    d = DisplayWitness()
    d.set_times("x", MACE(modified=5.0, created=10.0))
    m = MFTWitness()
    m.record_birth("x", 9.0)
    m.record_modified("x", 100.0)  # $FN modified much later than the displayed modified
    det = DivergenceDetector(d, m, JournalWitness(Ledger()), now=1000.0)
    assert "R7_si_fn_modified_divergence" in rules(det.scan("x"))


def test_r7_not_flagged_when_si_modified_is_recent():
    d = DisplayWitness()
    d.set_times("x", MACE(modified=200.0, created=10.0))
    m = MFTWitness()
    m.record_birth("x", 9.0)
    m.record_modified("x", 100.0)  # displayed modified newer than $FN modified -> normal
    det = DivergenceDetector(d, m, JournalWitness(Ledger()), now=1000.0)
    assert "R7_si_fn_modified_divergence" not in rules(det.scan("x"))


def test_clean_file_has_no_findings():
    det = make(
        MACE(modified=5.0, created=1.0),
        birth=1.0,
        journal_events=[({"op": "create"}, 1.0), ({"op": "write"}, 5.0)],
    )
    assert det.scan("x") == []
