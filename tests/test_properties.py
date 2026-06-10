"""Property-based tests: the detection invariants must hold for *all* inputs in
range, not just the hand-picked examples. Skipped cleanly if Hypothesis is not
installed."""

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from quantumlock.detector import DivergenceDetector  # noqa: E402
from quantumlock.ledger import Ledger  # noqa: E402
from quantumlock.witnesses import MACE, DisplayWitness, JournalWitness, MFTWitness  # noqa: E402

# realistic-but-bounded epoch range with sub-second precision
times = st.floats(min_value=1.0e9, max_value=2.0e9, allow_nan=False, allow_infinity=False)
gaps = st.floats(min_value=1.0, max_value=1.0e8, allow_nan=False, allow_infinity=False)


def detector(si, birth, journal_events, now):
    d = DisplayWitness()
    d.set_times("f", si)
    m = MFTWitness()
    m.record_birth("f", birth)
    led = Ledger()
    for ev, t in journal_events:
        led.append({"file_id": "f", **ev}, recorded_at=t)
    return DivergenceDetector(d, m, JournalWitness(led), now=now)


def rules(det):
    return {f.rule for f in det.scan("f")}


@settings(max_examples=200)
@given(birth=times, mgap=gaps, ngap=gaps)
def test_clean_timeline_never_fires(birth, mgap, ngap):
    write = birth + mgap
    now = write + ngap
    si = MACE(modified=write, created=birth)
    det = detector(si, birth, [({"op": "create"}, birth), ({"op": "write"}, write)], now)
    assert det.scan("f") == []


@settings(max_examples=200)
@given(birth=times, backdate=gaps, mgap=gaps)
def test_any_birth_backdate_is_caught(birth, backdate, mgap):
    # $SI created strictly before the kernel $FN birth must always trip R1.
    forged_created = birth - backdate
    si = MACE(modified=forged_created + mgap, created=forged_created)
    det = detector(si, birth, [({"op": "create"}, birth)], now=birth + 1e9)
    assert "R1_si_fn_birth_divergence" in rules(det)


@settings(max_examples=200)
@given(birth=times, wgap=gaps, rollback=gaps)
def test_any_modified_rollback_is_caught(birth, wgap, rollback):
    # $SI modified earlier than the journal's true last write must trip R2.
    write = birth + wgap
    forged_modified = write - rollback
    si = MACE(modified=forged_modified, created=birth)
    det = detector(
        si, birth, [({"op": "create"}, birth), ({"op": "write"}, write)], now=write + 1e9
    )
    assert "R2_si_journal_rollback" in rules(det)
