from quantumlock.ledger import Ledger


def build() -> Ledger:
    led = Ledger()
    led.append({"file_id": "a", "op": "create"}, recorded_at=1.0)
    led.append({"file_id": "a", "op": "write"}, recorded_at=2.0)
    led.append({"file_id": "a", "op": "write"}, recorded_at=3.0)
    return led


def test_clean_chain_verifies():
    assert build().verify().ok


def test_inplace_edit_detected():
    led = build()
    led.simulate_inplace_edit(0, {"file_id": "a", "op": "create", "forged": True})
    result = led.verify()
    assert not result.ok
    assert any("broken chain link" in p for p in result.problems)


def test_truncation_breaks_length_not_chain():
    led = build()
    led.simulate_truncate(2)
    # internal chain still links; detection of a dropped tail needs an external
    # anchor (documented). Remaining records are self-consistent:
    assert led.verify().ok
    assert len(led) == 2


def test_head_hash_advances():
    led = Ledger()
    h0 = led.head_hash
    led.append({"file_id": "a", "op": "create"}, recorded_at=1.0)
    assert led.head_hash != h0
