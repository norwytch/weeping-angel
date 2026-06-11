from dataclasses import replace

from weeping_angel.anchor import Anchor
from weeping_angel.ledger import Ledger

KEY = b"off-box-collector-secret"


def build(n: int = 3) -> Ledger:
    led = Ledger()
    for i in range(n):
        led.append({"file_id": "a", "op": "write", "i": i}, recorded_at=float(i))
    return led


def test_clean_ledger_passes_anchor():
    led = build()
    anchor = Anchor(KEY)
    anchor.checkpoint(led)
    assert anchor.verify(led).ok


def test_tail_truncation_detected_by_anchor_only():
    led = build(3)
    anchor = Anchor(KEY)
    anchor.checkpoint(led)  # pin length 3
    led.simulate_truncate(2)  # drop the tail
    # The chain alone still verifies (this is the documented gap)...
    assert led.verify().ok
    # ...but the anchor catches it.
    result = anchor.verify(led)
    assert not result.ok
    assert any("truncated" in p for p in result.problems)


def test_interior_rewrite_under_checkpoint_detected():
    led = build(3)
    anchor = Anchor(KEY)
    anchor.checkpoint(led)
    led.simulate_inplace_edit(0, {"file_id": "a", "op": "write", "i": 0, "forged": True})
    result = anchor.verify(led)
    assert not result.ok


def test_forged_checkpoint_mac_rejected():
    led = build(3)
    anchor = Anchor(KEY)
    cp = anchor.checkpoint(led)
    # Attacker fabricates a checkpoint endorsing a shorter ledger but lacks the key.
    anchor._checkpoints[0] = replace(cp, length=1, head_hash=led.head_hash_at(1))
    result = anchor.verify(led)
    assert not result.ok
    assert any("invalid MAC" in p for p in result.problems)


def test_empty_key_rejected():
    try:
        Anchor(b"")
    except ValueError:
        return
    raise AssertionError("empty key should be rejected")
