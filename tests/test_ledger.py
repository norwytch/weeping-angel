import hashlib
import json

from quantumlock.ledger import GENESIS_HASH, Ledger


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


def integer_ledger() -> Ledger:
    # The shared (cross-language) format: integer-ns timestamps, string events.
    led = Ledger()
    led.append({"file_id": "evil.exe", "op": "create"}, recorded_at=1_700_000_000_000_000_000)
    led.append({"file_id": "evil.exe", "op": "write"}, recorded_at=1_700_000_000_500_000_000)
    return led


def test_preimage_format_is_locked():
    # Pin the exact preimage bytes so the Go recorder has a precise spec: a
    # compact, key-sorted JSON object {event, index, prev_hash, recorded_at}.
    event = {"file_id": "a", "op": "create"}
    preimage = (
        '{"event":{"file_id":"a","op":"create"},"index":0,'
        f'"prev_hash":"{GENESIS_HASH}","recorded_at":1700000000000000000}}'
    )
    assert (
        json.dumps(
            {"event": event, "index": 0, "prev_hash": GENESIS_HASH,
             "recorded_at": 1_700_000_000_000_000_000},
            sort_keys=True, separators=(",", ":"),
        )
        == preimage
    )
    expected = hashlib.sha256(preimage.encode()).hexdigest()
    rec = Ledger().append(event, 1_700_000_000_000_000_000)
    assert rec.hash == expected


def test_jsonl_round_trip_preserves_chain(tmp_path):
    led = integer_ledger()
    path = tmp_path / "ledger.jsonl"
    led.dump(str(path))
    loaded = Ledger.load(str(path))
    assert len(loaded) == len(led)
    assert loaded.head_hash == led.head_hash
    assert loaded.verify().ok


def test_jsonl_load_catches_tampering(tmp_path):
    led = integer_ledger()
    path = tmp_path / "ledger.jsonl"
    led.dump(str(path))
    # tamper with a stored line's event, keeping its hash field
    lines = path.read_text().splitlines()
    first = json.loads(lines[0])
    first["event"]["op"] = "forged"
    lines[0] = json.dumps(first)
    path.write_text("\n".join(lines) + "\n")
    assert not Ledger.load(str(path)).verify().ok
