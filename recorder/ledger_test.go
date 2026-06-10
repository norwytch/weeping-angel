package main

import "testing"

// Golden vector shared with the Python side (tests/test_ledger.py locks the same
// preimage). If Go and Python ever diverge on serialization, this breaks.
const goldenHash = "c98a24581211dafacfe7c69734201a1ca4e834f25ce3233a51b4948c3b737e88"

func TestGoldenVectorMatchesPython(t *testing.T) {
	l := &Ledger{}
	rec, err := l.Append(1700000000000000000, map[string]any{"file_id": "a", "op": "create"})
	if err != nil {
		t.Fatal(err)
	}
	if rec.Hash != goldenHash {
		t.Fatalf("hash mismatch:\n got  %s\n want %s", rec.Hash, goldenHash)
	}
}

func TestChainVerifies(t *testing.T) {
	l := &Ledger{}
	l.Append(1, map[string]any{"file_id": "a", "op": "create"})
	l.Append(2, map[string]any{"file_id": "a", "op": "write"})
	if ok, problems := l.Verify(); !ok {
		t.Fatalf("clean chain failed: %v", problems)
	}
}

func TestTamperIsDetected(t *testing.T) {
	l := &Ledger{}
	l.Append(1, map[string]any{"file_id": "a", "op": "create"})
	l.Append(2, map[string]any{"file_id": "a", "op": "write"})
	// edit a past record's event in place; its stored hash no longer matches
	l.records[0].Event["op"] = "forged"
	if ok, _ := l.Verify(); ok {
		t.Fatal("expected tamper to be detected")
	}
}

func TestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/ledger.jsonl"
	l := &Ledger{}
	l.Append(1700000000000000000, map[string]any{"file_id": "evil.exe", "op": "create"})
	if err := l.Dump(path); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if ok, problems := loaded.Verify(); !ok {
		t.Fatalf("reloaded ledger failed verify: %v", problems)
	}
	if loaded.headHash() != l.headHash() {
		t.Fatal("head hash changed across dump/load")
	}
}
