# recorder — the out-of-band collector (Go)

The recorder is the host collector in the Weeping Angel model: it watches file
operations, computes a forward hash chain, and appends to the same append-only
JSONL ledger the Python detector reads. Go is the natural fit — a single static
binary with good concurrency, which is what you actually deploy on an endpoint.

It writes the **same hash chain** as `quantumlock/ledger.py`. The preimage is a
compact, key-sorted JSON object `{event, index, prev_hash, recorded_at}`; Go's
encoder (HTML escaping off) emits bytes identical to Python's
`json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=False)`. This
holds only for integer/string values, so the shared ledger uses integer
(nanosecond) timestamps and string event fields. A golden-vector test on each
side fails loudly if the two ever diverge.

## Build and test

```bash
go -C recorder build ./...
go -C recorder test ./...
```

## Use

```bash
# record file ops in a directory (poll-based; production would use fsnotify)
go -C recorder run . watch /path/to/watch ledger.jsonl

# chain a stream of {"recorded_at": <int ns>, "event": {...}} events
go -C recorder run . replay events.jsonl ledger.jsonl

# re-check a ledger's chain (exit 0 = intact, 1 = tampered)
go -C recorder run . verify ledger.jsonl
```

The Python side consumes the output unchanged:

```python
from quantumlock.ledger import Ledger
Ledger.load("ledger.jsonl").verify().ok   # True for an intact chain
```

Cross-language agreement is tested both directions in
`tests/test_recorder_interop.py` (Python) and `recorder/ledger_test.go` (Go).
