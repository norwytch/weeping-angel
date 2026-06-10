"""Cross-language tests: the Go recorder and the Python ledger agree on the same
hash chain. Skipped if the Go toolchain is not installed (so CI without Go is
unaffected)."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from quantumlock.ledger import Ledger

go = shutil.which("go")
pytestmark = pytest.mark.skipif(go is None, reason="Go toolchain not installed")

RECORDER = Path(__file__).resolve().parents[1] / "recorder"


def run_recorder(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [go, "-C", str(RECORDER), "run", ".", *args],
        capture_output=True,
        text=True,
        timeout=120,
    )


def py_integer_ledger() -> Ledger:
    led = Ledger()
    led.append({"file_id": "evil.exe", "op": "create"}, 1_700_000_000_000_000_000)
    led.append(
        {"file_id": "evil.exe", "op": "setinfo", "written": "2019"}, 1_700_000_000_500_000_000
    )
    return led


def test_go_verifies_a_python_written_ledger(tmp_path):
    path = tmp_path / "py.jsonl"
    py_integer_ledger().dump(str(path))
    result = run_recorder("verify", str(path))
    assert result.returncode == 0, result.stderr
    assert "OK" in result.stdout


def test_python_verifies_a_go_written_ledger_and_hashes_match(tmp_path):
    events = tmp_path / "events.jsonl"
    out = tmp_path / "go.jsonl"
    events.write_text(
        '{"recorded_at":1700000000000000000,"event":{"file_id":"evil.exe","op":"create"}}\n'
        '{"recorded_at":1700000000500000000,"event":{"file_id":"evil.exe","op":"setinfo","written":"2019"}}\n'
    )
    result = run_recorder("replay", str(events), str(out))
    assert result.returncode == 0, result.stderr

    go_ledger = Ledger.load(str(out))
    assert go_ledger.verify().ok
    # Go's chain head equals what Python computes independently for the same input
    assert go_ledger.head_hash == py_integer_ledger().head_hash


def test_go_detects_tampering_in_a_ledger(tmp_path):
    events = tmp_path / "events.jsonl"
    out = tmp_path / "go.jsonl"
    events.write_text(
        '{"recorded_at":1700000000000000000,"event":{"file_id":"a","op":"create"}}\n'
        '{"recorded_at":1700000000500000000,"event":{"file_id":"a","op":"write"}}\n'
    )
    assert run_recorder("replay", str(events), str(out)).returncode == 0

    lines = out.read_text().splitlines()
    first = json.loads(lines[0])
    first["event"]["op"] = "forged"
    lines[0] = json.dumps(first)
    out.write_text("\n".join(lines) + "\n")

    result = run_recorder("verify", str(out))
    assert result.returncode == 1
    assert "TAMPERED" in result.stdout
