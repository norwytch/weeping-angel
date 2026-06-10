import json
from pathlib import Path

import pytest

from quantumlock.cli import main
from quantumlock.ledger import Ledger

SAMPLE_MFT = Path(__file__).resolve().parents[1] / "examples" / "data" / "sample.mft"


def test_scan_human_output(capsys):
    assert main(["scan", str(SAMPLE_MFT)]) == 0
    assert "evil.exe" in capsys.readouterr().out


def test_scan_siem_output_is_jsonl(capsys):
    assert main(["scan", str(SAMPLE_MFT), "--format", "ocsf"]) == 0
    line = capsys.readouterr().out.strip().splitlines()[0]
    assert json.loads(line)["class_uid"] == 2004


def test_verify_ledger_ok(tmp_path, capsys):
    led = Ledger()
    led.append({"file_id": "a", "op": "create"}, 1_700_000_000_000_000_000)
    path = tmp_path / "l.jsonl"
    led.dump(str(path))
    assert main(["verify-ledger", str(path)]) == 0
    assert "intact" in capsys.readouterr().out


def test_verify_ledger_detects_tampering(tmp_path):
    led = Ledger()
    led.append({"file_id": "a", "op": "create"}, 1_700_000_000_000_000_000)
    led.append({"file_id": "a", "op": "write"}, 1_700_000_000_500_000_000)
    path = tmp_path / "l.jsonl"
    led.dump(str(path))
    lines = path.read_text().splitlines()
    first = json.loads(lines[0])
    first["event"]["op"] = "forged"
    lines[0] = json.dumps(first)
    path.write_text("\n".join(lines) + "\n")
    assert main(["verify-ledger", str(path)]) == 1


def test_arena_runs(capsys):
    assert main(["arena", "--episodes", "5"]) == 0
    assert "caught" in capsys.readouterr().out


def test_no_command_errors():
    with pytest.raises(SystemExit):
        main([])
