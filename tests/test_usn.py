import importlib.util
from pathlib import Path

from weeping_angel.adapters.usn import (
    filetime_to_epoch,
    journal_ledger,
    parse_records,
    scan_with_usn,
)

DATA = Path(__file__).resolve().parents[1] / "examples" / "data"
USN = DATA / "sample.usnjrnl"
MFT = DATA / "sample.mft"

_UNIX_EPOCH_FILETIME = 11_644_473_600 * 10_000_000


def _load_builder():
    spec = importlib.util.spec_from_file_location("make_usn", DATA / "make_usn_sample.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_filetime_epoch():
    assert filetime_to_epoch(0) is None
    assert abs(filetime_to_epoch(_UNIX_EPOCH_FILETIME)) < 1e-4


def test_parses_records_and_skips_sparse_prefix():
    recs = list(parse_records(USN.read_bytes()))
    assert len(recs) == 5
    assert {r.name for r in recs} == {"evil.exe", "report.docx"}


def test_reason_flags_decode():
    recs = list(parse_records(USN.read_bytes()))
    stomp = next(r for r in recs if "BASIC_INFO_CHANGE" in r.reasons())
    assert stomp.name == "evil.exe"


def test_journal_ledger_classifies_ops_and_verifies():
    led = journal_ledger(USN.read_bytes())
    ops = {r.event["op"] for r in led.all_records()}
    assert {"create", "write", "setinfo"} <= ops
    assert led.verify().ok


def test_scan_with_usn_catches_the_rollback():
    res = scan_with_usn(str(MFT), str(USN))
    evil = {f.rule for f in res["evil.exe"]}
    assert "R2_si_journal_rollback" in evil  # $SI modified predates the journal's true write
    assert res["report.docx"] == []


def test_parser_round_trips_the_builder():
    b = _load_builder()
    ts = b.filetime(2023, 6, 1, 12, 0, 0)
    raw = bytearray(16)  # sparse prefix
    raw += b.usn_record(8, 99, 5, ts, b.FILE_CREATE, "doc.txt")
    recs = list(parse_records(bytes(raw)))
    assert len(recs) == 1
    assert recs[0].name == "doc.txt"
    assert "FILE_CREATE" in recs[0].reasons()
    assert abs(recs[0].timestamp - filetime_to_epoch(ts)) < 1e-6
