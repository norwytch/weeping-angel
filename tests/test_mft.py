import importlib.util
from pathlib import Path

from quantumlock.adapters.mft import filetime_to_epoch, iter_records, parse_record, scan_mft

DATA = Path(__file__).resolve().parents[1] / "examples" / "data"
SAMPLE = DATA / "sample.mft"

# FILETIME for the Unix epoch (1970-01-01): 11644473600 seconds of 100ns ticks.
_UNIX_EPOCH_FILETIME = 11_644_473_600 * 10_000_000


def _load_builder():
    spec = importlib.util.spec_from_file_location("make_mft_sample", DATA / "make_mft_sample.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def rules(findings):
    return {f.rule for f in findings}


def test_filetime_epoch_and_subsecond():
    # float64 can't hold the full 100ns resolution at FILETIME magnitudes
    # (~1.16e17), so the recovered fraction is good to roughly a microsecond.
    assert abs(filetime_to_epoch(_UNIX_EPOCH_FILETIME)) < 1e-4
    assert abs(filetime_to_epoch(_UNIX_EPOCH_FILETIME + 1_234_567) - 0.1234567) < 1e-4
    assert filetime_to_epoch(0) is None


def test_sample_parses_two_records_with_names():
    recs = {r.name: r for r in iter_records(SAMPLE.read_bytes())}
    assert set(recs) == {"report.docx", "evil.exe"}
    # clean file: $SI creation equals the $FN birth
    assert abs(recs["report.docx"].si_created - recs["report.docx"].fn_created) < 1e-6
    # stomped file: $SI creation sits years before the $FN birth
    assert recs["evil.exe"].si_created < recs["evil.exe"].fn_created


def test_stomped_record_flagged_from_raw_mft():
    results = scan_mft(str(SAMPLE))
    assert "R1_si_fn_birth_divergence" in rules(results["evil.exe"])
    assert "R6_subsecond_truncation" in rules(results["evil.exe"])


def test_clean_record_has_no_findings():
    assert scan_mft(str(SAMPLE))["report.docx"] == []


def test_parser_round_trips_the_builder():
    # Build a record with known FILETIMEs, parse the bytes back, confirm the
    # timestamps survive the FILE-record + fixup round trip.
    b = _load_builder()
    birth = b.filetime(2023, 6, 1, 12, 0, 0, 5_000_000)
    mtime = b.filetime(2023, 6, 2, 12, 0, 0, 1_111_111)
    raw = b.build_record(99, "doc.txt", (birth, mtime, mtime, mtime), (birth, mtime, mtime, mtime))
    rec = parse_record(raw)
    assert rec is not None
    assert rec.name == "doc.txt"
    assert abs(rec.si_created - filetime_to_epoch(birth)) < 1e-6
    assert abs(rec.si_modified - filetime_to_epoch(mtime)) < 1e-6
    assert abs(rec.fn_created - filetime_to_epoch(birth)) < 1e-6


def test_non_file_record_is_skipped():
    assert parse_record(b"BAAD" + b"\x00" * 1020) is None
    assert parse_record(b"\x00" * 1024) is None
