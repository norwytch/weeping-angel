from pathlib import Path

from quantumlock.adapters.mft_csv import parse_filetime, scan_csv

SAMPLE = Path(__file__).resolve().parents[1] / "examples" / "data" / "mft_sample.csv"


def rules(findings):
    return {f.rule for f in findings}


def test_parse_filetime_preserves_subsecond():
    a = parse_filetime("2024-03-10 14:02:11.1234567")
    b = parse_filetime("2024-03-10 14:02:11.0000000")
    assert a is not None and b is not None
    assert abs(a - b) > 0  # the 100ns fraction survives
    assert abs((a - b) - 0.1234567) < 1e-6


def test_parse_filetime_blank_is_none():
    assert parse_filetime("") is None
    assert parse_filetime(None) is None


def test_parse_filetime_malformed_is_none():
    assert parse_filetime("not-a-timestamp") is None
    assert parse_filetime("2024-13-99 99:99:99") is None


def test_parse_filetime_overlong_fraction_is_clamped():
    # A hostile cell with a huge fractional string must not trigger a giant
    # bignum exponentiation; it is clamped to FILETIME's 7 digits (LOW-1).
    clamped = parse_filetime("2024-03-10 14:02:11." + "1" * 100_000)
    seven = parse_filetime("2024-03-10 14:02:11.1111111")
    assert clamped is not None and seven is not None
    assert clamped == seven


def test_stomped_file_flagged_on_real_mft_columns():
    results = scan_csv(str(SAMPLE))
    evil = rules(results["evil.exe"])
    # $SI creation predates the $FN birth, and $SI is zeroed to whole seconds.
    assert "R1_si_fn_birth_divergence" in evil
    assert "R6_subsecond_truncation" in evil


def test_clean_file_has_no_findings():
    results = scan_csv(str(SAMPLE))
    assert results["report.docx"] == []


def test_findings_carry_attack_technique():
    results = scan_csv(str(SAMPLE))
    for f in results["evil.exe"]:
        assert f.technique == "T1070.006"
        assert f.tactic == "TA0005"
