"""Executable offline adapter: run the divergence rules on a real ``$MFT`` dump.

Unlike :mod:`quantumlock.adapters.windows` (design-only, needs a live host), this
adapter is **runnable here**. It ingests the CSV produced by the standard DFIR
MFT parsers -- Eric Zimmerman's ``MFTECmd`` (and, loosely, ``analyzeMFT``) -- and
drives the same :class:`~quantumlock.detector.DivergenceDetector` over real NTFS
artifacts.

MFTECmd emits both attribute sets per record:

* ``*0x10`` columns -> ``$STANDARD_INFORMATION`` (``$SI``)  -> :class:`DisplayWitness`
* ``*0x30`` columns -> ``$FILE_NAME`` (``$FN``)             -> :class:`MFTWitness`

so the canonical ``$SI``-vs-``$FN`` comparison (rules ``R1`` and ``R6``) runs on
genuine data. The USN-backed journal rules need a separate USN export and are
skipped when only an MFT is available.

Usage::

    python -m quantumlock.adapters.mft_csv path/to/mft.csv
"""

from __future__ import annotations

import csv
import sys
from datetime import datetime, timezone

from ..detector import DivergenceDetector, Finding
from ..ledger import Ledger
from ..witnesses import MACE, DisplayWitness, JournalWitness, MFTWitness

# MFTECmd timestamps look like "2021-03-04 11:22:33.4567890" (7-digit, 100ns).
_DATE_FMT = "%Y-%m-%d %H:%M:%S"


def parse_filetime(value: str | None) -> float | None:
    """Parse an MFTECmd timestamp into an epoch float, preserving sub-second
    (100ns) precision. Returns ``None`` for blank/unparseable cells."""
    if not value or not value.strip():
        return None
    text = value.strip().replace("T", " ").rstrip("Z").strip()
    frac = 0.0
    if "." in text:
        text, frac_digits = text.split(".", 1)
        # A FILETIME has at most 7 fractional (100ns) digits; cap before the
        # int()/10**n so a hostile cell can't force a huge bignum exponentiation.
        frac_digits = "".join(ch for ch in frac_digits if ch.isdigit())[:7]
        if frac_digits:
            frac = int(frac_digits) / (10 ** len(frac_digits))
    try:
        dt = datetime.strptime(text, _DATE_FMT).replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return dt.timestamp() + frac


def _col(row: dict, *names: str) -> str | None:
    """First present, non-empty value among candidate column names."""
    for n in names:
        if n in row and row[n] and row[n].strip():
            return row[n]
    return None


def load_witnesses(rows) -> tuple[DisplayWitness, MFTWitness, list[str]]:
    """Build $SI and $FN witnesses from MFTECmd rows. Returns the witnesses and
    the ordered list of file ids seen."""
    display = DisplayWitness()
    mft = MFTWitness()
    file_ids: list[str] = []
    for row in rows:
        fid = _col(row, "FileName", "Name") or _col(row, "EntryNumber") or ""
        if not fid:
            continue
        si = MACE(
            modified=parse_filetime(_col(row, "LastModified0x10", "LastModified")),
            created=parse_filetime(_col(row, "Created0x10", "Created")),
            accessed=parse_filetime(_col(row, "LastAccess0x10", "LastAccess")),
            entry_modified=parse_filetime(_col(row, "LastRecordChange0x10")),
        )
        display.set_times(fid, si)
        fn_birth = parse_filetime(_col(row, "Created0x30"))
        if fn_birth is not None:
            mft.record_birth(fid, fn_birth)
        file_ids.append(fid)
    return display, mft, file_ids


def scan_csv(path: str, now: float | None = None) -> dict[str, list[Finding]]:
    """Parse an MFTECmd CSV and return findings per file id. No USN here, so the
    journal is empty and journal-only rules (R2/R4) stay silent by design."""
    with open(path, newline="", encoding="utf-8-sig") as fh:
        # Stream rows straight from the reader (no list()) so a large export
        # isn't held in memory all at once.
        display, mft, file_ids = load_witnesses(csv.DictReader(fh))
        journal = JournalWitness(Ledger())  # empty: MFT-only evidence
        detector = DivergenceDetector(display, mft, journal, now=now)
        return {fid: detector.scan(fid) for fid in file_ids}


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print("usage: python -m quantumlock.adapters.mft_csv <mftecmd.csv>")
        return 2
    results = scan_csv(argv[0])
    flagged = {fid: fs for fid, fs in results.items() if fs}
    print(f"Scanned {len(results)} file(s); {len(flagged)} with timestomp indicators.\n")
    for fid, findings in flagged.items():
        print(f"  {fid}")
        for f in findings:
            print(f"    [{f.severity.upper():6}] {f.rule}  ({f.technique})")
            print(f"            {f.explanation}")
    if not flagged:
        print("  no divergence found.")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
