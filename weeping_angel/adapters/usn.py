"""Parse the NTFS USN change journal (``$Extend\\$UsnJrnl:$J``).

The journal is the project's "journal witness" grounded in real evidence: a
stream of USN_RECORD_V2 structures, each recording a change to a file with a
kernel timestamp and a set of *reason* flags. This parses that binary stream and
maps it onto the same :class:`~weeping_angel.ledger.Ledger` the detector reads, so
``R2`` (displayed modified predates the journal's true last write) runs on a real
journal.

Reason-flag correlation matters: ``FILE_CREATE`` and the ``DATA_*`` reasons are
true content changes (they set the journal's last-write time), while
``BASIC_INFO_CHANGE`` is a metadata/timestamp edit. A pure timestomp shows up as
a ``BASIC_INFO_CHANGE`` with no accompanying content change. The journal records
*that* the metadata changed and *when*, but not the value written -- capturing
the attempted value needs the minifilter (rule ``R4``). That split is the
USN-only vs minifilter trade-off documented in ``docs/DESIGN.md``.

    python -m weeping_angel.adapters.usn examples/data/sample.usnjrnl
"""

from __future__ import annotations

import struct
import sys
from collections.abc import Iterator
from dataclasses import dataclass

from ..ledger import Ledger

_FILETIME_EPOCH_DIFF = 11_644_473_600  # seconds between 1601-01-01 and 1970-01-01

# USN reason flags (subset). https://learn.microsoft.com/windows/win32/api/winioctl
REASON_FLAGS = {
    0x00000001: "DATA_OVERWRITE",
    0x00000002: "DATA_EXTEND",
    0x00000004: "DATA_TRUNCATION",
    0x00000800: "FILE_CREATE",
    0x00001000: "FILE_DELETE",
    0x00002000: "EA_CHANGE",
    0x00008000: "RENAME_OLD_NAME",
    0x00010000: "RENAME_NEW_NAME",
    0x00040000: "BASIC_INFO_CHANGE",  # $SI basic info, incl. timestamps -- the stomp
    0x80000000: "CLOSE",
}

_FILE_CREATE = 0x00000800
_DATA_CHANGE = 0x00000001 | 0x00000002 | 0x00000004
_BASIC_INFO_CHANGE = 0x00040000


def filetime_to_epoch(ft: int) -> float | None:
    if ft == 0:
        return None
    return ft / 10_000_000.0 - _FILETIME_EPOCH_DIFF


@dataclass
class UsnRecord:
    usn: int
    file_ref: int
    parent_ref: int
    timestamp: float | None
    reason: int
    name: str

    def reasons(self) -> list[str]:
        return [name for bit, name in REASON_FLAGS.items() if self.reason & bit]


def parse_records(data: bytes) -> Iterator[UsnRecord]:
    """Iterate USN_RECORD_V2 entries, skipping the sparse zero prefix the $J
    file begins with. Non-V2 records are skipped."""
    n = len(data)
    off = 0
    while off + 4 <= n:
        rec_len = struct.unpack_from("<I", data, off)[0]
        if rec_len == 0:
            off += 8  # sparse / unwritten region
            continue
        if rec_len < 0x3C or off + rec_len > n:
            break
        major = struct.unpack_from("<H", data, off + 0x04)[0]
        if major != 2:
            off += rec_len
            continue
        file_ref = struct.unpack_from("<Q", data, off + 0x08)[0]
        parent_ref = struct.unpack_from("<Q", data, off + 0x10)[0]
        usn = struct.unpack_from("<Q", data, off + 0x18)[0]
        ts = struct.unpack_from("<Q", data, off + 0x20)[0]
        reason = struct.unpack_from("<I", data, off + 0x28)[0]
        name_len = struct.unpack_from("<H", data, off + 0x38)[0]
        name_off = struct.unpack_from("<H", data, off + 0x3A)[0]
        name = ""
        start, stop = off + name_off, off + name_off + name_len
        if name_off >= 0x3C and stop <= off + rec_len and stop <= n:
            name = bytes(data[start:stop]).decode("utf-16-le", errors="replace")
        yield UsnRecord(usn, file_ref, parent_ref, filetime_to_epoch(ts), reason, name)
        off += rec_len


def _op_for(reason: int) -> str | None:
    """Map reason flags to a ledger op, using reason-flag correlation: content
    changes set the true last-write time; a basic-info change is a setinfo."""
    if reason & _FILE_CREATE:
        return "create"
    if reason & _DATA_CHANGE:
        return "write"
    if reason & _BASIC_INFO_CHANGE:
        return "setinfo"  # metadata edit; value not captured by USN (R4 needs the minifilter)
    return None


def journal_ledger(data: bytes) -> Ledger:
    """Build a ledger from a $J stream that the detector's JournalWitness reads."""
    ledger = Ledger()
    for r in parse_records(data):
        if r.timestamp is None:
            continue
        op = _op_for(r.reason)
        if op is None:
            continue
        ledger.append({"file_id": r.name, "op": op}, recorded_at=r.timestamp)
    return ledger


def scan_with_usn(mft_path: str, usn_path: str, now: float | None = None) -> dict:
    """End-to-end: displayed ``$SI``/``$FN`` come from the MFT, the true timeline
    from the USN journal. This is how R2 gets a real journal to compare against."""
    from ..detector import DivergenceDetector
    from ..witnesses import JournalWitness
    from .mft import load_witnesses

    with open(mft_path, "rb") as fh:
        display, mft, file_ids = load_witnesses(fh.read())
    with open(usn_path, "rb") as fh:
        journal = JournalWitness(journal_ledger(fh.read()))
    detector = DivergenceDetector(display, mft, journal, now=now)
    return {fid: detector.scan(fid) for fid in file_ids}


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print("usage: python -m weeping_angel.adapters.usn <usnjrnl-$J>")
        return 2
    with open(argv[0], "rb") as fh:
        data = fh.read()
    records = list(parse_records(data))
    print(f"Parsed {len(records)} USN record(s):\n")
    for r in records:
        when = "?" if r.timestamp is None else f"{r.timestamp:.0f}"
        print(f"  usn={r.usn:<8} {r.name:<16} t={when}  {', '.join(r.reasons())}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
