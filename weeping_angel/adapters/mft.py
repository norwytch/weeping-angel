"""Executable offline adapter: run the divergence rules on a raw NTFS $MFT.

Where ``mft_csv.py`` trusts a parser (MFTECmd) to have already decoded the
records, this reads the on-disk bytes itself: FILE records, the Update Sequence
Array fixups, and the resident ``$STANDARD_INFORMATION`` (0x10) and
``$FILE_NAME`` (0x30) attributes, decoding Windows FILETIME (100ns ticks since
1601-01-01 UTC) into epoch seconds with sub-second precision intact. It then
drives the same :class:`~weeping_angel.detector.DivergenceDetector`, so the
``$SI``-vs-``$FN`` comparison (rules R1 and R6) runs on genuine NTFS structures.

Point it at a ``$MFT`` extracted from a live volume (FTK Imager, or ``dd`` of the
``$MFT`` from a raw image) or at the bundled sample:

    python -m weeping_angel.adapters.mft examples/data/sample.mft

Only resident $SI/$FN attributes are needed for timestomp detection, so the
parser deliberately ignores data runs, non-resident attributes, and attribute
lists. Records are assumed to be the standard 1024 bytes.
"""

from __future__ import annotations

import mmap
import os
import struct
import sys
from collections.abc import Iterator
from dataclasses import dataclass

from ..detector import DivergenceDetector, Finding
from ..ledger import Ledger
from ..witnesses import MACE, DisplayWitness, JournalWitness, MFTWitness

_FILE_SIGNATURE = b"FILE"
_ATTR_STANDARD_INFORMATION = 0x10
_ATTR_FILE_NAME = 0x30
_ATTR_END = 0xFFFFFFFF
_FLAG_IN_USE = 0x01
_DOS_NAMESPACE = 2  # 8.3 short name; prefer the Win32 long name when both exist
_FILETIME_EPOCH_DIFF = 11_644_473_600  # seconds between 1601-01-01 and 1970-01-01
_SECTOR = 512
_RECORD_SIZE = 1024


def filetime_to_epoch(ft: int) -> float | None:
    """Windows FILETIME (100ns ticks since 1601-01-01 UTC) to Unix epoch
    seconds, keeping sub-second precision. 0 means the field is unset."""
    if ft == 0:
        return None
    return ft / 10_000_000.0 - _FILETIME_EPOCH_DIFF


def _apply_fixups(rec: bytearray, usa_offset: int, usa_count: int) -> None:
    """Reverse the Update Sequence Array. NTFS overwrites the last two bytes of
    every sector with a sequence number and stores the originals in the USA;
    restore them so attribute data that crosses a sector boundary is intact."""
    if usa_count == 0:
        return
    for i in range(1, usa_count):
        pos = i * _SECTOR - 2
        if usa_offset + 2 * i + 2 <= len(rec) and pos + 2 <= len(rec):
            original = struct.unpack_from("<H", rec, usa_offset + 2 * i)[0]
            struct.pack_into("<H", rec, pos, original)


@dataclass
class ParsedRecord:
    record_number: int
    name: str | None
    si_created: float | None
    si_modified: float | None
    fn_created: float | None
    fn_modified: float | None = None


def _parse_standard_information(content: bytes) -> tuple[float | None, float | None]:
    if len(content) < 16:
        return None, None
    created = filetime_to_epoch(struct.unpack_from("<Q", content, 0x00)[0])
    modified = filetime_to_epoch(struct.unpack_from("<Q", content, 0x08)[0])
    return created, modified


def _parse_file_name(content: bytes) -> tuple[float | None, float | None, str | None, int]:
    if len(content) < 0x42:
        return None, None, None, -1
    created = filetime_to_epoch(struct.unpack_from("<Q", content, 0x08)[0])
    modified = filetime_to_epoch(struct.unpack_from("<Q", content, 0x10)[0])
    name_chars = content[0x40]
    namespace = content[0x41]
    name = None
    end = 0x42 + name_chars * 2
    if end <= len(content):
        name = content[0x42:end].decode("utf-16-le", errors="replace")
    return created, modified, name, namespace


def parse_record(raw: bytes) -> ParsedRecord | None:
    """Parse one FILE record. Returns ``None`` for slack, unallocated, or
    non-FILE records (e.g. ``BAAD``)."""
    if len(raw) < 0x30 or raw[0:4] != _FILE_SIGNATURE:
        return None
    rec = bytearray(raw)
    usa_offset = struct.unpack_from("<H", rec, 0x04)[0]
    usa_count = struct.unpack_from("<H", rec, 0x06)[0]
    first_attr = struct.unpack_from("<H", rec, 0x14)[0]
    flags = struct.unpack_from("<H", rec, 0x16)[0]
    record_number = struct.unpack_from("<I", rec, 0x2C)[0]
    if not flags & _FLAG_IN_USE:
        return None
    _apply_fixups(rec, usa_offset, usa_count)

    si_created = si_modified = fn_created = fn_modified = None
    name: str | None = None
    best_namespace = -1
    n = len(rec)
    off = first_attr
    while off + 8 <= n:
        attr_type = struct.unpack_from("<I", rec, off)[0]
        if attr_type == _ATTR_END:
            break
        attr_len = struct.unpack_from("<I", rec, off + 4)[0]
        if attr_len < 24 or off + attr_len > n:
            break
        resident = rec[off + 8] == 0
        if resident:
            content_len = struct.unpack_from("<I", rec, off + 0x10)[0]
            content_off = struct.unpack_from("<H", rec, off + 0x14)[0]
            start = off + content_off
            stop = start + content_len
            if 0 < content_len and stop <= n:
                content = bytes(rec[start:stop])
                if attr_type == _ATTR_STANDARD_INFORMATION:
                    si_created, si_modified = _parse_standard_information(content)
                elif attr_type == _ATTR_FILE_NAME:
                    fc, fm, nm, ns = _parse_file_name(content)
                    if fc is not None and fn_created is None:
                        fn_created = fc
                    if fm is not None and fn_modified is None:
                        fn_modified = fm
                    if nm is not None and ns != _DOS_NAMESPACE and ns > best_namespace:
                        name, best_namespace = nm, ns
        off += attr_len
    return ParsedRecord(record_number, name, si_created, si_modified, fn_created, fn_modified)


def iter_records(
    data: bytes | mmap.mmap, record_size: int = _RECORD_SIZE
) -> Iterator[ParsedRecord]:
    for off in range(0, len(data) - record_size + 1, record_size):
        rec = parse_record(data[off : off + record_size])
        if rec is not None:
            yield rec


def load_witnesses(
    data: bytes | mmap.mmap, record_size: int = _RECORD_SIZE
) -> tuple[DisplayWitness, MFTWitness, list[str]]:
    display = DisplayWitness()
    mft = MFTWitness()
    file_ids: list[str] = []
    for r in iter_records(data, record_size):
        fid = r.name or f"record-{r.record_number}"
        display.set_times(fid, MACE(modified=r.si_modified, created=r.si_created))
        if r.fn_created is not None:
            mft.record_birth(fid, r.fn_created)
        if r.fn_modified is not None:
            mft.record_modified(fid, r.fn_modified)
        file_ids.append(fid)
    return display, mft, file_ids


def scan_mft(
    path: str, now: float | None = None, record_size: int = _RECORD_SIZE
) -> dict[str, list[Finding]]:
    """Parse a raw $MFT and return findings per file. The file is memory-mapped
    rather than read whole, so this scales to multi-GB images. No USN here, so
    the journal is empty and journal-only rules (R2/R4) stay silent by design."""
    with open(path, "rb") as fh:
        size = os.fstat(fh.fileno()).st_size
        if size == 0:
            return {}
        with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as data:
            display, mft, file_ids = load_witnesses(data, record_size)
            journal = JournalWitness(Ledger())  # empty: MFT-only evidence
            detector = DivergenceDetector(display, mft, journal, now=now)
            return {fid: detector.scan(fid) for fid in file_ids}


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    fmt = None
    if "--format" in argv:
        i = argv.index("--format")
        if i + 1 >= len(argv):
            print("usage: python -m weeping_angel.adapters.mft <mft-image> [--format ecs|ocsf]")
            return 2
        fmt = argv[i + 1]
        del argv[i : i + 2]
    if not argv:
        print("usage: python -m weeping_angel.adapters.mft <mft-image> [--format ecs|ocsf]")
        return 2
    results = scan_mft(argv[0])

    if fmt:  # SIEM-ready output for a detection pipeline
        from ..export import to_jsonl

        all_findings = [f for fs in results.values() for f in fs]
        if all_findings:
            print(to_jsonl(all_findings, schema=fmt))
        return 0

    flagged = {fid: fs for fid, fs in results.items() if fs}
    print(f"Parsed {len(results)} record(s); {len(flagged)} with timestomp indicators.\n")
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
