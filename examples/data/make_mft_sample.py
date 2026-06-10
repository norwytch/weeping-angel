"""Generate a small, spec-compliant NTFS $MFT image for the binary parser demo.

Each record is a real 1024-byte FILE record: a proper header, an Update Sequence
Array with fixups, and resident $STANDARD_INFORMATION (0x10) and $FILE_NAME
(0x30) attributes carrying Windows FILETIME timestamps. The structure follows the
NTFS on-disk format, so MFTECmd / analyzeMFT would parse it too; only the values
are hand-chosen. This is the inverse of quantumlock/adapters/mft.py -- writing
the format we elsewhere read.

    python examples/data/make_mft_sample.py      # regenerates examples/data/sample.mft

Two files are written: a clean `report.docx`, and `evil.exe` whose $SI creation
is backdated below its $FN birth and zeroed to a whole second (trips R1 and R6).
"""

from __future__ import annotations

import datetime
import struct
from pathlib import Path

SECTOR = 512
RECORD_SIZE = 1024
FILETIME_EPOCH_DIFF = 11_644_473_600


def filetime(year, month, day, hour=0, minute=0, second=0, ticks100ns=0) -> int:
    """Build a Windows FILETIME (100ns ticks since 1601-01-01 UTC)."""
    dt = datetime.datetime(year, month, day, hour, minute, second, tzinfo=datetime.timezone.utc)
    whole_seconds = int(dt.timestamp())
    return (whole_seconds + FILETIME_EPOCH_DIFF) * 10_000_000 + ticks100ns


def _resident_attr(attr_type: int, attr_id: int, content: bytes) -> bytes:
    header_len = 0x18
    total = header_len + len(content)
    total_padded = total + (-total % 8)
    hdr = bytearray(header_len)
    struct.pack_into("<I", hdr, 0x00, attr_type)
    struct.pack_into("<I", hdr, 0x04, total_padded)
    hdr[0x08] = 0  # resident
    hdr[0x09] = 0  # name length
    struct.pack_into("<H", hdr, 0x0A, 0)  # name offset
    struct.pack_into("<H", hdr, 0x0C, 0)  # flags
    struct.pack_into("<H", hdr, 0x0E, attr_id)
    struct.pack_into("<I", hdr, 0x10, len(content))  # content length
    struct.pack_into("<H", hdr, 0x14, header_len)  # content offset
    return bytes(hdr) + content + b"\x00" * (total_padded - total)


def _si_content(created: int, modified: int, changed: int, accessed: int) -> bytes:
    c = bytearray(0x30)
    struct.pack_into("<Q", c, 0x00, created)
    struct.pack_into("<Q", c, 0x08, modified)
    struct.pack_into("<Q", c, 0x10, changed)
    struct.pack_into("<Q", c, 0x18, accessed)
    return bytes(c)  # 0x20 DOS flags / versions left zero


def _fn_content(
    parent_ref: int, created: int, modified: int, changed: int, accessed: int, name: str
) -> bytes:
    name_utf16 = name.encode("utf-16-le")
    c = bytearray(0x42 + len(name_utf16))
    struct.pack_into("<Q", c, 0x00, parent_ref)
    struct.pack_into("<Q", c, 0x08, created)
    struct.pack_into("<Q", c, 0x10, modified)
    struct.pack_into("<Q", c, 0x18, changed)
    struct.pack_into("<Q", c, 0x20, accessed)
    # 0x28 allocated size / 0x30 real size / 0x38 flags / 0x3C reparse left zero
    c[0x40] = len(name)  # name length in characters
    c[0x41] = 1  # Win32 namespace
    c[0x42:] = name_utf16
    return bytes(c)


def build_record(
    record_number: int,
    name: str,
    si_times: tuple[int, int, int, int],
    fn_times: tuple[int, int, int, int],
    parent_ref: int = (5 << 48) | 5,  # the root directory ($MFT record 5)
) -> bytes:
    usa_offset = 0x30
    usa_count = RECORD_SIZE // SECTOR + 1  # one sequence number + one entry per sector
    first_attr = 0x38

    si = _resident_attr(0x10, 1, _si_content(*si_times))
    fn = _resident_attr(0x30, 2, _fn_content(parent_ref, *fn_times, name))
    attrs = si + fn + struct.pack("<I", 0xFFFFFFFF)  # end-of-attributes marker
    used = first_attr + len(attrs)
    used_padded = used + (-used % 8)

    rec = bytearray(RECORD_SIZE)
    rec[0:4] = b"FILE"
    struct.pack_into("<H", rec, 0x04, usa_offset)
    struct.pack_into("<H", rec, 0x06, usa_count)
    struct.pack_into("<H", rec, 0x10, 1)  # sequence number
    struct.pack_into("<H", rec, 0x12, 1)  # hard-link count
    struct.pack_into("<H", rec, 0x14, first_attr)
    struct.pack_into("<H", rec, 0x16, 0x01)  # flags: in use, file
    struct.pack_into("<I", rec, 0x18, used_padded)
    struct.pack_into("<I", rec, 0x1C, RECORD_SIZE)
    struct.pack_into("<H", rec, 0x28, 3)  # next attribute id
    struct.pack_into("<I", rec, 0x2C, record_number)
    rec[first_attr : first_attr + len(attrs)] = attrs

    # Update Sequence Array fixups: stash each sector's last two bytes in the
    # USA and write the sequence number over them on disk.
    seq = 0x0001
    struct.pack_into("<H", rec, usa_offset, seq)
    for i in range(1, usa_count):
        pos = i * SECTOR - 2
        original = struct.unpack_from("<H", rec, pos)[0]
        struct.pack_into("<H", rec, usa_offset + 2 * i, original)
        struct.pack_into("<H", rec, pos, seq)
    return bytes(rec)


def build_sample() -> bytes:
    # report.docx: $SI and $FN agree, sub-second precision intact -> clean.
    birth = filetime(2024, 3, 10, 14, 2, 11, 1_234_567)
    mtime = filetime(2024, 3, 12, 8, 30, 0, 7_654_321)
    clean = build_record(
        64, "report.docx", (birth, mtime, mtime, mtime), (birth, mtime, mtime, mtime)
    )

    # evil.exe: true $FN birth in 2024; $SI backdated to a whole second in 2019.
    true_birth = filetime(2024, 5, 1, 9, 15, 22, 7_654_321)
    forged = filetime(2019, 1, 1, 0, 0, 0, 0)
    evil = build_record(
        65,
        "evil.exe",
        (forged, forged, true_birth, true_birth),
        (true_birth, true_birth, true_birth, true_birth),
    )
    return clean + evil


def main() -> None:
    out = Path(__file__).with_name("sample.mft")
    data = build_sample()
    out.write_bytes(data)
    print(f"wrote {out} ({len(data)} bytes, {len(data) // RECORD_SIZE} records)")


if __name__ == "__main__":
    main()
