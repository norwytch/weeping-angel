"""Generate a small, spec-compliant USN change journal ($J) for the parser demo.

Each entry is a real USN_RECORD_V2 (the format ``$Extend\\$UsnJrnl:$J`` holds),
with a kernel FILETIME and reason flags. The stream starts with a sparse zero
prefix, like a real $J. This is the inverse of quantumlock/adapters/usn.py.

    python examples/data/make_usn_sample.py      # regenerates examples/data/sample.usnjrnl

Records: evil.exe is created, written, then has a BASIC_INFO_CHANGE (the stomp);
report.docx is created and written. Pairs with sample.mft (same file names).
"""

from __future__ import annotations

import datetime
import struct
from pathlib import Path

FILETIME_EPOCH_DIFF = 11_644_473_600

DATA_EXTEND = 0x00000002
FILE_CREATE = 0x00000800
BASIC_INFO_CHANGE = 0x00040000
CLOSE = 0x80000000


def filetime(year, month, day, hour=0, minute=0, second=0, ticks100ns=0) -> int:
    dt = datetime.datetime(year, month, day, hour, minute, second, tzinfo=datetime.timezone.utc)
    return (int(dt.timestamp()) + FILETIME_EPOCH_DIFF) * 10_000_000 + ticks100ns


def usn_record(usn: int, file_ref: int, parent_ref: int, ts: int, reason: int, name: str) -> bytes:
    name16 = name.encode("utf-16-le")
    base = 0x3C
    total = base + len(name16)
    total_padded = total + (-total % 8)
    b = bytearray(total_padded)
    struct.pack_into("<I", b, 0x00, total_padded)  # record length
    struct.pack_into("<H", b, 0x04, 2)  # major version
    struct.pack_into("<H", b, 0x06, 0)  # minor version
    struct.pack_into("<Q", b, 0x08, file_ref)
    struct.pack_into("<Q", b, 0x10, parent_ref)
    struct.pack_into("<Q", b, 0x18, usn)
    struct.pack_into("<Q", b, 0x20, ts)
    struct.pack_into("<I", b, 0x28, reason)
    struct.pack_into("<H", b, 0x38, len(name16))  # file name length (bytes)
    struct.pack_into("<H", b, 0x3A, 0x3C)  # file name offset
    b[0x3C : 0x3C + len(name16)] = name16
    return bytes(b)


def build_sample() -> bytes:
    out = bytearray(16)  # sparse zero prefix, like a real $J
    evil, report, root = 92, 81, 5

    out += usn_record(8, evil, root, filetime(2024, 5, 1, 9, 15, 22, 7_654_321),
                      FILE_CREATE, "evil.exe")
    out += usn_record(16, evil, root, filetime(2024, 5, 1, 9, 16, 0),
                      DATA_EXTEND | CLOSE, "evil.exe")
    out += usn_record(24, evil, root, filetime(2024, 5, 1, 10, 0, 0),
                      BASIC_INFO_CHANGE | CLOSE, "evil.exe")  # the timestomp
    out += usn_record(32, report, root, filetime(2024, 3, 10, 14, 2, 11, 1_234_567),
                      FILE_CREATE, "report.docx")
    out += usn_record(40, report, root, filetime(2024, 3, 12, 8, 30, 0, 7_654_321),
                      DATA_EXTEND | CLOSE, "report.docx")
    return bytes(out)


def main() -> None:
    out = Path(__file__).with_name("sample.usnjrnl")
    data = build_sample()
    out.write_bytes(data)
    print(f"wrote {out} ({len(data)} bytes)")


if __name__ == "__main__":
    main()
