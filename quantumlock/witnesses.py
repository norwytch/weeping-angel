"""Witnesses: independent vantage points on a file's timestamps.

The defeat hinges on having several witnesses that *must* agree if nothing
forged anything. No single witness catches the Angel in the act; their
**disagreement** is the fingerprint -- the system analog of trapping two
Angels so they lock each other.

Three witnesses are modeled, each mirroring a real NTFS / OS artifact:

* :class:`DisplayWitness`   -> ``$STANDARD_INFORMATION`` (``$SI``). What Explorer
  and most tools show. Freely writable by userland; this is what a classic
  timestomper edits.
* :class:`MFTWitness`       -> ``$FILE_NAME`` (``$FN``). Birth time set by the
  kernel in the MFT; left untouched by classic stompers.
* :class:`JournalWitness`   -> USN change journal / external append-only log,
  backed by the tamper-evident :class:`~quantumlock.ledger.Ledger`. Records the
  *true* time of every operation, out-of-band.

Real adapters for each live in ``quantumlock/adapters/windows.py`` (design-only).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from .ledger import Ledger

# Content-changing operations whose true time we trust from the journal.
_CONTENT_OPS = {"create", "write"}


@dataclass(frozen=True)
class MACE:
    """Modified / Accessed / Created(birth) / Entry-modified, as epoch floats.

    ``None`` means "this witness does not assert this field."
    """

    modified: float | None = None
    accessed: float | None = None
    created: float | None = None
    entry_modified: float | None = None


class Witness(ABC):
    """Something that can report what it believes a file's timestamps are."""

    name: str

    @abstractmethod
    def observe(self, file_id: str) -> MACE | None:
        """Return the timestamps this witness asserts, or ``None`` if unknown."""


class DisplayWitness(Witness):
    """``$SI`` analog: mutable, userland-writable. The Angel edits this."""

    name = "display($SI)"

    def __init__(self) -> None:
        self._store: dict[str, MACE] = {}

    def observe(self, file_id: str) -> MACE | None:
        return self._store.get(file_id)

    def set_times(self, file_id: str, mace: MACE) -> None:
        self._store[file_id] = mace


class MFTWitness(Witness):
    """``$FN`` analog: kernel-set birth time, not touched by classic stompers."""

    name = "mft($FN)"

    def __init__(self) -> None:
        self._birth: dict[str, float] = {}
        self._modified: dict[str, float] = {}

    def observe(self, file_id: str) -> MACE | None:
        if file_id not in self._birth:
            return None
        return MACE(created=self._birth[file_id], modified=self._modified.get(file_id))

    def record_birth(self, file_id: str, when: float) -> None:
        self._birth.setdefault(file_id, when)

    def record_modified(self, file_id: str, when: float) -> None:
        """The ``$FN`` modified time, kernel-set and left alone by classic
        stompers; lets the detector compare it against the displayed modified."""
        self._modified.setdefault(file_id, when)


class JournalWitness(Witness):
    """USN / external-log analog. Reconstructs the *true* timeline from the
    tamper-evident ledger. The Angel has no handle to this in the basic model:
    it is written out-of-band."""

    name = "journal(USN)"

    def __init__(self, ledger: Ledger) -> None:
        self._ledger = ledger

    @property
    def ledger(self) -> Ledger:
        return self._ledger

    def observe(self, file_id: str) -> MACE | None:
        recs = self._ledger.records_for(file_id)
        if not recs:
            return None
        created = None
        modified = None
        for r in recs:
            op = r.event.get("op")
            if op == "create":
                created = r.recorded_at
            if op in _CONTENT_OPS:
                modified = r.recorded_at  # true last content change
        return MACE(created=created, modified=modified)

    def setinfo_events(self, file_id: str) -> list[dict]:
        """Metadata-set operations the recorder captured, with the real time the
        op occurred and the value that was written. The act of stomping, seen."""
        out = []
        for r in self._ledger.records_for(file_id):
            if r.event.get("op") == "setinfo":
                out.append({"real_time": r.recorded_at, **r.event})
        return out
