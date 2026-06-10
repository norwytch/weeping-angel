"""Tamper-evident, append-only witness ledger.

This is the *indelible observer* in the Weeping Angel model: a forward
hash-chained log in which every record commits to its predecessor. Any edit,
deletion, or reordering of a past record breaks the chain and is caught by
:meth:`Ledger.verify`. This is the system analog of the temporal paradox that
locks an Angel forever -- you cannot rewrite the past without producing a
contradiction in the record.

In production this ledger would be written *out-of-band* by a kernel minifilter
(so userland malware can neither enumerate nor reach it) and periodically
anchored to write-once / off-box storage so that even the most recent record
cannot be silently rewritten. Here it is an in-process, pure-stdlib
implementation so the integrity properties can be demonstrated and tested
directly.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, replace
from typing import Any

GENESIS_HASH = "0" * 64


def _canonical(event: dict[str, Any]) -> str:
    """Deterministic serialization so hashing is stable across runs."""
    return json.dumps(event, sort_keys=True, separators=(",", ":"))


def _digest(index: int, recorded_at: float, event: dict[str, Any], prev_hash: str) -> str:
    payload = f"{index}|{recorded_at!r}|{_canonical(event)}|{prev_hash}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Record:
    """A single immutable, chained observation."""

    index: int
    recorded_at: float
    event: dict[str, Any]
    prev_hash: str
    hash: str

    def recompute_hash(self) -> str:
        return _digest(self.index, self.recorded_at, self.event, self.prev_hash)


@dataclass
class VerifyResult:
    ok: bool
    problems: list[str] = field(default_factory=list)

    def __bool__(self) -> bool:  # lets callers write `if ledger.verify():`
        return self.ok


class Ledger:
    """An append-only, hash-chained log of observed file-system events."""

    def __init__(self) -> None:
        self._records: list[Record] = []

    def __len__(self) -> int:
        return len(self._records)

    @property
    def head_hash(self) -> str:
        return self._records[-1].hash if self._records else GENESIS_HASH

    def head_hash_at(self, length: int) -> str:
        """Head hash of the chain truncated to ``length`` records (GENESIS for
        0). Lets an external anchor pin "the head when I had N records" so a
        later tail-truncation is detectable."""
        if length <= 0:
            return GENESIS_HASH
        if length > len(self._records):
            raise IndexError(f"length {length} exceeds ledger size {len(self._records)}")
        return self._records[length - 1].hash

    def append(self, event: dict[str, Any], recorded_at: float) -> Record:
        """Commit a new observation. ``recorded_at`` is the *true* time the
        operation was seen by the out-of-band recorder (a logical clock in the
        simulator, a kernel timestamp in production)."""
        index = len(self._records)
        prev_hash = self.head_hash
        rec = Record(
            index=index,
            recorded_at=recorded_at,
            event=dict(event),
            prev_hash=prev_hash,
            hash=_digest(index, recorded_at, event, prev_hash),
        )
        self._records.append(rec)
        return rec

    def records_for(self, file_id: str) -> list[Record]:
        return [r for r in self._records if r.event.get("file_id") == file_id]

    def all_records(self) -> list[Record]:
        return list(self._records)

    def verify(self) -> VerifyResult:
        """Return whether the chain is internally consistent.

        Detects three classes of tampering:
          * a record's payload edited in place (stored hash no longer matches),
          * a broken link (``prev_hash`` does not match the prior record),
          * deletion or reordering (index discontinuity / link break).
        """
        problems: list[str] = []
        expected_prev = GENESIS_HASH
        for i, rec in enumerate(self._records):
            if rec.index != i:
                problems.append(
                    f"index discontinuity at position {i}: record claims index {rec.index} "
                    "(record deleted or reordered)"
                )
            if rec.hash != rec.recompute_hash():
                problems.append(
                    f"record {rec.index}: stored hash does not match contents "
                    "(payload edited in place)"
                )
            if rec.prev_hash != expected_prev:
                problems.append(
                    f"record {rec.index}: broken chain link "
                    "(a prior record was altered or removed)"
                )
            expected_prev = rec.hash
        return VerifyResult(ok=not problems, problems=problems)

    # -- demo / adversary hooks -------------------------------------------------
    # These exist so the simulator's "advanced Angel" can *attempt* to scrub the
    # journal, letting us show that verify() catches it. A real attacker has no
    # such handle: the ledger lives behind a kernel boundary and is anchored
    # off-box.

    def simulate_inplace_edit(self, index: int, new_event: dict[str, Any]) -> None:
        """A naive attacker overwrites a past event but cannot recompute the
        whole forward chain (later records still commit to the old hash)."""
        old = self._records[index]
        self._records[index] = replace(self._records[index], event=dict(new_event))
        # Sophisticated variant: also patch this record's own hash. The break
        # then surfaces at index+1, whose prev_hash still points at the old hash.
        patched = self._records[index]
        self._records[index] = replace(patched, hash=patched.recompute_hash())
        _ = old  # documented: successor link is now stale -> verify() fails

    def simulate_truncate(self, keep: int) -> None:
        """Attacker drops the tail of the log. Detectable only if the head is
        externally anchored; see docs/DESIGN.md."""
        self._records = self._records[:keep]
