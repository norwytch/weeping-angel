"""External head anchoring -- closing the tail-truncation gap.

The hash chain (:mod:`weeping_angel.ledger`) makes any edit to an *interior*
record detectable: a later record's ``prev_hash`` stops matching. The one gap it
cannot close on its own is truncation of the *tail* -- an attacker who drops the
most recent records leaves a shorter but still self-consistent chain.

The fix is to anchor the head out of the attacker's reach: periodically commit
``(length, head_hash)`` to an append-only store the in-guest adversary can
neither reach nor forge -- an off-box collector, a write-once medium, or a
transparency log. Here that store is authenticated with an HMAC over a key the
attacker never holds; in production this stands in for an ed25519-signed
transparency-log checkpoint (RFC 6962 style). ``compare_digest`` is used for the
verification so the check is constant-time.

A dropped tail then shows up as "the anchored length is ahead of what's on
disk"; a rewritten interior record shows up as "the anchored head at that length
no longer matches."
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field

from .ledger import GENESIS_HASH, Ledger


@dataclass(frozen=True)
class Checkpoint:
    length: int
    head_hash: str
    mac: str


@dataclass
class AnchorVerifyResult:
    ok: bool
    problems: list[str] = field(default_factory=list)

    def __bool__(self) -> bool:
        return self.ok


class Anchor:
    """An off-box, append-only set of authenticated head checkpoints.

    The signing key models a secret held only by the external collector, so the
    in-guest attacker cannot mint a checkpoint that endorses a truncated or
    rewritten ledger.
    """

    def __init__(self, key: bytes) -> None:
        if not key:
            raise ValueError("anchor requires a non-empty signing key")
        self._key = key
        self._checkpoints: list[Checkpoint] = []

    def _mac(self, length: int, head_hash: str) -> str:
        msg = f"{length}|{head_hash}".encode()
        return hmac.new(self._key, msg, hashlib.sha256).hexdigest()

    def checkpoint(self, ledger: Ledger) -> Checkpoint:
        """Pin the ledger's current head. Call periodically / on a cadence."""
        length = len(ledger)
        head = ledger.head_hash
        cp = Checkpoint(length=length, head_hash=head, mac=self._mac(length, head))
        self._checkpoints.append(cp)
        return cp

    @property
    def checkpoints(self) -> list[Checkpoint]:
        return list(self._checkpoints)

    def verify(self, ledger: Ledger) -> AnchorVerifyResult:
        """Check the ledger against every anchored checkpoint (and its own
        internal chain). Detects tail truncation and interior rewrites that the
        chain alone, post-truncation, would miss."""
        problems: list[str] = []

        chain = ledger.verify()
        if not chain.ok:
            problems.extend(chain.problems)

        for cp in self._checkpoints:
            # The checkpoint itself must be authentic -- an attacker without the
            # key cannot forge one that endorses tampered state.
            if not hmac.compare_digest(self._mac(cp.length, cp.head_hash), cp.mac):
                problems.append(
                    f"anchored checkpoint at length {cp.length} has an invalid MAC "
                    "(forged or corrupted anchor record)"
                )
                continue
            if len(ledger) < cp.length:
                problems.append(
                    f"ledger truncated: {len(ledger)} records on disk but length "
                    f"{cp.length} was anchored (tail dropped)"
                )
                continue
            try:
                actual = ledger.head_hash_at(cp.length)
            except IndexError:
                actual = GENESIS_HASH
            if not hmac.compare_digest(actual, cp.head_hash):
                problems.append(
                    f"anchored head at length {cp.length} does not match the on-disk "
                    "chain (history was rewritten)"
                )

        return AnchorVerifyResult(ok=not problems, problems=problems)
