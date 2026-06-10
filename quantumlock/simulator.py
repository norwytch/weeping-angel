"""A small filesystem simulation with an Angel that timestomps when it believes
it is unobserved -- and an out-of-band recorder that sees it anyway.

Everything runs on a logical clock (a monotonically increasing integer) so runs
are deterministic and the "true" timeline is unambiguous.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .ledger import Ledger
from .witnesses import MACE, DisplayWitness, JournalWitness, MFTWitness


class Clock:
    """Monotonic logical clock. Each tick advances a whole second but the
    emitted timestamp also carries a deterministic sub-second component, so
    genuine OS operations look like real NTFS timestamps (100ns FILETIME
    resolution). A whole-second-only value is therefore a tell, not the norm --
    which is what rule ``R6`` keys on."""

    def __init__(self, start: int = 1000) -> None:
        self._step = int(start)

    @staticmethod
    def _stamp(step: int) -> float:
        # Deterministic, varying sub-second part in [0, 1) so runs stay
        # reproducible while every real op carries fractional 100ns-grade precision.
        frac = (step * 7919 % 10_000_000) / 10_000_000.0
        return step + frac

    def tick(self) -> float:
        step = self._step
        self._step += 1
        return self._stamp(step)

    def now(self) -> float:
        return self._stamp(self._step)


class ObservationOracle:
    """What the Angel can see: only *in-band* watchers. The out-of-band recorder
    is deliberately not represented here -- that is the whole point."""

    def __init__(self) -> None:
        self.procmon_running = False
        self.handle_open = False
        self.debugger_attached = False

    def is_observed(self) -> bool:
        return self.procmon_running or self.handle_open or self.debugger_attached


class FileSystemSim:
    def __init__(self) -> None:
        self.clock = Clock()
        self.ledger = Ledger()
        self.display = DisplayWitness()
        self.mft = MFTWitness()
        self.journal = JournalWitness(self.ledger)
        self.oracle = ObservationOracle()

    # -- legitimate operations (also seen by the out-of-band recorder) ----------
    def create_file(self, file_id: str) -> None:
        t = self.clock.tick()
        self.display.set_times(file_id, MACE(modified=t, accessed=t, created=t, entry_modified=t))
        self.mft.record_birth(file_id, t)
        self.ledger.append({"file_id": file_id, "op": "create"}, recorded_at=t)

    def write_file(self, file_id: str) -> None:
        t = self.clock.tick()
        prev = self.display.observe(file_id) or MACE()
        self.display.set_times(
            file_id, MACE(modified=t, accessed=t, created=prev.created, entry_modified=t)
        )
        self.ledger.append({"file_id": file_id, "op": "write"}, recorded_at=t)

    # -- the stomp ($SI write) -- the recorder captures it out-of-band ----------
    def stomp(self, file_id: str, forged: MACE) -> None:
        t = self.clock.tick()  # the *real* time the metadata was set
        self.display.set_times(file_id, forged)
        self.ledger.append(
            {
                "file_id": file_id,
                "op": "setinfo",
                "written_modified": forged.modified,
                "written_created": forged.created,
            },
            recorded_at=t,
        )


@dataclass
class Angel:
    """Quantum-locked timestomper. Moves iff it believes it is unobserved."""

    target: str
    forged: MACE = field(
        # internally-consistent lie (created < modified) that also predates the
        # real birth time: looks like an old file, so single-source heuristics
        # miss it. Only cross-witness checks catch it.
        default_factory=lambda: MACE(
            modified=20.0, accessed=20.0, created=10.0, entry_modified=20.0
        )
    )

    def tick(self, sim: FileSystemSim) -> str:
        if sim.oracle.is_observed():
            return "STONE"  # frozen, harmless
        sim.stomp(self.target, self.forged)
        return "MOVING"


@dataclass
class AdvancedAngel(Angel):
    """A sophisticated variant that *also* tries to scrub the journal it does not
    realize it cannot reach (here we hand it a direct ledger edit to show the
    chain catches it)."""

    def tick(self, sim: FileSystemSim) -> str:
        result = super().tick(sim)
        if result == "MOVING":
            recs = sim.ledger.records_for(self.target)
            if recs:
                # try to backdate the create record so the timeline looks old
                sim.ledger.simulate_inplace_edit(
                    recs[0].index,
                    {"file_id": self.target, "op": "create", "forged_birth": 10.0},
                )
        return result
