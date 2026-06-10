"""Detection-efficacy harness: precision / recall over a labeled corpus.

A detector is only as good as its false-positive / false-negative behavior. This
harness builds a deterministic, labeled corpus of synthetic timelines -- clean
files, *benign* timestamp-setting operations (archivers / restore / ``cp -p``),
and several timestomp variants -- runs the :class:`DivergenceDetector` over each,
and reports a confusion matrix with precision, recall, and F1.

The benign-setinfo class is the one that matters: it is exactly the case that a
naive "any metadata write is evil" rule flags as a false positive. A healthy
report shows it landing in the true-negative column.

    python -m quantumlock.efficacy
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from .detector import DivergenceDetector
from .ledger import Ledger
from .witnesses import MACE, DisplayWitness, JournalWitness, MFTWitness

BENIGN = "benign"
MALICIOUS = "malicious"


def _detector(si, birth, journal_events, now, trusted=None) -> DivergenceDetector:
    d = DisplayWitness()
    d.set_times("f", si)
    m = MFTWitness()
    if birth is not None:
        m.record_birth("f", birth)
    led = Ledger()
    for ev, t in journal_events:
        led.append({"file_id": "f", **ev}, recorded_at=t)
    j = JournalWitness(led)
    return DivergenceDetector(d, m, j, now=now, trusted_setinfo_actors=trusted)


def _make_case(rng: random.Random, kind: str):
    """Return (label, detector) for one synthetic file of the given ``kind``."""
    # fractional birth/write so genuine ops carry sub-second precision
    birth = rng.uniform(1.6e9, 1.7e9) + rng.uniform(0.05, 0.95)
    write = birth + rng.uniform(10, 1e6) + rng.uniform(0.05, 0.95)
    now = write + rng.uniform(10, 1e6)
    base_journal = [({"op": "create"}, birth), ({"op": "write"}, write)]

    if kind == "clean":
        si = MACE(modified=write, created=birth)
        return BENIGN, _detector(si, birth, base_journal, now)

    if kind == "benign_setinfo":
        # restore/copy sets a plausible time: >= true last write, <= now, birth intact
        plausible = rng.uniform(write, now)
        si = MACE(modified=plausible, created=birth)
        ev = base_journal + [
            ({"op": "setinfo", "written_modified": plausible, "written_created": birth}, now)
        ]
        return BENIGN, _detector(si, birth, ev, now)

    if kind == "stomp_backdate":
        forged_c = birth - rng.uniform(1e6, 1e8)
        forged_m = forged_c + rng.uniform(1, 1e5)
        si = MACE(modified=forged_m, created=forged_c)
        ev = base_journal + [
            ({"op": "setinfo", "written_modified": forged_m, "written_created": forged_c}, now)
        ]
        return MALICIOUS, _detector(si, birth, ev, now)

    if kind == "stomp_subsecond":
        si = MACE(modified=float(int(write)), created=float(int(birth)))
        return MALICIOUS, _detector(si, birth, base_journal, now)

    if kind == "stomp_future":
        si = MACE(modified=now + rng.uniform(1e3, 1e7), created=birth)
        return MALICIOUS, _detector(si, birth, base_journal, now)

    raise ValueError(kind)


@dataclass
class Efficacy:
    tp: int
    fp: int
    tn: int
    fn: int

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 1.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def accuracy(self) -> float:
        total = self.tp + self.fp + self.tn + self.fn
        return (self.tp + self.tn) / total if total else 1.0


def evaluate(n_per_kind: int = 200, seed: int = 1729) -> Efficacy:
    """Build a balanced corpus and score the detector. Deterministic for a seed."""
    # synthetic test corpus, not security-sensitive
    rng = random.Random(seed)  # nosec B311
    kinds = ["clean", "benign_setinfo", "stomp_backdate", "stomp_subsecond", "stomp_future"]
    tp = fp = tn = fn = 0
    for _ in range(n_per_kind):
        for kind in kinds:
            label, det = _make_case(rng, kind)
            predicted_malicious = bool(det.scan("f"))
            if label == MALICIOUS and predicted_malicious:
                tp += 1
            elif label == MALICIOUS:
                fn += 1
            elif predicted_malicious:
                fp += 1
            else:
                tn += 1
    return Efficacy(tp=tp, fp=fp, tn=tn, fn=fn)


def main() -> int:
    e = evaluate()
    print("Detection efficacy over a labeled synthetic corpus")
    print("=" * 52)
    print(f"  TP={e.tp}  FP={e.fp}  TN={e.tn}  FN={e.fn}")
    print(f"  precision = {e.precision:.4f}")
    print(f"  recall    = {e.recall:.4f}")
    print(f"  F1        = {e.f1:.4f}")
    print(f"  accuracy  = {e.accuracy:.4f}")
    if e.fp == 0:
        print("\n  benign timestamp-setting (archivers / restore / cp -p) -> 0 false positives")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
