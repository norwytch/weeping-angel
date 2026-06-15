"""A labeled corpus of per-file evidence, and the precision/recall scoring a
rule set is measured against.

The corpus extends the classes in :mod:`weeping_angel.efficacy` -- clean files,
benign timestamp-setting, and timestomp variants -- but expresses each case as a
flat feature dict (the quantities a
:class:`~weeping_angel.ruleforge.rule.CandidateRule` may reference) rather than a
full detector, and adds a class that needs a *conjunction* to catch cleanly. A
rule set is scored with the same confusion-matrix metrics the efficacy harness
reports, so "did the agent's rules help" is measured the same way the hand-written
rules are.

``stomp_widen`` is the headroom case. It widens the apparent active window on both
ends (birth pushed earlier *and* modified pushed later, both by a moderate amount)
without any single impossible value:

* a benign ``birth_skew`` file (FS migration / timezone bug) also has its birth
  moderately early, so ``si_created < fn_created`` alone false-positives on it;
* a benign ``restore_postdate`` file also has its modified time after the true
  last write, so ``si_modified > journal_last`` alone false-positives on it.

So no single comparison separates ``stomp_widen`` from benign without a false
positive -- only the conjunction of the two does. A greedy single-clause search
plateaus; an agent that can propose ``all_of([...])`` closes the gap.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from ..efficacy import BENIGN, MALICIOUS, Efficacy
from .rule import CandidateRule

# One labeled case: the per-file feature dict plus its kind and ground-truth label.
Case = tuple[dict[str, float], str, str]  # (features, kind, label)

KINDS = (
    "clean", "benign_setinfo", "birth_skew", "restore_postdate",
    "stomp_backdate", "stomp_subsecond", "stomp_future", "stomp_widen",
)

_MODERATE = (20_000, 80_000)        # a "moderate" shift, in whole seconds
_GROSS = (1_000_000, 100_000_000)   # a gross backdate, in whole seconds


def _features(rng: random.Random, kind: str) -> tuple[dict[str, float], str]:
    """Build one case's features. Shifts are whole-second integers so they
    preserve the sub-second fractional precision of genuine times (only a real
    stomp zeroes it out, which is what `whole_second` keys on)."""
    # Exact-integer base + a bounded fraction, shifted only by whole seconds, so
    # every genuine time keeps a clearly non-zero sub-second part (frac in
    # [0.1, 0.9]). Only an int() stomp zeroes it, which is what `whole_second` keys
    # on -- a wrapping fraction would make that check randomly false-positive.
    epoch_base = rng.randint(1_600_000_000, 1_700_000_000)
    birth = epoch_base + rng.uniform(0.1, 0.9)
    write = birth + rng.randint(10, 1_000_000)
    now = write + rng.randint(10, 1_000_000)
    now_far = write + rng.randint(200_000, 1_000_000)  # room for a postdate below now
    base = {"fn_created": birth, "journal_first": birth, "journal_last": write, "now": now}

    if kind == "clean":
        return {**base, "si_created": birth, "si_modified": write}, BENIGN
    if kind == "benign_setinfo":
        # restore/copy sets a plausible time: >= true last write, <= now, birth kept
        plausible = write + rng.randint(1, max(1, int(now - write)))
        return {**base, "si_created": birth, "si_modified": plausible}, BENIGN
    if kind == "birth_skew":
        # benign: birth moderately early (FS migration / tz bug), modified normal
        return {**base, "si_created": birth - rng.randint(*_MODERATE), "si_modified": write}, BENIGN
    if kind == "restore_postdate":
        # benign: a tool sets modified moderately after the true last write
        si_mod = write + rng.randint(*_MODERATE)
        far = {**base, "now": now_far}
        return {**far, "si_created": birth, "si_modified": si_mod}, BENIGN
    if kind == "stomp_backdate":
        forged_c = birth - rng.randint(*_GROSS)
        forged_m = forged_c + rng.randint(1, 100_000)
        return {**base, "si_created": forged_c, "si_modified": forged_m}, MALICIOUS
    if kind == "stomp_subsecond":
        si = {"si_created": float(int(birth)), "si_modified": float(int(write))}
        return {**base, **si}, MALICIOUS
    if kind == "stomp_future":
        si_mod = now + rng.randint(1000, 10_000_000)
        return {**base, "si_created": birth, "si_modified": si_mod}, MALICIOUS
    if kind == "stomp_widen":
        # malicious: birth pushed earlier AND modified pushed later, both moderate;
        # neither shift alone separates it from birth_skew / restore_postdate.
        si = {"si_created": birth - rng.randint(*_MODERATE),
              "si_modified": write + rng.randint(*_MODERATE)}
        return {**base, "now": now_far, **si}, MALICIOUS
    raise ValueError(kind)


def build_corpus(n_per_kind: int = 120, seed: int = 1729) -> list[Case]:
    """A balanced, deterministic labeled corpus."""
    rng = random.Random(seed)  # nosec B311 -- synthetic test corpus, not security-sensitive
    corpus: list[Case] = []
    for _ in range(n_per_kind):
        for kind in KINDS:
            feats, label = _features(rng, kind)
            corpus.append((feats, kind, label))
    return corpus


def predict(rules: list[CandidateRule], features: dict[str, float]) -> bool:
    """A file is flagged malicious if *any* rule fires (the detector's logic)."""
    return any(r.fires(features) for r in rules)


def score_ruleset(rules: list[CandidateRule], corpus: list[Case]) -> Efficacy:
    """Run the rule set over the corpus and return the confusion matrix."""
    tp = fp = tn = fn = 0
    for features, _kind, label in corpus:
        flagged = predict(rules, features)
        if label == MALICIOUS and flagged:
            tp += 1
        elif label == MALICIOUS:
            fn += 1
        elif flagged:
            fp += 1
        else:
            tn += 1
    return Efficacy(tp=tp, fp=fp, tn=tn, fn=fn)


@dataclass(frozen=True)
class Bar:
    """The acceptance bar a rule set must clear."""

    min_precision: float = 0.95
    min_recall: float = 0.95

    def met(self, eff: Efficacy) -> bool:
        return eff.precision >= self.min_precision and eff.recall >= self.min_recall


@dataclass(frozen=True)
class RuleSetResult:
    rules: tuple[CandidateRule, ...]
    score: Efficacy
    source: str                 # "agent" | "miner"
    iterations: int
    log: tuple[str, ...] = ()

    def met(self, bar: Bar) -> bool:
        return bar.met(self.score)

    def explain(self) -> str:
        s = self.score
        lines = [
            f"{self.source} rule set ({len(self.rules)} rule(s), {self.iterations} iteration(s)): "
            f"precision={s.precision:.3f} recall={s.recall:.3f} F1={s.f1:.3f} "
            f"(TP={s.tp} FP={s.fp} TN={s.tn} FN={s.fn})"
        ]
        for r in self.rules:
            lines.append(f"  - {r.describe()}")
        return "\n".join(lines)
