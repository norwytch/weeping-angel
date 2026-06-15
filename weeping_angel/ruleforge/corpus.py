"""A labeled corpus of per-file evidence, and the precision/recall scoring a
rule set is measured against.

The corpus mirrors the classes in :mod:`weeping_angel.efficacy` -- clean files,
benign timestamp-setting (archivers / restore / ``cp -p``), and three timestomp
variants -- but expresses each case as a flat feature dict (the quantities a
:class:`~weeping_angel.ruleforge.rule.CandidateRule` may reference) rather than a
full detector. A rule set is scored with the same confusion-matrix metrics the
efficacy harness reports, so "did the agent's rules help" is measured the same
way the hand-written rules are.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from ..efficacy import BENIGN, MALICIOUS, Efficacy
from .rule import CandidateRule

# One labeled case: the per-file feature dict plus its kind and ground-truth label.
Case = tuple[dict[str, float], str, str]  # (features, kind, label)

KINDS = ("clean", "benign_setinfo", "stomp_backdate", "stomp_subsecond", "stomp_future")


def _features(rng: random.Random, kind: str) -> tuple[dict[str, float], str]:
    """Build one case's features, mirroring efficacy._make_case but as a dict."""
    birth = rng.uniform(1.6e9, 1.7e9) + rng.uniform(0.05, 0.95)
    write = birth + rng.uniform(10, 1e6) + rng.uniform(0.05, 0.95)
    now = write + rng.uniform(10, 1e6)
    base = {"fn_created": birth, "journal_first": birth, "journal_last": write, "now": now}

    if kind == "clean":
        return {**base, "si_created": birth, "si_modified": write}, BENIGN
    if kind == "benign_setinfo":
        # restore/copy sets a plausible time: >= true last write, <= now, birth kept
        plausible = rng.uniform(write, now)
        return {**base, "si_created": birth, "si_modified": plausible}, BENIGN
    if kind == "stomp_backdate":
        forged_c = birth - rng.uniform(1e6, 1e8)
        forged_m = forged_c + rng.uniform(1, 1e5)
        return {**base, "si_created": forged_c, "si_modified": forged_m}, MALICIOUS
    if kind == "stomp_subsecond":
        si = {"si_created": float(int(birth)), "si_modified": float(int(write))}
        return {**base, **si}, MALICIOUS
    if kind == "stomp_future":
        return {**base, "si_created": birth, "si_modified": now + rng.uniform(1e3, 1e7)}, MALICIOUS
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
