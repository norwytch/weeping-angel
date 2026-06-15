"""A deterministic greedy rule miner: the non-LLM baseline and fallback.

It enumerates every rule in the grammar, then greedily adds whichever candidate
catches the most still-missed malicious cases without introducing false
positives, until the acceptance bar is met or nothing improves recall. This is to
the rule-engineering agent what the linear scorer is to the triage agent: a
deterministic floor that needs no API key, and the thing the agent has to beat to
justify itself.
"""

from __future__ import annotations

from itertools import permutations

from .corpus import Bar, Case, RuleSetResult, score_ruleset
from .rule import FIELDS, CandidateRule


def candidate_rules() -> list[CandidateRule]:
    """Every rule the grammar allows: each ordered field pair under ``<`` and
    ``>``, plus a whole-second check on each field."""
    rules: list[CandidateRule] = []
    for left, right in permutations(FIELDS, 2):
        for op in ("<", ">"):
            rules.append(CandidateRule(kind="compare", left=left, op=op, right=right))
    for field in FIELDS:
        rules.append(CandidateRule(kind="whole_second", field=field))
    return rules


class RuleMiner:
    def __init__(self, bar: Bar | None = None, max_rules: int = 5) -> None:
        self.bar = bar or Bar()
        self.max_rules = max_rules

    def mine(self, corpus: list[Case]) -> RuleSetResult:
        chosen: list[CandidateRule] = []
        log: list[str] = []
        pool = candidate_rules()
        score = score_ruleset(chosen, corpus)

        for _ in range(self.max_rules):
            if self.bar.met(score):
                break
            best, best_score = None, score
            for cand in pool:
                if cand.key() in {c.key() for c in chosen}:
                    continue
                trial = score_ruleset([*chosen, cand], corpus)
                # Prefer more true positives, but never at the cost of precision:
                # a candidate that adds a false positive is rejected outright.
                if trial.fp > best_score.fp:
                    continue
                if trial.tp > best_score.tp or (
                    trial.tp == best_score.tp and trial.fp < best_score.fp
                ):
                    best, best_score = cand, trial
            if best is None:
                break  # nothing improves recall without hurting precision
            chosen.append(best)
            score = best_score
            log.append(f"added [{best.describe()}] -> recall={score.recall:.3f} fp={score.fp}")

        return RuleSetResult(
            rules=tuple(chosen),
            score=score,
            source="miner",
            iterations=len(chosen),
            log=tuple(log),
        )
