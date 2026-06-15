"""ruleforge: an agent that *writes detection rules*, scored by the efficacy harness.

Where the triage agent judges one file, this improves the detector itself. It runs
a closed loop with a real reward signal -- propose a structured rule, score it
against the labeled corpus with precision/recall, revise -- until an acceptance
bar is met. Two engineers share one interface (`engineer(corpus) -> RuleSetResult`):

* :class:`RuleMiner` -- a deterministic greedy search, the non-LLM baseline and
  offline fallback.
* :class:`RuleEngineerAgent` -- the ReAct agent (Claude proposes rules, the harness
  scores them), optional ``[agent]`` extra, falls back to the miner with no key.

Rules are structured data validated against an allowlist, never executed code, and
the output is a *proposal*: promoting a discovered rule into the detector is a
human review step."""

from __future__ import annotations

from .agent import DEFAULT_MODEL, RuleEngineerAgent, make_rule_engineer
from .corpus import Bar, RuleSetResult, build_corpus, score_ruleset
from .miner import RuleMiner, candidate_rules
from .rule import FIELDS, OPS, CandidateRule, parse_rule

__all__ = [
    "RuleEngineerAgent",
    "RuleMiner",
    "make_rule_engineer",
    "DEFAULT_MODEL",
    "Bar",
    "RuleSetResult",
    "build_corpus",
    "score_ruleset",
    "candidate_rules",
    "CandidateRule",
    "parse_rule",
    "FIELDS",
    "OPS",
]
