"""Content-aware triage: read the *evidence* behind a finding (who, which
direction, how round) and use it to make the response layer more cautious -- and
only ever more cautious.

Two assessors share one ``assess(...) -> TriageReport`` interface:

* :class:`TriageScorer` -- a transparent linear policy, pure stdlib, same shape
  as ``learn``; the deterministic baseline and offline fallback.
* :class:`TriageAgent` -- a ReAct agent (Claude reasons over the evidence via
  read-only tools), optional ``[agent]`` extra, falls back to the scorer when no
  SDK/key is present.

Either way the result feeds :func:`gated_decide`, which can only downgrade an
action, so an LLM in the loop can never escalate an autonomous response."""

from __future__ import annotations

from .agent import DEFAULT_MODEL, TriageAgent, make_assessor
from .features import FEATURE_NAMES, triage_features
from .integrate import cap_decision, gated_decide
from .report import Contribution, TriageReport
from .score import DEFAULT_WEIGHTS, TriageScorer

__all__ = [
    "TriageScorer",
    "TriageAgent",
    "make_assessor",
    "DEFAULT_MODEL",
    "TriageReport",
    "Contribution",
    "DEFAULT_WEIGHTS",
    "FEATURE_NAMES",
    "triage_features",
    "gated_decide",
    "cap_decision",
]
