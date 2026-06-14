"""A linear triage scorer -- the same shape as ``learn.LearnedBlue``: a few
features, one dot product, baked-in weights that work untrained, optionally
tuned by the very same Evolution Strategies loop in ``weeping_angel.learn``.

It deliberately is *not* a language model. The gap in the framework was that
``response.confidence`` counts corroborating rules but cannot read the *content*
of the evidence (who set the time, which direction, how round). A handful of
content features and a transparent linear score close that gap with zero new
dependencies and a fully auditable trace.
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Sequence

from ..detector import Finding
from ..witnesses import MACE
from .features import FEATURE_NAMES, triage_features
from .report import Contribution, TriageReport

# Hand-set, like response._SEVERITY_BASE. Positive = argues benign.
#   bias  actor_trusted  no_clash  corroboration  whole_second  rollback
DEFAULT_WEIGHTS: list[float] = [0.0, 2.5, 1.0, -1.1, -1.3, -1.5]

_HOLD_THRESHOLD = 0.60   # benign_likelihood at/above which we ask the responder to back off
_BENIGN_AT = 0.60
_SUSPICIOUS_AT = 0.35


def _sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))


def _disposition(p: float) -> str:
    if p >= _BENIGN_AT:
        return "likely_benign"
    if p <= _SUSPICIOUS_AT:
        return "suspicious"
    return "inconclusive"


class TriageScorer:
    """Linear policy over :func:`triage_features`. Default weights work out of
    the box; pass trained weights (e.g. from an ES run) to override."""

    def __init__(self, weights: Sequence[float] | None = None) -> None:
        self.weights = list(weights if weights is not None else DEFAULT_WEIGHTS)
        if len(self.weights) != len(FEATURE_NAMES):
            raise ValueError(
                f"expected {len(FEATURE_NAMES)} weights, got {len(self.weights)}"
            )

    def assess(
        self,
        file_id: str,
        findings: Sequence[Finding],
        display: MACE | None,
        setinfo_events: Iterable[dict],
        trusted_actors: set[str] | None = None,
    ) -> TriageReport:
        feats = triage_features(findings, display, setinfo_events, trusted_actors or set())
        contributions = tuple(
            Contribution(name, value, w)
            for name, value, w in zip(FEATURE_NAMES, feats, self.weights, strict=True)
        )
        score = sum(c.product for c in contributions)
        p = _sigmoid(score)
        return TriageReport(
            file_id=file_id,
            benign_likelihood=p,
            disposition=_disposition(p),
            recommend_hold=p >= _HOLD_THRESHOLD,
            contributions=contributions,
        )
