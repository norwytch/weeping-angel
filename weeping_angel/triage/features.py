"""Evidence features for triage, computed only from data the framework already
produces: the :class:`~weeping_angel.detector.Finding`s, the displayed
timestamps, and the captured ``setinfo`` events. No new collection, no new deps.

Every feature is oriented so that a *positive* value argues the touch was
*benign* (a legitimate tool) and a negative one argues forgery. That keeps the
weights readable and the safety invariant simple: triage can only ever talk the
responder *down*.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from ..detector import Finding
from ..witnesses import MACE

EPSILON = 1e-9

# Feature order is fixed (like learn._features); weights line up positionally.
FEATURE_NAMES: tuple[str, ...] = (
    "bias",
    "actor_trusted",        # a known-legit tool performed the setinfo
    "no_groundtruth_clash",  # no R4: nothing contradicted out-of-band truth
    "corroboration",         # distinct rules firing (more = more like forgery)
    "whole_second_si",       # forged $SI is often suspiciously round
    "rollback",              # time was pushed backward (R2/R4)
)


def _whole_second(v: float | None) -> bool:
    return v is not None and abs(v - round(v)) <= EPSILON


def triage_features(
    findings: Sequence[Finding],
    display: MACE | None,
    setinfo_events: Iterable[dict],
    trusted_actors: set[str],
) -> list[float]:
    rules = {f.rule for f in findings}
    events = list(setinfo_events)

    actor_trusted = any((e.get("actor") in trusted_actors) for e in events)
    no_clash = "R4_setinfo_captured" not in rules
    corroboration = float(len(rules))
    whole_second = display is not None and (
        _whole_second(display.modified) or _whole_second(display.created)
    )
    rollback = bool(rules & {"R2_si_journal_rollback", "R4_setinfo_captured"})

    return [
        1.0,
        1.0 if actor_trusted else 0.0,
        1.0 if no_clash else 0.0,
        corroboration,
        1.0 if whole_second else 0.0,
        1.0 if rollback else 0.0,
    ]
