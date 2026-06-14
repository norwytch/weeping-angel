"""Glue: let triage cap a response, and *only* cap it.

This enforces the one invariant that makes the layer safe to ship: triage can
move an action *down* (toward caution) but never *up*. It reuses the exact
downgrade shape ``ResponsePolicy`` already applies to protected files, so the
behaviour is one the codebase already trusts.

The safe path is ``gated_decide`` -> ``ResponsePolicy.decide(triage=...)``: the
cap is applied *inside* ``decide``, before it computes ``executed`` and before
any executor runs. Capping only the returned object (the old wrapper) was unsafe
with ``dry_run`` off -- ``decide`` had already executed the un-capped action by
the time the wrapper relabelled it. ``cap_decision`` below remains for the
analysis case (cap a decision you already hold, e.g. in a dry-run study).
"""

from __future__ import annotations

from collections.abc import Iterable

from ..detector import Finding
from ..response import Action, ResponseDecision, ResponsePolicy
from .report import TriageReport


def cap_decision(decision: ResponseDecision, report: TriageReport) -> ResponseDecision:
    """Post-hoc cap of a decision you already hold: if triage recommends holding,
    downgrade anything above ALERT to ALERT. Never raises the action; returns the
    input unchanged otherwise.

    This does not execute anything, so it is safe to use on a decision for
    analysis. To gate a *live* responder, use :func:`gated_decide`, which caps
    before execution rather than after.
    """
    if not report.recommend_hold or decision.action <= Action.ALERT:
        return decision
    return ResponseDecision(
        file_id=decision.file_id,
        action=Action.ALERT,
        confidence=decision.confidence,
        dry_run=decision.dry_run,
        executed=False,  # held: do not execute a downgraded-by-triage action
        rules=decision.rules,
        reason=(
            f"{decision.reason}; triage held ({report.disposition}, "
            f"benign_likelihood={report.benign_likelihood:.2f})"
        ),
    )


def gated_decide(
    policy: ResponsePolicy,
    file_id: str,
    findings: Iterable[Finding],
    report: TriageReport,
) -> ResponseDecision:
    """Decide under the policy with triage in the loop.

    The report is handed to :meth:`ResponsePolicy.decide`, which applies the cap
    *before* it computes ``executed`` and before any executor runs. That ordering
    is load-bearing: a held action is never executed, not merely relabelled after
    the fact. The triage rationale is appended to the same ledger inside
    ``decide`` (rationale first, then the capped decision).
    """
    return policy.decide(file_id, list(findings), triage=report)
