"""Response layer: from detection to action, under rules of engagement.

The detector emits :class:`~weeping_angel.detector.Finding`s and stops. This turns
findings into decisions: alert, ticket, quarantine, or isolate, gated by a
confidence threshold and an explicit rules-of-engagement config. Three things
make autonomous action deployable rather than reckless, and all three are here:

* **Dry-run by default.** A policy decides and records but does not execute
  unless ``dry_run`` is turned off, so the safe state is the default state.
* **A confidence gate.** Each action requires a minimum confidence, and
  confidence rises with corroboration -- more independent rules firing on the
  same file means a higher score. Destructive actions need more agreement.
* **A tamper-evident audit trail.** Every decision is appended to the same
  hash-chained :class:`~weeping_angel.ledger.Ledger` the detector reads, so the
  autonomous action is itself recorded, replayable, and impossible to rewrite
  without breaking the chain.

The rules of engagement also bound what may happen at all: which actions are
permitted in this engagement, and which files must never be touched.
"""

from __future__ import annotations

import itertools
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from enum import IntEnum

from .detector import Finding
from .ledger import Ledger

# Confidence a single finding contributes, by severity. Corroboration (multiple
# distinct rules on one file) raises it from there.
_SEVERITY_BASE = {"high": 0.6, "medium": 0.35, "low": 0.2}
_CORROBORATION_STEP = 0.15
_MAX_CONFIDENCE = 0.99


class Action(IntEnum):
    """Escalation ordering matters: higher value = more disruptive."""

    NONE = 0
    ALERT = 1
    TICKET = 2
    QUARANTINE = 3
    ISOLATE = 4


# Actions that touch the host and must be held to a higher bar / a protected list.
DESTRUCTIVE = frozenset({Action.QUARANTINE, Action.ISOLATE})

_DEFAULT_THRESHOLDS = {
    Action.ALERT: 0.30,
    Action.TICKET: 0.50,
    Action.QUARANTINE: 0.80,
    Action.ISOLATE: 0.95,
}


def confidence(findings: Iterable[Finding]) -> float:
    """Aggregate confidence for one file. Starts at the strongest single
    finding's severity and rises with each additional distinct rule that agrees,
    with diminishing returns. The multi-witness premise of the framework made
    concrete: corroboration is confidence."""
    findings = list(findings)
    if not findings:
        return 0.0
    base = max(_SEVERITY_BASE.get(f.severity, _SEVERITY_BASE["low"]) for f in findings)
    corroboration = len({f.rule for f in findings}) - 1
    return min(_MAX_CONFIDENCE, base + _CORROBORATION_STEP * corroboration)


@dataclass
class RulesOfEngagement:
    """What the responder is allowed to do, and how sure it must be."""

    dry_run: bool = True
    allowed_actions: frozenset[Action] = frozenset(
        {Action.ALERT, Action.TICKET, Action.QUARANTINE, Action.ISOLATE}
    )
    thresholds: dict[Action, float] = field(default_factory=lambda: dict(_DEFAULT_THRESHOLDS))
    # Files that must never be quarantined/isolated (e.g. critical system files);
    # a destructive decision on one is downgraded to an alert.
    protected_files: frozenset[str] = frozenset()


@dataclass
class ResponseDecision:
    file_id: str
    action: Action
    confidence: float
    dry_run: bool
    executed: bool
    rules: tuple[str, ...]
    reason: str

    def to_event(self) -> dict:
        return {
            "file_id": self.file_id,
            "op": "response",
            "action": self.action.name,
            "confidence": round(self.confidence, 3),
            "dry_run": self.dry_run,
            "executed": self.executed,
            "rules": list(self.rules),
        }


Executor = Callable[[ResponseDecision], None]


class ResponsePolicy:
    """Maps findings to a single bounded action per file under an RoE config,
    and records every decision to the tamper-evident ledger."""

    def __init__(
        self,
        roe: RulesOfEngagement | None = None,
        ledger: Ledger | None = None,
        executors: dict[Action, Executor] | None = None,
        now: Callable[[], float] | None = None,
    ) -> None:
        self.roe = roe or RulesOfEngagement()
        self.ledger = ledger
        self.executors = executors or {}
        # Monotonic logical clock for audit timestamps when none is supplied.
        self._counter = itertools.count()
        self._now = now or (lambda: float(next(self._counter)))

    def _choose(self, conf: float) -> Action:
        eligible = [
            a
            for a in self.roe.allowed_actions
            if a != Action.NONE and conf >= self.roe.thresholds.get(a, 1.0)
        ]
        return max(eligible, default=Action.NONE)

    def decide(self, file_id: str, findings: Iterable[Finding]) -> ResponseDecision:
        findings = list(findings)
        conf = confidence(findings)
        action = self._choose(conf)
        reason = f"confidence {conf:.2f} from {len({f.rule for f in findings})} rule(s)"

        if action in DESTRUCTIVE and file_id in self.roe.protected_files:
            downgraded = Action.ALERT if Action.ALERT in self.roe.allowed_actions else Action.NONE
            reason += f"; {action.name} blocked on protected file, downgraded to {downgraded.name}"
            action = downgraded

        executed = (not self.roe.dry_run) and action != Action.NONE
        decision = ResponseDecision(
            file_id=file_id,
            action=action,
            confidence=conf,
            dry_run=self.roe.dry_run,
            executed=executed,
            rules=tuple(sorted({f.rule for f in findings})),
            reason=reason,
        )

        # Record the decision before acting, so an action can never have
        # side effects without a durable ledger entry first.
        if self.ledger is not None and action != Action.NONE:
            self.ledger.append(decision.to_event(), recorded_at=self._now())

        # Execute last, handing the executor the real decision (with the rules
        # that justified it). If it fails, the decision is already recorded;
        # log the failure too, then re-raise so the caller learns of it.
        if executed and action in self.executors:
            try:
                self.executors[action](decision)
            except Exception as exc:
                if self.ledger is not None:
                    self.ledger.append(
                        {
                            "file_id": file_id,
                            "op": "response_failed",
                            "action": action.name,
                            "error": type(exc).__name__,
                        },
                        recorded_at=self._now(),
                    )
                raise

        return decision

    def respond(self, findings_by_file: dict[str, list[Finding]]) -> list[ResponseDecision]:
        return [self.decide(fid, fs) for fid, fs in findings_by_file.items()]
