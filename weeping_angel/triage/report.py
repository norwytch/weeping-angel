"""The triage layer's output: a disposition, a cautious recommendation, and a
fully transparent per-feature trace.

Mirrors :class:`~weeping_angel.response.ResponseDecision`'s ``to_event`` so the
rationale lands in the same tamper-evident ledger. The ``contributions`` list is
the "reasoning trace" -- but unlike a free-text model trace, every line is a
named feature, its value, its weight, and the product, so the disposition is
exactly reconstructable.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Contribution:
    feature: str
    value: float
    weight: float

    @property
    def product(self) -> float:
        return self.value * self.weight


@dataclass(frozen=True)
class TriageReport:
    file_id: str
    benign_likelihood: float          # 0..1; high = looks like a legitimate touch
    disposition: str                  # "likely_benign" | "suspicious" | "inconclusive"
    recommend_hold: bool              # True = ask the responder to back off
    contributions: tuple[Contribution, ...]
    # Free-text reasoning. Empty for the linear scorer (the contributions *are*
    # its trace); populated by the ReAct agent with its evidence-grounded
    # rationale. Either way the disposition stays reconstructable.
    rationale: str = ""

    def to_event(self) -> dict:
        event: dict = {
            "file_id": self.file_id,
            "op": "triage",
            "disposition": self.disposition,
            "benign_likelihood": round(self.benign_likelihood, 3),
            "recommend_hold": self.recommend_hold,
            "trace": [
                {"f": c.feature, "v": round(c.value, 3), "w": round(c.weight, 3),
                 "wx": round(c.product, 3)}
                for c in self.contributions
            ],
        }
        if self.rationale:
            event["rationale"] = self.rationale
        return event

    def explain(self) -> str:
        """Human-readable trace, ordered by absolute impact."""
        ordered = sorted(self.contributions, key=lambda c: abs(c.product), reverse=True)
        lines = [f"{self.disposition} (benign_likelihood={self.benign_likelihood:.2f})"]
        for c in ordered:
            if c.feature == "bias":
                continue
            sign = "benign" if c.product > 0 else "suspicious"
            lines.append(f"  {c.feature}={c.value:+.2f}  ->  {c.product:+.2f} ({sign})")
        if self.rationale:
            lines.append(f"  rationale: {self.rationale}")
        return "\n".join(lines)
