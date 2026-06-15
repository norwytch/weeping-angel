"""A safe, structured representation for a candidate detection rule.

A rule the agent proposes is *data*, not code: a small JSON object validated
against an allowlist of fields and operators, then evaluated by a deterministic
interpreter. The model never produces executable Python, so an agent-authored
rule can be scored and audited without ever running model output as code.

A rule is one of:

* ``compare``: a binary relation between two named timestamp quantities, with a
  tolerance margin to absorb float and second-resolution noise. For example
  ``si_created < fn_created`` flags a file whose displayed birth predates the
  kernel-set birth (a backdated `$SI`).
* ``whole_second``: a unary check that a quantity is suspiciously round (forged
  times are often whole seconds; genuine ones carry sub-second precision).
"""

from __future__ import annotations

from dataclasses import dataclass

# The only quantities a rule may reference -- the per-file evidence the corpus
# exposes. Anything outside this set is rejected at parse time.
FIELDS: tuple[str, ...] = (
    "si_created",     # displayed $SI birth time
    "si_modified",    # displayed $SI modified time
    "fn_created",     # kernel-set $FN birth time (hard for userland to forge)
    "journal_first",  # first change the recorder saw (true create)
    "journal_last",   # last change the recorder saw (true last write)
    "now",            # observation time
)

OPS: tuple[str, ...] = ("<", "<=", ">", ">=")

DEFAULT_TOLERANCE = 1.0   # seconds of margin on a comparison
_WHOLE_EPS = 1e-3         # how close to an integer counts as "whole second"


@dataclass(frozen=True)
class CandidateRule:
    kind: str                       # "compare" | "whole_second"
    name: str = ""
    left: str = ""                  # compare: left field
    op: str = "<"                   # compare: operator
    right: str = ""                 # compare: right field
    tolerance: float = DEFAULT_TOLERANCE
    field: str = ""                 # whole_second: the field to test

    def fires(self, features: dict[str, float]) -> bool:
        """True if this rule flags the given per-file evidence as suspicious."""
        if self.kind == "compare":
            a, b, tol = features[self.left], features[self.right], self.tolerance
            if self.op == "<":
                return a < b - tol
            if self.op == "<=":
                return a <= b - tol
            if self.op == ">":
                return a > b + tol
            if self.op == ">=":
                return a >= b + tol
            raise ValueError(f"bad op {self.op!r}")
        if self.kind == "whole_second":
            v = features[self.field]
            return abs(v - round(v)) <= _WHOLE_EPS
        raise ValueError(f"bad rule kind {self.kind!r}")

    def key(self) -> tuple:
        """Identity for dedup (ignores the cosmetic name)."""
        if self.kind == "compare":
            return ("compare", self.left, self.op, self.right, round(self.tolerance, 3))
        return ("whole_second", self.field)

    def describe(self) -> str:
        if self.kind == "compare":
            tol = "" if self.tolerance == DEFAULT_TOLERANCE else f" (tol {self.tolerance:g}s)"
            return f"{self.left} {self.op} {self.right}{tol}"
        return f"{self.field} is whole-second"

    def as_dict(self) -> dict:
        d: dict = {"kind": self.kind, "name": self.name or self.describe()}
        if self.kind == "compare":
            d.update(left=self.left, op=self.op, right=self.right, tolerance=self.tolerance)
        else:
            d.update(field=self.field)
        return d


def parse_rule(spec: dict) -> CandidateRule:
    """Validate a rule spec (e.g. from a model tool call) into a CandidateRule.

    Raises ``ValueError`` on anything outside the allowlisted grammar -- this is
    the boundary that keeps untrusted model output from becoming executable.
    """
    if not isinstance(spec, dict):
        raise ValueError("rule must be an object")
    kind = spec.get("kind")
    name = str(spec.get("name", ""))[:80]

    if kind == "compare":
        left, op, right = spec.get("left"), spec.get("op"), spec.get("right")
        if left not in FIELDS or right not in FIELDS:
            raise ValueError(f"left/right must be one of {FIELDS}")
        if op not in OPS:
            raise ValueError(f"op must be one of {OPS}")
        try:
            tol = float(spec.get("tolerance", DEFAULT_TOLERANCE))
        except (TypeError, ValueError) as exc:
            raise ValueError("tolerance must be a number") from exc
        if tol < 0:
            raise ValueError("tolerance must be >= 0")
        return CandidateRule(
            kind="compare", name=name, left=left, op=op, right=right, tolerance=tol
        )

    if kind == "whole_second":
        field = spec.get("field")
        if field not in FIELDS:
            raise ValueError(f"field must be one of {FIELDS}")
        return CandidateRule(kind="whole_second", name=name, field=field)

    raise ValueError("kind must be 'compare' or 'whole_second'")
