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
* ``all_of``: a conjunction of two to four of the above. This is the expressive
  step a greedy single-clause search can't reach: some forgeries are caught only
  by a *combination* of conditions, where each condition alone would also fire on
  some benign file (a false positive).
"""

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field as dc_field

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
_MAX_CLAUSES = 4


@dataclass(frozen=True)
class CandidateRule:
    kind: str                       # "compare" | "whole_second" | "all_of"
    name: str = ""
    left: str = ""                  # compare: left field
    op: str = "<"                   # compare: operator
    right: str = ""                 # compare: right field
    tolerance: float = DEFAULT_TOLERANCE
    field: str = ""                 # whole_second: the field to test
    clauses: tuple[CandidateRule, ...] = dc_field(default_factory=tuple)  # all_of: sub-rules

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
        if self.kind == "all_of":
            return all(c.fires(features) for c in self.clauses)
        raise ValueError(f"bad rule kind {self.kind!r}")

    def key(self) -> tuple:
        """Identity for dedup (ignores the cosmetic name)."""
        if self.kind == "compare":
            return ("compare", self.left, self.op, self.right, round(self.tolerance, 3))
        if self.kind == "whole_second":
            return ("whole_second", self.field)
        return ("all_of", tuple(sorted(c.key() for c in self.clauses)))

    def describe(self) -> str:
        if self.kind == "compare":
            tol = "" if self.tolerance == DEFAULT_TOLERANCE else f" (tol {self.tolerance:g}s)"
            return f"{self.left} {self.op} {self.right}{tol}"
        if self.kind == "whole_second":
            return f"{self.field} is whole-second"
        return "(" + " AND ".join(c.describe() for c in self.clauses) + ")"

    def as_dict(self) -> dict:
        d: dict = {"kind": self.kind, "name": self.name or self.describe()}
        if self.kind == "compare":
            d.update(left=self.left, op=self.op, right=self.right, tolerance=self.tolerance)
        elif self.kind == "whole_second":
            d.update(field=self.field)
        else:
            d.update(clauses=[c.as_dict() for c in self.clauses])
        return d


def _parse_simple(spec: dict) -> CandidateRule:
    """Parse a compare/whole_second leaf. Rejects conjunctions (no nesting)."""
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
        f = spec.get("field")
        if f not in FIELDS:
            raise ValueError(f"field must be one of {FIELDS}")
        return CandidateRule(kind="whole_second", name=name, field=f)

    raise ValueError("kind must be 'compare' or 'whole_second'")


def parse_rule(spec: dict) -> CandidateRule:
    """Validate a rule spec (e.g. from a model tool call) into a CandidateRule.

    Raises ``ValueError`` on anything outside the allowlisted grammar -- this is
    the boundary that keeps untrusted model output from becoming executable.
    """
    if not isinstance(spec, dict):
        raise ValueError("rule must be an object")
    if spec.get("kind") == "all_of":
        raw = spec.get("clauses")
        if not isinstance(raw, list) or not (2 <= len(raw) <= _MAX_CLAUSES):
            raise ValueError(f"all_of needs 2-{_MAX_CLAUSES} clauses")
        clauses = tuple(_parse_simple(c) for c in raw)  # leaves only -- no nested all_of
        return CandidateRule(kind="all_of", name=str(spec.get("name", ""))[:80], clauses=clauses)
    return _parse_simple(spec)
