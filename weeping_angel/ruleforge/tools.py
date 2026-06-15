"""ReAct tool surface for the rule-engineering agent.

The agent's whole job is a closed feedback loop: propose a rule, score it against
the labeled corpus, read the precision/recall, revise. These tools are that loop.
``evaluate_rule`` is the reward signal; ``commit_rule`` and ``finish`` are the
control flow (handled in agent.py). Every rule the agent passes is validated by
:func:`weeping_angel.ruleforge.rule.parse_rule` before it is scored, so model
output is treated as data, never executed.
"""

from __future__ import annotations

import json

from .corpus import KINDS, Case, predict, score_ruleset
from .rule import FIELDS, OPS, CandidateRule, parse_rule

COMMIT = "commit_rule"
FINISH = "finish"

_LEAF_SCHEMA = {
    "type": "object",
    "properties": {
        "kind": {"type": "string", "enum": ["compare", "whole_second"]},
        "left": {"type": "string", "enum": list(FIELDS)},
        "op": {"type": "string", "enum": list(OPS)},
        "right": {"type": "string", "enum": list(FIELDS)},
        "tolerance": {"type": "number"},
        "field": {"type": "string", "enum": list(FIELDS)},
    },
    "required": ["kind"],
    "additionalProperties": False,
}

_RULE_SCHEMA = {
    "type": "object",
    "properties": {
        "kind": {"type": "string", "enum": ["compare", "whole_second", "all_of"]},
        "name": {"type": "string", "description": "Short human label for the rule."},
        "left": {"type": "string", "enum": list(FIELDS), "description": "compare: left field"},
        "op": {"type": "string", "enum": list(OPS), "description": "compare: operator"},
        "right": {"type": "string", "enum": list(FIELDS), "description": "compare: right field"},
        "tolerance": {"type": "number", "description": "compare: seconds of margin (default 1)"},
        "field": {"type": "string", "enum": list(FIELDS), "description": "whole_second: field"},
        "clauses": {
            "type": "array",
            "items": _LEAF_SCHEMA,
            "minItems": 2,
            "maxItems": 4,
            "description": "all_of: 2-4 compare/whole_second sub-rules, all must fire",
        },
    },
    "required": ["kind"],
    "additionalProperties": False,
}

TOOL_SCHEMAS: list[dict] = [
    {
        "name": "list_fields",
        "description": "List the evidence fields and operators a rule may use, plus the grammar.",
        "input_schema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "inspect_corpus",
        "description": (
            "Summarize the labeled corpus and the committed rule set so far: class "
            "counts, current precision/recall, and how many malicious cases of each "
            "kind are still uncaught (the gap to close)."
        ),
        "input_schema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "evaluate_rule",
        "description": (
            "Score a candidate rule WITHOUT committing it. Returns the rule's "
            "standalone precision/recall, the rule set's precision/recall if it were "
            "added, and the marginal effect (new true positives, new false positives, "
            "and which malicious kinds it newly catches). This is how you probe."
        ),
        "input_schema": _RULE_SCHEMA,
    },
    {
        "name": COMMIT,
        "description": (
            "Add a candidate rule to the rule set (do this once evaluate_rule shows it "
            "adds true positives without false positives). Returns the updated rule-set score."
        ),
        "input_schema": _RULE_SCHEMA,
    },
    {
        "name": FINISH,
        "description": "Stop: the committed rule set meets the bar (or you can do no better).",
        "input_schema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
]


def describe_fields() -> str:
    return json.dumps(
        {
            "fields": list(FIELDS),
            "operators": list(OPS),
            "rule_shapes": {
                "compare": {"kind": "compare", "left": "<field>", "op": "<op>", "right": "<field>",
                            "tolerance": "<seconds, default 1>"},
                "whole_second": {"kind": "whole_second", "field": "<field>"},
                "all_of": {"kind": "all_of", "clauses": ["<compare or whole_second>", "..."],
                           "note": "fires only when ALL clauses fire; use it when no single "
                                   "comparison separates a forgery from benign cleanly"},
            },
            "examples": [
                {"kind": "compare", "left": "si_created", "op": "<", "right": "fn_created"},
                {"kind": "whole_second", "field": "si_modified"},
                {"kind": "all_of", "clauses": [
                    {"kind": "compare", "left": "si_created", "op": "<", "right": "fn_created"},
                    {"kind": "compare", "left": "si_modified", "op": ">",
                     "right": "journal_last"}]},
            ],
        }
    )


def _per_kind(rules: list[CandidateRule], corpus: list[Case]) -> dict[str, dict[str, int]]:
    out = {k: {"flagged": 0, "total": 0} for k in KINDS}
    for features, kind, _label in corpus:
        out[kind]["total"] += 1
        if predict(rules, features):
            out[kind]["flagged"] += 1
    return out


def summarize_corpus(corpus: list[Case], ruleset: list[CandidateRule]) -> str:
    eff = score_ruleset(ruleset, corpus)
    pk = _per_kind(ruleset, corpus)
    return json.dumps(
        {
            "total_cases": len(corpus),
            "committed_rules": [r.describe() for r in ruleset],
            "current": {"precision": round(eff.precision, 3), "recall": round(eff.recall, 3),
                        "tp": eff.tp, "fp": eff.fp, "fn": eff.fn},
            "per_kind_caught": {k: f"{v['flagged']}/{v['total']}" for k, v in pk.items()},
        }
    )


def eval_candidate(spec: dict, corpus: list[Case], ruleset: list[CandidateRule]) -> str:
    """Validate + score a candidate. Returns a JSON observation (or a JSON error
    the agent can learn from). Never raises."""
    try:
        rule = parse_rule(spec)
    except ValueError as exc:
        return json.dumps({"error": str(exc)})

    standalone = score_ruleset([rule], corpus)
    combined = score_ruleset([*ruleset, rule], corpus)
    new_tp_kinds: dict[str, int] = {}
    new_fp = 0
    for features, kind, label in corpus:
        before = predict(ruleset, features)
        after = predict([*ruleset, rule], features)
        if not before and after:
            if label == "malicious":
                new_tp_kinds[kind] = new_tp_kinds.get(kind, 0) + 1
            else:
                new_fp += 1
    return json.dumps(
        {
            "rule": rule.describe(),
            "standalone": {"precision": round(standalone.precision, 3),
                           "recall": round(standalone.recall, 3)},
            "if_added": {"precision": round(combined.precision, 3),
                         "recall": round(combined.recall, 3), "fp": combined.fp},
            "marginal_new_true_positives": sum(new_tp_kinds.values()),
            "newly_caught_kinds": new_tp_kinds,
            "marginal_new_false_positives": new_fp,
        }
    )
