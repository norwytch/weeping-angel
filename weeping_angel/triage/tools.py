"""ReAct tool surface for the triage agent.

These are *inspection* tools over evidence the framework already produced: no new
collection, no side effects, all read-only. The agent reasons, calls a tool to
look at one facet of the evidence, reads the observation, and repeats, until it
calls ``conclude_triage`` with a calibrated benign-likelihood.

Because every tool is read-only and the only thing the conclusion can drive is a
*downgrade* (see :func:`weeping_angel.response.ResponsePolicy.decide`), the agent
cannot escalate anything. The worst an over-confident agent can do is hold back an
auto-response a human still sees in the alert.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence

from ..detector import Finding
from ..witnesses import MACE
from .features import _whole_second

# The terminal tool: when the agent calls this, the ReAct loop stops and reads
# its input as the assessment.
CONCLUDE = "conclude_triage"

TOOL_SCHEMAS: list[dict] = [
    {
        "name": "list_findings",
        "description": (
            "List the detection rules that fired on this file, each with its "
            "severity and explanation. Call this first to see exactly what the "
            "detector flagged and how strongly the rules corroborate."
        ),
        "input_schema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "inspect_timestamps",
        "description": (
            "Inspect the file's displayed $SI created/modified timestamps and "
            "whether each is suspiciously whole-second (forged times are often "
            "round to the second; genuine ones usually carry sub-second precision)."
        ),
        "input_schema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "inspect_setinfo",
        "description": (
            "Inspect the captured setinfo events: who wrote the timestamp "
            "(actor), the value written, and the real wall-clock time of the "
            "write. Use it to see who touched the time and which direction it "
            "moved (a backdated time is a classic stomp tell)."
        ),
        "input_schema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "check_trusted_actors",
        "description": (
            "Check the configured allowlist of trusted timestamp-setting tools "
            "(e.g. backup/restore software) and whether any actor that touched "
            "this file is on it. A trusted actor argues strongly for a benign "
            "touch; an unknown one does not."
        ),
        "input_schema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": CONCLUDE,
        "description": (
            "Conclude triage. Provide benign_likelihood: your calibrated "
            "probability from 0.0 to 1.0 that this timestamp touch was BENIGN (a "
            "legitimate tool), grounded in the evidence you inspected, plus a one "
            "or two sentence rationale. The system maps the probability to a "
            "hold/no-hold decision. Remember: triage can only make the responder "
            "MORE cautious, so a high benign_likelihood asks it to hold off, and "
            "the worst case of a wrong hold is a missed auto-response a human "
            "still reviews."
        ),
        "strict": True,
        "input_schema": {
            "type": "object",
            "properties": {
                "benign_likelihood": {
                    "type": "number",
                    "description": "Probability 0.0-1.0 that the touch was benign.",
                },
                "rationale": {
                    "type": "string",
                    "description": "One or two sentences citing the evidence.",
                },
            },
            "required": ["benign_likelihood", "rationale"],
            "additionalProperties": False,
        },
    },
]


def evidence_summary(file_id: str, findings: Sequence[Finding]) -> str:
    """The opening user message: the bare facts, then a nudge to investigate."""
    rules = sorted({f.rule for f in findings})
    return (
        f"A timestamp anomaly was flagged on file {file_id!r}. "
        f"{len(findings)} finding(s) across {len(rules)} rule(s): {', '.join(rules) or 'none'}.\n\n"
        "Investigate the evidence with the tools, then call conclude_triage with "
        "your benign_likelihood. Decide whether this looks like a legitimate tool "
        "touching the timestamp or a forgery (timestomp)."
    )


def run_tool(
    name: str,
    tool_input: dict,
    *,
    findings: Sequence[Finding],
    display: MACE | None,
    setinfo_events: Iterable[dict],
    trusted_actors: set[str],
) -> str:
    """Execute one read-only inspection tool and return a JSON observation."""
    if name == "list_findings":
        return json.dumps(
            [
                {"rule": f.rule, "severity": f.severity, "explanation": f.explanation}
                for f in findings
            ]
        )

    if name == "inspect_timestamps":
        if display is None:
            return json.dumps({"displayed": None, "note": "no displayed timestamps captured"})
        return json.dumps(
            {
                "modified": display.modified,
                "created": display.created,
                "modified_whole_second": _whole_second(display.modified),
                "created_whole_second": _whole_second(display.created),
            }
        )

    if name == "inspect_setinfo":
        events = [
            {
                "actor": e.get("actor"),
                "written_modified": e.get("written_modified"),
                "real_time": e.get("real_time"),
            }
            for e in setinfo_events
        ]
        return json.dumps({"setinfo_events": events})

    if name == "check_trusted_actors":
        actors = sorted({str(e.get("actor")) for e in setinfo_events if e.get("actor") is not None})
        return json.dumps(
            {
                "trusted_actors": sorted(trusted_actors),
                "actors_on_file": actors,
                "any_trusted": any(a in trusted_actors for a in actors),
            }
        )

    return json.dumps({"error": f"unknown tool {name!r}"})
