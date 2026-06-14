"""ReAct triage agent demo.

With ANTHROPIC_API_KEY set (and `pip install weeping_angel[agent]`), this runs a
real Claude ReAct loop over the evidence. Without a key, it drives the same loop
with a scripted fake client so the reasoning/acting/observing flow is visible
offline -- and shows that an agent-driven hold can only ever downgrade the live
responder.

    python examples/triage_agent_demo.py
"""

from __future__ import annotations

import os
import types

from weeping_angel.detector import Finding
from weeping_angel.response import Action, ResponsePolicy, RulesOfEngagement
from weeping_angel.triage import TriageAgent, gated_decide
from weeping_angel.witnesses import MACE


def banner(t: str) -> None:
    print("\n" + t + "\n" + "-" * len(t))


# A trusted-restore scenario: several rules fire (raw confidence is high enough
# for ISOLATE), but a backup tool did it with sub-second times -- exactly the
# case where triage should override a destructive auto-response and hold.
FINDINGS = [
    Finding("fileA", "R1_si_fn_birth_divergence", "high", "", ()),
    Finding("fileA", "R2_si_journal_rollback", "high",
            "displayed modified older than journal write", ("display($SI)", "journal(USN)")),
    Finding("fileA", "R4_setinfo_captured", "high", "", ()),
    Finding("fileA", "R7_si_fn_modified_divergence", "high", "", ()),
]
DISPLAY = MACE(modified=1609459200.45, created=1609459100.12)
SETINFO = [{"actor": "veeam-backup", "written_modified": 1609459200.45, "real_time": 1700000005.0}]
TRUSTED = {"veeam-backup"}


def _scripted_client() -> types.SimpleNamespace:
    """A fake client that mimics a ReAct trajectory: inspect, then conclude."""

    class _Block:
        def __init__(self, type, **kw):
            self.type = type
            self.__dict__.update(kw)

    class _Resp:
        def __init__(self, content):
            self.content = content
            self.stop_reason = "tool_use"

    script = [
        _Resp([_Block("tool_use", name="check_trusted_actors", input={}, id="t1")]),
        _Resp([_Block("tool_use", name="inspect_timestamps", input={}, id="t2")]),
        _Resp([_Block("tool_use", name="conclude_triage", id="t3", input={
            "benign_likelihood": 0.9,
            "rationale": "veeam-backup is a trusted restore tool and the times are sub-second; "
                         "this looks like a legitimate restore, not a forgery.",
        })]),
    ]

    class _Messages:
        def create(self, **kw):
            return script.pop(0)

    return types.SimpleNamespace(messages=_Messages())


def main() -> None:
    if os.environ.get("ANTHROPIC_API_KEY"):
        banner("Running the REAL ReAct agent (ANTHROPIC_API_KEY found)")
        agent = TriageAgent()
    else:
        banner("No ANTHROPIC_API_KEY -- driving the ReAct loop with a scripted client")
        agent = TriageAgent(client=_scripted_client())

    report = agent.assess("fileA", FINDINGS, DISPLAY, SETINFO, TRUSTED)
    print(report.explain())

    # The agent's opinion only ever constrains the responder. Allow destructive
    # actions and turn execution ON, then show the hold caps it to ALERT and the
    # ISOLATE executor never fires.
    executed: list[str] = []
    policy = ResponsePolicy(
        roe=RulesOfEngagement(
            dry_run=False,
            allowed_actions=frozenset(
                {Action.ALERT, Action.TICKET, Action.QUARANTINE, Action.ISOLATE}
            ),
        ),
        executors={Action.ISOLATE: lambda d: executed.append("ISOLATE")},
    )
    decision = gated_decide(policy, "fileA", FINDINGS, report)
    banner("Live responder, gated by triage")
    print(f"-> action: {decision.action.name}  (executed={decision.executed})")
    print(f"-> executors fired: {executed or '(none)'}")
    print(f"-> {decision.reason}")


if __name__ == "__main__":
    main()
