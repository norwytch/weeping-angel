"""Triage demo: same findings can mean a backup tool or an Angel. The linear
scorer reads the evidence content and only ever argues the responder *down*."""

from __future__ import annotations

from weeping_angel.detector import Finding
from weeping_angel.response import Action, ResponsePolicy, RulesOfEngagement
from weeping_angel.triage import TriageScorer, gated_decide
from weeping_angel.witnesses import MACE


def banner(t: str) -> None:
    print("\n" + t + "\n" + "-" * len(t))


def main() -> None:
    scorer = TriageScorer()
    # Allow destructive actions so we can see triage hold one back.
    policy = ProbePolicy()
    trusted = {"veeam-backup"}

    # --- Case A: a legitimate restore. Rules fire, but a trusted tool did it,
    # one coherent setinfo, restored real (sub-second) times, no R4 clash. ---
    banner("Case A: trusted backup restore (should be HELD)")
    findings_a = [
        Finding("fileA", "R2_si_journal_rollback", "high",
                "displayed modified older than journal write",
                ("display($SI)", "journal(USN)"),
                {"display_modified": 1609459200.45, "journal_modified": 1700000000.0}),
    ]
    display_a = MACE(modified=1609459200.45, created=1609459100.12)  # sub-second: real
    setinfo_a = [{"actor": "veeam-backup", "written_modified": 1609459200.45,
                  "real_time": 1700000005.0}]
    report_a = scorer.assess("fileA", findings_a, display_a, setinfo_a, trusted)
    print(report_a.explain())
    decision_a = gated_decide(policy, "fileA", findings_a, report_a)
    print(f"-> action: {decision_a.action.name}  ({decision_a.reason})")

    # --- Case B: a classic stomp. No trusted actor, whole-second forged $SI
    # rolled back, ground-truth clash (R4), several rules agree. ---
    banner("Case B: classic timestomp (should NOT be held)")
    findings_b = [
        Finding("fileB", "R1_si_fn_birth_divergence", "high", "", (), {}),
        Finding("fileB", "R2_si_journal_rollback", "high", "", (), {}),
        Finding("fileB", "R4_setinfo_captured", "high", "", (), {}),
        Finding("fileB", "R7_si_fn_modified_divergence", "high", "", (), {}),
    ]
    display_b = MACE(modified=1500000000.0, created=1500000000.0)  # whole seconds: forged
    setinfo_b = [{"actor": "evil.exe", "written_modified": 1500000000.0,
                  "real_time": 1700000000.0}]
    report_b = scorer.assess("fileB", findings_b, display_b, setinfo_b, trusted)
    print(report_b.explain())
    decision_b = gated_decide(policy, "fileB", findings_b, report_b)
    print(f"-> action: {decision_b.action.name}  ({decision_b.reason})")


class ProbePolicy(ResponsePolicy):
    """ResponsePolicy with destructive actions allowed and no ledger, for demo."""
    def __init__(self) -> None:
        super().__init__(roe=RulesOfEngagement(
            dry_run=True,
            allowed_actions=frozenset(
                {Action.ALERT, Action.TICKET, Action.QUARANTINE, Action.ISOLATE}
            ),
        ))


if __name__ == "__main__":
    main()
