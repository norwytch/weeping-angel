"""Narrated walkthrough of the three core scenarios.

    python examples/demo.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quantumlock import (  # noqa: E402
    AdvancedAngel,
    Anchor,
    Angel,
    DivergenceDetector,
    FileSystemSim,
    prove_no_paradox_free_move,
)


def rule(title: str) -> None:
    print("\n" + "=" * 68)
    print(title)
    print("=" * 68)


def show_findings(detector: DivergenceDetector, file_id: str) -> None:
    findings = detector.scan(file_id)
    if not findings:
        print("  no divergence -> the Angel is quantum-locked (harmless)")
        return
    for f in findings:
        print(f"  [{f.severity.upper():4}] {f.rule}")
        print(f"         {f.explanation}")
        print(f"         witnesses: {', '.join(f.witnesses)}")
        print(f"         evidence:  {f.evidence}")


def scenario_unobserved() -> None:
    rule("Scenario 1 -- the Angel moves while it believes no one is watching")
    sim = FileSystemSim()
    sim.create_file("report.docx")
    sim.write_file("report.docx")  # genuine edit at the real time
    angel = Angel("report.docx")

    sim.oracle.procmon_running = False  # in-band: nothing visible to the Angel
    print(f"  Angel.tick -> {angel.tick(sim)}  (it sees no in-band observer)")

    detector = DivergenceDetector(sim.display, sim.mft, sim.journal, now=sim.clock.now())
    print("  But three independent witnesses disagree:")
    show_findings(detector, "report.docx")


def scenario_observed() -> None:
    rule("Scenario 2 -- the Angel freezes because it believes it is watched")
    sim = FileSystemSim()
    sim.create_file("report.docx")
    sim.write_file("report.docx")
    angel = Angel("report.docx")

    sim.oracle.procmon_running = True  # a fake in-band watcher is enough
    print(f"  Angel.tick -> {angel.tick(sim)}  (it believes it is observed)")

    detector = DivergenceDetector(sim.display, sim.mft, sim.journal, now=sim.clock.now())
    show_findings(detector, "report.docx")


def scenario_scrub() -> None:
    rule("Scenario 3 -- the Angel also tries to rewrite history")
    sim = FileSystemSim()
    sim.create_file("report.docx")
    sim.write_file("report.docx")
    angel = AdvancedAngel("report.docx")

    sim.oracle.procmon_running = False
    print(f"  AdvancedAngel.tick -> {angel.tick(sim)}  (stomps, then scrubs the log)")

    result = sim.ledger.verify()
    print(f"  ledger.verify().ok = {result.ok}")
    for p in result.problems:
        print(f"    - {p}")
    print("  You cannot rewrite the past without producing a contradiction.")

    # The remaining gap is dropping the tail, which leaves a shorter but
    # self-consistent chain -- closed by anchoring the head off-box.
    sim2 = FileSystemSim()
    sim2.create_file("report.docx")
    sim2.write_file("report.docx")
    anchor = Anchor(b"off-box-collector-secret")
    anchor.checkpoint(sim2.ledger)  # head pinned out of the Angel's reach
    sim2.ledger.simulate_truncate(1)  # Angel drops the tail
    print(f"\n  after tail-truncation: ledger.verify().ok = {sim2.ledger.verify().ok} "
          "(chain alone is fooled)")
    anchored = anchor.verify(sim2.ledger)
    print(f"  anchor.verify().ok = {anchored.ok}  (off-box head catches the drop)")
    for p in anchored.problems:
        print(f"    - {p}")


def scenario_paradox() -> None:
    rule("The paradox, formalized")
    holds = prove_no_paradox_free_move(actually_observed=True)
    breaks = prove_no_paradox_free_move(actually_observed=False)
    print(f"  with out-of-band observation: unsafe state reachable? "
          f"{holds.unsafe_state_reachable}  -> paradox holds: {holds.holds}")
    for state, outcome in holds.transcript:
        print(f"      believes_observed={state.believes_observed!s:5} -> {outcome.value}")
    print(f"  without out-of-band observation: unsafe state reachable? "
          f"{breaks.unsafe_state_reachable}  -> paradox holds: {breaks.holds}")
    print("  => the out-of-band vantage point is exactly what is load-bearing.")


if __name__ == "__main__":
    scenario_unobserved()
    scenario_observed()
    scenario_scrub()
    scenario_paradox()
    print()
