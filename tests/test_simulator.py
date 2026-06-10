from quantumlock.detector import DivergenceDetector
from quantumlock.simulator import AdvancedAngel, Angel, FileSystemSim


def primed_sim():
    sim = FileSystemSim()
    sim.create_file("report.docx")
    sim.write_file("report.docx")
    return sim


def test_unobserved_angel_is_caught():
    sim = primed_sim()
    sim.oracle.procmon_running = False
    assert Angel("report.docx").tick(sim) == "MOVING"
    det = DivergenceDetector(sim.display, sim.mft, sim.journal, now=sim.clock.now())
    findings = det.scan("report.docx")
    assert findings  # the move was recorded by independent witnesses
    assert {
        "R1_si_fn_birth_divergence",
        "R2_si_journal_rollback",
        "R4_setinfo_captured",
        "R6_subsecond_truncation",
    } <= {f.rule for f in findings}


def test_observed_angel_freezes_and_leaves_no_trace():
    sim = primed_sim()
    sim.oracle.procmon_running = True
    assert Angel("report.docx").tick(sim) == "STONE"
    det = DivergenceDetector(sim.display, sim.mft, sim.journal, now=sim.clock.now())
    assert det.scan("report.docx") == []


def test_scrubbing_the_journal_breaks_the_chain():
    sim = primed_sim()
    sim.oracle.procmon_running = False
    AdvancedAngel("report.docx").tick(sim)
    assert not sim.ledger.verify().ok
