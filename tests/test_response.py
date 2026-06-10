from quantumlock.detector import DivergenceDetector, Finding
from quantumlock.ledger import Ledger
from quantumlock.response import (
    Action,
    ResponsePolicy,
    RulesOfEngagement,
    confidence,
)
from quantumlock.simulator import Angel, FileSystemSim


def fs(*rules, severity="high"):
    return [Finding("f", r, severity, "x", ()) for r in rules]


def test_confidence_scales_with_severity_and_corroboration():
    assert confidence([]) == 0.0
    assert abs(confidence(fs("R1")) - 0.60) < 1e-9
    assert abs(confidence(fs("R1", severity="medium")) - 0.35) < 1e-9
    assert confidence(fs("R1", "R2")) > confidence(fs("R1"))  # corroboration helps
    assert confidence(fs("R1", "R2", "R3", "R4", "R5")) <= 0.99  # capped


def test_escalation_ladder():
    p = ResponsePolicy()
    assert p.decide("f", fs("R1", severity="medium")).action == Action.ALERT  # 0.35
    assert p.decide("f", fs("R1")).action == Action.TICKET  # 0.60
    assert p.decide("f", fs("R1", "R2", "R3")).action == Action.QUARANTINE  # 0.90
    assert p.decide("f", fs("R1", "R2", "R3", "R4")).action == Action.ISOLATE  # 0.99


def test_empty_findings_is_no_action():
    assert ResponsePolicy().decide("f", []).action == Action.NONE


def test_dry_run_is_the_default_and_blocks_execution():
    d = ResponsePolicy().decide("f", fs("R1", "R2", "R3", "R4"))
    assert d.action == Action.ISOLATE
    assert d.dry_run is True
    assert d.executed is False  # decided but not carried out


def test_roe_can_forbid_destructive_actions():
    roe = RulesOfEngagement(allowed_actions=frozenset({Action.ALERT, Action.TICKET}))
    d = ResponsePolicy(roe).decide("f", fs("R1", "R2", "R3", "R4"))
    assert d.action == Action.TICKET  # capped despite 0.99 confidence


def test_protected_file_downgrades_destructive_to_alert():
    roe = RulesOfEngagement(protected_files=frozenset({"f"}))
    d = ResponsePolicy(roe).decide("f", fs("R1", "R2", "R3", "R4"))
    assert d.action == Action.ALERT
    assert "protected file" in d.reason


def test_decisions_are_logged_to_the_tamper_evident_ledger():
    led = Ledger()
    p = ResponsePolicy(ledger=led)
    p.decide("evil.exe", fs("R1", "R2"))  # actionable -> logged
    p.decide("clean.txt", [])  # NONE -> not logged
    records = led.all_records()
    assert len(records) == 1
    assert records[0].event["op"] == "response"
    assert records[0].event["file_id"] == "evil.exe"
    assert led.verify().ok


def test_executor_runs_only_when_not_dry_run():
    calls = []
    roe = RulesOfEngagement(dry_run=False)
    p = ResponsePolicy(roe, executors={Action.ISOLATE: lambda d: calls.append(d.action)})
    d = p.decide("f", fs("R1", "R2", "R3", "R4"))
    assert d.executed is True
    assert calls == [Action.ISOLATE]


def test_integration_detector_findings_drive_a_response():
    sim = FileSystemSim()
    sim.create_file("report.docx")
    sim.write_file("report.docx")
    Angel("report.docx").tick(sim)  # stomp while unobserved
    det = DivergenceDetector(sim.display, sim.mft, sim.journal, now=sim.clock.now())
    findings = det.scan("report.docx")

    led = Ledger()
    decision = ResponsePolicy(ledger=led).decide("report.docx", findings)
    # multiple corroborating rules -> high confidence -> destructive tier
    assert decision.action >= Action.QUARANTINE
    assert decision.confidence >= 0.8
    assert led.verify().ok and len(led) == 1
