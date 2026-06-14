from weeping_angel.detector import Finding
from weeping_angel.response import Action, ResponsePolicy, RulesOfEngagement
from weeping_angel.triage import TriageReport, TriageScorer, cap_decision, gated_decide
from weeping_angel.witnesses import MACE


def _held_report(fid="f"):
    return TriageReport(fid, benign_likelihood=0.95, disposition="likely_benign",
                        recommend_hold=True, contributions=())


def _open_policy(executed):
    return ResponsePolicy(
        roe=RulesOfEngagement(
            dry_run=False,
            allowed_actions=frozenset({Action.ALERT, Action.QUARANTINE, Action.ISOLATE}),
        ),
        executors={
            Action.ALERT: lambda d: executed.append(d.action.name),
            Action.QUARANTINE: lambda d: executed.append(d.action.name),
            Action.ISOLATE: lambda d: executed.append(d.action.name),
        },
    )


def _stomp_findings(fid="f"):
    return [
        Finding(fid, "R1_si_fn_birth_divergence", "high", "", (), {}),
        Finding(fid, "R2_si_journal_rollback", "high", "", (), {}),
        Finding(fid, "R4_setinfo_captured", "high", "", (), {}),
        Finding(fid, "R7_si_fn_modified_divergence", "high", "", (), {}),
    ]


def test_trusted_restore_is_held():
    s = TriageScorer()
    f = [Finding("f", "R2_si_journal_rollback", "high", "", (), {})]
    display = MACE(modified=1609459200.45, created=1609459100.12)
    setinfo = [{"actor": "veeam-backup", "written_modified": 1609459200.45}]
    r = s.assess("f", f, display, setinfo, {"veeam-backup"})
    assert r.disposition == "likely_benign"
    assert r.recommend_hold


def test_classic_stomp_not_held():
    s = TriageScorer()
    display = MACE(modified=1500000000.0, created=1500000000.0)
    setinfo = [{"actor": "evil.exe", "written_modified": 1500000000.0}]
    r = s.assess("f", _stomp_findings(), display, setinfo, {"veeam-backup"})
    assert r.disposition == "suspicious"
    assert not r.recommend_hold


def test_triage_can_only_downgrade():
    """The invariant: a hold never raises an action, only caps it at ALERT."""
    policy = ResponsePolicy(roe=RulesOfEngagement(
        dry_run=True,
        allowed_actions=frozenset({Action.ALERT, Action.QUARANTINE, Action.ISOLATE}),
    ))
    s = TriageScorer()
    f = [Finding("f", "R2_si_journal_rollback", "high", "", (), {})]
    display = MACE(modified=1609459200.45)
    setinfo = [{"actor": "veeam-backup", "written_modified": 1609459200.45}]
    report = s.assess("f", f, display, setinfo, {"veeam-backup"})

    raw = policy.decide("f", f)
    capped = cap_decision(raw, report)
    assert capped.action <= raw.action          # never raised
    assert capped.action == Action.ALERT         # destructive held down to alert


def test_no_hold_leaves_decision_untouched():
    policy = ResponsePolicy(roe=RulesOfEngagement(dry_run=True))
    s = TriageScorer()
    display = MACE(modified=1500000000.0, created=1500000000.0)
    report = s.assess("f", _stomp_findings(), display, [], set())
    raw = policy.decide("f", _stomp_findings())
    assert cap_decision(raw, report) == raw      # suspicious -> no change


def test_gated_decide_caps_before_executing_when_live():
    """The fix: with dry_run OFF, a held destructive action is capped BEFORE the
    executor runs -- the un-capped action never executes (only relabelling it
    after the fact, the old wrapper let the executor fire first)."""
    executed: list[str] = []
    policy = _open_policy(executed)
    decision = gated_decide(policy, "f", _stomp_findings(), _held_report())
    assert decision.action == Action.ALERT       # destructive capped down
    assert decision.executed is False            # held -> not executed
    assert executed == []                        # nothing fired, not even ISOLATE


def test_gated_decide_executes_when_not_held():
    """The gate doesn't break normal execution: a non-hold runs as usual."""
    executed: list[str] = []
    policy = _open_policy(executed)
    not_held = TriageReport("f", benign_likelihood=0.0, disposition="suspicious",
                            recommend_hold=False, contributions=())
    decision = gated_decide(policy, "f", _stomp_findings(), not_held)
    assert decision.action == Action.ISOLATE
    assert executed == ["ISOLATE"]


def test_gated_decide_logs_rationale_then_decision():
    """Hold or not, the triage rationale and the decision both land in the
    tamper-evident ledger, rationale first."""
    from weeping_angel.ledger import Ledger

    led = Ledger()
    policy = ResponsePolicy(ledger=led, roe=RulesOfEngagement(dry_run=True))
    gated_decide(policy, "f", _stomp_findings(), _held_report())
    ops = [r.event["op"] for r in led.all_records()]
    assert ops == ["triage", "response"]
    assert led.verify().ok
