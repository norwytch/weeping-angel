"""Tests for the ReAct TriageAgent. A fake Anthropic-shaped client drives the
reason/act/observe loop with no network, so these run in CI without a key."""

import types

from weeping_angel.detector import Finding
from weeping_angel.response import Action, ResponsePolicy, RulesOfEngagement
from weeping_angel.triage import TriageAgent, TriageScorer, gated_decide
from weeping_angel.witnesses import MACE


def _stomp_findings(fid="f"):
    return [
        Finding(fid, "R1_si_fn_birth_divergence", "high", "", (), {}),
        Finding(fid, "R2_si_journal_rollback", "high", "", (), {}),
        Finding(fid, "R4_setinfo_captured", "high", "", (), {}),
        Finding(fid, "R7_si_fn_modified_divergence", "high", "", (), {}),
    ]


class _Block:
    """A stand-in for an SDK content block (tool_use / text / thinking)."""

    def __init__(self, type, **kw):
        self.type = type
        self.__dict__.update(kw)


class _Resp:
    def __init__(self, content, stop_reason="tool_use"):
        self.content = content
        self.stop_reason = stop_reason


class _FakeMessages:
    def __init__(self, scripted):
        self.scripted = list(scripted)
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return self.scripted.pop(0)


def _fake_client(scripted):
    return types.SimpleNamespace(messages=_FakeMessages(scripted))


def test_agent_runs_react_loop_then_concludes():
    scripted = [
        _Resp([_Block("tool_use", name="list_findings", input={}, id="t1")]),
        _Resp([_Block(
            "tool_use", name="conclude_triage", id="t2",
            input={"benign_likelihood": 0.9,
                   "rationale": "Trusted veeam restore, sub-second times."},
        )]),
    ]
    client = _fake_client(scripted)
    agent = TriageAgent(client=client)

    findings = [Finding("f", "R2_si_journal_rollback", "high", "", (), {})]
    display = MACE(modified=1609459200.45, created=1609459100.12)
    report = agent.assess("f", findings, display, [{"actor": "veeam-backup"}], {"veeam-backup"})

    assert report.benign_likelihood == 0.9
    assert report.disposition == "likely_benign"
    assert report.recommend_hold                       # 0.9 >= hold threshold
    assert "veeam" in report.rationale.lower()
    # The loop actually executed the inspection tool and fed an observation back
    # before the model concluded (true ReAct, not a single shot).
    second_call_msgs = client.messages.calls[1]["messages"]
    assert any(
        isinstance(m["content"], list) and m["content"][0].get("type") == "tool_result"
        for m in second_call_msgs if m["role"] == "user"
    )


def test_agent_maps_low_likelihood_to_suspicious():
    scripted = [_Resp([_Block(
        "tool_use", name="conclude_triage", id="t1",
        input={"benign_likelihood": 0.1,
               "rationale": "Backdated whole-second time by an unknown actor."},
    )])]
    agent = TriageAgent(client=_fake_client(scripted))
    report = agent.assess("f", _stomp_findings(), MACE(modified=1500000000.0), [], set())
    assert report.disposition == "suspicious"
    assert not report.recommend_hold


def test_agent_falls_back_on_api_failure():
    class _Boom:
        def create(self, **kw):
            raise RuntimeError("api down")

    agent = TriageAgent(client=types.SimpleNamespace(messages=_Boom()))
    findings = [Finding("f", "R2_si_journal_rollback", "high", "", (), {})]
    display = MACE(modified=1609459200.45, created=1609459100.12)
    setinfo = [{"actor": "veeam-backup", "written_modified": 1609459200.45}]

    got = agent.assess("f", findings, display, setinfo, {"veeam-backup"})
    want = TriageScorer().assess("f", findings, display, setinfo, {"veeam-backup"})
    assert got == want                                  # degrades to the linear scorer
    assert got.disposition == "likely_benign"


def test_agent_uses_fallback_when_no_client(monkeypatch):
    agent = TriageAgent()
    monkeypatch.setattr(agent, "_client_or_none", lambda: None)
    findings = _stomp_findings()
    display = MACE(modified=1500000000.0, created=1500000000.0)
    got = agent.assess("f", findings, display, [], set())
    want = TriageScorer().assess("f", findings, display, [], set())
    assert got == want


def test_agent_never_concludes_falls_back():
    # Model keeps inspecting and never calls conclude_triage within the budget.
    scripted = [
        _Resp([_Block("tool_use", name="list_findings", input={}, id=f"t{i}")]) for i in range(10)
    ]
    agent = TriageAgent(client=_fake_client(scripted), max_iterations=3)
    findings = _stomp_findings()
    got = agent.assess("f", findings, MACE(modified=1500000000.0), [], set())
    want = TriageScorer().assess("f", findings, MACE(modified=1500000000.0), [], set())
    assert got == want


def test_agent_hold_is_capped_before_execution():
    """End-to-end: an agent-driven hold can only downgrade the live responder."""
    scripted = [_Resp([_Block(
        "tool_use", name="conclude_triage", id="t1",
        input={"benign_likelihood": 0.95, "rationale": "Trusted restore."},
    )])]
    agent = TriageAgent(client=_fake_client(scripted))
    findings = _stomp_findings()
    report = agent.assess(
        "f", findings, MACE(modified=1.5), [{"actor": "veeam-backup"}], {"veeam-backup"}
    )
    assert report.recommend_hold

    executed: list[str] = []
    policy = ResponsePolicy(
        roe=RulesOfEngagement(
            dry_run=False,
            allowed_actions=frozenset({Action.ALERT, Action.QUARANTINE, Action.ISOLATE}),
        ),
        executors={Action.ISOLATE: lambda d: executed.append("ISOLATE")},
    )
    decision = gated_decide(policy, "f", findings, report)
    assert decision.action == Action.ALERT
    assert executed == []
