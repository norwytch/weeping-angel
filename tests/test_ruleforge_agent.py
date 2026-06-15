"""Tests for the ReAct rule-engineering agent. A fake Anthropic-shaped client
drives the propose -> evaluate -> commit -> finish loop with no network."""

import types

from weeping_angel.ruleforge import Bar, RuleEngineerAgent, build_corpus


class _Block:
    def __init__(self, type, **kw):
        self.type = type
        self.__dict__.update(kw)


class _Resp:
    def __init__(self, content):
        self.content = content
        self.stop_reason = "tool_use"


class _FakeMessages:
    def __init__(self, scripted):
        self.scripted = list(scripted)
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return self.scripted.pop(0)


def _fake_client(scripted):
    return types.SimpleNamespace(messages=_FakeMessages(scripted))


def _tool(name, _id, **inp):
    return _Resp([_Block("tool_use", name=name, id=_id, input=inp)])


def test_agent_closes_the_gap_with_a_conjunction():
    # The agent reaches the bar where the greedy miner can't: three single rules
    # for the easy kinds, plus an all_of conjunction for stomp_widen.
    scripted = [
        _tool("inspect_corpus", "t1"),
        _tool("commit_rule", "t2", kind="compare",
              left="si_modified", op="<", right="journal_last"),
        _tool("commit_rule", "t3", kind="compare", left="si_modified", op=">", right="now"),
        _tool("commit_rule", "t4", kind="whole_second", field="si_created"),
        _tool("commit_rule", "t5", kind="all_of", clauses=[
            {"kind": "compare", "left": "si_created", "op": "<", "right": "fn_created"},
            {"kind": "compare", "left": "si_modified", "op": ">", "right": "journal_last"}]),
        _tool("finish", "t6"),
    ]
    agent = RuleEngineerAgent(client=_fake_client(scripted))
    result = agent.engineer(build_corpus(n_per_kind=40))
    assert result.source == "agent"
    assert len(result.rules) == 4
    assert any(r.kind == "all_of" for r in result.rules)
    assert result.met(Bar())                            # cleared the bar the miner couldn't
    assert result.score.fp == 0


def test_agent_rejects_a_rule_outside_the_grammar():
    # A malicious/garbage rule must never enter the set or execute.
    scripted = [
        _tool("commit_rule", "t1", kind="compare", left="__import__", op="<", right="now"),
        _tool("commit_rule", "t2", kind="compare",
              left="si_modified", op="<", right="journal_last"),
        _tool("finish", "t3"),
    ]
    agent = RuleEngineerAgent(client=_fake_client(scripted))
    result = agent.engineer(build_corpus(n_per_kind=20))
    assert len(result.rules) == 1                       # only the valid rule landed
    assert result.rules[0].describe() == "si_modified < journal_last"


def test_agent_falls_back_to_miner_without_client(monkeypatch):
    agent = RuleEngineerAgent()
    monkeypatch.setattr(agent, "_client_or_none", lambda: None)
    result = agent.engineer(build_corpus(n_per_kind=40))
    assert result.source == "miner"
    assert result.score.precision == 1.0                # a clean, if incomplete, set
    assert not result.met(Bar())


def test_agent_falls_back_on_api_failure():
    class _Boom:
        def create(self, **kw):
            raise RuntimeError("api down")

    agent = RuleEngineerAgent(client=types.SimpleNamespace(messages=_Boom()))
    result = agent.engineer(build_corpus(n_per_kind=40))
    assert result.source == "miner"
    assert result.score.precision == 1.0


def test_agent_commits_nothing_falls_back_to_miner():
    # Model just inspects and finishes without committing -> don't ship empty.
    scripted = [_tool("inspect_corpus", "t1"), _tool("finish", "t2")]
    agent = RuleEngineerAgent(client=_fake_client(scripted))
    result = agent.engineer(build_corpus(n_per_kind=20))
    assert result.source == "miner"
    assert len(result.rules) > 0
