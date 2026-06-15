"""Tests for the rule grammar, the labeled corpus, and the deterministic miner."""

import pytest

from weeping_angel.ruleforge import (
    Bar,
    CandidateRule,
    RuleMiner,
    build_corpus,
    parse_rule,
    score_ruleset,
)


def test_compare_rule_fires_with_tolerance():
    r = CandidateRule(kind="compare", left="si_created", op="<", right="fn_created")
    assert r.fires({"si_created": 100.0, "fn_created": 200.0})        # clearly less
    assert not r.fires({"si_created": 199.5, "fn_created": 200.0})    # within 1s tolerance
    assert not r.fires({"si_created": 300.0, "fn_created": 200.0})    # greater


def test_whole_second_rule():
    r = CandidateRule(kind="whole_second", field="si_modified")
    assert r.fires({"si_modified": 1700000000.0})        # forged round time
    assert not r.fires({"si_modified": 1700000000.42})   # genuine sub-second


def test_parse_rejects_anything_outside_the_grammar():
    # The safety boundary: model output is validated, never executed.
    with pytest.raises(ValueError):
        parse_rule({"kind": "compare", "left": "__import__", "op": "<", "right": "now"})
    with pytest.raises(ValueError):
        parse_rule({"kind": "compare", "left": "si_created", "op": "rm -rf", "right": "now"})
    with pytest.raises(ValueError):
        parse_rule({"kind": "exec", "field": "now"})
    with pytest.raises(ValueError):
        parse_rule({"kind": "whole_second", "field": "not_a_field"})
    with pytest.raises(ValueError):  # too few clauses
        parse_rule({"kind": "all_of", "clauses": [{"kind": "whole_second", "field": "now"}]})
    with pytest.raises(ValueError):  # a bad clause inside a conjunction
        parse_rule({"kind": "all_of", "clauses": [
            {"kind": "whole_second", "field": "now"},
            {"kind": "compare", "left": "evil", "op": "<", "right": "now"}]})
    with pytest.raises(ValueError):  # no nested conjunctions
        parse_rule({"kind": "all_of", "clauses": [
            {"kind": "whole_second", "field": "now"},
            {"kind": "all_of", "clauses": []}]})


def test_parse_accepts_valid_specs():
    r = parse_rule({"kind": "compare", "left": "si_created", "op": "<", "right": "fn_created"})
    assert r.kind == "compare" and r.op == "<"
    r2 = parse_rule({"kind": "whole_second", "field": "si_modified"})
    assert r2.kind == "whole_second" and r2.field == "si_modified"
    r3 = parse_rule({"kind": "all_of", "clauses": [
        {"kind": "compare", "left": "si_created", "op": "<", "right": "fn_created"},
        {"kind": "whole_second", "field": "si_modified"}]})
    assert r3.kind == "all_of" and len(r3.clauses) == 2


def test_conjunction_fires_only_when_all_clauses_fire():
    r = parse_rule({"kind": "all_of", "clauses": [
        {"kind": "compare", "left": "si_created", "op": "<", "right": "fn_created"},
        {"kind": "compare", "left": "si_modified", "op": ">", "right": "journal_last"}]})
    f = {"si_created": 100.0, "si_modified": 500.0, "fn_created": 200.0, "journal_last": 300.0,
         "journal_first": 200.0, "now": 600.0}
    assert r.fires(f)                                   # both clauses true
    assert not r.fires({**f, "si_modified": 250.0})     # second clause false


def test_empty_ruleset_catches_nothing():
    corpus = build_corpus(n_per_kind=20)
    eff = score_ruleset([], corpus)
    assert eff.tp == 0 and eff.fp == 0          # no rules -> no positives
    assert eff.recall == 0.0


def test_miner_plateaus_without_conjunctions():
    # The greedy single-clause miner is clean but incomplete: it catches three of
    # the four malicious kinds and cannot express the conjunction the fourth needs.
    corpus = build_corpus()
    bar = Bar()
    result = RuleMiner(bar).mine(corpus)
    assert result.source == "miner"
    assert result.score.fp == 0                 # never flags a benign file
    assert not result.met(bar)                  # can't reach the recall bar
    assert result.score.recall == 0.75          # 3 of 4 malicious kinds


def test_conjunction_closes_the_gap_the_miner_cannot():
    # No single comparison cleanly catches stomp_widen; the conjunction does.
    corpus = build_corpus(n_per_kind=60)
    miner = RuleMiner(Bar()).mine(corpus)
    assert miner.score.recall < 1.0             # the headroom the agent targets
    conjunction = parse_rule({"kind": "all_of", "clauses": [
        {"kind": "compare", "left": "si_created", "op": "<", "right": "fn_created"},
        {"kind": "compare", "left": "si_modified", "op": ">", "right": "journal_last"}]})
    closed = score_ruleset([*miner.rules, conjunction], corpus)
    assert closed.precision == 1.0 and closed.recall == 1.0   # bar cleared, zero FPs
