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


def test_parse_accepts_valid_specs():
    r = parse_rule({"kind": "compare", "left": "si_created", "op": "<", "right": "fn_created"})
    assert r.kind == "compare" and r.op == "<"
    r2 = parse_rule({"kind": "whole_second", "field": "si_modified"})
    assert r2.kind == "whole_second" and r2.field == "si_modified"


def test_empty_ruleset_catches_nothing():
    corpus = build_corpus(n_per_kind=20)
    eff = score_ruleset([], corpus)
    assert eff.tp == 0 and eff.fp == 0          # no rules -> no positives
    assert eff.recall == 0.0


def test_miner_clears_the_bar_with_no_false_positives():
    corpus = build_corpus()
    bar = Bar()
    result = RuleMiner(bar).mine(corpus)
    assert result.source == "miner"
    assert result.met(bar)
    assert result.score.fp == 0                 # never flags a benign file
    assert 0 < len(result.rules) <= 5


def test_good_ruleset_separates_the_classes():
    corpus = build_corpus(n_per_kind=50)
    rules = [
        parse_rule({"kind": "compare", "left": "si_created", "op": "<", "right": "fn_created"}),
        parse_rule({"kind": "compare", "left": "si_modified", "op": ">", "right": "now"}),
        parse_rule({"kind": "whole_second", "field": "si_modified"}),
    ]
    eff = score_ruleset(rules, corpus)
    assert eff.precision == 1.0 and eff.recall == 1.0
