# ruleforge: an agent that writes detection rules

The triage agent judges one file. This one improves the *detector*. It is the
agent task in this repo with a real reward signal, so the loop converges instead
of producing plausible-sounding rules that don't work: propose a rule, score it
against the labeled corpus with precision/recall, read the result, revise.

## The loop

1. `inspect_corpus` shows what malicious cases are still uncaught and the current
   precision/recall.
2. The agent proposes a candidate rule and calls `evaluate_rule` to score it: the
   rule's standalone precision/recall, the rule set's score if it were added, and
   the marginal effect (new true positives, new false positives, which malicious
   kinds it newly catches).
3. `commit_rule` adds a rule that gains true positives with zero new false
   positives; `finish` stops when recall and precision clear the bar.

The corpus extends `weeping_angel.efficacy`: clean files, benign timestamp-setting
(backup/restore/`cp -p`, which must not be flagged), and timestomp variants. No
single rule catches every variant, so the agent has to reason about coverage and
build a small rule set.

## The headroom: where reasoning beats brute force

One malicious class, `stomp_widen`, is the point. It pushes the apparent birth a
little earlier *and* the modified time a little later, with no single impossible
value. A benign `birth_skew` file (FS migration / timezone bug) also has an early
birth, so `si_created < fn_created` alone false-positives on it; a benign
`restore_postdate` file also has a late modified time, so `si_modified >
journal_last` alone false-positives on it. **No single comparison separates
`stomp_widen` from benign without a false positive.**

The greedy miner only ORs single clauses, so it plateaus at recall 0.75 (it cannot
catch `stomp_widen` cleanly). The agent can propose a *conjunction* whose two
clauses are individually impure but jointly clean, and close the gap to 1.0. That
is the case where an agent's reasoning beats enumeration: the conjunction space is
combinatorial (pairs, triples of clauses), so the greedy baseline doesn't search
it, but the agent reasons its way straight to the right combination.

## Rules are data, not code

A rule is a small validated object, never executable Python:

```python
{"kind": "compare", "left": "si_created", "op": "<", "right": "fn_created"}  # backdated $SI
{"kind": "whole_second", "field": "si_modified"}                            # forged round time
{"kind": "all_of", "clauses": [                                             # a conjunction
    {"kind": "compare", "left": "si_created",  "op": "<", "right": "fn_created"},
    {"kind": "compare", "left": "si_modified", "op": ">", "right": "journal_last"}]}
```

`parse_rule` validates every spec against an allowlist of fields and operators
(and bounds conjunctions to 2-4 non-nested clauses), so an agent-authored rule can
be scored and audited without the framework ever running model output as code.
Fields: `si_created`, `si_modified`, `fn_created`, `journal_first`,
`journal_last`, `now`.

## Two engineers, one interface

Both expose `engineer(corpus) -> RuleSetResult`:

- **`RuleMiner`** (default, pure stdlib): deterministic greedy search over the
  whole grammar; the baseline and offline fallback.
- **`RuleEngineerAgent`** (optional `[agent]` extra): Claude runs the ReAct loop;
  falls back to the miner with no SDK/key or on any API failure.

## Use

```python
from weeping_angel.ruleforge import make_rule_engineer

result = make_rule_engineer().engineer()   # agent if a key is present, else the miner
print(result.explain())                    # the rule set + its precision/recall/F1
```

## Output is a proposal, not a merge

The agent discovers and scores rules; it never edits `detector.py` or executes its
own rules. Promoting a discovered rule into the live detector is a human review
step, the same posture as the triage agent only ever advising the responder.
