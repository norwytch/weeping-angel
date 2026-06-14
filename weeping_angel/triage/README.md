# triage: content-aware, transparent, downgrade-only

`response.confidence()` scores a file by *counting* corroborating rules. It can't
read the *content* of the evidence: who performed the `setinfo`, which direction
the time moved, whether the forged `$SI` is suspiciously round. This package adds
exactly that, and constrains it so it can only ever make the responder more
cautious.

## Two assessors, one interface

Both expose `assess(file_id, findings, display, setinfo_events, trusted_actors) -> TriageReport`:

- **`TriageScorer`** (default, pure stdlib): a transparent linear policy over a
  handful of evidence features, same shape as `learn.LearnedBlue`: a feature
  vector, one dot product, baked-in weights that work untrained, optionally tuned
  by the existing Evolution Strategies loop. Per-feature contributions are a fully
  reconstructable trace. This is the deterministic baseline and the offline
  fallback.
- **`TriageAgent`** (optional `[agent]` extra): a real **ReAct agent**. Claude
  reasons over the evidence through read-only inspection tools
  (reason -> tool call -> observation, looped), then concludes with a calibrated
  `benign_likelihood`. The threshold-to-hold mapping is the *same* deterministic
  step the linear scorer uses, so the model supplies the judgement and the policy
  supplies the decision. If the SDK or an API key is missing, or any call fails,
  it falls back to `TriageScorer`, so the core stays pure-stdlib and CI needs no
  key.

The ReAct tools (`tools.py`) are all read-only views over evidence the framework
already produced: `list_findings`, `inspect_timestamps`, `inspect_setinfo`,
`check_trusted_actors`, and the terminal `conclude_triage`. No collection, no side
effects.

## The safety invariant

Triage can only make the responder **more** cautious. A hold downgrades a held
action to `ALERT`; it never raises one. So the worst failure is a missed
auto-response a human still sees in the alert, never an autonomous escalation an
LLM talked itself into. The dangerous metric is therefore the **false-benign
rate** (holding a real stomp), which is what to gate eval on.

This is enforced *where execution happens*. `gated_decide` passes the report into
`ResponsePolicy.decide(triage=...)`, which applies the cap **before** it computes
`executed` and before any executor runs. Capping only the returned decision after
`decide` would be unsafe with `dry_run` off: `decide` would already have executed
the un-capped action. Cap-before-execute is the load-bearing ordering. The
rationale and the capped decision both land in the tamper-evident ledger
(rationale first), so "why we backed off" is as auditable as "why we acted".

## Use

```python
from weeping_angel.triage import TriageAgent, gated_decide  # or TriageScorer

assessor = TriageAgent()                      # falls back to the linear scorer
report = assessor.assess(file_id, findings, display_mace, setinfo_events, trusted_actors)
decision = gated_decide(policy, file_id, findings, report)   # caps before executing, logs rationale
print(report.explain())
```

Swap `TriageAgent()` for `TriageScorer()` for the deterministic, dependency-free
path. The interface is identical.

## Features (linear scorer; all benign-positive)

`actor_trusted`, `no_groundtruth_clash` (no R4), `corroboration` (-),
`whole_second_si` (-), `rollback` (-). Fixed order; weights line up positionally,
like `learn._features`.

## Why a ReAct agent here

The triage gap is exactly the kind of small, evidence-bounded judgement an agent
is good at: a handful of read-only lookups and one calibrated probability. The
design keeps the LLM on a short leash by construction: it only *reads* evidence
and outputs a number, and the responder it feeds can only de-escalate. That makes
it a safe place to put an LLM agent inside an autonomous-response loop, which is
the point. The linear scorer stays as the deterministic floor: when the agent is
unavailable, mis-calibrated, or simply not wanted, the framework still triages.
