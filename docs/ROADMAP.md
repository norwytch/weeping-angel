# Roadmap

Where the project is, and what could come next. Items are grouped by theme, not
strict priority. Rough effort is noted as S/M/L.

## Done

- Seven divergence rules (R1-R7), each tagged to MITRE ATT&CK T1070.006, with the
  R4 false-positive fix (ground-truth contradiction + trusted-actor allowlist).
- Raw NTFS `$MFT` binary parser (FILE records, USA fixups, FILETIME) and an
  MFTECmd-CSV adapter.
- Tamper-evident hash-chained ledger plus an HMAC-authenticated off-box head
  anchor (closes tail-truncation).
- Epistemic-paradox state machine with an unreachability proof.
- Deterministic simulator, efficacy harness (precision/recall), Hypothesis
  property tests.
- Sigma rules + Sysmon config (Event ID 2).
- Adversarial arena (Angels vs recorder) with baseline and inference agents,
  packaged as a kaggle-environments sim and published as a Kaggle notebook.
- Response / rules-of-engagement layer (`weeping_angel/response.py`): findings to
  bounded actions, dry-run default, confidence gate, every decision logged to the
  tamper-evident ledger *before* it executes (cap-before-execute, so a held or
  failed action can never have unrecorded side effects). (Priority 2)
- Content-aware triage (`weeping_angel/triage/`): reads the evidence behind a
  finding (who set the time, which direction, how round) and can only ever
  *de-escalate* the responder. Two assessors behind one interface: a transparent
  linear scorer (pure stdlib, the default and offline fallback) and an optional
  Claude ReAct agent (`TriageAgent`, reason -> tool -> observe loop over read-only
  evidence tools, `[agent]` extra) that falls back to the scorer with no key.
- Go recorder (`recorder/`): out-of-band host collector that builds the same
  hash chain and shared JSONL ledger the Python detector reads; Go and Python
  compute byte-identical SHA-256 chains, verified both directions. (Priority 1)
- Terraform test range (`range/`): Docker-provider config that provisions a
  fleet of recorder containers, with a scenario harness that injects timestomps
  and scans the collected ledgers. (Priority 3)
- Findings exporter (`weeping_angel/export.py`): renders findings as ECS or OCSF
  Detection Findings (with the ATT&CK mapping) for SIEM ingestion; the MFT
  adapter has a `--format ecs|ocsf` flag. (Priority 4)
- CI (ruff, mypy, bandit, pytest; plus go vet/test and terraform fmt/validate),
  full-repo security reviews (response executor ordering and 0600 ledger
  permissions fixed; the LLM triage agent reviewed and bounded by the
  downgrade-only invariant).
- USN journal binary parser (`weeping_angel/adapters/usn.py`): parses
  `$Extend\$UsnJrnl:$J` (USN_RECORD_V2, reason flags, FILETIME), maps it onto the
  ledger so R2 runs on a real journal; `scan_with_usn` combines MFT + USN.
- Rule R7 (`$SI` modified predates the kernel-set `$FN` modified), the canonical
  `$SI`-vs-`$FN` tell extended to the modified field; the MFT/CSV parsers now
  read `$FN` modified. Seven rules total.
- Deeper arena: an opt-in staging-cost mechanic (`arm_ticks`), a Bayesian
  (Thompson-sampling) blue, and a persistent mixed-strategy red.
- Polish batch: `docs/WRITEUP.md` explainer; a unified `weeping-angel` CLI
  (`weeping_angel/cli.py`, console entry point); an SVG timeline visualization
  (`weeping_angel/timeline.py`, embedded in the README); Splunk SPL + Elastic EQL
  rule exports; memory-mapped streaming for large `$MFT`/CSV (LOW-2); coverage
  reporting in CI (93%); packaging metadata for PyPI.

## Near-term priorities

Ranked. Each closes a capability the framework currently only hand-waves.

### 1. Go recorder agent - DONE

Shipped as `recorder/` (see Done above): a Go collector with `watch` / `replay`
/ `verify` subcommands that builds the same hash chain and shared JSONL ledger
the Python detector reads. Cross-language hashing is verified both directions in
`tests/test_recorder_interop.py` and `recorder/ledger_test.go`. Remaining
follow-ups: swap the poll-based watcher for fsnotify, and let the Python
detector run rules directly on a recorder-produced ledger.

### 2. Response / rules-of-engagement layer - DONE

Shipped as `weeping_angel/response.py` (see Done above): `ResponsePolicy` maps
findings to a bounded action under an RoE config, dry-run by default, gated on
corroboration-based confidence, with every decision appended to the
tamper-evident ledger.

### 3. Terraform range - DONE

Shipped as `range/` (see Done above): Docker-provider Terraform that builds the
recorder image and runs a fleet of endpoint containers, plus `scenario.py` which
injects a timestomp on each and scans the collected ledgers. `terraform
fmt`/`validate` run in CI. Follow-ups: a cloud-VM variant, and exercising it
against a live daemon in CI (validate-only today).

### 4. Platform integration: OCSF/ECS exporter - DONE

Shipped as `weeping_angel/export.py` (see Done above): `ecs_event`, `ocsf_finding`,
and `to_jsonl` render findings (with the ATT&CK mapping) for SIEM ingestion; the
MFT adapter emits them with `--format ecs|ocsf`.

## Detection depth

- Validation matrix against real timestomping tools (Metasploit `timestomp`,
  SetMACE, nTimetools): capture artifacts, map each tool's signature to the rule
  that catches it. (M, needs a Windows lab)
- More rules still open: `$MFT` sequence-number anomalies, `$LogFile`,
  registry/prefetch timestamps. (M)
- Confidence scoring already lands in `response.py`; rule-level weighting (some
  rules count more than others toward confidence) is still open. (M)
- DONE: rule R7; Splunk SPL + Elastic EQL exports; USN reason-flag correlation
  (content vs metadata classification). Chronicle YARA-L still open.

## Data and realism

- Real evidence pipeline: the step-by-step lab guide is written
  (`docs/LAB.md`) -- timestomp with real tools, collect `$MFT`/USN, run the
  detector, build the validation matrix. Still to execute on a Windows VM and
  ship a sanitized real sample + filled-in matrix. (L, needs a Windows lab)
- Live USN collection (real-time `FSCTL_READ_USN_JOURNAL`) is still design-only;
  the offline `$J` binary parser is done. (M)
- DONE: USN journal binary parser; LOW-2 memory-mapped streaming for `$MFT`/CSV.

## Arena and competition

- JS/HTML renderer so the Kaggle notebook shows an animated replay
  (`html_renderer` is currently empty). (M)
- Hosted competition: the merge-ready env package and the contribution + pitch
  guide are in `kaggle/contrib/` (upstream layout: spec JSON, agents, tests, JS
  renderer). Remaining work is opening the PR to Kaggle/kaggle-environments and
  pitching them to host it -- gated on their interest. (L)
- DONE: staging-cost mechanic, Bayesian (Thompson-sampling) blue, mixed-strategy
  persistent red. In the `weeping_angel` arena the mechanic is opt-in (`arm_ticks`,
  default off); the published Kaggle env turns it on by default (`armTicks=3`) so
  the hosted competition is the deep game.
- DONE: a learned agent baseline (`weeping_angel/learn.py`) -- a linear coverage
  policy trained by Evolution Strategies, pure stdlib (no deep-learning deps). It
  beats random and matches the hand-tuned inference agent, and proves the arena is
  a learnable environment (reward improves over generations).

## Communication and distribution

- Publish the package to PyPI (metadata is ready; needs an account token). (S)
- asciinema/GIF of the demo in the README (record locally). (S)
- DONE: `docs/WRITEUP.md` explainer; unified `weeping-angel` CLI.

## Engineering

- Live coverage badge (needs a Codecov/Coveralls account; reporting is in CI). (S)
- Extend mypy to `tests/` (noisy; deferred). bandit now also scans `examples/`. (S)
- DONE: coverage reporting in CI; SVG timeline visualization.

## Ideas parking lot

<!-- Drop new ideas here; we'll triage them into the sections above. -->
