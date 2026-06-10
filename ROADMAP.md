# Roadmap

Where the project is, and what could come next. Items are grouped by theme, not
strict priority. Rough effort is noted as S/M/L.

## Done

- Six divergence rules (R1-R6), each tagged to MITRE ATT&CK T1070.006, with the
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
- Response / rules-of-engagement layer (`quantumlock/response.py`): findings to
  bounded actions, dry-run default, confidence gate, every decision logged to the
  tamper-evident ledger. (Priority 2)
- Go recorder (`recorder/`): out-of-band host collector that builds the same
  hash chain and shared JSONL ledger the Python detector reads; Go and Python
  compute byte-identical SHA-256 chains, verified both directions. (Priority 1)
- Terraform test range (`range/`): Docker-provider config that provisions a
  fleet of recorder containers, with a scenario harness that injects timestomps
  and scans the collected ledgers. (Priority 3)
- Findings exporter (`quantumlock/export.py`): renders findings as ECS or OCSF
  Detection Findings (with the ATT&CK mapping) for SIEM ingestion; the MFT
  adapter has a `--format ecs|ocsf` flag. (Priority 4)
- CI (ruff, mypy, bandit, pytest; plus go vet/test and terraform fmt/validate),
  security review (LOW-1/LOW-3 fixed).

## Near-term priorities

Ranked. Each closes a capability the framework currently only hand-waves.

### 1. Go recorder agent — DONE

Shipped as `recorder/` (see Done above): a Go collector with `watch` / `replay`
/ `verify` subcommands that builds the same hash chain and shared JSONL ledger
the Python detector reads. Cross-language hashing is verified both directions in
`tests/test_recorder_interop.py` and `recorder/ledger_test.go`. Remaining
follow-ups: swap the poll-based watcher for fsnotify, and let the Python
detector run rules directly on a recorder-produced ledger.

### 2. Response / rules-of-engagement layer — DONE

Shipped as `quantumlock/response.py` (see Done above): `ResponsePolicy` maps
findings to a bounded action under an RoE config, dry-run by default, gated on
corroboration-based confidence, with every decision appended to the
tamper-evident ledger.

### 3. Terraform range — DONE

Shipped as `range/` (see Done above): Docker-provider Terraform that builds the
recorder image and runs a fleet of endpoint containers, plus `scenario.py` which
injects a timestomp on each and scans the collected ledgers. `terraform
fmt`/`validate` run in CI. Follow-ups: a cloud-VM variant, and exercising it
against a live daemon in CI (validate-only today).

### 4. Platform integration: OCSF/ECS exporter — DONE

Shipped as `quantumlock/export.py` (see Done above): `ecs_event`, `ocsf_finding`,
and `to_jsonl` render findings (with the ATT&CK mapping) for SIEM ingestion; the
MFT adapter emits them with `--format ecs|ocsf`.

## Detection depth

- Validation matrix against real timestomping tools (Metasploit `timestomp`,
  SetMACE, nTimetools): capture artifacts, map each tool's signature to the rule
  that catches it. (M, needs a Windows lab)
- More rules: `$MFT` sequence-number anomalies, USN reason-flag correlation,
  `$LogFile`, registry/prefetch timestamps. (M)
- Export rules to more formats alongside Sigma: Splunk SPL, Elastic/KQL,
  Chronicle YARA-L. (S each)
- Confidence scoring / rule weighting so weak signals can combine. (M)

## Data and realism

- LOW-2 from the security review: stream large `$MFT` / CSV (mmap or chunked) so
  it scales to full disk images instead of loading whole files. (S)
- Real evidence pipeline: generate timestomped files in a Windows VM with real
  tools, collect real `$MFT`/`$FN`/USN, ship a sanitized real sample. (L)
- USN journal binary parser for `$Extend\$UsnJrnl:$J` (currently the journal is
  design-only / ledger-backed). (M)

## Output and UX

- Real CLI (typer/argparse): `weeping-angel scan <input> --format json|table`,
  exit codes, JSONL for SIEM ingestion. (S)
- Timeline visualization (matplotlib or HTML): forged vs true timeline with the
  divergence highlighted. One screenshot for the README/social preview. (M)

## Arena and competition

- JS/HTML renderer so the Kaggle notebook shows an animated replay
  (`html_renderer` is currently empty). (M)
- Deeper game: a staging-cost mechanic (an Angel must emit activity to "arm"
  before it can stomp), plus a Bayesian blue and a mixed-strategy red. (M)
- Hosted competition: contribute the env upstream to Kaggle/kaggle-environments
  and pitch it, or run a community code-competition with a fixed opponent pool. (L)
- A reinforcement-learning agent baseline. (M)

## Communication and distribution

- `docs/WRITEUP.md`: a blog-style explainer (what timestomping is, why
  `$SI`/`$FN`/USN diverge, a worked example through all six rules). (S)
- Publish the package to PyPI. (S)
- asciinema/GIF of the demo in the README. (S)

## Engineering

- Coverage reporting + badge. (S)
- Extend mypy/bandit to `kaggle/` and `tests/`, not just `quantumlock`. (S)

## Ideas parking lot

<!-- Drop new ideas here; we'll triage them into the sections above. -->
