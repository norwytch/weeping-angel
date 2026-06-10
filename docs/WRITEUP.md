# Catching an Angel: detecting timestomping malware that only acts when unobserved

This is the long-form explanation of what the repo does and why it works. The
[README](../README.md) is the tour; this is the argument.

## The problem: timestomping

Timestamps are load-bearing in a forensic investigation. The first thing a
responder does is build a timeline: what happened, in what order, and when.
Timestomping attacks that directly. The malware forges file timestamps so the
investigator cannot establish when anything happened, which collapses the
timeline that everything else hangs on. MITRE catalogs it as
[T1070.006](https://attack.mitre.org/techniques/T1070/006/), a Defense Evasion
technique.

On NTFS a file has more than one set of timestamps:

- **`$STANDARD_INFORMATION` (`$SI`)** is what Explorer and most tools display.
  It is writable from userland: `SetFileTime` changes it, and that is exactly
  what a classic timestomper does.
- **`$FILE_NAME` (`$FN`)** lives in the MFT and is set by the kernel on create
  and rename. Classic stompers leave it alone, so the `$SI`-vs-`$FN` comparison
  is the canonical timestomp tell.
- The **USN change journal** records the true time of every metadata and data
  operation, with a kernel timestamp.

A naive stomp only edits `$SI`. The defense compares `$SI` against `$FN` and the
journal: if a file's displayed creation time predates the kernel-set birth, or
its displayed modified time predates the journal's true last write, something
forged it.

## The harder case: the Weeping Angel

The interesting adversary does not just stomp. It gates its action on whether it
believes it is being watched. It checks for in-band observers (Procmon, EDR,
open handles, a debugger) and only stomps when it concludes no one is looking.
In Doctor Who terms it is a Weeping Angel: it can only move when unobserved, and
the instant you look at it, it freezes.

Two things make this hard:

1. You cannot reliably catch it in the act from inside the system, because it is
   specifically checking for in-band observers before it moves.
2. A capable stomp is *internally consistent*. It sets created before modified
   and picks a plausible old date, so single-source heuristics (modified before
   created, a future timestamp) miss it entirely.

## The defense: three pillars

The framework rests on three ideas. None is novel alone; the point is how they
compose.

**1. Out-of-band observation.** The malware enumerates in-band observers, so
watch it from a layer it cannot enumerate: a kernel minifilter below the level
userland inspects, or a hypervisor watching the guest from outside. Its
precondition for acting ("unobserved") is then permanently false in reality
while it still reads as true to the malware. The one moment it is willing to act
becomes the moment it is most completely recorded.

This reframes the Doctor Who "temporal paradox." In the show the paradox is
mechanical: you trap the Angel in a physical contradiction. On a computer that
would mean destabilizing the OS. The translation that costs nothing is
*epistemic*: decouple the malware's belief about being observed from the reality
of it. `quantumlock/paradox.py` formalizes this as a tiny state machine and
proves that, under a fixed out-of-band-observation invariant, the unsafe state
"acted but was not recorded" is unreachable.

**2. Multi-witness divergence.** Keep several independent timestamp sources that
must agree if nothing forged anything. No single witness catches the Angel; their
disagreement does. `quantumlock/detector.py` runs seven rules, each citing the
witnesses whose disagreement triggered it:

| Rule | Catches |
|---|---|
| R1 | displayed creation predates the kernel-set `$FN` birth |
| R2 | displayed modified predates the journal's true last write |
| R3 | modified precedes its own creation (impossible) |
| R4 | a captured metadata-set op writes a value that contradicts ground truth |
| R5 | a timestamp in the future |
| R6 | `$SI` zeroed to whole seconds while a witness keeps 100ns precision |
| R7 | displayed modified predates the kernel-set `$FN` modified |

R6 is worth a note: many `SetFileTime`-based tools truncate sub-second
precision, so a creation time of exactly `...000` next to a `$FN`/USN value with
real 100-nanosecond ticks is a high-confidence tell.

**3. Tamper-evident ledger.** The out-of-band record is a forward hash-chained,
append-only log: every record commits to its predecessor, so editing the past
breaks the chain (`quantumlock/ledger.py`). The remaining gap is dropping the
tail, which leaves a shorter but self-consistent chain; `quantumlock/anchor.py`
closes it with HMAC-authenticated off-box checkpoints, so a dropped tail shows up
as "the anchored head is ahead of what's on disk."

## Where the metaphor breaks

Being honest about the limits is the point, not a footnote.

- A sophisticated sample need not use a clean observed/unobserved binary. It may
  stomp probabilistically or on a timer, so there is no single blink to exploit.
  The defense therefore assumes it acts and relies on indelible recording, not on
  freezing it.
- Freezing it with fake observers (a decoy Procmon process) is on-theme but
  brittle: it depends on enumerating its exact checks, and authors adapt.
- Tamper-evidence protects the recorded past; it cannot reconstruct a value the
  recorder never saw. Coverage of the out-of-band recorder is the real security
  boundary.
- Setting an old timestamp is not inherently malicious. Archivers, restore,
  `cp -p`, and `rsync -t` all do it. So R4 fires only when a captured `setinfo`
  contradicts out-of-band ground truth, and exempts an allowlist of
  known-legitimate setters. The value alone is ambiguous; corroboration plus
  known-good baselining is the fix.

## From detection to response

A detector that only emits findings is half a system. `quantumlock/response.py`
adds a rules-of-engagement layer: a finding maps to a bounded action (alert,
ticket, quarantine, isolate), gated on a confidence that rises with
corroboration, dry-run by default, with every decision appended to the same
tamper-evident ledger. The three guardrails that make autonomous response
deployable rather than reckless are all there: a safe default, a confidence
gate, and an auditable trail.

## How it is built

The repo is deliberately multi-language and split between working code and
design-only documentation.

- Detection, the ledger, the response layer, the simulator, and the offline
  adapters are working, tested Python.
- The out-of-band **recorder** is Go (`recorder/`), because a host collector is
  what Go is for: a single static binary. It writes the same JSONL ledger the
  Python detector reads, and the two compute byte-identical SHA-256 chains
  (verified cross-language). The shared hash preimage is canonical, key-sorted
  JSON over integer-nanosecond timestamps, chosen specifically so Go's encoder
  and Python's `json.dumps` emit the same bytes.
- A Terraform range (`range/`) provisions a fleet of recorder containers and
  injects timestomp scenarios, exercising the whole pipeline end to end.
- Findings export to ECS and OCSF for SIEM ingestion (`quantumlock/export.py`),
  and ship as Sigma/Sysmon detections.
- The minifilter, hypervisor/VMI vantage point, and live USN collection are
  design-only, with the real data source for each witness documented in
  `quantumlock/adapters/windows.py` and `docs/DESIGN.md`.

## The one honest line about "quantum"

The package is called `quantumlock` and the framing borrows "quantum locked"
from the show. Nothing in the mechanism is quantum. "Observation" here is an
epistemic check (the malware testing whether a monitor is present), not a
physical measurement. The name is a wink, and the README says so plainly.
