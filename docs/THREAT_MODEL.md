# Threat model

## Adversary

Anti-forensic malware running with userland privileges, and in the strongest
case able to attempt log scrubbing. Its goal is to corrupt the forensic timeline
by forging file timestamps so an investigator cannot establish when something
happened. It gates its action on a self-report of being observed: it checks for
monitoring and stomps only when it concludes no one is watching. That gating is
why it is modeled as a Weeping Angel.

## Adversary capabilities (assumed)

- Read and write `$STANDARD_INFORMATION` timestamps (`SetFileTime`).
- Enumerate in-band observers: running processes (Procmon/EDR), open handles on
  its target, an attached debugger.
- Attempt to tamper with on-disk logs it can reach.

## Adversary limitations (relied upon)

- Cannot enumerate or reach an out-of-band recorder (kernel minifilter / VMI).
- Cannot silently edit an interior ledger record without breaking the hash chain.
- Cannot rewrite an externally anchored ledger head.

If any of these fails, the corresponding guarantee degrades. See "Where the
metaphor breaks" in the README and "Anchoring the ledger head" in `DESIGN.md`.

## What is protected

- Integrity of the recorded timeline. Any post-hoc edit to recorded history is
  detectable (`Ledger.verify`).
- Detectability of forgery. A stomp that contradicts any unreachable witness is
  flagged, even when it is internally consistent.

## What is not protected

- Values the recorder never saw. Tamper-evidence cannot reconstruct truth the
  out-of-band collector failed to observe; recorder coverage is the real
  boundary.
- Pre-deployment activity. Anything before the recorder was in place is out of
  scope.
- Availability. The framework detects and attributes; it does not block the
  write, by design, because the goal is to record the act.
