# Design: out-of-band collection and anchoring

How the abstract witnesses map onto real Windows/NTFS artifacts, where the
recorder stands so the malware cannot see it, and how the ledger head is
anchored. These parts are design-only in this repo.

## Witness to artifact

| Witness | Artifact | Source API | Notes |
|---|---|---|---|
| `DisplayWitness` | `$STANDARD_INFORMATION` | `GetFileTime`, `NtQueryInformationFile(FileBasicInformation)` | What Explorer shows and what classic stompers rewrite. |
| `MFTWitness` | `$FILE_NAME` | Parse `$MFT`; read `$FN` timestamps (MFTECmd, analyzeMFT) | Kernel-set on create/rename, untouched by classic stompers. The `$SI` vs `$FN` comparison is the canonical timestomp tell. |
| `JournalWitness` | USN change journal + external log | `FSCTL_QUERY_USN_JOURNAL`, `FSCTL_READ_USN_JOURNAL` | Every change emits a USN record with a kernel timestamp. |

## The out-of-band vantage point

The malware enumerates in-band observers, so the recorder must sit where that
enumeration cannot reach:

- Minifilter driver (`FltRegisterFilter`) intercepting `IRP_MJ_SET_INFORMATION`
  (and create/write) below the level userland inspects, mirroring each relevant
  op into the append-only ledger. A USN-only approach is cheaper, but the
  minifilter also captures the attempted `setinfo` value (rule `R4`).
- Hypervisor/VMI (e.g. LibVMI) observing the guest from outside. Strongest
  isolation, highest cost.

The invariant the framework maintains (`paradox.py`): `actually_observed` is
always true because of this vantage point, while the malware's
`believes_observed` follows only its in-band checks. That gap is the exploit.

## Anchoring the ledger head

The hash chain makes any edit to an interior record detectable, since a later
record's `prev_hash` stops matching. The remaining gap is truncation of the
tail: dropping the most recent records leaves a shorter but self-consistent
chain. Close it by anchoring the head out of the attacker's reach, either by
shipping the head hash off-box to a collector the malware cannot write to, or by
committing the head to write-once storage or a transparency log on a cadence. A
dropped tail then shows up as "the anchored head is ahead of what's on disk."

This is implemented in [`quantumlock/anchor.py`](../quantumlock/anchor.py).
`Anchor.checkpoint()` pins `(length, head_hash)` under an HMAC keyed with a
secret the in-guest attacker never holds, standing in for an ed25519
transparency-log signature and verified with `hmac.compare_digest`.
`Anchor.verify()` flags tail-truncation (on-disk length behind an anchored
checkpoint) and interior rewrites (anchored head at a given length no longer
matching), neither of which `Ledger.verify()` catches once the tail is gone.

## Cost and placement trade-offs

| Vantage | Isolation from malware | Captures the act? | Cost |
|---|---|---|---|
| USN journal only | Medium | Partial (sees the change, not always the attempted value) | Low |
| Minifilter | High | Yes (`setinfo` value captured) | Medium |
| Hypervisor/VMI | Very high | Yes | High |

A practical deployment pairs a minifilter recorder with off-box head anchoring,
reserving VMI for high-value analysis hosts.
