# Detections: operational mapping

Each rule corresponds to a real artifact and real host telemetry, not just a
simulation. This directory makes that explicit so the rules drop into an
ATT&CK-aligned pipeline.

## ATT&CK

Every rule detects the same technique from a different vantage point:

- Tactic: [TA0005, Defense Evasion](https://attack.mitre.org/tactics/TA0005/)
- Technique: [T1070.006, Indicator Removal: Timestomp](https://attack.mitre.org/techniques/T1070/006/)

Findings from `weeping_angel.detector` carry `technique` and `tactic` fields set
to these ids.

## Rule to artifact to telemetry

| Rule | Artifact comparison | Data source |
|---|---|---|
| `R1_si_fn_birth_divergence` | `$SI.created` < `$FN.created` | `$MFT` parse (MFTECmd / analyzeMFT) |
| `R2_si_journal_rollback` | `$SI.modified` < true last write | USN journal (`$Extend\$UsnJrnl:$J`) |
| `R3_internal_ordering` | `$SI.modified` < `$SI.created` | `$SI` alone (GetFileTime) |
| `R4_setinfo_captured` | captured metadata-set contradicts truth | minifilter `IRP_MJ_SET_INFORMATION` / Sysmon EID 2 |
| `R5_future_timestamp` | `$SI` > now | `$SI` alone |
| `R6_subsecond_truncation` | `$SI` whole-second, `$FN`/USN fractional | `$MFT` + USN (100ns FILETIME precision) |

## Sigma

[`sigma/timestomp_si_fn_divergence.yml`](sigma/timestomp_si_fn_divergence.yml)
and [`sigma/timestomp_subsecond_zeroed.yml`](sigma/timestomp_subsecond_zeroed.yml)
target Sysmon Event ID 2 (`FileCreateTime` changed), the live telemetry for
timestomping. Both encode the same false-positive discipline as rule `R4`: a
`not filter_known_good` clause exempts archivers, backup, and copy tools that
legitimately rewrite timestamps.

## Splunk and Elastic

The same logic in two more query languages, for teams not on Sigma:

- [`splunk/timestomp.spl`](splunk/timestomp.spl) — SPL over Sysmon EID 2, with
  the creation-rollback and sub-second-zeroed checks.
- [`elastic/timestomp.eql`](elastic/timestomp.eql) — EQL (needed to compare two
  timestamp fields for the rollback check).

Both keep the known-good exclusions and need field-name tuning for your ingest.

## Sysmon

[`sysmon/timestomp.xml`](sysmon/timestomp.xml) turns on `FileCreateTime` (EID 2)
collection, which is off in many baseline configs. Merge it into your
`<RuleGroup>` set.
