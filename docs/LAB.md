# Lab guide: detecting real timestomps on real NTFS evidence

Everything in the repo so far runs on synthetic (but format-accurate) samples.
This guide takes the last step: timestomp real files on a real NTFS volume with
real tools, collect the `$MFT` and USN journal, and run the detector on them. It
also produces the validation matrix (which tool trips which rule) and, optionally,
a sanitized real sample to ship with the repo.

## Safety and scope

- Do this in an **isolated Windows VM** you own, on **files you create**. Snapshot
  first so you can roll back.
- Timestomping tools are dual-use. Only run them in authorized testing on your own
  lab. Do not run actual malware; the PowerShell and standalone tools below are
  benign timestamp setters, not malware.
- Real disk artifacts can contain personal data. If you ship a sample, sanitize it
  (see the last section).

## 1. Build the lab

1. A Windows 10/11 VM (VirtualBox, VMware, Hyper-V). Host-only / no network.
2. Take a clean snapshot.
3. Install the collection tools (copy them in; keep the VM offline):
   - **Eric Zimmerman's MFTECmd** (parses `$MFT` to CSV).
   - **FTK Imager** (exports locked system files like `$MFT` and the USN journal).
   - Optional offense tools for the matrix: **SetMACE**, **nTimetools**, or
     Metasploit's standalone `timestomp`.

## 2. Make sure the USN journal is on

The change journal is usually enabled on `C:`. Confirm, and enable if needed
(run as Administrator):

```bat
fsutil usn queryjournal C:
fsutil usn createjournal m=0x2000000 a=0x100000 C:   :: only if queryjournal says it's off
```

## 3. Create baseline files (the ground truth)

```powershell
mkdir C:\lab
"quarterly report" | Out-File C:\lab\report.docx
"staging payload"  | Out-File C:\lab\evil.exe
Get-Item C:\lab\*.* | Select Name, CreationTime, LastWriteTime
```

Note the true times. The kernel has now written `$SI`, `$FN`, and USN records for
each create/write.

## 4. Timestomp with real tools

**Built-in (no install): PowerShell calls `SetFileTime`,** which rewrites `$SI`
only and zeroes sub-second precision -- the classic stomp:

```powershell
$f = Get-Item C:\lab\evil.exe
$f.CreationTime   = '2019-01-01 00:00:00'
$f.LastWriteTime  = '2019-01-01 00:00:00'
$f.LastAccessTime = '2019-01-01 00:00:00'
```

This should trip **R1** (`$SI` created < `$FN` birth), **R7** (`$SI` modified <
`$FN` modified), and **R6** (sub-seconds zeroed) once you scan.

**Advanced: a tool that also rewrites `$FN`.** SetMACE (and similar) can forge the
`$FN` timestamps too, defeating the `$SI`-vs-`$FN` comparison. Run one against a
second file. The `$MFT` rules (R1/R7) now go quiet -- which is the whole point of
the out-of-band journal: the USN still recorded the real write time and the
`BASIC_INFO_CHANGE`, so **R2** catches it where R1/R7 cannot. (See the tool's own
README for exact flags; they change between versions.)

## 5. Collect the artifacts

Both `$MFT` and the journal are locked system files, so export them with FTK
Imager (File menu, add the logical `C:` drive, then export):

- `C:\$MFT`
- `C:\$Extend\$UsnJrnl:$J`

That gives you the raw binaries the repo's parsers read directly. (Alternatively,
`MFTECmd -f "C:\$MFT" --csv out --csvf mft.csv` produces a CSV for the
`mft_csv` adapter; the USN parser wants the raw `$J`.)

## 6. Run the detector

Copy the exported `$MFT` and `$J` to a machine with the repo installed:

```bash
# raw $MFT -> the binary parser, human or SIEM output
weeping-angel scan ./\$MFT
python -m weeping_angel.adapters.mft ./\$MFT --format ocsf

# combine $MFT ($SI/$FN) with the USN journal so R2 runs on the real timeline
python -c "from weeping_angel.adapters.usn import scan_with_usn; \
import json; print({k:[f.rule for f in v] for k,v in scan_with_usn('./\$MFT','./\$J').items() if v})"

# MFTECmd CSV instead of the raw $MFT
python -m weeping_angel.adapters.mft_csv ./mft.csv
```

Confirm `evil.exe` is flagged and your untouched files are clean.

## 7. Build the validation matrix

Record which tool tripped which rule. This is the credibility artifact: it shows
the detector catches real tools, and shows the design trade-off (simple stomps die
to the `$MFT` rules; `$FN`-aware tools need the journal).

| Tool | Touches | Expected rules |
|---|---|---|
| PowerShell `SetFileTime` | `$SI` only, sub-seconds zeroed | R1, R6, R7 |
| Metasploit `timestomp` | `$SI` only | R1, R7 |
| SetMACE (full) | `$SI` and `$FN` | R2 (via USN); R1/R7 evaded |

Fill the matrix from your actual runs (versions vary), and note any tool that
evades everything offline -- that is the case for the minifilter/live capture
(R4), which is design-only here.

## 8. Sanitize and ship a sample (optional)

A real, redacted artifact is a strong addition to the repo. Carve a tiny subset
rather than shipping a whole `$MFT`/`$J`:

- Keep only the records for your lab files, drop everything else.
- Rename paths to neutral names, zero out owner SIDs and any personal fields.
- Re-verify it still parses and flags as expected, then commit it next to
  `examples/data/sample.mft` with a note that it is sanitized real evidence.

Do not commit a full `$MFT`/`$J` from a real machine; they are large and contain
the whole filesystem's metadata.
