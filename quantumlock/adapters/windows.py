"""Real-world adapters (DESIGN-ONLY).

These map each abstract witness onto a concrete Windows/NTFS artifact. They are
intentionally not executable in this repo -- they require a Windows host, kernel
access, and a privileged collector -- but the docstrings record exactly where
the real timestamps come from so the simulated witnesses are not hand-waving.

  DisplayWitness  -> $STANDARD_INFORMATION
      Source: GetFileTime / NtQueryInformationFile (FileBasicInformation).
      This is what Explorer shows and what classic stompers (e.g. the
      Metasploit `timestomp` command, SetFileTime-based tools) rewrite.

  MFTWitness      -> $FILE_NAME
      Source: parse the MFT ($MFT) and read the $FN attribute timestamps,
      which the kernel sets on create/rename and which classic stompers leave
      untouched. Tools: analyzeMFT, MFTECmd. The $SI-vs-$FN comparison is the
      canonical timestomp tell.

  JournalWitness  -> USN change journal ($Extend\\$UsnJrnl:$J) + external log
      Source: FSCTL_QUERY_USN_JOURNAL / FSCTL_READ_USN_JOURNAL. Every metadata
      and data change emits a USN record with a kernel timestamp. For tamper-
      evidence beyond what the journal alone provides, a minifilter mirrors
      events into an append-only hash-chained log shipped off-box.

Out-of-band vantage points (so the malware cannot enumerate the observer):
  * Minifilter driver (FltRegisterFilter) intercepting IRP_MJ_SET_INFORMATION
    below the level userland inspects.
  * Hypervisor / VMI (e.g. LibVMI) observing the guest from outside -- the
    closest analog to "looking at it from outside time."
"""

from __future__ import annotations

from ..witnesses import MACE, Witness


class _DesignOnly(Witness):
    name = "design-only"

    def observe(self, file_id: str) -> MACE | None:  # pragma: no cover
        raise NotImplementedError(
            "Design-only adapter: requires a Windows host with privileged "
            "collection. See module docstring for the real data sources."
        )


class WindowsStandardInfoWitness(_DesignOnly):
    name = "windows.$SI"


class WindowsFileNameWitness(_DesignOnly):
    name = "windows.$FN"


class WindowsUsnJournalWitness(_DesignOnly):
    name = "windows.USN"
