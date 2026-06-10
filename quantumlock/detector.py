"""Multi-witness divergence detection.

Each rule is independently motivated and cites the witnesses whose disagreement
triggered it. A single internally-consistent forgery can pass any one heuristic;
the point of the framework is that it cannot satisfy *all* witnesses at once,
because some of them sit where the Angel cannot reach.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .witnesses import DisplayWitness, JournalWitness, MFTWitness

EPSILON = 1e-9

# MITRE ATT&CK mapping. Every rule here detects the same technique seen from a
# different artifact; surfacing the technique id lets findings flow straight
# into ATT&CK-aligned detection pipelines and dashboards.
#   Tactic:    TA0005  Defense Evasion
#   Technique: T1070.006  Indicator Removal: Timestomp
ATTACK_TACTIC = "TA0005"  # Defense Evasion
ATTACK_TECHNIQUE = "T1070.006"  # Indicator Removal: Timestomp


def _whole_second(v: float | None) -> bool:
    """True if ``v`` carries no sub-second (100ns FILETIME) component."""
    return v is not None and abs(v - round(v)) <= EPSILON


def _has_subsecond(v: float | None) -> bool:
    return v is not None and abs(v - round(v)) > EPSILON


@dataclass
class Finding:
    file_id: str
    rule: str
    severity: str  # "high" | "medium"
    explanation: str
    witnesses: tuple[str, ...]
    evidence: dict = field(default_factory=dict)
    technique: str = ATTACK_TECHNIQUE
    tactic: str = ATTACK_TACTIC


class DivergenceDetector:
    def __init__(
        self,
        display: DisplayWitness,
        mft: MFTWitness,
        journal: JournalWitness,
        now: float | None = None,
        trusted_setinfo_actors: set[str] | None = None,
    ) -> None:
        self.display = display
        self.mft = mft
        self.journal = journal
        self.now = now
        # Tools whose legitimate function is to write non-"now" timestamps
        # (archivers, restore/backup, `cp -p`, `rsync -t`). A captured setinfo
        # from one of these is expected, not anti-forensic, so it is exempt
        # from R4. In production these are matched on the recorder-supplied
        # acting image path / signer, not a userland-spoofable name.
        self.trusted_setinfo_actors = trusted_setinfo_actors or set()

    def scan(self, file_id: str) -> list[Finding]:
        findings: list[Finding] = []
        d = self.display.observe(file_id)
        f = self.mft.observe(file_id)
        j = self.journal.observe(file_id)

        # R1 -- birth divergence ($SI created earlier than the kernel's $FN birth)
        if d and f and d.created is not None and f.created is not None:
            if d.created < f.created - EPSILON:
                findings.append(
                    Finding(
                        file_id,
                        "R1_si_fn_birth_divergence",
                        "high",
                        "Displayed creation time predates the kernel-set MFT birth "
                        "time; a file cannot exist before the kernel created it.",
                        (self.display.name, self.mft.name),
                        {"display_created": d.created, "mft_created": f.created},
                    )
                )

        # R7 -- $SI modified earlier than the kernel-set $FN modified. Classic
        # stompers rewrite $SI but leave the $FN timestamps, so a displayed
        # modified far older than $FN's modified is the same tell as R1, applied
        # to the modified field rather than birth.
        if d and f and d.modified is not None and f.modified is not None:
            if d.modified < f.modified - EPSILON:
                findings.append(
                    Finding(
                        file_id,
                        "R7_si_fn_modified_divergence",
                        "high",
                        "Displayed modified time predates the kernel-set $FN modified "
                        "time, which classic stompers leave untouched.",
                        (self.display.name, self.mft.name),
                        {"display_modified": d.modified, "fn_modified": f.modified},
                    )
                )

        # R2 -- modified rollback ($SI modified earlier than the journal's true write)
        if d and j and d.modified is not None and j.modified is not None:
            if d.modified < j.modified - EPSILON:
                findings.append(
                    Finding(
                        file_id,
                        "R2_si_journal_rollback",
                        "high",
                        "Displayed modified time is earlier than the last content "
                        "write recorded out-of-band by the journal.",
                        (self.display.name, self.journal.name),
                        {"display_modified": d.modified, "journal_modified": j.modified},
                    )
                )

        # R3 -- internal ordering impossibility (modified before created)
        if d and d.modified is not None and d.created is not None:
            if d.modified < d.created - EPSILON:
                findings.append(
                    Finding(
                        file_id,
                        "R3_internal_ordering",
                        "medium",
                        "Displayed modified time precedes its own creation time.",
                        (self.display.name,),
                        {"display_modified": d.modified, "display_created": d.created},
                    )
                )

        # R4 -- the act of stomping, captured by the out-of-band recorder.
        #
        # A metadata-set op writing a value != the real op time is NOT, on its
        # own, evidence of forgery: archivers, restore/backup, `cp -p`, and
        # `rsync -t` all legitimately set old timestamps. We flag a captured
        # setinfo only when its written value *contradicts independently
        # recorded ground truth* -- it predates the kernel-set $FN birth, rolls
        # the modified time back before the journal's true last content write,
        # or lands in the future. That contradiction is what no benign tool
        # produces and no internally-consistent lie can avoid, because the
        # ground truth sits where the Angel cannot reach. Known-legitimate
        # actors are exempt entirely (see ``trusted_setinfo_actors``).
        for ev in self.journal.setinfo_events(file_id):
            actor = ev.get("actor")
            if actor is not None and actor in self.trusted_setinfo_actors:
                continue
            wm = ev.get("written_modified")
            wc = ev.get("written_created")
            real = ev.get("real_time")
            reasons: list[str] = []
            if wm is not None:
                if j and j.modified is not None and wm < j.modified - EPSILON:
                    reasons.append("rolls the modified time back before the true last write")
                if self.now is not None and wm > self.now + EPSILON:
                    reasons.append("sets the modified time in the future")
            if wc is not None:
                if f and f.created is not None and wc < f.created - EPSILON:
                    reasons.append("sets the created time before the kernel-set birth")
                if self.now is not None and wc > self.now + EPSILON:
                    reasons.append("sets the created time in the future")
            if reasons:
                findings.append(
                    Finding(
                        file_id,
                        "R4_setinfo_captured",
                        "high",
                        "A metadata-set operation was observed writing a timestamp that "
                        "contradicts ground truth recorded out-of-band (" + "; ".join(reasons)
                        + ") -- the forgery caught in the act.",
                        (self.journal.name,),
                        {
                            "written_modified": wm,
                            "written_created": wc,
                            "real_time": real,
                            "true_modified": j.modified if j else None,
                            "mft_birth": f.created if f else None,
                        },
                    )
                )

        # R5 -- timestamp in the future
        if self.now is not None and d:
            for label, val in (("modified", d.modified), ("created", d.created)):
                if val is not None and val > self.now + EPSILON:
                    findings.append(
                        Finding(
                            file_id,
                            "R5_future_timestamp",
                            "medium",
                            f"Displayed {label} time is in the future.",
                            (self.display.name,),
                            {label: val, "now": self.now},
                        )
                    )

        # R6 -- sub-second precision stripped. NTFS stores timestamps as 100ns
        # FILETIME ticks. SetFileTime-based stompers (Metasploit `timestomp`,
        # older SetMACE) write whole-second $SI values, zeroing the sub-second
        # ticks the kernel-set $FN and the USN journal still carry. Whole-second
        # $SI next to a fractional, independently-recorded witness is the
        # canonical "nanoseconds zeroed" tell.
        if d:
            si_vals = [v for v in (d.modified, d.created) if v is not None]
            cross = []
            if f and f.created is not None:
                cross.append(f.created)
            if j:
                cross.extend(v for v in (j.created, j.modified) if v is not None)
            if si_vals and all(_whole_second(v) for v in si_vals) and any(
                _has_subsecond(v) for v in cross
            ):
                findings.append(
                    Finding(
                        file_id,
                        "R6_subsecond_truncation",
                        "medium",
                        "Displayed timestamps are zeroed to whole seconds while an "
                        "independent witness retains 100ns precision -- the signature "
                        "of a SetFileTime-based timestomp.",
                        (self.display.name, self.mft.name, self.journal.name),
                        {
                            "display": {"modified": d.modified, "created": d.created},
                            "subsecond_witness_values": cross,
                        },
                    )
                )

        return findings

    def scan_all(self, file_ids) -> dict[str, list[Finding]]:
        return {fid: self.scan(fid) for fid in file_ids}
