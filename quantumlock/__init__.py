"""quantumlock -- defeating timestomping malware that acts only when unobserved.

A Weeping Angel only moves when no one is watching. This package defeats the
software analog -- malware that timestomps only when it believes it is
unobserved -- by observing from a vantage point it cannot enumerate, so the only
moment it can act is the moment it is most completely recorded.
"""

from .anchor import Anchor, AnchorVerifyResult, Checkpoint
from .detector import DivergenceDetector, Finding
from .export import ecs_event, ocsf_finding, to_jsonl
from .ledger import Ledger, Record, VerifyResult
from .paradox import Outcome, ParadoxProof, WorldState, prove_no_paradox_free_move, step
from .response import Action, ResponseDecision, ResponsePolicy, RulesOfEngagement, confidence
from .simulator import AdvancedAngel, Angel, FileSystemSim, ObservationOracle
from .timeline import Marker, divergence_svg, render_timeline
from .witnesses import MACE, DisplayWitness, JournalWitness, MFTWitness, Witness

__all__ = [
    "Ledger",
    "Record",
    "VerifyResult",
    "Anchor",
    "AnchorVerifyResult",
    "Checkpoint",
    "MACE",
    "Witness",
    "DisplayWitness",
    "MFTWitness",
    "JournalWitness",
    "DivergenceDetector",
    "Finding",
    "Outcome",
    "WorldState",
    "ParadoxProof",
    "step",
    "prove_no_paradox_free_move",
    "FileSystemSim",
    "ObservationOracle",
    "Angel",
    "AdvancedAngel",
    "Action",
    "RulesOfEngagement",
    "ResponsePolicy",
    "ResponseDecision",
    "confidence",
    "ecs_event",
    "ocsf_finding",
    "to_jsonl",
    "Marker",
    "render_timeline",
    "divergence_svg",
]
__version__ = "0.1.0"
