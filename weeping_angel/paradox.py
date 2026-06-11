"""The epistemic paradox, formalized.

In the show the paradox is *mechanical* -- the Angel is trapped in a physical
contradiction. On a computer that would mean destabilizing the OS, which we do
not want. The translation that costs the system nothing is *epistemic*: we
decouple the Angel's **belief** about being observed from the **reality** of
being observed.

State of the world:
    believes_observed : what the Angel concludes from in-band checks
    actually_observed : whether an out-of-band witness is, in fact, watching

Angel behavior (its only rule):
    it ACTS iff it believes it is unobserved.

The framework maintains the invariant ``actually_observed == True`` by watching
from a layer the Angel cannot enumerate. Under that invariant the unsafe state
"acted but was not recorded" is unreachable: every move is a recorded move.
That impossibility is the paradox -- the only moment the Angel can act is the
moment it is most completely seen.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Outcome(Enum):
    STONE = "stone"  # believed observed -> frozen, harmless
    RECORDED = "recorded"  # acted while (unknowingly) observed -> captured
    UNRECORDED_MOVE = "unrecorded_move"  # the unsafe state we must keep unreachable


@dataclass(frozen=True)
class WorldState:
    believes_observed: bool
    actually_observed: bool


def step(state: WorldState) -> Outcome:
    """One tick of the Angel under the model's rules."""
    acts = not state.believes_observed
    if not acts:
        return Outcome.STONE
    return Outcome.RECORDED if state.actually_observed else Outcome.UNRECORDED_MOVE


@dataclass
class ParadoxProof:
    invariant_actually_observed: bool
    unsafe_state_reachable: bool
    transcript: list[tuple[WorldState, Outcome]]

    @property
    def holds(self) -> bool:
        return not self.unsafe_state_reachable


def prove_no_paradox_free_move(actually_observed: bool = True) -> ParadoxProof:
    """Exhaustively enumerate the Angel's belief states under a fixed
    out-of-band-observation invariant and check whether it can ever move without
    being recorded.

    With ``actually_observed=True`` (out-of-band witness active) the unsafe
    outcome is unreachable -> the paradox holds. With ``actually_observed=False``
    (no out-of-band witness) it becomes reachable -> demonstrating exactly why
    the out-of-band vantage point is load-bearing.
    """
    transcript: list[tuple[WorldState, Outcome]] = []
    unsafe = False
    for believes in (True, False):
        s = WorldState(believes_observed=believes, actually_observed=actually_observed)
        outcome = step(s)
        transcript.append((s, outcome))
        if outcome is Outcome.UNRECORDED_MOVE:
            unsafe = True
    return ParadoxProof(
        invariant_actually_observed=actually_observed,
        unsafe_state_reachable=unsafe,
        transcript=transcript,
    )
