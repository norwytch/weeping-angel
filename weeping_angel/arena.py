"""Adversarial arena: Angels (red) vs an out-of-band recorder (blue).

A prototype competition environment built on the Weeping Angel model. It is the
*record* framing of the defense turned into a two-sided game:

* Red controls several Angels, each lurking on a file. On any tick an Angel may
  stomp (forge its timestamps) or stay still. Red wins by corrupting timelines
  without being recorded.
* Blue runs the out-of-band recorder but can only watch ``coverage_budget``
  files per tick (the "system limitation"). Blue wins by catching stomps in the
  act.

The load-bearing rule, straight from the project's thesis: **Blue's coverage is
invisible to Red.** Red cannot see where the recorder is pointed, and because
its forgeries are internally consistent, a stomp is caught *iff* the file was
covered on the tick it moved (this is rule ``R4``, the setinfo captured out of
band). A stomp on an uncovered file succeeds unrecorded and corrupts the
timeline. Conversely Blue never sees the uncovered moves during play; it only
learns from what it covers. That asymmetry is the whole game.

Scoring (Burak's framing):
* angels caught            -- blue's score
* angels corrupted         -- red's score (got away)
* time to first corruption -- how long blue held the line

Agents subclass :class:`BlueAgent` / :class:`RedAgent`; a few baselines ship
here. :func:`play` runs one episode, :func:`tournament` runs a round-robin.
"""

from __future__ import annotations

import random
from collections.abc import Iterable
from dataclasses import dataclass

LURKING = "lurking"
CAUGHT = "caught"
CORRUPTED = "corrupted"


@dataclass
class ArenaConfig:
    n_files: int = 12
    n_angels: int = 4
    n_ticks: int = 30
    coverage_budget: int = 3
    # Activity (cover traffic) per tick. A file hosting a lurking Angel is
    # noisier than an empty one -- malware stages, writes, probes -- which is the
    # signal an inference-based blue can learn. Blue only sees it where it covers.
    benign_rate: float = 0.15  # empty file
    angel_rate: float = 0.50  # file hosting a lurking Angel
    # Staging cost (opt-in, 0 = off). An Angel must emit activity on >= arm_ticks
    # prior ticks before it is allowed to stomp -- so acting requires first making
    # noise, which is what an inference blue can detect. Off by default so the
    # baseline game (and the published Kaggle env) are unchanged.
    arm_ticks: int = 0
    seed: int = 0


@dataclass
class AngelView:
    """What red knows about one of its own Angels: where it sits and its fate."""

    angel_id: int
    file: int
    status: str = LURKING


@dataclass
class MatchResult:
    caught: int
    corrupted: int
    dormant: int  # Angels that never moved
    time_to_corruption: int  # tick of first corruption, or n_ticks if none
    n_ticks: int

    @property
    def moves(self) -> int:
        return self.caught + self.corrupted

    @property
    def blue_detection_rate(self) -> float:
        return self.caught / self.moves if self.moves else 1.0


class BlueAgent:
    """Allocates the out-of-band recorder. Sees only what it covers."""

    def reset(self, config: ArenaConfig, rng: random.Random) -> None:
        self.config = config
        self.rng = rng

    def coverage(self, tick: int, observations: list[dict]) -> Iterable[int]:
        """Return up to ``coverage_budget`` file indices to record this tick.
        ``observations`` is the running log of ``{tick, file, kind}`` for covered
        files, where ``kind`` is ``"catch"`` or ``"benign"``."""
        raise NotImplementedError


class RedAgent:
    """Times the Angels' moves. Never sees blue's coverage."""

    def reset(self, config: ArenaConfig, rng: random.Random) -> None:
        self.config = config
        self.rng = rng

    def act(self, tick: int, angels: list[AngelView]) -> Iterable[int]:
        """Return the ids of Angels that stomp this tick. Only ``LURKING`` ones
        take effect."""
        raise NotImplementedError


# -- baseline blue agents ------------------------------------------------------
class RandomBlue(BlueAgent):
    def coverage(self, tick: int, observations: list[dict]) -> Iterable[int]:
        k = min(self.config.coverage_budget, self.config.n_files)
        return self.rng.sample(range(self.config.n_files), k)


class SweepBlue(BlueAgent):
    """Round-robins coverage across all files, guaranteeing every file is seen
    once per ceil(n_files / budget) ticks."""

    def reset(self, config: ArenaConfig, rng: random.Random) -> None:
        super().reset(config, rng)
        self._cursor = 0

    def coverage(self, tick: int, observations: list[dict]) -> Iterable[int]:
        k = min(self.config.coverage_budget, self.config.n_files)
        cov = [(self._cursor + i) % self.config.n_files for i in range(k)]
        self._cursor = (self._cursor + k) % self.config.n_files
        return cov


# -- baseline red agents -------------------------------------------------------
class RushRed(RedAgent):
    """Every Angel stomps on tick 0. Maximal corruption unless blue happens to
    cover those files immediately."""

    def act(self, tick: int, angels: list[AngelView]) -> Iterable[int]:
        return [a.angel_id for a in angels if a.status == LURKING] if tick == 0 else []


class RandomRed(RedAgent):
    """Each Angel picks a random tick to move, independently."""

    def reset(self, config: ArenaConfig, rng: random.Random) -> None:
        super().reset(config, rng)
        self._when = {i: rng.randrange(config.n_ticks) for i in range(config.n_angels)}

    def act(self, tick: int, angels: list[AngelView]) -> Iterable[int]:
        return [
            a.angel_id for a in angels if a.status == LURKING and self._when[a.angel_id] == tick
        ]


class SpreadRed(RedAgent):
    """Moves one Angel at a time, evenly spaced across the episode, so blue can
    never catch more than one per window."""

    def reset(self, config: ArenaConfig, rng: random.Random) -> None:
        super().reset(config, rng)
        gap = max(1, config.n_ticks // max(1, config.n_angels))
        self._when = {i: i * gap for i in range(config.n_angels)}

    def act(self, tick: int, angels: list[AngelView]) -> Iterable[int]:
        return [
            a.angel_id for a in angels if a.status == LURKING and self._when[a.angel_id] == tick
        ]


class InferenceBlue(BlueAgent):
    """Learns where the Angels are. A lurking Angel's file shows activity more
    often than an empty one, so blue tracks each file's activity-when-covered
    rate and concentrates coverage on the noisiest unresolved files, while
    reserving exploration for files it has barely seen.

    Belief(f) = (activity seen + 1) / (times covered + 2). Never-covered files
    sit at the 0.5 prior, so they get explored before being dismissed; empties
    fall below that with coverage, Angel files climb above it."""

    def reset(self, config: ArenaConfig, rng: random.Random) -> None:
        super().reset(config, rng)
        self._covered = [0] * config.n_files

    def coverage(self, tick: int, observations: list[dict]) -> Iterable[int]:
        caught: set[int] = set()
        activity = [0] * self.config.n_files
        for o in observations:
            if o["kind"] == "catch":
                caught.add(o["file"])
            else:
                activity[o["file"]] += 1

        def belief(f: int) -> float:
            return (activity[f] + 1) / (self._covered[f] + 2)

        candidates = [f for f in range(self.config.n_files) if f not in caught]
        # high belief first; break ties toward the least-covered file (explore)
        candidates.sort(key=lambda f: (-belief(f), self._covered[f]))
        k = min(self.config.coverage_budget, len(candidates))
        chosen = candidates[:k]
        for f in chosen:
            self._covered[f] += 1
        return chosen


class BayesBlue(BlueAgent):
    """Maintains a Beta posterior per file over "hosts an Angel" and covers by
    Thompson sampling: draw a probability from each file's posterior and take the
    highest. Sampling builds in exploration -- uncertain files occasionally win a
    draw -- without a hand-tuned exploration term."""

    def reset(self, config: ArenaConfig, rng: random.Random) -> None:
        super().reset(config, rng)
        self._covered = [0] * config.n_files

    def coverage(self, tick: int, observations: list[dict]) -> Iterable[int]:
        caught: set[int] = set()
        activity = [0] * self.config.n_files
        for o in observations:
            if o["kind"] == "catch":
                caught.add(o["file"])
            else:
                activity[o["file"]] += 1

        def sample(f: int) -> float:
            alpha = activity[f] + 1
            beta = (self._covered[f] - activity[f]) + 1
            return self.rng.betavariate(alpha, max(1, beta))

        candidates = [f for f in range(self.config.n_files) if f not in caught]
        candidates.sort(key=sample, reverse=True)
        chosen = candidates[: min(self.config.coverage_budget, len(candidates))]
        for f in chosen:
            self._covered[f] += 1
        return chosen


class EvasiveRed(RedAgent):
    """Counters an inference blue by striking before it can learn. All Angels
    move on a single random early tick, denying blue both the observation time
    to locate them and a second tick to refine its coverage."""

    def reset(self, config: ArenaConfig, rng: random.Random) -> None:
        super().reset(config, rng)
        self._strike = rng.randrange(max(1, min(3, config.n_ticks)))

    def act(self, tick: int, angels: list[AngelView]) -> Iterable[int]:
        if tick != self._strike:
            return []
        return [a.angel_id for a in angels if a.status == LURKING]


class MixedRed(RedAgent):
    """Each Angel draws a random strike tick, then keeps attempting every tick
    until it succeeds. The randomized timing is hard for blue to anticipate, and
    the persistent retries make it robust to a staging cost (it waits until the
    Angel is armed without knowing when that is)."""

    def reset(self, config: ArenaConfig, rng: random.Random) -> None:
        super().reset(config, rng)
        self._after = {i: rng.randrange(config.n_ticks) for i in range(config.n_angels)}

    def act(self, tick: int, angels: list[AngelView]) -> Iterable[int]:
        return [
            a.angel_id for a in angels if a.status == LURKING and tick >= self._after[a.angel_id]
        ]


def play(blue: BlueAgent, red: RedAgent, config: ArenaConfig) -> MatchResult:
    """Run one episode. Deterministic for a given config.seed and agents."""
    # game/episode RNGs for reproducibility, not security-sensitive
    env_rng = random.Random(config.seed)  # nosec B311
    blue.reset(config, random.Random(config.seed * 2 + 1))  # nosec B311
    red.reset(config, random.Random(config.seed * 2 + 2))  # nosec B311

    # Hidden Angel placement: red knows it, blue must infer it.
    files = env_rng.sample(range(config.n_files), config.n_angels)
    angels = [AngelView(i, f) for i, f in enumerate(files)]
    file_to_angel = {a.file: a.angel_id for a in angels}
    armed: dict[int, int] = {}  # angel_id -> ticks it has emitted activity (staging)

    observations: list[dict] = []
    caught = corrupted = 0
    time_to_corruption = config.n_ticks

    for tick in range(config.n_ticks):
        budget = min(config.coverage_budget, config.n_files)
        raw = list(blue.coverage(tick, list(observations)))
        cover = set()
        for idx in raw:  # honor the budget; ignore out-of-range / duplicates
            i = int(idx)
            if 0 <= i < config.n_files and i not in cover:
                cover.add(i)
                if len(cover) == budget:
                    break

        views = [AngelView(a.angel_id, a.file, a.status) for a in angels]
        moves = {int(i) for i in red.act(tick, views)}
        acted_files = set()
        for a in angels:
            if a.status != LURKING or a.angel_id not in moves:
                continue
            if config.arm_ticks and armed.get(a.angel_id, 0) < config.arm_ticks:
                continue  # staging cost: not yet armed, the stomp is a no-op
            acted_files.add(a.file)
            if a.file in cover:
                a.status = CAUGHT
                caught += 1
                observations.append({"tick": tick, "file": a.file, "kind": "catch"})
            else:
                a.status = CORRUPTED
                corrupted += 1
                if corrupted == 1:
                    time_to_corruption = tick
                # uncovered move is invisible to blue -- nothing observed

        # background activity, visible to blue only where it is covering. Files
        # hosting a still-lurking Angel are noisier than empty ones; each emission
        # also advances that Angel's arming progress.
        lurking_files = {a.file for a in angels if a.status == LURKING}
        for f in range(config.n_files):
            if f in acted_files:
                continue
            is_angel = f in lurking_files
            rate = config.angel_rate if is_angel else config.benign_rate
            emitted = env_rng.random() < rate
            if emitted and is_angel:
                armed[file_to_angel[f]] = armed.get(file_to_angel[f], 0) + 1
            if emitted and f in cover:
                observations.append({"tick": tick, "file": f, "kind": "activity"})

    dormant = sum(1 for a in angels if a.status == LURKING)
    return MatchResult(caught, corrupted, dormant, time_to_corruption, config.n_ticks)


def tournament(
    blues: dict[str, type[BlueAgent]],
    reds: dict[str, type[RedAgent]],
    base: ArenaConfig | None = None,
    episodes: int = 50,
) -> dict[tuple[str, str], MatchResult]:
    """Round-robin every blue against every red over ``episodes`` seeds.
    Returns aggregated results keyed by (blue_name, red_name)."""
    base = base or ArenaConfig()
    out: dict[tuple[str, str], MatchResult] = {}
    for bname, bcls in blues.items():
        for rname, rcls in reds.items():
            caught = corrupted = dormant = ttc = 0
            for ep in range(episodes):
                cfg = ArenaConfig(**{**base.__dict__, "seed": ep})
                r = play(bcls(), rcls(), cfg)
                caught += r.caught
                corrupted += r.corrupted
                dormant += r.dormant
                ttc += r.time_to_corruption
            out[(bname, rname)] = MatchResult(
                caught, corrupted, dormant, ttc // episodes, base.n_ticks
            )
    return out


BLUE_BASELINES: dict[str, type[BlueAgent]] = {
    "random": RandomBlue,
    "sweep": SweepBlue,
    "inference": InferenceBlue,
    "bayes": BayesBlue,
}
RED_BASELINES: dict[str, type[RedAgent]] = {
    "rush": RushRed,
    "random": RandomRed,
    "spread": SpreadRed,
    "evasive": EvasiveRed,
    "mixed": MixedRed,
}
