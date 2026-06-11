"""A learned blue agent for the arena, trained with Evolution Strategies.

The hand-written agents (`InferenceBlue`, `BayesBlue`) encode a strategy. This
one *learns* it: a linear policy scores each file from a few features, and the
weights are optimized by Evolution Strategies (the OpenAI-ES update -- perturb
the weights, weight each perturbation by the reward it earned, step that way).
No deep-learning framework, pure stdlib, deterministic for a seed.

This is the lightweight, dependency-free "RL baseline": it demonstrates the arena
is a learnable environment (reward improves over generations) and gives a trained
reference agent to beat. Train with :func:`train`; use the baked-in weights via
:class:`LearnedBlue` out of the box.
"""

from __future__ import annotations

import random
from collections.abc import Iterable

from .arena import (
    ArenaConfig,
    BlueAgent,
    MixedRed,
    RandomRed,
    RedAgent,
    SpreadRed,
    play,
)

_N_FEATURES = 5

# Weights produced by `train(generations=20, seed=1)`. Strongly positive on the
# activity-rate feature -- the learner discovered to chase the noisy files.
DEFAULT_WEIGHTS = [-0.267, 3.805, 0.455, 1.239, 1.086]


def _features(covered: int, activity: int, last_seen: int, tick: int) -> list[float]:
    """Per-file features for the coverage policy."""
    return [
        1.0,  # bias
        activity / (covered + 1.0),  # activity-when-covered rate (exploit)
        1.0 if covered == 0 else 0.0,  # never covered (explore)
        -covered / (tick + 1.0),  # prefer less-covered files (explore)
        1.0 if last_seen == tick - 1 else 0.0,  # activity very recently
    ]


class LearnedBlue(BlueAgent):
    """Linear policy over :func:`_features`, weights learned by ES."""

    def __init__(self, weights: list[float] | None = None) -> None:
        self.weights = list(weights if weights is not None else DEFAULT_WEIGHTS)

    def reset(self, config: ArenaConfig, rng: random.Random) -> None:
        super().reset(config, rng)
        self._covered = [0] * config.n_files

    def coverage(self, tick: int, observations: list[dict]) -> Iterable[int]:
        caught: set[int] = set()
        activity = [0] * self.config.n_files
        last_seen = [-1] * self.config.n_files
        for o in observations:
            if o["kind"] == "catch":
                caught.add(o["file"])
            else:
                activity[o["file"]] += 1
                last_seen[o["file"]] = o["tick"]

        def score(f: int) -> float:
            feats = _features(self._covered[f], activity[f], last_seen[f], tick)
            return sum(w * x for w, x in zip(self.weights, feats, strict=True))

        candidates = [f for f in range(self.config.n_files) if f not in caught]
        candidates.sort(key=score, reverse=True)
        chosen = candidates[: min(self.config.coverage_budget, len(candidates))]
        for f in chosen:
            self._covered[f] += 1
        return chosen


def fitness(
    weights: list[float],
    reds: list[type[RedAgent]],
    n_seeds: int = 30,
    base: ArenaConfig | None = None,
) -> float:
    """Mean blue reward (caught - corrupted) across seeds and red opponents."""
    base = base or ArenaConfig()
    total = 0.0
    n = 0
    for red in reds:
        for seed in range(n_seeds):
            cfg = ArenaConfig(**{**base.__dict__, "seed": seed})
            result = play(LearnedBlue(weights), red(), cfg)
            total += result.caught - result.corrupted
            n += 1
    return total / n


def train(
    generations: int = 20,
    pop: int = 16,
    sigma: float = 0.3,
    lr: float = 0.2,
    n_seeds: int = 30,
    seed: int = 0,
    reds: list[type[RedAgent]] | None = None,
) -> tuple[list[float], list[float]]:
    """Evolution Strategies. Returns (weights, fitness-per-generation history)."""
    rng = random.Random(seed)  # nosec B311 -- training RNG, not security
    reds = reds or [RandomRed, MixedRed, SpreadRed]
    w = [0.0] * _N_FEATURES
    history: list[float] = [fitness(w, reds, n_seeds)]

    for _ in range(generations):
        noises = [[rng.gauss(0, 1) for _ in range(_N_FEATURES)] for _ in range(pop)]
        rewards = [
            fitness([w[i] + sigma * z[i] for i in range(_N_FEATURES)], reds, n_seeds)
            for z in noises
        ]
        mean = sum(rewards) / pop
        var = sum((r - mean) ** 2 for r in rewards) / pop
        std = var**0.5 or 1.0
        adv = [(r - mean) / std for r in rewards]
        for i in range(_N_FEATURES):
            grad = sum(adv[k] * noises[k][i] for k in range(pop)) / pop
            w[i] += lr / sigma * grad
        history.append(fitness(w, reds, n_seeds))
    return w, history


def main() -> int:
    print("Training a blue coverage policy with Evolution Strategies...\n")
    weights, history = train(generations=20, seed=1)
    print("fitness (mean reward) by generation:")
    print("  " + "  ".join(f"{h:+.2f}" for h in history))
    print(f"\nlearned weights: [{', '.join(f'{x:.3f}' for x in weights)}]")
    print(f"improvement: {history[0]:+.2f} -> {history[-1]:+.2f}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
