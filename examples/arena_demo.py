"""Round-robin the baseline Angel (red) and recorder (blue) agents.

    python examples/arena_demo.py

Prints, for each blue-vs-red matchup, the share of Angel moves blue caught and
the average tick of first corruption (higher = blue held the line longer).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from weeping_angel.arena import (  # noqa: E402
    BLUE_BASELINES,
    RED_BASELINES,
    ArenaConfig,
    tournament,
)


def main() -> None:
    cfg = ArenaConfig(n_files=12, n_angels=4, n_ticks=30, coverage_budget=3)
    results = tournament(BLUE_BASELINES, RED_BASELINES, base=cfg, episodes=200)

    reds = list(RED_BASELINES)
    print(f"Arena: {cfg.n_angels} angels on {cfg.n_files} files, "
          f"{cfg.coverage_budget}/tick coverage, {cfg.n_ticks} ticks, 200 episodes\n")
    print("blue \\ red    " + "".join(f"{r:>14}" for r in reds))
    for b in BLUE_BASELINES:
        cells = []
        for r in reds:
            res = results[(b, r)]
            cells.append(f"{res.blue_detection_rate:5.0%} caught")
        print(f"  {b:<10}" + "".join(f"{c:>14}" for c in cells))
    print("\ntime-to-corruption (avg first-corruption tick)\n")
    print("blue \\ red    " + "".join(f"{r:>14}" for r in reds))
    for b in BLUE_BASELINES:
        cells = [f"{results[(b, r)].time_to_corruption:d}/{cfg.n_ticks}" for r in reds]
        print(f"  {b:<10}" + "".join(f"{c:>14}" for c in cells))


if __name__ == "__main__":
    main()
