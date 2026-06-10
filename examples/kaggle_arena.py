"""Run the Weeping Angel Arena as a kaggle-environments simulation.

    pip install kaggle-environments
    python examples/kaggle_arena.py

Registers the env, round-robins the built-in agents over many seeds, and prints
the mean blue reward (caught - corrupted; higher is better for blue) per matchup.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_env():
    path = ROOT / "kaggle" / "weeping_angel.py"
    spec = importlib.util.spec_from_file_location("weeping_angel_env", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.register()
    return mod


def main() -> int:
    try:
        import kaggle_environments
    except ImportError:
        print("kaggle-environments is not installed. Run: pip install kaggle-environments")
        return 1

    load_env()
    blues = ["random_blue", "sweep_blue", "inference_blue"]
    reds = ["rush_red", "random_red", "evasive_red"]
    episodes = 100

    def mean_blue(blue, red):
        total = 0.0
        for seed in range(episodes):
            env = kaggle_environments.make("weeping_angel", configuration={"seed": seed})
            total += env.run([blue, red])[-1][0].reward
        return total / episodes

    print(f"Weeping Angel Arena (kaggle-environments) -- mean blue reward over {episodes} seeds")
    print("higher = blue caught more than it let through\n")
    print("blue \\ red       " + "".join(f"{r:>14}" for r in reds))
    for blue in blues:
        cells = [f"{mean_blue(blue, red):+.2f}" for red in reds]
        print(f"  {blue:<14}" + "".join(f"{c:>14}" for c in cells))
    return 0


if __name__ == "__main__":
    sys.exit(main())
