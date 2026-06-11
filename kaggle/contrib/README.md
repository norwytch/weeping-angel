# Contributing the env to kaggle-environments (Path C: a hosted competition)

A bot-vs-bot Kaggle Simulation Competition (Halite / Lux / Kore style) is
Kaggle-hosted, not self-serve: their backend runs the episodes and the TrueSkill
leaderboard. The path to one has two milestones:

1. **Get the env merged into [Kaggle/kaggle-environments](https://github.com/Kaggle/kaggle-environments).**
   A real, self-contained OSS contribution, valuable on its own.
2. **Pitch Kaggle to run a competition on it.** A separate ask you make after the
   env lands, on their timeline.

[`weeping_angel/`](weeping_angel/) is the merge-ready env, structured exactly like
the bundled envs (e.g. `rps/`): `weeping_angel.py` exposes `specification`,
`interpreter`, `renderer`, `html_renderer`, and `agents`; the spec is in
`weeping_angel.json`; agents are in `agents.py`; tests in `test_weeping_angel.py`;
a canvas replay renderer in `weeping_angel.js`.

## Submitting the PR

```bash
git clone https://github.com/Kaggle/kaggle-environments
cd kaggle-environments
cp -r /path/to/weeping_angel kaggle_environments/envs/weeping_angel
pip install -e ".[all]"
python -c "import kaggle_environments as k; k.make('weeping_angel').run(['inference_blue','mixed_red'])"
pytest kaggle_environments/envs/weeping_angel
```

The package is auto-discovered (their loader imports `envs.<name>.<name>` and
registers the five attributes), so no edits outside the new directory are needed.
Then open a PR.

**Before submitting, verify the JS renderer in a browser** (`env.render(mode="ipython")`
in a notebook). It follows the `renderer(context)` contract but was authored
without a live player to test against; the env is fully functional without it
(`html_renderer` falls back to an empty string).

### PR description (copy-paste starting point)

> **Add the Weeping Angel Arena environment**
>
> A two-player, simultaneous, hidden-information pursuit game. Red controls Angels
> that forge file timestamps ("stomp") only when unobserved; blue is an
> out-of-band recorder that catches stomps under a per-tick coverage budget. A
> staging cost (`armTicks`) makes acting require first emitting detectable
> activity, so there is no dominant strategy.
>
> - Hidden information is enforced by construction: blue never sees Angel
>   placement, red never sees coverage.
> - Reward is zero-sum (`caught - corrupted`).
> - Ships eight baseline agents (random/sweep/inference/Bayesian blue;
>   rush/random/evasive/mixed red), a canvas replay renderer, and tests.
> - Modelled on a real DFIR problem (NTFS timestomping, MITRE T1070.006); the
>   wider detection framework is at <your repo link>.

## The competition pitch (after the env is merged)

Kaggle onboards community-proposed simulation envs case by case. Reach out via the
PR thread or Kaggle's competition team with a short pitch:

- **Hook:** a security-themed pursuit game with genuine strategic depth (no
  dominant strategy) grounded in a real attack technique (timestomping, T1070.006).
- **Why it competes well:** simultaneous hidden information + the staging-cost
  trade-off make for non-trivial agents; there are clear baselines to beat and a
  learnable signal (an Evolution-Strategies agent already beats the heuristics).
- **Readiness:** env merged, spec/tests/renderer in place, starter notebook and
  baseline pool available.

Realistic outcome: getting the env merged is achievable and worthwhile by itself;
a hosted competition depends on Kaggle's interest and roadmap.
