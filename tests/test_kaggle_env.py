"""Tests for the kaggle-environments wrapper. Skipped if the package is absent."""

import importlib.util
from pathlib import Path

import pytest

pytest.importorskip("kaggle_environments")
import kaggle_environments  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def _make(**config):
    spec = importlib.util.spec_from_file_location(
        "weeping_angel_env", ROOT / "kaggle" / "weeping_angel.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.register()
    return kaggle_environments.make("weeping_angel", configuration=config)


def test_episode_runs_and_terminates():
    final = _make(seed=0).run(["inference_blue", "random_red"])[-1]
    assert [s.status for s in final] == ["DONE", "DONE"]


def test_new_agents_run():
    final = _make(seed=1).run(["bayes_blue", "mixed_red"])[-1]
    assert [s.status for s in final] == ["DONE", "DONE"]


def test_staging_cost_blunts_an_unarmed_rush():
    # rush_red only attempts on tick <= 1; with a staging cost it can't arm in
    # time, so it corrupts far fewer files than with the cost off.
    def corrupted(arm):
        total = 0
        for seed in range(20):
            final = _make(seed=seed, armTicks=arm).run(["random_blue", "rush_red"])[-1]
            total += sum(1 for a in final[1].observation.angels if a[2] == 2)
        return total

    assert corrupted(3) < corrupted(0)


def test_reward_is_zero_sum():
    final = _make(seed=2).run(["sweep_blue", "rush_red"])[-1]
    assert final[0].reward == -final[1].reward


def test_hidden_information_holds():
    # Blue must never see Angel placement; red must never see the coverage log.
    final = _make(seed=3).run(["inference_blue", "random_red"])[-1]
    assert final[0].observation.angels == []  # blue (agent 0)
    assert final[1].observation.coverageLog == []  # red (agent 1)
    assert len(final[1].observation.angels) == _make(seed=3).configuration.nAngels


def test_deterministic_for_seed():
    a = _make(seed=7).run(["inference_blue", "random_red"])[-1][0].reward
    b = _make(seed=7).run(["inference_blue", "random_red"])[-1][0].reward
    assert a == b


def test_inference_beats_sweep_against_patient_red():
    def mean_blue(blue):
        return sum(
            _make(seed=s).run([blue, "random_red"])[-1][0].reward for s in range(25)
        ) / 25

    assert mean_blue("inference_blue") > mean_blue("sweep_blue")
