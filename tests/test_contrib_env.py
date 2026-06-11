"""Verify the upstream-format contrib env package (kaggle/contrib/weeping_angel/)
registers and runs through kaggle-environments. Skipped if the package is absent."""

import sys
from pathlib import Path

import pytest

pytest.importorskip("kaggle_environments")
import kaggle_environments  # noqa: E402

CONTRIB = Path(__file__).resolve().parents[1] / "kaggle" / "contrib"


def _register():
    sys.path.insert(0, str(CONTRIB))
    from weeping_angel import weeping_angel as env  # the env module in the package

    kaggle_environments.register(
        "weeping_angel_contrib",
        {
            "agents": env.agents,
            "html_renderer": env.html_renderer,
            "interpreter": env.interpreter,
            "renderer": env.renderer,
            "specification": env.specification,
        },
    )


def test_contrib_env_runs_and_is_zero_sum():
    _register()
    env = kaggle_environments.make("weeping_angel_contrib", configuration={"seed": 1})
    final = env.run(["inference_blue", "mixed_red"])[-1]
    assert [s.status for s in final] == ["DONE", "DONE"]
    assert final[0].reward == -final[1].reward


def test_contrib_env_hidden_information():
    _register()
    env = kaggle_environments.make("weeping_angel_contrib", configuration={"seed": 3})
    final = env.run(["bayes_blue", "mixed_red"])[-1]
    assert final[0].observation.angels == []
    assert final[1].observation.coverageLog == []


def test_contrib_spec_matches_inline_env():
    # The contrib spec should mirror the self-contained kaggle/weeping_angel.py.
    _register()
    from weeping_angel import weeping_angel as env

    assert env.specification["name"] == "weeping_angel"
    assert env.specification["configuration"]["armTicks"]["default"] == 3
    assert set(env.agents) >= {"inference_blue", "bayes_blue", "mixed_red"}
