"""Verify the upstream-format contrib env package (kaggle/contrib/weeping_angel/)
registers and runs through kaggle-environments. Skipped if the package is absent."""

import importlib.util
import sys
from pathlib import Path

import pytest

pytest.importorskip("kaggle_environments")
import kaggle_environments  # noqa: E402

CONTRIB_PKG = Path(__file__).resolve().parents[1] / "kaggle" / "contrib" / "weeping_angel"


def _load_env():
    # Load the contrib package under a unique name so it does not collide with
    # the core `weeping_angel` package (same dir name, different code). The env
    # module uses `from .agents import ...`, so register the package with its
    # search location and let the relative import resolve against it.
    pkg = "wa_contrib_env"
    if pkg not in sys.modules:
        spec = importlib.util.spec_from_file_location(
            pkg,
            CONTRIB_PKG / "__init__.py",
            submodule_search_locations=[str(CONTRIB_PKG)],
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules[pkg] = module
        spec.loader.exec_module(module)
    env_name = f"{pkg}.weeping_angel"
    if env_name not in sys.modules:
        spec = importlib.util.spec_from_file_location(env_name, CONTRIB_PKG / "weeping_angel.py")
        env = importlib.util.module_from_spec(spec)
        sys.modules[env_name] = env
        spec.loader.exec_module(env)
    return sys.modules[env_name]


def _register():
    env = _load_env()
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
    env = _load_env()

    assert env.specification["name"] == "weeping_angel"
    assert env.specification["configuration"]["armTicks"]["default"] == 3
    assert set(env.agents) >= {"inference_blue", "bayes_blue", "mixed_red"}
