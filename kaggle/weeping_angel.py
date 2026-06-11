"""Weeping Angel Arena as a kaggle-environments simulation environment.

Two agents play simultaneously each step:
  * agent 0 = blue, the out-of-band recorder. Action: a list of file indices to
    cover this tick (truncated to coverageBudget). It sees only ``coverageLog``,
    the activity and catches on files it has covered.
  * agent 1 = red, the Angels. Action: a list of Angel ids to stomp this tick.
    It sees ``angels`` ([id, file, status]) -- red knows where its own Angels
    are, but never sees blue's coverage.

A stomp is caught iff the file was covered on that tick (rule R4, the setinfo
captured out of band). Otherwise it corrupts the timeline, unseen by blue. A
file hosting a lurking Angel emits activity more often than an empty one
(angelRate vs benignRate), the signal an inference agent can learn.

Staging cost (armTicks): an Angel must emit activity on >= armTicks prior ticks
before it is allowed to stomp. Acting therefore requires first making noise --
exactly what an inference blue detects -- so red must trade exposure for the
ability to move. This is what makes the game deep: there is no dominant strategy.

Reward is zero-sum: blue = caught - corrupted, red = corrupted - caught.

Register and run:

    import kaggle_environments
    from kaggle.weeping_angel import register
    register()
    env = kaggle_environments.make("weeping_angel")
    env.run(["inference_blue", "evasive_red"])
"""

from __future__ import annotations

import random

LURKING, CAUGHT, CORRUPTED = 0, 1, 2

specification = {
    "name": "weeping_angel",
    "title": "Weeping Angel Arena",
    "description": "Adversarial timestomp game: Angels vs an out-of-band recorder under a budget.",
    "version": "2.0.0",
    "agents": [2],
    "configuration": {
        "episodeSteps": {"type": "integer", "default": 31, "minimum": 2},
        "nFiles": {"type": "integer", "default": 12, "minimum": 1},
        "nAngels": {"type": "integer", "default": 4, "minimum": 1},
        "coverageBudget": {"type": "integer", "default": 3, "minimum": 0},
        "benignRate": {"type": "number", "default": 0.15, "minimum": 0, "maximum": 1},
        "angelRate": {"type": "number", "default": 0.50, "minimum": 0, "maximum": 1},
        # Staging cost: ticks of activity an Angel must emit before it can stomp.
        "armTicks": {"type": "integer", "default": 3, "minimum": 0},
        "seed": {"type": "integer", "default": 0},
        "actTimeout": 2,
    },
    "reward": {"type": "number", "default": 0},
    "observation": {
        "angels": {
            "description": "Red-only. [id, file, status, armed]; status 0=lurk,1=caught,2=corrupt.",
            "type": "array",
            "default": [],
        },
        "coverageLog": {
            "description": "Blue-only. [tick, file, kind] on covered files (0=activity,1=catch).",
            "type": "array",
            "default": [],
        },
        "remainingOverageTime": 60,
    },
    "action": {
        "description": "Blue: file indices to cover. Red: Angel ids to stomp.",
        "type": "array",
        "default": [],
    },
}


def interpreter(state, env):
    blue, red = state[0], state[1]
    config = env.configuration

    if env.done:
        # Reset: place the Angels on hidden files (seeded). Red is allowed to
        # know its own placement; blue's `angels` stays empty.
        rng = random.Random(config.seed)  # nosec B311 -- game seeding, not security
        files = rng.sample(range(config.nFiles), config.nAngels)
        red.observation.angels = [[i, f, LURKING, 0] for i, f in enumerate(files)]
        blue.observation.coverageLog = []
        return state

    tick = blue.observation.step
    angels = red.observation.angels
    budget = min(config.coverageBudget, config.nFiles)

    # Blue's coverage: honor the budget, drop out-of-range / duplicate indices.
    cover: set[int] = set()
    for raw in blue.action or []:
        try:
            f = int(raw)
        except (TypeError, ValueError):
            continue
        if 0 <= f < config.nFiles and f not in cover:
            cover.add(f)
            if len(cover) == budget:
                break

    moves = set()
    for raw in red.action or []:
        try:
            moves.add(int(raw))
        except (TypeError, ValueError):
            continue

    arm_ticks = config.armTicks
    log = blue.observation.coverageLog
    acted_files = set()
    for a in angels:
        aid, f, status, armed = a[0], a[1], a[2], a[3]
        if status != LURKING or aid not in moves:
            continue
        if arm_ticks and armed < arm_ticks:
            continue  # staging cost: not yet armed, the stomp is a no-op
        acted_files.add(f)
        if f in cover:
            a[2] = CAUGHT
            log.append([tick, f, 1])  # catch is visible to blue
        else:
            a[2] = CORRUPTED  # uncovered: corrupts unseen by blue

    # Background activity, visible to blue only where it covers. A file hosting a
    # still-lurking Angel is noisier than an empty one; each emission also
    # advances that Angel's arming progress.
    angel_on = {a[1]: a for a in angels if a[2] == LURKING}
    act_rng = random.Random(config.seed * 100003 + tick)  # nosec B311
    for f in range(config.nFiles):
        if f in acted_files:
            continue
        is_angel = f in angel_on
        rate = config.angelRate if is_angel else config.benignRate
        emitted = act_rng.random() < rate
        if emitted and is_angel:
            angel_on[f][3] += 1
        if emitted and f in cover:
            log.append([tick, f, 0])

    caught = sum(1 for a in angels if a[2] == CAUGHT)
    corrupted = sum(1 for a in angels if a[2] == CORRUPTED)
    blue.reward = caught - corrupted
    red.reward = corrupted - caught

    resolved = caught + corrupted
    remaining = config.episodeSteps - tick - 1
    if remaining <= 1 or resolved >= config.nAngels:
        blue.status = "DONE"
        red.status = "DONE"
    return state


def renderer(state, env):
    last = env.steps[-1]
    blue, red = last[0], last[1]
    caught = sum(1 for a in red.observation.angels if a[2] == CAUGHT)
    corrupted = sum(1 for a in red.observation.angels if a[2] == CORRUPTED)
    dormant = sum(1 for a in red.observation.angels if a[2] == LURKING)
    return (
        f"step {blue.observation.step}: caught={caught} corrupted={corrupted} "
        f"dormant={dormant}  (blue {blue.reward} / red {red.reward})"
    )


def html_renderer():
    return ""


# -- agents --------------------------------------------------------------------
def _angel_ids(obs, status=LURKING):
    return [a[0] for a in obs["angels"] if a[2] == status]


def random_blue(obs, config):
    rng = random.Random(obs["step"] * 7919 + 1)  # nosec B311
    k = min(config["coverageBudget"], config["nFiles"])
    return rng.sample(range(config["nFiles"]), k)


def sweep_blue(obs, config):
    k = min(config["coverageBudget"], config["nFiles"])
    start = (obs["step"] * k) % config["nFiles"]
    return [(start + i) % config["nFiles"] for i in range(k)]


def inference_blue(obs, config):
    """Stateless: weight files by the activity seen on them so far, and cover the
    noisiest non-caught files, rotating exploration in on ties."""
    n = config["nFiles"]
    activity = [0] * n
    caught = set()
    for _tick, f, kind in obs["coverageLog"]:
        if kind == 1:
            caught.add(f)
        else:
            activity[f] += 1
    rot = obs["step"]
    candidates = [f for f in range(n) if f not in caught]
    candidates.sort(key=lambda f: (-activity[f], (f + rot) % n))
    k = min(config["coverageBudget"], len(candidates))
    return candidates[:k]


def bayes_blue(obs, config):
    """Thompson sampling: draw a score from each file's activity-based posterior
    (Beta(activity+1, 1)) and cover the highest. Sampling builds in exploration."""
    n = config["nFiles"]
    activity = [0] * n
    caught = set()
    for _tick, f, kind in obs["coverageLog"]:
        if kind == 1:
            caught.add(f)
        else:
            activity[f] += 1
    rng = random.Random(config["seed"] * 131 + obs["step"])  # nosec B311
    candidates = [f for f in range(n) if f not in caught]
    candidates.sort(key=lambda f: rng.betavariate(activity[f] + 1, 1), reverse=True)
    return candidates[: min(config["coverageBudget"], len(candidates))]


def rush_red(obs, config):
    return _angel_ids(obs) if obs["step"] <= 1 else []


def evasive_red(obs, config):
    strike = 1 + (config["seed"] % 3)
    return _angel_ids(obs) if obs["step"] == strike else []


def random_red(obs, config):
    n_ticks = config["episodeSteps"] - 1
    seed = config["seed"]
    out = []
    for a in obs["angels"]:
        if a[2] == LURKING and (seed * 31 + a[0] * 2654435761) % n_ticks == obs["step"]:
            out.append(a[0])
    return out


def mixed_red(obs, config):
    """Each Angel draws a random strike tick and then attempts every tick after
    it -- the persistent retries wait out the staging cost without knowing when
    the Angel is armed, and the randomized timing is hard for blue to anticipate."""
    n_ticks = config["episodeSteps"] - 1
    seed = config["seed"]
    out = []
    for a in obs["angels"]:
        if a[2] != LURKING:
            continue
        strike = (seed * 131 + a[0] * 2654435761) % n_ticks
        if obs["step"] >= strike:
            out.append(a[0])
    return out


agents = {
    "random_blue": random_blue,
    "sweep_blue": sweep_blue,
    "inference_blue": inference_blue,
    "bayes_blue": bayes_blue,
    "rush_red": rush_red,
    "evasive_red": evasive_red,
    "random_red": random_red,
    "mixed_red": mixed_red,
}


def env_dict():
    return {
        "specification": specification,
        "interpreter": interpreter,
        "renderer": renderer,
        "html_renderer": html_renderer,
        "agents": agents,
    }


def register():
    import kaggle_environments

    kaggle_environments.register("weeping_angel", env_dict())
