from quantumlock.arena import ArenaConfig, MixedRed, RandomBlue, play
from quantumlock.learn import LearnedBlue, train


def test_training_improves_fitness():
    # Evolution Strategies should raise mean reward over generations.
    _, history = train(generations=6, pop=8, n_seeds=10, seed=3, reds=[MixedRed])
    assert history[-1] > history[0]


def test_training_is_deterministic():
    a, _ = train(generations=4, pop=6, n_seeds=8, seed=5, reds=[MixedRed])
    b, _ = train(generations=4, pop=6, n_seeds=8, seed=5, reds=[MixedRed])
    assert a == b


def test_learned_agent_beats_random():
    def rate(blue):
        return sum(
            play(blue, MixedRed(), ArenaConfig(seed=s)).blue_detection_rate for s in range(40)
        ) / 40

    assert rate(LearnedBlue()) > rate(RandomBlue())


def test_learned_blue_is_deterministic_in_play():
    cfg = ArenaConfig(seed=11)
    a = play(LearnedBlue(), MixedRed(), cfg)
    b = play(LearnedBlue(), MixedRed(), cfg)
    assert (a.caught, a.corrupted) == (b.caught, b.corrupted)
