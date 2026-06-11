from weeping_angel.efficacy import evaluate


def test_no_false_positives_on_benign_corpus():
    # The benign classes include legitimate timestamp-setting (archivers /
    # restore / cp -p) -- the case the #1 fix protects. None may be flagged.
    e = evaluate(n_per_kind=100)
    assert e.fp == 0


def test_catches_every_stomp_variant():
    e = evaluate(n_per_kind=100)
    assert e.fn == 0
    assert e.recall == 1.0


def test_deterministic():
    assert evaluate(n_per_kind=50, seed=7) == evaluate(n_per_kind=50, seed=7)
