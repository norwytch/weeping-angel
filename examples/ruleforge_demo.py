"""Detection-engineering agent demo.

With ANTHROPIC_API_KEY set (and `pip install weeping_angel[agent]`), Claude runs
the ReAct loop: propose a rule, score it against the labeled corpus, commit the
ones that add coverage with no false positives, repeat until the bar is met.
Without a key, the deterministic greedy miner does the same job offline.

    python examples/ruleforge_demo.py
"""

from __future__ import annotations

import os

from weeping_angel.ruleforge import Bar, build_corpus, make_rule_engineer


def main() -> None:
    has_key = bool(os.environ.get("ANTHROPIC_API_KEY"))
    where = "Claude ReAct agent" if has_key else "deterministic miner (no key)"
    print(f"Engineering detection rules with: {where}\n")

    bar = Bar(min_precision=0.95, min_recall=0.95)
    result = make_rule_engineer(bar).engineer(build_corpus())

    print(result.explain())
    print(f"\nmeets bar (precision>={bar.min_precision}, recall>={bar.min_recall}): "
          f"{result.met(bar)}")
    if result.log:
        print("\ntrace:")
        for line in result.log:
            print(f"  {line}")
    print(
        "\nThese are *proposals*: each rule is scored, but promoting one into "
        "detector.py is a human review step."
    )


if __name__ == "__main__":
    main()
