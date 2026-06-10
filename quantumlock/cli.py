"""Unified command-line entry point: ``weeping-angel <command>``.

Ties the pieces into one tool:

    weeping-angel scan <mft> [--format ecs|ocsf]   scan a raw $MFT (human or SIEM output)
    weeping-angel verify-ledger <ledger.jsonl>     re-check a hash-chained ledger
    weeping-angel efficacy                          precision/recall over a labeled corpus
    weeping-angel arena [--episodes N]              run the adversarial arena scoreboard
"""

from __future__ import annotations

import argparse

from . import efficacy as _efficacy
from .adapters import mft as _mft
from .ledger import Ledger


def _cmd_scan(args: argparse.Namespace) -> int:
    argv = [args.mft]
    if args.format:
        argv += ["--format", args.format]
    return _mft.main(argv)


def _cmd_verify_ledger(args: argparse.Namespace) -> int:
    ledger = Ledger.load(args.ledger)
    result = ledger.verify()
    if result.ok:
        print(f"OK: {len(ledger)} records, chain intact")
        return 0
    print("TAMPERED:")
    for problem in result.problems:
        print("  -", problem)
    return 1


def _cmd_efficacy(args: argparse.Namespace) -> int:
    return _efficacy.main()


def _cmd_arena(args: argparse.Namespace) -> int:
    from .arena import BLUE_BASELINES, RED_BASELINES, ArenaConfig, tournament

    cfg = ArenaConfig()
    results = tournament(BLUE_BASELINES, RED_BASELINES, base=cfg, episodes=args.episodes)
    reds = list(RED_BASELINES)
    print(f"Arena: {cfg.n_angels} angels on {cfg.n_files} files, "
          f"{cfg.coverage_budget}/tick coverage, {args.episodes} episodes\n")
    print("blue \\ red    " + "".join(f"{r:>14}" for r in reds))
    for blue in BLUE_BASELINES:
        cells = [f"{results[(blue, r)].blue_detection_rate:5.0%} caught" for r in reds]
        print(f"  {blue:<10}" + "".join(f"{c:>14}" for c in cells))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="weeping-angel", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="scan a raw $MFT for timestomp indicators")
    p_scan.add_argument("mft", help="path to a raw $MFT image")
    p_scan.add_argument("--format", choices=["ecs", "ocsf"], help="emit findings as SIEM JSONL")
    p_scan.set_defaults(func=_cmd_scan)

    p_verify = sub.add_parser("verify-ledger", help="re-check a hash-chained ledger")
    p_verify.add_argument("ledger", help="path to a JSONL ledger")
    p_verify.set_defaults(func=_cmd_verify_ledger)

    p_eff = sub.add_parser("efficacy", help="precision/recall over a labeled corpus")
    p_eff.set_defaults(func=_cmd_efficacy)

    p_arena = sub.add_parser("arena", help="run the adversarial arena scoreboard")
    p_arena.add_argument("--episodes", type=int, default=100, help="episodes per matchup")
    p_arena.set_defaults(func=_cmd_arena)

    p_learn = sub.add_parser("learn", help="train an arena blue agent with Evolution Strategies")
    p_learn.add_argument("--generations", type=int, default=20)
    p_learn.set_defaults(func=_cmd_learn)

    return parser


def _cmd_learn(args: argparse.Namespace) -> int:
    from .learn import train

    weights, history = train(generations=args.generations, seed=1)
    print("fitness (mean reward) by generation:")
    print("  " + "  ".join(f"{h:+.2f}" for h in history))
    print(f"\nlearned weights: [{', '.join(f'{x:.3f}' for x in weights)}]")
    print(f"improvement: {history[0]:+.2f} -> {history[-1]:+.2f}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
