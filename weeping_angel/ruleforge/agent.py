"""A detection-engineering agent: an LLM that *writes new detection rules*.

Unlike the triage agent (which judges one file), this one improves the detector
itself. It runs a closed loop with a real reward signal: propose a candidate
rule, score it against the labeled corpus with the precision/recall harness, read
the result, and revise -- committing rules that add coverage without false
positives until the acceptance bar is met. The feedback signal is what makes the
loop *converge* instead of producing plausible-sounding rules that don't work.

Same shape as the triage agent: optional ``[agent]`` extra, and a deterministic
greedy :class:`~weeping_angel.ruleforge.miner.RuleMiner` fallback when there is no
SDK/key or a call fails. The agent's output is a *proposal*: discovered rules are
scored and explained, but promoting one into ``detector.py`` is a human review
step -- the agent never edits the detector or executes its own rules as code.
"""

from __future__ import annotations

import json
from typing import Any

from . import tools as _tools
from .corpus import Bar, Case, RuleSetResult, build_corpus, score_ruleset
from .miner import RuleMiner
from .rule import CandidateRule, parse_rule

DEFAULT_MODEL = "claude-opus-4-8"

_SYSTEM = """\
You are a detection-engineering agent for an NTFS timestomping detector. Your job \
is to discover detection RULES that separate forged timestamps from legitimate \
ones, measured by precision and recall on a labeled corpus.

A rule is structured data (never code): a `compare` of two evidence fields with a \
tolerance, a `whole_second` check on one field, or an `all_of` conjunction of two \
to four of those. Call list_fields for the grammar. The corpus has clean files, \
benign timestamp-setting (backup/restore/cp -p, which you must NOT flag), and \
several timestomp variants you must catch.

Work the closed loop: inspect_corpus to see what's still uncaught, propose a rule \
and evaluate_rule to score it, commit_rule when it adds true positives with zero \
new false positives, and repeat until recall and precision clear the bar. A false \
positive on a benign file is worse than a miss, so never commit a rule that adds \
one. Some forgeries are caught by no single comparison without a false positive on \
some benign file -- when evaluate_rule shows every single clause you try adds a \
false positive, reach for an `all_of` conjunction whose clauses are individually \
impure but jointly clean. Call finish when the rule set meets the bar or you can \
do no better. Prefer the smallest rule set that works."""


class RuleEngineerAgent:
    """ReAct rule-mining backed by Claude, with a deterministic miner fallback."""

    def __init__(
        self,
        *,
        model: str = DEFAULT_MODEL,
        client: Any | None = None,
        max_iterations: int = 10,
        bar: Bar | None = None,
        fallback: RuleMiner | None = None,
    ) -> None:
        self.model = model
        self.max_iterations = max_iterations
        self.bar = bar or Bar()
        self._client = client
        self._fallback = fallback or RuleMiner(self.bar)

    def _client_or_none(self) -> Any | None:
        if self._client is not None:
            return self._client
        try:
            import anthropic
        except ImportError:
            return None
        try:
            return anthropic.Anthropic()  # resolves ANTHROPIC_API_KEY; raises if unset
        except Exception:
            return None

    def engineer(self, corpus: list[Case] | None = None) -> RuleSetResult:
        corpus = corpus if corpus is not None else build_corpus()
        client = self._client_or_none()
        if client is None:
            return self._fallback.mine(corpus)
        try:
            result = self._run(client, corpus)
        except Exception:
            return self._fallback.mine(corpus)
        # If the agent committed nothing usable, fall back rather than ship empty.
        if not result.rules:
            return self._fallback.mine(corpus)
        return result

    def _run(self, client: Any, corpus: list[Case]) -> RuleSetResult:
        ruleset: list[CandidateRule] = []
        log: list[str] = []
        messages: list[dict] = [{
            "role": "user",
            "content": (
                "Engineer a rule set for this corpus. Acceptance bar: "
                f"precision >= {self.bar.min_precision}, recall >= {self.bar.min_recall}. "
                "Start by inspecting the corpus."
            ),
        }]
        iterations = 0
        while iterations < self.max_iterations:
            iterations += 1
            response = client.messages.create(
                model=self.model,
                max_tokens=1024,
                system=_SYSTEM,
                tools=_tools.TOOL_SCHEMAS,
                thinking={"type": "adaptive"},
                messages=messages,
            )
            tool_uses = [b for b in response.content if getattr(b, "type", None) == "tool_use"]
            if not tool_uses:
                break

            messages.append({"role": "assistant", "content": response.content})
            results = []
            finished = False
            for tu in tool_uses:
                obs, done = self._handle(tu.name, tu.input, corpus, ruleset, log)
                finished = finished or done
                results.append({"type": "tool_result", "tool_use_id": tu.id, "content": obs})
            messages.append({"role": "user", "content": results})
            if finished:
                break

        return RuleSetResult(
            rules=tuple(ruleset),
            score=score_ruleset(ruleset, corpus),
            source="agent",
            iterations=iterations,
            log=tuple(log),
        )

    def _handle(
        self,
        name: str,
        tool_input: dict,
        corpus: list[Case],
        ruleset: list[CandidateRule],
        log: list[str],
    ) -> tuple[str, bool]:
        """Execute one tool call. Returns (observation, is_terminal)."""
        if name == "list_fields":
            return _tools.describe_fields(), False
        if name == "inspect_corpus":
            return _tools.summarize_corpus(corpus, ruleset), False
        if name == "evaluate_rule":
            return _tools.eval_candidate(tool_input, corpus, ruleset), False
        if name == _tools.COMMIT:
            try:
                rule = parse_rule(tool_input)
            except ValueError as exc:
                return json.dumps({"error": str(exc)}), False
            if rule.key() not in {r.key() for r in ruleset}:
                ruleset.append(rule)
                log.append(f"committed [{rule.describe()}]")
            return _tools.summarize_corpus(corpus, ruleset), False
        if name == _tools.FINISH:
            return json.dumps({"status": "done"}), True
        return json.dumps({"error": f"unknown tool {name}"}), False


def make_rule_engineer(bar: Bar | None = None) -> RuleEngineerAgent:
    """Return a rule-engineering assessor: the ReAct agent when it can run,
    otherwise the deterministic miner (the agent falls back to it internally)."""
    return RuleEngineerAgent(bar=bar)
