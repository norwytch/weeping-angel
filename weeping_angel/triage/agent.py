"""A ReAct triage agent: an LLM reasons over the evidence through read-only tools
(reason -> tool call -> observation, looped) and outputs a calibrated
benign-likelihood, which the deterministic policy maps to a hold/no-hold the same
way the linear :class:`~weeping_angel.triage.score.TriageScorer` does.

It is the same ``assess(...) -> TriageReport`` interface as the linear scorer, so
it drops in behind :func:`weeping_angel.triage.gated_decide` unchanged. When the
Anthropic SDK or an API key is unavailable, or any API call fails, it falls back
to the linear scorer -- so the framework stays runnable and CI stays green with
zero configuration.

Safety: the agent only ever *reads* evidence and outputs a probability;
``response.decide`` maps a hold to a strict downgrade. An agent that mis-assesses
can at worst miss an auto-response a human still sees -- it can never escalate.
The model produces the benign-likelihood; the threshold-to-hold mapping stays
deterministic and shared with the linear baseline.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any

from ..detector import Finding
from ..witnesses import MACE
from . import tools as _tools
from .report import TriageReport
from .score import _HOLD_THRESHOLD, TriageScorer, _disposition

DEFAULT_MODEL = "claude-opus-4-8"

_SYSTEM = """\
You are a digital-forensics triage agent for an NTFS timestomping detector \
(MITRE ATT&CK T1070.006). A file's timestamp was flagged as possibly forged. Your \
job is to judge how likely the touch was BENIGN -- a legitimate tool (backup, \
restore, installer) setting a timestamp -- versus a forgery by malware hiding its \
tracks.

Work in the ReAct style: think, call one tool to inspect a facet of the evidence, \
read the observation, then continue, until you are ready to conclude. Weigh, at \
least: who performed the write (a trusted actor argues benign), which direction \
the time moved (backdating argues forgery), whether the displayed times are \
suspiciously whole-second, and how many independent rules corroborate.

Then call conclude_triage with a calibrated benign_likelihood (0.0-1.0) and a \
short evidence-grounded rationale. You can only make the responder MORE cautious: \
a high benign_likelihood asks it to hold an automated action so a human reviews \
it. A wrong hold costs a missed auto-response (a human still sees the alert); it \
never escalates. Be well-calibrated, not reflexively cautious."""


class TriageAgent:
    """ReAct triage backed by Claude, with a linear-scorer fallback.

    Parameters
    ----------
    model: the Claude model id (defaults to the latest Opus).
    client: an Anthropic-compatible client (anything with ``messages.create``).
        Injected for tests; if omitted, one is constructed from the environment.
    max_iterations: cap on reason/act rounds before falling back.
    fallback: the assessor used when the agent can't run; defaults to
        :class:`TriageScorer`.
    """

    def __init__(
        self,
        *,
        model: str = DEFAULT_MODEL,
        client: Any | None = None,
        max_iterations: int = 6,
        fallback: TriageScorer | None = None,
    ) -> None:
        self.model = model
        self.max_iterations = max_iterations
        self._client = client
        self._fallback = fallback or TriageScorer()

    def _client_or_none(self) -> Any | None:
        if self._client is not None:
            return self._client
        try:
            import anthropic
        except ImportError:
            return None
        try:
            # Resolves ANTHROPIC_API_KEY from the environment; raises if unset.
            return anthropic.Anthropic()
        except Exception:
            return None

    def assess(
        self,
        file_id: str,
        findings: Sequence[Finding],
        display: MACE | None,
        setinfo_events: Iterable[dict],
        trusted_actors: set[str] | None = None,
    ) -> TriageReport:
        findings = list(findings)
        events = list(setinfo_events)
        trusted = trusted_actors or set()

        client = self._client_or_none()
        if client is None:
            return self._fallback.assess(file_id, findings, display, events, trusted)
        try:
            return self._run(client, file_id, findings, display, events, trusted)
        except Exception:
            # Any API/transport failure degrades to the deterministic scorer
            # rather than failing the responder. Caution is the default state.
            return self._fallback.assess(file_id, findings, display, events, trusted)

    def _run(
        self,
        client: Any,
        file_id: str,
        findings: list[Finding],
        display: MACE | None,
        events: list[dict],
        trusted: set[str],
    ) -> TriageReport:
        messages: list[dict] = [
            {"role": "user", "content": _tools.evidence_summary(file_id, findings)}
        ]
        for _ in range(self.max_iterations):
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
                break  # model stopped without concluding -> fall back

            conclusion = next((b for b in tool_uses if b.name == _tools.CONCLUDE), None)
            if conclusion is not None:
                return self._report(file_id, conclusion.input)

            # Echo the assistant turn back (thinking + tool_use blocks intact),
            # then return one observation per inspection tool and continue.
            messages.append({"role": "assistant", "content": response.content})
            results = [
                {
                    "type": "tool_result",
                    "tool_use_id": tu.id,
                    "content": _tools.run_tool(
                        tu.name,
                        tu.input,
                        findings=findings,
                        display=display,
                        setinfo_events=events,
                        trusted_actors=trusted,
                    ),
                }
                for tu in tool_uses
            ]
            messages.append({"role": "user", "content": results})

        # Never concluded within the budget -> deterministic fallback.
        return self._fallback.assess(file_id, findings, display, events, trusted)

    def _report(self, file_id: str, conclusion: dict) -> TriageReport:
        # The agent supplies the probability; the threshold->hold mapping stays
        # deterministic and identical to the linear scorer's.
        p = min(1.0, max(0.0, float(conclusion.get("benign_likelihood", 0.0))))
        rationale = str(conclusion.get("rationale", "")).strip()[:500]
        return TriageReport(
            file_id=file_id,
            benign_likelihood=p,
            disposition=_disposition(p),
            recommend_hold=p >= _HOLD_THRESHOLD,
            contributions=(),
            rationale=rationale,
        )


def make_assessor() -> TriageAgent:
    """Return a triage assessor: the ReAct agent when it can run, otherwise the
    linear scorer (the agent falls back to it internally). Either way you get an
    object with ``assess(...) -> TriageReport``."""
    return TriageAgent()
