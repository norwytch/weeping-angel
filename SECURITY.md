# Security Policy

Weeping Angel is a defensive digital-forensics project: it detects NTFS
timestomping (MITRE ATT&CK T1070.006) by comparing multiple timestamp witnesses
and recording the result in a tamper-evident ledger. Because it parses
attacker-controllable evidence and can drive automated response, its own
security matters. This document explains how to report issues and what to expect.

## Reporting a vulnerability

Please report security issues privately. Do not open a public issue for
anything that could be exploited.

1. Preferred: GitHub private vulnerability reporting. Go to the repository's
   **Security** tab and choose **Report a vulnerability**. This opens a private
   advisory visible only to the maintainers.
2. If that is unavailable, open a regular issue that contains only "security
   report, please enable private reporting" with no details, and a maintainer
   will follow up with a private channel.

Please include:

- the affected component (see Scope below) and version or commit,
- a description of the issue and its impact,
- steps or a minimal sample to reproduce (for parser issues, attach the smallest
  `$MFT` / USN fragment that triggers it),
- any suggested fix.

Expect an acknowledgement within a few days. This is a personal open-source
project, so timelines are best-effort rather than contractual. Coordinated
disclosure is appreciated: give the maintainer a reasonable window to ship a fix
before publishing details.

## Supported versions

The project is pre-1.0 and moves on `main`. Security fixes land on `main`; there
are no backported release branches. Pin a commit if you depend on it.

## Scope

In scope, in rough order of sensitivity:

- **Binary parsers** (`weeping_angel/adapters/mft.py`, `weeping_angel/adapters/usn.py`).
  These read untrusted, attacker-controlled forensic artifacts. Out-of-bounds
  reads, infinite loops, unbounded allocation, or any crash on malformed input
  are in scope.
- **Response / rules-of-engagement layer** (`weeping_angel/response.py`). Any
  path that lets an action execute outside the configured rules of engagement,
  bypasses the protected-file, dry-run, or triage cap, or causes an action to run
  without a corresponding ledger entry. The cap (protected-file and triage hold)
  is applied before execution by design; a path that executes an un-capped action
  and only relabels the result afterwards would be in scope.
- **Triage agent** (`weeping_angel/triage/`). The optional Claude ReAct agent
  reasons over evidence and can recommend holding a response. Two properties are
  load-bearing and in scope: it must only ever *de-escalate* (never raise an
  action or cause execution), and an API/transport failure or malformed model
  output must degrade to the deterministic linear scorer rather than fail open.
  Evidence strings (file ids, actor names) are attacker-influenced and reach the
  model, so prompt-injection that flips the agent toward a *hold* is expected; the
  downgrade-only invariant is what bounds it (see Operating notes).
- **Ledger and anchor** (`weeping_angel/ledger.py`, `weeping_angel/anchor.py`,
  and the Go recorder in `recorder/`). Hash-chain or HMAC weaknesses that let a
  record be edited, reordered, or truncated without detection, or any divergence
  between the Go and Python implementations of the canonical hash preimage.
- **Findings exporter** (`weeping_angel/export.py`). Injection into the ECS/OCSF
  output that could mislead or exploit a downstream SIEM.

Out of scope:

- The bot-vs-bot arena, learned agent, and Kaggle environment use the standard
  pseudo-random generator (`random`) for game logic. This is intentional and not
  a cryptographic context.
- Demonstration secrets in tests and examples (for instance the sample HMAC
  anchor key) are illustrative and not real credentials.
- The Terraform range (`range/`) provisions a local Docker lab for testing. It is
  not meant to be exposed to untrusted networks.

## Operating notes

This is research and portfolio code. It demonstrates the integrity properties
rather than shipping a hardened production agent. If you run it against real or
hostile data, keep these in mind:

- Run parsers on copies of evidence, ideally in an isolated environment. They are
  bounds-checked and stream large files via `mmap`, but treat all input as hostile.
- The response layer defaults to **dry-run**: it decides and records but does not
  execute. Enabling execution is opt-in and runs whatever executors you register,
  so review your rules of engagement and executors before turning it off.
- The ledger's integrity guarantee assumes the head is anchored off-box (the HMAC
  anchor). An attacker with write access to the local ledger file can still
  truncate the tail; the anchor is what closes that gap. Ledger files are created
  with owner-only (0600) permissions.
- The triage agent is **opt-in** (the `[agent]` extra plus an API key); the
  default linear scorer runs locally and sends nothing off-box. Enabling the agent
  transmits evidence metadata (file ids, rule names, timestamps, actor names) to
  the LLM provider, so treat it as you would any third-party analytics path and
  do not enable it on data you may not disclose. Its influence is bounded by
  construction: it only reads evidence and can only ask the responder to hold, so
  the worst case of a mis-assessment or a prompt-injection in the evidence is a
  missed auto-response that a human still sees in the alert, never an escalation.
  Treat agent holds as advisory, and keep a human in the loop before relying on
  them to suppress a response.
