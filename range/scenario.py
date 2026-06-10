"""Range scenario harness: inject timestomp activity, then detect it.

Run after ``terraform apply`` has provisioned the endpoint containers (each
running ``recorder watch``). For every endpoint this harness:

  1. creates and writes a file inside the watched dir (the recorder logs the
     true create/write times to its out-of-band ledger),
  2. timestomps the file by rolling its mtime back to 1970 (`touch -d`),
  3. reads the displayed (now-forged) mtime and the recorder's ledger,
  4. runs the DivergenceDetector: the displayed mtime predates the true last
     write the recorder captured, so R2 fires, and
  5. feeds the findings to the ResponsePolicy (dry-run) for a recommended action.

The point: detection uses only the recorder's out-of-band timeline, which the
"malware" (the touch) could not reach. Requires a running Docker daemon and the
applied range; it talks to the containers via ``docker exec``.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time

from quantumlock.detector import DivergenceDetector
from quantumlock.ledger import Ledger
from quantumlock.response import ResponsePolicy
from quantumlock.witnesses import MACE, DisplayWitness, JournalWitness, MFTWitness

WATCH = "/watch"
LEDGER = "/ledger/ledger.jsonl"
TARGET = "secret.bin"
POLL = 0.8  # a little longer than the recorder's 0.5s poll


def dexec(container: str, *cmd: str, check: bool = True) -> str:
    out = subprocess.run(
        ["docker", "exec", container, *cmd], capture_output=True, text=True
    )
    if check and out.returncode != 0:
        raise RuntimeError(f"{container}: {' '.join(cmd)}\n{out.stderr}")
    return out.stdout


def endpoints() -> list[str]:
    out = subprocess.run(
        ["docker", "ps", "--filter", "name=wa-endpoint-", "--format", "{{.Names}}"],
        capture_output=True,
        text=True,
    )
    return sorted(n for n in out.stdout.split() if n)


def inject(container: str) -> None:
    path = f"{WATCH}/{TARGET}"
    dexec(container, "sh", "-c", f"echo created > {path}")  # create
    time.sleep(POLL)
    dexec(container, "sh", "-c", f"echo more >> {path}")  # genuine write
    time.sleep(POLL)
    dexec(container, "touch", "-d", "1970-01-01T00:00:00", path)  # the stomp
    time.sleep(POLL)


def journal_from_recorder(container: str) -> Ledger:
    """Load the recorder's ledger and re-express its nanosecond timestamps as
    seconds so the witness lines up with stat's second-resolution mtime."""
    raw = dexec(container, "cat", LEDGER)
    journal = Ledger()
    for line in raw.splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        journal.append(rec["event"], recorded_at=rec["recorded_at"] / 1e9)
    return journal


def scan(container: str) -> None:
    inject(container)
    journal = journal_from_recorder(container)
    recs = journal.records_for(TARGET)
    if not recs:
        print(f"  {container}: recorder captured nothing (is it running?)")
        return

    displayed_mtime = float(dexec(container, "stat", "-c", "%Y", f"{WATCH}/{TARGET}").strip())
    true_birth = recs[0].recorded_at

    display = DisplayWitness()
    display.set_times(TARGET, MACE(modified=displayed_mtime, created=true_birth))
    mft = MFTWitness()
    mft.record_birth(TARGET, true_birth)
    detector = DivergenceDetector(display, mft, JournalWitness(journal), now=time.time())

    findings = detector.scan(TARGET)
    audit = Ledger()
    decision = ResponsePolicy(ledger=audit).decide(TARGET, findings)
    rules = ", ".join(f.rule for f in findings) or "none"
    print(f"  {container}: rules=[{rules}] -> {decision.action.name} "
          f"(confidence {decision.confidence:.2f}, dry_run={decision.dry_run})")


def main() -> int:
    hosts = endpoints()
    if not hosts:
        print("No endpoint containers found. Run `terraform apply` in range/ first.")
        return 1
    print(f"Injecting timestomp activity on {len(hosts)} endpoint(s):\n")
    for h in hosts:
        scan(h)
    print("\nDetection used only the recorder's out-of-band ledger; the stomp could not reach it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
