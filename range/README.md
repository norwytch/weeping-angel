# range — a Terraform test range

Provisions a small fleet of endpoint containers, each running the Go
[`recorder`](../recorder) in `watch` mode, then injects timestomp activity and
detects it. Uses the Docker provider so it runs locally with no cloud account;
the same config retargets to cloud VMs by swapping the provider.

```
range/
  versions.tf    # required terraform + the kreuzwerker/docker provider
  variables.tf   # host_count, image/watch/ledger paths
  main.tf        # build recorder image, network, one container per endpoint
  outputs.tf     # endpoint names, image, next step
  Dockerfile     # build the recorder, run it as a non-root user
  scenario.py    # inject a stomp on each endpoint, then scan with the detector
```

## Prerequisites

- A running Docker daemon (Docker Desktop, Colima, or `dockerd`).
- Terraform >= 1.5.
- The Python package installed (`pip install -e .` at the repo root) for `scenario.py`.

## Run

```bash
cd range
terraform init
terraform apply -var host_count=3     # builds the image, starts the fleet
python scenario.py                    # inject timestomps, detect, recommend a response
terraform destroy                     # tear it down
```

Expected `scenario.py` output (per endpoint):

```
  wa-endpoint-0: rules=[R2_si_journal_rollback] -> TICKET (confidence 0.60, dry_run=True)
  ...
```

## What it demonstrates

Each endpoint's recorder logs the **true** create/write timeline to its own
hash-chained ledger, out of band. The scenario then rolls a file's mtime back to
1970 (a timestomp). The displayed mtime now predates the last write the recorder
captured, so `R2_si_journal_rollback` fires — detection that relies only on the
out-of-band record the stomp could not reach. The finding flows into the
dry-run response policy for a recommended action.

## Validate without applying

`terraform fmt -check` and `terraform validate` check the config without a
running daemon (CI does this). `terraform apply` needs the daemon.
