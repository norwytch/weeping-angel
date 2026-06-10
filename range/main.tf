# A minimal local range: build the Go recorder into an image and run it on a
# fleet of endpoint containers, each watching a directory and writing its own
# hash-chained ledger. The scenario harness then injects timestomp activity and
# the Python detector scans the collected ledgers. Docker provider so it runs
# locally with no cloud account; the same config swaps to cloud VMs by changing
# the provider.

provider "docker" {}

# Build the recorder image from the repo root (context one level up so the
# Dockerfile can COPY recorder/).
resource "docker_image" "recorder" {
  name = var.image_name

  build {
    context    = "${path.module}/.."
    dockerfile = "range/Dockerfile"
    tag        = [var.image_name]
  }

  # Rebuild when the recorder source changes.
  triggers = {
    src = sha1(join("", [for f in fileset("${path.module}/../recorder", "**") : filesha1("${path.module}/../recorder/${f}")]))
  }
}

# A private network for the fleet.
resource "docker_network" "range" {
  name = "weeping-angel-range"
}

# One container per endpoint, each running `recorder watch <dir> <ledger>`.
resource "docker_container" "endpoint" {
  count    = var.host_count
  name     = "wa-endpoint-${count.index}"
  image    = docker_image.recorder.image_id
  command  = ["watch", var.watch_dir, var.ledger_path]
  must_run = true

  networks_advanced {
    name = docker_network.range.name
  }

  # Ephemeral working dirs for the watched files and the ledger.
  upload {
    content = "endpoint ${count.index}\n"
    file    = "${var.watch_dir}/.endpoint"
  }
}
