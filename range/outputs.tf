output "endpoints" {
  description = "Names of the provisioned endpoint containers."
  value       = docker_container.endpoint[*].name
}

output "image" {
  description = "The locally built recorder image."
  value       = docker_image.recorder.name
}

output "next_step" {
  description = "Inject timestomp activity and scan the collected ledgers."
  value       = "python range/scenario.py"
}
