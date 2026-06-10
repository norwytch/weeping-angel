variable "host_count" {
  description = "Number of endpoint containers to provision, each running the recorder."
  type        = number
  default     = 3

  validation {
    condition     = var.host_count >= 1 && var.host_count <= 25
    error_message = "host_count must be between 1 and 25."
  }
}

variable "image_name" {
  description = "Tag for the locally built recorder image."
  type        = string
  default     = "weeping-angel-recorder:latest"
}

variable "watch_dir" {
  description = "Directory inside each container the recorder watches for file ops."
  type        = string
  default     = "/watch"
}

variable "ledger_path" {
  description = "Path inside each container where the recorder writes its JSONL ledger."
  type        = string
  default     = "/ledger/ledger.jsonl"
}
