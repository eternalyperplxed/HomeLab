variable "pm_url" {
  description = "URL of the Proxmox server"
  type        = string
  default     = env("PM_URL")
}

variable "pm_user" {
  description = "Username used to connect to the Proxmox Server"
  type        = string
  default     = env("PM_USER")
}

variable "pm_token" {
  description = "API token used to connect to the Proxmox Server"
  type        = string
  default     = env("PM_TOKEN")
}

variable "pm_src_id" {
  description = "ID of source template to clone"
  type        = number
  default     = 9000
}

variable "pm_node" {
  description = "Name of the node in the Proxmox environemnt to build on"
  type        = string
  default     = "proxmox"
}

variable "pm_template_name" {
  description = "Name of the template for Packer to create"
  type        = string
  default     = "ubuntu2204cis"
}

