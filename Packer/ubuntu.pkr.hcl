packer {
  required_plugins {
    proxmox = {
      version = ">= 1.1.3"
      source  = "github.com/hashicorp/proxmox"
    }
  }
}

source "proxmox-clone" "ubuntu-2204" {
  proxmox_url              = var.pm_url
  insecure_skip_tls_verify = "false" #My Proxmox server is secured with a Let's Encrypt certificate, if yours is using a self signed certificate, change this to true!
  full_clone               = false
  clone_vm_id              = var.pm_src_id
  template_name            = var.pm_template_name
  username                 = var.pm_user
  node                     = "proxmox"
  ssh_username             = "ubuntu"
  cloud_init               = true
  token                    = var.pm_token
  qemu_agent               = true
  task_timeout             = "5m"
  scsi_controller          = "virtio-scsi-pci"
}

build {
  sources = ["proxmox-clone.ubuntu-2204"]

  provisioner "shell" {
    execute_command = "echo 'ubuntu' | sudo -S sh -c '{{ .Vars }} {{ .Path }}'"
    scripts         = ["../scripts/ubuntu/2204/utilities.sh", "../scripts/ubuntu/2204/disk.sh", "../scripts/ubuntu/2204/cis_lvl1_v1_0_0/cis.sh"]
  }
}
