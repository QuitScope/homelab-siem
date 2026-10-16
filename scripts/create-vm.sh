#!/usr/bin/env bash
# Run on the Proxmox host. Creates the Docker VM (4 vCPU, 8 GB, 50 GB) from the Ubuntu 24.04 cloud image.
# Usage: VMID=210 STORAGE=local-lvm BRIDGE=vmbr0 IPCONFIG="ip=dhcp" SSHKEY=/root/key.pub ./create-vm.sh
#   static IP: IPCONFIG="ip=192.168.1.50/24,gw=192.168.1.1"
set -euo pipefail
VMID=${VMID:-210}
STORAGE=${STORAGE:-local-lvm}
BRIDGE=${BRIDGE:-vmbr0}
IPCONFIG=${IPCONFIG:-ip=dhcp}
SSHKEY=${SSHKEY:?path to public ssh key required}

img=/var/lib/vz/template/iso/noble-server-cloudimg-amd64.img
[ -f "$img" ] || wget -qO "$img" https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img

qm create "$VMID" --name siem-docker --cores 4 --cpu host --memory 8192 \
  --net0 "virtio,bridge=$BRIDGE" --scsihw virtio-scsi-pci --agent 1 --ostype l26 \
  --serial0 socket --vga serial0
qm set "$VMID" --scsi0 "$STORAGE:0,import-from=$img" --boot order=scsi0 \
  --ide2 "$STORAGE:cloudinit" --ciuser siem --sshkeys "$SSHKEY" --ipconfig0 "$IPCONFIG"
qm resize "$VMID" scsi0 50G
qm start "$VMID"
echo "VM $VMID started. Login: ssh siem@<ip>"
