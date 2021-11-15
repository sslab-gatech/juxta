#!/bin/sh
# SPDX-License-Identifier: MIT

DISK=${DISK:-"fs.img"}
KERN=${KERN:-"$HOME/refs/linux-git/arch/x86_64/boot/bzImage"}

# debug: -D qemulog.log -d in_asm,op,int,exec,cpu,cpu_reset
KVM=${KVM:-"-enable-kvm"}
ARG=${ARG:-"-curses"}
CMD=${CMD:-"root=/dev/sda"}

# load kvm
(lsmod | grep -q kvm) || {
  echo "[!] loading kvm module"
  sudo modprobe kvm-intel
}

# invoke
qemu-system-x86_64 \
  -hda "$DISK" \
  -kernel "$KERN" \
  -append "$CMD" \
  $KVM \
  $ARG \
  "$@"
