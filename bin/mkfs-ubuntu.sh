#!/bin/sh -x
# SPDX-License-Identifier: MIT

DISK=${DISK:-fs.img}
SIZE=${SIZE:-1G}
ROOT=${ROOT:-mnt}
RELS=${RELS:-trusty}
SERV=${SERV:-http://ubuntu.media.mit.edu/ubuntu/}
MKFS=${MKFS:-ext4}
PKGS=${PKGS:-apt}
HOST=${HOST:-vm}

# creating a fs img
if [[ ! -e $DISK ]]; then
  # create disk img
  qemu-img create -f raw $DISK $SIZE || exit 1
  # use ext4
  mkfs -t $MKFS $DISK
fi

# mount / unmount
mkdir -p $ROOT
sudo mount -o loop $DISK $ROOT
trap "sudo umount $ROOT; rmdir $ROOT" 0

# install
sudo debootstrap \
  --arch amd64 \
  --variant=minbase \
  --components=main,universe \
  --include=$PKGS \
  $RELS $ROOT $SERV

# setup default fs
sudo tee $ROOT/etc/fstab <<EOF
/dev/sda /     $MKFS   noatime,rw,defaults 0 0
proc     /proc proc     defaults 0 0
sysfs    /sys  sysfs    defaults 0 0
EOF

# NOTE.
#  - use sda as rootfs
#  - nilfs_cleanerd access /dev/root (as /proc/mounts reports)
#  - make /dev/root point to /dev/sda
#
sudo mknod $ROOT/dev/sda b 8 0
sudo ln -s $ROOT/dev/sda $ROOT/dev/root

# network: enable dhcp
sudo tee /etc/hosts $ROOT/etc/hosts <<EOF
127.0.0.1 localhost
127.0.1.1 $HOST

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
ff02::3 ip6-allhosts
EOF

sudo tee $ROOT/etc/network/interfaces <<EOF
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet dhcp
EOF

sudo tee $ROOT/etc/resolv.conf <<EOF
nameserver 8.8.8.8
nameserver 8.8.4.4
EOF

sudo tee $ROOT/etc/hostname <<EOF
$HOST
EOF

sudo tee $ROOT/etc/apt/sources.list <<EOF
deb $SERV $RELS main
deb-src $SERV $RELS main
EOF

# populate passwd and group if missing
if [[ ! -e $ROOT/etc/passwd ]] ; then
  sudo cp $ROOT/usr/share/base-passwd/passwd.master $ROOT/etc/passwd
fi

if [[ ! -e $ROOT/etc/group ]] ; then
  sudo cp $ROOT/usr/share/base-passwd/group.master $ROOT/etc/group
fi
