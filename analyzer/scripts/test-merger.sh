#!/bin/bash -eu
# SPDX-License-Identifier: MIT

LINUX=${1:-../linux-3.17}

while read d; do
  if [[ ! $d =~ \#.* ]]; then
    ./merger.py -l ${LINUX} $d
    (cd out/$d; make -f Makefile.build)
  fi
done <<EOF
# 9p
# adfs
# affs
# afs
# autofs4
# befs
# bfs
# btrfs
# ceph
# cifs
# coda
# XXX. configfs (to_item, static inline .h as well)
# cramfs
# XXX. debugfs
# devpts
# dlm
# ecryptfs
# efivarfs
# efs
# XXX. exofs (no makefile)
# exportfs
# ext2
# ext3
# ext4
# f2fs
# fat
# freevxfs
# XXX. fscache
# fuse
# XXX. gfs2 (missing ./trace_gfs2.h?)
# hfs
# hfsplus
# XXX. hostfs (uml)
# hpfs
# hppfs
# hugetlbfs
# isofs
# jbd
# jbd2
# jffs2
# jfs
# XXX. kernfs
# XXX. lockd
# logfs
# minix
# ncpfs
# XXX. nfs
# XXX. nfs_common
# nfsd
# nilfs2
# XXX. nls
# XXX. notify
# ntfs
# ocfs2
# omfs
# XXX. openpromfs
# XXX. proc
# XXX. pstore
# qnx4
# qnx6
# quota
# ramfs
# XXX. reiserfs
# XXX. romfs
# squashfs
# sysfs
# sysv
# ubifs
# udf
# ufs
# xfs
EOF
