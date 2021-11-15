#!/bin/bash
# SPDX-License-Identifier: MIT

OUT=$(dirname "$0")/../linux-3.17/fss-out

LAST_DIR=$OUT/$(ls -1t $OUT | head -1)
DIFF_TOOL=${DIFF_TOOL:-kdiff3}
DIFF_DIR=${1:-$LAST_DIR}

$DIFF_TOOL $DIFF_DIR/*.file_operations.compat_ioctl.*
$DIFF_TOOL $DIFF_DIR/*.file_operations.fallocate.*
$DIFF_TOOL $DIFF_DIR/*.file_operations.fsync.*
$DIFF_TOOL $DIFF_DIR/*.file_operations.llseek.*
$DIFF_TOOL $DIFF_DIR/*.file_operations.mmap.*
$DIFF_TOOL $DIFF_DIR/*.file_operations.open.*
$DIFF_TOOL $DIFF_DIR/*.file_operations.read.*
$DIFF_TOOL $DIFF_DIR/*.file_operations.read_iter.*
$DIFF_TOOL $DIFF_DIR/*.file_operations.release.*
$DIFF_TOOL $DIFF_DIR/*.file_operations.splice_read.*
$DIFF_TOOL $DIFF_DIR/*.file_operations.unlocked_ioctl.*
$DIFF_TOOL $DIFF_DIR/*.file_operations.write.*
$DIFF_TOOL $DIFF_DIR/*.file_operations.write_iter.*
$DIFF_TOOL $DIFF_DIR/*.inode_operations.fiemap.*
$DIFF_TOOL $DIFF_DIR/*.inode_operations.get_acl.*
$DIFF_TOOL $DIFF_DIR/*.inode_operations.getattr.*
$DIFF_TOOL $DIFF_DIR/*.inode_operations.getxattr.*
$DIFF_TOOL $DIFF_DIR/*.inode_operations.listxattr.*
$DIFF_TOOL $DIFF_DIR/*.inode_operations.permission.*
$DIFF_TOOL $DIFF_DIR/*.inode_operations.removexattr.*
$DIFF_TOOL $DIFF_DIR/*.inode_operations.set_acl.*
$DIFF_TOOL $DIFF_DIR/*.inode_operations.setattr.*
$DIFF_TOOL $DIFF_DIR/*.inode_operations.setxattr.*
