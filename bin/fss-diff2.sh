#!/bin/bash
# SPDX-License-Identifier: MIT
DIFF_TOOL=kdiff3
DIFF_DIR=$1

$DIFF_TOOL $DIFF_DIR/ebc/*.setattr.* 
$DIFF_TOOL $DIFF_DIR/ebf/*.setattr.* 
$DIFF_TOOL $DIFF_DIR/exc/*.setattr.* 
$DIFF_TOOL $DIFF_DIR/ebc/*.write_iter.* 
$DIFF_TOOL $DIFF_DIR/ebf/*.write_iter.* 
$DIFF_TOOL $DIFF_DIR/exf/*.write_iter.* 
$DIFF_TOOL $DIFF_DIR/ebc/*.llseek.*
$DIFF_TOOL $DIFF_DIR/ebc/*.mmap.* 
$DIFF_TOOL $DIFF_DIR/exf/*.fallocate.* 
