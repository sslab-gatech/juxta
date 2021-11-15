#!/bin/bash
# SPDX-License-Identifier: MIT

source $(dirname "$0")/conf.sh

if [[ $# != 1 ]]; then
  echo "$0 [linux/]file.c"
  exit 1
fi

IR="${1#linux-*/}"
IR="${IR%%.c}"
IR="${IR%%.ll}"
IR=$IR.ll

$TOP/gen.sh $IR
llvm-as < $LNX/$IR | opt -analyze -view-cfg
