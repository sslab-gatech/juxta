#!/bin/sh
# SPDX-License-Identifier: MIT

source $(dirname "$0")/conf.sh

(cd $LNX; make CC=clang HOSTCC=clang "$@")
