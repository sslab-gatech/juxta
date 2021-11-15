#!/bin/bash -e
# SPDX-License-Identifier: MIT

if [[ $# != 3 ]]; then
  echo "usage: $0 [src] [dst] [img]"
  exit 1
fi

SRC=$1
DST=$2
IMG=$3
TMP=/tmp/undosmnt

if [[ $DST =~ ^[^/].* ]]; then
  echo "err: $DST should be the absolute path"
  exit 1
fi

mkdir -p $TMP
sudo mount $IMG $TMP
trap "sudo umount $TMP; rmdir $TMP" EXIT

sudo cp -rf $SRC $TMP/$DST
