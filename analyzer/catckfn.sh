#!/bin/bash

cat `grep $2 $1/* | awk 'BEGIN { FS=":" } {print $1}'` | less -R

