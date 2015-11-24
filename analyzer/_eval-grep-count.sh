#!/bin/bash -e
# $1 : directory
# $2 : grep pattern
cd $1
#grep -R --include *.fss $2|wc -l
grep "$2" *.fss |wc -l

