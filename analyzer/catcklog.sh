#!/bin/bash

echo "[95m[C] [Ranking]	[Distan]	[                Funtion]	[Return values][0m"
sort -k3 -g -r $1/*.log  | less -R
