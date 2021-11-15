#!/usr/bin/env python2
# SPDX-License-Identifier: MIT

import os
import glob
import pprint
import collections

import utils

ROOT = os.path.abspath(os.path.dirname(__file__))

category = {}
perfunc = collections.defaultdict(list)
perlock = collections.defaultdict(list)

def normalize(lock):
    if "->i_mutex" in lock:
        return "i_mutex"
    if "->i_lock" in lock:
        return "i_lock"
    return lock

for f in glob.glob("results/*/lock-locked.log"):
    # no report
    if os.stat(f).st_size < 10:
        continue

    (_, fs, pn) = f.split("/")

    log = eval(utils.read_file(f))
    for f, (n, lock) in log.iteritems():
        # trim
        if len(f) > 100:
            continue
        # print "%40s: %10s, %s" % (f, n, lock)

        l = normalize(lock)
        perfunc[f].append((fs, l))
        perlock[l].append((fs, f))
    category[fs] = log

def rank(d):
    return sorted(d.items(), key=lambda e: len(e[1]), reverse=True)

print "=" * 70
for (f, lst) in rank(perfunc):
    print "[%3d] %s" % (len(lst), f)
    for (n, l) in lst:
        print "   %-10s: %s" % (n, l)

print "=" * 70
for (l, lst) in rank(perlock)():
    print "[%3d] %s" % (len(lst), f)
    for (n, f) in lst:
        print "   %-10s: %s" % (n, f)
