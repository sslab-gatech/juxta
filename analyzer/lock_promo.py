#!/usr/bin/env python2
# SPDX-License-Identifier: MIT

import os
import sys
import optparse
import collections

import multiprocessing as mp

import dbg
import utils
import lock

from path import PathCall
from path import PathStore

from parser import Parser

ROOT = os.path.dirname(__file__)

def explore_path(path):
    locks = []
    unlocks = []
    for e in path.effects:
        if isinstance(e, PathCall):
            if lock.is_lock(e.func):
                locks.append(e)
            if lock.is_unlock(e.func):
                unlocks.append(e)
        if len(locks) > 3 or len(unlocks) > 3:
            break
    return (locks, unlocks)

def get_promotion_target(path):
    (locks, unlocks) = explore_path(path)
    # too many un/locks
    if len(locks) != 0 and len(unlocks) != 0:
        return None
    # no single un/lock
    if len(locks) == 0 and len(unlocks) == 0:
        return None
    # too many single un/locks
    if len(locks) > 3 or len(unlocks) > 3:
        return None
    return "lock" if len(locks) else "unlock"

def check_all_paths(promos):
    # does it all same?
    if all("lock" == typ for (typ, _) in promos):
        return "lock"
    if all("unlock" == typ for (typ, _) in promos):
        return "unlock"
    return None

def analyze_lock_promo(out_d):
    promo = collections.defaultdict(list)
    for path in Parser(out_d).parse():
        f = path.get_target()
        typ = get_promotion_target(path)
        promo[f.func].append((typ, f))

    for (key, vals) in promo.iteritems():
        promo = check_all_paths(vals)
        nlock = len([typ for (typ, _) in vals if "lock" == typ])
        nunlock = len([typ for (typ, _) in vals if "unlock" == typ])
        print "%-30s: %10s/%s/%s (%s) %s" % (key, promo, nlock, nunlock, len(vals), vals)
        # if promo:
        #     print "%-30s: %10s (%s)" % (key, promo, len(vals))

        # # single lock
        # f = path.get_target()
        # if not f.func in promo:
        #     typ = "unlock"
        #     if lock.is_lock(f.func):
        #         typ = "lock"
        #     entry = (typ, f.func)
        #     print("'%s': '%s'," % entry)
        #     promo.add(entry)

def load_promo_log(pn):
    funcs = {}
    for l in open(pn):
        (func, lock) = l.split(":", 1)
        func = func.strip()
        lock = lock.strip()
        lock = lock.replace("@", " @LOCATION: ")
        funcs[func] = PathCall(lock)
    return funcs

if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option("--promo", "-p", help="list of promo log", default=None)
    (opts, args) = parser.parse_args()

    # load other targets
    if opts.promo:
        BOOTSTRAP.update(load_promo_log(opts.promo).keys())

    utils.install_pdb()

    # pick the latest one from /tmp
    log_d = utils.get_latest_file("/tmp/fss-*/")
    if log_d is None:
        # second choice
        log_d = os.path.join(ROOT, "data", "sample-fss-output")
    # perfered one
    if len(args) >= 1:
        log_d = args[0]

    # enable trace output on unittest
    if not "unit" in log_d:
        dbg.quiet(["trace"])

    analyze_lock_promo(log_d)
