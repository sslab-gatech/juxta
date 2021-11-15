#!/usr/bin/env python2
# SPDX-License-Identifier: MIT

import os
import sys
import optparse

import multiprocessing as mp

import dbg
import utils

from path import PathCall
from path import PathStore

from parser import Parser

from lock_promo import load_promo_log

ROOT = os.path.dirname(__file__)

# do all possible paths contain one un/lock?
def explore_path(path, match):
    m = []
    for l in path.effects:
        if isinstance(e, PathCall):
            if e.func == match.func:
                m.append(e)
    # error: if more than single instance
    if len(m) != 1:
        dbg.error("! error (L=%d): %s", len(m), str(path))
        for l in m:
            dbg.error("! NOTE: %s", str(l))

def explore_file(pn, promo):
    for path in Parser().parse_file(pn):
        f = path.get_target().func
        if f in promo:
            explore_path(path, promo[f])

if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option("--promo", "-p",
                      help="list of promo log",
                      default="data/lock-promo.log")
    (opts, args) = parser.parse_args()

    utils.install_pdb()

    # pick the latest one from /tmp
    log_d = utils.get_latest_file("/tmp/fss-*/")
    if log_d is None:
        # second choice
        log_d = os.path.join(ROOT, "data", "sample-fss-output")
    # perfered one
    if len(args) > 1:
        log_d = args[1]

    # enable trace output on unittest
    if not "unit" in log_d:
        dbg.quiet(["trace"])

    promo = load_promo_log(opts.promo)
    dbg.info("# %d loaded, %s", len(promo), log_d)

    pool = mp.Pool(mp.cpu_count())
    for pn in Parser(log_d)._get_files():
        pool.apply_async(explore_file, args=(pn, promo))
    pool.close()
    pool.join()
