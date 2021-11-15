#!/usr/bin/env python2
# SPDX-License-Identifier: MIT

import os
import sys
import re
import pprint
import collections

import lock
import dbg
import utils

from path import PathCall
from path import PathStore

from parser import Parser

ROOT = os.path.abspath(os.path.dirname(__file__))

def explore_path(path, report):
    state = lock.LockState()
    for e in path.effects:
        if state.is_locked():
            state.add(e)

        if isinstance(e, PathCall):
            # like this
            #   extracted from results/lock-locked.log
            if "i_size_read" == e.func:
                dbg.bug_range("XXXX: %s (locked: %s)", str(e), state.is_locked())
                report.add("not protected", e.func, path, e.loc)
            if lock.is_lock(e.func):
                state.lock(e)
            elif lock.is_unlock(e.func):
                state.unlock(e)

    return state

def analyze_fs(fs, out_d, fss_d):
    fd = open(os.path.join(out_d, "lock-range.log"), "w")

    report = lock.ErrReport(fd)
    for path in Parser(fss_d).parse():
        state = explore_path(path, report)

    report.report()
    fd.close()

if __name__ == '__main__':
    utils.install_pdb()

    # pick the latest one from /tmp
    log_d = utils.get_latest_file("/tmp/fss-*/")
    if log_d is None:
        # second choice
        log_d = os.path.join(ROOT, "data", "sample-fss-output")
    # perfered one
    if len(sys.argv) > 1:
        log_d = sys.argv[1]

    # enable trace output on unittest
    if not "unit" in log_d:
        dbg.quiet(["trace", "bug_lock"])

    dbg.info("> %s", log_d)

    report = lock.ErrReport()
    for path in Parser(log_d).parse():
        state = explore_path(path, report)
    report.report()
