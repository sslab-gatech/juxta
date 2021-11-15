#!/usr/bin/env python2
# SPDX-License-Identifier: MIT

import os
import sys
import dbg
import utils
import pprint
import errno

from collections import defaultdict

from path import PathCall
from path import PathStore

from parser import Parser

ROOT = os.path.dirname(__file__)

def iter_uniq_path(paths, fn):
    _cache = []
    for p in paths:
        bslice = ""
        for e in p.effects:
            bslice += str(e)
            if fn(e):
                if not bslice in _cache:
                    yield p
                    _cache.append(bslice)
                break

def get_uniq_call(paths):
    _cache = defaultdict(set)
    for p in paths:
        calls = set()
        for e in p.effects:
            if isinstance(e, PathCall):
                if not e.func in calls:
                    calls.add(e.func)
        _cache[p.get_target().func].update(calls)
    return _cache

def get_uniq_errs(paths):
    _cache = defaultdict(set)
    for p in paths:
        try:
            err = int(p.get_rtn())
        except:
            continue
        if err < 0:
            _cache[p.get_target().func].add(err)
    return _cache

def load_unit_out(fs, out_d):
    log = None
    for root, dirs, files in os.walk(out_d):
        for name in files:
            pn = os.path.join(root, name)
            if name.startswith(fs):
                log = pn
                break
    assert(log)

    paths = []
    for p in Parser().parse_file(log):
        paths.append(p)
    return paths

def get_all_fs_from_unit_output(out_d):
    fs = []
    for root, dirs, files in os.walk(out_d):
        for name in files:
            if "main" in name:
                continue
            if name.endswith(".fss"):
                name = name[:-4]
                fs.append(os.path.splitext(name)[0])
    return fs

def mininig_common_calls(out_d):
    cap = defaultdict(set)
    for fs in get_all_fs_from_unit_output(out_d):
        calls = get_uniq_call(load_unit_out(fs, out_d))
        for (func, call) in calls.iteritems():
            # XXX. entry point
            if not "xattr" in func:
                continue
            for c in call:
                cap[c].add(fs)

    for (func, fs) in cap.iteritems():
        if len(fs) >= 3:
            print "%-20s: %s" % (func, ",".join(sorted(fs)))


def mininig_common_errs(out_d):
    cap = defaultdict(set)
    for fs in get_all_fs_from_unit_output(out_d):
        errs = get_uniq_errs(load_unit_out(fs, out_d))
        for (func, err) in errs.iteritems():
            # XXX. entry point
            if not "xattr" in func:
                continue
            for e in err:
                cap[e].add(fs)

    for (err, fs) in cap.iteritems():
        if len(fs) >= 3:
            slug = errno.errorcode.get(-err, "%s" % err)
            print "%-20s: %s" % (slug, ",".join(sorted(fs)))

if __name__ == '__main__':
    utils.install_pdb()

    def _pivot(e):
        if isinstance(e, PathStore):
            if e.lhs and "i_ctime" in e.lhs:
                return True
        return False

    out_d = "../unittest-bugs/output/set-xattr"
    # out_d = "../unittest-bugs/output/rename"

    mininig_common_calls(out_d)
    mininig_common_errs(out_d)
