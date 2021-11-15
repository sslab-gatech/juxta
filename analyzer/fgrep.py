#!/usr/bin/env python2
# SPDX-License-Identifier: MIT

import os
import pprint
import optparse
import collections

import fsop

ROOT  = os.path.abspath(os.path.dirname(__file__))
LINUX = os.path.normpath(os.path.join(ROOT, "../../linux"))

def _dump_to_func_end(fd, maxline):
    cnt = 0
    for l in fd:
        l = l.rstrip()
        print l
        if l.startswith("}"):
            break
        cnt += 1
        if cnt > maxline:
            break

def search(fs, func, maxline):
    for root, dirs, files in os.walk(os.path.join(LINUX, "fs", fs)):
        for name in files:
            pn = os.path.join(root, name)
            if not (name.endswith(".c") or name.endswith(".h")):
                continue
            with open(pn) as fd:
                for l in fd:
                    l = l.rstrip()
                    if impl + "(" in l \
                       and not l.endswith(";") \
                       and not l.strip().startswith("extern ") \
                       and not l.strip().startswith("*"):
                        print l
                        _dump_to_func_end(fd, maxline)

def dump_index(opts, args):
    summary = collections.defaultdict(set)
    for (key, val) in fsop.get_ops("*", *args):
        for (vfs, impl) in val.iteritems():
            summary[vfs].add(key[0])

    def __ranked(summary):
        return sorted(summary.items(), key=lambda a: len(a[1]), reverse=True)

    for (vfs, fs) in __ranked(summary):
        print "%-20s (%2d): %s" % (vfs, len(fs), ", ".join(sorted(fs)[:10]))

if __name__ == "__main__":
    parser = optparse.OptionParser()
    parser.add_option("--linux", help="Linux kernel", default=LINUX)
    parser.add_option("--fs", help="List of fs", default=None)
    parser.add_option("--func", help="List of func", default=None)
    parser.add_option("--line", help="List of code to show", default=30)
    parser.add_option("--index", help="List of summary of funcs",
                      action="store_true", default=None)
    (opts, args) = parser.parse_args()

    fs = "*"
    if opts.fs:
        fs = opts.fs.split(",")

    func = None
    if opts.func:
        func = opts.func.split(",")

    if opts.index:
        dump_index(opts, args)
        exit(0)

    for (key, val) in fsop.get_ops(fs, *args):
        for (vfs, impl) in val.iteritems():
            if func is None or vfs in func:
                print "/".join(key), vfs, impl
                print "-" * 80
                search(key[0], impl, opts.line)


