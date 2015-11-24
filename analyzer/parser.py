#!/usr/bin/env python2

import os
import sys
import dbg
import utils

from path import RetPath

ROOT = os.path.dirname(__file__)

class Parser(object):
    def __init__(self, out_d = None):
        self.out_d = out_d
        return

    # open with one lookahead
    def _dual_open(self, pn, start, end):
        with open(pn) as fd:
            fd.seek(start)
            p = fd.readline()
            offset = start + len(p) # XXX. len(x) is slow
            p = p.strip()
            for n in fd:
                offset += len(n) # XXX. len(x) is slow
                n = n.strip()
                if offset >= end and p.startswith("@@>>"):
                    break
                yield (p, n)
                p = n
            yield (p, None)

    # split lines to key, value
    def _feeder(self, pn, start, end):
        # only @@<< ... @@>>
        state_enable = False

        fd = self._dual_open(pn, start, end)
        for (l, n) in fd:
            if l == "":
                continue
            elif l.startswith("@@<<"):
                state_enable = True
            elif l.startswith("@@>>"):
                state_enable = False
            else:
                # if it is in the middle of a state, skip until next
                if state_enable == False:
                    continue

                # relax, found a case where clang crashes
                if l[0] != "@" or not ":" in l:
                    dbg.warn("not parsable: %s", l)
                    continue

                (key, val) = self._split(l)

                # ok, new entry
                #   None: end of line
                #   ""  : newline
                #   "@" : normal entry
                if n is None or n == "" or n[0] == "@":
                    yield (key, val)
                    continue

                # entry w/ multiple lines
                for (l, n) in fd:
                    val += l
                    if n is None or n == "" or n[0] == "@":
                        break

                yield (key, val)

    # XXX. parse -> parse_all
    def parse(self):
        for f in self.get_files():
            for path in self.parse_file(f):
                yield path

    def parse_file(self, pn, start = 0, end = 2**64):
        entries = []

        state_path = None
        for (key, val) in self._feeder(pn, start, end):
            # begining of new path
            if key == "LOCATION":
                if state_path:
                    yield state_path
                state_path = RetPath()
            state_path.add_entry(key, val)
        # last entry
        if state_path:
            yield state_path

    def _split(self, line):
        # from: @CONDITION: ..
        # to  : (CONDITION, etc)
        (key, _) = line.split(":", 1)
        val = line[len(key)+1:].strip()
        return (key[1:], val)

    def get_files(self):
        for root, dirs, files in os.walk(self.out_d):
            for name in files:
                pn = os.path.join(root, name)
                if pn.endswith(".fss"):
                    yield pn

if __name__ == "__main__":
    utils.install_pdb()

    # pick the latest one from /tmp
    log_d = utils.get_latest_file("/tmp/fss-*/")
    if log_d is None:
        # second choice
        log_d = os.path.join(ROOT, "data", "sample-fss-output")
    # perfered one
    if len(sys.argv) > 1:
        log_d = sys.argv[1]

    print("> %s" % log_d)

    for path in Parser(log_d).parse():
        print(path)
