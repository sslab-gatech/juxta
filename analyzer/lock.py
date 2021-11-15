#!/usr/bin/env python2
# SPDX-License-Identifier: MIT

import os
import sys
import re
import pprint
import collections

import dbg
import utils

from path import PathCall
from path import PathStore

from parser import Parser

ROOT = os.path.abspath(os.path.dirname(__file__))

# will be loaded
LOCKS = {
    "spin_lock"     : "spin_unlock",
    "spin_trylock"  : "spin_unlock",
    "mutex_lock"    : "mutex_unlock",
    "mutex_trylock" : "mutex_unlock",
    "lock_page"     : "unlock_page",
    # promoted
    "reiserfs_write_lock": "reiserfs_write_unlock",
}

# reverse mapping
ILOCKS = {v: k for k, v in LOCKS.items()}

def is_lock(func):
    return func in LOCKS.keys()

def is_unlock(func):
    return func in LOCKS.values()

class LockState:
    def __init__(self):
        self.ever_locked = False
        self.locks = []
        self.entries = []
        self.errs = {}

    def is_locked(self):
        return len(self.locks) >= 1

    def err(self, kind, note, loc):
        if not loc in self.errs:
            dbg.bug_lock("! %s %s @%s", kind, note, loc)
            self.errs[loc] = (kind, note)

    def add(self, entry):
        self.entries.append(entry)

    def _cmp_args(self, args1, args2):
        if len(args1) != len(args2):
            return False
        for (a, b) in zip(args1, args2):
            # opt out clang-pass glitches
            if a == "0" or b == "0":
                continue
            if a != b:
                return False
        return True

    def _cmp_func(self, f, g):
        return f.func == g.func \
            and len(f.args) == len(g.args) \
            and all(a == b for (a, b) in zip(f.args, g.args))

    def _check_double_locks(self, lock):
        return any(self._cmp_func(lock, l) for l in self.locks)

    def lock(self, lock):
        # at least, locked once?
        self.ever_locked = True

        # already acquired?
        if self._check_double_locks(lock):
            self.err("double locking", lock, lock.loc)

        # if not nested, push lock to entries as well
        if not self.is_locked():
            self.entries.append(lock)
        self.locks.append(lock)

    def unlock(self, unlock):
        # error: uncoordinated unlock
        if len(self.locks) == 0 or len(self.entries) == 0:
            # liekly error: if not, better to promote as
            # highlevel lock/unlock* (e.g., unlock_buffer())
            #
            # XXX. ubifs
            # if self.ever_locked:
            self.err("uncoordinated unlock", str(unlock), unlock.loc)
            return (None, [], None)

        assert(unlock == self.entries.pop())

        # paired lock
        while True:
            lock = self.locks.pop()
            # error: lock is not matched
            if not self.check_if_paired(lock, unlock):
                # assume it's failed trylock
                if "try" in lock.func:
                    continue
                self.err("not paired", "%s <-> %s" % (lock, unlock), unlock.loc)
            break

        # find out entries assigned w/ lock
        reclaimed = []
        while len(self.entries) != 0:
            e = self.entries.pop()
            # found match
            if e == lock:
                break
            reclaimed.append(e)

        # error: found unlocked lock
        for e in reclaimed:
            if isinstance(e, PathCall):
                if is_lock(e.func) and not "try" in e.func:
                    self.err("found unlocked lock %s", str(lock), lock.loc)

        return (lock, reclaimed, unlock)

    def check_if_paired(self, lock, unlock):
        # check their func name
        pair = LOCKS.get(lock.func, None)
        # unkonwn
        if not pair:
            self.err("unknown lock", str(lock), lock.loc)
            return False
        # not paired
        if pair != unlock.func:
            return False
        # their args not matched
        return self._cmp_args(unlock.args, lock.args)


class FSLockedData:
    def __init__(self, fd = None):
        self.summary = collections.defaultdict(list)
        self.fd = fd

        if self.fd is None:
            self.fd = sys.stdout

    def handle_member_protected(self, protected, lock, struct, lock_field):
        #
        # struct->lock
        #  struct->field1
        #  call(struct)
        #
        norm = "%s->%s" % (struct, lock_field)
        for e in protected:
            if isinstance(e, PathCall):
                if e.func:
                    self.summary[e.func + "()"].append(norm)
            elif isinstance(e, PathStore):
                if e.lhs and e.lhs.startswith(struct + "->"):
                    self.summary[e.lhs].append(norm)

    def handle_global_lock(self, protected, lock, global_lock):
        norm = global_lock
        for e in protected:
            if isinstance(e, PathCall):
                if e.func:
                    self.summary[e.func + "()"].append(norm)
            elif isinstance(e, PathStore):
                if e.lhs:
                    self.summary[e.lhs].append(norm)

    def collect(self, lock, protected, unlock):
        if len(lock.args) != 1:
            return
        arg = lock.args[0]

        # handle struct type & global lock
        matches = [
            (r"^&(\w+)->(\w+)$", self.handle_member_protected),
            (r"^&([\w_>\-]+)$", self.handle_global_lock),
        ]

        for (regexp, fn) in matches:
            m = re.match(regexp, str(arg))
            if m:
                fn(protected, lock, *m.groups())

        dbg.trace("paired: #%d protected" % len(protected))
        dbg.trace(" > %s" % lock)
        for e in protected:
            dbg.trace("     %s", e)
        dbg.trace(" < %s", unlock)

    def write(self, msg):
        self.fd.write(msg.replace(ROOT + "/", ""))

    def report(self):
        summary = sorted(self.summary.items(),
                         reverse = True,
                         key = lambda e: len(e[1]))
        self.write("{\n")
        for (field, locks) in summary:
            self.write(" %-40s: (%d, '%s'),\n" \
                       % ("'%s'" % field, len(locks), ",".join(set(locks))))
        self.write("}\n")

class ErrReport:
    def __init__(self, fd = None):
        self.errs = {}
        self.fd = fd

        if self.fd is None:
            self.fd = sys.stdout

    def add(self, note, kind, path, loc):
        self.errs[loc] = (note, kind, path)

    def write(self, msg):
        # neutralize message
        self.fd.write(msg.replace(ROOT + "/", ""))

    def report(self):
        for (loc, (note, kind, path)) in self.errs.iteritems():
            self.write("%s\n" % loc)
            self.write(" ! [%s] %s" % (kind, note))
            for e in path.effects:
                m = ">"
                if isinstance(e, PathCall):
                    if is_lock(e.func):
                        m = "L"
                    elif is_unlock(e.func):
                        m = "U"
                self.write(" %s %s\n" % (m, e))
            self.write("\n")

def _grep(beg, stack, end):
    reclaimed = []
    protected = False
    for e in stack:
        if e == beg:
            protected = True
            continue
        if e == end:
            protected = False
            break
        if protected:
            reclaimed.append(e)
    return reclaimed

def explore_path(path, pattern):
    state = LockState()
    for e in path.effects:
        if state.is_locked():
            state.add(e)

        if isinstance(e, PathCall):
            if is_lock(e.func):
                dbg.trace("%s", e)
                state.lock(e)
            elif is_unlock(e.func):
                dbg.trace("%s", e)

                # NOTE. ignore 'reclaimed' for now, which do not
                # consider nested locks, so regrep such elements by
                # ourselves
                (lock, _, unlock) = state.unlock(e)
                if lock and unlock:
                    reclaimed = _grep(lock, path.effects, unlock)
                    pattern.collect(lock, reclaimed, unlock)

    if len(state.locks) > 1:
        for l in state.locks:
            if not "try" in l.func:
                state.err("not resolved", str(l), l.loc)

    return state

def analyze_fs(fs, out_d, fss_d):
    fd_locked = open(os.path.join(out_d, "lock-locked.log"), "w")
    fd_report = open(os.path.join(out_d, "lock-report.log"), "w")

    locked = FSLockedData(fd_locked)
    report = ErrReport(fd_report)
    for path in Parser(fss_d).parse():
        state = explore_path(path, locked)
        for (loc, (kind, note)) in state.errs.iteritems():
            report.add(note, kind, path, loc)

    report.report()
    locked.report()

    fd_report.close()
    fd_locked.close()

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
        dbg.quiet(["trace"])

    dbg.info("> %s", log_d)

    pattern = FSLockedData()
    report = ErrReport()
    for path in Parser(log_d).parse():
        state = explore_path(path, pattern)
        for (loc, (kind, note)) in state.errs.iteritems():
            report.add(note, kind, path, loc)

    report.report()
    pattern.report()



