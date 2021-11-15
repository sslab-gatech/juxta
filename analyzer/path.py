#!/usr/bin/env python2
# SPDX-License-Identifier: MIT

import os
import sys
import re
import dbg
import utils
import pprint

LIST_TYPE = ["CONDITION", "LOG_CALL", "LOG_STORE"]

def _parse_typed_arg(targ):
    end_type = None
    i = 0
    for i in utils.to_zero(len(targ)):
        if targ[i] == ' ':
            end_type = i
            break

    # no typed arg (e.g., foo(x))
    if i == 0:
        return (None, targ)

    # typed arg (e.g., foo(int x))
    ty = str.strip(targ[0:end_type])
    arg = str.strip(targ[end_type+1:])
    return (ty, arg)

def _parse_func(decl):
    beg_args = None
    depth = 0
    for i in utils.to_zero(len(decl)):
        if decl[i] == ')':
            depth += 1
        elif decl[i] == '(':
            depth -= 1
        if depth == 0 and decl[i] == '(':
            beg_args = i
            break

    # not parsable (e.g., '0' in ext4)
    if beg_args is None:
        return (None, None, None)

    # normal path
    arg_str = decl[beg_args+1:-1]
    arg_str = map(str.strip, arg_str.split(","))
    targs   = map(_parse_typed_arg, arg_str)

    types = map(lambda x: x[0], targs)
    args  = map(lambda x: x[1], targs)
    func  = decl[:beg_args]

    return (func, types, args)

# represent LOG_CALL
class PathCall(object):
    def __init__(self, line):
        (decl, loc) = utils.split(line, "@LOCATION:")

        (func, types, args) = _parse_func(decl)

        # not parsable (e.g., '0' in ext4)
        if func is None:
            func  = line
            args  = []

        # normal path
        self.func  = func
        self.args  = args
        self.loc   = loc

    def basename(self):
        beg = 0
        for i in utils.to_zero(len(self.func)):
            if self.func[i] == '>':
                beg = i+1
                break
        return self.func[beg:]

    def get_arg(self, index):
        return self.args[index]
    
    def callname(self):
        return "%s(%s)" \
            % (self.func, ",".join(self.args))

    def get_feature(self, detail=False):
        if detail:
            return self.func + "@" + str(self.args)
        return self.func

    def __repr__(self):
        return "'%s'" % self

    def __str__(self):
        return "%s(%s)@%s" \
            % (self.func, ",".join(self.args), self.loc)

# represet LOG_STORE
class PathStore(object):
    def __init__(self, line):
        (stmt, loc) = utils.split(line, "@LOCATION:")
        # increment, decrement
        if "++" in stmt:
            self.lhs = stmt.rstrip("+")
            self.rhs = self.lhs + "+ 1"
        elif "--" in stmt:
            self.lhs = stmt.rstrip("-")
            self.rhs = self.lhs + "- 1"
        # compound assignment
        elif "+=" in stmt:
            (self.lhs, self.rhs) = utils.split(stmt, "+=")
            self.rhs = self.rhs + " + " + self.lhs
        elif "-=" in stmt:
            (self.lhs, self.rhs) = utils.split(stmt, "-=")
            self.rhs = self.rhs + " - " + self.lhs
        elif "*=" in stmt:
            (self.lhs, self.rhs) = utils.split(stmt, "*=")
            self.rhs = self.rhs + " * " + self.lhs
        elif "/=" in stmt:
            (self.lhs, self.rhs) = utils.split(stmt, "/=")
            self.rhs = self.rhs + " / " + self.lhs
        elif "%=" in stmt:
            (self.lhs, self.rhs) = utils.split(stmt, "%=")
            self.rhs = self.rhs + " % " + self.lhs
        elif "&=" in stmt:
            (self.lhs, self.rhs) = utils.split(stmt, "&=")
            self.rhs = self.rhs + " & " + self.lhs
        elif "|=" in stmt:
            (self.lhs, self.rhs) = utils.split(stmt, "|=")
            self.rhs = self.rhs + " | " + self.lhs
        elif "<<=" in stmt:
            (self.lhs, self.rhs) = utils.split(stmt, "<<=")
            self.rhs = self.rhs + " << " + self.lhs
        elif ">>=" in stmt:
            (self.lhs, self.rhs) = utils.split(stmt, ">>=")
            self.rhs = self.rhs + " >> " + self.lhs
        # simple assignment
        elif "=" in stmt:
            (self.lhs, self.rhs) = utils.split(stmt, "=")
        else:
            # unkonw format, bare with real life
            self.lhs = None
            self.rhs = line

    def get_feature(self, detail=False):
        if detail:
            return self.lhs + "@" + self.rhs
        return self.lhs
        
    def __repr__(self):
        return "'%s'" % self

    def __str__(self):
        return "%s = %s" % (self.lhs, self.rhs)


# represet FUNCTION
class PathFunc(object):
    def __init__(self, line):
        (func, types, args) = _parse_func(line)
        self.func  = func
        self.types = types
        self.args  = args

    def get_func_name(self):
        return self.func

    def __repr__(self):
        return "'%s'" % self

    def __str__(self):
        # XXX: print types as well
        return "%s(%s)" % (self.func, ",".join(self.args))

# represent CONDITION
class PathCond(object):
    def __init__(self, line):
        if ":" in line:
            (expr, ranges) = utils.split(line, ":")
            self.expr = expr.strip()
            self.ranges = ranges.strip().lstrip("{").rstrip("}")
        else:
            self.expr = "nil"
            self.ranges = "nil"

    def get_feature(self, detail=False):
        if detail:
            return self.expr + "@" + self.ranges
        return self.expr

    def get_ranges(self):
        ranges = []
        rb = self.ranges.find('[')
        while rb != -1:
            re = self.ranges.find(']', rb)
            rang_ = self.ranges[rb+1:re]
            comma = rang_.find(',')
            lb_str = rang_[0:comma]
            ub_str = rang_[comma+2:]
            #try:
            lb = int(lb_str)
            ub = int(ub_str)
            ranges.append((lb,ub))
            #except ValueError:
            #    ranges.append(rang_)
            rb = self.ranges.find('[', re)
        return ranges

    def is_conjure(self):
        if self.expr.startswith("(E #"):
            return True
        return False

    def __repr__(self):
        return "'%s'" % self

    def __str__(self):
        return "%s : { %s }" % (self.expr, self.ranges)

# represent a single path upto return
class RetPath(object):
    def __init__(self):
        self.index = {}
        self.effects = []

        self.dispatch = {
            "FUNCTION" : PathFunc,
            "CONDITION": PathCond,
            "LOG_CALL" : PathCall,
            "LOG_STORE": PathStore,
        }

    def _parse_entry(self, key, val):
        func = self.dispatch.get(key, None)
        if func:
            return func(val)
        return val

    def _parse_log_store(self, key, val):
        return val

    def add_entry(self, key, val):
        entry = self._parse_entry(key, val)

        if key.startswith("LOG_"):
            self.effects.append(entry)
        if key in LIST_TYPE:
            if not key in self.index:
                self.index[key] = []
            self.index[key].append(entry)
        else:
            assert(not key in self.index)
            self.index[key] = entry

    # encapsulate unhandy names
    def get_target(self):
        return self.index.get("FUNCTION", None)
    def get_calls(self):
        return self.index.get("LOG_CALL", None)
    def get_conds(self):
        return self.index.get("CONDITION", None)
    def get_rtn(self):
        return self.index.get("RETURN", None)
    def get_stores(self):
        return self.index.get("LOG_STORE", None)
    def get_effects(self):
        return self.effects

    def __str__(self):
        return pprint.pformat(self.index)

def _test_path_fdecl():
    lines = [
        'ext2_rename(struct inode * old_dir, struct dentry * old_dentry, struct inode * new_dir, struct dentry * new_dentry)',
        'main()',
    ]
    for l in lines:
        print(PathFunc(l))

def _test_path_call():
    lines = [
        '((struct dentry *)fd)->d_inode->i_op->setattr(dentry, attr) @LOCATION: syscall.c:37:9',
        'mext_check_arguments(&orig_inode, &donor_inode, orig_start, donor_start, &len) @LOCATION: test.c:48:6',
    ]
    for l in lines:
        print(PathCall(l))

if __name__ == "__main__":
    utils.install_pdb()
    _test_path_fdecl()
    _test_path_call()
