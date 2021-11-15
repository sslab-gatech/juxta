#!/usr/bin/env python2
# SPDX-License-Identifier: MIT

import os
import sys
import dbg
import utils
import pdb
import errno
from struct import pack, unpack

from path import PathCall
from path import PathStore
from parser import Parser

ROOT = os.path.dirname(__file__)
DELIMITERS  = ['+', '-', '*', '/', '%', '!', '~', '^', '|', '&',
               '(', ')', '{', '}', '[', ']', '<', '>', 
               ' ', '.', ',', ':', '=', '#', '$', '@']
EXPR_PREFIX = ["(S64 #", "(I #", "(E #"]
    

def _mangle_type(ty):
    return {
        ' ' : '_', 
        '*' : 'P',
        '&' : 'R',
    }.get(ty, ty)

def _tokenize_expr(expr):
    while expr != "":
        p = 0
        # expression prefix 
        for prefix in EXPR_PREFIX:
            if expr.startswith(prefix):
                p = len(prefix)
                break;

        # delimiters
        for (i, c) in enumerate(expr[p:]):
            if not c in DELIMITERS:
                p += i
                break
        else:
            p = len(expr)
        if p > 0:
            yield (expr[0:p], False)
            expr = expr[p:]
            continue
            
        # if not beginning with delimeters, get subexpr
        for (i, c) in enumerate(expr):
            if c in DELIMITERS:
                p = i
                break
            else:
                p = len(expr)
        yield (expr[0:p], True)
        expr = expr[p:]

class ArgNormalizer(object):
    def __init__(self, path):
        self.path   = path
        self.func   = path.get_target()
        self.argmap = {}
        targs = zip(self.func.types, self.func.args)
        for i, ta in enumerate(targs):
            if ta[0] == None:
                return
            arg = ta[1]
            encoded_type = ''.join( map(_mangle_type, ta[0]) )
            self.argmap[arg] = "$A" + str(i) + '__' + encoded_type
        self._normalize()

    def _normalize(self):
        self._normalize_target()
        self._normalize_calls()
        self._normalize_conds()
        self._normalize_rtn()
        self._normalize_stores()

    def _normalize_target(self):
        for i, arg in enumerate(self.func.args):
            self.func.args[i] = self.argmap[arg]

    def _normalize_calls(self):
        calls = self.path.get_calls()
        for call in calls if calls else []:
            for (i, arg) in enumerate(call.args):
                call.args[i] = self._normalize_expr(arg)
        
    def _normalize_conds(self):
        conds = self.path.get_conds()
        for cond in conds if conds else []:
            cond.expr = self._normalize_expr(cond.expr)

    def _normalize_rtn(self):
        # XXX. ugly. it breakes encapsulation.
        rtn = self.path.get_rtn()
        self.path.index["RETURN"] = self._normalize_expr(rtn)

    def _normalize_stores(self):
        stores = self.path.get_stores()
        for store in stores if stores else []:
            if store.lhs:
                store.lhs = self._normalize_expr(store.lhs)
            store.rhs = self._normalize_expr(store.rhs)

    def _normalize_expr(self, expr):
        nexpr = []
        p_is_expr = False
        for (expr, is_expr) in _tokenize_expr(expr):
            if not p_is_expr and is_expr:
                expr = self.argmap.get(expr, expr)
            nexpr.append(expr)
            p_is_expr = is_expr
        return ''.join(nexpr)

    def __repr__(self):
        return "'%s'" % self

    def __str__(self):
        return self.path.__str__()

def errno_to_str(str):
    def __lookup_errno(err_int):
        ERRNO_DICT = {  # from <include/uapi/asm-generic/errno.h>
                123 : 'ENOMEDIUM',
                124 : 'EMEDIUMTYPE',
                125 : 'ECANCELED',
                126 : 'ENOKEY',
                127 : 'EKEYEXPIRED',
                128 : 'EKEYREVOKED',
                129 : 'EOWNERDEAD',
                130 : 'EOWNERDEAD',
                131 : 'ENOTRECOVERABLE',
                132 : 'ERFKILL',
                133 : 'EHWPOISON',
                # from <include/linux/errno.h>
                512 : 'ERESTARTSYS',
                513 : 'ERESTARTNOINTR',
                514 : 'ERESTARTNOHAND',
                515 : 'ENOIOCTLCMD',
                516 : 'ERESTART_RESTARTBLOCK',
                517 : 'EPROBE_DEFER',
                518 : 'EOPENSTALE',
                521 : 'EBADHANDLE',
                522 : 'ENOTSYNC',
                523 : 'EBADCOOKIE',
                524 : 'ENOTSUPP',
                525 : 'ETOOSMALL',
                526 : 'ESERVERFAULT',
                527 : 'EBADTYPE',
                528 : 'EJUKEBOX',
                529 : 'EIOCBQUEUED',
        }
        if err_int <= 122:
            return errno.errorcode.get(err_int, None)
        return ERRNO_DICT.get(err_int, None)

    try:
        err_int = int(str)
    except ValueError:
        return str

    if err_int > 0x80000000: # assumes 32bit int
        # signed value processed as unsigned
        # convert back
        err_int &= 0xffffffff
        err_int = unpack("i", pack("I", err_int))[0]
    err_str = __lookup_errno(abs(err_int))
    if err_str and err_int < 0:
        err_str = "-" + err_str
        return err_str
    return str

def have_args(sym_str):
    return "$A" in sym_str

def filter_out_non_args(sym_str):
    def __filter_name(s):
        stop_words = ["S64", "E", "I", ""]
        if s in DELIMITERS or s in stop_words or have_args(s):
            return s
        try:
            float(s)
            return s
        except ValueError:
            return "-"

    def __tokenize(sym_str):
        beg = 0
        for (i, c) in enumerate(sym_str):
            if c == ')' or c == ',' or c == ' ':
                if beg < i:
                    yield __filter_name(sym_str[beg:i])
                yield sym_str[i:i+1]
                beg = i + 1
            if c == '(':
                yield sym_str[beg:i+1]
                beg = i + 1
        yield __filter_name(sym_str[beg:len(sym_str)])

    newstr = ''.join(__tokenize(sym_str))
    return newstr
                
def _test_filter_out_non_args():
    assert(filter_out_non_args("(S64 # $A3__struct_dentry_P->d_inode)")
           == "(S64 # $A3__struct_dentry_P->d_inode)")
    assert(filter_out_non_args("(E # S_ISDIR($A1__struct_dentry_P->d_inode->i_mode))")
           == "(E # S_ISDIR($A1__struct_dentry_P->d_inode->i_mode))")
    assert(filter_out_non_args("(S64 # new->inode)")
           == "(S64 # -)")
    assert(filter_out_non_args("$A1_XXX")=="$A1_XXX")
    assert(filter_out_non_args("xyz")=="-")
    assert(filter_out_non_args("ext2_set_attr($A1__xxx, $A2__yyy, local)")
           =="ext2_set_attr($A1__xxx, $A2__yyy, -)")
    assert(filter_out_non_args("ext2_set_attr($A1__xxx, malloc(x, y, z), xxx)")
           =="ext2_set_attr($A1__xxx, malloc(-, -, -), -)")
    assert(filter_out_non_args("(S64 # $A4__unsigned_int) & (I # 4294967294)") 
           == "(S64 # $A4__unsigned_int) & (I # 4294967294)")
    return

if __name__ == '__main__':
    utils.install_pdb()

    # get log dir
    log_d = os.path.join(ROOT, "data", "sample-fss-output")
    if len(sys.argv) > 1:
        log_d = sys.argv[1]

    dbg.info("> %s", log_d)
    for path in Parser(log_d).parse():
        print "<< Before normalization"
        print(path)
        npath = ArgNormalizer(path)
        print ">> After normalization"
        print(npath)
