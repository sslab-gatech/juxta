#!/usr/bin/env python2
# SPDX-License-Identifier: MIT

import os
import sys
import dbg
import utils
import cPickle as pickle
import errno
from color import Color
import optparse
import collections
import glob
import pdb
from os.path import join
from struct import pack, unpack
import fnmatch
from bugginess import calc_bugginess, calc_entropy

import fsop
from pathbin import PathBin, get_pickle_name
from checker import BaseChecker, CheckerRunner, CheckerPlan
from argnorm import errno_to_str

ROOT  = os.path.abspath(os.path.dirname(__file__))
PICKLE_DIR = os.path.normpath("/data/fss-data/out-2015-03-19")

MAX_S8  = 127
MIN_S8  = -128
MAX_U8  = 255
MAX_S16 = 32767
MIN_S16 = -32768
MAX_U16 = 65536
MAX_S32 = 2147483647
MIN_S32 = -2147483648
MAX_U32 = 4294967295
MAX_S64 = 9223372036854775807
MIN_S64 = -9223372036854775808
MAX_U64 = 18446744073709551615L
MAX_ERRNO = 18446744073709547521L

report_in_one_line = False

class ExternAPI(object):
    def __init__(self, api, rtn_expr):
        self.api = api
        self.rtn_expr = rtn_expr
        self.conds_dict = dict()
        self.has_majority = False

    def _filter(self, func):
        if func.find("__builtin_") == 0:
            return True
        elif func.find("xattr") != -1:
            return True
        elif func.find("WARN_ON") == 0:
            return True

        return False

    def add(self, func, cond):
        #if self._filter(func):
        #    return
        conds = self.conds_dict.get(func, set())
        conds.add(cond)
        self.conds_dict[func] = conds

    def _gen_event_occ_dict(self, range_set):
        # range_set[return check condition] = list of functions
        #           -+--------------------    -+---------------
        #            \ event                   \ occurrence
        ev_occ = {}
        for ev in range_set:
            ev_occ[ev] = len(range_set[ev])
        if report_in_one_line:
            return calc_entropy(ev_occ)
        return calc_bugginess(ev_occ)

    def _calculate_result(self):
        range_set = dict()
        for func, conds in self.conds_dict.iteritems():
            f_conds = frozenset(conds)
            func_list = range_set.get(f_conds, list())
            func_list.append(func)
            range_set[f_conds] = func_list

        sorted_keys = sorted(range_set, key=lambda k: len(range_set[k]), reverse=True)
        if (len(sorted_keys) > 1) and \
           (len(range_set[sorted_keys[0]]) > len(range_set[sorted_keys[1]])):
            self.has_majority = True
        elif len(range_set[sorted_keys[0]]) > 1:
            self.has_majority = True

        return (sorted_keys, range_set)

    def _isdisjoint(self, mk, k):
        for i in mk:
            if not i:
                # be conservative
                return False
            for j in k:
                if not j:
                    continue
                if j.find(i) != -1:
                    return False
                elif (i[0] != '!') and (j[0] != '!') \
                     and j[1:].find(i[1:]) != -1:
                    return False
        return True

    def report(self, func_num):
        if len(self.conds_dict.keys()) < 2:
            return

        (sorted_keys, range_set) = self._calculate_result()
        if (len(sorted_keys) == 1) and \
           (len(sorted_keys[0]) == 1) and \
           (not list(sorted_keys[0])[0] or len(list(sorted_keys[0])[0]) == 0):
            return
        bugginess  = self._gen_event_occ_dict(range_set)

        if not report_in_one_line:
            print("%s> Report on API %s from RetPath %s%s" % \
                  (Color.HEADER, self.api, self.rtn_expr, Color.ENDC))
            majority_printed = False
            majority_key = sorted_keys[0]
            for key in sorted_keys:
                if not self.has_majority:
                    print("%s[o]    %s => %s%s" % \
                          (Color.OKBLUE, range_set[key], list(key), Color.ENDC))
                elif not majority_printed:
                    print("%s[O]    %s => %s%s" % \
                          (Color.OKGREEN, range_set[key], list(key), Color.ENDC))
                    majority_printed = True
                elif self._isdisjoint(majority_key, key):
                    print("%s[x]    %s => %s%s" % \
                          (Color.FAIL, range_set[key], list(key), Color.ENDC))
                else:
                    print("%s[?]    %s => %s%s" % \
                          (Color.WARNING, range_set[key], list(key), Color.ENDC))
                print("")
                print(">>\t bugginess: %s" % bugginess)
        else:
            # entropy api return path 
            for key in sorted_keys:
                print("%f : %s : %s : %s : %s" % 
                      (bugginess, self.api, self.rtn_expr,
                       range_set[key], list(key)))

    def report_raw(self):
        # dump all result
        for func, conds in self.conds_dict.iteritems():
            print("@API %s:%s @FUNCTION %s:%s" % (self.api, self.rtn_expr, func, list(conds)))

    def __str__(self):
        return "%s => %s" % (self.api, self.conds_dict)

class ExternAPIChecker(BaseChecker):
    def __init__(self, check_all=False):
        BaseChecker.__init__(self)
        self.apis = dict()
        self.colors = []
        self.func_num = 0
        self.check_all = check_all

    def report(self, report_all = True):
        for api in self.apis.values():
            if self.check_all:
                api.report_raw()
            else:
                api.report(self.func_num)

    def get_rtn_paths_list(self, funcs):
        rtn_paths_list = []
        for func in funcs:
            rtn_paths = self.pathbin[func] # {@RETURN, [RetPath*]}
            if self.check_all:
                # no expansion when checking all funcs
                rtn_paths_list.append(rtn_paths)
            else:
                rtn_paths_list.append(self._expand_rtn_paths(rtn_paths))
        return rtn_paths_list

    def _expand_rtn_paths(self, rtn_paths):
        new_rtn_paths = dict()
        if not rtn_paths:
            return None

        for rtn_value, paths in rtn_paths.iteritems():
            self._add_rtn_value(rtn_value, paths, new_rtn_paths)
        return new_rtn_paths

    def _add_rtn_value(self, rtn_value, paths, rtn_paths):
        # normalize errno
        rtn_value = errno_to_str(rtn_value)

        # expand function invocation if possible
        paren_index = rtn_value.find('(')
        if paren_index > 1:
            rtn_func = rtn_value[0:paren_index]
            arg_list = rtn_value[paren_index+1:-1]
            if self._add_rtn_values(rtn_func, arg_list, paths, rtn_paths):
                return
        # if not a function or expand fails
        paths_list = rtn_paths.get(rtn_value, list())
        paths_list.extend(paths)
        rtn_paths[rtn_value] = paths_list

    def _add_rtn_values(self, func, arg_list, current_paths, rtn_paths):
        # if the return value is a function
        # 1. find possible return values of this function
        # 2. append current RetPath to the list of all poosible return values
        # 3. append new RetPath to the current list
        #
        if func == "ERR_PTR":
            self._add_rtn_value(arg_list, current_paths, rtn_paths)
            return True

        new_rtn_paths = self.get_rtn_paths(func)
        if new_rtn_paths == None:
            sys.stderr.write("_expand_rtn_value: cannot find return paths for function: %s\n" % func)
            return False

        for rtn_value, new_paths in new_rtn_paths.iteritems():
            sys.stderr.write("_expand_rtn_value: expand return value (%s) from %s\n" % (rtn_value, func))
            # add current path
            rtn_value = errno_to_str(rtn_value)
            paths_list = rtn_paths.get(rtn_value, list())
            paths_list.extend(current_paths)
            rtn_paths[rtn_value] = paths_list
            # add new paths
            self._add_rtn_value(rtn_value, new_paths, rtn_paths)
        return True

    def _parse_range(self, value_range):
        (lb, ub) = value_range
        if lb == ub:
            if lb > 0xffff:
                return "== %s" % hex(lb)
            else:
                return "== %d" % lb
        elif ub == MAX_S64 or ub == MAX_S32 or ub == MAX_S16 or ub == MAX_S8:
            if lb == 1:
                return "> 0"
            else:
                return ">= %d" % lb
        elif lb == MIN_S64 or lb == MIN_S32 or ub == MIN_S16 or ub == MIN_S8:
            if ub == -1:
                return "< 0"
            else:
                return "<= %d" % ub
        elif ub == MAX_U64 or ub == MAX_U32 or ub == MAX_U16 or ub == MAX_U8:
            assert(lb >= 0)
            if lb == MAX_ERRNO:
                return "== ERROR_VALUE"
            elif lb == 1:
                return "!= 0"
            else:
                return ">= %d" % lb
        elif lb == 0 and ub == (MAX_ERRNO-1):
            return "!= ERROR_VALUE"
        elif lb == 1 and ub == (MAX_ERRNO-1):
            return "!= 0 && != ERROR_VALUE"
        else:
            if ub > 0xffff:
                return ">= %d && <= %s" % (lb, hex(ub))
            else:
                return ">= %d && <= %d" % (lb, ub)

    def _parse_range_pair(self, value_range1, value_range2):
        (lb1, ub1) = value_range1
        (lb2, ub2) = value_range2

        # swap the two ranges if necessary
        if ub1 > lb2:
            lb1,lb2 = lb2,lb1
            ub1,ub2 = ub2,ub1

        assert(lb2 > ub1)

        if (lb1 == MIN_S64 or lb1 == MIN_S32 or lb1 == MIN_S16 or lb1 == MIN_S8) and \
           (ub2 == MAX_S64 or ub2 == MAX_S32 or ub2 == MAX_S16 or ub2 == MAX_S8) and \
           ((lb2 - ub1) == 2):
            return "!= %d" % ((lb2 + ub1) / 2)

        if (lb1 == 0) and \
           (ub2 == MAX_U64 or ub2 == MAX_U32 or ub2 == MAX_U16 or ub2 == MAX_U8) and \
           ((lb2 - ub1) == 2):
            return "!= %d" % ((lb2 + ub1) / 2)

        vl1 = self._parse_range(value_range1)
        vl2 = self._parse_range(value_range2)
        return vl1 + " || " + vl2

    def _parse_ranges(self, value_ranges):
        if (not value_ranges) or (len(value_ranges) == 0):
            return ""

        if len(value_ranges) == 1:
            return self._parse_range(value_ranges[0])
        elif len(value_ranges) == 2:
            return self._parse_range_pair(value_ranges[0], value_ranges[1])

        vrs = ""
        for vr in value_ranges:
            if len(vrs) != 0:
                vrs += " || "
            vrs += self._parse_range(vr)

    def _is_valid(self, api, func):
        if len(api) == 0:
            return False
        elif api.find("$") != -1:
            return False
        elif api.find("-") != -1:
            return False
        elif api.find(">") != -1:
            return False
        elif api.find("__builtin_") == 0:
            return False
        elif api.find("WARN_ON") == 0:
            return False
        elif api.find("BUG") == 0:
            return False

        # filter internal funcs
        us_index1 = func.find('_')
        us_index2 = 0
        while api[us_index2] == '_':
            us_index2 += 1
        if us_index1 > 0 and \
           func[0:us_index1] == api[us_index2:us_index1+us_index2]:
            return False

        return True

    def _parse_rtn_paths(self, func, rtn, rtn_paths):
        for rtn_path in rtn_paths:
            if (not rtn_path.get_conds()) or (not rtn_path.get_calls()):
                continue

            for call in rtn_path.get_calls():
                callee = call.get_feature()
                if not self._is_valid(callee, func):
                    continue

                # get full func now
                callee = call.callname()
                rtn = errno_to_str(rtn)
                key = "%s on %s path" % (callee, rtn)
                api = self.apis.get(key, ExternAPI(callee, rtn))
                has_cond = False
                for cond in rtn_path.get_conds():
                    feature = cond.get_feature()
                    if feature.find(callee) != -1:
                        vrange = self._parse_ranges(cond.get_ranges())
                        api.add(func, vrange)
                        has_cond = True
                        break
                if not has_cond:
                    api.add(func, "")
                self.apis[key] = api
        
    def check(self, funcs):
        self.func_num = len(funcs)
        if self.func_num == 1:
            self.check_all = True
        rtn_paths_list = self.get_rtn_paths_list(funcs)

        # get common returns, copy from spec.py
        common_ret_exprs = set()
        for func, rtn_paths in zip(funcs, rtn_paths_list):
            if rtn_paths == None:
                continue
            if len(common_ret_exprs) == 0:
                common_ret_exprs.update(rtn_paths.keys())
            else:
                if self.check_all:
                    common_ret_exprs.update(rtn_paths.keys())
                else:
                    common_ret_exprs.intersection_update(rtn_paths.keys())

        for retExpr in common_ret_exprs:
            for func, rtn_paths in zip(funcs, rtn_paths_list):
                if rtn_paths == None or not rtn_paths.get(retExpr, None):
                    continue
                self._parse_rtn_paths(func, retExpr, rtn_paths[retExpr])
        self.pathbin = None

def run_test(check_all=False):
    funcs = ["ext2_rename",
             "ext3_rename",
             "ext4_rename2",
             "btrfs_rename2",
            ]

    log_d = os.path.join(ROOT, "data", "sample-fss-output")
    ck = ExternAPIChecker(check_all=check_all)
    ck.load_pathbin(log_d)
    ck.check(funcs)
    ck.report()

def check_all_func(log_d):
    funcs = []
    for f in os.listdir(log_d):
        if fnmatch.fnmatch(f, "pathbin*.p"):
            funcs.append(f[8:-2])

    ck = ExternAPIChecker(check_all=True)
    ck.load_pathbin(log_d)
    ck.check(funcs)
    ck.report()

if __name__ == '__main__':
    utils.install_pdb()

    # option parsing
    parser = optparse.OptionParser()
    parser.add_option("--pickle", help="pickle directory", default=PICKLE_DIR)
    parser.add_option("--fs", help="List of fs", default=None)
    parser.add_option("--test", help="run test", action="store_true", dest="test", default=False)
    parser.add_option("--all", help="apply to all functions", action="store_true", dest="check_all", default=False)
    parser.add_option("--debug", help="debug", action="store_true", dest="debug", default=False)
    (opts, args) = parser.parse_args()

    if opts.test:
        run_test(opts.check_all)
        sys.exit(0)

    fs = "*"
    if opts.fs:
        fs = opts.fs.split(",")
    log_d = opts.pickle

    #if opts.check_all:
    #    check_all_func(log_d)
    #    sys.exit(0)

    # run return check
    runner = CheckerRunner(type(ExternAPIChecker(check_all=opts.check_all)), "fss-ckapi-", log_d, fs, check_all=opts.check_all, debug=opts.debug, *args)
    runner.run_check()
