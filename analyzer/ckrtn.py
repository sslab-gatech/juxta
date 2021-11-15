#!/usr/bin/env python2
# SPDX-License-Identifier: MIT

import os
import sys
import dbg
import utils
import cPickle as pickle
from color import Color
import optparse
import collections
import glob
import pdb
from os.path import join

import fsop
import rsf
from argnorm import errno_to_str
from pathbin import PathBin, get_pickle_name
from rsv import RangeSetVector, calc_average_rsv
from checker import BaseChecker, CheckerRunner, CheckerPlan

ROOT  = os.path.abspath(os.path.dirname(__file__))
PICKLE_DIR = os.path.normpath(os.path.join(ROOT, "./out"))

class ReturnVector(RangeSetVector):
    def __init__(self, func, rtn_dic):
        self.func = func
        self.rtn_dic = rtn_dic

        rs = rsf.build(self.rtn_dic.keys())
        RangeSetVector.__init__(self, "@RETURN", rs)

    def get_func_name(self):
        return self.func

    def get_rtn_values(self):
        rtn_values = []
        for rv in self.rtn_dic.keys():
            rtn_values.append( errno_to_str(rv) )
        return rtn_values

    def get_missing_rtn_values(self, threshold):
        (myself_diff, avg_diff) = self.get_diffs("@RETURN")
        if avg_diff == []:
            return ""
        
        total_impact = 0
        mrv_str = "{{{-- "
        for ad in avg_diff:
            (impact, rs) = (ad[0], ad[1])
            mrv_str += "<%.5s, %s[%s, %s]%s, %s> " % \
                       (impact, \
                        Color.HEADER, \
                        rs.start, \
                        rs.end, \
                        Color.ENDC, \
                        self.__stringify_rs_comments(rs, 50))

            total_impact += impact
            if total_impact >= threshold:
                break
        mrv_str += "}}}"
        return mrv_str

    def __stringify_rs_comments(self, rs, limit):
        comments = ""
        for comment in list(rs.comments):
            comments += comment[:limit]
            limit -= len(comment[:limit])
            if limit <= 0:
                comments += "..."
                break
            comments += ", "
        return comments

    def __repr__(self):
        return "'%s'" % self

    def __str__(self):
        return "%s: %s\n  %s"  % (self.func, self.rtn_dic.keys(), self.rsv)

class ReturnChecker(BaseChecker):
    def __init__(self):
        BaseChecker.__init__(self)
        self.colors = []

    def report(self, report_all = True):
        print("%s[C] [%7s] [%.6s] [%23s] [%s] [%s]%s"% \
              (Color.HEADER,\
               "Ranking", "Distance", \
               "Funtion", "Return values", \
               "Missing return values", \
               Color.ENDC))
        for (ranking, result) in enumerate(self.results):
            distance = result[0]
            rv = result[1]
            if not report_all and distance <= self.avg_distance:
                break
            (cc, ac, l) = self._get_color_code(result)
            delta = distance - self.avg_distance
            print("%s[%s] %7s   %.6s   %23s   %s   %s%s" % \
                  (cc, ac, \
                   ranking+1, delta, \
                   rv.get_func_name(), \
                   sorted(self._get_rtn_values(rv)), \
                   Color.ENDC, \
                   rv.get_missing_rtn_values(delta * 0.7)))
                   #sorted(rv.get_rtn_values()), \
                   #sorted(self._get_rtn_values(rv)), \
        print("")

    def _add_rtn_value(self, rtn_value, rtn_values):
        paren_index = rtn_value.find('(')
        if paren_index > 1:
            rtn_func = rtn_value[0:paren_index]
            arg_list = rtn_value[paren_index+1:-1]
            if not self._add_rtn_values(rtn_func, arg_list, rtn_values):
                rtn_values.add(rtn_value)
        else:
            rtn_values.add(rtn_value)

    def _get_rtn_values(self, rv):
        rtn_values = set()
        for rtn_value in rv.get_rtn_values():
            self._add_rtn_value(rtn_value, rtn_values)
        return list(rtn_values)

    def _add_rtn_values(self, func, arg_list, rtn_values):
        if func == "ERR_PTR":
            self._add_rtn_value(arg_list, rtn_values)
            return True

        rtn_paths = self.get_rtn_paths(func)
        if rtn_paths == None:
            sys.stderr.write("__add_rtn_values: cannot find return paths for function: %s\n" % func)
            return False

        rv = ReturnVector(func, rtn_paths)
        for rtn_value in rv.get_rtn_values():
            sys.stderr.write("__add_rtn_values: expand return value (%s) from %s\n" % (rtn_value, func));
            self._add_rtn_value(rtn_value, rtn_values)
        return True

    def _build_vector(self, funcs):
        rvs = []
        rtn_paths_list = self.get_rtn_paths_list(funcs)

        for func, rtn_paths in zip(funcs, rtn_paths_list):
            if rtn_paths == None:
                continue
            rv = ReturnVector(func, rtn_paths)
            rvs.append(rv)
        return rvs


if __name__ == '__main__':
    utils.install_pdb()

    # option parsing
    parser = optparse.OptionParser()
    parser.add_option("--pickle", help="pickle directory", default=PICKLE_DIR)
    parser.add_option("--fs", help="List of fs", default=None)
    (opts, args) = parser.parse_args()

    fs = "*"
    if opts.fs:
        fs = opts.fs.split(",")
    log_d = opts.pickle

    # run return check
    runner = CheckerRunner(type(ReturnChecker()), "fss-ckrtn-", log_d, fs, *args)
    runner.run_check()
