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
from argnorm import filter_out_non_args, have_args, errno_to_str
from pathbin import PathBin, get_pickle_name
from rsv import RangeSetVector, calc_average_rsv
from checker import BaseChecker, CheckerRunner, CheckerPlan

ROOT  = os.path.abspath(os.path.dirname(__file__))
PICKLE_DIR = os.path.normpath(os.path.join(ROOT, "./out"))

class CondVector(RangeSetVector):
    def __init__(self, func, rtn):
        self.func = func
        self.rtn = rtn
        RangeSetVector.__init__(self)

    def add_path(self, tcv):
        ucv = self.union(tcv)
        self.rsv = ucv.rsv

    def normalize(self):
        self.resize_area(rsf.RANGE_AREA)

    def get_func_name(self):
        return self.func

    def get_rtn(self):
        return self.rtn

    def get_missing_conditions(self, threshold):
        diff_dic = self.__build_diff_dic()
        idx_list = [0] * len(diff_dic)

        total_impact = 0
        mcnd_str = "{{{-- "
        while True:
            # find the most impactful factor in all dimensions
            (max_dim, max_impact, max_rs, max_idx) = ("", -1.0, None, -1)
            for (i, (dim, diffs)) in enumerate(diff_dic.iteritems()):
                # check if index is sane
                if idx_list[i] == -1:
                    continue
                if idx_list[i] >= len(diffs):
                    idx_list[i] = -1
                    continue
                
                # get impact and range set
                ad = diffs[ idx_list[i] ]
                (impact, rs) = (ad[0], ad[1])

                # is it the most impactful?
                if impact > max_impact:
                    (max_dim, max_impact, max_rs, max_idx) = (dim, impact, rs, i)

            # if nothing left
            if max_idx == -1:
                break
                
            # I got the most impactful one
            mcnd_str += "<%.5s, %s%s%s [%s, %s]> " % \
                       (impact, Color.HEADER, max_dim, Color.ENDC, \
                        rs.start, rs.end)

            # prepare for the next iteration
            total_impact += impact
            if total_impact >= threshold:
                break
            idx_list[max_idx] += 1
        mcnd_str += "}}}"
        return mcnd_str

    def __build_diff_dic(self):
        diff_dic = {}
        for dim in self.rsv:
            (myself_diff, avg_diff) = self.get_diffs(dim)
            if avg_diff == []:
                continue
            diff_dic[dim] = avg_diff
        return diff_dic
        
    def __repr__(self):
        return "'%s'" % self

    def __str__(self):
        return "%s:%s\n  %s"  % (self.func, self.rtn, self.rsv)

class CondChecker(BaseChecker):
    def __init__(self, rtn, pathbin):
        BaseChecker.__init__(self, pathbin)
        self.rtn = rtn

    def report(self, report_all = True):
        print("%s[C] [%7s] [%.6s] [%23s] [%s]%s"% \
              (Color.HEADER,\
               "Ranking", "Distance", "Funtion", "Missing Conditions", \
               Color.ENDC))
        for (ranking, result) in enumerate(self.results):
            distance = result[0]
            cv = result[1]
            if not report_all and distance <= self.avg_distance:
                break
            (cc, ac, l) = self._get_color_code(result)
            delta = distance - self.avg_distance
            print("%s[%s]  %7s   %.6s   %23s   %s%s"% \
                  (cc, ac, \
                   ranking+1, delta, \
                   ''.join((cv.get_func_name(), \
                            ':', \
                            errno_to_str(cv.get_rtn()))), \
                   Color.ENDC, \
                   cv.get_missing_conditions(delta * 0.7)))
        print("")

    def _build_vector(self, funcs):
        cvs = []

        # for each function
        for func in funcs:
            # create condition vector
            cv = CondVector(func, self.rtn)

            # collect @CONDITION for the specified return value
            rtn_dic = self.pathbin[func]
            symbol_set = set()
            for retpath in rtn_dic.get(self.rtn, []):
                conds = retpath.get_conds()
                if conds == None:
                    continue

                # create a temp. condition vector for a single path condition 
                tcv = CondVector(func, self.rtn)
                for cond in conds:
                    # first, decide whether a cond is included or not
                    if self.__filter_out_cond(cond):
                        continue
                    nexpr = filter_out_non_args(cond.expr)
                    if not have_args(nexpr):
                        continue
                    # add {nexpr, ranges} to the vector 
                    tcv.add(nexpr, rsf.build([cond.ranges]))

                # add a single path condition to the condition vector for return
                cv.add_path(tcv)

            # now, a condition vector is ready. 
            cv.normalize()
            cvs.append(cv)
        return cvs

    def __filter_out_cond(self, cond):
        # null condition 
        if not cond or cond.ranges == 'nil':
            return True

        # blacklisted condition 
        FEATURE_BLACKLIST = [
            "(E # __builtin_expect",
            "(E # __builtin_constant_p",
            "(E # WARN_ON",
            "nil",
        ]
        for black in FEATURE_BLACKLIST:
            if cond.expr.startswith(black):
                return True
        
        # everything else
        return False

class CondCheckers(BaseChecker):
    def __init__(self):
        BaseChecker.__init__(self)
        self.rtn_funcs_dic = {} # {rtn, [list of functions]}*
        self.cks = []

    def check(self, funcs):
        # collect functions, which return the same value
        self.__generate_rtn_funcs_dic(funcs)

        # run condition check for each (return, functions) pair
        for rtn in self.rtn_funcs_dic.keys():
            if len(self.rtn_funcs_dic[rtn]) < 3:
                continue

            ckcond = CondChecker(rtn, self.pathbin)
            rtn_funcs  = self.rtn_funcs_dic[rtn]
            ckcond.check(rtn_funcs)

            self.cks.append(ckcond)

    def report(self, report_all = True):
        # simply gathering report from all store checkers
        map(lambda ck: ck.report(report_all), self.cks)

    def __generate_rtn_funcs_dic(self, funcs):
        rtn_paths_list = self.get_rtn_paths_list(funcs)

        for func, rtn_paths in zip(funcs, rtn_paths_list):
            if rtn_paths == None:
                continue
            for rtn in rtn_paths.keys():
                rtn_funcs = self.rtn_funcs_dic.get(rtn, [])
                rtn_funcs.append(func)
                self.rtn_funcs_dic[rtn] = rtn_funcs

if __name__ == '__main__':
    # sys.setrecursionlimit( sys.getrecursionlimit() * 100 )

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
    runner = CheckerRunner(type(CondCheckers()), "fss-ckcond-", log_d, fs, *args)
    runner.run_check()
