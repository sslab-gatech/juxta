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
from checker import BaseChecker, CheckerRunner, CheckerPlan, SymbolTable

ROOT  = os.path.abspath(os.path.dirname(__file__))
PICKLE_DIR = os.path.normpath(os.path.join(ROOT, "./out"))

class CallVector(RangeSetVector):
    def __init__(self, func, rtn, sym_ids, symbol_tbl):
        self.func = func
        self.rtn = rtn
        self.sym_ids = sym_ids # ["0", "3", ...]
        self.symbol_tbl = symbol_tbl

        num_sym = max(len(self.sym_ids), 1)
        rs = rsf.build(self.sym_ids, range_area = 100.0 * num_sym)
        RangeSetVector.__init__(self, "@LOG_CALL", rs)

    def get_func_name(self):
        return self.func

    def get_rtn(self):
        return self.rtn

    def get_missing_calls(self, threshold):
        (myself_diff, avg_diff) = self.get_diffs("@LOG_CALL")
        if avg_diff == []:
            return ""
        
        total_impact = 0
        msto_str = "{{{-- "
        for ad in avg_diff:
            (impact, rs) = (ad[0], ad[1])
            assert(rs.start == rs.end)
            symbol = self.symbol_tbl.get_symbol_string( int(rs.start) )
            assert(symbol is not None)
            msto_str += "<%.5s, %s%s%s> " % \
                       (impact, Color.HEADER, symbol, Color.ENDC)

            total_impact += impact
            if total_impact >= threshold:
                break
        msto_str += "}}}"
        return msto_str

    def __repr__(self):
        return "'%s'" % self

    def __str__(self):
        return "%s:%s %s\n  %s"  % (self.func, self.rtn, self.sym_ids, self.rsv)

class CallChecker(BaseChecker):
    def __init__(self, rtn, pathbin, symbol_tbl):
        BaseChecker.__init__(self, pathbin)
        self.rtn = rtn
        self.symbol_tbl = symbol_tbl

    def report(self, report_all = True):
        print("%s[C] [%7s] [%.6s] [%23s] [%s]%s"% \
              (Color.HEADER,\
               "Ranking", "Distance", "Funtion", "Missing Calls", \
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
                   cv.get_missing_calls(delta * 0.7)))
        print("")

    def _build_vector(self, funcs):
        cvs = []

        # for each function
        for func in funcs:
            # collect callname of @LOG_CALL for the specified return value
            rtn_dic = self.pathbin[func]
            symbol_set = set()
            for retpath in rtn_dic.get(self.rtn, []):
                calls = retpath.get_calls()
                if calls == None:
                    continue
                for call in calls:
                    symbol_set.add(call.callname())

            # change them to symbol id 
            sym_id_set = set()
            for symbol in symbol_set:
                # NOTE: 
                # - Ignoring the details of arguments seems better 
                #   since our static analysis results have some errors. 
                # - So let's simply take functions names.
                """
                fo_symbol = filter_out_non_args(symbol)
                if have_args(fo_symbol):
                    sym_id= self.symbol_tbl.get_symbol_id(fo_symbol)
                    sym_id_set.add( str(sym_id) )
                """
                fo_symbol = symbol[0:symbol.find('(')]
                sym_id= self.symbol_tbl.get_symbol_id(fo_symbol)
                sym_id_set.add( str(sym_id) )
            
            cv = CallVector(func, self.rtn, list(sym_id_set), self.symbol_tbl)
            cvs.append(cv)
        return cvs

class CallCheckers(BaseChecker):
    def __init__(self):
        BaseChecker.__init__(self)
        self.rtn_funcs_dic = {} # {rtn, [list of functions]}*
        self.symbol_tbl = SymbolTable()
        self.cks = []

    def check(self, funcs):
        # collect functions, which return the same value
        self.__generate_rtn_funcs_dic(funcs)

        # run store check for each (return, functions) pair
        for rtn in self.rtn_funcs_dic.keys():
            if len(self.rtn_funcs_dic[rtn]) < 3:
                continue

            ckstore = CallChecker(rtn, self.pathbin, self.symbol_tbl)
            rtn_funcs  = self.rtn_funcs_dic[rtn]
            ckstore.check(rtn_funcs)

            self.cks.append(ckstore)

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
    runner = CheckerRunner(type(CallCheckers()), "fss-ckcall-", log_d, fs, *args)
    runner.run_check()
