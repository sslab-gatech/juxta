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

class StoreVector(RangeSetVector):
    def __init__(self, func, rtn, sym_ids, symbol_tbl):
        self.func = func
        self.rtn = rtn
        self.sym_ids = sym_ids # ["0", "3", ...]
        self.symbol_tbl = symbol_tbl

        num_sym = max(len(self.sym_ids), 1)
        rs = rsf.build(self.sym_ids, range_area = 100.0 * num_sym)
        RangeSetVector.__init__(self, "@LOG_STORE", rs)

    def get_func_name(self):
        return self.func

    def get_rtn(self):
        return self.rtn

    def get_missing_stores(self, threshold):
        (myself_diff, avg_diff) = self.get_diffs("@LOG_STORE")
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

class StoreChecker(BaseChecker):
    def __init__(self, rtn, pathbin, symbol_tbl):
        BaseChecker.__init__(self, pathbin)
        self.rtn = rtn
        self.symbol_tbl = symbol_tbl

    def report(self, report_all = True):
        print("%s[C] [%7s] [%.6s] [%23s] [%s]%s"% \
              (Color.HEADER,\
               "Ranking", "Distance", "Funtion", "Missing Updates", \
               Color.ENDC))
        for (ranking, result) in enumerate(self.results):
            distance = result[0]
            sv = result[1]
            if not report_all and distance <= self.avg_distance:
                break
            (cc, ac, l) = self._get_color_code(result)
            delta = distance - self.avg_distance
            print("%s[%s]  %7s   %.6s   %23s   %s%s"% \
                  (cc, ac, \
                   ranking+1, delta, \
                   ''.join((sv.get_func_name(), \
                            ':', \
                            errno_to_str(sv.get_rtn()))), \
                   Color.ENDC, \
                   sv.get_missing_stores(delta * 0.7)))
        print("")

    def _build_vector(self, funcs):
        svs = []

        # for each function
        for func in funcs:
            # collect LHS of @LOG_STORE for the specified return value
            rtn_dic = self.pathbin[func]
            symbol_set = set()
            for retpath in rtn_dic.get(self.rtn, []):
                stores = retpath.get_stores()
                if stores == None:
                    continue
                for store in stores:
                    # collect LHS of stor
                    if store.lhs:
                        assert(store.lhs is not None)
                        symbol_set.add(store.lhs)

            # change them to symbol id 
            sym_id_set = set()
            for symbol in symbol_set:
                fo_symbol = filter_out_non_args(symbol)
                if have_args(fo_symbol):
                    sym_id= self.symbol_tbl.get_symbol_id(fo_symbol)
                    sym_id_set.add( str(sym_id) )
            
            sv = StoreVector(func, self.rtn, list(sym_id_set), self.symbol_tbl)
            svs.append(sv)
        return svs

class StoreCheckers(BaseChecker):
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

            ckstore = StoreChecker(rtn, self.pathbin, self.symbol_tbl)
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
    runner = CheckerRunner(type(StoreCheckers()), "fss-ckstore-", log_d, fs, *args)
    runner.run_check()
