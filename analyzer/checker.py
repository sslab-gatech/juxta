#!/usr/bin/env python2

import os
import sys
import dbg
import utils
import cPickle as pickle
import errno
from color import Color
import optparse
import collections
import multiprocessing
import datetime
import glob
import pdb
from os.path import join

import fsop
from pathbin import PathBin, get_pickle_name
from rsv import RangeSetVector, calc_average_rsv

ROOT  = os.path.abspath(os.path.dirname(__file__))
PICKLE_DIR = os.path.normpath(os.path.join(ROOT, "./out"))

class BaseChecker(object):
    def __init__(self, pathbin = None):
        self.pathbin = pathbin
        self.results = []
        self.avg = RangeSetVector()
        self.avg_distance = 0
        self.colors = []


    def load_pathbin(self, log_d):
        self.pathbin = PathBin(log_d, verbose=False)
        self.pathbin = self.pathbin.load_pickle()
        return self if self.pathbin is not None else None

    def load_pathbin_from_pickle(self, func, pkl_name):
        if not self.pathbin:
            self.pathbin = PathBin("", verbose=False)
        self.pathbin.load_from_pickle(func, pkl_name)
        return

    def get_rtn_paths(self, func):
        return self.pathbin[func]

    def get_rtn_paths_list(self, funcs):
        rtn_paths_list = []
        for func in funcs:
            rtn_paths = self.pathbin[func]
            rtn_paths_list.append(rtn_paths)
        return rtn_paths_list

    def check(self, funcs):
        rvs = self._build_vector(funcs)
        self.avg = calc_average_rsv(rvs)
        self.avg_distance = 0
        for (n, rv) in enumerate(rvs):
            distance = rv.distance(self.avg)
            self.results.append([distance, rv])
            self.avg_distance += distance
        self.avg_distance /= float(n+1)
        self.results.sort(reverse=True)
        self._build_color_table()

    def _build_color_table(self):
        r4 = (self.results[-1][0] - self.avg_distance) / 2.0 + self.avg_distance
        r3 = self.avg_distance
        r2 = (self.results[0][0] - self.avg_distance) / 2.0 + self.avg_distance
        r1 = self.results[0][0]
        self.colors = [(r4, Color.OKGREEN, 'O'),
                       (r3, Color.OKBLUE,  'o'), 
                       (r2, Color.WARNING, '?'), 
                       (r1, Color.FAIL,    'X')]
                       
    def _get_color_code(self, result):
        distance = result[0]
        for (l, c) in enumerate(self.colors):
            if distance <= c[0]:
                return (c[1], c[2], l)
        assert(0)
        
    def __repr__(self):
        return "'%s'" % self

    def __str__(self):
        return "%s"  % self.results

class SymbolTable(object):
    def __init__(self):
        self.symbol_tbl = {}    # {symbol string, id}*
        self.id_tbl = {}        # {id, symbol string}
        self.__symbol_id = 0

    def get_symbol_id(self, sym_str):
        # look up the symbol dictionary. 
        sym_id = self.symbol_tbl.get(sym_str, None)
        if sym_id == None:
            self.symbol_tbl[sym_str] = sym_id = self.__symbol_id
            self.id_tbl[sym_id] = sym_str
            self.__symbol_id += 3
        return sym_id

    def get_symbol_string(self, sym_id):
        return self.id_tbl.get(sym_id, None)

    def __repr__(self):
        return "'%s'" % self

    def __str__(self):
        return "%s" % self.symbol_dict

class CheckerPlan(object):
    def __init__(self, ck_type, log_d, funcs, id, temp_d):
        self.ck_type = ck_type
        self.log_d = log_d
        self.funcs = funcs
        self.id = id
        self.temp_d = temp_d
        self.redirect = True

    def __repr__(self):
        return "'%s'" % self

    def __str__(self):
        return "[%s %s]" % (self.log_d, self.funcs)

def do_check(plan):
    # redirect stdout and stderrto log files.
    if plan.redirect:
        out_file = join(plan.temp_d, str(plan.id).zfill(5) + ".log")
        err_file = join(plan.temp_d, str(plan.id).zfill(5) + ".err")
        org_stdout = sys.stdout
        org_stderr = sys.stderr
        sys.stdout = open(out_file, "a", buffering=0)
        sys.stderr = open(err_file, "a", buffering=0)

    # run checker
    ck = plan.ck_type()
    if ck.load_pathbin(plan.log_d) == None:
        print("> Fail to load pickle file at %s" % plan.log_d)
        return -1
    ck.check(plan.funcs)
    ck.report()

    # remove .err if there was no error. 
    if plan.redirect and os.path.getsize(err_file) == 0:
        os.remove(err_file)
        sys.stdout.close()
        sys.stderr.close()
        sys.stdout = org_stdout
        sys.stderr = org_stderr
    return 0

class CheckerRunner(object):
    def __init__(self, ck_type, out_prefix, log_d, fs, check_all = False, debug = False, *args):
        self.ck_type = ck_type
        self.out_prefix = out_prefix
        self.log_d = log_d
        self.fs = fs
        self.args = args
        self.plans = set()
        self.temp_d = ""
        self.check_all = check_all
        self.debug = debug

    def run_check(self):
        # setup plan for parallel analysis
        print("%s[1/3] Create analysis plan.%s" % \
              (Color.HEADER, Color.ENDC))
        self.__generate_plan()

        # parallelizing analysis
        print("%s[2/3] Running checker. Logs will be in %s %s" % \
              (Color.HEADER, self.temp_d, Color.ENDC))
        if not self.debug:
            self.__parallel_exec()
        else:
            self.__sequential_exec()

        # done
        print("%s[3/3] Done. Logs are in %s %s" % \
              (Color.HEADER, self.temp_d, Color.ENDC))
        
    def __parallel_exec(self):
        os.mkdir(self.temp_d)

        ncpu  = min(multiprocessing.cpu_count(), max(len(self.plans), 1))
        pool = multiprocessing.Pool(processes=ncpu,)
        pool_returns = pool.map(do_check, self.plans)
        pool.close()
        pool.join()

    def __sequential_exec(self):
        for plan in self.plans:
            plan.redirect = False
            do_check(plan)

    def __generate_plan(self):
        dt = str(datetime.datetime.now()).replace(' ','-').replace(':','-')
        self.temp_d = ''.join(("/tmp/", self.out_prefix, dt))
        self.plans = set()

        for (id, fops) in enumerate(self.__generate_fops()):
            plan = CheckerPlan(self.ck_type, self.log_d, fops, id, self.temp_d)
            self.plans.add(plan)

    def __generate_fops(self):
        all_pickles = glob.glob( join(self.log_d, "*.p") )
        if self.check_all:
            for pickle in all_pickles:
                fops = pickle[len(self.log_d)+9:-2]
                yield [fops]
        else:
            for fops in fsop.get_matched_ops(self.fs, *self.args):
                fops = self.__check_validity(all_pickles, fops)
                if fops == None:
                    continue
                yield fops
        """
        # XXX
        return [["btrfs_rename2", "ext2_rename", "ext3_rename", "ext4_rename2"]]
        """

    def __check_validity(self, all_pickles, fops):
        stop_words = ['XATTR_USER_PREFIX',
                      'XATTR_TRUSTED_PREFIX',
                      'THIS_MODULE']
        if fops == None or len(fops) < 3 or fops[0] in stop_words:
            return None

        filtered_fops = set()
        for op in fops:
            op = op.strip()
            pickle = get_pickle_name(self.log_d, op)
            if pickle in all_pickles:
                filtered_fops.add(op)
        fops = list(filtered_fops)

        if len(fops) < 3:
            return None
        return fops

    def __repr__(self):
        return "'%s'" % self

    def __str__(self):
        return "[%s %s]" % (self.log_d, self.args)

if __name__ == "__main__":
    _test_canonicalize()
