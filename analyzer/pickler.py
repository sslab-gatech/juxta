#!/usr/bin/env python2
# SPDX-License-Identifier: MIT

import os
import sys
import dbg
import utils
import cPickle as pickle
import sys
import multiprocessing
import glob
import pdb
from os.path import join
from color import Color

from parser import Parser
from pathbin import PathBin, PICKLE_NAME

ROOT = os.path.dirname(__file__)
PICKLER_NAME = "_pickler"
MIN_UNIT_SIZE = 32 * 1024 * 1024

class PicklePlan(object):
    def __init__(self, log_d, id, sub_id, fss, start, end):
        self.log_d = log_d
        self.id = id
        self.sub_id = sub_id
        self.fss = fss
        self.start = start
        self.end = end

    def get_pickle_name(self):
        return '-'.join((PICKLER_NAME, \
                         str(self.id).zfill(4), \
                         str(self.sub_id).zfill(4)))

    def __repr__(self):
        return "'%s'" % self

    def __str__(self):
        return "[%s:%s %s:%s:%s]" % \
            (self.id, self.sub_id, self.fss, self.start, self.end)

def do_pickle(plan):
    pathbin = PathBin(plan.log_d, plan.get_pickle_name())
    pathbin.parse_file(plan.fss, plan.start, plan.end)
    pathbin.save_as_pickle()
    return 0

class FixupPlan(object):
    def __init__(self, log_d, func, pickle_files):
        self.log_d = log_d
        self.func = func
        self.pickle_files = pickle_files

    def __repr__(self):
        return "'%s'" % self

    def __str__(self):
        return "%s %s" % (self.func, self.pickle_files)

def do_fixup(plan):
    # single file, no merge, simple rename
    if len(plan.pickle_files) == 1:
        dst = join(plan.log_d, '.'.join((PICKLE_NAME, plan.func, "p")))
        os.rename(plan.pickle_files[0], dst)
        print("@RENAME: %s => %s" % (plan.pickle_files[0], dst))
    # scattered to multiple files, merge them all
    else:
        pathbin = PathBin(plan.log_d).load_from_pickle(plan.func, plan.pickle_files[0])
        print("@MERGE: %s " % plan.pickle_files[0])
        assert(pathbin)
        for pickle in plan.pickle_files[1:]:
            tempbin = PathBin(plan.log_d).load_from_pickle(plan.func, pickle)
            print("@MERGE: %s " % pickle)
            assert(tempbin)
            pathbin.merge(tempbin)
        pathbin.save_as_pickle()

        # remove temp. pickle files
        for pickle in plan.pickle_files:
            os.remove(pickle)
    return 0

class Pickler(object):
    def __init__(self, log_d):
        self.log_d = log_d
        self.ncpu  = multiprocessing.cpu_count()
        self.parser = Parser(self.log_d)

    def parse_and_pickle(self):
        print("%s[1/2] Parsing and save pickcles %s"% (Color.HEADER, Color.ENDC))
        self._pickle()
        print("%s[2/2] Fixup dividend pickles %s"% (Color.HEADER, Color.ENDC))
        self._fixup()
        print("%s== Happy pickling! ==%s"% (Color.OKGREEN, Color.ENDC))
        
    def __pickle_plans(self):
        total_size = 0
        size_fss_list = []
        for fss in self.parser.get_files():
            fss_size = os.path.getsize(fss)
            size_fss_list.append([fss_size, fss])
            total_size += fss_size
        size_fss_list.sort(reverse=True)
            
        unit = max(total_size/(self.ncpu * 4), MIN_UNIT_SIZE)
        plans = []
        for (id, size_fss) in enumerate(size_fss_list):
            (size, fss) = (size_fss[0], size_fss[1])
            for (sub_id, start) in enumerate(range(0, size+unit/2, unit)):
                plan = PicklePlan(self.log_d, \
                                  id, sub_id, \
                                  fss, start, start + unit)
                plans.append(plan)
        return plans

    def _pickle(self):
        pool = multiprocessing.Pool(processes=self.ncpu,)
        pool_returns = pool.map(do_pickle, self.__pickle_plans())
        pool.close()
        pool.join()

    def __fixup_plans(self):
        pickles = glob.glob( join(self.log_d, PICKLER_NAME + "*.p"))
        pickle_dic = {}

        # construct pickle dictionary 
        #  { function name, [pickle file names, ...]}
        for pickle in pickles:
            func_p = pickle.split('.')[-2:-1][0]
            pickle_files = pickle_dic.get(func_p, [])
            pickle_files += [pickle]
            pickle_dic[func_p] = pickle_files

        # fixup plan
        plans = []
        for key in pickle_dic:
            plan = FixupPlan(self.log_d, key, pickle_dic[key])
            plans.append(plan)
        return plans

    def _fixup(self):
        pool = multiprocessing.Pool(processes=self.ncpu,)
        pool_returns = pool.map(do_fixup, self.__fixup_plans())
        pool.close()
        pool.join()
            
    def __repr__(self):
        return "'%s'" % self

    def __str__(self):
        return "Pickler for %s" % self.log_d
    

def parse_and_pickle(log_d):
    Pickler(log_d).parse_and_pickle()

if __name__ == '__main__':
    utils.install_pdb()

    # perfered one
    log_d = os.path.join(ROOT, "data", "sample-fss-output")
    if len(sys.argv) > 1:
        log_d = sys.argv[1]

    parse_and_pickle(log_d)
