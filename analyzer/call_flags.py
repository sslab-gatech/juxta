#!/usr/bin/env python2
# SPDX-License-Identifier: MIT
import os
from checker import BaseChecker
import pprint
import fsop
import utils
from color import Color
import sys
from collections import Counter
import scipy.stats
import multiprocessing as mp
import time
from bugginess import calc_bugginess

ROOT = os.path.dirname(__file__)

PATTERNS = {}
PATTERNS["kmalloc"] = 1
PATTERNS["__vmalloc"] = 1
PATTERNS["kzalloc"] = 1
PATTERNS["radix_tree_preload"] = 0
PATTERNS["kmemdup"] = 2
PATTERNS["kstrdup"] = 1
PATTERNS["kmem_cache_alloc"] = 1
PATTERNS["mempool_alloc"] = 1
PATTERNS["find_or_create_page"] = 2
PATTERNS["get_zeroed_page"] = 2
PATTERNS["blkdev_issue_flush"] = 2

report_in_one_line = False

def compute_entropy(xs):
    freq = Counter(xs)
    e = scipy.stats.entropy(freq.values())
    return freq, e

class Logger:
    def __init__(self):
        self.msg = ""
        return

    def log(self, msg):
        self.msg += msg

    def __str__(self):
        return self.msg
    
class CallArgPatterns:
    def __init__(self):
        self.patterns = {}
        for p in PATTERNS:
            self.patterns[p] = []
        return
    
    def get_flatten_calls(self, rtn_paths):
        l = map(lambda x:x.get_calls(), rtn_paths)
        flatten_calls = [item for sublist in l if sublist for item in sublist]
        return flatten_calls

    def update(self, func, rtn_paths):
        calls = self.get_flatten_calls(rtn_paths)
        for call in calls:
            call_name = call.basename()
            if call_name in PATTERNS.keys():
                index = PATTERNS[call_name]
                arg = call.get_arg(index)
                self.patterns[call_name].append((arg, func))                
        return


    def report(self, name_info, ret_info = ""):
        logger = Logger()
        header_out = False

        for name, values in self.patterns.iteritems():
            if len(values) <= 1:
                continue

            freq_info, e = compute_entropy([x[0] for x in values])
            if len(freq_info) == 1:
                # We have no interests here.
                continue
            bug_info = calc_bugginess(freq_info)

            if not report_in_one_line:
                if header_out is False:
                    logger.log("\n> Reporting %s @ %s\n" % (name_info, ret_info))
                    header_out = True
                logger.log(">> %s\n" % name)
                logger.log(">>\t %s\n" % str(freq_info))
                logger.log(">>\t entropy : %f\n" % e)
                logger.log(">>\t bugginess : %s\n" % bug_info)
            else:
                # entroy api file system @ return info 
                logger.log("%f : %s : %s : %s : %s \n" % (e, name, name_info, ret_info, str(freq_info)))

        if header_out:
            if not report_in_one_line:
                logger.log("> END\n\n")
        return str(logger)
    
class CallFlagsChecker(BaseChecker):
    def __init__(self, name = "NA"):
        BaseChecker.__init__(self)
        self.name = name

    def check_without_ret_bin(self, funcs, rtn_paths_list):
        # No bins on return values.
        cap = CallArgPatterns()
        for func, rtn_paths in zip(funcs, rtn_paths_list):
            if rtn_paths == None:
                continue

            map(lambda x:cap.update(func, x), rtn_paths.values())
        return cap.report(funcs, "N/A")

    def check_and_report(self, funcs):
        rtn_paths_list = self.get_rtn_paths_list(funcs)
        logs = ""
        logs += self.check_without_ret_bin(funcs, rtn_paths_list)
        # logs += self.check_with_ret_bin(funcs, rtn_paths_list)
        return logs

def match_each(funcs):
    ck = CallFlagsChecker(str(funcs))

    for func in funcs:
        # pkl_name = os.path.join("out", "pathbin.%s.p" % func)
        pkl_name = os.path.join("/data/fss-data/out-2015-03-19", "pathbin.%s.p" % func)
        ck.load_pathbin_from_pickle(func, pkl_name)

    return ck.check_and_report(funcs)

def main(match_funcs = None, num_parallel = 1):
    if not match_funcs:
        fs_list = fsop.get_all_fs()
        match_funcs = fsop.get_matched_ops(fs_list, "*")

    if num_parallel > 1:
        pool = mp.Pool(num_parallel)    
        results = [pool.apply_async(match_each, args=(x,)) for x in match_funcs]
        pool.close()
        pool.join()
        
        for res in results:
            try:
                print res.get(False)
            except:
                print("")
    else:
        for funcs in match_funcs:            
            print match_each(funcs)            
    return

def test_rename():
    funcs = ["ext2_rename", 
             "ext3_rename", 
             "ext4_rename2", 
             "btrfs_rename2", 
             ]
    
    log_d = os.path.join(ROOT, "data", "sample-fss-output")
    ck = CallFlagsChecker(funcs)
    ck.load_pathbin(log_d)
    ck.check_and_report(funcs)
    return
        
if __name__ == '__main__':
    utils.install_pdb()
    # test_rename()

    if len(sys.argv) > 1:
        match_funcs = eval(sys.argv[1])
        main(match_funcs)
    else:
        main(num_parallel=mp.cpu_count())


