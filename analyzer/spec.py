#!/usr/bin/env python2
# SPDX-License-Identifier: MIT

import os
from checker import BaseChecker
import pprint
import fsop
import utils
from color import Color
import sys
import multiprocessing as mp
import time
from call_flags import Logger

ROOT = os.path.dirname(__file__)

MIN_REPORT_SCORE = 0.5

FEATURE_BLACKLIST = [
    "(E # __builtin_expect",
    "(E # __builtin_constant_p",
    ]

def is_blacklisted_feature(feature):
    # if True in map(lambda x:feature.startswith(x), FEATURE_BLACKLIST):
    #     return True
    return False

class CommonRetPath:
    def __init__(self):
        self.paths = []

        self.common_dict_conds = {}
        self.common_dict_stores = {}
        self.common_dict_calls = {}

        self.updated_func_conds = set()
        self.updated_func_stores = set()
        self.updated_func_calls = set()

        self.updated_funcs = set()
        
        self.num_updated = 0
        self.no_color = False
        return
    
    def getFlattenFeatures(self, kind, rtn_paths):
        kindFunc = "get_%s" % kind
        l = map(lambda x:getattr(x, kindFunc)(), rtn_paths)
        flattenItems = [item for sublist in l if sublist for item in sublist]
        features = [x.get_feature() for x in flattenItems]
        return features

    def compute_match_score(self, func_set, updated_func_set):
        # TODO : need somehow better score matching methods.
        if len(func_set) <= 1:
            return 0
        score = 1.0 * len(func_set) / len(updated_func_set)
        assert(score <= 1.0)
        return score

    def get_num_updated_funcs(self):
        return len(self.updated_funcs)

    def decorate_str(self, s, score=None, color_cmd=None):
        if self.no_color:
            return s

        if color_cmd:
            if color_cmd == "g":
                clr = Color.OKGREEN
            elif color_cmd == "r":
                clr = Color.FAIL
        elif score:
            if score >= 1:
                clr = Color.WARNING
            elif score >= MIN_REPORT_SCORE:
                clr = Color.FAIL
            else:
                clr = ""
        else:
            clr = ""
            
        ds = "%s%s%s%s" % (Color.HEADER, clr, s, Color.ENDC)
        return ds
    
    def update_common_feature(self, func, rtn_paths):
        for kind in ["conds", "stores", "calls"]:
            features = self.getFlattenFeatures(kind, rtn_paths)
            common_dict = getattr(self, "common_dict_%s" % kind)
            updated_func_kind = getattr(self, "updated_func_%s" % kind)
            for feature in features:
                if feature == "" or feature == None or \
                       is_blacklisted_feature(feature):
                    continue
                func_set = common_dict.get(feature, set())
                func_set.add(func)
                common_dict[feature] = func_set
                updated_func_kind.add(func)
        self.num_updated += 1
        self.updated_funcs.add(func)
        return

    def __str__(self):
        return s

    def report(self, name_info, retExpr_info = ""):
        header_printed = False

        logger = Logger()
        logger.log("> Reporting %s @ %s\n" % (name_info, retExpr_info))

        for kind in ["conds", "stores", "calls"]:
            common_dict = getattr(self, "common_dict_%s" % kind)
            updated_func_set = getattr(self, "updated_func_%s" % kind)
            if len(common_dict) == 0: continue

            for feature, func_set in common_dict.iteritems():
                score = self.compute_match_score(func_set, updated_func_set)
                if score > MIN_REPORT_SCORE:
                    if not header_printed:
                        print
                        logger.log(self.decorate_str("> Report on %s\n" %
                                                     name_info, color_cmd='g'))
                        logger.log("\t Return value : %s\n" % retExpr_info)
                        logger.log("\t Num updated : %d\n" % self.num_updated)
                        header_printed = True
                    logger.log("    [%s] : %s " % \
                               (self.decorate_str(kind, score=score),\
                                self.decorate_str(feature, score=score)))
                    logger.log("\t %d/%d" % (len(func_set), len(updated_func_set)))
                    missing_funcs = list(updated_func_set-func_set)
                    if len(missing_funcs) > 0:
                        logger.log(self.decorate_str(missing_funcs,
                                                     color_cmd="r"))
                    logger.log(str(list(func_set)) + "\n")
        logger.log("> END\n\n")
        return str(logger)

class SpecChecker(BaseChecker):
    def __init__(self, name = "NA"):
        BaseChecker.__init__(self)
        self.name = name

    def check_with_ret_bin(self, funcs, rtn_paths_list):
        # Compute a intersection of return values. Here, we are not interested
        # in missing return values as the focus is to identify similarities.
        common_ret_exprs = set()
        for func, rtn_paths in zip(funcs, rtn_paths_list):
            if rtn_paths == None:
                continue
            if len(common_ret_exprs) == 0:
                common_ret_exprs.update(rtn_paths.keys())
            else:
                common_ret_exprs.intersection_update(rtn_paths.keys())

        res = ""
        for retExpr in common_ret_exprs:
            common = CommonRetPath()
            for func, rtn_paths in zip(funcs, rtn_paths_list):
                if rtn_paths == None or not rtn_paths.get(retExpr, None):
                    continue
                common.update_common_feature(func, rtn_paths[retExpr])
            res += common.report(funcs, retExpr)
        return res

    def check_without_ret_bin(self, funcs, rtn_paths_list):
        # No bins on return values.
        common = CommonRetPath()
        for func, rtn_paths in zip(funcs, rtn_paths_list):
            if rtn_paths == None:
                continue
            map(lambda x:common.update_common_feature(func, x),
                rtn_paths.values())
        return common.report(funcs, "N/A")
    
    def check_and_report(self, funcs):
        rtn_paths_list = self.get_rtn_paths_list(funcs)
        res = ""
        res += self.check_without_ret_bin(funcs, rtn_paths_list)
        res += self.check_with_ret_bin(funcs, rtn_paths_list)
        return res

def match_each(funcs):
    ck = SpecChecker(str(funcs))

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

        while 1:
            if len(results) == 0:
                break
            print "> Unfinished jobs : ", len(results)
            print
            next_results = []
            for res in results:
                try:
                    print res.get(False),
                except mp.TimeoutError:
                    next_results.append(res)
                
            time.sleep(2)
            results = next_results

    for funcs in match_funcs:
        match_each(funcs)
    return

def test_rename():
    funcs = ["ext2_rename", 
             "ext3_rename", 
             "ext4_rename2", 
             "btrfs_rename2", 
             ]
    
    log_d = os.path.join(ROOT, "data", "sample-fss-output")
    ck = SpecChecker(funcs)
    ck.load_pathbin(log_d)
    ck.check_and_report(funcs)
        
if __name__ == '__main__':
    utils.install_pdb()
    # test_rename()

    if len(sys.argv) > 1:
        match_funcs = eval(sys.argv[1])
        main(match_funcs)
    else:
        main(num_parallel = 4)
