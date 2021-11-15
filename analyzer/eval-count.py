#!/usr/bin/env python2
# SPDX-License-Identifier: MIT
import os
import pprint
import fsop
import utils
from checker import BaseChecker
import multiprocessing as mp

ROOT  = os.path.abspath(os.path.dirname(__file__))
PKL_BASE_DIR = "/data/fss-data/out-2015-03-19"

class Counter(BaseChecker):
    def __init__(self, fs_name = "NA"):
        BaseChecker.__init__(self)
        self.fs_name = fs_name
        self.count = {}
        self.count["path"] = 0
        self.count["cond"] = 0
        self.count["cond-conj"] = 0
        self.count["call"] = 0
        self.count["store"] = 0

    def update(self, func):
        rtn_paths = self.get_rtn_paths(func)
        if not rtn_paths:
            return
        
        for rp_list in rtn_paths.values():
            self.count["path"] += len(rp_list)
            # for rp in rp_list:
            #     conds = rp.get_conds()

            #     if conds:
            #         self.count["cond"] += len(conds)
            #         conj_conds = [x for x in conds \
            #                       if x.is_conjure()]

            #         if conj_conds:
            #             self.count["cond-conj"] += len(conj_conds)
                
            #     try:
            #         self.count["call"] += len(rp.get_calls())
            #     except TypeError:
            #         pass
            #     try:
            #         self.count["store"] += len(rp.get_stores())
            #     except TypeError:
            #         pass
                    
        return

    def report(self):
        return self.fs_name + ":" + str(self.count)

def count_fs(fs, funcs = None):
    ct = Counter(fs)

    if not funcs:
        funcs = fsop.get_fs_entry_funcs([fs], "*")
        funcs = list(set(funcs))

    for func in funcs:
        pkl_name = os.path.join(PKL_BASE_DIR, "pathbin.%s.p" % func)
        ct.load_pathbin_from_pickle(func, pkl_name)
        ct.update(func)
    return ct.report()

def load_all_available_funcs_by_fs(fs_list):
    fs_func_dic = {}
    for fn in os.listdir(PKL_BASE_DIR):
        if not fn.startswith("pathbin.") or not fn.endswith(".p"):
            continue
        try:
            fs_name, func_name = fn.split(".",1)[1].split("_",1)
        except ValueError:
            continue

        if fs_name in fs_list:
            assert(func_name.endswith(".p"))
            func_name = func_name[:-2]
            print fs_name, func_name
            l = fs_func_dic.get(fs_name, [])
            l.append(func_name)
            fs_func_dic[fs_name] = l
    return fs_func_dic

def main():
    fs_list = fsop.get_all_fs()
    print fs_list

    fs_func_dic = load_all_available_funcs_by_fs(fs_list)    

    num_parallel = 30
    pool = mp.Pool(num_parallel)
    results = [pool.apply_async(count_fs, args=(fs,fs_func_dic[fs])) \
               for fs in fs_list]
    pool.close()
    pool.join()
    for res in results:
        print res.get(False)
        #res = count_fs(fs)
    return

def count_path_by_funcs(target_funcs, k0, k1):
    res = {}

    matches = fsop.get_ops("*", "*")
    for keys, func_dict in matches:
        fs = keys[0]
        for tf in target_funcs:
            func = func_dict.get(tf, None)
            if func and k0 == keys[1] and k1 == keys[2]:
                res[fs] = func


    fs_list = ["btrfs","ext2","ext3","ext4","fat","jfs","reiserfs","xfs"]

    for fs in fs_list:
        func = res.get(fs, None)
        if func:
            print count_fs("%s @ %s" % (fs, func), [func])
        else:
            print "%s is missing" % fs
    return

def test_rename():
    funcs = ["ext2_rename", 
             "ext3_rename", 
             "ext4_rename2", 
             "btrfs_rename2", 
             ]
    
    log_d = os.path.join(ROOT, "data", "sample-fss-output")
    ct = Counter("test-rename")
    ct.load_pathbin(log_d)
    for func in funcs:
        ct.update(func)
    print ct.report()
    return

if __name__ == '__main__':
    utils.install_pdb()
    # test_rename()
    # main()
    count_path_by_funcs(["lookup"], "inode", "dir")
    count_path_by_funcs(["create"], "inode", "dir")
    count_path_by_funcs(["rename", "rename2"], "inode", "dir")

