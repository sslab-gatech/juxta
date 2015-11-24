#!/usr/bin/env python2

import os
import sys
import dbg
import utils
import cPickle as pickle
import pdb
import fsop
import time
import glob

from os.path import join
from parser import Parser
from argnorm import ArgNormalizer

ROOT = os.path.dirname(__file__)
BASE_DIR = join(ROOT, "out")
SUFFIX_DIR = "clang-log"
PICKLE_NAME = "pathbin"
DIC_STATUS_LOADING = "@LOADING"
DIC_STATUS_ERROR = "@IO_ERROR"
ALL_ENTRY_FUNCS = fsop.get_all_fs_entry_funcs()

def get_pickle_name(log_d, func, pickle_prefix = PICKLE_NAME):
    return join(log_d, '.'.join((pickle_prefix, func, "p")))

def _merge_dict(lhs, rhs):
    # merges rhs into lhs
    for key in rhs:
        if key in lhs:
            if isinstance(lhs[key], dict) and isinstance(rhs[key], dict):
                _merge_dict(lhs[key], rhs[key])
            else:
                lhs[key] += rhs[key]
        else:
            lhs[key] = rhs[key]

class PathBin(object):
    def __init__(self, log_d, pickle_name = PICKLE_NAME, verbose=True):
        # { @FUNCTION, 
        #   {@RETURN, [RetPath*]} }
        self.fn_dic = {}
        self.log_d = log_d
        self.pickle_name = pickle_name
        self.verbose = verbose

    def __getitem__(self, func):
        dic = DIC_STATUS_LOADING
        while dic == DIC_STATUS_LOADING:
            dic = self.fn_dic.get(func, None)
            if dic == DIC_STATUS_ERROR:
                return None
            elif dic == None:
                pickle_name = self.__get_pickle_name(func)
                dic = self.__load_from_pickle(func, pickle_name)
                if dic == DIC_STATUS_ERROR:
                    return None
        return dic

    def load_pickle(self):
        if glob.glob(self.__get_pickle_name("*")):
            return self
        return None
            
    def parse_all(self):
        t0 = time.clock()
        self.__parse_dir()
        t1 = time.clock()
        print("> Parsing complete [%s] (took %.2lf secs)" % (self.log_d, t1-t0))
        return

    def parse_file(self, fss_name, start = 0, end = 2**64):
        t0 = time.clock()
        self.__parse_file(fss_name, start, end)
        t1 = time.clock()
        print("> Parsing complete [%s] (took %.2lf secs)" % (fss_name, t1-t0))
        return

    def load_from_pickle(self, func, pickle_name):
        self.__load_from_pickle(func, pickle_name)
        return self

    def __load_from_pickle(self, func, pickle_name):
        try:
            self.fn_dic[func] = DIC_STATUS_LOADING
            with open(pickle_name, "rb") as fd:
                self.fn_dic[func] = pickle.load(fd)
        except IOError:
            self.fn_dic[func] = DIC_STATUS_ERROR
            if self.verbose:
                print("> Fail to load %s from %s" % (func, pickle_name))
        finally:
            return self.fn_dic[func]

    def save_as_pickle(self):
        for func in self.fn_dic.keys():
            func_dic = self.fn_dic[func]
            pickle_name = self.__get_pickle_name(func)
            with open(pickle_name, "wb") as fd:
                pickle.dump(func_dic, fd)
        
    def merge(self, rhs):
        _merge_dict(self.fn_dic, rhs.fn_dic)

    def __parse_file(self, fss_name, start = 0, end = 2**64):
        parser = Parser(self.log_d)
        for (cnt, path) in enumerate(parser.parse_file(fss_name, start, end)):
            self.__process_path(cnt, path)

    def __parse_dir(self):
        for (cnt, path) in enumerate(Parser(self.log_d).parse()):
            self.__process_path(cnt, path)
            
    def __process_path(self, cnt, path):
        # function name
        fn = path.get_target().get_func_name()
        """
        # XXX: do not filter out non-VFS functions
        if not fn in ALL_ENTRY_FUNCS:
            return
        """
            
        # normalization
        ArgNormalizer(path)

        rtn_dic = self.fn_dic.get(fn, None)
        if not rtn_dic:
            self.fn_dic[fn] = rtn_dic = {}

        # return condition
        rtn = path.get_rtn()
        paths = rtn_dic.get(rtn, None)
        if not paths:
            rtn_dic[rtn] = paths = []

        # append path condition
        paths.append(path)

        if cnt % 1000 == 0:
            sys.stdout.write("[%s]" % cnt)
            sys.stdout.flush()

    def __get_pickle_name(self, func):
        return get_pickle_name(self.log_d, func, self.pickle_name)

    def __get_pickle_lock_file(self):
        return self.__get_pickle_name("L.O.C.K")

    def __len__(self):
        return len(self.fn_dic)

    def __repr__(self):
        return "'%s'" % self

    def __str__(self):
        return " PathBin has %d paths"  % (len(self.fn_dic))

def __test_simple_load():
    # get log dir
    log_d = os.path.join(ROOT, "data", "sample-fss-output")
    if len(sys.argv) > 1:
        log_d = sys.argv[1]

    # load from directory 
    pathbin1 = PathBin(log_d)
    pathbin1.parse_all()
    pathbin1.save_as_pickle()
    print("@@@ %s" % pathbin1["ext2_rename"])
    

    pathbin2 = PathBin(log_d)
    print("@@@ %s" % pathbin2["ext2_rename"])

def __test_simple_load_func(func):
    import pprint

    pathbin = PathBin("")
    pkl_name = os.path.join("/data/fss-data/out-2015-03-19", "pathbin.%s.p" % func)
    pathbin.load_from_pickle(func, pkl_name)
    rtn_paths = pathbin[func]
    for ret_expr, paths in rtn_paths.iteritems():
        print "ret:", ret_expr
        for path in paths:
            print path
    return
            
if __name__ == '__main__':
    utils.install_pdb()

    if len(sys.argv) > 1:
        func = sys.argv[1]
        __test_simple_load_func(func)
    else:
        __test_simple_load()        
