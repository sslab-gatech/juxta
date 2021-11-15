#!/usr/bin/env python2
# SPDX-License-Identifier: MIT
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OPS_BASE_DIR = os.path.join(SCRIPT_DIR, "../doc/ops/linux-3.17")
#OPS_BASE_DIR = os.path.join(SCRIPT_DIR, "../doc/ops/linux-4.0")
FS_LIST = ["ext2", "ext3", "ext4", "btrfs", "f2fs", "jfs", "nilfs2", "xfs"]
OPS_LIST = ["address_space", "file", "inode", "super"]

class Ops():
    def __init__(self, opsName):
        assert(opsName in OPS_LIST)        
        self.d = {}
        self.opsName = opsName

        self.__parse()
        return

    def getSettingList(self):
        return self.d.keys()

    def getBaseFunctionList(self, setting):
        return self.d[setting].keys()

    def getFsFunctionList(self, setting, function):
        return self.d[setting][function]

    def __parse(self):
        dn = os.path.join(OPS_BASE_DIR, self.opsName)
        outputNames = [fn for fn in os.listdir(dn) if fn.startswith("output_")]
        
        for outputName in outputNames:
            self.d[outputName] = {}
            for line in open(os.path.join(dn, outputName)):
                line = line.strip()
                if line == "": continue
                items = line.split(",")
                function = items[0]
                assert(len(items) == len(FS_LIST)+1)
                self.d[outputName][function] = []
                for i, fsName in enumerate(FS_LIST):
                    fsFunction = items[i+1].strip()
                    if fsFunction == "NA":
                        fsFunction = None
                    self.d[outputName][function].append((fsName, fsFunction))
        return

'''
Yield the match function list for each FS.
example :
('address_space',
 'output_addr_ops_2',
 'readpages',
 [('ext2', 'ext2_readpages'),
  ('ext3', 'ext3_readpages'),
  ('ext4', 'ext4_readpages'),
  ('btrfs', 'btrfs_readpages'),
  ('f2fs', 'f2fs_read_data_pages'),
  ('jfs', 'jfs_readpages'),
  ('nilfs2', 'nilfs_readpages'),
  ('xfs', 'xfs_vm_readpages')])
'''

import collections

FOp = collections.namedtuple("FOp", "name struct field funcs")

def getAllEntryFunctions():
    allFuncSet = set()
    for opsName in OPS_LIST:
        o = Ops(opsName)
        for setting in o.getSettingList():
            functions = o.getBaseFunctionList(setting)
            for fn in functions:
                fns = o.getFsFunctionList(setting, fn)
                map(lambda x:allFuncSet.add(x[1]) if x[1] else False, fns)
    print "> Loaded all entry funcs :", len(allFuncSet)
    return allFuncSet
    
def matchFunctionGenerator():
    for opsName in OPS_LIST:
        o = Ops(opsName)
        for setting in o.getSettingList():
            functions = o.getBaseFunctionList(setting)
            for fn in functions:
                # bad names
                yield FOp(opsName, setting, fn, dict(o.getFsFunctionList(setting, fn)))
                
if __name__ == "__main__":
    getAllEntryFunctions()
    
    import pprint
    gen = matchFunctionGenerator()
    for i, l in enumerate(gen):
        print i,">"
        pprint.pprint(l)


