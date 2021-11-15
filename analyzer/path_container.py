#!/usr/bin/env python2
# SPDX-License-Identifier: MIT

from path import RetPath
import os

ROOT = os.path.dirname(__file__)

def getRetPathKey(rp):
    key = "%s@%s" % (rp.get_target().get_func_name(), rp.get_rtn())
    return key

class RetPathContainer:
    def __init__(self):
        self.rpDict = {}
        self.rpDictFtn = {}
        return

    def append(self, rp):
        assert(isinstance(rp, RetPath))
        key = getRetPathKey(rp)
        self.rpDict[key] = self.rpDict.get(key, [])
        self.rpDict[key].append(rp)
        
        ftnName = rp.get_target().get_func_name()
        self.rpDictFtn[ftnName] = self.rpDictFtn.get(ftnName, [])
        self.rpDictFtn[ftnName].append(rp)
        return
    
    def getKeys(self):
        return self.rpDict.keys()

    def getByFuncName(self, ftnName):
        return self.rpDictFtn.get(ftnName, None)

    def __getitem__(self, key):
        return self.rpDict.get(key,None)

    def __len__(self):
        return len(self.rpDict)

def test():
    from parser import Parser
    log_d = os.path.join(ROOT, "data", "sample-fss-output")

    rpc = RetPathContainer()
    for path in Parser(log_d).parse():
        rpc.append(path)
    return

    
if __name__ == "__main__":
    test()

