#!/usr/bin/env python2
# SPDX-License-Identifier: MIT

class ConditionContainer(object):
    def __init__(self, isCNF=True, conditions = None):
        self.isCNF = isCNF
        if conditions:
            assert(isinstance(conditions,list))
            self.condList = conditions
        else:
            self.condList = []            
        return

    def __iter__(self):
        for cond in self.condList:
            yield cond

    def __len__(self):
        return len(self.condList)

    def __getitem__(self, ii):
        return self.condList[ii]
    
    def __setitem__(self, ii, val):
        self.condList[ii] = val
        return self.condList[ii]

    def getZ3Operator(self):
        if self.isCNF:
            return "And"
        return "Or"

    def isCNF():
        return self.isCNF

    def isDNF():
        return not self.isCNF

    def append(self, cond):
        # Only allow insert string representation (condtion),
        # and or recursive (inner) representation using ConditionContainer.
        assert(isinstance(cond, str) or isinstance(cond, ConditionContainer))
        self.condList.append(cond)
        return

    def extend(self, condList):
        for cond in condList:
            self.append(cond)
        return

    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        if self.isCNF:
            op = " AND "
        else:
            op = " OR "
        return "(" + op.join([str(x) for x in self.condList]) + ")"
    
if __name__ == "__main__":
    cc = ConditionContainer(False)
    cc.append("xxx")
    cc.append("yyy")
    print type(cc)
    
    ccInner = ConditionContainer(True)
    ccInner.append("p")
    ccInner.append("q")
    cc.append(ccInner)
    print cc
