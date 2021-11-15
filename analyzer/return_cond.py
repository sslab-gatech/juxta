#!/usr/bin/env python2
# SPDX-License-Identifier: MIT

import dbg
import utils

MUST_KEYWORDS      = ["LOCATION", "FUNCTION", "RETURN"]
OPT_KEYWORDS       = ["CONDITION", "LOG_CALL", "LOG_STORE"]
LIST_TYPE_KEYWORDS = ["CONDITION", "LOG_CALL", "LOG_STORE"]

class ReturnCond(object):
    def __init__(self):
        return

    def getKey(self):
        # Get the unique (string) representation of the return condition.
        return "@".join([self["LOCATION"].split(":",1)[0], # Filename only
                         self["FUNCTION"],
                         self["RETURN"]])

    def getFunctionName(self):
        ftnSig = self["FUNCTION"]
        return ftnSig[:ftnSig.find("(")]

    def getFunctionArgs(self):
        ftnSig = self["FUNCTION"]
        assert("(" in ftnSig and ftnSig[-1] == ")")
        argStr = ftnSig[ftnSig.find("(")+1:-1]
        return [x.strip() for x in argStr.split(",")]

    def __getitem__(self, k):
        return self.__dict__.get(k,None)

    def __setitem__(self, k, v):
        if k in LIST_TYPE_KEYWORDS:
            assert(isinstance(v, str))
            if v != "nil":
                self.__dict__[k] = self.__dict__.get(k,[])
                self.__dict__[k].append(v)
        else:
            assert(self.__dict__.get(k,None)==None)
            self.__dict__[k] = v
        return

    def __repr__(self):
        s = ">>KEY : %s\n" % self.getKey()
        for k,v in self.__dict__.iteritems():
            if k in LIST_TYPE_KEYWORDS:
                s += "\t%s (%d)\n" % (k, len(v))
                for i, cond in enumerate(v):
                    s += "\t\t%s\n" % cond
            else:
                s +="\t%s %s\n" % (k,v)
        return s

    # def isComplete(self):
    #     for k in KEYWORDS:
    #         if k not in self.__dict__.keys():
    #             return False
    #     return True

if __name__ == '__main__':
    dbg.install_pdb()
