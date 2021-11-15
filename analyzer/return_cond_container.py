#!/usr/bin/env python2
# SPDX-License-Identifier: MIT

import z3helper
from return_cond  import ReturnCond
from condition_container import ConditionContainer

ROOT = os.path.dirname(__file__)

def parseCondition(cond):
    assert(len(cond.split(":"))==2)
    exprStr, rangeStr = cond.split(":")
    z3range = z3helper.parseRange(rangeStr)
    tokens = z3helper.breakExprIntoTokens(exprStr)
    return tokens, z3range

def parseConjExpr(expr):
    # conj expr must have the function calling form.
    assert(expr.find("(") != 0 and expr.endswith(")"))
    ftnName = expr[:expr.find("(")]
    if ">" in ftnName:
        ftnName = ftnName[ftnName.rfind(">")+1:]
    if "." in ftnName:
        ftnName = ftnName[ftnName.rfind(".")+1:]
    args = [x.strip() for x in expr[expr.find("(")+1:-1].split(",")]
    return ftnName, args

def replaceConditionArgs(cond, oldArgs, newArgs):
    if isinstance(cond, ConditionContainer):
        for i, c in enumerate(cond):
            cond[i] = replaceConditionArgs(c, oldArgs, newArgs)
        return cond
    
    assert(isinstance(cond, str))
    tokens, z3range = parseCondition(cond)
    newTokens = []
    for token in tokens:
        if token.startswith("S"):
            # Need to replace symbol name here.
            for i in range(len(oldArgs)):
                cond = cond.replace("# " + oldArgs[i], "# " + newArgs[i])
        elif token.startswith("E"):
            # TODO: we don't handle this recursive case for now.            
            # TODO: raise exception here.
            continue

    return cond

class ReturnCondContainer:
    '''
    key : LOCATION@FUNCTION@RETURN_VALUE
    
    We maintain two internal data structures, rcDict and rcDictByFunction.
    rcDict : key ==> list of ReturnCond
    rcDictFunction : FunctionName ==> list of ReturnCond
    '''
    def __init__(self):
        self.rcDict = {}
        self.rcDictFtn = {} # TODO
        return

    '''
    rc : ReturnCond
    '''
    def append(self, rc):
        assert(isinstance(rc, ReturnCond))
        key = rc.getKey()
        self.rcDict[key] = self.rcDict.get(key, [])
        self.rcDict[key].append(rc)
        
        ftnName = rc.getFunctionName()
        self.rcDictFtn[ftnName] = self.rcDictFtn.get(ftnName, [])
        self.rcDictFtn[ftnName].append(rc)
        return
    
    def extend(self, rcList):
        for rc in rcList:
            self.append(rc)
        return

    '''
    Returns unrolled conditions for the given key, which basically performs an
    interprocedural analysis. If there's any condition with E kind (conjecture
    symbols from the checker), we first locate those conjecture symbols from the
    container and then properly replace them with other non-E kind conditions.
    '''
    def __doReplaceCond(self, cond):
        assert(isinstance(cond, str))
        tokens, z3range = parseCondition(cond)
        cc = ConditionContainer(isCNF=True)
        for token in tokens:
            if len(token.split("#")) != 2:
                # FIXME : ignore complicated conjured cases for now.
                return cc
            tokenKind, tokenExp = [x.strip() for x in token.split("#")]

            if tokenKind[0] != "E":
                cc.append(cond)
                continue

            # Now we have E kind, so let's unroll it.

            # Locate rc of the target function, which also has the
            # return value in the proper range.
            ftnName, args = parseConjExpr(tokenExp)
            conjuredCc = self.__getConditionByFunction(ftnName, args, z3range)
            if len(conjuredCc) == 0:
                # FIXME: Failed to locate the target function condition.
                return cc


            # TODO: Reppresent into DNF if there's multiple conditions.
            assert(len(conjuredCc) == 1)
            print "conjuredCc:", conjuredCc, type(conjuredCc)
        return cc

    def __doUnrollByKey(self, key, cc):
        assert(isinstance(cc, ConditionContainer))
        
        for i, cond in enumerate(cc):
            if isinstance(cond, str):
                cc[i] = self.__doReplaceCond(cond)
            elif isinstance(cond, ConditionContainer):
                cc[i] = self.__doUnrollByKey(key, cond)
            else:
                raise("Not supporting type")
        return cc
        
    def getUnrolledConditionsByKey(self, key):
        topCc = self.getConditionsByKey(key)
        self.__doUnrollByKey(key, topCc)
        return topCc

    '''
    Return the condition with the given function name (ftnName). Also check the
    return value of the condition.
    '''
    def __getConditionByFunction(self, ftnName, args, z3range=None):
        rcList = self.rcDictFtn.get(ftnName, [])
        if z3range == None:
            cc = ConditionContainer(isCNF=False)
            for x in rcList:
                if x["CONDITION"] != None:
                    cc.append(ConditionContainer(isCNF=True,
                                                 conditions = x["CONDITION"]))
            return cc

        # If z3range is given, check if the return value of condition is in
        # z3range.
        filteredRcs = []
        for rc in rcList:
            # TODO: what if the return value is not integer type?
            retValue = int(rc["RETURN"])
            for minValue, maxValue in z3range:
                if retValue >= minValue and retValue <= maxValue:
                    filteredRcs.append(rc)
                    break

        # For each condition, we should replace all arguments into
        # as presented in a conjured form.
        # That is, rcArgs are replaced with args
        newCc = ConditionContainer(isCNF=False)
        for rc in filteredRcs:
            newSubCc = ConditionContainer(isCNF=True)
            rcArgs = rc.getFunctionArgs()
            rcConds = rc["CONDITION"]
            for rcCond in rcConds:
                newSubCc.append(replaceConditionArgs(rcCond, rcArgs, args))
        return newCc

    '''
    get ConditionContainer using the key.  Because there are multiple ReturnCond
    instances for each key (i.e., there are possibly multiple return statements
    for the given pair (function name, return value), the top level is
    represented as DNF.
    '''
    def getConditionsByKey(self, key):
        l = self.rcDict.get(key,None)

        cc = ConditionContainer(isCNF=False)
        for x in l:
            if x["CONDITION"] != None:
                cc.append(ConditionContainer(isCNF=True,
                                             conditions = x["CONDITION"]))
        return cc

    def getKeys(self):
        return self.rcDict.keys()

    def __getitem__(self, key):
        return self.rcDict.get(key,None)

def test_parseConjExpr():
    assert(("foo", ["argc"]) == parseConjExpr("foo(argc)"))
    assert(("foo", ["argc"]) == parseConjExpr("x->y->foo(argc)"))
    assert(("foo", ["argc"]) == parseConjExpr("x->y.z->foo(argc)"))
    assert(("foo", ["argc"]) == parseConjExpr("x->y.z.foo(argc)"))
    assert(("foo", ["argc"]) == parseConjExpr("foo(argc)"))
    assert(("foo", ["arg1", "arg2"])) == parseConjExpr("foo(  arg1 , arg2 )")
    return

def test_replaceConditionArgs():
    expr = "(S64 # x) : { [1, 2147483647] }"
    oldArgs = ["x"]
    newArgs = ["argc"]
    assert(replaceConditionArgs(expr, oldArgs, newArgs)
           == "(S64 # argc) : { [1, 2147483647] }")

    expr = "(S64 # attr->ia_valid) & (I # 1) : { [0, 0] }"
    oldArgs = ["x", "y", "attr->ia_valid"]
    newArgs = ["p", "q", "new"]
    assert(replaceConditionArgs(expr, oldArgs, newArgs)
           == "(S64 # new) & (I # 1) : { [0, 0] }")
    return

def test_unrollCondition():
    from parse import Parse
    rcContainer = Parse(os.path.join(ROOT, "data", "sample-fss-output-ipa")).parse()
    for k in rcContainer.getKeys():
        print "=" * 30
        print "k:", k
        unrolled = rcContainer.getUnrolledConditionsByKey(k)
        print "unrolled:", unrolled
    return

if __name__ == "__main__":
    test_parseConjExpr()
    test_replaceConditionArgs()
    test_unrollCondition()

    
