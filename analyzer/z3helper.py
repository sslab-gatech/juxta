#!/usr/bin/env python2
import os,sys
from condition_container import ConditionContainer

ALLOWED_BIN_OP = ["+", "-", "/", "*", # Numerical arithmetics.
                  "&", "|", "~" # Bit-wise operators.
                  ]

TMP_Z3_FILENAME = "_tmp_z3.py"

# Convert rangeStr into a list of tuples, where each tuple shows the inclusive
# range --- (min value, max value).
def parseRange(rangeStr):
    rangeStr = rangeStr.strip()

    # Remove { and }.
    assert(rangeStr[0] == '{' and rangeStr[-1] == '}')
    rangeStr = rangeStr[1:-1]

    # Embrace with list brackets to be generally evaluated as a list.
    ranges = eval("[" + rangeStr + "]")
    return ranges

def breakExprIntoTokens(exprStr):
    tokens = []
    nest = 0
    inExpr = ""
    for c in exprStr:
        inExpr += c
        if c == "(":
            nest += 1
        elif c == ")":
            nest -= 1
        if nest == 0 and len(inExpr.strip()) != 0:
            inExpr = inExpr.strip()
            if inExpr[0] == '(' and inExpr[-1] == ')':
                inExpr = inExpr[1:-1]
            tokens.append(inExpr.strip())
            inExpr = ""
    return tokens

def getZ3Symbol(expr):
    z3sym = expr
    z3sym = z3sym.replace("->", "__")
    return z3sym

class Z3Helper:
    def __init__(self, rcContainer = None):
        self.symTable = None
        self.z3constraints = None
        self.runModule = None
        self.rcContainer = rcContainer
        return

    '''
    Return True if given two conditions are proved to be equal.
    Return False otherwise.
    '''
    def isEqual(self, cc1, cc2):
        assert(isinstance(cc1, ConditionContainer))
        assert(isinstance(cc2, ConditionContainer))        
        # TODO : Reasonable matching methods for symbols. need test?
        symTable = {}
        z3const1, symTable = self.__genConstZ3(cc1, symTable)
        z3const2, symTable = self.__genConstZ3(cc2, symTable)

        z3fstr = self.__genEqualityZ3(symTable, z3const1, z3const2)
        z3filename = self.__saveToPyFile(z3fstr)
        return self.runPyFile(z3filename)

    # def simplify(self, condList):
    #     symTable, z3constraints = self.__parseCondList(condList)
    #     z3fstr = self.__genSimplifyZ3(symTable, z3constraints)
    #     self.__saveToPyFile(z3fstr)
    #     return z3fstr

    def runPyFile(self, z3filename):
        assert(z3filename.endswith(".py"))
        moduleName = z3filename[:-3]
        if not self.runModule:
            self.runModule = __import__(moduleName)
        else:
            # Reload the module.
            os.remove(moduleName + ".pyc") # delete .pyc
            reload(self.runModule)

        res = self.runModule.proof()
        return res

    def __saveToPyFile(self, z3fstr, z3filename = None) :
        if not z3filename:
            z3filename = TMP_Z3_FILENAME
        open(z3filename, "w").write(z3fstr)
        return z3filename

    '''
    Generate z3 formated constraints.
    '''
    def __genConstZ3(self, cc, symTable):
        z3strList = []
        assert(isinstance(cc, ConditionContainer))
        for cond in cc:
            if isinstance(cond, str):
                # condition
                _z, symTable = self.__parseCheckerCondition(cond, symTable)
                z3strList.append(_z)
            elif isinstance(cond, ConditionContainer):
                # recursive
                _z, symTable = self.__genConstZ3(cond, symTable)
                z3strList.append(_z)                
            else:
                # ERROR : Should not reach here
                raise Exception("This should not be reached")

        z3Operator = cc.getZ3Operator()
        z3str = "%s(%s)" % (z3Operator, ",".join(z3strList))
        return z3str, symTable
    

    def __genEqualityZ3(self, symTable, z3const1, z3const2):
        z3fstr = ""
        z3fstr += "from z3 import *\n"
        for sym in symTable:
            z3fstr += "%s = BitVec('%s', 64)\n" % (sym, sym)

        z3fstr += "\n"
        z3fstr += "__z3_x = %s\n\n" % z3const1
        z3fstr += "__z3_y = %s\n\n" % z3const2

        z3fstr += "__z3_eq = __z3_x == __z3_y\n\n"
        z3fstr += open("proof.z3.template").read()

        z3fstr += "\n"
        return z3fstr
    
    def __genSimplifyZ3(self, symTable, z3constraints, z3filename = None):
        z3fstr = ""
        z3fstr += "from z3 import *\n"
        for sym in symTable:
            z3fstr += "%s = BitVec('%s', 64)\n" % (sym, sym)
        z3fstr += "print simplify(And("
        z3fstr += ",".join(z3constraints)
        z3fstr += "))\n"

        if not z3filename:
            z3filename = TMP_Z3_FILENAME

        open(z3filename,"w").write(z3fstr)
        return z3fstr

    def __parseCheckerCondition(self, checkerCondition, symTable = {}):
        z3constraints = []
        # print cond
        assert(len(checkerCondition.split(":"))==2)
        exprStr, rangeStr = checkerCondition.split(":")
        z3range = parseRange(rangeStr)
        z3expr = self.__parseExpr(exprStr, symTable)

        if z3expr == "":
            return [], symTable

        z3constraints = []
        for minValue, maxValue in z3range:
            if minValue == maxValue:
                z3constraints.append("(%s) == %s" % (z3expr, minValue))
            else:
                z3constraints.append("(%s) >= %s" % (z3expr, minValue))
                z3constraints.append("(%s) <= %s" % (z3expr, maxValue))
        z3str = "Or(" + ",".join(z3constraints) + ")"
        return z3str, symTable

    def __parseCondList(self, condList, symTable = {}):
        z3StrList = []
        z3constraints = []
        for cond in condList:
            # print cond
            assert(len(cond.split(":"))==2)
            exprStr, rangeStr = cond.split(":")
            z3range = parseRange(rangeStr)
            z3expr = self.__parseExpr(exprStr, symTable)

            if z3expr == "":
                continue
            localConstraints = []
            for minValue, maxValue in z3range:
                if minValue == maxValue:
                    localConstraints.append("(%s) == %s" % (z3expr, minValue))
                else:
                    localConstraints.append("(%s) >= %s" % (z3expr, minValue))
                    localConstraints.append("(%s) <= %s" % (z3expr, maxValue))
            z3constraints.append("Or(" + ",".join(localConstraints) + ")")
        return symTable, z3constraints

    def __parseExpr(self, exprStr, unknownSymTable):
        z3expr = ""
        tokens = breakExprIntoTokens(exprStr)
        for token in tokens:
            if " # " in token:
                # (KIND # tokenExp)
                assert(len(token.split("#")) == 2)
                tokenKind, tokenExp = [x.strip() for x in token.split("#")]
                kind = tokenKind[0]            
                if kind == "I":
                    z3expr += tokenExp
                elif kind == "S":
                    unknownSym = getZ3Symbol(tokenExp)
                    assert(unknownSymTable.get(unknownSym, None) == None
                           or unknownSymTable[unknownSym] == tokenExp)
                    unknownSymTable[unknownSym] = tokenExp
                    z3expr += unknownSym
                    pass
                elif kind == "E":
                    print "ERROR : THERE SHOULD NOT BE ANY E KIND"
                    print "\t", token
                    sys.exit(-1)
            else:
                # BinaryOperator
                assert(token in ALLOWED_BIN_OP)
                z3expr += " %s " % token
        return z3expr

def test_breakExprIntoTokens():
    def eqTest(expr, tokens):
        assert(breakExprIntoTokens(expr) == tokens)
    eqTest("(S64 # attr->ia_valid) & (I # 1)",
           ['S64 # attr->ia_valid', '&', 'I # 1'])
    eqTest("(E # inode_change_ok(inode, attr))",
           ['E # inode_change_ok(inode, attr)'])
    return

def test_isEqual():
    cc1 = ConditionContainer(isCNF=True)
    cc1.append("(S64 # attr->ia_valid) & (I # 1) : { [0, 0] }")
    cc1.append("(S64 # attr->ia_valid) & (I # 8) : { [1, 4294967295] }")

    cc2 = ConditionContainer(isCNF=True)
    cc2.append("(S64 # attr->ia_valid) & (I # 1) : { [0, 0] }")
    cc2.append("(S64 # attr->ia_valid) & (I # 8) : { [1, 4294967295] }")
    cc2.append("(S64 # attr->ia_valid) & (I # 2) : { [0, 0] }")

    cc3 = ConditionContainer(isCNF=True)
    cc3.append("(S64 # attr->ia_valid) & (I # 8) : { [1, 4294967295] }")
    cc3.append("(S64 # attr->ia_valid) & (I # 1) : { [0, 0] }")

    cc4 = ConditionContainer(isCNF=True)
    cc4.append("(S64 # attr->ia_valid) & (I # 8) : { [1, 4294967295] }")

    cc5 = ConditionContainer(isCNF=True)
    cc5.append("(S64 # attr->ia_valid) & (I # 1) : { [0, 1] }")
    cc5.append("(S64 # attr->ia_valid) & (I # 8) : { [1, 4294967295] }")

    cc6 = ConditionContainer(isCNF=True)
    cc6.append("(S64 # x) : { [0,100]}")
    
    cc7 = ConditionContainer(isCNF=False)
    cc7.append(ConditionContainer(isCNF=True,
                                  conditions = ["(S64 # x) : { [0,100]}",
                                                "(S64 # y) : { [-9223372036854775808, -1], [1, 9223372036854775807]}",]))
    cc7.append(ConditionContainer(isCNF=True,
                                  conditions = ["(S64 # x) : { [0,100]}",
                                                "(S64 # y) : { [0,0]}"]))

    # We don't handle these cases.
    # cc8 = ConditionContainer(isCNF=True)
    # cc8.append("(S64 # (S64 # __fdget(fdout)) & (I # 3)) & (I # 1) : { [1, 4294967295] }")

    # cc9 = ConditionContainer(isCNF=True)
    # cc9.append("(S64 # (S64 # __fdget(fdout)) & (I # 3)) & (I # 1) : { [1, 4294967295] }")
        
    z3f = Z3Helper()
    assert(z3f.isEqual(cc1, cc1) == True)
    assert(z3f.isEqual(cc1, cc2) == False)
    assert(z3f.isEqual(cc1, cc2) == False)
    assert(z3f.isEqual(cc1, cc3) == True)
    assert(z3f.isEqual(cc1, cc4) == False)
    assert(z3f.isEqual(cc1, cc5) == False)
    assert(z3f.isEqual(cc6, cc7) == True)
    # assert(z3f.isEqual(cc8, cc9) == True)    
    return
    
if __name__ == "__main__":
    test_breakExprIntoTokens()
    test_isEqual()
    
