#!/usr/bin/env python2
from parse import Parse
from return_cond import ReturnCond
from return_cond_container import ReturnCondContainer
from z3helper import Z3Helper

z3f = Z3Helper()
def getMatchConditionsForTest(beforeList, afterList):
    keys = set(beforeList.getKeys())
    keys.intersection(afterList.getKeys())

    # Only care intersection for now.
    for k in keys:
        print "[*]", k

        # beforeConds = beforeList.getConditionsByKey(k)
        # afterConds = afterList.getConditionsByKey(k)
        
        beforeCc = beforeList.getUnrolledConditionsByKey(k)
        afterCc = afterList.getUnrolledConditionsByKey(k)

        # If one of conditions are empty, no point of doing analysis.
        if len(beforeCc) == 0 or len(afterCc) == 0:
            if len(beforeCc) != len(afterCc):
                # CHECKME : looks like there's a bug.
                pass
            continue

        proofResult = z3f.isEqual(beforeCc, afterCc)
        if proofResult:
            print "\t Equal"
        else:
            print "\t Not equal"
            # print "\t before"
            # for conds in beforeConds:
            #     print "\t\t", conds
            # print "\t after"
            # for conds in afterConds:
            #     print "\t\t", conds
    return


def test_analyzer():
    for i in range(1,4):
        print "TEST %d" % i
        beforeList = Parse("../unittest-bugs/output/before_%d"%i).parse()
        afterList = Parse("../unittest-bugs/output/after_%d"%i).parse()
        getMatchConditionsForTest(beforeList, afterList)

    # beforeList = Parse("../unittest-bugs/output/before_ipa").parse()
    # afterList = Parse("../unittest-bugs/output/after_ipa").parse()
    # getMatchConditionsForTest(beforeList, afterList)
    return

def analyze_kernel(fssOutputDir):
    import ops
    # rcContainer = Parse(fssOutputDir).parse()
    matchGen = ops.matchFunctionGenerator()

    for i, (opsName, setting, ftnName, matchList) in enumerate(matchGen):
        if i < 5: break
        print opsName
        print setting
        print ftnName
        print matchList
    return

if __name__ == "__main__":
    # test_analyzer()
    analyze_kernel("asdf")

    

