#!/usr/bin/env python2
# SPDX-License-Identifier: MIT
import math
import dbg
import utils

# bugginess
# - how a class of event is unlike
#   - find the most deviant evnet in a most predictable set of events
# 
# - B(i, X) = 1 / ((P_i  * H(X)) + 1)
#   - P_i:  probability of event i
#   - H(X): standard Shannon entropy for a set of event X
# - greater or equal to 1
# - the larger, the more buggy

def _calc_entropy(ev_occ, total_occ):
    entropy_val = 0.0
    for x in ev_occ:
        p_x = float(ev_occ[x]) / total_occ
        if p_x > 0:
            entropy_val += - p_x * math.log(p_x, 2)
    return entropy_val

def calc_entropy(ev_occ):
    total_occ = float( sum(ev_occ.values()) )
    return _calc_entropy(ev_occ, total_occ)

def calc_bugginess(ev_occ):
    total_occ = float( sum(ev_occ.values()) )
    entropy_val = _calc_entropy(ev_occ, total_occ)

    ev_bugginess = {}
    for x in ev_occ:
        p_x = float(ev_occ[x]) / total_occ
        ev_bugginess[x] = 1.0 / (p_x * entropy_val + 1)
    return ev_bugginess
        

def _test_bugginess(ev_occ):
    total_occ = float( sum(ev_occ.values()) )
    entropy_val = calc_entropy(ev_occ, total_occ)
    bugginess_val = calc_bugginess(ev_occ)
    print("\nev_occ: %s" % ev_occ)
    print("total_occ: %s  entropy_val: %s" % (total_occ, entropy_val))
    print("bugginess: %s" % bugginess_val)
    return bugginess_val
        
def test_bugginess():
    bugs1 = _test_bugginess({"a":10, "b":1, "c":4})
    bugs2 = _test_bugginess({"x":6,  "y":5, "z":4})
    bugs = dict(bugs1.items() + bugs2.items())

    assert(bugs["b"] == max(bugs.values()))
    assert(bugs["c"] >  bugs["z"])
    
    print("\nbugs: %s" % bugs)
    
if __name__ == '__main__':
    utils.install_pdb()
    test_bugginess()
