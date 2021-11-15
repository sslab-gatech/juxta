#!/usr/bin/env python2
# SPDX-License-Identifier: MIT

import os
import sys
import dbg
import utils
import pdb
from rsv import Range, RangeSet

S64_MIN = -2**63
S64_MAX = 2**63 - 1
RANGE_AREA = 100.0

def build(rs_strs, range_area = RANGE_AREA, comments = []):
    range_set = RangeSet()
    for rs_str in rs_strs:
        __build(range_set, rs_str, comments)
    range_set.resize_area(range_area)
    return range_set

def __build(range_set, rs_str, comments = {}):
    rs_str = rs_str.strip()    
    if __is_number(rs_str):
        # 1, +1, -1, 0.5, .5
        start = end = float(rs_str)
        range_set.add( __new(start, end, {rs_str}) )
    elif __is_range(rs_str):
        # "[-2147483648, -1], [1, 2147483647]"
        rs = rs_str.split("],")
        for r in rs:
            se = r.strip().lstrip("[").rstrip("]").split(",")
            start = float(se[0].strip())
            end = float(se[1].strip())
            range_set.add( __new(start, end, {r}) )
    else:
        # retval, foo($A1...)
        range_set.add( __new(S64_MIN, S64_MAX, {rs_str}) )
            
def __new(start, end, comments):
    weight = RANGE_AREA / (end - start + 1)
    r = Range(start, end, weight, comments)
    return r

def __is_number(s):
    try:
        float(s)
        return True
    except ValueError:
        return False
        
def __is_range(s):
    return s[0] == '['
        
def __test_range_set_factory():
    rs_strs = ["1",
               "-1", 
               "[1, 4294967295]",
               "[-2147483648, -1], [1, 2147483647]",
               "retval", 
               "foo($A1__xxx)"]
    rs = build(rs_strs)
    print rs
    
if __name__ == '__main__':
    utils.install_pdb()
    __test_range_set_factory()
