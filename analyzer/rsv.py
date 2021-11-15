#!/usr/bin/env python2
# SPDX-License-Identifier: MIT

import os
import sys
import dbg
import pdb
import utils
import copy

class Range(object):
    def __init__(self, start, end, weight, comments = []):
        self.start    = start # inclusive
        self.end      = end   # inclusive
        self.weight   = float(weight)
        self.comments = comments
        assert(self.start <= self.end)
        assert(self.weight >= 0)

    def div_assign(self, n):
        self.weight /= n

    def union_assign(self, rhs):
        return self.__op(rhs, max)

    def intersection_assign(self, rhs):
        return self.__op(rhs, add_two)

    def distance(self, rhs):
        # for now, use histogram intersection as a distance measure
        return self.__histogram_intersection(rhs)

    def __op(self, rhs, op):
        # lhs <= rhs
        lhs = self
        if lhs.start > rhs.start:
            (lhs, rhs) = (rhs, lhs)

        # CASE 1: single region
        # Two are completely overlapped.
        if lhs.start == rhs.start and lhs.end == rhs.end:
            lhs.weight = op(lhs.weight, rhs.weight)
            lhs.comments = lhs.comments | rhs.comments
            return [lhs]

        # CASE 2: two regions
        # no overlap, do nothing
        if lhs.end < rhs.start:
            return [lhs, rhs]

        # partianlly overlapped
        if lhs.start == rhs.start:
            if lhs.end > rhs.end:
                (lhs, rhs) = (rhs, lhs)
            lhs.weight = op(lhs.weight, rhs.weight)
            lhs.comments = lhs.comments | rhs.comments
            rhs.start = lhs.end + 1
            assert(rhs.check_sanity())
            return [lhs, rhs]
        elif lhs.end == rhs.end:
            rhs.weight = op(lhs.weight, rhs.weight)
            rhs.comments = lhs.comments | rhs.comments
            lhs.end = rhs.start - 1
            assert(lhs.check_sanity())
            return [lhs, rhs]

        # CASE 3: three regions
        mhs = Range(rhs.start, min(lhs.end, rhs.end), \
                    op(lhs.weight, rhs.weight), \
                    lhs.comments | rhs.comments)
        if lhs.end > rhs.end:
            rhs.end = lhs.end 
            rhs.weight = lhs.weight
            rhs.comments = lhs.comments
        (lhs.end, rhs.start) = (mhs.start - 1, mhs.end + 1)
        assert(lhs.check_sanity())
        assert(mhs.check_sanity())
        assert(rhs.check_sanity())
        return [lhs, mhs, rhs]

    def check_sanity(self):
        return self.start <= self.end

    @staticmethod
    def __calc_area(s, e, w):
        return (e - s + 1) * w

    def _calc_area(self):
        return Range.__calc_area(self.start, self.end, self.weight)

    def _overlapped_area(self, rhs):
        s = max(self.start, rhs.start)
        e = min(self.end, rhs.end)
        if s > e:
            return (0, 0, 0, 0)
        w = min(self.weight, rhs.weight)
        area = Range.__calc_area(s, e, w)
        return (area, s, e, w)

    def __histogram_intersection(self, rhs):
        total  = self._calc_area() + rhs._calc_area()
        (overlap, s, e, w) = self._overlapped_area(rhs)
        dist = total - overlap
        assert(dist >= 0)
        return dist
        
    def __repr__(self):
        return "'%s'" % self

    def __str__(self):
        return "[%s, %s, %s, @%s]" \
            % (self.start, self.end, self.weight, self.comments)

def add_two(lhs, rhs):
    return lhs + rhs

def union_assign(lhs, rhs):
    return lhs.union_assign(rhs)

def intersection_assign(lhs, rhs):
    return lhs.intersection_assign(rhs)

class RangeSet(object):
    def __init__(self, r = None):
        # my range set
        self.rs = []
        if r :
            self.rs.append(r)

        # difference to rhs
        self.ldiff = []

        # rhs's difference to myself
        self.rdiff = []

    def add(self, new):
        assert(type(new) is Range)
        self.__add_with(new, intersection_assign)
        return self

    def div_assign(self, n):
        map(lambda x: x.div_assign(n), self.rs)
        return self

    def union_assign(self, rhs):
        map(lambda x: self.__add_with(x, union_assign), rhs.rs)
        return self

    def intersection_assign(self, rhs):
        map(lambda x: self.__add_with(x, intersection_assign), rhs.rs)
        return self

    def distance(self, rhs):
        # for now, use histogram intersection as a distance measure
        return self.__histogram_intersection(rhs)

    def resize_area(self, area):
        total = 0
        for s in self.rs:
            total += s._calc_area()
        norm_factor = float(total)/float(area)
        map(lambda r: r.div_assign(norm_factor), self.rs)

    def get_diffs(self):
        return (self.ldiff, self.rdiff)

    def __add_with(self, new, op):
        for n in self.__decompose_range(new):
            self.__add_with2(n, op)

    def __add_with2(self, new, op):
        new_rs = []
        for r in self.rs:
            for x in op(new, r):
                if x != new:
                    new_rs.append(x)
        new_rs.append(new)
        self.rs = new_rs

    def __decompose_range(self, new):
        (decomposed_news, will_be_decomposed_news) = ([], [new])
        # If it cannot be converged in three iteratios, give up.
        for i in xrange(0, 30):
            will_be_decomposed_news2 = []
            for tobe_new in will_be_decomposed_news:
                (d_news, w_news) = self.__decompose_range2(tobe_new)
                decomposed_news += d_news
                will_be_decomposed_news2 += w_news
            if will_be_decomposed_news2 == []:
                break
            will_be_decomposed_news = will_be_decomposed_news2
        return decomposed_news + will_be_decomposed_news

    def __decompose_range2(self, new):
        for r in self.rs:
            start = max(r.start, new.start)
            end   = min(r.end,   new.end)
            
            # no overlap
            if start > end:
                continue

            # completely overlap
            if start == new.start and end == new.end:
                break

            # partially overlapped
            #   [new*, new1, new2*]
            #   new1: completely overlapped region
            #   new, new2: unknown whether they are overlapped with others
            new1 = copy.deepcopy(new)
            (new1.start, new1.end) = (start, end)
            # recursively decompose non-overlapping 'new'
            recursive_new = [new]
            assert(new1.check_sanity())
            if new1.start == new.start:
                new.start = new1.end + 1
            elif new1.end == new.end:
                new.end = new1.start - 1
            else:
                new2 = copy.deepcopy(new)
                (new.end, new2.start) = (new1.start - 1, new1.end + 1)
                # recursively decompose non-overlapping 'new2'
                recursive_new.append(new2)
            return ([new1], recursive_new)
        return ([new], [])

    def __histogram_intersection(self, rhs):
        self.ldiff = RangeSet.__create_diff(self)
        self.rdiff = RangeSet.__create_diff(rhs)

        total = 0
        for s in self.rs:
            total += s._calc_area()
        for r in rhs.rs:
            total += r._calc_area()
        overlap = 0
        for s in self.rs:
            for r in rhs.rs:
                (area, start, end, weight) = s._overlapped_area(r)
                overlap += area

                if weight <= 0:
                    continue

                self.ldiff = RangeSet.__diff_out(self.ldiff, start, end, weight)
                self.rdiff = RangeSet.__diff_out(self.rdiff, start, end, weight)

        dist = total - overlap
        assert(dist >= 0)

        self.ldiff.sort(reverse=True)
        self.rdiff.sort(reverse=True)
        return dist

    @staticmethod
    def __create_diff(inst):
        diff = [] 
        for r in inst.rs:
            cr = copy.deepcopy(r)
            area = cr._calc_area()
            diff.append([area, cr])
        return diff

    @staticmethod
    def __diff_out(diff, s, e, w):
        new_diff = []
        for d in diff:
            # test whether two are overlapped
            rs1 = d[1]
            ms = max(rs1.start, s)
            me = min(rs1.end, e)

            # case 0. non-overlapped
            if ms > me or rs1.weight <= 0:
                new_diff.append([rs1._calc_area(), rs1])
                continue
            mw = min(rs1.weight, w)

            # case 1. completely overlapped
            if rs1.start == ms and rs1.end == me:
                rs1.weight -= mw
                if rs1.weight > 0:
                    new_diff.append([rs1._calc_area(), rs1])
                continue
                
            # case 2. partially overlapped, generating two new regions
            if rs1.start < ms and me < rs1.end:
                rs0 = copy.deepcopy(rs1)
                rs2 = copy.deepcopy(rs1)
                rs0.end = ms - 1
                rs2.start = me + 1
                new_diff.append([rs0._calc_area(), rs0])
                new_diff.append([rs2._calc_area(), rs2])

                rs1.weight -= mw
                if rs1.weight > 0:
                    new_diff.append([rs1._calc_area(), rs1])
                continue

            # case 3. partially overlapped, generating one new region
            rs0 = copy.deepcopy(rs1)
            if rs1.start == ms:
                rs0.start = me + 1
                new_diff.append([rs0._calc_area(), rs0])

                rs1.end = me
                rs1.weight -= mw
                if rs1.weight > 0:
                    new_diff.append([rs1._calc_area(), rs1])
                continue
            elif rs1.end == me:
                rs0.end = ms - 1
                new_diff.append([rs0._calc_area(), rs0])
                
                rs1.start = ms
                rs1.weight -= mw
                if rs1.weight > 0:
                    new_diff.append([rs1._calc_area(), rs1])
                continue
        return new_diff

    def __repr__(self):
        return "'%s'" % self

    def __str__(self):
        return "{ %s }" % self.rs

# sparse vector using dictionary
class RangeSetVector(object):
    def __init__(self, dim = None, rs = None):
        self.rsv = {}
        if dim != None and rs != None:
            self.add(dim, rs)

    def add(self, dim, rs):
        assert(type(rs) is RangeSet)
        self.rsv[dim] = rs
        return self

    def div_assign(self, n):
        map(lambda x: self.rsv[x].div_assign(n), self.rsv)
        return self

    def union(self, rhs):
        return self.__op(rhs, union_assign)

    def intersection(self, rhs):
        return self.__op(rhs, intersection_assign)

    def distance(self, rhs):
        # for now, use Euclidean distance
        return self.__euclidean_distance(rhs)

    def resize_area(self, area):
        map(lambda rsv: rsv.resize_area(area), self.rsv.itervalues())

    def get_diffs(self, dim):
        rs = self.rsv[dim]
        return rs.get_diffs()

    def __op(self, rhs, op_assign):
        new_rsv = RangeSetVector()
        dims = self.__get_dimensions(rhs)
        for dim in dims:
            new_lrs = copy.deepcopy( self.rsv.get(dim, RangeSet()) )
            new_rrs = copy.deepcopy( rhs.rsv.get(dim, RangeSet()) )
            op_assign(new_lrs, new_rrs)
            new_rsv.add(dim, new_lrs)
        return new_rsv

    def __get_dimensions(self, rhs):
        return set(self.rsv.keys() + rhs.rsv.keys())

    def __euclidean_distance(self, rhs):
        new_rsv = RangeSetVector()
        dims = self.__get_dimensions(rhs)
        dsum = 0.0
        for dim in dims:
            lrs = self.rsv.get(dim, None)
            if not lrs:
                # add dim to keep track ldiff
                self.add(dim, RangeSet())
                lrs = self.rsv[dim]
            rrs = rhs.rsv.get(dim, RangeSet())
            dsum = lrs.distance(rrs) ** 2
        return dsum ** 0.5

    def __repr__(self):
        return "'%s'" % self

    def __str__(self):
        return "< %s >" % self.rsv

# calculate average of rsv
def calc_average_rsv(rsvs):
    (n, avg) = (-1, rsvs[0])
    for (n, rsv) in enumerate(rsvs[1:]):
        # Do not change the order of rsv and avg
        # Some state updates are done in lvalue, i.e., rsv.
        avg = rsv.intersection(avg)
    avg.div_assign(n + 2)
    return avg

# unit testcases
def _test_range():
    lhs = Range(1, 100, 2, {"a"})
    rhs = Range(51, 200, 1, {"b"})
    print( lhs.distance(rhs) )
    for x in lhs.union_assign(rhs):
        print x
    lhs.div_assign(0.3)
    print(lhs)
    
def _test_range_set():
    rs = RangeSet()
    rs.add( Range(1, 100, 2, {"l"}) )
    print(rs)
    rs.add( Range(51, 200, 1, {"r"}) )
    print(rs)
    rs.add( Range(151, 300, 3, {"s"}) )
    print(rs)
    rs.add( Range(500, 600, 5, {"t"}) )
    print(rs)
    rs.add( Range(-100, 0, 100, {"u"}) )
    print(rs)
    rs.div_assign(2)
    print(rs)
    rs.resize_area(100)
    print(rs)

def _test_range_set2():
    rs = RangeSet()
    rs.add( Range(0, 0, 100, {"a"}) )
    print(rs)
    rs.add( Range(-100, 100, 1, {"b"}) )
    print(rs)

def _test_range_set3():
    rs = RangeSet()
    rs.add( Range(-2, -2, 100, {"a"}) )
    print(rs)
    rs.add( Range(-1, -1, 100, {"b"}) )
    print(rs)
    rs.add( Range(0, 0, 100, {"c"}) )
    print(rs)
    print("=========================================")
    rs.add( Range(-9, -1, 1, {"X"}) )
    print(rs)

def _test_range_set_op():
    x_rs = RangeSet(); 
    x_rs.add( Range(1, 100, 2, {"a"}) )
    x_rs.add( Range(51, 200, 1, {"b"}) )
    print(x_rs)
    y_rs = RangeSet(); 
    y_rs.add( Range(25, 75, 10, {"c"}) )
    y_rs.add( Range(150, 210, 1, {"d"}) )
    print(y_rs)
    dist  = x_rs.distance(y_rs)
    print("dist = %s" % dist)
    print(x_rs.ldiff)
    print(x_rs.rdiff)
    x_rs.union_assign(y_rs)
    print(x_rs) 

def _test_range_set_vector():
    x_rsv = RangeSetVector( \
                            "A", \
                            RangeSet(Range(1, 100, 2, {"a1"})).\
                            add(Range(25, 75, 10, {"a2"})) )
    x_rsv.add("B", RangeSet( Range(51, 200, 1, {"b"})) )
    print(x_rsv)

    y_rsv = RangeSetVector( \
                            "A", \
                            RangeSet(Range(25, 75, 10, {"a3"})) )
    y_rsv.add("C", RangeSet(Range(150, 210, 1, {"d"})) )
    print(y_rsv)

    print( x_rsv.union(y_rsv) )
    print( x_rsv.intersection(y_rsv) )
    print( x_rsv.distance(y_rsv) )
    print( x_rsv.div_assign(2) )

def _test_rsv_average():
    x_rsv = RangeSetVector( \
                            "A", \
                            RangeSet(Range(1, 100, 2, {"a1"})).\
                            add(Range(25, 75, 10, {"a2"})) )
    x_rsv.add("B", RangeSet( Range(51, 200, 1, {"b"})) )
    print(x_rsv)

    y_rsv = RangeSetVector( \
                            "A", \
                            RangeSet(Range(25, 75, 10, {"a3"})) )
    y_rsv.add("C", RangeSet(Range(150, 210, 1, {"d"})) )
    print(y_rsv)

    avg_rsv = calc_average_rsv([x_rsv, y_rsv])
    print(avg_rsv)


def _test_rsv_average2():
    x_rsv = RangeSetVector( \
                            "@RETURN", \
                            RangeSet(Range(0, 0, 10, {"x1"})).\
                            add(Range(-2, -2, 10, {"x2"})) )
    print("@X:\n%s" % x_rsv)

    y_rsv = RangeSetVector( \
                            "@RETURN", \
                            RangeSet(Range(0, 0, 10, {"y1"})).\
                            add(Range(1, 1000, 1, {"y2"})).\
                            add(Range(-1000, -1, 1, {"y3"})))
    print("@Y:\n%s" % y_rsv)

    z_rsv = RangeSetVector( \
                            "@RETURN", \
                            RangeSet(Range(-10, -10, 10, {"z1"})).\
                            add(Range(0, 0, 10, {"z2"})).\
                            add(Range(10, 10, 10, {"z3"})).\
                            add(Range(-1000, -11, 1, {"z4"})).\
                            add(Range(-9, -1, 1, {"z5"})).\
                            add(Range(1, 9, 1, {"z6"})).\
                            add(Range(11, 1000, 1, {"z7"})))
    print("@Z:\n%s" % z_rsv)

    print("@@================================")
    avg_rsv = calc_average_rsv([x_rsv, y_rsv, z_rsv])
    print("@@AVG:\n%s" % avg_rsv)

if __name__ == "__main__":
    utils.install_pdb()

    print("@R1==============")
    _test_range()
    print("@RS1=============")
    _test_range_set()
    print("@RS2=============")
    _test_range_set2()
    print("@RS3=============")
    _test_range_set3()
    print("@R===============")
    _test_range()
    print("@RS==============")
    _test_range_set()
    print("@RSop============")
    _test_range_set_op()
    print("@RSV=============")
    _test_range_set_vector()
    print("@RSV-AVERAGE======")
    _test_rsv_average()
    print("@RSV-AVERAGE2=====")
    _test_rsv_average2()
