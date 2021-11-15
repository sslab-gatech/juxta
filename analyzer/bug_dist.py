#!/usr/bin/env python2
# SPDX-License-Identifier: MIT
from __future__ import print_function

import os
import sys
import dbg
import optparse
import subprocess

# graph size in inch
GP_WIDTH=3
GP_HEIGHT=2.5

def _tokenize(string, sep):
    start = 0
    opening_brace = 0
    for (i, c) in enumerate(string):
        if c == '(' or c == '[':
            opening_brace += 1
            continue
        elif c == ')' or c == ']':
            opening_brace -= 1
            continue
        elif opening_brace > 0:
            continue
        elif sep.find(c) is not -1:
            if sep.find(string[start]) is -1:
                yield(string[start:i].strip())
            start = i + 1
    yield(string[start:].strip())

def _tokenize2(string, sep):
    for (i, token) in enumerate(_tokenize(string, sep)):
        if i % 2 == 0:
            first = token
        else:
            yield(first, token)
    
def parse_bugginess(log_file):
    bugginess_found_list = []
    with open(log_file) as fd:
        for l in fd:
            if l.find("bugginess") is -1:
                continue
            cond_bugginess_str = l[l.find(":")+1:].strip().lstrip("{").rstrip("}")
            for (cond, bugginess) in _tokenize2(cond_bugginess_str, ":,"):
                bugginess = float(bugginess)
                found = cond.startswith("$")
                bugginess_found_list.append((bugginess, found))
    return sorted(bugginess_found_list, reverse=True)

def parse_distance(log_file):
    dist_found_list = []
    with open(log_file) as fd:
        for l in fd:
            l = l.strip()
            if l.startswith(">") or l == "":
                continue
            elif l.startswith("\033"):
                l = l[l.find("m")+1:]

            for (i, token) in enumerate(_tokenize(l, "\t ")):
                if i == 2:
                    found = token.startswith("$")
                    try:
                        dist = float(token[found:])
                        dist_found_list.append((dist, found))
                    except ValueError:
                        continue
    return sorted(dist_found_list, reverse=True)

def _gen_gp_header(fd, pdf_file, title, xlabel, ylabel):
    print("set term pdfcairo size %sin,%sin font \',10\'" %
          (GP_WIDTH, GP_HEIGHT), file=fd)
    print("set_out=\'set output \"`if test -z $OUT; then echo %s; else echo $OUT; fi`\"\'"
          % pdf_file, file=fd)
    print("eval set_out", file=fd)
    if title is not None:
        print("set title \'%s\'" % title, file=fd)
    print("set xlabel \'%s\'" % xlabel, file=fd)
    print("set ylabel \'%s\'" % ylabel, file=fd)
                        

def _gen_gp_data(fd, score_found_list):
    print("  # score distribution", file=fd)
    for (i, score_found) in enumerate(score_found_list):
        if (score_found[0] >= 0):
            print("  %d %f" % (i, score_found[0]), file=fd)
    print("e", file=fd)
        
    print("  # found or not", file=fd)
    for (i, score_found) in enumerate(score_found_list):
        if (score_found[0] >= 0):
            found = score_found[0] if score_found[1] else -1.0
            print("  %d %f" % (i, found), file=fd)
    print("e", file=fd)

def _gen_gp_plot_cmd(fd):
    print("plot [0:][0:] "
          "\'-\' using 1:2 title \'\' with lines,"
          " \'\' using 1:2 title \'\' with points", file=fd)

def gen_gnuplot(score_found_list, gp_file=None, pdf_file="gp.pdf",
                title=None, xlabel="Ranking", ylabel="Score"):
    fd = sys.stdout if gp_file is None else open(gp_file, "w")
    try:
        _gen_gp_header(fd, pdf_file, title, xlabel, ylabel)
        _gen_gp_plot_cmd(fd)
        _gen_gp_data(fd, score_found_list)
    finally:
        if fd is not sys.stdout:
            fd.close()
        
if __name__ == "__main__":
    parser = optparse.OptionParser()
    parser.add_option("--type", help="score type: distance or bugginess",
                      choices=["distance", "bugginess"])
    parser.add_option("--report_file", help="bug report file")
    parser.add_option("--gp_file",  help="gnuplot script file")
    parser.add_option("--pdf_file",  help="output pdf file")
    (opts, args) = parser.parse_args()

    # check options
    for opt in vars(opts):
        val = getattr(opts, opt)
        if val == None:
            print("Missing options: %s" % opt)
            parser.print_help()
            exit(1)

    # generate gnuplot script
    if opts.type == "distance":
        df_list = parse_distance(opts.report_file)
        gen_gnuplot(df_list, gp_file=opts.gp_file, pdf_file=opts.pdf_file,
                    xlabel="distance ranking", ylabel="distance")
    elif opts.type == "bugginess":
        bf_list = parse_bugginess(opts.report_file)
        gen_gnuplot(bf_list, gp_file=opts.gp_file, pdf_file=opts.pdf_file,
                    xlabel="bugginess ranking", ylabel="bugginess")
    else:
        print("Unknow type: %s" % opts.type)
        parser.print_help()
        exit(1)
    
    # run gnuplot
    subprocess.call("gnuplot %s" % opts.gp_file, shell=True)

