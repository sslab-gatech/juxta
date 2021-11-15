#!/usr/bin/env python2
# SPDX-License-Identifier: MIT
import os
import sys
import dbg
import optparse
import subprocess

chekers = [("call-flags", "bugginess"),
	   ("ckapi", "bugginess"),
	   ("ckcall", "distance"),
	   ("ckcond", "distance"),
	   ("ckrtn", "distance"),
	   ("ckstore", "distance")]

if __name__ == "__main__":
   for c in chekers:
      cmd = "./bug_dist.py --type=%s --report_file=results-%s/bug-report.log --gp_file=results-%s/dist-%s.gp --pdf_file=results-%s/dist-%s.pdf" % (c[1], c[0], c[0], c[0], c[0], c[0])
      print("# Running: %s" % cmd)
      subprocess.call(cmd, shell=True)
