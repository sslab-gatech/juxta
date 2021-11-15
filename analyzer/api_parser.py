#!/usr/bin/env python2
# SPDX-License-Identifier: MIT

import os
import sys
import dbg
import utils
from color import Color
import glob
import pdb

from ckapi import ExternAPI

if __name__ == '__main__':
    utils.install_pdb()

    if len(sys.argv) != 2:
        print "%s input_file" % sys.argv[0]
        exit(1)

    f = open(sys.argv[1], "r")
    if not f:
        print "failed to open input file %s" % sys.argv[1]
        exit(1)

    apis = dict()
    for line in f:
        (api_str, func_str) = utils.split(line, "@FUNCTION")
        if api_str[0:4] != "@API":
            continue

        api_str = api_str[5:]
        (api_name, rtn) = api_str.split(":", 1)
        (func, conds) = func_str.split(":", 1)
        conds = eval(conds)
        
        api = apis.get(api_str, ExternAPI(api_name, rtn))
        for cond in conds:
            api.add(func, cond)
        apis[api_str] = api

    for api in apis.values():
        api.report(0)
