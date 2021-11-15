#!/usr/bin/env python2
# SPDX-License-Identifier: MIT

import os
import sys

from pygments            import highlight
from pygments.lexers     import CLexer
from pygments.formatters import HtmlFormatter
from pygments.formatter  import Formatter
from pygments.token      import *

ROOT  = os.path.abspath(os.path.dirname(__file__))
LINUX = os.path.join(ROOT, "../../linux")

class Dumb(Formatter):
    def format(self, tokensource, outfile):
        lookup = []
        for ttype, value in tokensource:
            print(ttype, value)

if __name__ == '__main__':
    with open(sys.argv[1]) as fd:
        highlight(fd.read(), CLexer(), Dumb())
