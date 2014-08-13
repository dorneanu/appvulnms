#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: victor
# @Date:   2014-02-09
# @Last Modified by:   victor
# @Last Modified time: 2014-06-06
# @Copyright:
#
#    This file is part of the AppVulnMS project.
#
#
#    Copyright (c) 2014 Victor Dorneanu <info AAET dornea DOT nu>
#
#    Permission is hereby granted, free of charge, to any person obtaining a copy
#    of this software and associated documentation files (the "Software"), to deal
#    in the Software without restriction, including without limitation the rights
#    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#    copies of the Software, and to permit persons to whom the Software is
#    furnished to do so, subject to the following conditions:
#
#    The above copyright notice and this permission notice shall be included in all
#    copies or substantial portions of the Software.
#
#    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#    SOFTWARE.
#
#    The MIT License (MIT)

import argparse
import pprint
import sys,os.path

# Add folders to Pythons system path
sys.path.append('./src/')

# Add own modules/packages
from core.parser.ArgsParser import ArgsParser
import core.conf.appvulnms as conf


def display_banner():
    """ Display banner """
    print(conf.appvulnms['banner'])

if __name__ == '__main__':
    display_banner()

    # Create parser
    parser = ArgsParser(sys.argv[0])

    # Check for arguments
    if (len(sys.argv) > 1):
        # Parse options
        args = parser.parse(sys.argv[1:])

        # Run actions
        parser.run_actions(args)
    else:
        parser.print_help()
