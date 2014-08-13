#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: victor
# @Date:   2014-01-30
# @Last Modified by:   victor
# @Last Modified time: 2014-06-05
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

# Modules specific options/settings
modules = {}
modules['path']                 = './src/modules/'
modules['path_delim']           = '/'
modules['path_loadname_delim']  = '::'
modules['module_suffix']        = '.py'

# appvulnms specific options/settings
appvulnms = {}
appvulnms['banner'] = """
       _           __   __    _      __  __ ___
      /_\  _ __ _ _\ \ / /  _| |_ _ |  \/  / __|
     / _ \| '_ \ '_ \ V / || | | ' \| |\/| \__ \ \

    /_/ \_\ .__/ .__/\_/ \_,_|_|_||_|_|  |_|___/
          |_|  |_|

    --------------------------------------------
    Application Vulnerability Management System

"""

# Parser settings
appvulnms['usage'] = \
"%(prog)s [optional args] {positional args}\n\n\
------------------------------------------------------------------------\n\
Choose between the available modes and check parameters:\n\
\t$ $%(prog)s <mode> --help\n\
------------------------------------------------------------------------\n\
"

appvulnms['module_mode_usage'] = \
"%(prog)s [optional args] [positional args]\n\n\
------------------------------------------------------------------------\n\
In order to list available modules:\n\
\t$ %(prog)s -l \n\n\
To interact with specific module:\n\
\t$ %(prog)s <modules name> <modules parameters>\n\n\
To get modules parameters:\n\
\t$ %(prog)s <modules name> --help\n\
------------------------------------------------------------------------\n\
"
