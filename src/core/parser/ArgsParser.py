#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: victor
# @Date:   2014-02-02
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

import core.framework as framework
import core.conf.appvulnms as conf


class ArgsParser():

    """Implements basic command line parsing"""

    def __init__(self, params):
        """ Initialize parser """
        # Add common options
        self.base_parser = argparse.ArgumentParser(add_help=False)
        self.base_parser.add_argument("-q", "--quiet", dest="quiet", action="store_true", help="Keep it quiet")
        self.base_parser.add_argument("-v", "--verbose", dest="verbose", action="store_true", help="Add verbosity")

        # Add AppVulnMS parser where several modes are possible
        self.parser = argparse.ArgumentParser()
        self.subparsers = self.parser.add_subparsers(dest="action", help="Choose mode")

        # Module mode (m)
        self.m_parser = self.subparsers.add_parser(
            "m", parents=[self.base_parser],
            usage=conf.appvulnms['module_mode_usage'],
            help="Interact with available modules",
            description="::: Interact with the available modules."
        )
        self.m_parser.add_argument("-l", "--list-modules", dest="list_modules",
                                   action="store_true", help="List available modules")
        self.m_parser.add_argument("module_name", action="store", nargs="?", help="Modules name")
        self.m_parser.add_argument('module_params', action="store",
                                   nargs=argparse.REMAINDER, help="Modules parameters")

    def parse(self, params):
        """Parse parameters and return options/args

        :param params: ArgParse parameters
        :returns: Arguments as dictionary
        """
        args = self.parser.parse_args(params)
        return args

    def get_description(self):
        """Gets tool description"""
        print(conf.appvulnms['banner'])
        return "sample description"

    def print_usage(self):
        """Print usage message"""
        usage = "AppVulnMS.py [options]"
        return usage

    def print_help(self):
        """Print help message"""
        self.parser.print_help()

    def run_actions(self, opts):
        """Run actions specified by the parameters

        :param opts: Dictionary containing arguments
        """

        modules_path = conf.modules['path']
        modules_collection = framework.ModuleCollection(modules_path)
        modules_collection.load_modules()

        # Show all available modules
        if opts.list_modules:
            modules_collection.show_modules()
            return

        # Show available module options
        if opts.module_name:
            m = modules_collection.load_module(opts.module_name)
            # m.parse_params(self.module_parser)

            # Print modules info if no parameters
            if not opts.module_params:
                m.display_info()
            else:
                m.parse_params(opts.module_params)
                m.module_run()
            return
