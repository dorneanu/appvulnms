#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: victor
# @Date:   2014-06-04
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

import imp
import os
import sys
import traceback
from abc import ABCMeta, abstractmethod
from pprint import pprint

import core.conf.appvulnms as conf


class Log():

    """Implements simple logging functionalities
    """

    def __init__(self):
        pass

    @staticmethod
    def info(msg):
        """Prints a info message

        :param msg: Message to be printed
        """
        print("[\033[33mINFO\033[0m]\t%s" % msg)

    @staticmethod
    def warn(msg):
        """Prints a warning message

        :param msg: Message to be printed
        """
        print("[\033[34mWARN\033[0m]\t%s" % msg)

    @staticmethod
    def error(msg):
        """Print an error message

        :param msg: Message to be printed
        """
        print("[\033[31mERROR\033[0m]\t%s\n" % msg)


class ModuleCollection():

    """Easy modules management

    Provides some sort of API in order to organize modules.
    """

    def __init__(self, path):
        self.categories = {}
        self.modules = {}
        self.path = path

    def load_modules(self):
        """Loads modules from specified path (self.path)"""

        for dirpath, dirs, files in os.walk(self.path):

            # Filter only Python files
            modules = [f for f in files if f.endswith(conf.modules['module_suffix'])]

            if len(modules) > 0:
                category_path = dirpath.split('/')[3:]
                modules_category = "/".join(category_path)

                # Add new category
                if modules_category not in self.categories:
                    self.categories[modules_category] = []

                # Seek for available modules
                for m in modules:
                    module = {}
                    module['name'] = m.split('.')[0]
                    module['path'] = os.path.join(dirpath, m)
                    module['disp_name'] = modules_category + conf.modules['path_delim'] + module['name']
                    module['load_name'] = module['disp_name'].replace('/', conf.modules['path_loadname_delim'])

                    # Open and load module
                    try:
                        module_file = open(module['path'], 'rb')
                        imp.load_source(module['load_name'], module['path'], module_file)
                        __import__(module['load_name'])

                        # Add to list(s)
                        self.categories[modules_category].append(module['load_name'])
                        self.modules[module['disp_name']] = module['load_name']
                    except:
                        traceback.print_exc()

    def load_module(self, module):
        """Loads specified module

        :param module: Module to load
        """
        try:
            # FIXME: Load module name from self.modules (e.g. self.modules[module])
            _m = sys.modules[module.replace('/', conf.modules['path_loadname_delim'])]
            loaded_module = _m.Module(module)
            return loaded_module
        except Exception:
            Log.error("Error loading module: %s" % traceback.format_exc())
            return

    def show_modules(self):
        """Prints all available modules in self.path"""

        Log.info("Available modules:")
        for m in self.modules:
            module = self.load_module(m)
            module.display_info()
            print("")

    def show_modules_by_category(self, category):
        """Prints all modules available in specified category

        :param category: Category to lookup for modules.
        """

        # TODO: Implement me
        pass

    def show_module(self, module):
        """Prints information about module

        :param module: Print information about module
        """

        # TODO: Implement me
        pass


class BaseModule():

    """Abstract class for inner structure of a module

    Defines abstract methodes which _have_ to be implemented by the
    modules subclassing/inheriting this class.
    """

    @abstractmethod
    def __init__(self, params):
        self.info = 'Module'
        self.parameters = {}
        pass

    @abstractmethod
    def module_load(self, params):
        """Loads a module

        :param params: Parameters in order to load module.
        """

        pass

    @abstractmethod
    def module_run(self):
        """Runs module"""

        pass

    @abstractmethod
    def parse_params(self, params):
        """Parses parameters and return arguments

        :param params: Module specific parameters
        """

        self.args = self.parser.parse_args(params)

    @abstractmethod
    def get_usage(self):
        """Displays module usage"""

        pass

    @abstractmethod
    def get_description(self):
        """Returns module description

        :returns: Modules description
        """

        if 'Description' in self.info:
            return self.info['Description']
        else:
            return None

    @abstractmethod
    def display_info(self):
        """Displays basic information about current module"""

        if 'Name' in self.info:
            print("::: %s " % self.info['Name'])

        if 'Description' in self.info:
            print("\t_ Desc\t\t %s" % self.info['Description'])

        if 'Author' in self.info:
            print("\t_ Author\t %s" % self.info['Author'])

        if 'Version' in self.info:
            print("\t_ Version\t %s" % self.info['Version'])

        if 'URL' in self.info:
            print("\t_ URL:\t\t %s" % self.info['URL'])


class AppVulnDB():

    """Abstract class for inner structure of modules implementing
    AppVulnDB functionalities.


    Defines abstract methodes which _have_ to be implemented by the
    modules subclassing/inheriting this class.
    """

    @abstractmethod
    def init(self):
        """ Creates and inits DB with specified schema """
        pass

    @abstractmethod
    def connect(self):
        """Connects to DB"""
        pass

    @abstractmethod
    def import_scan(self):
        """Imports scan results from AppVulnXML file"""
        pass

    @abstractmethod
    def commit(self):
        """Commits transactions to DB"""
        pass

    @abstractmethod
    def close(self):
        """Close connection to DB"""
