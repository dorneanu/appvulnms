#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: victor
# @Date:   2014-01-12
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

import argparse
import os
import sqlite3
import traceback
from lxml import etree

import core.framework as framework
from core.framework import Log
from core.parser.AppVulnXMLParser import AppVulnXMLParser
from core.db.AppVulnDB import AppVulnDB


class AppVulnDB_SQLite(framework.AppVulnDB):

    """
    SQLite version of AppVulnDB
    """

    def __init__(self, db_file):
        # Location for DB schema
        self.db_schema = "./data/AppVulnDB/schema.sqlite"
        self.db = db_file

    def init(self):
        """ Init and creates the DB """
        try:
            if not os.path.exists(self.db):
                with open(self.db_schema) as f:
                    schema = f.read()
                    conn = sqlite3.connect(self.db)
                    conn.executescript(schema)
                    conn.close()
                    return True
            else:
                Log.error("File exists. Exiting")
                return False
        except:
            Log.error("Error creating DB\n%s" % traceback.format_exc())
            return False

    def connect(self):
        """ Connects to DB """
        try:
            self.conn = sqlite3.connect(self.db)
        except:
            Log.error("Couldn't connect to DB")

    def __get_poc_type_id_by_name(self, type_name):
        """ Return PoC type id by specified name """
        cursor = self.conn.cursor()
        cursor.execute("SELECT id FROM poc_type WHERE name = ?", [type_name])
        poc_type = cursor.fetchone()
        if poc_type:
            return poc_type[0]
        else:
            return None

    def __get_poc_table_name_by_id(self, poc_type_id):
        """ Return PoC table name by specified PoC type id """
        cursor = self.conn.cursor()
        cursor.execute("SELECT poc_table_name FROM poc_type WHERE id = ?", (poc_type_id,))
        poc_table_name = cursor.fetchone()
        if poc_table_name:
            return poc_table_name[0]
        else:
            return None

    def __import_scanner(self, scanner):
        """ Imports scanner data """
        # Check if scanner already exists
        cursor = self.conn.cursor()
        cursor.execute("SELECT id FROM scanner WHERE name=? AND version=?",
                       (scanner['name'], scanner['version']))

        scanner_ids = cursor.fetchall()

        if len(scanner_ids) == 0:
            # Prepare insert query
            query = """
                INSERT INTO scanner (name, version)
                VALUES (?, ?)
            """
            cursor.execute(query, (scanner['name'], scanner['version']))
            return cursor.lastrowid
        else:
            # Return scanner id
            return scanner_ids[0][0]

    def __import_scan_summary(self, summary, scanner_id):
        """ Imports summary data """
        cursor = self.conn.cursor()
        query = """
            INSERT INTO scan (scope, target, count_total_vulns, scanner_id)
            VALUES (?, ?, ?, ?)
        """
        cursor.execute(query, (summary['TargetHost'],
                               summary['TargetHost'],
                               summary['TotalIssues'],
                               scanner_id))

        # Return scan id
        return cursor.lastrowid

    def __import_vulns(self, vulns, scan_id, scanner_id):
        """ Import vulnerabilities into DB """
        for v in vulns:
            # Extract vulnerability details
            issue = v['issue']
            poc_data = v['poc_data']

            # Add extra information
            issue['scan_id'] = scan_id
            issue['poc_type_id'] = self.__get_poc_type_id_by_name("http")
            issue['poc_table_name'] = self.__get_poc_table_name_by_id(issue['poc_type_id'])

            query = """
                INSERT INTO %s
                (
                    URL, method, request_header, request_cookie, request_data,
                    response_header, response_cookie, response_data, input_type, input_name, input_payload,
                    scanner, vulnerability_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """ % (issue['poc_table_name'])

            cursor = self.conn.cursor()
            cursor.execute(query,
                           (
                               poc_data['URL'], poc_data['method'], poc_data[
                                   'req_hdr'], poc_data['req_cookies'], poc_data['req_data'],
                               poc_data['res_hdr'], poc_data['res_cookies'], poc_data['res_data'],
                               poc_data['payload_type'], poc_data['payload_name'], poc_data['payload_data'],
                               scanner_id, 1
                           )
                           )
            poc_id = cursor.lastrowid

            # Prepare insert query for vulnerability data
            query = """
                INSERT INTO vulnerability
                (
                    type, name, severity, description, scan_id,
                    error_type, poc_type_id, poc_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """
            cursor = self.conn.cursor()
            cursor.execute(query,
                           (
                               issue['type'], "FIXME", issue['severity'], issue['description'], issue['scan_id'],
                               issue['error_type'], issue['poc_type_id'], poc_id
                           )
                           )
            vuln_id = cursor.lastrowid
            print(vuln_id)

    def commit(self):
        """ Commit transactions """
        self.conn.commit()

    def import_data_from_xml(self, appVulnXML):
        """ Imports data from provided AppVulnXML file """
        scanner_id = self.__import_scanner(appVulnXML.get_scanner())
        scan_id = self.__import_scan_summary(appVulnXML.get_scan_summary(), scanner_id)
        self.__import_vulns(appVulnXML.get_vulns(), scan_id, scanner_id)

    def import_scan(self, xml_filename):
        try:
            # Create AppVulnDB handler
            appVulnXML = AppVulnDB(xml_filename)

            # Connect to DB
            self.connect()

            # Import data
            self.import_data_from_xml(appVulnXML)

            # Commit transactions
            self.commit()

            # Close connection
            self.close()
        except:
            Log.error("Error importing AppVulnXML\n%s" % traceback.format_exc())
            return False
        return True

    def close(self):
        """ Close DB """
        self.conn.close()


class Module(framework.BaseModule):

    """
    Vulnerability Management System for AppVulnXML issues for SQLite
    """

    def __init__(self, params):
        framework.BaseModule.__init__(self, params)
        self.info = {
            'Name': 'vms/appvulndb/sqlite',
            'Author': 'Cyneox / nullsecurity.net',
            'Descripbtion': 'Manages application vulnerabilities in SQLite DB ',
            'Version': 'v0.1',
            'URL': 'http://sqlite.org/'
        }
        # Location for DB schema
        self.db_schema_filename = "./data/AppVulnDB/schema.sqlite"

        # Add common options
        self.base_parser = argparse.ArgumentParser(add_help=False)
        self.base_parser.add_argument("-q", "--quiet", dest="quiet", action="store_true", help="Keep it quiet")
        self.base_parser.add_argument("-v", "--verbose", dest="verbose", action="store_true", help="Add verbosity")

        # Add AppVulnDB parser where several modes are possible
        self.parser = argparse.ArgumentParser()
        self.subparsers = self.parser.add_subparsers(dest="action", help="Choose mode")

        # Add modes
        self.mode_init = self.subparsers.add_parser("init", parents=[self.base_parser], help="Create SQLite AppVulnDB")
        self.mode_init.add_argument("-f", "--db-file", dest="db_file", action="store",
                                    help="Specify file where to store DB")

        self.mode_import = self.subparsers.add_parser(
            "import", parents=[self.base_parser], help="Import vulns in AppVulnXML format into DB")
        self.mode_import.add_argument("-f", "--xml-input", dest="appvulnxml_file",
                                      action="store", help="Specify AppVulnXML file")
        self.mode_import.add_argument("-d", "--db-file", dest="db_file", action="store", help="AppVulnDB SQLite file")

    def module_run(self):
        try:
            # Init modus
            if self.args.action == "init":
                appVulnDB = AppVulnDB_SQLite(self.args.db_file)

                if appVulnDB.init():
                    Log.info("Succesfully created DB")
                else:
                    Log.warn("Couldn't create DB")

            # Import modus
            elif self.args.action == "import":
                appVulnDB = AppVulnDB_SQLite(self.args.db_file)

                if appVulnDB.import_scan(self.args.appvulnxml_file):
                    Log.info("Successfully imported data into DB")
                else:
                    Log.warn("Couldn't import data")

            # No modus
            else:
                print("No modus")

        except Exception:
            Log.error("Error loading module: %s" % traceback.format_exc())
            return
# EOF
