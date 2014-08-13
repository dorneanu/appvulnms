#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: victor
# @Date:   2014-01-30
# @Last Modified by:   victor
# @Last Modified time: 2014-06-04
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

from core.framework import Log
from core.parser.AppVulnXMLParser import AppVulnXMLParser


class AppVulnDB():

    """ Manage and imports AppVulnXML files """

    def __init__(self, appVulnXML_file):
        try:
            with open(appVulnXML_file) as f:
                xml_data = f.read()
                self.VulnParser = AppVulnXMLParser(xml_data)
        except:
            Log.error("Error reading AppVulnXML file\n%s" % traceback.format_exc())

    def get_scanner(self):
        """Return scanner data

        :returns: Dictionary with scanner information
        """

        scanner = {}
        data = self.VulnParser.get_scanner()

        try:
            if len(data) > 0:
                scanner = {}
                scanner['name'] = data[0].xpath("Name")[0].text
                scanner['version'] = data[0].xpath("Version")[0].text
        except:
            Log.warn("Failed getting scanner data")
        finally:
            return scanner

    def get_scan_summary(self):
        """Returns scan summary details

        :returns: Dictionary with scan summary information
        """

        summary = {}
        data = self.VulnParser.get_summary()
        try:
            if len(data) > 0:
                summary['TotalIssues'] = data[0].xpath("TotalIssues")[0].text
                summary['NumHighIssues'] = data[0].xpath("Target/Host/Issues/High")[0].text
                summary['NumMediumIssues'] = data[0].xpath("Target/Host/Issues/Medium")[0].text
                summary['NumLowIssues'] = data[0].xpath("Target/Host/Issues/Low")[0].text
                summary['NumInfoIssues'] = data[0].xpath("Target/Host/Issues/Informational")[0].text
                summary['TargetHost'] = data[0].xpath("Target/Host/@name")[0]
                summary['ScanDuration'] = data[0].xpath("ScanDuration")[0].text
        except:
            Log.warn("Failed getting scan summary details")
        finally:
            return summary

    def get_request_headers(self, poc_xml):
        """Get XML tree containing all request headers from POC data

        :param poc_xml: PoC XML data
        :returns: Tuple of (headers, cookie, data)
        """

        headers = etree.Element("Headers")
        cookies = etree.Element("Cookies")
        data = etree.Element("Data")
        try:
            req_headers = poc_xml.xpath("Request/Parsed/Header")
            req_cookies = poc_xml.xpath("Request/Parsed/Header[@name = 'Cookie']")
            data = poc_xml.xpath("Request/Parsed/Data")[0]

            for h in req_headers:
                headers.append(h)
            for c in req_cookies:
                cookies.append(c)
        except:
            Log.warn("Couldn't get request headers")
        finally:
            return (headers, cookies, data)

    def get_response_headers(self, poc_xml):
        """Get XML tree containing all response headers from POC data

        :param poc_xml: PoC XML data
        :returns: Tuple of (headers, cookie, response_data)
        """

        headers = etree.Element("Headers")
        cookies = etree.Element("Cookies")
        data = etree.Element("Data")

        try:
            res_headers = poc_xml.xpath("Response/Parsed/Header")
            res_cookies = poc_xml.xpath("Response/Parsed/Header[@name = 'Set-Cookie']")
            res_data = poc_xml.xpath("Response/Parsed/Data")

            if res_data:
                res_data = res_data[0]
            else:
                res_data = etree.Element('Data')

            for h in res_headers:
                headers.append(h)
                for c in res_cookies:
                    cookies.append(c)
        except:
            Log.warn("Couldn't get response headers")
        finally:
            return (headers, cookies, res_data)

    def get_payload_data(self, poc_xml):
        """ Get payload specific information

        :param poc_xml: POC XML data
        :returns: Tuple of (payload_type, payload_name, payload_data)
        """

        payload = poc_xml.xpath("Request/Payload")
        try:
            if payload:
                payload_type = payload[0].xpath("Input/@type")[0]
                payload_name = payload[0].xpath("Input/@name")[0]
                payload_data = payload[0].xpath("Raw")[0].text
                return payload_type, payload_name, payload_data
            else:
                return '', '', ''
        except:
            Log.warn("Couldn't get payload data")
            return '', '', ''

    def get_references(self, poc_xml):
        """ Get XML tree containing references

        :param poc_xml: POC XML data
        :returns: etree.Element containing references
        """
        references = poc_xml.xpath("References")

        if references:
            return references[0]
        else:
            return etree.Element("References")

    def get_vulns(self):
        """ Get all vulnerabilities with detailed data (e.g. header, poc etc.)

        :returns: List of vulnerabilities
        """
        appVulnXML_vulns = self.VulnParser.get_vulnerabilities()
        vulns = []

        try:
            if len(appVulnXML_vulns) > 0:
                for v in appVulnXML_vulns:
                    # Gather general information
                    issue = {}
                    issue['type'] = v.xpath("@type")[0]
                    issue['description'] = v.xpath("Description")[0].text
                    issue['severity'] = v.xpath("Severity")[0].text
                    issue['error_type'] = v.xpath("@error_type")[0]

                    # Extract POC information
                    poc_xml = v.xpath("TestProbe/HTTP")[0]
                    poc_data = {}
                    poc_data['URL'] = poc_xml.xpath("Request/URL")[0].text
                    poc_data['method'] = poc_xml.xpath("Request/@method")[0]

                    # Extract request data
                    headers, cookies, data = self.get_request_headers(poc_xml)
                    poc_data['req_hdr'] = etree.tostring(headers).decode("utf-8")
                    poc_data['req_cookies'] = etree.tostring(cookies).decode("utf-8")
                    poc_data['req_data'] = etree.tostring(data).decode("utf-8")

                    # Extract response data
                    headers, cookies, data = self.get_response_headers(poc_xml)
                    poc_data['res_hdr'] = etree.tostring(headers).decode("utf-8")
                    poc_data['res_cookies'] = etree.tostring(cookies).decode("utf-8")
                    poc_data['res_data'] = etree.tostring(data).decode("utf-8")

                    # Extract payload data
                    payload_type, payload_name, payload_data = self.get_payload_data(poc_xml)
                    poc_data['payload_type'] = payload_type
                    poc_data['payload_name'] = payload_name
                    poc_data['payload_data'] = payload_data

                    # Add references
                    poc_data['references'] = etree.tostring(self.get_references(poc_xml))

                    # Add vulnerability to list
                    v = {}
                    v['issue'] = issue
                    v['poc_data'] = poc_data
                    vulns.append(v)

        except:
            Log.warn("Failed getting vulnerabilities")
        finally:
            return vulns
