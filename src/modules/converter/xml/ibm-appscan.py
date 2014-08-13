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
import re
from lxml import etree

import core.framework as framework
from core.parser.AppVulnXMLParser import AppVulnXMLParser
from core.util import XMLTools


class Module(framework.BaseModule):

    """
    Converts IBM AppScan Rational scanning data into AppVulnXML format
    """

    def __init__(self, params):
        framework.BaseModule.__init__(self, params)
        self.info = {
            'Name': 'converter/xml/ibm-appscan',
            'Author': 'Cyneox / nullsecurity.net',
            'Description': 'Converts IBM AppScan results into suitable AppVulnXML format using XSLT',
            'Version': 'v0.1',
            'URL': 'http://www-03.ibm.com/software/products/us/en/appscan/'
        }

        # Add module parameters
        # TODO: Add defaults
        self.parser = argparse.ArgumentParser(
            usage=self.get_usage(),
            description=self.get_description())

        self.parser.add_argument('-i', '--input',
                                 help='Input file', type=argparse.FileType('r'),
                                 dest='input_file')

        self.parser.add_argument('-o', '--output',
                                 help='Output file',
                                 dest='output_file')

        self.parser.add_argument('-x', '--xslt',
                                 help='XSLT file', type=argparse.FileType('r'),
                                 dest='xslt_file')

    def set_payload(self, xml):
        """ Set payload data for every issue """
        issuesParser = AppVulnXMLParser(xml)

        # Adjust payload information
        for i in issuesParser:
            payload = i.xpath("TestProbe/HTTP/Request/Payload")[0]
            payload_input = payload.xpath("Input")[0]
            payload_raw = payload.xpath("Raw")[0]

            if payload_raw.text:
                payloads = re.split(r",", payload_raw.text)

                # Iterate through all available payloads
                for p in payloads:
                    match = re.search(r"(%s):(.*) -> (.*)=(.*)" % payload_input.attrib['type'], p)

                    # Any matches ?
                    # If one match found abort search since AppScan is
                    # providing variants of the same payload
                    if match:
                        payload_input.text = etree.CDATA(match.group(4).strip())
                        break

        # Return modified XML
        return issuesParser.string()

    def post_actions(self, xml):
        """ Perform post actions after XSLT transformation """
        # Add HTTP data to issues
        issuesParser = AppVulnXMLParser(xml)
        issuesParser.add_data()

        # Set payload data
        new_xml = self.set_payload(issuesParser.string())
        return new_xml

    def module_run(self):
        try:
            # Convert XML file
            converted_xml = XMLTools.transform_xml(self.args.input_file, self.args.xslt_file)

            # Post actions
            xml_out = self.post_actions(converted_xml)

            # Write to file
            XMLTools.write_xml_to_file(xml_out, self.args.output_file)

        except Exception:
            Log.error("Error loading module: %s" % traceback.format_exc())
            return
# EOF
