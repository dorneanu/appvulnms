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

import base64

from lxml import etree
from core.parser.HTTPParser import HTTPParser
from core.parser.HTTPParser import HTTPRequestParser
from core.parser.HTTPParser import HTTPResponseParser


class AppVulnXMLParser():

        """AppVulnXML parser. Edits XML data"""

        def __init__(self, xml_data):
            # Create parser to parse the XML tree and insert new data into it
            self.parser = etree.XMLParser(remove_blank_text=True, strip_cdata=False,
                                          ns_clean=True, recover=True, encoding='utf-8')
            self.xml_tree = etree.XML(str(xml_data), self.parser)
            self.issues = self.xml_tree.xpath("/XmlReport/Results/Vulnerabilities/*")
            self.issue_index = 0

        def __len__(self):
            """Returns number of available issues

            :returns: Number of available issues
            """
            return len(self.issues)

        def __iter__(self):
            """Iterator to walk through issues

            :returns: Iterator to iterate through issues
            """
            return self

        def __next__(self):
            """Walk through issues"""
            issue = self.issues[self.issue_index]
            if (self.issue_index + 1) < len(self.issues):
                self.issue_index += 1
            else:
                raise StopIteration

            return issue

        def get_root(self):
            """Get root of XML document

            :returns: Root XML Element
            """
            return self.xml_tree

        def get_xml(self):
            """Returns XML tree as string

            :returns: XML tree as string
            """
            return etree.tostring(self.xml_tree, pretty_print=True, encoding="utf-8").decode("utf-8")

        def get_scanner(self):
            """Returns /XmlReport/Scanner

            :returns: /XmlReport/Scanner as XML document
            """
            return self.xml_tree.xpath("/XmlReport/Scanner")

        def get_summary(self):
            """Returns /XmlReport/Summary

            :returns: /XmlReport/Summary as XML document
            """
            return self.xml_tree.xpath("/XmlReport/Summary")

        def get_vulnerabilities(self):
            """Return /XmlReport/Results/Vulnerabilities

            :returns: /XmlReport/Results/Vulnerabilities as XML document
            """
            return self.xml_tree.xpath("/XmlReport/Results/Vulnerabilities/*")

        def add_request_data(self, issue, request_data):
            """Add parsed request data to the node

            :param issue: Issue as XML document
            :param request_data: HTTP request data
            """
            request = HTTPRequestParser(request_data)
            request.parse_data()
            request.set_http_headers()
            headers = request.get_headers()

            # Add request attributes method like method
            try:
                xml_request_node = issue.xpath("TestProbe/HTTP/Request")[0]
                xml_request_node.attrib['method'] = request.get_method()
                xml_request_node.attrib['version'] = request.get_request_version()
            except IndexError:
                log.error("Index error")

            # Add parsed data
            try:
                xml_parsed_traffic = issue.xpath("TestProbe/HTTP/Request/Parsed")[0]
            except IndexError:
                Log.error("Index error")

            # Iterate through headers and create new XML nodes
            for h in headers.keys():
                for v in headers[h]:
                    # Create new sub-element
                    header_node = etree.Element('Header', name=h, value=v)
                    xml_parsed_traffic.append(header_node)

            # Add request data node
            request_data_node = etree.Element('Data')
            request_data_node.text = etree.CDATA(request.get_request_data())
            xml_parsed_traffic.append(request_data_node)

        def add_response_data(self, issue, response_data, binary_data=False):
            """Add parsed response data to the node

            :param issue: Issue as XML document
            :param response_data: HTTP response data
            :param binary_data: Flag indicating whether responde_data is binary
            """
            response = HTTPResponseParser(response_data, binary_data)
            response.parse_data()
            response.set_http_headers()
            headers = response.get_headers()

            # Add response metadata
            try:
                xml_response_node = issue.xpath("TestProbe/HTTP/Response")[0]
                xml_response_node.attrib['version'] = response.get_response_version()
                xml_response_node.attrib['status'] = response.get_status()
                xml_response_node.attrib['reason'] = response.get_reason()
            except IndexError:
                log.error("Index error")

            # Add response data
            try:
                xml_parsed_traffic = issue.xpath("TestProbe/HTTP/Response/Parsed")[0]
            except IndexError:
                Log.error("Index error")

            # Iterate through headers and create new XML nodes
            for h in headers.keys():
                for v in headers[h]:
                    # Create new sub-element
                    header_node = etree.Element('Header', name=h, value=v)
                    xml_parsed_traffic.append(header_node)

            # Add request data node
            request_data_node = etree.Element('Data')
            request_data_node.text = etree.CDATA(response.get_response_data())
            request_data_node.attrib['base64'] = str(binary_data)
            xml_parsed_traffic.append(request_data_node)

        def extract_traffic(self, issue, binary_data=False):
            """Extract HTTP traffic from RawTraffic/MergedTraffic and adjust XML in single issue

            :param issue: Issue as XML document
            :param binary_data: Flag indicating whether traffic is binary
            """
            raw_traffic = issue.xpath("RawTraffic")[0]
            raw_request_traffic = issue.xpath("RawTraffic/RequestTraffic")
            raw_response_traffic = issue.xpath("RawTraffic/ResponseTraffic")
            raw_merged_traffic = issue.xpath("RawTraffic/MergedTraffic")

            # New nodes
            request_node = etree.Element("RequestTraffic")
            response_node = etree.Element("ResponseTraffic")
            request_node.text = ''
            response_node.text = ''

            # Add base64 flag to traffic
            request_node.attrib['base64'] = 'false'
            response_node.attrib['base64'] = 'false'

            # Check if merged traffic is provided
            if len(raw_merged_traffic) > 0:
                # Split traffic
                http_data = HTTPParser.split_http_traffic(raw_merged_traffic[0].text)

                # Adjust XML data
                if http_data:
                    request_node.text = etree.CDATA(http_data['request'])
                    raw_traffic.append(request_node)

                    response_node.text = etree.CDATA(http_data['response'])
                    raw_traffic.append(response_node)

                # Remove MergedTraffic node
                raw_merged_traffic[0].getparent().remove(raw_merged_traffic[0])

            # Check if request traffic already provided
            # TODO: Do the same for request traffic?
            if len(raw_request_traffic) > 0:

                if len(raw_request_traffic[0].text) > 0:
                    base64_flag = False
                    if 'base64' in raw_request_traffic[0].attrib:
                        if raw_request_traffic[0].attrib['base64'] == 'true':
                            base64_flag = True

                    # Check if base64
                    if base64_flag:
                        # Replace binary data by plaintext data
                        decoded_request_data = base64.b64decode(raw_request_traffic[0].text).decode("utf-8")

                        raw_request_traffic[0].getparent().remove(raw_request_traffic[0])
                        new_request_traffic = etree.Element("RequestTraffic")
                        new_request_traffic.text = etree.CDATA(decoded_request_data)
                        new_request_traffic.attrib['base64'] = "false"

                        # Append new node
                        raw_traffic.append(new_request_traffic)

            else:
                # Add new nodes
                raw_traffic.append(request_node)
                raw_traffic.append(response_node)

        def add_data(self, binary_data=False):
            """Adds request data (e.g. headers) to the XML tree

            :param binary_data: Flag indicating whether data is binary
            """
            for issue in self.issues:
                # Extract traffic
                self.extract_traffic(issue, binary_data)

                # Extract request and response
                raw_request_traffic = issue.xpath("RawTraffic/RequestTraffic")[0]
                raw_response_traffic = issue.xpath("RawTraffic/ResponseTraffic")[0]

                # Add request data
                if raw_request_traffic.text:
                    base64_flag = False
                    if 'base64' in raw_request_traffic.attrib:
                        if raw_request_traffic.attrib['base64'] == 'true':
                                base64_flag = True

                    # Check if base64
                    if base64_flag:
                        decoded_request_traffic = base64.b64decode(raw_request_traffic.text)
                        self.add_request_data(issue, decoded_request_traffic.decode(encoding="utf-8", errors="ignore"))
                    else:
                        self.add_request_data(issue, raw_request_traffic.text)

                # Add response data
                if raw_response_traffic.text:
                    base64_flag = False
                    if 'base64' in raw_response_traffic.attrib:
                        if raw_response_traffic.attrib['base64'] == 'true':
                            base64_flag = True

                    # Check if base64
                    if base64_flag:
                        decoded_response_traffic = base64.b64decode(raw_response_traffic.text)
                        self.add_response_data(
                            issue, decoded_response_traffic.decode(encoding="utf-8", errors="ignore"), True)
                    else:
                        self.add_response_data(issue, raw_response_traffic.text)

        def get_payload(self, issue):
            """Gets issue payload information, e.g. parameter/cookie and value

            :param issue: Issue as XML document
            :returns: XML data containing PoC information
            """
            raw_query = issue.xpath("TestProbe/Request/Query")
            if len(raw_query) > 0:
                return raw_query
            else:
                return None

        def convert_base64_to_plain(self):
            """Converts Base64 traffic to plaintext

            For all issue the traffic will be converted to base64.
            """
            for issue in self.issues:
                raw_traffic = issue.xpath("RawTraffic")
                request_traffic = issue.xpath("RawData/RawRequest")
                response_traffic = issue.xpath("RawData/RawResponse")

                # Decode request traffic
                if len(request_traffic) > 0:
                    base64_traffic = request_traffic[0].text
                    traffic = base64.b64decode(base64_traffic)
                    request_traffic[0].text = etree.CDATA(traffic.decode('utf-8'))

                # Decode response traffic
                if len(response_traffic) > 0:
                    base64_traffic = response_traffic[0].text
                    traffic = base64.b64decode(base64_traffic)

                    # FIXME: Do this better
                    if len(traffic) < 10000:
                        response = str(traffic)
                    else:
                        response = base64_traffic

                    # print(response)
                    response_traffic[0].text = etree.CDATA(response)

                # Merge traffic data
                raw_traffic[0].text = ''.join([request_traffic[0].text, str(response_traffic[0].text)])

                # Remove RawData
                raw_data = issue.xpath("RawData")
                issue.remove(raw_data[0])

        def string(self):
            """Returns string respresentation of XML tree

            :returns: Returns string respresentation of XML tree
            """
            return etree.tostring(self.xml_tree,
                                  pretty_print=True,
                                  xml_declaration=False
                                  ).decode(encoding="utf-8")

        def __str__(self):
            return self.string()
