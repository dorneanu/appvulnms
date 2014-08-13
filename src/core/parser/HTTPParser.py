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

import io
import email
import re
import base64

from lxml import etree
from http.server import BaseHTTPRequestHandler
from core.framework import Log
from collections import defaultdict


class HTTPParser(BaseHTTPRequestHandler):

    """ Simple HTTP Request Handler parser """

    def __init__(self, http_traffic):
        # Parse HTTP traffic
        self.rfile = io.BytesIO(http_traffic.encode('utf-8'))
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None

    def parse_data(self):
        """ Parse HTTP request and set internal variables.
            This code is taken from Python3 standard library
                http.server
            I have changed the code to call my own parse_headers function.
        """
        self.command = None  # set in case of error on the first line
        self.request_version = version = self.default_request_version
        self.close_connection = 1
        requestline = str(self.raw_requestline, 'utf-8')
        requestline = requestline.rstrip('\r\n')
        self.requestline = requestline
        words = requestline.split()
        if len(words) == 3:
            command, path, version = words
            if version[:5] != 'HTTP/':
                self.send_error(400, "Bad request version (%r)" % version)
                return False
            try:
                base_version_number = version.split('/', 1)[1]
                version_number = base_version_number.split(".")
                # RFC 2145 section 3.1 says there can be only one "." and
                #   - major and minor numbers MUST be treated as
                #      separate integers;
                #   - HTTP/2.4 is a lower version than HTTP/2.13, which in
                #      turn is lower than HTTP/12.3;
                #   - Leading zeros MUST be ignored by recipients.
                if len(version_number) != 2:
                    raise ValueError
                version_number = int(version_number[0]), int(version_number[1])
            except (ValueError, IndexError):
                self.send_error(400, "Bad request version (%r)" % version)
                return False
            if version_number >= (1, 1) and self.protocol_version >= "HTTP/1.1":
                self.close_connection = 0
            if version_number >= (2, 0):
                self.send_error(505,
                                "Invalid HTTP Version (%s)" % base_version_number)
                return False
        elif len(words) == 2:
            command, path = words
            self.close_connection = 1
            if command != 'GET':
                self.send_error(400,
                                "Bad HTTP/0.9 request type (%r)" % command)
                return False
        elif not words:
            return False
        else:
            self.send_error(400, "Bad request syntax (%r)" % requestline)
            return False
        self.command, self.path, self.request_version = command, path, version

        # Examine the headers and look for a Connection directive.
        try:
            self.headers = self.parse_headers(self.rfile)
        except http.client.LineTooLong:
            self.send_error(400, "Line too long")
            return False

        conntype = self.headers.get('Connection', "")
        if conntype.lower() == 'close':
            self.close_connection = 1
        elif (conntype.lower() == 'keep-alive' and
              self.protocol_version >= "HTTP/1.1"):
            self.close_connection = 0
        # Examine the headers and look for an Expect directive
        expect = self.headers.get('Expect', "")
        if (expect.lower() == "100-continue" and
                self.protocol_version >= "HTTP/1.1" and
                self.request_version >= "HTTP/1.1"):
            if not self.handle_expect_100():
                return False
        return True

    def parse_headers(self, fp):
        """ Parse HTTP headers and return appropriate object to represent them.

            This code was taken from Python3 standard library
                http.client

            I have adapted it to ignore the first line of the request.
        """
        headers = []
        while True:
            line = fp.readline()
            headers.append(line)
            if line in (b'\r\n', b'\n', b''):
                break

        # Ignore first line of request
        hstring = b''.join(headers[1:]).decode('utf-8')
        return email.parser.Parser().parsestr(hstring)

    def set_http_headers(self):
        """ Set HTTP headers after parsing the request"""
        self.http_headers = defaultdict(list)

        if 'headers' in self.__dict__:
            # Iterate headers
            for k in self.headers.keys():
                if k == 'Cookie':
                    values = []
                    cookies = {}
                    values = self.headers.get_all(k)

                    # Iterate and extract cookies
                    for v in values:
                        trimmed = v.replace(" ", "")
                        pairs = trimmed.split(';')

                        for p in pairs:
                            self.http_headers[k].append(p)

                elif k == 'Set-Cookie':
                    values = []
                    cookies = []
                    values = self.headers.get_all(k)

                    # Iterate and extract cookies
                    for v in values:
                        trimmed = v.replace(" ", "")
                        self.http_headers[k].append(trimmed)

                else:
                    values = self.headers.get_all(k)
                    if len(values) > 1:
                        self.http_headers[k].append(values)
                    else:
                        self.http_headers[k].append(values[0])

    def send_error(self, code, message):
        self.error_code = code
        self.error_message = message

    def get_error_code(self):
        """ Get request error code """
        if 'error_code' in self.__dict__:
            return self.error_code
        else:
            return None

    def get_method(self):
        """ Return method (GET, POST etc.) """
        if 'command' in self.__dict__:
            return self.command
        else:
            return None

    def get_request_version(self):
        """ Return used HTTP version """
        if 'request_version' in self.__dict__:
            return self.request_version
        else:
            return None

    def get_url(self):
        """ Get requests URL """
        if 'path' in self.__dict__:
            return self.path
        else:
            return None

    def get_data(self):
        if 'data' in self.__dict__:
            return self.data
        else:
            return None

    def get_response_data(self):
        if 'http_response' in self.__dict__:
            return self.http_response
        else:
            return None

    def get_request(self):
        return "%s %s %s" % (self.get_method(), self.get_url(), self.get_request_version())

    def get_headers(self):
        """ Get HTTP headers """
        return self.http_headers

    @staticmethod
    def split_http_traffic(http_traffic):
        """ Splits HTTP traffic by request and response traffic data

            Returns dictionary: data['request'] ,data['response']
        """
        try:
            fp = io.BytesIO(http_traffic.encode('utf-8'))
        except:
            Log.warn("No HTTP traffic data found")
            return

        http_data = dict()
        request_data = []
        response_data = []

        # Fead raw HTTP request traffic
        while True:
            line = fp.readline()
            request_data.append(line)
            if line in (b'\r\n', b'\n', b''):
                break

        # Read data (e.g. POST data)
        while True:
            line = fp.readline()
            # print(line)
            # request_data.append(line)
            if line in (b'\r\n', b'\n', b''):
                break
            else:
                request_data.append(line)

        # Read raw HTTP response traffic
        while True:
            line = fp.readline()
            # print(line)
            response_data.append(line)
            if line in (b''):
                break

        # Return data
        http_data['request'] = b''.join(request_data).decode('utf-8')
        http_data['response'] = b''.join(response_data).decode('utf-8')
        return http_data

    def __str__(self):
        output = "%s\t %s\t %s" % (self.get_method(), self.get_url(), self.get_data())
        output = self.get_request()
        return output


class HTTPRequestParser(HTTPParser):

        """ HTTP Request implementation of HTTPParser """

        def __init__(self, request_text):
            super().__init__(request_text)

        def parse_headers(self, fp):
            """ Override parent method in order to parse the request
                data as well.
            """
            headers = []
            while True:
                line = fp.readline()
                headers.append(line)
                if line in (b'\r\n', b'\n', b''):
                    break

            # Parse request data (e.g, POST dataa)
            self.request_data = fp.readline().decode('utf-8')

            # Ignore first line of request
            hstring = b''.join(headers[1:]).decode('utf-8')
            return email.parser.Parser().parsestr(hstring)

        def get_request_data(self):
            """ Return request data (e.g. POST data) """
            return self.request_data


class HTTPResponseParser(HTTPParser):

        """ HTTP Response implementation of HTTPParser """

        def __init__(self, response_text, binary_data=False):
            super().__init__(response_text)
            self.binary_data = binary_data

        def parse_data(self):
            """ Override parent method to parse only headers and data.
                No additional logic is required here.
            """
            self.statusline = str(self.raw_requestline.decode('utf-8'))
            words = self.statusline.split()

            # Parse first line of response
            if len(words) >= 3:
                self.version = words[0]
                self.statuscode = words[1]
                self.reason = ' '.join(words[2:])

            # Parse headers
            try:
                self.headers = self.parse_headers(self.rfile)
            except http.client.LineTooLong:
                self.send_error(400, "Line too long")
                return False
            return True

        def parse_headers(self, fp):
            """ Override parent method """
            headers = []
            while True:
                line = fp.readline()
                headers.append(line)
                if line in (b'\r\n', b'\n', b''):
                    break

            # Get response data
            self.body_data = []
            while True:
                line = fp.readline()
                if line in (b'\r\n', b'\n'):
                    continue
                elif line in (b''):
                    break
                else:
                    self.body_data.append(line)

            # Set response data
            if self.binary_data:
                # Bae64-Encode response data
                response_data = b''.join(self.body_data)
                encoded_response_data = base64.b64encode(response_data)
                self.response_data = encoded_response_data
            else:
                self.response_data = b''.join(self.body_data).decode('utf-8')

            # Merge headers
            hstring = b''.join(headers).decode('utf-8')
            return email.parser.Parser().parsestr(hstring)

        def get_status(self):
            if 'statuscode' in self.__dict__:
                return self.statuscode
            else:
                return ''

        def get_reason(self):
            if 'reason' in self.__dict__:
                return self.reason
            else:
                return ''

        def get_response_version(self):
            if 'version' in self.__dict__:
                return self.version
            else:
                return ''

        def get_response_data(self):
            return self.response_data
