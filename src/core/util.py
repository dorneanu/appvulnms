#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: victor
# @Date:   2014-05-27
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

from lxml import etree


class XMLTools():

    """Provides simple XML utilities"""


    @staticmethod
    def write_xml_to_file(xml, filename):
        """Writes xml to filename

        :param filename: File to write XML to.
        """
        try:
            xml_file = open(filename, "w")
            xml_file.seek(xml_file.tell())
            xml_file.write(xml)
            xml_file.close()
            return True
        except:
            Log.error("Couldn't write to XML to file")
            return False

    @staticmethod
    def transform_xml(xml_file, xslt_file):
        """Transform XML using XSLT

        :param xml_file: XML file to convert
        :param xslt_file: XSLT conversion file
        """

        input_xml = xml_file.read().encode('utf-8')
        xml_tree = etree.XML(input_xml)

        input_xslt = xslt_file.read().encode('utf-8')
        xslt_root = etree.XML(input_xslt)

        # Convert XML using XSLT
        transform = etree.XSLT(xslt_root)
        converted_xml = transform(xml_tree)

        return converted_xml
