#!/usr/bin/env python

###################################################################################################
#
# Copyright (c) 2015, Armin Buescher (armin.buescher@googlemail.com)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
###################################################################################################
#
# File:		ioc-parser.py
# Desc.:	IOC Parser is a tool to extract indicators of compromise from security reports
#			in PDF format.
# Usage:	ioc-parser.py [-h] [-p INI] [-f FORMAT] PDF
# Req.:		PyPDF2 (https://github.com/mstamy2/PyPDF2)
# Author:	Armin Buescher (@armbues)
# Contributors: Angelo Dell'Aera (@angelodellaera)
#
###################################################################################################

import os
import sys
import fnmatch
import argparse
import re
import traceback
from PyPDF2 import PdfFileReader

try:
    import configparser as ConfigParser
except ImportError:
    import ConfigParser

import output
from whitelist import WhiteList

class IOC_Parser(object):
    patterns = {}

    def __init__(self, args):
        self.files = args.PDF
        self.dedup = args.DEDUP
        self.load_patterns(args.INI)
        self.whitelist = WhiteList()
        self.handler = output.getHandler(args.FORMAT)

    def load_patterns(self, fpath):
        config = ConfigParser.ConfigParser()
        with open(args.INI) as f:
            config.readfp(f)

        for ind_type in config.sections():
            try:
                ind_pattern = config.get(ind_type, 'pattern')
            except:
                continue

            if ind_pattern:
                ind_regex = re.compile(ind_pattern)
                self.patterns[ind_type] = ind_regex

    def is_whitelisted(self, ind_match, ind_type):
        for w in self.whitelist[ind_type]:
            if w.findall(ind_match):
                return True

        return False

    def parse_file(self, fpath):
        with open(fpath, 'rb') as f:
            try:
                pdf = PdfFileReader(f, strict = False)

                self.handler.print_header(fpath)

                if self.dedup:
                    dd = set()

                page_num = 0
                for page in pdf.pages:
                    page_num += 1
                    data = page.extractText()

                    for ind_type, ind_regex in self.patterns.items():
                        matches = ind_regex.findall(data)

                        for ind_match in matches:
                            if isinstance(ind_match, tuple):
                                ind_match = ind_match[0]

                            if self.is_whitelisted(ind_match, ind_type):
                                continue

                            if self.dedup:
                                if (ind_type, ind_match) in dd:
                                    continue

                                dd.add((ind_type, ind_match))

                            self.handler.print_match(fpath, page_num, ind_type, ind_match)
                self.handler.print_footer(fpath)
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as e:
                self.handler.print_error(fpath, e)

    def parse(self):
        if os.path.isfile(args.PDF):
            self.parse_file(args.PDF)
            return

        if os.path.isdir(args.PDF):
            for walk_root, walk_dirs, walk_files in os.walk(args.PDF):
                for walk_file in fnmatch.filter(walk_files, '*.pdf'):
                    self.parse_file(os.path.join(walk_root, walk_file))

            return

        print("[ERROR] Invalid PDF file path")

argparser = argparse.ArgumentParser()
argparser.add_argument('PDF', action='store', help='File/directory path to PDF report(s)')
argparser.add_argument('-p', dest='INI', default='patterns.ini', help='Pattern file')
argparser.add_argument('-f', dest='FORMAT', default='csv', help='Output format (csv/json/yara)')
argparser.add_argument('-d', dest='DEDUP', action='store_true', default=False, help='Deduplicate matches')
args = argparser.parse_args()

if __name__ == "__main__":
    parser = IOC_Parser(args)
    parser.parse()
