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
# Contrib.: Angelo Dell'Aera (@angelodellaera)
#
###################################################################################################

import os
import sys
import fnmatch
import argparse
import ConfigParser
import StringIO
import re
import csv
import json
import traceback
from PyPDF2 import PdfFileReader
from whitelist import WhiteList

class IOC_Parser(object):
    OUTPUT_FORMATS = ('csv', 'json', )
    patterns = {}

    def __init__(self, args):
        self.files     = args.PDF
        self.format    = self.check_format(args.FORMAT)
        self.dd        = set() if args.DEDUP else None
        self.whitelist = WhiteList()

        self.load_patterns(args.INI)

        if self.format == 'csv':
            self.csv_writer = csv.writer(sys.stdout, delimiter = '\t')

    def check_format(self, format):
        if not format.lower() in self.OUTPUT_FORMATS:
            print("[WARNING] Invalid output format specified.. using CSV")
            return 'csv'

        return format.lower()

    def load_patterns(self, fpath):
        config = ConfigParser.ConfigParser()
        with open(args.INI) as f:
            config.readfp(f)

        for ind_type in config.sections():
            ind_pattern = config.get(ind_type, 'pattern', None)

            if ind_pattern:
                ind_regex = re.compile(ind_pattern)
                self.patterns[ind_type] = ind_regex

    def is_whitelisted(self, ind_match, ind_type):
        for w in self.whitelist[ind_type]:
            if w.findall(ind_match):
                return True

        return False

    def parse_page(self, page, page_num, fpath):
        data = page.extractText()

        for ind_type, ind_regex in self.patterns.iteritems():
            matches = ind_regex.findall(data)

            for ind_match in matches:
                if isinstance(ind_match, tuple):
                    ind_match = ind_match[0]

                if self.is_whitelisted(ind_match, ind_type):
                    continue

                if self.dd:
                    if (ind_type, ind_match) in self.dd:
                        continue

                    self.dd.add((ind_type, ind_match))

                self.print_match(fpath, page_num, ind_type, ind_match)

    def parse_file(self, fpath):
        with open(fpath, 'rb') as f:
            try:
                pdf = PdfFileReader(f, strict = False)

                page_num = 0
                for page in pdf.pages:
                    page_num += 1
                    self.parse_page(page, page_num, fpath)
            except (KeyboardInterrupt, SystemExit):
                raise
            except:
                self.print_error(fpath, traceback.format_exc())

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

    def print_match(self, fpath, page, name, match):
        match = match.encode('utf8')
        handler = getattr(self, 'handle_match_%s' % (self.format, ), None)
        if handler:
            handler(fpath, page, name, match)

    def handle_match_json(self, fpath, page, name, match):
        data = {
            'path' : fpath,
            'file' : os.path.basename(fpath),
            'page' : page,
            'type' : name,
            'match': match
        }

        print(json.dumps(data))

    def handle_match_csv(self, fpath, page, name, match):
        self.csv_writer.writerow((fpath, page, name, match))

    def print_error(self, fpath, exception):
        handler = getattr(self, 'handle_error_%s' % (self.format, ), None)
        if handler:
            handler(fpath, exception)

    def handle_error_json(self, fpath, exception):
        data = {
            'path'      : fpath,
            'file'      : os.path.basename(fpath),
            'type'      : 'error',
            'exception' : exception
        }

        print(json.dumps(data))

    def handle_error_csv(self, fpath, exception):
        self.csv_writer.writerow((fpath, '0', 'error', exception))


argparser = argparse.ArgumentParser()
argparser.add_argument('PDF', action='store', help='File/directory path to PDF report(s)')
argparser.add_argument('-p', dest='INI', default='patterns.ini', help='Pattern file')
argparser.add_argument('-f', dest='FORMAT', default='csv', help='Output format (csv/json)')
argparser.add_argument('-d', dest='DEDUP', action='store_true', default=False, help='Deduplicate matches')
args = argparser.parse_args()

if __name__ == "__main__":
    parser = IOC_Parser(args)
    parser.parse()
