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
# File:             ioc-parser.py
# Description:      IOC Parser is a tool to extract indicators of compromise from security reports
#                   in PDF format.
# Usage:            ioc-parser.py [-h] [-p INI] [-f FORMAT] PDF
# Req.:             PyPDF2 (https://github.com/mstamy2/PyPDF2)
# Author:           Armin Buescher (@armbues)
# Contributors:     Angelo Dell'Aera (@angelodellaera)
# Thanks to:        Jose Ramon Palanco
#                   Koen Van Impe (@cudeso)
#
###################################################################################################

import os
import fnmatch
import argparse
import re
from StringIO import StringIO
try:
    import configparser as ConfigParser
except ImportError:
    import ConfigParser

# Import available PDF parser libraries
PARSER_LIBS = []
try:
    from PyPDF2 import PdfFileReader
    PARSER_LIBS.append('pypdf2')
except ImportError:
    pass
try:
    from pdfminer.pdfpage import PDFPage
    from pdfminer.pdfinterp import PDFResourceManager
    from pdfminer.converter import TextConverter
    from pdfminer.pdfinterp import PDFPageInterpreter
    from pdfminer.layout import LAParams
    PARSER_LIBS.append('pdfminer')
except ImportError:
    pass
if len(PARSER_LIBS) == 0:
    raise ImportError('No PDF parser libraries found (pypdf2, pdfminer)')

# Import additional source files
import output
from whitelist import WhiteList

class IOC_Parser(object):
    patterns = {}

    def __init__(self, patterns_ini='patterns.ini', format='csv', dedup=False, library='pypdf2'):
        basedir = os.path.dirname(os.path.abspath(__file__))
        if patterns_ini == 'patterns.ini':
            patterns_ini = os.path.join(basedir, 'patterns.ini')
        self.load_patterns(patterns_ini)
        self.whitelist = WhiteList(basedir)
        self.handler = output.getHandler(format)
        self.dedup = dedup

        if library not in PARSER_LIBS:
            e = 'Selected PDF parser library not found: %s' % (library)
            raise ImportError(e)
        self.library = library

    def load_patterns(self, fpath):
        config = ConfigParser.ConfigParser()
        with open(fpath) as f:
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

    def parse_page(self, fpath, data, page_num):
        for ind_type, ind_regex in self.patterns.items():
            matches = ind_regex.findall(data)

            for ind_match in matches:
                if isinstance(ind_match, tuple):
                    ind_match = ind_match[0]

                if self.is_whitelisted(ind_match, ind_type):
                    continue

                if self.dedup:
                    if (ind_type, ind_match) in self.dedup_store:
                        continue

                    self.dedup_store.add((ind_type, ind_match))

                self.handler.print_match(fpath, page_num, ind_type, ind_match)

    def parse_file_pypdf2(self,fpath):
        with open(fpath, 'rb') as f:
            try:
                pdf = PdfFileReader(f, strict = False)

                if self.dedup:
                    self.dedup_store = set()

                self.handler.print_header(fpath)
                page_num = 0
                for page in pdf.pages:
                    page_num += 1

                    data = page.extractText()

                    self.parse_page(fpath, data, page_num)
                self.handler.print_footer(fpath)
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as e:
                self.handler.print_error(fpath, e)

    def parse_file_pdfminer(self,fpath):
        with open(fpath, 'rb') as f:
            try:
                laparams = LAParams()
                laparams.all_texts = True  
                rsrcmgr = PDFResourceManager()
                pagenos = set()

                if self.dedup:
                    self.dedup_store = set()

                self.handler.print_header(fpath)
                page_num = 0
                for page in PDFPage.get_pages(f, pagenos, check_extractable=True):
                    page_num += 1

                    retstr = StringIO()
                    device = TextConverter(rsrcmgr, retstr, laparams=laparams)
                    interpreter = PDFPageInterpreter(rsrcmgr, device)
                    interpreter.process_page(page)
                    data = retstr.getvalue()
                    retstr.close()

                    self.parse_page(fpath, data, page_num)
                self.handler.print_footer(fpath)
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as e:
                self.handler.print_error(fpath, e)

    def parse_file(self, fpath):
        parser_format = "parse_file_" + self.library
        parser_func = getattr(self, parser_format)

        parser_func(fpath)

    def parse(self, path):
        if os.path.isfile(path):
            self.parse_file(path)
            return

        if os.path.isdir(path):
            for walk_root, walk_dirs, walk_files in os.walk(path):
                for walk_file in fnmatch.filter(walk_files, '*.pdf'):
                    self.parse_file(os.path.join(walk_root, walk_file))
            return

        print("[ERROR] Invalid PDF file path")

if __name__ == "__main__":
    argparser = argparse.ArgumentParser()
    argparser.add_argument('PDF', action='store', help='File/directory path to PDF report(s)')
    argparser.add_argument('-p', dest='INI', default=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'patterns.ini'), help='Pattern file')
    argparser.add_argument('-f', dest='FORMAT', default='csv', help='Output format (csv/json/yara)')
    argparser.add_argument('-d', dest='DEDUP', action='store_true', default=False, help='Deduplicate matches')
    argparser.add_argument('-l', dest='LIB', default='pypdf2', help='PDF parsing library (pypdf2/pdfminer)')
    args = argparser.parse_args()

    parser = IOC_Parser(args.INI, args.FORMAT, args.DEDUP, args.LIB)
    parser.parse(args.PDF)