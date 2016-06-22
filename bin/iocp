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
# File:             iocp.py
# Description:      IOC Parser is a tool to extract indicators of compromise from security reports
#                   in PDF format.
# Usage:            iocp.py [-h] [-p INI] [-f FORMAT] PDF
# Author:           Armin Buescher (@armbues)
# Contributors:     Angelo Dell'Aera (@angelodellaera)
# Thanks to:        Jose Ramon Palanco
#                   Koen Van Impe (@cudeso)
#
###################################################################################################

import argparse

from iocp import Parser

if __name__ == "__main__":
	argparser = argparse.ArgumentParser()
	argparser.add_argument('PATH', action='store', help='File/directory/URL to report(s)')
	argparser.add_argument('-p', dest='INI', default=None, help='Pattern file')
	argparser.add_argument('-i', dest='INPUT_FORMAT', default='pdf', help='Input format (pdf/txt/html)')
	argparser.add_argument('-o', dest='OUTPUT_FORMAT', default='csv', help='Output format (csv/tsv/json/yara/netflow)')
	argparser.add_argument('-d', dest='DEDUP', action='store_true', default=False, help='Deduplicate matches')
	argparser.add_argument('-l', dest='LIB', default='pdfminer', help='PDF parsing library (pypdf2/pdfminer)')
	args = argparser.parse_args()

	parser = Parser.Parser(args.INI, args.INPUT_FORMAT, args.DEDUP, args.LIB, args.OUTPUT_FORMAT)
	parser.parse(args.PATH)