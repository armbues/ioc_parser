#!/usr/bin/env python

import os
from setuptools import setup

setup(
	name = "ioc_parser",
	version = "0.9.1",
	author = "Armin Buescher",
	author_email = "armin.buescher@googlemail.com",
	scripts=['bin/iocp'],
	description = ("Tool to extract indicators of compromise from security reports"),
	license = "MIT",
	url = "https://github.com/armbues/ioc_parser",
	packages=['iocp'],
	include_package_data=True,
	classifiers=[
		"Development Status :: 4 - Beta",
		"Topic :: Security",
		"License :: OSI Approved :: MIT License",
	],
	install_requires=[
		"pdfminer",
		"PyPDF2",
		"requests",
		"beautifulsoup4"
	],
)