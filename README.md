# ioc-parser
IOC Parser is a tool to extract indicators of compromise from security reports in PDF format. A good collection of APT related reports with many IOCs can be found here: [APTNotes](https://github.com/kbandla/APTnotes).

## Usage
**ioc-parser.py [-h] [-p INI] [-f FORMAT] PDF**
* PDF can be a single file or a directory
* INI can point to an alternative configuration file with regex patterns
* FORMAT can be one of ['text', 'csv', 'json']

## Requirements
[PyPDF2](https://github.com/mstamy2/PyPDF2) - *pip install pypdf2*
