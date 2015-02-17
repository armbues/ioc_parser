# ioc-parser
IOC Parser is a tool to extract indicators of compromise from security reports in PDF format. A good collection of APT related reports with many IOCs can be found here: [APTNotes](https://github.com/kbandla/APTnotes).

## Usage
**ioc-parser.py [-h] [-p INI] [-f FORMAT] [-d] PDF**
* *PDF* File/directory path to PDF report(s)
* *-p INI* Pattern file
* *-f FORMAT* Output format (csv/json/yara)
* *-d* Deduplicate matches
* *-t* Use PDF2TXT instead of PdfFileReader

## Requirements
[PyPDF2](https://github.com/mstamy2/PyPDF2) - *pip install pypdf2*

## Use PDF2TXT instead of the PdfFileReader library
With PdfFileReader not every URL or IP gets parsed from certain PDFs. That's why you can use the PDF2TXT library. You'll loose the page references with this option.