# ioc-parser
IOC Parser is a tool to extract indicators of compromise from security reports in PDF format. A good collection of APT related reports with many IOCs can be found here: [APTNotes](https://github.com/kbandla/APTnotes).

## Usage
**iocp.py [-h] [-p INI] [-i FORMAT] [-o FORMAT] [-d] [-l LIB] FILE**
* *FILE* File/directory path to report(s)
* *-p INI* Pattern file
* *-i FORMAT* Input format (pdf/txt/html)
* *-o FORMAT* Output format (csv/json/yara)
* *-d* Deduplicate matches
* *-l LIB* Parsing library

## Usage as a package
Import IOC_Parser and create iocp object with 'data' output format.
'data' output format allows you to get any parsed IOCs as a dict.
```python
from ioc_parser.iocp import IOC_Parser
iocp = IOC_Parser(output_format='data')
```

Adding a host to a whitelist after creating iocp object. IOC_Parser
constructor parses any whitelist_*.ini files supplied in the basedir, but this
allows you to add whitelists inline.
```python
whitelist_host_str = "{}$".format("example.com")
whitelist_dict = {"Host": whitelist_host_str}
wl = WhiteList(whitelist_dict=whitelist_dict)
iocp.whitelist.update(wl)
```

Open a file and pass the file object and path to the parse_pdf_pdfminer method.
This specifies which pdf parser to use, alternatively you can specify which
pdf parser to use in the IOC_Parser constructor and use parse_pdf here. Or use
the default pdf parser.
```python
with open(pdf_path, "rb") as f:
    iocp.parse_pdf_pdfminer(f, pdf_path)

iocs = iocp.handler.get_iocs() # Returns a dictionary of any IOCs found
  ```

`get_iocs()` returns a dictionary in the following format:
```javascript
{
    "Email": {
        "file": "report1.pdf",
        "match": "domains@winmsn.com",
        "page": 4,
        "path": "./downloaded_files/report1.pdf",
        "type": "Email"
    },
    "IP": {
        "file": "report1.pdf",
        "match": "213.200.66.26",
        "page": 8,
        "path": "./downloaded_files/report1.pdf",
        "type": "IP"
    }
}
```

## Requirements
One of the following PDF parsing libraries:
* [PyPDF2](https://github.com/mstamy2/PyPDF2) - *pip install pypdf2*
* [pdfminer](https://github.com/euske/pdfminer) - *pip install pdfminer*

For HTML parsing support:
* [BeautifulSoup](http://www.crummy.com/software/BeautifulSoup/) - *pip install beautifulsoup4*

For HTTP(S) support:
* [requests](http://docs.python-requests.org/en/latest/) - *pip install requests*
