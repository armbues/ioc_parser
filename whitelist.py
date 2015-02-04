import os
import re

class WhiteList(dict):
    types = ("URL", 
             "Host", 
             "IP", 
             "Email", 
             "MD5", 
             "SHA1", 
             "SHA256") 

    def __init__(self):
        for t in self.types:
            self.load_patterns(t)

    def load_patterns(self, t):
        fpath    = os.path.join("whitelists", "whitelist_%s.ini" % (t, ))
        patterns = [line.strip() for line in open(fpath)]
        self[t]  = [re.compile(p) for p in patterns]

