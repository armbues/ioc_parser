import os
import glob
import re

class WhiteList(dict):
    def __init__(self):
        fpaths = glob.glob("whitelists/whitelist_*.ini")
        for fpath in fpaths:
            t = os.path.splitext(fpath)[0].split('_',1)[1]
            patterns = [line.strip() for line in open(fpath)]
            self[t]  = [re.compile(p) for p in patterns]