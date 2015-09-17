import os
import glob
import re

class WhiteList(dict):
    def __init__(self, basedir=None, whitelist_dict=None):
        if basedir is not None:
            searchdir = os.path.join(basedir, "whitelists/whitelist_*.ini")
            fpaths = glob.glob(searchdir)
            for fpath in fpaths:
                t = os.path.splitext(os.path.split(fpath)[1])[0].split('_',1)[1]
                with open(fpath) as f:
                    patterns = [line.strip() for line in f]
                    self[t]  = [re.compile(p) for p in patterns]

        if whitelist_dict is not None:
            for t in whitelist_dict:
                self[t] = [re.compile(p) for p in whitelist_dict[t]]
