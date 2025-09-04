#!/usr/bin/env python3

__author__ = "Tasos Keliris"

import os

def cleanup(self, args):
    """
    Remove artifacts created by graphbuilder/analytics.
    No args
    """
    try:
        prg = self.prg
    except AttributeError:
        print("Error: You need to first load or analyze a program")
        return 0

    root = os.path.join(os.getcwd(), "results", prg.name)
    for dirname, dirnames, filenames in os.walk(root):
        for fn in filenames:
            if fn.endswith(".disasm") or fn.endswith(".svg") or fn.endswith(".PRG") or fn.endswith(".CHK"):
                os.remove(os.path.join(dirname, fn))
            if fn == "analytics.txt" or fn.endswith(".analytics"):
                os.remove(os.path.join(dirname, fn))
    print("Cleanup complete")
    return 0

