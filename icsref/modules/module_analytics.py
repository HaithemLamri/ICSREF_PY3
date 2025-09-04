#!/usr/bin/env python3

__author__ = "Tasos Keliris"

import os

def analytics(self, args):
    """
    Print analytics of program.

    No args
    """
    try:
        prg = self.prg
    except AttributeError:
        print("Error: You need to first load or analyze a program")
        return 0

    path = os.path.join("results", prg.name)
    os.makedirs(path, exist_ok=True)
    out_path = os.path.join(path, f"{prg.name}.analytics")

    totals = {}

    with open(out_path, "w") as txt_f:
        for fun in prg.Functions:
            for call in fun.calls:
                if call not in list(prg.statlibs_dict.values()):
                    line = f"{fun.name} --|{fun.calls[call]}|--> {call}"
                else:
                    target_hash = [x.hash for x in prg.Functions if x.name == call][0]
                    line = f"{fun.name} --|{fun.calls[call]}|--> {call} <=> {fun.hash} --|{fun.calls[call]}|--> {target_hash}"
                print(line)
                txt_f.write(line + "\n")
                totals[call] = totals.get(call, 0) + fun.calls[call]
            if fun.calls:
                print("")
                txt_f.write("\n")

        print("\nTotals:")
        for key, cnt in totals.items():
            if key in list(prg.statlibs_dict.values()):
                target_hash = [x.hash for x in prg.Functions if x.name == key][0]
                line = f"{cnt} calls to {key} <=> {target_hash}"
            else:
                line = f"{cnt} calls to {key}"
            print(line)
            txt_f.write(line + "\n")

    return 0

