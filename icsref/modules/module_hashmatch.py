#!/usr/bin/env python3

__author__ = "Tasos Keliris"

import ujson
import os

def _load_signatures(path):
    # Support either JSON-lines or a single JSON array
    with open(path, "r") as f:
        txt = f.read().strip()
        try:
            data = ujson.loads(txt)
            return data if isinstance(data, list) else []
        except ValueError:
            pass
    sigs = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                sigs.append(ujson.loads(line))
    return sigs

def hashmatch(self, args):
    """
    Match known library functions with opcode-hash technique.
    No args.
    """
    try:
        prg = self.prg
    except AttributeError:
        print("Error: You need to first load or analyze a program")
        return 0

    thisdir = os.path.split(os.path.split(__file__)[0])[0]
    f_main = os.path.join(thisdir, "data", "MAIN_signatures.json")
    f_init = os.path.join(thisdir, "data", "INIT_signatures.json")

    main_sign = _load_signatures(f_main)
    init_sign = _load_signatures(f_init)

    num_funcs = len(prg.Functions)
    matched = []

    # Rename last function to MEMORY_INIT
    func_index = num_funcs - 1
    matched.append(func_index)
    __replace_callname(self, [func_index, "MEMORY_INIT"])

    # Rename first function to GLOBAL_INIT
    func_index = 0
    matched.append(func_index)
    __replace_callname(self, [func_index, "GLOBAL_INIT"])

    # Rename second-to-last to PLC_PRG (superloop main)
    func_index = num_funcs - 2
    matched.append(func_index)
    __replace_callname(self, [func_index, "PLC_PRG"])

    # Byte-pattern summaries for some inits (keep as in original)
    init_1   = "0dc0a0e100582de90cb0a0e104102de50c109fe50021a0e1020091e704109de400a81be9"
    process_ID = "0dc0a0e100582de90cb0a0e100009fe500a81be9"
    init_2   = "0dc0a0e100582de90cb0a0e100a81be9"

    # Try to match (MAIN, INIT) pairs
    for idx, func in enumerate(prg.Functions[:-2]):
        mains = [s for s in main_sign if s.get("hash") == func.hash]
        inits = [s for s in init_sign if s.get("hash") == prg.Functions[idx + 1].hash]

        if mains and inits:
            matched.extend([idx, idx + 1])
            print("Hashmatch module found function {} at 0x{:x}".format(mains[0]["name"], prg.Functions[idx].start))
            __replace_callname(self, [idx, mains[0]["name"], mains[0].get("lib")])
            __replace_callname(self, [idx + 1, inits[0]["name"]])
        elif "SysDebugHandler" in func.calls:
            matched.append(idx)
            __replace_callname(self, [idx, "SYSDEBUG"])
        elif "".join([x[28:36] for x in prg.Functions[idx].disasm[:-1]]) == init_1:
            matched.append(idx)
            __replace_callname(self, [idx, "SUB_1"])
        elif "".join([x[28:36] for x in prg.Functions[idx].disasm[:-1]]) == process_ID:
            matched.append(idx)
            __replace_callname(self, [idx, "PROCESS_ID"])
        elif "".join([x[28:36] for x in prg.Functions[idx].disasm[:-1]]) == init_2:
            matched.append(idx)
            __replace_callname(self, [idx, "SUB_2"])

    # Common structure hints (optional renames)
    if len(prg.Functions) > 4 and prg.Functions[4].name == "DEBUG_HANDLER":
        if prg.Functions[1].name != "INIT_1":
            __replace_callname(self, [1, "maybe_INIT_1"])
        if prg.Functions[2].name != "PROCESS_ID":
            __replace_callname(self, [2, "maybe_PROCESS_ID"])
        if prg.Functions[3].name != "INIT_2":
            __replace_callname(self, [3, "maybe_INIT_2"])

    # Single matches (maybe_)
    not_matched = [x for x in range(num_funcs) if x not in matched]
    for idx in not_matched:
        func = prg.Functions[idx]
        mains = [s for s in main_sign if s.get("hash") == func.hash]
        if mains:
            new_name = "maybe_" + mains[0]["name"]
            for s in mains[1:]:
                new_name += " or maybe_" + s["name"]
            __replace_callname(self, [idx, new_name])
            print("Hashmatch module (MAY HAVE) found function {} at 0x{:x}".format(new_name, prg.Functions[idx].start))

        inits = [s for s in init_sign if s.get("hash") == func.hash]
        if inits:
            new_name = "maybe_" + inits[0]["name"]
            for s in inits[1:]:
                new_name += " or maybe_" + s["name"]
            __replace_callname(self, [idx, new_name])
            print("Hashmatch module (MAY HAVE) found function {} at 0x{:x}".format(new_name, prg.Functions[idx].start))

    return 0

def __replace_callname(self, args):
    """
    Replace name of function (also updating references and static-lib map).
    args = [func_index, new_name, (optional) lib_name]
    """
    prg = self.prg
    func_index = args[0]
    old = prg.Functions[func_index].name
    new = args[1]
    prg.Functions[func_index].name = new

    if len(args) > 2 and args[2]:
        prg.Functions[func_index].lib = args[2]

    # Update statlibs_dict values equal to old
    for k, v in list(prg.statlibs_dict.items()):
        if v == old:
            prg.statlibs_dict[k] = new

    # Update all references in disassembly and calls dicts
    for fun in prg.Functions:
        if old in fun.calls:
            fun.disasm = [x.replace(f"call to {old}", f"call to {new}") for x in fun.disasm]
            fun.calls[new] = fun.calls.pop(old)

    return 0

