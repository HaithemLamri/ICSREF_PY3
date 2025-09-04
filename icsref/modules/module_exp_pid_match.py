#!/usr/bin/env python3

__author__ = "Tasos Keliris"

import ujson  # kept (unused) to preserve original environment

def exp_pid_match(self, args):
    """
    Experimental PID-like function matcher based on constant patterns and call graph.
    No args.
    """
    try:
        prg = self.prg
    except AttributeError:
        print("Error: You need to first load or analyze a program")
        return 0

    # Little-endian IEEE-754 encodings as BYTES
    id1000    = b"\x00\x00\x7A\x44"  # 1000.0 -> 0x447A0000
    id3       = b"\x00\x00\x40\x40"  #   3.0  -> 0x40400000
    id1E38    = b"\x99\x76\x96\x7E"  #  1e38
    idnot1E38 = b"\x99\x76\x96\xFE"  # -1e38
    id1E30    = b"\xCA\xF2\x49\x71"  #  1e30
    idnot1E30 = b"\xCA\xF2\x49\xF1"  # -1e30

    # Occurrence lists (lists of offsets)
    oc1000    = prg._Program__allindices(prg.hexdump, id1000)
    oc3       = prg._Program__allindices(prg.hexdump, id3)
    oc1E38    = prg._Program__allindices(prg.hexdump, id1E38)
    ocnot1E38 = prg._Program__allindices(prg.hexdump, idnot1E38)
    oc1E30    = prg._Program__allindices(prg.hexdump, id1E30)
    ocnot1E30 = prg._Program__allindices(prg.hexdump, idnot1E30)

    # If the program doesn't contain these constants at all, bail out early
    if not all([oc1000, oc3, oc1E38, ocnot1E38, oc1E30, ocnot1E30]):
        return 0

    # Heuristic search for a PID main which calls DERIVATIVE and INTEGRAL candidates
    for func_index, func in enumerate(prg.Functions[:-2]):
        # Track candidates with explicit None sentinel (index 0 is valid!)
        maybe_PID = None
        maybe_INTEGRAL = None
        maybe_DERIVATIVE = None

        if "PID" not in func.name:
            maybe_PID = func_index
            # Look at its callees that are NOT dynamic libs
            for call in set(func.calls):
                if call not in list(prg.dynlibs_dict.values()):
                    idx_list = [i for i, j in enumerate(prg.Functions) if j.name == call]
                    if not idx_list:
                        continue
                    callindex = idx_list[0]
                    callfunc = prg.Functions[callindex]

                    # DERIVATIVE ~ contains 3.0 and 1000.0
                    if (id3 in callfunc.hexdump) and (id1000 in callfunc.hexdump):
                        maybe_DERIVATIVE = callindex
                    # INTEGRAL ~ contains (+/-)1E38 and 1000.0
                    if (id1E38 in callfunc.hexdump) and (idnot1E38 in callfunc.hexdump) and (id1000 in callfunc.hexdump):
                        maybe_INTEGRAL = callindex

            # If all three candidates found, rename
            if (maybe_PID is not None) and (maybe_INTEGRAL is not None) and (maybe_DERIVATIVE is not None):
                print("Experimental module found function PID at 0x{:x}".format(prg.Functions[maybe_PID].start))
                self.do___replace_callname([maybe_PID, "exp_maybe_PID"])
                self.do___replace_callname([maybe_PID + 1, "exp_maybe_PID_INIT"])
                self.do___replace_callname([maybe_DERIVATIVE, "exp_maybe_DERIVATIVE"])
                self.do___replace_callname([maybe_DERIVATIVE + 1, "exp_maybe_DERIVATIVE_INIT"])
                self.do___replace_callname([maybe_INTEGRAL, "exp_maybe_INTEGRAL"])
                self.do___replace_callname([maybe_INTEGRAL + 1, "exp_maybe_INTEGRAL_INIT"])
                return 0

    return 0

