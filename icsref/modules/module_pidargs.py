#!/usr/bin/env python3

__author__ = "Tasos Keliris"

import os
import angr
import struct
import re
import logging

logging.getLogger("angr").setLevel(logging.ERROR)

class PID():
    """Holds extracted PID_FIXCYCLE arguments (float + raw int) and call info."""
    def __init__(self):
        self.SET_POINT_f = self.SET_POINT_i = 0
        self.KP_f = self.KP_i = 0
        self.TN_f = self.TN_i = 0
        self.TV_f = self.TV_i = 0
        self.Y_MANUAL_f = self.Y_MANUAL_i = 0
        self.Y_OFFSET_f = self.Y_OFFSET_i = 0
        self.Y_MIN_f = self.Y_MIN_i = 0
        self.Y_MAX_f = self.Y_MAX_i = 0
        self.MANUAL_f = self.MANUAL_i = 0
        self.RESET_f = self.RESET_i = 0
        self.CYCLE_f = self.CYCLE_i = 0
        self.callto = -1
        self.stackbase = -1

def _read_u_le(state, addr, size):
    """Read size bytes from memory at addr (little-endian) and return Python int."""
    endness = state.arch.memory_endness  # should be 'Iend_LE' on ARMEL
    bv = state.memory.load(addr, size, endness=endness)
    return state.solver.eval(bv)

def _read_f32_le_from_u32(u32):
    """Convert a 32-bit unsigned int to IEEE-754 float (little endian)."""
    return struct.unpack("<f", struct.pack("<I", u32 & 0xFFFFFFFF))[0]

def pidargs(self, args):
    """Find arguments to PID_FIXCYCLE calls using symbolic execution (angr)."""
    try:
        prg = self.prg
    except AttributeError:
        print("Error: You need to first load or analyze a program.")
        return 0

    # Require at least one recognized PID function name
    pid_funcs = [x for x in prg.Functions if "PID" in x.name]
    if not pid_funcs:
        print("No PID_FIXCYCLE functions identified. Cannot extract arguments.")
        return 0

    # Calls found in penultimate function (often PLC_PRG)
    PLC_PRG_fun = prg.Functions[-2]
    PIDoffsets_index, PIDoffsets_pc = [], []
    for index, line in enumerate(PLC_PRG_fun.disasm):
        if ("call to " in line) and ("PID" in line):
            PIDoffsets_pc.append(int(re.findall(r"\S+", line)[0], 16))
            PIDoffsets_index.append(index)

    # Stack base offset (R9 base) from the first PID function's 4th line
    # (legacy heuristic from original code)
    a = pid_funcs[0]
    m = re.search(r"\[.+?,.+?\]", a.disasm[3])
    if not m:
        print("Could not infer stack base offset; aborting.")
        return 0
    sb_offset = int(m.group(0).split(", ")[1][:-1], 16) - 0xC

    if PIDoffsets_pc:
        prg.PIDcall = []

    # ARM code patterns (BYTES)
    epilogue = b"\x00\xa8\x1b\xe9"      # LDMDB ..., {r... , pc}
    movpclr  = b"\x0f\xe0\xa0\xe1"      # MOV PC, LR
    nop      = b"\x00\x00\xa0\xe1"      # NOP

    # Entry point of GLOBAL_INIT function
    entry_offset = prg.Functions[0].start
    g_start = prg.FunctionBoundaries[0][0]
    g_stop  = prg.FunctionBoundaries[0][1]

    for i in range(len(PIDoffsets_index)):
        pidinstance = PID()
        pidinstance.callto = PIDoffsets_pc[i]

        # Patch GLOBAL_INIT epilogues to branch into PLC_PRG (force a path)
        branch_offset = ((PLC_PRG_fun.start - g_stop - 4) // 4) + 0xEA000000
        branch_target = struct.pack("<I", branch_offset)
        hexdump_mod = prg.hexdump[:g_stop].replace(epilogue, branch_target) + prg.hexdump[g_stop:]

        # NOP out sequences around 'MOV PC, LR'
        search_pos = 0
        while True:
            idx = hexdump_mod.find(movpclr, search_pos)
            if idx == -1:
                break
            start = max(0, idx - 8)
            hexdump_mod = hexdump_mod[:start] + (nop * 5) + hexdump_mod[idx + 12:]
            search_pos = start + 5 * len(nop)

        # Force angr to stop at the desired call by injecting 0xFFFFFFFF at call site
        PIDcall = PIDoffsets_pc[i]
        hexdump_mod = hexdump_mod[:PIDcall] + (b"\xff" * 4) + hexdump_mod[PIDcall + 4:]

        tmp_path = f"temphexdump{i}.bin"
        with open(tmp_path, "wb") as f:
            f.write(hexdump_mod)

        proj = angr.Project(
            tmp_path,
            load_options={
                "main_opts": {
                    "backend": "blob",
                    "custom_arch": "ARMEL",
                    "custom_base_addr": 0,
                    "custom_entry_point": entry_offset
                },
                "auto_load_libs": False,
            },
        )

        # Run a bounded exploration to avoid hang
        state0 = proj.factory.entry_state()
        simgr = proj.factory.simulation_manager(state0)
        simgr.run(n=10000)  # limit steps

        # Prefer an errored state (faulted at our injected 0xFFFFFFFF), else active
        if simgr.errored:
            s1 = simgr.errored[0].state
        elif simgr.active:
            s1 = simgr.active[0]
        else:
            s1 = state0

        try:
            os.remove(tmp_path)
        except OSError:
            pass

        # Record stackbase (R9)
        pidinstance.stackbase = s1.solver.eval(s1.regs.r9)

        base = s1.regs.r9 + sb_offset

        # Helpers that do NOT use FP sorts in Z3
        def read_f32(off):
            u = _read_u_le(s1, base + off, 4)
            return _read_f32_le_from_u32(u), u

        def read_u32(off):
            u = _read_u_le(s1, base + off, 4)
            return float(u), u

        def read_u8(off):
            u = _read_u_le(s1, base + off, 1) & 0xFF
            return float(u), u

        # Field layout (based on your offsets; MANUAL/RESET are 1-byte flags)
        pidinstance.SET_POINT_f, pidinstance.SET_POINT_i = read_f32(0x04)
        pidinstance.KP_f,        pidinstance.KP_i        = read_f32(0x08)
        pidinstance.TN_f,        pidinstance.TN_i        = read_f32(0x0C)
        pidinstance.TV_f,        pidinstance.TV_i        = read_f32(0x10)
        pidinstance.Y_MANUAL_f,  pidinstance.Y_MANUAL_i  = read_f32(0x14)
        pidinstance.Y_OFFSET_f,  pidinstance.Y_OFFSET_i  = read_f32(0x18)
        pidinstance.Y_MIN_f,     pidinstance.Y_MIN_i     = read_f32(0x1C)
        pidinstance.Y_MAX_f,     pidinstance.Y_MAX_i     = read_f32(0x20)
        # Flags at 0x24 and 0x25 (1 byte each)
        pidinstance.MANUAL_f,    pidinstance.MANUAL_i    = read_u8(0x24)
        pidinstance.RESET_f,     pidinstance.RESET_i     = read_u8(0x25)
        # Next float at 0x28
        pidinstance.CYCLE_f,     pidinstance.CYCLE_i     = read_f32(0x28)

        print(f"\nCall to PID at {hex(PIDoffsets_pc[i])}")
        print(f"SET_POINT = {pidinstance.SET_POINT_f}".ljust(32) + f"({hex(pidinstance.SET_POINT_i)})")
        print(f"       KP = {pidinstance.KP_f}".ljust(32)        + f"({hex(pidinstance.KP_i)})")
        print(f"       TN = {pidinstance.TN_f}".ljust(32)        + f"({hex(pidinstance.TN_i)})")
        print(f"       TV = {pidinstance.TV_f}".ljust(32)        + f"({hex(pidinstance.TV_i)})")
        print(f" Y_MANUAL = {pidinstance.Y_MANUAL_f}".ljust(32)  + f"({hex(pidinstance.Y_MANUAL_i)})")
        print(f" Y_OFFSET = {pidinstance.Y_OFFSET_f}".ljust(32)  + f"({hex(pidinstance.Y_OFFSET_i)})")
        print(f"    Y_MIN = {pidinstance.Y_MIN_f}".ljust(32)     + f"({hex(pidinstance.Y_MIN_i)})")
        print(f"    Y_MAX = {pidinstance.Y_MAX_f}".ljust(32)     + f"({hex(pidinstance.Y_MAX_i)})")
        print(f"   MANUAL = {pidinstance.MANUAL_f}".ljust(32)    + f"(0x{pidinstance.MANUAL_i:02x})")
        print(f"    RESET = {pidinstance.RESET_f}".ljust(32)     + f"(0x{pidinstance.RESET_i:02x})")
        print(f"    CYCLE = {pidinstance.CYCLE_f}".ljust(32)     + f"({hex(pidinstance.CYCLE_i)})")

        prg.PIDcall.append(pidinstance)

    return 0

