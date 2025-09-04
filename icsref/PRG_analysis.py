#!/usr/bin/env python3

__author__ = 'Tasos Keliris'
"Modifications and improvements by w00kong (Py3 fixes by ChatGPT)"

# Imports
import sys
import os
import r2pipe
import angr
import re
import operator
import hashlib
import ujson
import dill
import struct
import logging
from difflib import SequenceMatcher
from glob import glob

logging.getLogger("angr").setLevel(logging.ERROR)

thisdir = os.path.split(__file__)[0]
trg_file = os.path.join(thisdir, 'data', '0750-0881.trg')


def _ensure_bytes(x):
    if isinstance(x, bytes):
        return x
    return str(x).encode('latin-1', errors='ignore')


class Program:
    """
    Program class

    Attributes:
    - path, name
    - hexdump (bytes)
    - program_start, program_end, dynlib_end
    - strings (dict: offset -> str)
    - FunctionBoundaries (list of (start, end))
    - Functions (list[Function])
    - dynlibs_dict, statlibs_dict, libs_dict
    - inputs, outputs
    """

    def __init__(self, path):
        # Program path & name
        self.path = path
        self.name = os.path.splitext(os.path.basename(self.path))[0]

        # Program hexdump
        self.hexdump = self.__read_file()
        print('DONE: Hexdump generation')

        # Analyze program header (little-endian)
        # ROM:00000020: Entry point + 0x18
        self.program_start = struct.unpack('<I', self.hexdump[0x20:0x24])[0] + 24
        # ROM:0000002C: End of OUTRO? + 0x18
        self.program_end = struct.unpack('<I', self.hexdump[0x2C:0x30])[0] + 24
        # ROM:00000044: End of dynamic libs (Before SYSDBGHANDLER)
        self.dynlib_end = struct.unpack('<I', self.hexdump[0x44:0x48])[0]
        print('DONE: Header analysis')

        # Program strings
        self.strings = self.__strings()
        print('DONE: String analysis')

        # I/O analysis from TRG file
        self.__find_io()
        print('DONE: I/O analysis')

        # Function Boundaries
        self.FunctionBoundaries = self.__find_blocks()
        print('DONE: Find function boundaries')

        # Program functions
        self.Functions = []
        self.__find_functions()
        print('DONE: Function disassembly')

        # Dynamic & Static libraries
        self.dynlibs_dict = self.__find_dynlibs()
        print('DONE: Find dynamic calls')

        self.statlibs_dict = self.__find_statlibs()
        print('DONE: Find static calls')

        # Merge
        self.libs_dict = dict(self.dynlibs_dict)
        self.libs_dict.update(self.statlibs_dict)

        # Annotate calls
        self.__find_libcalls()
        print('DONE: Call offsets renaming')

        # Save object instance
        self.__save_object()

    # --------------------------- helpers ---------------------------

    def __read_file(self):
        with open(self.path, 'rb') as f_in:
            return f_in.read()

    def __save_object(self):
        # Create directory for output results
        path = os.path.join('results', self.name)
        os.makedirs(path, exist_ok=True)
        dat_f = os.path.join(path, f'{self.name}_init_analysis.dat')
        # dill needs binary mode
        with open(dat_f, 'wb') as f:
            dill.dump(self, f)

    def __allindices(self, file_bytes, sub, offset=0):
        """
        Finds all occurrences of substring in bytes
        """
        file_bytes = _ensure_bytes(file_bytes)
        sub = _ensure_bytes(sub)
        i = file_bytes.find(sub, offset)
        res = []
        while i >= 0:
            res.append(i)
            i = file_bytes.find(sub, i + 1)
        return res

    # --------------------------- analyses ---------------------------

    def __find_io(self):
        """
        Find program INPUTS and OUTPUTS based on TRG information.
        Assumes ASCII text TRG file with hex values.
        """
        self.inputs = {}
        self.outputs = {}
        if not os.path.isfile(trg_file):
            return 0

        with open(trg_file, 'r', encoding='utf-8', errors='ignore') as f:
            trg_data = f.readlines()

        hex_pattern = re.compile(r'([0-9a-fA-F]+)')
        input_start = output_start = input_size = output_size = None

        for line in trg_data:
            if 'BaseAddressOfInputSegment' in line:
                m = re.search(hex_pattern, line.split('=')[1].replace('16#', ''))
                if m:
                    input_start = int(m.group(1), 16)
            elif 'BaseAddressOfOutputSegment' in line:
                m = re.search(hex_pattern, line.split('=')[1].replace('16#', ''))
                if m:
                    output_start = int(m.group(1), 16)
            elif 'SizeOfInputSegment' in line:
                m = re.search(hex_pattern, line.split('=')[1].replace('16#', ''))
                if m:
                    input_size = int(m.group(1), 16)
            elif 'SizeOfOutputSegment' in line:
                m = re.search(hex_pattern, line.split('=')[1].replace('16#', ''))
                if m:
                    output_size = int(m.group(1), 16)

        if None in (input_start, input_size, output_start, output_size):
            return 0

        # Find inputs/outputs offsets in the code
        for i in range(input_start, input_start + input_size):
            match = self.__allindices(self.hexdump, struct.pack('<I', i))
            if match:
                self.inputs[hex(i)] = [hex(k) for k in match]
        for i in range(output_start, output_start + output_size):
            match = self.__allindices(self.hexdump, struct.pack('<I', i))
            if match:
                self.outputs[hex(i)] = [hex(k) for k in match]
        return 0

    def __find_blocks(self):
        """
        Finds binary blobs (routines) based on delimiters:

        START: 0D C0 A0 E1 00 58 2D E9 0C B0 A0 E1
        STOP:  00 A8 1B E9
        """
        prologue = b'\x0d\xc0\xa0\xe1\x00\x58\x2d\xe9\x0c\xb0\xa0\xe1'
        epilogue = b'\x00\xa8\x1b\xe9'

        beginnings = self.__allindices(self.hexdump, prologue)
        endings = [i + len(epilogue) for i in self.__allindices(self.hexdump, epilogue)]

        # Guard: ensure monotonic pairs
        pairs = []
        ei = 0
        for b in beginnings:
            while ei < len(endings) and endings[ei] <= b:
                ei += 1
            if ei < len(endings):
                pairs.append((b, endings[ei]))
                ei += 1
        return pairs

    def __find_functions(self):
        """
        Produces disassembly listings for all functions using radare2 via r2pipe.
        """
        r2 = r2pipe.open(self.path)
        try:
            r2.cmd('e asm.arch=arm; e asm.bits=32; e cfg.bigendian=false')
            for i in range(len(self.FunctionBoundaries)):
                start_code = self.FunctionBoundaries[i][0]
                stop_code = self.FunctionBoundaries[i][1]
                length_code = max(0, stop_code - start_code)

                # Disassemble code
                disasm_code = r2.cmd(f'b {length_code}; pD @{start_code}')
                disasm_code = (12 * ' ' + disasm_code).splitlines()

                # Data after code up to next start (or program_end)
                start_data = stop_code
                if i == len(self.FunctionBoundaries) - 1:
                    stop_data = self.program_end
                else:
                    stop_data = self.FunctionBoundaries[i + 1][0]
                length_data = max(0, stop_data - start_data)

                disasm_data = r2.cmd(f'pxr {length_data} @{start_data}').splitlines()

                # Formatting: be robust to short lines
                fmt_data = []
                for line in disasm_data:
                    left = line[:11] if len(line) >= 11 else line
                    mid = line[14:23] if len(line) >= 23 else ''
                    rest = line[14:] if len(line) >= 14 else ''
                    fmt_data.append(f'            {left}     {mid}      {rest}')

                disasm = disasm_code + fmt_data
                self.Functions.append(Function(self.path, start_code, stop_data,
                                               self.hexdump[start_code:stop_data], disasm))
        finally:
            r2.quit()
        return 0

    def __find_dynlibs(self):
        """
        Finds dynamic libraries and their jump offsets.
        Layout (heuristic):
          ... 0xFFFF marker ... [ASCII name] 00 [2 bytes little-endian idx] ...
        """
        dynlibs = {}
        offset_limit = int(self.dynlib_end)
        idx_marker = self.hexdump.rfind(b'\xff\xff', 0, offset_limit)
        if idx_marker == -1:
            return dynlibs
        dynlib_offset = idx_marker + 2

        ascii_pat = re.compile(rb'[ -~]*')

        while dynlib_offset < len(self.hexdump):
            m = ascii_pat.match(self.hexdump, dynlib_offset)
            if not m:
                break
            name_bytes = m.group(0)
            name = name_bytes.decode('latin-1', errors='ignore')
            dynlib_offset = m.end()

            if not name:
                break
            if dynlib_offset + 2 > len(self.hexdump):
                break

            two = self.hexdump[dynlib_offset:dynlib_offset + 2]
            val = int.from_bytes(two, 'little')
            jump_offset = val * 4 + 8

            dynlibs[jump_offset] = name
            dynlib_offset += 2

        return dynlibs

    def __find_statlibs(self):
        """
        Uses angr to find static library call table (heuristic).
        """
        if not self.FunctionBoundaries:
            return {}

        entry_offset = self.Functions[-1].start
        stop_offset = self.FunctionBoundaries[-1][1] - 8

        # Avoid overwriting code during emulation: patch 0x2000 -> 0x10000000
        code_start = b'\x00\x20\x00\x00'
        hexdump_mod = self.hexdump.replace(code_start, b'\x00\x00\x00\x10')

        tmp_path = 'temphexdump.bin'
        with open(tmp_path, 'wb') as f:
            f.write(hexdump_mod)

        proj = angr.Project(
            tmp_path,
            load_options={
                'main_opts': {
                    'backend': 'blob',
                    'custom_base_addr': 0,
                    'custom_arch': 'ARMEL',
                    'custom_entry_point': 0x50
                },
                'auto_load_libs': False
            }
        )

        state = proj.factory.entry_state()
        state.regs.pc = entry_offset
        simgr = proj.factory.simulation_manager(state)

        # Initialize some memory so that execution doesn't jump to end.
        try:
            for i in range(0, 0xFF, 4):
                sim = simgr.active[0]
                sim.mem[sim.regs.r0 + i].long = 0xFFFFFFFF
        except Exception:
            pass

        # Run the code to create the static offsets in memory
        try:
            simgr.explore(find=stop_offset)
        except Exception:
            pass

        statlibs = {}
        try:
            funs = [x for x, _ in self.FunctionBoundaries]
            i = 0
            if simgr.found:
                tgt = simgr.found[0]
                # R1 is assumed to point to table
                while len(statlibs) < max(0, len(funs) - 1):
                    try:
                        mem_val = state.solver.eval(tgt.mem[tgt.regs.r1 + i].int.resolved)
                    except Exception:
                        break
                    if mem_val in funs:
                        statlibs[i + 8] = f'sub_{mem_val:x}'
                    i += 4
        finally:
            try:
                os.remove(tmp_path)
            except OSError:
                pass

        return statlibs

    def __find_libcalls(self):
        """
        Finds the calls from all functions (dynamic and static) by annotating disassembly.
        """
        for func in self.Functions:
            for index, line in enumerate(func.disasm):
                if 'mov pc, r' in line:
                    # search backward for a line like: '...; something = <addr>'
                    i = 3
                    while index - i >= 0 and ('ldr r' not in func.disasm[index - i] and '0x' not in func.disasm[index - i]):
                        i += 1
                        if index - i < 0:
                            break
                    if index - i < 0:
                        continue
                    parts = func.disasm[index - i].split(';')
                    if len(parts) < 2:
                        continue
                    rhs = parts[1].split('=')[-1].strip()
                    try:
                        jump = int(rhs, 16) if '0x' in rhs else int(rhs)
                    except ValueError:
                        continue
                    lib_name = self.libs_dict.get(jump)
                    if lib_name:
                        func.disasm[index] += f'                  ; call to {lib_name}'
                        func.calls[lib_name] = func.calls.get(lib_name, 0) + 1
        return 0

    def __strings(self):
        """
        Finds consecutive >=4-byte ASCII strings from the binary (bytes-safe).
        Returns dict: offset(int) -> str
        """
        strings = {}
        p = re.compile(rb'([ -~]{4,})')
        for m in p.finditer(self.hexdump):
            try:
                strings[m.start()] = m.group(1).decode('latin-1', errors='ignore')
            except Exception:
                pass
        return strings


class Function:
    """
    Function class

    Attributes:
    - path, start, stop, offset, name
    - length, hexdump (bytes)
    - disasm (list[str])
    - hash (sha256 of opcode string)
    - calls (dict)
    """

    def __init__(self, path, start, stop, hexdump, disasm):
        self.path = path
        self.start = start
        self.offset = start
        self.name = f'sub_{self.start:x}'
        self.stop = stop
        self.length = max(0, stop - start)
        self.hexdump = hexdump
        self.disasm = disasm

        # Build opcode string (conservative)
        op_bytes = b''
        for line in self.disasm:
            tail = line[43:] if len(line) >= 43 else line
            op = tail.split(' ')[0]
            # Discard data-like lines (heuristic: too long tokens)
            if len(op) < 6:
                op_bytes += op.encode('latin-1', errors='ignore')

        self.hash = hashlib.sha256(op_bytes).hexdigest()
        self.calls = {}


def main(argv):
    if not argv:
        print("Usage: PRG_analysis.py <file.PRG>")
        return 1

    prg = Program(argv[0])

    # Print dynamic and static libraries and their calling offsets
    sort_libs = sorted(list(prg.libs_dict.items()), key=operator.itemgetter(0))
    for lib in sort_libs:
        print(f'{hex(lib[0])}\t{lib[1]}')

    # Print the calls from each function
    for fun in prg.Functions:
        print(f'{fun.name}\t==>\t{fun.calls}')

    return 0


if __name__ == '__main__':
    main(sys.argv[1:])

